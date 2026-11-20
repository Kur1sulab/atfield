package enforcer

// nft.go —— Linux 后端：nftables。
//
// 命名空间：`table inet atfield`（自带 set/chain），所有操作都在这个 table 内，
// 不碰 filter/iptables/nft 里别人的表。
//
// 幂等靠两件事：
//  1. nft 的 `add` 语义本身就是「不存在则创建，存在则不动」，所以建表/建 set/
//     建 chain 可以每次重发，不会报错也不会重复。
//  2. 元素级增删：`add element` 对已在集合里的元素是 no-op；`delete element`
//     对不存在的元素会报错，这个错误被显式识别成「本来就没有」而不是失败。
//
// 为什么每次 Block 都重发一遍脚手架（setup）：nft 的规则集是内核对象，
// 重启后消失、被别人 `nft flush ruleset` 清掉、被容器 runtime 重建都发生过。
// 重发脚手架 10 条命令的成本远低于「以为封了其实没封」的代价。
// 建规则用 `flush chain` + `add rule` 保证「恰好一条」，避免重复规则累积。

import (
	"context"
	"fmt"
	"strings"
)

// nftBin 默认路径。PATH 里通常有，但 systemd 单元的最小 PATH 未必。
const nftBin = "/usr/sbin/nft"

// nft 命名空间常量。表名与 Python 版 anchor 同名，便于运维一套心智模型。
const (
	nftFamily = "inet"
	nftSet4   = "blocked4"
	nftSet6   = "blocked6"
	nftIn     = "in"
	nftOut    = "out"
)

// NFT Linux 后端。
type NFT struct{ *backend }

// NewNFT 构造 nftables 后端。
func NewNFT(opts Options) *NFT {
	b := newBackend(opts)
	if b.opts.Bin == "" {
		b.opts.Bin = nftBin
	}
	return &NFT{backend: b}
}

// Name 后端名。
func (n *NFT) Name() string { return "nftables" }

// Caps 能力声明。
//
// Persist=false 是诚实的：nft 规则只存在于内核，重启即消失，要持久化得靠
// netfilter-persistent / systemd unit 把规则重放一遍，那是安装步骤不是本层职责。
func (n *NFT) Caps() Caps {
	return Caps{
		Backend:  n.Name(),
		DryRun:   n.opts.DryRun,
		Rollback: true,
		Flush:    true,
		CIDR:     true,
		IPv6:     true,
		Persist:  false,
		Root:     true,
		Note:     "规则只在 table inet " + n.opts.Anchor + " 内；重启后丢失，需由 systemd/netfilter-persistent 重放",
	}
}

// nftAddr 把目标转成 nft 接受的字面量：整段前缀（/32、/128）省略，
// 否则带前缀（interval set 支持 CIDR）。
func nftAddr(t Target) string {
	if t.Net == nil {
		return ""
	}
	bits := 128
	if !t.IsV6() {
		bits = 32
	}
	if t.PrefixLen() == bits {
		return t.Net.IP.String()
	}
	return t.Net.String()
}

func (n *NFT) setFor(t Target) string {
	if t.IsV6() {
		return nftSet6
	}
	return nftSet4
}

// setup 返回「确保命名空间存在且规则唯一」的命令序列。
// 全部用 `add`（幂等）；chain 先 flush 再 add rule，保证规则条数恒定。
func (n *NFT) setup() []Command {
	tbl := n.opts.Anchor
	return []Command{
		{Bin: n.opts.Bin, Args: []string{"add", "table", nftFamily, tbl}},
		{Bin: n.opts.Bin, Args: []string{"add", "set", nftFamily, tbl, nftSet4,
			"{", "type", "ipv4_addr;", "flags", "interval;", "}"}},
		{Bin: n.opts.Bin, Args: []string{"add", "set", nftFamily, tbl, nftSet6,
			"{", "type", "ipv6_addr;", "flags", "interval;", "}"}},
		{Bin: n.opts.Bin, Args: []string{"add", "chain", nftFamily, tbl, nftIn,
			"{", "type", "filter", "hook", "input", "priority", "0;", "policy", "accept;", "}"}},
		{Bin: n.opts.Bin, Args: []string{"add", "chain", nftFamily, tbl, nftOut,
			"{", "type", "filter", "hook", "output", "priority", "0;", "policy", "accept;", "}"}},
		// 先清空再建，规则条数恒为 4——重复调用不会越积越多。
		{Bin: n.opts.Bin, Args: []string{"flush", "chain", nftFamily, tbl, nftIn}},
		{Bin: n.opts.Bin, Args: []string{"flush", "chain", nftFamily, tbl, nftOut}},
		{Bin: n.opts.Bin, Args: []string{"add", "rule", nftFamily, tbl, nftIn, "ip", "saddr", "@" + nftSet4, "drop"}},
		{Bin: n.opts.Bin, Args: []string{"add", "rule", nftFamily, tbl, nftOut, "ip", "daddr", "@" + nftSet4, "drop"}},
		{Bin: n.opts.Bin, Args: []string{"add", "rule", nftFamily, tbl, nftIn, "ip6", "saddr", "@" + nftSet6, "drop"}},
		{Bin: n.opts.Bin, Args: []string{"add", "rule", nftFamily, tbl, nftOut, "ip6", "daddr", "@" + nftSet6, "drop"}},
	}
}

func (n *NFT) addElemCmd(t Target) Command {
	return Command{Bin: n.opts.Bin, Args: []string{"add", "element", nftFamily, n.opts.Anchor,
		n.setFor(t), "{", nftAddr(t), "}"}}
}

func (n *NFT) delElemCmd(t Target) Command {
	return Command{Bin: n.opts.Bin, Args: []string{"delete", "element", nftFamily, n.opts.Anchor,
		n.setFor(t), "{", nftAddr(t), "}"}}
}

// Block 封禁。已在表内 → 幂等跳过。
func (n *NFT) Block(ctx context.Context, t Target, reason, actor string) Result {
	res := Result{Backend: n.Name(), Op: "block", IP: t.Key(), DryRun: n.opts.DryRun}
	n.mu.Lock()
	defer n.mu.Unlock()

	if t.Net == nil {
		res.Detail = "目标为空"
		res.Err = res.Detail
		return res
	}
	if n.tbl.Has(t.Key()) {
		res.OK = true
		res.Skipped = true
		res.Detail = "已在阻断表内（幂等，未重复下发）"
		return res
	}
	if n.tbl.Len() >= n.opts.MaxEntries {
		res.Detail = fmt.Sprintf("阻断表已满（上限 %d 条），请先清理", n.opts.MaxEntries)
		res.Err = res.Detail
		return res
	}

	cmds := append(n.setup(), n.addElemCmd(t))
	entry := Entry{Reason: cleanReason(reason), TS: n.opts.Now().Unix(), Actor: actor}
	if n.opts.DryRun {
		// dry-run 只写内存表（不碰内核）：幂等可观测，系统不受影响。
		n.tbl.Put(t.Key(), entry)
		res.OK = true
		res.Changed = true
		res.Validated = true
		res.Commands = cmds
		res.Detail = "dry-run：未下发（命令已构造）"
		return res
	}
	if ok, detail := n.execAll(ctx, cmds); !ok {
		res.Err = detail
		res.Detail = detail
		return res
	}
	next := n.tbl.SnapshotMap()
	next[t.Key()] = entry
	n.lkgEntries = entriesFromMap(next)
	n.tbl.Put(t.Key(), entry)
	res.OK = true
	res.Changed = true
	res.Detail = "已加入 set " + n.setFor(t)
	return res
}

// Unblock 解封。不在表内或元素本来就不存在 → OK 且 Removed=false。
func (n *NFT) Unblock(ctx context.Context, t Target) Result {
	res := Result{Backend: n.Name(), Op: "unblock", IP: t.Key(), DryRun: n.opts.DryRun}
	n.mu.Lock()
	defer n.mu.Unlock()

	if t.Net == nil || !n.tbl.Has(t.Key()) {
		res.OK = true
		res.Removed = false
		res.Detail = "本来就不在阻断表里"
		return res
	}
	cmds := []Command{n.delElemCmd(t)}
	if n.opts.DryRun {
		n.tbl.Delete(t.Key())
		res.OK = true
		res.Removed = true
		res.Changed = true
		res.Commands = cmds
		res.Detail = "dry-run：未下发（命令已构造）"
		return res
	}
	out, errText, err := n.opts.Runner.Run(ctx, cmds[0])
	if err != nil {
		msg := firstNonEmpty(errText, out, err.Error())
		if !nftMissing(msg) {
			res.Err = clip(msg, 300)
			res.Detail = res.Err
			return res
		}
		// 元素/set 本来就不存在：目标状态已达成，按成功处理但标 removed=false。
		res.OK = true
		res.Removed = false
		res.Detail = "内核里本来就没有该元素（幂等）"
		n.tbl.Delete(t.Key())
		return res
	}
	next := n.tbl.SnapshotMap()
	delete(next, t.Key())
	n.lkgEntries = entriesFromMap(next)
	n.tbl.Delete(t.Key())
	res.OK = true
	res.Removed = true
	res.Changed = true
	res.Detail = "已从 set " + n.setFor(t) + " 移除"
	return res
}

// Flush 删掉整个 table——这是「清空我自己的全部阻断」最彻底且最原子的做法，
// 顺带清掉可能残留的旧 set，不留半截状态。
func (n *NFT) Flush(ctx context.Context) Result {
	res := Result{Backend: n.Name(), Op: "flush", DryRun: n.opts.DryRun}
	n.mu.Lock()
	defer n.mu.Unlock()

	cnt := n.tbl.Len()
	cmds := []Command{{Bin: n.opts.Bin, Args: []string{"delete", "table", nftFamily, n.opts.Anchor}}}
	if n.opts.DryRun {
		n.tbl.Clear()
		res.OK = true
		res.Flushed = cnt
		res.Changed = cnt > 0
		res.Commands = cmds
		res.Detail = "dry-run：未下发（命令已构造）"
		return res
	}
	out, errText, err := n.opts.Runner.Run(ctx, cmds[0])
	if err != nil {
		msg := firstNonEmpty(errText, out, err.Error())
		if !nftMissing(msg) {
			res.Err = clip(msg, 300)
			res.Detail = res.Err
			return res
		}
		// 表本来就不存在：已经是「全清」状态。
		n.tbl.Clear()
		n.lkgEntries = nil
		res.OK = true
		res.Flushed = cnt
		res.Detail = "table 本来就不存在（幂等）"
		return res
	}
	n.tbl.Clear()
	n.lkgEntries = nil
	res.OK = true
	res.Flushed = cnt
	res.Changed = cnt > 0
	res.Detail = "已删除 table " + nftFamily + " " + n.opts.Anchor
	return res
}

// Rollback 用上一次成功下发后的期望集合重建：脚手架 → 清空两个 set → 逐条重加。
func (n *NFT) Rollback(ctx context.Context) Result {
	res := Result{Backend: n.Name(), Op: "rollback", DryRun: n.opts.DryRun}
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.lkgEntries == nil {
		res.Detail = "没有可回滚的上一版（尚未成功下发过任何规则）"
		res.Err = res.Detail
		return res
	}
	cmds := n.setup()
	cmds = append(cmds,
		Command{Bin: n.opts.Bin, Args: []string{"flush", "set", nftFamily, n.opts.Anchor, nftSet4}},
		Command{Bin: n.opts.Bin, Args: []string{"flush", "set", nftFamily, n.opts.Anchor, nftSet6}},
	)
	for _, e := range n.lkgEntries {
		t, err := ParseTarget(e.Key)
		if err != nil {
			continue
		}
		cmds = append(cmds, n.addElemCmd(t))
	}
	if n.opts.DryRun {
		res.OK = true
		res.Changed = true
		res.Commands = cmds
		res.Detail = "dry-run：未下发（命令已构造）"
		return res
	}
	if ok, detail := n.execAll(ctx, cmds); !ok {
		res.Err = detail
		res.Detail = detail
		return res
	}
	// 回滚成功 → 内存表也回到上一版。
	n.tbl.Clear()
	for _, e := range n.lkgEntries {
		n.tbl.Put(e.Key, e.entry)
	}
	res.OK = true
	res.Changed = true
	res.Detail = fmt.Sprintf("已回滚到上一版（%d 条）", len(n.lkgEntries))
	return res
}

// Status 读 table 现状。table 不存在 = 没有任何阻断（available 仍为 true），
// 权限不足 = available=false + 原因。
func (n *NFT) Status(ctx context.Context) Status {
	n.mu.Lock()
	defer n.mu.Unlock()

	st := n.statusOf(n.Name())
	st.Caps = n.Caps()
	if n.opts.DryRun {
		st.Available = true
		st.Reason = "dry-run：未探测系统状态"
		return st
	}
	out, errText, err := n.opts.Runner.Run(ctx,
		Command{Bin: n.opts.Bin, Args: []string{"list", "table", nftFamily, n.opts.Anchor}})
	if err != nil {
		msg := firstNonEmpty(errText, err.Error())
		if nftMissing(msg) {
			st.Available = true
			st.Reason = "table 尚未创建（当前没有任何阻断）"
			return st
		}
		st.Available = false
		st.Reason = "nft 不可用：" + clip(msg, 200)
		return st
	}
	st.Available = true
	st.Attached = true
	st.Rules = strings.Count(out, "drop")
	return st
}

// execAll 顺序执行，遇错即停并返回首个错误详情。调用方已持锁。
func (n *NFT) execAll(ctx context.Context, cmds []Command) (bool, string) {
	for _, c := range cmds {
		out, errText, err := n.opts.Runner.Run(ctx, c)
		if err != nil {
			return false, clip(firstNonEmpty(errText, out, err.Error()), 300)
		}
	}
	return true, ""
}

// nftMissing 识别 nft 的「对象不存在」错误。nft 统一报
// "Error: No such file or directory"（退出码非 0），文本是唯一线索。
func nftMissing(msg string) bool {
	m := strings.ToLower(msg)
	return strings.Contains(m, "no such file or directory") ||
		strings.Contains(m, "does not exist") ||
		strings.Contains(m, "no such") && strings.Contains(m, "table")
}

// keyedEntry 带上 key 的条目（回滚要按 key 重建，Entry 本身不存 key）。
type keyedEntry struct {
	Key   string
	entry Entry
}

func entriesFromMap(m map[string]Entry) []keyedEntry {
	out := make([]keyedEntry, 0, len(m))
	for _, k := range sortEntries(m) {
		out = append(out, keyedEntry{Key: k, entry: m[k]})
	}
	return out
}
