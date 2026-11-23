package enforcer

// netsh.go —— Windows 后端：netsh advfirewall（降级路径）。
//
// 为什么是「降级」：Windows 防火墙没有 anchor/table 这种「一块可以整体替换的
// 规则集合」。每条封禁是一对独立规则（入向 + 出向），增删都是单条命令，
// 没有事务、没有原子重载、也没有「按前缀枚举我自己写了哪些规则」的稳定接口。
// 后果：
//   - 无法整表回滚（Rollback 明确不支持，而不是假装支持）
//   - Flush 只能清掉本进程内存表里知道的规则；进程重启前的残留要靠
//     `netsh advfirewall firewall show rule name=all` 人工按 atfield- 前缀清
//   - 幂等靠命名 + 「已存在」错误识别，而不是内核状态查询
//
// 规则命名固定为 atfield-in-<key> / atfield-out-<key>：名字即归属，
// 运维一眼能看出这条规则是谁写的、什么时候该删。key 里的 '/' 换成 '_'
// （CIDR 的斜杠在规则名里是合法字符但会让命令行引用变脆）。

import (
	"context"
	"fmt"
	"strings"
)

// netshBin Windows 上 netsh 在 System32 下。
const netshBin = "netsh"

// NFT/NFT 之外的前缀：规则名前缀，用于人工核对与清理。
const netshPrefix = "atfield"

// Netsh Windows 后端。
type Netsh struct{ *backend }

// NewNetsh 构造 netsh 后端。
func NewNetsh(opts Options) *Netsh {
	b := newBackend(opts)
	if b.opts.Bin == "" {
		b.opts.Bin = netshBin
	}
	return &Netsh{backend: b}
}

// Name 后端名。
func (w *Netsh) Name() string { return "netsh" }

// Caps 能力声明：能封能解、能 CIDR/IPv6、规则重启后仍在；
// 但没有事务回滚，Flush 只覆盖已知条目。
func (w *Netsh) Caps() Caps {
	return Caps{
		Backend:  w.Name(),
		DryRun:   w.opts.DryRun,
		Rollback: false,
		Flush:    true,
		CIDR:     true,
		IPv6:     true,
		Persist:  true,
		Root:     true,
		Note: "降级路径：规则名 atfield-in-*/atfield-out-*，无事务回滚；" +
			"flush 只能清理内存表已知规则，进程重启前的残留需按前缀手工清理",
	}
}

// ruleName 生成规则名。key 形如 1.2.3.4/32 → atfield-in-1.2.3.4_32。
func ruleName(dir, key string) string {
	safe := strings.NewReplacer("/", "_", ":", "_", " ", "_").Replace(key)
	return netshPrefix + "-" + dir + "-" + safe
}

func (w *Netsh) addCmd(t Target, dir string) Command {
	name := ruleName(dir, t.Key())
	return Command{Bin: w.opts.Bin, Args: []string{
		"advfirewall", "firewall", "add", "rule",
		"name=" + name,
		"dir=" + dir,
		"action=block",
		"remoteip=" + t.Key(),
		"profile=any",
		"enable=yes",
	}}
}

func (w *Netsh) delCmd(t Target, dir string) Command {
	return Command{Bin: w.opts.Bin, Args: []string{
		"advfirewall", "firewall", "delete", "rule",
		"name=" + ruleName(dir, t.Key()),
		"dir=" + dir,
	}}
}

// Block 封禁：入向 + 出向各一条规则。
func (w *Netsh) Block(ctx context.Context, t Target, reason, actor string) Result {
	res := Result{Backend: w.Name(), Op: "block", IP: t.Key(), DryRun: w.opts.DryRun}
	w.mu.Lock()
	defer w.mu.Unlock()

	if t.Net == nil {
		res.Detail = "目标为空"
		res.Err = res.Detail
		return res
	}
	if w.tbl.Has(t.Key()) {
		res.OK = true
		res.Skipped = true
		res.Detail = "已在阻断表内（幂等，未重复下发）"
		return res
	}
	if w.tbl.Len() >= w.opts.MaxEntries {
		res.Detail = fmt.Sprintf("阻断表已满（上限 %d 条），请先清理", w.opts.MaxEntries)
		res.Err = res.Detail
		return res
	}

	cmds := []Command{w.addCmd(t, "in"), w.addCmd(t, "out")}
	entry := Entry{Reason: cleanReason(reason), TS: w.opts.Now().Unix(), Actor: actor}
	if w.opts.DryRun {
		// dry-run 只写内存表（不碰系统防火墙）。
		w.tbl.Put(t.Key(), entry)
		res.OK = true
		res.Changed = true
		res.Validated = true
		res.Commands = cmds
		res.Detail = "dry-run：未下发（命令已构造）"
		return res
	}
	for _, c := range cmds {
		out, errText, err := w.opts.Runner.Run(ctx, c)
		if err != nil {
			msg := firstNonEmpty(errText, out, err.Error())
			if netshExists(msg) {
				// 规则已存在（上次进程留下的）→ 视为已达成，继续。
				continue
			}
			res.Err = clip(msg, 300)
			res.Detail = res.Err
			return res
		}
	}
	w.tbl.Put(t.Key(), entry)
	res.OK = true
	res.Changed = true
	res.Detail = "已添加防火墙规则 " + ruleName("in", t.Key()) + " / " + ruleName("out", t.Key())
	return res
}

// Unblock 解封：按名字删两条规则。规则不存在 = 已达成（幂等）。
func (w *Netsh) Unblock(ctx context.Context, t Target) Result {
	res := Result{Backend: w.Name(), Op: "unblock", IP: t.Key(), DryRun: w.opts.DryRun}
	w.mu.Lock()
	defer w.mu.Unlock()

	if t.Net == nil || !w.tbl.Has(t.Key()) {
		res.OK = true
		res.Removed = false
		res.Detail = "本来就不在阻断表里"
		return res
	}
	cmds := []Command{w.delCmd(t, "in"), w.delCmd(t, "out")}
	if w.opts.DryRun {
		w.tbl.Delete(t.Key())
		res.OK = true
		res.Removed = true
		res.Changed = true
		res.Commands = cmds
		res.Detail = "dry-run：未下发（命令已构造）"
		return res
	}
	for _, c := range cmds {
		out, errText, err := w.opts.Runner.Run(ctx, c)
		if err != nil {
			msg := firstNonEmpty(errText, out, err.Error())
			if netshMissingRule(msg) {
				continue
			}
			res.Err = clip(msg, 300)
			res.Detail = res.Err
			return res
		}
	}
	w.tbl.Delete(t.Key())
	res.OK = true
	res.Removed = true
	res.Changed = true
	res.Detail = "已删除防火墙规则"
	return res
}

// Flush 清掉内存表里已知的每一条规则（入/出各一次）。
// 明确不承诺「清干净系统里所有 atfield-* 规则」——netsh 没有按前缀删除。
func (w *Netsh) Flush(ctx context.Context) Result {
	res := Result{Backend: w.Name(), Op: "flush", DryRun: w.opts.DryRun}
	w.mu.Lock()
	defer w.mu.Unlock()

	keys := make([]string, 0, w.tbl.Len())
	for k := range w.tbl.SnapshotMap() {
		keys = append(keys, k)
	}
	var cmds []Command
	for _, k := range keys {
		t, err := ParseTarget(k)
		if err != nil {
			continue
		}
		cmds = append(cmds, w.delCmd(t, "in"), w.delCmd(t, "out"))
	}
	if w.opts.DryRun {
		w.tbl.Clear()
		res.OK = true
		res.Flushed = len(keys)
		res.Changed = len(keys) > 0
		res.Commands = cmds
		res.Detail = "dry-run：未下发（命令已构造）"
		return res
	}
	failed := 0
	for _, c := range cmds {
		out, errText, err := w.opts.Runner.Run(ctx, c)
		if err != nil {
			msg := firstNonEmpty(errText, out, err.Error())
			if !netshMissingRule(msg) {
				failed++
			}
		}
	}
	n := w.tbl.Clear()
	res.OK = failed == 0
	res.Flushed = n
	res.Changed = n > 0
	if failed > 0 {
		res.Err = fmt.Sprintf("%d 条规则删除失败", failed)
		res.Detail = res.Err + "（已清理内存表；残留规则请按 atfield- 前缀手工删除）"
		return res
	}
	res.Detail = fmt.Sprintf("已清理 %d 条已知规则；历史残留请按 atfield- 前缀手工核对", n)
	return res
}

// Rollback 明确不支持：netsh 没有事务，回滚只能重放，重放到一半失败会
// 留下「一半新一半旧」的状态，比不滚更危险。所以这里返回失败 + 指引。
func (w *Netsh) Rollback(context.Context) Result {
	res := Result{Backend: w.Name(), Op: "rollback", DryRun: w.opts.DryRun}
	res.Unsupported = true
	res.Detail = "netsh 无事务语义，不支持自动回滚；请按审计里的命令序列人工重放"
	res.Err = res.Detail
	return res
}

// Status 只读：`show rule name=atfield-*` 不支持通配，因此用
// `show rule name=all` 全量列举再按前缀过滤（只在非 dry-run 下执行）。
func (w *Netsh) Status(ctx context.Context) Status {
	w.mu.Lock()
	defer w.mu.Unlock()

	st := w.statusOf(w.Name())
	st.Caps = w.Caps()
	if w.opts.DryRun {
		st.Available = true
		st.Reason = "dry-run：未探测系统状态"
		return st
	}
	out, errText, err := w.opts.Runner.Run(ctx, Command{Bin: w.opts.Bin,
		Args: []string{"advfirewall", "firewall", "show", "rule", "name=all"}})
	if err != nil {
		st.Available = false
		st.Reason = "netsh 不可用：" + clip(firstNonEmpty(errText, err.Error()), 200)
		return st
	}
	st.Available = true
	st.Rules = strings.Count(out, netshPrefix+"-in-") + strings.Count(out, netshPrefix+"-out-")
	st.Attached = st.Rules > 0
	if st.Rules > st.Count*2 {
		st.Reason = "存在本进程之外的 atfield-* 规则（可能是上次运行的残留）"
	}
	return st
}

// netshExists 识别「规则已存在」。
func netshExists(msg string) bool {
	m := strings.ToLower(msg)
	return strings.Contains(m, "already exists") || strings.Contains(msg, "已存在")
}

// netshMissingRule 识别「规则不存在」。
func netshMissingRule(msg string) bool {
	m := strings.ToLower(msg)
	return strings.Contains(m, "no rules match") || strings.Contains(m, "not found") ||
		strings.Contains(msg, "没有与指定条件匹配的规则") || strings.Contains(msg, "找不到")
}
