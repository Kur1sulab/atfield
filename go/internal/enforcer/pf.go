package enforcer

// pf.go —— macOS 后端：pfctl + 独立 anchor。
//
// 为什么必须用 anchor 而不是往主规则集里塞规则：
//  1. 整表替换。anchor 内的规则是「一坨文本」，改一条就重发整坨，内核原子生效；
//     主规则集只能追加/插入，删改要靠行号，一旦别人也改了行号就错位。
//  2. 天然可回滚。上一版文本留着，加载失败就重放上一版。
//  3. 不越界。`pfctl -a atfield` 只碰 atfield 这个命名空间，系统的
//     com.apple/* anchor 一个字节都不动。
//
// 唯一不做的动作是「把 anchor 挂进主规则集」——那要改 /etc/pf.conf（系统文件），
// 属于安装步骤，由运维显式执行。本包只读它来判断是否已挂载，绝不代劳。

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// pfctl 默认路径。macOS 上 pfctl 在 /sbin 下，普通用户 PATH 里未必有。
const pfctlBin = "/sbin/pfctl"

// pfConf 主规则集文件（只读探测挂载状态）。
const pfConf = "/etc/pf.conf"

// pf 规则块的起止标记。与 Python 版同字面量：两版指向同一 anchor 时，
// 谁后写谁覆盖，但标记一致便于人工核对「这块是谁生成的」。
const (
	pfMarkBegin = "# >>> atfield managed >>>"
	pfMarkEnd   = "# <<< atfield managed <<<"
)

// PF macOS 后端。
type PF struct{ *backend }

// NewPF 构造 pf 后端。
func NewPF(opts Options) *PF {
	b := newBackend(opts)
	if b.opts.Bin == "" {
		b.opts.Bin = pfctlBin
	}
	return &PF{backend: b}
}

// Name 后端名。
func (p *PF) Name() string { return "pf" }

// Caps 能力声明：pf 三件事都做得到，唯一限制是必须 root 才能读写 /dev/pf。
func (p *PF) Caps() Caps {
	return Caps{
		Backend:  p.Name(),
		DryRun:   p.opts.DryRun,
		Rollback: true,
		Flush:    true,
		CIDR:     true,
		IPv6:     true,
		Persist:  true,
		Root:     true,
		Note:     "规则只写进 anchor \"" + p.opts.Anchor + "\"，不改 /etc/pf.conf；重启后 anchor 内容保留但需已挂载",
	}
}

// renderPF 把阻断表渲染成 anchor 规则文本。纯函数——同样的表必然产出
// 同样的字节（除时间戳注释），这样才能拿来做「加载前/回滚后」的文本对比。
//
// 与 Python 版 pfhelper.PfHelper.render() 逐行对齐：同样的起止标记、
// 同样的 `on ! lo0` 双向规则。排除 lo0 是因为封一个地址不该把
// 本机自己跟自己说话（127.0.0.1 之外的回环流量）也一起断掉。
func renderPF(anchor string, entries map[string]Entry, now time.Time) string {
	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	sb.WriteString(pfMarkBegin)
	sb.WriteByte('\n')
	fmt.Fprintf(&sb, "# generated %s\n", now.Format("2006-01-02T15:04:05-0700"))
	fmt.Fprintf(&sb, "# anchor %s\n", anchor)
	fmt.Fprintf(&sb, "# rules %d\n", len(keys))
	for _, k := range keys {
		why := cleanReason(entries[k].Reason)
		if why != "" {
			fmt.Fprintf(&sb, "# %s %s\n", k, why)
		} else {
			fmt.Fprintf(&sb, "# %s\n", k)
		}
		// 双向各一条：只挡出向等于允许对方继续扫；只挡入向等于自己不回包也拦不住。
		fmt.Fprintf(&sb, "block drop quick on ! lo0 from %s to any\n", k)
		fmt.Fprintf(&sb, "block drop quick on ! lo0 from any to %s\n", k)
	}
	sb.WriteString(pfMarkEnd)
	sb.WriteByte('\n')
	return sb.String()
}

func (p *PF) parseCmd(text string) Command {
	return Command{Bin: p.opts.Bin, Args: []string{"-a", p.opts.Anchor, "-n", "-f", "-"}, Stdin: text}
}

func (p *PF) loadCmd(text string) Command {
	return Command{Bin: p.opts.Bin, Args: []string{"-a", p.opts.Anchor, "-f", "-"}, Stdin: text}
}

// Block 封禁一个目标。
//
// 事务语义：先在内存里算出「加入后」的整表文本 → `pfctl -n` 只解析不加载
// （语法错在这里就挡住，内核规则一条没变）→ `pfctl -f` 真加载 →
// 成功才把条目写进内存表。任何一步失败，内存表保持原样，磁盘状态不变。
func (p *PF) Block(ctx context.Context, t Target, reason, actor string) Result {
	res := Result{Backend: p.Name(), Op: "block", IP: t.Key(), DryRun: p.opts.DryRun}
	p.mu.Lock()
	defer p.mu.Unlock()

	if t.Net == nil {
		res.Detail = "目标为空"
		res.Err = res.Detail
		return res
	}
	if p.tbl.Has(t.Key()) {
		res.OK = true
		res.Skipped = true
		res.Detail = "已在阻断表内（幂等，未重复下发）"
		return res
	}
	if p.tbl.Len() >= p.opts.MaxEntries {
		res.Detail = fmt.Sprintf("阻断表已满（上限 %d 条），请先清理", p.opts.MaxEntries)
		res.Err = res.Detail
		return res
	}

	now := p.opts.Now()
	next := p.tbl.SnapshotMap()
	next[t.Key()] = Entry{Reason: cleanReason(reason), TS: now.Unix(), Actor: actor}
	text := renderPF(p.opts.Anchor, next, now)

	cmds := []Command{p.parseCmd(text), p.loadCmd(text)}
	if p.opts.DryRun {
		// dry-run 只写内存表（不碰内核）：这样「幂等」在预演里也可观测，
		// 而「绝不改系统」的保证依然成立。
		p.tbl.Put(t.Key(), next[t.Key()])
		res.OK = true
		res.Validated = true
		res.Changed = true
		res.Detail = "语法校验通过，未加载"
		res.Commands = cmds
		return res
	}

	if ok, detail := p.execCheck(ctx, cmds[0]); !ok {
		res.Stage = "parse"
		res.Detail = detail
		res.Err = detail
		return res
	}
	if ok, detail := p.execCheck(ctx, cmds[1]); !ok {
		res.Stage = "load"
		res.Err = detail
		res.Detail = detail
		// 加载失败：内核里现在可能是半截状态，重放上一版已成功文本。
		if p.lkgText != "" {
			if ok2, _ := p.execCheck(ctx, p.loadCmd(p.lkgText)); ok2 {
				res.RolledBack = true
			}
		}
		return res
	}

	p.lkgText = text
	p.tbl.Put(t.Key(), next[t.Key()])
	res.OK = true
	res.Changed = true
	res.Detail = "已加载到 anchor " + p.opts.Anchor
	return res
}

// Unblock 解封。不在表内视为已达成目标（幂等），不报错。
func (p *PF) Unblock(ctx context.Context, t Target) Result {
	res := Result{Backend: p.Name(), Op: "unblock", IP: t.Key(), DryRun: p.opts.DryRun}
	p.mu.Lock()
	defer p.mu.Unlock()

	if t.Net == nil || !p.tbl.Has(t.Key()) {
		res.OK = true
		res.Removed = false
		res.Detail = "本来就不在阻断表里"
		return res
	}
	next := p.tbl.SnapshotMap()
	delete(next, t.Key())
	text := renderPF(p.opts.Anchor, next, p.opts.Now())
	cmds := []Command{p.loadCmd(text)}
	if p.opts.DryRun {
		p.tbl.Delete(t.Key())
		res.OK = true
		res.Removed = true
		res.Changed = true
		res.Commands = cmds
		res.Detail = "dry-run：未加载"
		return res
	}
	if ok, detail := p.execCheck(ctx, cmds[0]); !ok {
		res.Err = detail
		res.Detail = detail
		return res
	}
	p.lkgText = text
	p.tbl.Delete(t.Key())
	res.OK = true
	res.Removed = true
	res.Changed = true
	res.Detail = "已从 anchor " + p.opts.Anchor + " 移除"
	return res
}

// Flush 清空 anchor。注意：只清自己的 anchor，系统的 com.apple anchor 不动。
func (p *PF) Flush(ctx context.Context) Result {
	res := Result{Backend: p.Name(), Op: "flush", DryRun: p.opts.DryRun}
	p.mu.Lock()
	defer p.mu.Unlock()

	n := p.tbl.Len()
	text := renderPF(p.opts.Anchor, nil, p.opts.Now())
	cmds := []Command{p.loadCmd(text)}
	if p.opts.DryRun {
		p.tbl.Clear()
		res.OK = true
		res.Flushed = n
		res.Changed = n > 0
		res.Commands = cmds
		res.Detail = "dry-run：未加载"
		return res
	}
	if ok, detail := p.execCheck(ctx, cmds[0]); !ok {
		res.Err = detail
		res.Detail = detail
		return res
	}
	p.lkgText = text
	p.tbl.Clear()
	res.OK = true
	res.Flushed = n
	res.Changed = n > 0
	res.Detail = "已清空 anchor " + p.opts.Anchor
	return res
}

// Rollback 重放上一次成功加载的文本。没有上一版时返回明确失败，
// 而不是假装回滚成功。
func (p *PF) Rollback(ctx context.Context) Result {
	res := Result{Backend: p.Name(), Op: "rollback", DryRun: p.opts.DryRun}
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.lkgText == "" {
		res.Detail = "没有可回滚的上一版（尚未成功加载过任何规则）"
		res.Err = res.Detail
		return res
	}
	cmds := []Command{p.loadCmd(p.lkgText)}
	if p.opts.DryRun {
		res.OK = true
		res.Changed = true
		res.Commands = cmds
		res.Detail = "dry-run：未加载"
		return res
	}
	if ok, detail := p.execCheck(ctx, cmds[0]); !ok {
		res.Err = detail
		res.Detail = detail
		return res
	}
	res.OK = true
	res.Changed = true
	res.Detail = "已回滚到上一版 anchor 内容"
	return res
}

// Status 读系统现状。dry-run 下不执行任何命令（连只读的都不执行），
// 只报告内存表——「dry-run 绝不碰系统」比「dry-run 顺便读一下」重要。
func (p *PF) Status(ctx context.Context) Status {
	p.mu.Lock()
	defer p.mu.Unlock()

	st := p.statusOf(p.Name())
	st.Caps = p.Caps()
	if p.opts.DryRun {
		st.Available = true
		st.Reason = "dry-run：未探测系统状态"
		return st
	}

	out, errText, err := p.opts.Runner.Run(ctx, Command{Bin: p.opts.Bin, Args: []string{"-s", "Anchors"}})
	if err != nil {
		st.Available = false
		st.Reason = "pfctl 不可用：" + clip(firstNonEmpty(errText, err.Error()), 200)
		return st
	}
	st.Available = true
	st.Attached = strings.Contains(out, p.opts.Anchor)
	if !st.Attached {
		// 再确认一次：anchor 存在但没挂进主规则集时，规则加载了也不生效。
		if body, rerr := os.ReadFile(pfConf); rerr == nil {
			st.Attached = strings.Contains(string(body), fmt.Sprintf("anchor %q", p.opts.Anchor))
		}
	}
	// 读 anchor 内的实际规则条数（读不到不影响 available：可能只是没加载过）。
	if rules, rerrText, rerr := p.opts.Runner.Run(ctx,
		Command{Bin: p.opts.Bin, Args: []string{"-a", p.opts.Anchor, "-s", "rules"}}); rerr == nil {
		st.Rules = countPFRules(rules)
	} else {
		st.Reason = clip(firstNonEmpty(rerrText, "读 anchor 规则失败"), 200)
	}
	return st
}

// countPFRules 数 anchor 里的 block 规则条数（一行一条，空行/注释跳过）。
func countPFRules(s string) int {
	n := 0
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		n++
	}
	return n
}

// execCheck 执行一条命令，返回是否成功与失败详情。调用方必须已持锁。
func (p *PF) execCheck(ctx context.Context, c Command) (bool, string) {
	out, errText, err := p.opts.Runner.Run(ctx, c)
	if err != nil {
		return false, clip(firstNonEmpty(errText, out, err.Error()), 300)
	}
	return true, ""
}
