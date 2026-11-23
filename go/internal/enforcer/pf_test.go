package enforcer

// pf_test.go —— macOS 后端：规则文本格式、命令构造、回滚、幂等。
//
// 所有用例都是 DryRun 或 fakeRunner，绝不调用真的 pfctl。

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestPFRenderGolden(t *testing.T) {
	now := time.Date(2026, 11, 21, 2, 30, 0, 0, time.FixedZone("CST", 8*3600))
	entries := map[string]Entry{
		"203.0.113.9/32":  {Reason: "暴力破解 #"},
		"198.51.100.7/32": {Reason: "端口扫描"},
	}
	got := renderPF("atfield", entries, now)
	want := `# >>> atfield managed >>>
# generated 2026-11-21T02:30:00+0800
# anchor atfield
# rules 2
# 198.51.100.7/32 端口扫描
block drop quick on ! lo0 from 198.51.100.7/32 to any
block drop quick on ! lo0 from any to 198.51.100.7/32
# 203.0.113.9/32 暴力破解 ＃
block drop quick on ! lo0 from 203.0.113.9/32 to any
block drop quick on ! lo0 from any to 203.0.113.9/32
# <<< atfield managed <<<
`
	if got != want {
		t.Fatalf("pf 规则文本与 Python 版格式不一致:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestPFRenderEmpty(t *testing.T) {
	got := renderPF("atfield", nil, fixedClock()())
	if strings.Contains(got, "block drop") {
		t.Fatalf("空表不应渲染出任何 block 规则:\n%s", got)
	}
	if !strings.Contains(got, "# rules 0") {
		t.Fatalf("空表应标注 rules 0:\n%s", got)
	}
}

func TestPFBlockDryRunCommands(t *testing.T) {
	cr := &countingRunner{}
	p := NewPF(Options{DryRun: true, Runner: cr, Now: fixedClock()})
	tgt, _ := ParseTarget("198.51.100.7")

	r := p.Block(context.Background(), tgt, "端口扫描", "analyst")
	if !r.OK || !r.Changed || !r.Validated {
		t.Fatalf("dry-run block 结果不对: %+v", r)
	}
	if len(r.Commands) != 2 {
		t.Fatalf("应构造 2 条命令（-n 校验 + -f 加载），实际 %d", len(r.Commands))
	}
	// 第一条：只解析不加载
	first := r.Commands[0]
	if first.Bin != "/sbin/pfctl" {
		t.Fatalf("pfctl 路径=%q", first.Bin)
	}
	if got := strings.Join(first.Args, " "); got != "-a atfield -n -f -" {
		t.Fatalf("校验命令参数=%q", got)
	}
	// 第二条：真加载，规则从 stdin 进（不出现在 ps 里）
	second := r.Commands[1]
	if got := strings.Join(second.Args, " "); got != "-a atfield -f -" {
		t.Fatalf("加载命令参数=%q", got)
	}
	if second.Stdin != first.Stdin {
		t.Fatal("两条命令喂的规则文本必须一致")
	}
	for _, want := range []string{
		"# >>> atfield managed >>>",
		"# 198.51.100.7/32 端口扫描",
		"block drop quick on ! lo0 from 198.51.100.7/32 to any",
		"block drop quick on ! lo0 from any to 198.51.100.7/32",
		"# <<< atfield managed <<<",
	} {
		if !strings.Contains(second.Stdin, want) {
			t.Fatalf("规则文本缺少 %q:\n%s", want, second.Stdin)
		}
	}
	if cr.n != 0 {
		t.Fatalf("dry-run 调用了 Runner %d 次", cr.n)
	}
}

func TestPFBlockIdempotent(t *testing.T) {
	fr := &fakeRunner{}
	p := NewPF(Options{Runner: fr, Now: fixedClock()})
	tgt, _ := ParseTarget("198.51.100.7")

	if r := p.Block(context.Background(), tgt, "x", "t"); !r.OK || !r.Changed {
		t.Fatalf("首次 block 失败: %+v", r)
	}
	before := len(fr.snapshot())
	r := p.Block(context.Background(), tgt, "x", "t")
	if !r.OK || !r.Skipped || r.Changed {
		t.Fatalf("重复 block 应幂等跳过: %+v", r)
	}
	if len(fr.snapshot()) != before {
		t.Fatal("幂等路径不应再执行任何命令")
	}
}

// TestPFLoadFailureRollsBack 钉住回滚：加载失败 → 重放上一版 → 内存表不变。
func TestPFLoadFailureRollsBack(t *testing.T) {
	failOn := ""
	fr := &fakeRunner{fn: func(c Command) (string, string, error) {
		// 只让「加载含 failOn 的规则文本」失败，回滚重放（不含 failOn）放行。
		if failOn != "" && strings.Contains(c.Stdin, failOn) && strings.Contains(strings.Join(c.Args, " "), "-f -") &&
			!strings.Contains(strings.Join(c.Args, " "), "-n") {
			return "", "pfctl: Syntax error", errors.New("exit status 1")
		}
		return "", "", nil
	}}
	p := NewPF(Options{Runner: fr, Now: fixedClock()})
	ctx := context.Background()

	first, _ := ParseTarget("198.51.100.7")
	if r := p.Block(ctx, first, "ok", "t"); !r.OK {
		t.Fatalf("第一条应成功: %+v", r)
	}

	failOn = "198.51.100.9"
	second, _ := ParseTarget("198.51.100.9")
	r := p.Block(ctx, second, "bad", "t")
	if r.OK {
		t.Fatal("加载失败必须回 OK=false")
	}
	if r.Stage != "load" {
		t.Fatalf("stage=%q, 期望 load", r.Stage)
	}
	if !r.RolledBack {
		t.Fatalf("应标记已回滚: %+v", r)
	}
	calls := fr.snapshot()
	if got := p.Status(ctx).Count; got != 1 {
		t.Fatalf("失败后阻断表应仍是 1 条，实际 %d", got)
	}
	// 回滚重放的那次加载，规则文本必须是上一版（只含 .7）
	last := calls[len(calls)-1]
	if !strings.Contains(last.Stdin, "198.51.100.7/32") || strings.Contains(last.Stdin, "198.51.100.9/32") {
		t.Fatalf("回滚重放的文本不对:\n%s", last.Stdin)
	}
}

func TestPFParseStageFailure(t *testing.T) {
	fr := &fakeRunner{fn: func(c Command) (string, string, error) {
		if strings.Contains(strings.Join(c.Args, " "), "-n") {
			return "", "pfctl: parse error", errors.New("exit status 1")
		}
		return "", "", nil
	}}
	p := NewPF(Options{Runner: fr, Now: fixedClock()})
	tgt, _ := ParseTarget("198.51.100.7")
	r := p.Block(context.Background(), tgt, "", "")
	if r.OK || r.Stage != "parse" {
		t.Fatalf("语法校验失败应在 parse 阶段中止: %+v", r)
	}
	if p.Status(context.Background()).Count != 0 {
		t.Fatal("parse 失败不应写进阻断表")
	}
}

func TestPFUnblockNotPresent(t *testing.T) {
	fr := &fakeRunner{}
	p := NewPF(Options{Runner: fr, Now: fixedClock()})
	tgt, _ := ParseTarget("198.51.100.7")
	r := p.Unblock(context.Background(), tgt)
	if !r.OK || r.Removed || len(fr.snapshot()) != 0 {
		t.Fatalf("解封不存在的目标应幂等成功且不执行命令: %+v", r)
	}
}

func TestPFUnblockAndFlush(t *testing.T) {
	fr := &fakeRunner{}
	p := NewPF(Options{Runner: fr, Now: fixedClock()})
	ctx := context.Background()
	a, _ := ParseTarget("198.51.100.7")
	b, _ := ParseTarget("198.51.100.8")
	if r := p.Block(ctx, a, "", ""); !r.OK {
		t.Fatal("block a 失败")
	}
	if r := p.Block(ctx, b, "", ""); !r.OK {
		t.Fatal("block b 失败")
	}
	r := p.Unblock(ctx, a)
	if !r.OK || !r.Removed {
		t.Fatalf("解封失败: %+v", r)
	}
	last := fr.snapshot()[len(fr.snapshot())-1]
	if got := p.Status(ctx).Count; got != 1 {
		t.Fatalf("解封后应剩 1 条，实际 %d", got)
	}
	if strings.Contains(last.Stdin, "198.51.100.7/32") {
		t.Fatalf("解封后重发的规则文本仍含被解封地址:\n%s", last.Stdin)
	}
	if !strings.Contains(last.Stdin, "198.51.100.8/32") {
		t.Fatalf("解封后规则文本丢了另一条:\n%s", last.Stdin)
	}

	f := p.Flush(ctx)
	if !f.OK || f.Flushed != 1 {
		t.Fatalf("flush 结果不对: %+v", f)
	}
	if p.Status(ctx).Count != 0 {
		t.Fatal("flush 后表应为空")
	}
	if strings.Contains(fr.snapshot()[len(fr.snapshot())-1].Stdin, "block drop") {
		t.Fatal("flush 后加载的文本不应含 block 规则")
	}
}

func TestPFRollbackWithoutPrevious(t *testing.T) {
	p := NewPF(Options{Runner: &fakeRunner{}, Now: fixedClock()})
	r := p.Rollback(context.Background())
	if r.OK || r.Detail == "" {
		t.Fatalf("没有上一版时回滚必须失败并说明原因: %+v", r)
	}
}

func TestPFStatus(t *testing.T) {
	fr := &fakeRunner{fn: func(c Command) (string, string, error) {
		args := strings.Join(c.Args, " ")
		switch {
		case args == "-s Anchors":
			return "com.apple/250.ApplicationFirewall\natfield\n", "", nil
		case args == "-a atfield -s rules":
			return "block drop quick on ! lo0 from 198.51.100.7/32 to any\n" +
				"block drop quick on ! lo0 from any to 198.51.100.7/32\n", "", nil
		}
		return "", "", nil
	}}
	p := NewPF(Options{Runner: fr, Now: fixedClock()})
	st := p.Status(context.Background())
	if !st.Available || !st.Attached {
		t.Fatalf("status 解析不对: %+v", st)
	}
	if st.Rules != 2 {
		t.Fatalf("规则条数=%d, 期望 2", st.Rules)
	}
	if st.Caps.Backend != "pf" || !st.Caps.Rollback {
		t.Fatalf("caps 不对: %+v", st.Caps)
	}
}

func TestPFStatusPermissionDenied(t *testing.T) {
	fr := &fakeRunner{fn: func(Command) (string, string, error) {
		return "", "pfctl: /dev/pf: Permission denied", errors.New("exit status 1")
	}}
	p := NewPF(Options{Runner: fr, Now: fixedClock()})
	st := p.Status(context.Background())
	if st.Available {
		t.Fatal("读不到 /dev/pf 时必须 available=false")
	}
	if !strings.Contains(st.Reason, "Permission denied") {
		t.Fatalf("原因应带原始错误: %q", st.Reason)
	}
}

func TestPFMaxEntries(t *testing.T) {
	p := NewPF(Options{DryRun: true, MaxEntries: 2, Now: fixedClock()})
	ctx := context.Background()
	for _, ip := range []string{"198.51.100.1", "198.51.100.2"} {
		tgt, _ := ParseTarget(ip)
		if r := p.Block(ctx, tgt, "", ""); !r.OK {
			t.Fatalf("block %s 失败: %+v", ip, r)
		}
	}
	tgt, _ := ParseTarget("198.51.100.3")
	if r := p.Block(ctx, tgt, "", ""); r.OK {
		t.Fatal("超过 MaxEntries 应拒绝")
	}
}
