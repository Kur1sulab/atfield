package enforcer

// netsh_test.go —— Windows 降级路径：规则命名、命令构造、幂等、能力边界。
//
// 测试机不是 Windows 也无所谓：这一层只构造命令行，不调用任何 Windows API。

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestNetshBlockCommands(t *testing.T) {
	cr := &countingRunner{}
	w := NewNetsh(Options{DryRun: true, Runner: cr, Now: fixedClock()})
	tgt, _ := ParseTarget("198.51.100.7")

	r := w.Block(context.Background(), tgt, "端口扫描", "analyst")
	if !r.OK || !r.Changed {
		t.Fatalf("dry-run block 失败: %+v", r)
	}
	if len(r.Commands) != 2 {
		t.Fatalf("应构造 2 条规则（入向+出向），实际 %d", len(r.Commands))
	}
	in := strings.Join(r.Commands[0].Args, " ")
	wantIn := "advfirewall firewall add rule name=atfield-in-198.51.100.7_32 dir=in action=block " +
		"remoteip=198.51.100.7/32 profile=any enable=yes"
	if in != wantIn {
		t.Fatalf("入向命令:\n got %q\nwant %q", in, wantIn)
	}
	out := strings.Join(r.Commands[1].Args, " ")
	if !strings.Contains(out, "name=atfield-out-198.51.100.7_32") || !strings.Contains(out, "dir=out") {
		t.Fatalf("出向命令=%q", out)
	}
	if cr.n != 0 {
		t.Fatalf("dry-run 执行了 %d 条命令", cr.n)
	}
}

func TestNetshRuleNameSanitized(t *testing.T) {
	cases := map[string]string{
		"198.51.100.7/32": "atfield-in-198.51.100.7_32",
		"198.51.100.0/24": "atfield-in-198.51.100.0_24",
		"2001:db8::1/128": "atfield-in-2001_db8__1_128",
		"2001:db8::/48":   "atfield-in-2001_db8___48",
	}
	for key, want := range cases {
		if got := ruleName("in", key); got != want {
			t.Fatalf("ruleName(in, %q)=%q, 期望 %q", key, got, want)
		}
	}
	// 名字里不允许出现 '/'（命令行引用会变脆）
	if strings.Contains(ruleName("out", "198.51.100.0/24"), "/") {
		t.Fatal("规则名不应含 '/'")
	}
}

func TestNetshAlreadyExistsIsIdempotent(t *testing.T) {
	fr := &fakeRunner{fn: func(Command) (string, string, error) {
		return "", "A rule with that name already exists.", errors.New("exit status 1")
	}}
	w := NewNetsh(Options{Runner: fr, Now: fixedClock()})
	tgt, _ := ParseTarget("198.51.100.7")
	r := w.Block(context.Background(), tgt, "", "")
	if !r.OK {
		t.Fatalf("规则已存在应视为已达成: %+v", r)
	}
	if w.Status(context.Background()).Count != 1 {
		t.Fatal("应记进内存表")
	}
}

func TestNetshBlockRealError(t *testing.T) {
	fr := &fakeRunner{fn: func(Command) (string, string, error) {
		return "", "The service cannot accept control messages at this time.", errors.New("exit status 1")
	}}
	w := NewNetsh(Options{Runner: fr, Now: fixedClock()})
	tgt, _ := ParseTarget("198.51.100.7")
	r := w.Block(context.Background(), tgt, "", "")
	if r.OK || !strings.Contains(r.Err, "cannot accept control") {
		t.Fatalf("真错误必须上报: %+v", r)
	}
	if w.Status(context.Background()).Count != 0 {
		t.Fatal("失败不应写进内存表")
	}
}

func TestNetshUnblockCommands(t *testing.T) {
	fr := &fakeRunner{}
	w := NewNetsh(Options{Runner: fr, Now: fixedClock()})
	ctx := context.Background()
	tgt, _ := ParseTarget("198.51.100.7")
	if r := w.Block(ctx, tgt, "", ""); !r.OK {
		t.Fatal("block 失败")
	}
	before := len(fr.snapshot())
	r := w.Unblock(ctx, tgt)
	if !r.OK || !r.Removed {
		t.Fatalf("unblock 失败: %+v", r)
	}
	calls := fr.snapshot()[before:]
	if len(calls) != 2 {
		t.Fatalf("解封应删 2 条规则，实际 %d", len(calls))
	}
	first := strings.Join(calls[0].Args, " ")
	want := "advfirewall firewall delete rule name=atfield-in-198.51.100.7_32 dir=in"
	if first != want {
		t.Fatalf("删除命令:\n got %q\nwant %q", first, want)
	}
}

func TestNetshUnblockMissingRuleIdempotent(t *testing.T) {
	fr := &fakeRunner{fn: func(c Command) (string, string, error) {
		if strings.Contains(strings.Join(c.Args, " "), "delete") {
			return "", "No rules match the specified criteria.", errors.New("exit status 1")
		}
		return "", "", nil
	}}
	w := NewNetsh(Options{Runner: fr, Now: fixedClock()})
	ctx := context.Background()
	tgt, _ := ParseTarget("198.51.100.7")
	if r := w.Block(ctx, tgt, "", ""); !r.OK {
		t.Fatal("block 失败")
	}
	r := w.Unblock(ctx, tgt)
	if !r.OK {
		t.Fatalf("规则本来不存在应幂等成功: %+v", r)
	}
	if w.Status(ctx).Count != 0 {
		t.Fatal("应已从内存表移除")
	}
}

func TestNetshRollbackUnsupported(t *testing.T) {
	w := NewNetsh(Options{Runner: &fakeRunner{}, Now: fixedClock()})
	r := w.Rollback(context.Background())
	if r.OK || !r.Unsupported {
		t.Fatalf("netsh 必须明确拒绝回滚: %+v", r)
	}
	if !strings.Contains(r.Detail, "无事务") {
		t.Fatalf("拒绝理由要写清楚: %q", r.Detail)
	}
	if w.Caps().Rollback {
		t.Fatal("Caps.Rollback 必须为 false，不能声明做不到的能力")
	}
}

func TestNetshFlushKnownEntries(t *testing.T) {
	fr := &fakeRunner{}
	w := NewNetsh(Options{Runner: fr, Now: fixedClock()})
	ctx := context.Background()
	for _, ip := range []string{"198.51.100.7", "203.0.113.9"} {
		tgt, _ := ParseTarget(ip)
		if r := w.Block(ctx, tgt, "", ""); !r.OK {
			t.Fatalf("block %s 失败", ip)
		}
	}
	f := w.Flush(ctx)
	if !f.OK || f.Flushed != 2 {
		t.Fatalf("flush 结果不对: %+v", f)
	}
	if !strings.Contains(f.Detail, "手工") {
		t.Fatalf("必须提示历史残留要手工清理: %q", f.Detail)
	}
	if w.Status(ctx).Count != 0 {
		t.Fatal("flush 后内存表应为空")
	}
}

func TestNetshStatusCountsRules(t *testing.T) {
	fr := &fakeRunner{fn: func(Command) (string, string, error) {
		return "Rule Name: atfield-in-198.51.100.7_32\n---\nRule Name: atfield-out-198.51.100.7_32\n", "", nil
	}}
	w := NewNetsh(Options{Runner: fr, Now: fixedClock()})
	st := w.Status(context.Background())
	if !st.Available {
		t.Fatalf("status 应 available: %+v", st)
	}
	if st.Rules != 2 {
		t.Fatalf("规则数=%d, 期望 2", st.Rules)
	}
	if st.Caps.Backend != "netsh" || st.Caps.Persist != true {
		t.Fatalf("caps 不对: %+v", st.Caps)
	}
}
