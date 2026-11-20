package enforcer

// enforcer_test.go —— 执行层公共契约测试：目标校验、阻断表、幂等、并发、
// 以及「dry-run 绝不执行任何命令」这条最重要的不变式。
//
// 测试原则：**没有一个用例会碰本机防火墙**。要么走 DryRun，要么给一个
// fakeRunner 把命令截下来断言。真执行只在生产由 ExecRunner 承担。

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeRunner 记录命令，可按需注入失败。绝不执行任何东西。
type fakeRunner struct {
	mu    sync.Mutex
	calls []Command
	// fn 返回 (stdout, stderr, err)；nil 表示一律成功。
	fn func(c Command) (string, string, error)
}

func (f *fakeRunner) Run(_ context.Context, c Command) (string, string, error) {
	f.mu.Lock()
	f.calls = append(f.calls, c)
	f.mu.Unlock()
	if f.fn != nil {
		return f.fn(c)
	}
	return "", "", nil
}

func (f *fakeRunner) snapshot() []Command {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Command, len(f.calls))
	copy(out, f.calls)
	return out
}

// countingRunner 只数调用次数，用来钉死「dry-run 零执行」。
type countingRunner struct{ n int64 }

func (c *countingRunner) Run(context.Context, Command) (string, string, error) {
	atomic.AddInt64(&c.n, 1)
	return "", "", nil
}

func fixedClock() func() time.Time {
	t := time.Date(2026, 11, 21, 2, 30, 0, 0, time.FixedZone("CST", 8*3600))
	return func() time.Time { return t }
}

func TestParseTarget(t *testing.T) {
	ok := []struct{ in, key string }{
		{"198.51.100.7", "198.51.100.7/32"},
		{"198.51.100.0/24", "198.51.100.0/24"},
		{"2001:db8::1", "2001:db8::1/128"},
		{"2001:db8::/48", "2001:db8::/48"},
		{"  198.51.100.7  ", "198.51.100.7/32"},
		// 主机位非零的 CIDR 要被归一化（与 Python strict=False 同口径）
		{"198.51.100.7/24", "198.51.100.0/24"},
	}
	for _, c := range ok {
		got, err := ParseTarget(c.in)
		if err != nil {
			t.Fatalf("ParseTarget(%q) 意外失败: %v", c.in, err)
		}
		if got.Key() != c.key {
			t.Fatalf("ParseTarget(%q).Key()=%q, 期望 %q", c.in, got.Key(), c.key)
		}
	}

	bad := []struct{ in, want string }{
		{"", "为空"},
		{"not-an-ip", "不是合法"},
		{"127.0.0.1", "回环"},
		{"::1", "回环"},
		{"0.0.0.0", "全零"},
		{"::", "全零"},
		{"224.0.0.1", "组播"},
		{"192.0.0.0/6", "网段过大"},
		{"2001:db8::/8", "网段过大"},
		{strings.Repeat("9", 80), "过长"},
	}
	for _, c := range bad {
		_, err := ParseTarget(c.in)
		if err == nil {
			t.Fatalf("ParseTarget(%q) 应当被拒绝", c.in)
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Fatalf("ParseTarget(%q) 错误信息=%q, 期望包含 %q", c.in, err.Error(), c.want)
		}
	}
}

func TestTableBasics(t *testing.T) {
	tb := NewTable()
	if tb.Len() != 0 {
		t.Fatal("新表应为空")
	}
	if !tb.Put("a", Entry{Reason: "r"}) {
		t.Fatal("首次 Put 应返回新增")
	}
	if tb.Put("a", Entry{Reason: "r2"}) {
		t.Fatal("重复 Put 应返回 false")
	}
	if e, ok := tb.Get("a"); !ok || e.Reason != "r2" {
		t.Fatalf("Get 拿到的条目不对: %+v %v", e, ok)
	}
	if !tb.Delete("a") || tb.Delete("a") {
		t.Fatal("Delete 语义不对")
	}
	tb.Put("b", Entry{})
	tb.Put("c", Entry{})
	if got := strings.Join(tb.Keys(), ","); got != "b,c" {
		t.Fatalf("Keys 顺序=%q, 期望 b,c", got)
	}
	if n := tb.Clear(); n != 2 {
		t.Fatalf("Clear 返回 %d, 期望 2", n)
	}
	if tb.Len() != 0 {
		t.Fatal("Clear 后应为空")
	}
}

// TestDryRunNeverExecutes 是整包最重要的一条测试：三个后端、五种操作，
// dry-run 下 Runner 的调用次数必须恒为 0。
func TestDryRunNeverExecutes(t *testing.T) {
	ctx := context.Background()
	tgt, err := ParseTarget("198.51.100.7")
	if err != nil {
		t.Fatal(err)
	}
	for _, goos := range []string{"darwin", "linux", "windows"} {
		cr := &countingRunner{}
		b := NewFor(goos, Options{DryRun: true, Runner: cr, Now: fixedClock()})

		if r := b.Block(ctx, tgt, "test", "tester"); !r.OK {
			t.Fatalf("%s: dry-run block 失败: %+v", goos, r)
		}
		if r := b.Block(ctx, tgt, "test", "tester"); !r.Skipped {
			t.Fatalf("%s: 第二次 block 应幂等跳过: %+v", goos, r)
		}
		if r := b.Unblock(ctx, tgt); !r.OK {
			t.Fatalf("%s: dry-run unblock 失败: %+v", goos, r)
		}
		if r := b.Flush(ctx); !r.OK {
			t.Fatalf("%s: dry-run flush 失败: %+v", goos, r)
		}
		_ = b.Rollback(ctx)
		st := b.Status(ctx)
		if !st.Available {
			t.Fatalf("%s: dry-run status 应 available: %+v", goos, st)
		}
		if n := atomic.LoadInt64(&cr.n); n != 0 {
			t.Fatalf("%s: dry-run 执行了 %d 条命令，必须是 0", goos, n)
		}
	}
}

func TestBlockTableFull(t *testing.T) {
	b := NewPF(Options{DryRun: true, MaxEntries: 1, Now: fixedClock()})
	ctx := context.Background()
	a, _ := ParseTarget("198.51.100.1")
	c, _ := ParseTarget("198.51.100.2")
	if r := b.Block(ctx, a, "", ""); !r.OK {
		t.Fatalf("第一条应成功: %+v", r)
	}
	r := b.Block(ctx, c, "", "")
	if r.OK || !strings.Contains(r.Detail, "已满") {
		t.Fatalf("超上限应拒绝: %+v", r)
	}
}

// TestConcurrentBlockSameTarget 钉住「并发封同一个地址只下发一次」。
func TestConcurrentBlockSameTarget(t *testing.T) {
	for _, goos := range []string{"darwin", "linux", "windows"} {
		fr := &fakeRunner{}
		b := NewFor(goos, Options{Runner: fr, Now: fixedClock()})
		tgt, _ := ParseTarget("198.51.100.7")

		var wg sync.WaitGroup
		var applied int64
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if r := b.Block(context.Background(), tgt, "race", "t"); r.OK && r.Changed {
					atomic.AddInt64(&applied, 1)
				}
			}()
		}
		wg.Wait()
		if applied != 1 {
			t.Fatalf("%s: 并发封禁实际下发 %d 次，期望 1 次", goos, applied)
		}
		if b.Status(context.Background()).Count != 1 {
			t.Fatalf("%s: 阻断表应只有 1 条", goos)
		}
	}
}

func TestUnsupportedPlatform(t *testing.T) {
	b := NewFor("plan9", Options{DryRun: true})
	if b.Name() != "unsupported" {
		t.Fatalf("后端名=%q", b.Name())
	}
	st := b.Status(context.Background())
	if st.Available || st.Reason == "" {
		t.Fatalf("未支持平台必须 available=false 且给原因: %+v", st)
	}
	tgt, _ := ParseTarget("198.51.100.7")
	r := b.Block(context.Background(), tgt, "", "")
	if r.OK || !r.Unsupported {
		t.Fatalf("未支持平台 block 应失败并标 unsupported: %+v", r)
	}
}

func TestNewPicksPlatform(t *testing.T) {
	cases := map[string]string{
		"darwin": "pf", "linux": "nftables", "windows": "netsh", "freebsd": "unsupported",
	}
	for goos, want := range cases {
		if got := NewFor(goos, Options{DryRun: true}).Name(); got != want {
			t.Fatalf("NewFor(%q)=%q, 期望 %q", goos, got, want)
		}
	}
}

func TestCleanReason(t *testing.T) {
	cases := map[string]string{
		"port scan":              "port scan",
		"a#b":                    "a＃b",
		"line1\nline2":           "line1line2",
		"tab\there":              "tab here",
		"  空格  ":                 "空格",
		strings.Repeat("长", 300): strings.Repeat("长", 180),
	}
	for in, want := range cases {
		if got := cleanReason(in); got != want {
			t.Fatalf("cleanReason(%q)=%q, 期望 %q", in, got, want)
		}
	}
}

func TestRunnerErrorSurfaces(t *testing.T) {
	fr := &fakeRunner{fn: func(Command) (string, string, error) {
		return "", "permission denied", errors.New("exit status 1")
	}}
	b := NewPF(Options{Runner: fr, Now: fixedClock()})
	tgt, _ := ParseTarget("198.51.100.7")
	r := b.Block(context.Background(), tgt, "", "")
	if r.OK {
		t.Fatal("执行失败必须回 OK=false")
	}
	if !strings.Contains(r.Detail, "permission denied") {
		t.Fatalf("失败详情应带 stderr: %+v", r)
	}
	if b.Status(context.Background()).Count != 0 {
		t.Fatal("失败后阻断表不应留下条目")
	}
}
