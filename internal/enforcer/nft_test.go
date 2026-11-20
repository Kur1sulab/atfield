package enforcer

// nft_test.go —— Linux 后端：脚手架命令、元素增删、幂等、回滚。
//
// 全部走 DryRun 或 fakeRunner；测试机是 macOS 也不会执行任何 nft 命令。

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestNFTBlockCommands(t *testing.T) {
	cr := &countingRunner{}
	n := NewNFT(Options{DryRun: true, Runner: cr, Now: fixedClock()})
	tgt, _ := ParseTarget("198.51.100.7")

	r := n.Block(context.Background(), tgt, "端口扫描", "analyst")
	if !r.OK || !r.Changed {
		t.Fatalf("dry-run block 失败: %+v", r)
	}
	// 11 条脚手架 + 1 条元素
	if len(r.Commands) != 12 {
		t.Fatalf("命令条数=%d, 期望 12", len(r.Commands))
	}
	if r.Commands[0].Bin != "/usr/sbin/nft" {
		t.Fatalf("nft 路径=%q", r.Commands[0].Bin)
	}
	// 脚手架全部是 add（幂等），且只碰 inet atfield
	for _, c := range r.Commands[:11] {
		args := strings.Join(c.Args, " ")
		if !strings.HasPrefix(args, "add ") && !strings.HasPrefix(args, "flush chain ") {
			t.Fatalf("脚手架命令既不是 add 也不是 flush chain: %q", args)
		}
		if !strings.Contains(args, "inet atfield") {
			t.Fatalf("脚手架命令越出了自己的命名空间: %q", args)
		}
	}
	last := r.Commands[11]
	if got := strings.Join(last.Args, " "); got != "add element inet atfield blocked4 { 198.51.100.7 }" {
		t.Fatalf("元素命令=%q", got)
	}
	if cr.n != 0 {
		t.Fatalf("dry-run 执行了 %d 条命令", cr.n)
	}
}

func TestNFTIPv6AndCIDR(t *testing.T) {
	cases := []struct{ in, set, elem string }{
		{"2001:db8::1", "blocked6", "2001:db8::1"},
		{"2001:db8::/48", "blocked6", "2001:db8::/48"},
		{"198.51.100.0/24", "blocked4", "198.51.100.0/24"},
		{"198.51.100.7", "blocked4", "198.51.100.7"},
	}
	for _, c := range cases {
		n := NewNFT(Options{DryRun: true, Now: fixedClock()})
		tgt, err := ParseTarget(c.in)
		if err != nil {
			t.Fatalf("ParseTarget(%q): %v", c.in, err)
		}
		r := n.Block(context.Background(), tgt, "", "")
		last := r.Commands[len(r.Commands)-1]
		want := "add element inet atfield " + c.set + " { " + c.elem + " }"
		if got := strings.Join(last.Args, " "); got != want {
			t.Fatalf("%s 的元素命令=%q, 期望 %q", c.in, got, want)
		}
	}
}

func TestNFTUnblockMissingIsIdempotent(t *testing.T) {
	fr := &fakeRunner{fn: func(c Command) (string, string, error) {
		if strings.HasPrefix(strings.Join(c.Args, " "), "delete element") {
			return "", "Error: No such file or directory", errors.New("exit status 1")
		}
		return "", "", nil
	}}
	n := NewNFT(Options{Runner: fr, Now: fixedClock()})
	ctx := context.Background()
	tgt, _ := ParseTarget("198.51.100.7")
	if r := n.Block(ctx, tgt, "", ""); !r.OK {
		t.Fatalf("block 失败: %+v", r)
	}
	r := n.Unblock(ctx, tgt)
	if !r.OK || r.Removed {
		t.Fatalf("元素本来不存在时应幂等成功且 removed=false: %+v", r)
	}
	if n.Status(ctx).Count != 0 {
		t.Fatal("幂等解封后内存表应已清理")
	}
}

func TestNFTUnblockRealError(t *testing.T) {
	fr := &fakeRunner{fn: func(c Command) (string, string, error) {
		if strings.HasPrefix(strings.Join(c.Args, " "), "delete element") {
			return "", "Error: Operation not permitted", errors.New("exit status 1")
		}
		return "", "", nil
	}}
	n := NewNFT(Options{Runner: fr, Now: fixedClock()})
	ctx := context.Background()
	tgt, _ := ParseTarget("198.51.100.7")
	if r := n.Block(ctx, tgt, "", ""); !r.OK {
		t.Fatalf("block 失败: %+v", r)
	}
	r := n.Unblock(ctx, tgt)
	if r.OK || !strings.Contains(r.Err, "Operation not permitted") {
		t.Fatalf("真错误必须上报，不能被当成「本来就没有」: %+v", r)
	}
	if n.Status(ctx).Count != 1 {
		t.Fatal("失败后条目必须留在表里")
	}
}

func TestNFTFlushDeletesTable(t *testing.T) {
	fr := &fakeRunner{}
	n := NewNFT(Options{Runner: fr, Now: fixedClock()})
	ctx := context.Background()
	tgt, _ := ParseTarget("198.51.100.7")
	if r := n.Block(ctx, tgt, "", ""); !r.OK {
		t.Fatalf("block 失败: %+v", r)
	}
	f := n.Flush(ctx)
	if !f.OK || f.Flushed != 1 {
		t.Fatalf("flush 结果不对: %+v", f)
	}
	last := fr.snapshot()[len(fr.snapshot())-1]
	if got := strings.Join(last.Args, " "); got != "delete table inet atfield" {
		t.Fatalf("flush 命令=%q", got)
	}
	if n.Status(ctx).Count != 0 {
		t.Fatal("flush 后表应为空")
	}
}

func TestNFTFlushMissingTableIdempotent(t *testing.T) {
	fr := &fakeRunner{fn: func(Command) (string, string, error) {
		return "", "Error: No such file or directory", errors.New("exit status 1")
	}}
	n := NewNFT(Options{Runner: fr, Now: fixedClock()})
	f := n.Flush(context.Background())
	if !f.OK {
		t.Fatalf("表本来就不存在时 flush 应幂等成功: %+v", f)
	}
}

func TestNFTRollbackRebuilds(t *testing.T) {
	fr := &fakeRunner{}
	n := NewNFT(Options{Runner: fr, Now: fixedClock()})
	ctx := context.Background()
	a, _ := ParseTarget("198.51.100.7")
	b, _ := ParseTarget("203.0.113.9")
	if r := n.Block(ctx, a, "", ""); !r.OK {
		t.Fatal("block a 失败")
	}
	if r := n.Block(ctx, b, "", ""); !r.OK {
		t.Fatal("block b 失败")
	}
	before := len(fr.snapshot())
	r := n.Rollback(ctx)
	if !r.OK {
		t.Fatalf("回滚失败: %+v", r)
	}
	calls := fr.snapshot()[before:]
	var adds []string
	for _, c := range calls {
		if strings.HasPrefix(strings.Join(c.Args, " "), "add element") {
			adds = append(adds, strings.Join(c.Args, " "))
		}
	}
	if len(adds) != 2 {
		t.Fatalf("回滚应重放 2 条元素，实际 %d: %v", len(adds), adds)
	}
	if !strings.Contains(adds[0], "198.51.100.7") || !strings.Contains(adds[1], "203.0.113.9") {
		t.Fatalf("回滚重放的元素不对: %v", adds)
	}
	// 回滚前必须有 flush set，否则会残留脏元素
	var flushed int
	for _, c := range calls {
		if strings.HasPrefix(strings.Join(c.Args, " "), "flush set") {
			flushed++
		}
	}
	if flushed != 2 {
		t.Fatalf("回滚应清空两个 set，实际 %d 次 flush set", flushed)
	}
}

func TestNFTRollbackWithoutPrevious(t *testing.T) {
	n := NewNFT(Options{Runner: &fakeRunner{}, Now: fixedClock()})
	if r := n.Rollback(context.Background()); r.OK {
		t.Fatal("没有上一版时回滚必须失败")
	}
}

func TestNFTStatus(t *testing.T) {
	fr := &fakeRunner{fn: func(c Command) (string, string, error) {
		if strings.Join(c.Args, " ") == "list table inet atfield" {
			return "table inet atfield {\n\tchain in {\n\t\tip saddr @blocked4 drop\n\t}\n}\n", "", nil
		}
		return "", "", nil
	}}
	n := NewNFT(Options{Runner: fr, Now: fixedClock()})
	st := n.Status(context.Background())
	if !st.Available || !st.Attached {
		t.Fatalf("status 不对: %+v", st)
	}
	if st.Rules != 1 {
		t.Fatalf("drop 规则条数=%d, 期望 1", st.Rules)
	}
}

func TestNFTStatusMissingTableIsAvailable(t *testing.T) {
	fr := &fakeRunner{fn: func(Command) (string, string, error) {
		return "", "Error: No such file or directory", errors.New("exit status 1")
	}}
	n := NewNFT(Options{Runner: fr, Now: fixedClock()})
	st := n.Status(context.Background())
	if !st.Available {
		t.Fatal("表不存在 = 没有阻断，不该判定后端不可用")
	}
	if st.Count != 0 || !strings.Contains(st.Reason, "尚未创建") {
		t.Fatalf("status 说明不对: %+v", st)
	}
}

func TestNFTCapsHonest(t *testing.T) {
	c := NewNFT(Options{DryRun: true}).Caps()
	if c.Persist {
		t.Fatal("nft 规则重启即丢，Persist 必须为 false")
	}
	if !c.Rollback || !c.Flush || !c.IPv6 || !c.CIDR {
		t.Fatalf("caps 声明不全: %+v", c)
	}
	if c.Note == "" {
		t.Fatal("能力限制必须写进 Note")
	}
}
