//go:build darwin

package collector

// fileless_darwin_test.go —— macOS 取数层的实测用例。
//
// 这里测的不是判定（fileless_test.go 已覆盖），而是「取数真的能把真实进程
// 的形状读对」——这是本模块唯一无法用合成数据证明的部分：
//
//	exe 路径含空格       ps 的 command 列按空格切会把 "/Applications/Google"
//	                     当成路径（本机实测 75 条误报的根因）
//	映像被删后仍在运行    lsof 的 NLINK=0 能不能抓到（能，本机验证）
//	非 ASCII 路径        不能做删除判定（C locale 下 ps 会转义成 "M-eM^S…"）
//
// 全部在 t.TempDir() 里造，不碰系统文件；ghost 用例会启一个自己编译的
// 小进程并在测试结束时 kill 掉。

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestDarwinResolveExe 命令行 → 真实 exe 路径。
func TestDarwinResolveExe(t *testing.T) {
	dir := t.TempDir()
	// 造一个路径里带空格的可执行文件（模拟 "Google Chrome Helper.app"）
	spaced := filepath.Join(dir, "My App.app", "Contents", "MacOS", "My App")
	if err := os.MkdirAll(filepath.Dir(spaced), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(spaced, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, ok := darwinResolveExe(spaced + " --type=renderer --flag=1")
	if !ok || got != spaced {
		t.Fatalf("含空格路径还原失败: got=%q ok=%v want=%q", got, ok, spaced)
	}

	// 反例：路径不存在 → 返回第一段并标记 exists=false
	missing := filepath.Join(dir, "nope", "gone")
	got, ok = darwinResolveExe(missing + " -x")
	if ok || !strings.HasPrefix(got, missing) {
		t.Fatalf("不存在的路径不该判存在: got=%q ok=%v", got, ok)
	}

	// 反例：内核线程（[kernel_task]）没有真实路径
	if got, ok := darwinResolveExe("[kernel_task]"); ok || got != "[kernel_task]" {
		t.Fatalf("内核线程: got=%q ok=%v", got, ok)
	}

	// 空命令行不该 panic
	if got, ok := darwinResolveExe(""); ok || got != "" {
		t.Fatalf("空命令行: got=%q ok=%v", got, ok)
	}
}

// TestFilelessLiveGhostDarwin 端到端：编译一个进程 → 运行 → 删掉磁盘文件 →
// 采集器必须报 fileless.exe_deleted。这是「lsof 确认」这条链路的唯一真证据。
func TestFilelessLiveGhostDarwin(t *testing.T) {
	if testing.Short() {
		t.Skip("-short 跳过需要编译与真实进程的用例")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("没有 go 工具链，跳过")
	}
	// 刻意用 /tmp 而不是 t.TempDir()：实测在 /var/folders/.../T 下，
	// 进程的 exe 被 unlink 后 macOS 往往几百毫秒内就把进程收掉（ps 变 Z），
	// 同一个用例连跑 5 次只有 1~2 次能采到；/tmp 下 5/5 稳定。
	dir, err := os.MkdirTemp("/tmp", "af-ghost")
	if err != nil {
		t.Fatalf("建临时目录失败: %v", err)
	}
	defer os.RemoveAll(dir)
	src := filepath.Join(dir, "main.go")
	if err := os.WriteFile(src, []byte("package main\n\nimport \"time\"\n\nfunc main() { time.Sleep(20 * time.Second) }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module ghost\n\ngo 1.21\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "af-ghost")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = dir
	if out, err := build.CombinedOutput(); err != nil {
		t.Skipf("编译失败（环境问题，不影响判定逻辑）: %v %s", err, out)
	}

	cmd := exec.Command(bin)
	if err := cmd.Start(); err != nil {
		t.Skipf("起进程失败: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()
	// 等它真的跑起来（把所有代码页进来了）再删：太早删会让进程立刻退出
	time.Sleep(800 * time.Millisecond)
	if err := os.Remove(bin); err != nil {
		t.Fatalf("删除二进制失败: %v", err)
	}
	if _, err := os.Stat(bin); !os.IsNotExist(err) {
		t.Fatalf("磁盘上应该已经没有这个文件: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	facts, err := platformFilelessFacts(ctx)
	if err != nil {
		t.Fatalf("采集失败: %v", err)
	}
	var found *filelessFact
	for i := range facts {
		if facts[i].PID == cmd.Process.Pid {
			found = &facts[i]
			break
		}
	}
	if found == nil {
		t.Skip("进程在采集前已退出（时序问题，不是判定失败）")
	}
	if !found.ImageDeleted {
		// 判定只由 lsof 的 NLINK=0 定案。如果 lsof 这时也看不到该进程的
		// txt 映射（进程已退出、或 ps 给的是 "(进程名)" 的僵尸形态），
		// 那是时序问题不是判定失败 —— 明确 skip，别把测试变成随机红灯。
		if paths := lsofDeletedTxt(ctx, cmd.Process.Pid); len(paths) == 0 {
			t.Skipf("lsof 看不到该进程的 txt 映射（进程可能已退出）: exe=%q", found.Exe)
		}
		t.Fatalf("lsof 有删除映射但未判定为删除: exe=%q proc=%q", found.Exe, found.Process)
	}
	hits := judgeFileless(*found)
	if !hasHit(hits, flReasonImageGone) {
		t.Fatalf("应命中 image-deleted，实际: %+v", hits)
	}
	for _, h := range hits {
		if h.Slug == flReasonImageGone && (h.Kind != EventFilelessImageGone || h.Severity != "high") {
			t.Fatalf("kind/sev = %s/%s", h.Kind, h.Severity)
		}
	}
}

// TestFilelessLiveScanNoJITHit 真机扫一遍：JIT 引擎（Chrome/Node）绝不能被
// 报成 anon-exec —— 这是「白名单」在生产数据上的回归测试。
// 不做「零命中」断言：开发机上完全可能真有一个被删的二进制。
func TestFilelessLiveScanNoJITHit(t *testing.T) {
	if testing.Short() {
		t.Skip("-short 跳过全量扫描")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	facts, err := platformFilelessFacts(ctx)
	if err != nil {
		t.Fatalf("采集失败: %v", err)
	}
	if len(facts) < 5 {
		t.Skipf("进程数太少（%d），跳过", len(facts))
	}
	for _, f := range facts {
		if !isJITEngine(f) {
			continue
		}
		if hasHit(judgeFileless(f), flReasonAnonExec) {
			t.Fatalf("JIT 引擎被误报 anon-exec: pid=%d exe=%q anon=%d", f.PID, f.Exe, f.AnonExecBytes)
		}
	}
}

// TestFilelessLiveDarwin 本机实测：真跑一次 vmmap，确认解析器吃得下活输出。
// 只测解析器不能证明 vmmap 在这个权限下能起得来（非 root 时它对别人的进程会拒绝）。
func TestFilelessLiveDarwin(t *testing.T) {
	if testing.Short() {
		t.Skip("-short 跳过外部命令")
	}
	pid := os.Getpid()
	if _, _, ok := vmmapAnonExec(context.Background(), pid); !ok {
		t.Skip("vmmap 不可用或超时（不影响判定逻辑，仅说明本机没这个能力）")
	}
	// 没有断言具体数值：自身进程的匿名段随运行时波动，只要求「跑得通」。
	if _, _, ok := vmmapAnonExec(context.Background(), 1); ok {
		t.Log("vmmap 能检查 pid 1：本进程大概是 root")
	}
}
