//go:build darwin

package collector

// realtime_darwin_test.go —— macOS 真机跑一遍三个采集器，报事件数。
//
// 这个文件存在的唯一理由是「编译通过」不算证据：session/authlog 走的是
// `who`/`last`/`log show`，integrity 走真实文件系统的 sha256，logstream 走
// `log stream` 子进程——全都是**只有在真机上才能证明接得上**的东西。
//
// 这些用例不折叠成「断言 0 事件」：本机安静时就是 0 条事件，那是对的；
// 测试只断言「不报错 + 字段完整 + 计数能打印出来」，把噪音留给 t.Logf，
// 让人肉读一眼就知道采集面通不通。
//
// 唯一的硬断言是 integrity 的「首轮 0 事件」：那条一旦红，说明基线逻辑
// 退化成「每轮全报」，是产品级故障。

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestDarwinOnceRunSummary 模拟 `atfieldd --once`：把三个采集器都构造出来、各跑
// 一轮 RunOnce，把「采集器 / 事件数 / 清点条数 / 耗时 / 不可用原因」打成一张表。
//
// 为什么不直接跑 `atfieldd --once`：本轮约束是「不改 registry」，所以这些
// 采集器还没进主程序的注册表（由主会话统一注册）。这个用例用**完全相同的
// 构造与驱动路径**（NewXxx(cfg) + collector.RunOnce），等价于注册之后
// --once 会看到的东西。
func TestDarwinOnceRunSummary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	builders := []func(Config) Collector{
		NewSession, NewAuthLog, NewIntegrity, NewLogStream,
	}
	type row struct {
		Name      string `json:"name"`
		Mode      string `json:"mode"`
		Interval  string `json:"interval"`
		Available bool   `json:"available"`
		Reason    string `json:"reason,omitempty"`
		Events    int    `json:"events"`
		Items     int    `json:"items"`
		MS        int64  `json:"ms"`
	}
	rows := make([]row, 0, len(builders))
	for _, build := range builders {
		c := build(Config{})
		b := baseOf(c)
		r := row{
			Name: c.Name(), Mode: c.Mode(), Interval: c.Interval().String(),
			Available: c.Probe() == nil,
		}
		if !r.Available {
			r.Reason = c.Probe().Error()
			rows = append(rows, r)
			continue
		}
		t0 := time.Now()
		evs := RunOnce(ctx, c, b)
		r.MS = time.Since(t0).Milliseconds()
		r.Events = len(evs)
		if ic, ok := c.(interface{ Items() int }); ok {
			r.Items = ic.Items()
		}
		rows = append(rows, r)
	}
	out, _ := json.MarshalIndent(map[string]any{"platform": Platform, "runs": rows}, "", "  ")
	t.Logf("--once 等价运行结果:\n%s", out)

	// 硬约束：四个采集器在 macOS 上都必须可用（真跑不起来的要当场红）
	for _, r := range rows {
		if !r.Available {
			t.Fatalf("%s 在 macOS 上不可用: %s", r.Name, r.Reason)
		}
	}
}

// baseOf 取出嵌入的 *Base（采集器都以值嵌入 Base）。
func baseOf(c Collector) *Base {
	switch v := c.(type) {
	case *Session:
		return &v.Base
	case *AuthLog:
		return &v.Base
	case *Integrity:
		return &v.Base
	case *LogStream:
		return &v.Base
	}
	return nil
}

// TestDarwinRealSession 真机跑 who/last，报活跃会话与历史登录条数。
func TestDarwinRealSession(t *testing.T) {
	if err := platformProbeSession(); err != nil {
		t.Fatalf("Probe 失败: %v", err)
	}
	who, err := platformWho(context.Background())
	if err != nil {
		t.Fatalf("who 失败: %v", err)
	}
	rows := parseWho(who)
	remote := 0
	for _, r := range rows {
		if r.Remote {
			remote++
		}
		t.Logf("会话: user=%q tty=%q from=%q since=%q remote=%v", r.User, r.TTY, r.From, r.Since, r.Remote)
	}
	t.Logf("who: %d 个活跃会话（其中远程 %d 个）", len(rows), remote)

	last, err := platformLast(context.Background())
	if err != nil {
		t.Fatalf("last 失败: %v", err)
	}
	hist := parseLast(last, 20)
	t.Logf("last: %d 条历史登录", len(hist))
	if len(hist) > 0 {
		t.Logf("  最近一条: %s", hist[0].Raw)
	}

	// 跑一轮完整采集：首轮必须 0 事件（只建基线），第二轮同样 0（无变化）
	s := NewSession(Config{}).(*Session)
	evs, err := s.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect 失败: %v", err)
	}
	if len(evs) != 0 {
		t.Fatalf("首轮出了 %d 条事件（不该把已有会话报成新登录）", len(evs))
	}
	evs2, err := s.Collect(context.Background())
	if err != nil {
		t.Fatalf("第二轮 Collect 失败: %v", err)
	}
	t.Logf("session 采集: 首轮 %d 事件 / 第二轮 %d 事件 / 活跃 %d 个 / 远程 %d 个",
		len(evs), len(evs2), s.Items(), s.Snapshot()["remote"])
	if len(evs2) != 0 {
		t.Logf("  第二轮有事件（会话确实变了，属正常）: %+v", evs2)
	}
}

// TestDarwinRealAuthLog 真机跑 `log show --last 5m`。
//
// 5 分钟窗口在本机绝大多数时候是 0 条（没人去敲错 sudo 密码）。
// 所以这里同时用 24h 窗口跑一次 `log show`，证明**解析链路**能把真实的
// 失败行认出来——否则「0 条」既可能是真没失败，也可能是解析全废。
func TestDarwinRealAuthLog(t *testing.T) {
	if err := platformProbeAuthLog(); err != nil {
		t.Fatalf("Probe 失败: %v", err)
	}
	a := NewAuthLog(Config{}).(*AuthLog)
	evs, err := a.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect 失败: %v", err)
	}
	t.Logf("authlog 5m 窗口: %d 条事件，失败行 %d 条", len(evs), a.Items())
	for _, ev := range evs {
		t.Logf("  %s severity=%s count=%v", ev.Kind, ev.Severity, ev.Subject["count"])
	}

	// 24h 回捞：只要历史上有过一次认证失败，解析就必须认出来
	out, err := runText(context.Background(), 40*time.Second, darwinLogPath,
		"show", "--last", "24h", "--style", "compact", "--predicate", darwinAuthPredicate)
	if err != nil {
		t.Fatalf("24h 回捞失败: %v", err)
	}
	lines := parseAuthLogText(out)
	fails := filterAuthFailLines(lines)
	t.Logf("authlog 24h 回捞: 候选 %d 行，判定为失败 %d 行", len(lines), len(fails))
	for i, l := range fails {
		if i >= 3 {
			break
		}
		t.Logf("  样本: %s", l)
	}
	if strings.TrimSpace(out) != "" && len(lines) == 0 && len(fails) == 0 {
		t.Logf("24h 窗口内没有认证失败行（本机没敲错过密码，属正常）")
	}

	// 用同一份**真实**日志喂一遍完整判定链，证明 auth.fail 事件真能产出
	// （否则「5m 窗口 0 事件」既可能是真没失败，也可能是判定链全废）
	if len(fails) > 0 {
		real := &AuthLog{window: "24h"}
		real.src = func(context.Context) ([]string, error) { return lines, nil }
		real.Init("authlog", ModePoll, time.Second, nil)
		evs, err := real.Collect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(evs) != 1 {
			t.Fatalf("24h 真实日志没产出 auth.fail 事件（%d 条）", len(evs))
		}
		t.Logf("authlog 真实事件: kind=%s severity=%s subject=%v", evs[0].Kind, evs[0].Severity, evs[0].Subject)
	}
}

// TestDarwinRealIntegrity 真机跑默认监控清单。
func TestDarwinRealIntegrity(t *testing.T) {
	paths := platformDefaultWatchPaths()
	if len(paths) == 0 {
		t.Fatal("macOS 默认监控清单为空")
	}

	// 基线写到临时目录，不污染 ~/.atfield
	stateDir := t.TempDir()
	ig := NewIntegrity(Config{Options: map[string]any{"data_dir": stateDir}}).(*Integrity)
	if err := ig.Probe(); err != nil {
		t.Fatalf("Probe 失败: %v", err)
	}
	if got := ig.Items(); got != len(paths) {
		t.Fatalf("监控条数 = %d，期望 %d", got, len(paths))
	}
	evs, err := ig.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect 失败: %v", err)
	}
	if len(evs) != 0 {
		t.Fatalf("首轮建基线却报了 %d 条: %+v", len(evs), evs)
	}

	snap := ig.Snapshot()
	rows, _ := snap["files"].([]integrityRow)
	readable := 0
	for _, r := range rows {
		if r.Exists {
			readable++
			t.Logf("  监控: %s exists=%v readable=%v digest=%s size=%d", r.Path, r.Exists, r.Readable, r.Digest, r.Size)
		}
	}
	t.Logf("integrity: 监控 %d 个文件，存在 %d 个，missing %d 个，首轮 0 事件",
		len(rows), readable, len(snap["missing"].([]string)))

	// 篡改一个真实文件（用清单里的 hosts 的**副本**，不动系统文件），
	// 验证「改了就要报」在真机上也成立
	tmp := filepath.Join(t.TempDir(), "hosts")
	data, err := os.ReadFile("/etc/hosts")
	if err != nil {
		t.Skipf("读不到 /etc/hosts，跳过篡改验证: %v", err)
	}
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		t.Fatal(err)
	}
	ig2 := NewIntegrity(Config{Options: map[string]any{
		"data_dir": t.TempDir(), "watch_paths": []any{tmp},
	}}).(*Integrity)
	if _, err := ig2.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tmp, append(data, []byte("\n10.0.0.1 attacker.example\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	evs, err = ig2.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 {
		t.Fatalf("篡改没被抓到（%d 条事件）", len(evs))
	}
	t.Logf("integrity 篡改验证: kind=%s severity=%s reason=%v",
		evs[0].Kind, evs[0].Severity, evs[0].Subject["reason"])
	return
}

// TestDarwinRealLogStream 真机跑 `log stream`，报解析到的事件数。
//
// 分两段：
//  1. 用安全相关谓词跑 6 秒，报「收到多少行原始日志」——安静机器上可能是 0 行，
//     那本身是有效信息（流接上了、系统确实安静）。
//  2. **造一条真实日志**：`/usr/bin/logger` 往系统日志写一行 "Failed password ..."，
//     谓词切到 process == "logger"，验证「真实 unified log → 解析 → 签名 → 事件」
//     这条链路端到端是通的。合成行只能证明 handleLine 能跑，证明不了
//     `log stream` 的 ndjson 字段名没变（Apple 改过字段名，DARWIN 上的
//     eventMessage/composedMessage 就是这个历史包袱）。
func TestDarwinRealLogStream(t *testing.T) {
	if err := platformProbeLogStream(); err != nil {
		t.Fatalf("Probe 失败: %v", err)
	}
	ls := NewLogStream(Config{}).(*LogStream)

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	var lines int
	src := func(ctx context.Context, sink func(string)) error {
		return platformLogSource(ctx, `process == "sudo" OR process == "sshd" OR process == "tccd" OR subsystem == "com.apple.TCC"`, func(l string) {
			lines++
			sink(l)
		})
	}
	err := src(ctx, ls.handleLine)
	// ctx 超时导致的退出不算失败：6 秒到了本来就该停
	if err != nil && ctx.Err() == nil {
		t.Fatalf("log stream 失败: %v", err)
	}
	t.Logf("logstream 6s 实跑: 收到 %d 行原始日志，命中签名 %d 条，drops %v",
		lines, ls.Items(), ls.Snapshot()["drops"])
	evs, _ := ls.Collect(context.Background())
	for i, ev := range evs {
		if i >= 5 {
			break
		}
		t.Logf("  事件: %s severity=%s process=%s msg=%q", ev.Kind, ev.Severity, ev.Process, clip(ev.Cmdline, 80))
	}

	// 第二段：真实日志注入 → 端到端验证
	loggerBin := "/usr/bin/logger"
	if _, statErr := os.Stat(loggerBin); statErr != nil {
		t.Skip("没有 /usr/bin/logger，跳过真实日志注入验证")
	}
	ls2 := &LogStream{maxRate: 40, kind: "ndjson"}
	ls2.Init("logstream", ModeStream, time.Second, nil)

	ctx2, cancel2 := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel2()

	got := make(chan int, 1)
	go func() {
		_ = platformLogSource(ctx2, `process == "logger"`, ls2.handleLine)
		got <- 1
	}()
	time.Sleep(2500 * time.Millisecond) // 等 log stream 真正挂上谓词
	if out, err := exec.Command(loggerBin, "Failed password for root from 10.0.0.9 port 40001 ssh2").CombinedOutput(); err != nil {
		t.Fatalf("logger 写入失败: %v %s", err, out)
	}
	time.Sleep(2500 * time.Millisecond)

	injected, _ := ls2.Collect(context.Background())
	t.Logf("logstream 注入验证: 命中 %d 条事件", len(injected))
	if len(injected) != 1 {
		t.Fatalf("真实注入的日志没被认成本地事件（%d 条）——ndjson 字段名或签名表出问题了", len(injected))
	}
	if injected[0].Kind != EventAuthFail || injected[0].Severity != "high" {
		t.Fatalf("注入事件的 kind/severity = %s/%s，期望 auth.fail/high",
			injected[0].Kind, injected[0].Severity)
	}
	t.Logf("  注入事件: %s severity=%s process=%s msg=%q",
		injected[0].Kind, injected[0].Severity, injected[0].Process, clip(injected[0].Cmdline, 80))
	cancel2()
	<-got
	if lines == 0 {
		t.Logf("提示：6 秒窗口内系统日志安静（0 行）属正常，端到端链路已由注入验证")
	}
}
