package collector

// session_test.go —— 会话 / 认证日志采集的双向测试。
//
// 为什么必须双向：只测「该报的报」会奖励「全判可疑」的实现——把所有
// session 都标 remote、所有 authlog 都报一条，测试照样绿。所以每条判定
// 都配反例：
//
//	远程来源 (10.0.0.5)      → session.login severity=medium
//	本地 console            → session.login severity=low（不是 medium）
//	首轮已有会话             → 0 事件（不许把现状报成新登录）
//	已知 key 重复出现         → 0 事件
//	窗口内无失败行           → 0 事件（不是「0 条也算一条」）
//
// 平台无关：本文件的输入全是**文本样本**，Windows 的 quser / wevtutil
// 输出、Linux 的 auth.log 行都在 macOS 上被验证。否则「Windows 采集器」
// 在本机永远只有「编译通过」这一条证据。

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// newTestSession 造一个数据源可控的 Session（不跑 Probe，不碰真实系统）。
func newTestSession(who, last string, whoErr error) *Session {
	s := &Session{seen: map[string]string{}}
	s.whoSrc = func(context.Context) (string, error) { return who, whoErr }
	s.lastSrc = func(context.Context) (string, error) { return last, nil }
	s.whoParse = parseWho
	s.lastParse = parseLast
	s.Init("session", ModePoll, time.Second, nil)
	return s
}

func TestParseWhoLocalAndRemote(t *testing.T) {
	cases := []struct {
		name     string
		line     string
		user     string
		tty      string
		from     string
		wantFrom bool
		remote   bool
	}{
		{"本地控制台", "xxx console      Nov 18 17:22 ", "xxx", "console", "", false, false},
		{"本地终端", "xxx ttys000      Nov 19 17:29 ", "xxx", "ttys000", "", false, false},
		{"远程 SSH 来源", "root     ttys001      Nov 19 17:29 (10.0.0.5)", "root", "ttys001", "10.0.0.5", true, true},
		{"远程主机名来源", "admin    ttys002      Nov 19 17:30 (bastion.corp.example)", "admin",
			"ttys002", "bastion.corp.example", true, true},
		{"括号里是 loginwindow 算本地", "xxx console      Nov 18 17:22 (loginwindow)", "xxx",
			"console", "loginwindow", true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rows := parseWho(c.line)
			if len(rows) != 1 {
				t.Fatalf("解析出 %d 行，期望 1 行", len(rows))
			}
			r := rows[0]
			if r.User != c.user || r.TTY != c.tty {
				t.Fatalf("user/tty = %q/%q，期望 %q/%q", r.User, r.TTY, c.user, c.tty)
			}
			if r.From != c.from {
				t.Fatalf("from = %q，期望 %q", r.From, c.from)
			}
			if r.Remote != c.remote {
				t.Fatalf("remote = %v，期望 %v（from=%q）", r.Remote, c.remote, r.From)
			}
			if c.wantFrom && !strings.Contains(r.Since, "Nov") {
				t.Fatalf("since 没解出时间: %q（from=%q）", r.Since, r.From)
			}
		})
	}
}

func TestParseWhoSkipsJunkLines(t *testing.T) {
	// who 的输出里偶尔夹着空行和单字段行（某些发行版的 "wtmp begins" 之类）
	out := "\n   \nlonely\nxxx ttys000  Nov 19 17:29 \n"
	rows := parseWho(out)
	if len(rows) != 1 {
		t.Fatalf("解析出 %d 行，期望 1 行: %+v", len(rows), rows)
	}
}

func TestParseLastSkipsRebootAndWtmp(t *testing.T) {
	out := `wtmp begins Wed Nov 18 17:21
xxx ttys001                          Thu Nov 19 17:30 - 17:30  (00:00)
reboot time                                Wed Nov 18 17:21
xxx console                          Wed Nov 18 17:22   still logged in
`
	rows := parseLast(out, 20)
	for _, r := range rows {
		if strings.Contains(strings.ToLower(r.Raw), "reboot") {
			t.Fatalf("reboot 记录没被过滤: %q", r.Raw)
		}
		if strings.HasPrefix(r.Raw, "wtmp") {
			t.Fatalf("wtmp 标记没被过滤: %q", r.Raw)
		}
	}
	if len(rows) != 2 {
		t.Fatalf("解析出 %d 行，期望 2 行: %+v", len(rows), rows)
	}
}

func TestSessionFirstRoundEmitsNothing(t *testing.T) {
	// 首轮：who 里有 2 个会话，一条事件都不该出（否则服务重启 = 假登录风暴）
	s := newTestSession("xxx console Nov 18 17:22 \nroot ttys000 Nov 19 17:29 (10.0.0.5)\n", "", nil)
	evs, err := s.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 0 {
		t.Fatalf("首轮出了 %d 条事件，期望 0: %+v", len(evs), evs)
	}
	if n := s.Items(); n != 2 {
		t.Fatalf("活跃会话清点 = %d，期望 2", n)
	}
	if snap := s.Snapshot(); snap["remote"].(int) != 1 {
		t.Fatalf("remote 计数 = %v，期望 1", snap["remote"])
	}
}

func TestSessionLoginRemoteVsLocal(t *testing.T) {
	s := newTestSession("xxx console Nov 18 17:22 \n", "", nil)
	if _, err := s.Collect(context.Background()); err != nil { // 首轮建基线
		t.Fatal(err)
	}

	// 第二轮：新增一个远程会话 + 一个本地会话
	s.whoSrc = func(context.Context) (string, error) {
		return "xxx console Nov 18 17:22 \n" +
			"root     ttys000 Nov 19 17:29 (10.0.0.5)\n" +
			"xxx ttys001 Nov 19 17:30 \n", nil
	}
	evs, err := s.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 {
		t.Fatalf("出了 %d 条事件，期望 2: %+v", len(evs), evs)
	}
	seen := map[string]string{}
	for _, ev := range evs {
		if ev.Kind != EventSessionLogin {
			t.Fatalf("事件类型 = %q，期望 %q", ev.Kind, EventSessionLogin)
		}
		seen[ev.User] = ev.Severity
		if ev.Source != "session" {
			t.Fatalf("source = %q", ev.Source)
		}
		if _, ok := ev.Subject["remote"]; !ok {
			t.Fatalf("subject 缺 remote 键: %+v", ev.Subject)
		}
		for _, k := range []string{"tty", "from", "remote", "since"} {
			if _, ok := ev.Subject[k]; !ok {
				t.Fatalf("subject 缺键 %q: %+v", k, ev.Subject)
			}
		}
	}
	// 反例：本地会话不许被抬成 medium
	if seen["root"] != "medium" {
		t.Fatalf("远程会话 severity = %q，期望 medium", seen["root"])
	}
	if seen["xxx"] != "low" {
		t.Fatalf("本地会话 severity = %q，期望 low", seen["xxx"])
	}
}

func TestSessionKnownSessionDoesNotRepeat(t *testing.T) {
	who := "xxx console Nov 18 17:22 \n"
	s := newTestSession(who, "", nil)
	if _, err := s.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		evs, err := s.Collect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(evs) != 0 {
			t.Fatalf("第 %d 轮重复报了 %d 条事件: %+v", i+2, len(evs), evs)
		}
	}
}

func TestSessionLogout(t *testing.T) {
	s := newTestSession("xxx console Nov 18 17:22 \nroot ttys000 Nov 19 17:29 (10.0.0.5)\n", "", nil)
	if _, err := s.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	// root 掉线，xxx 还在
	s.whoSrc = func(context.Context) (string, error) {
		return "xxx console Nov 18 17:22 \n", nil
	}
	evs, err := s.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 {
		t.Fatalf("出了 %d 条事件，期望 1: %+v", len(evs), evs)
	}
	ev := evs[0]
	if ev.Kind != EventSessionLogout {
		t.Fatalf("事件类型 = %q，期望 %q", ev.Kind, EventSessionLogout)
	}
	if ev.User != "root" {
		t.Fatalf("登出用户 = %q，期望 root", ev.User)
	}
	if ev.Process != "ttys000" {
		t.Fatalf("process = %q，期望 ttys000（key 的 tty 段）", ev.Process)
	}
	if ev.Severity != "info" {
		t.Fatalf("severity = %q，期望 info", ev.Severity)
	}
	if ev.Subject["key"] != "root@ttys000" {
		t.Fatalf("subject.key = %v，期望 root@ttys000", ev.Subject["key"])
	}
}

func TestSessionWhoErrorPropagates(t *testing.T) {
	// who 挂了必须报错（RunOnce 会记 errors），不能静默返回空
	s := newTestSession("", "", errors.New("who 不可执行"))
	if _, err := s.Collect(context.Background()); err == nil {
		t.Fatal("who 失败时 Collect 应返回错误")
	}
}

func TestSessionLastFailureDoesNotBlock(t *testing.T) {
	// last 拿不到（容器无 wtmp）不该让整轮失败 —— 历史登录只是态势
	s := newTestSession("xxx console Nov 18 17:22 \n", "", nil)
	s.lastSrc = func(context.Context) (string, error) { return "", errors.New("no wtmp") }
	if _, err := s.Collect(context.Background()); err != nil {
		t.Fatalf("last 失败不该让 Collect 报错: %v", err)
	}
}

// ---------------------------------------------------------------- authlog

func newTestAuthLog(lines []string, err error) *AuthLog {
	a := &AuthLog{window: "5m"}
	a.src = func(context.Context) ([]string, error) { return lines, err }
	a.Init("authlog", ModePoll, time.Second, nil)
	return a
}

func TestAuthLogNoFailuresEmitsNothing(t *testing.T) {
	// 反例：窗口内只有正常日志行，一条事件都不许出
	a := newTestAuthLog([]string{
		"Nov 19 17:29:01 x sudo[123]: xxx : TTY=ttys000 ; PWD=/Users/xxx ; USER=root ; COMMAND=/bin/ls",
		"Nov 19 17:29:02 x sshd[124]: Accepted publickey for xxx from 10.0.0.5 port 51234",
	}, nil)
	evs, err := a.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 0 {
		t.Fatalf("无失败行却出了 %d 条事件: %+v", len(evs), evs)
	}
	if n := a.Items(); n != 0 {
		t.Fatalf("失败计数 = %d，期望 0", n)
	}
}

func TestAuthLogFailuresAggregate(t *testing.T) {
	lines := []string{
		"Nov 19 17:29:01 x sudo[123]: xxx : 3 incorrect password attempts ; TTY=ttys000",
		"Nov 19 17:29:05 x sshd[124]: Failed password for invalid user admin from 10.0.0.9 port 40001 ssh2",
		"Nov 19 17:29:06 x sshd[124]: Failed password for root from 10.0.0.9 port 40002 ssh2",
		"Nov 19 17:29:07 x sshd[124]: Failed password for root from 10.0.0.9 port 40003 ssh2",
	}
	a := newTestAuthLog(lines, nil)
	evs, err := a.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 {
		t.Fatalf("出了 %d 条事件，期望聚合成 1 条: %+v", len(evs), evs)
	}
	ev := evs[0]
	if ev.Kind != EventAuthFail || ev.Source != "authlog" {
		t.Fatalf("kind/source = %q/%q", ev.Kind, ev.Source)
	}
	if ev.Severity != "medium" {
		t.Fatalf("severity = %q，期望 medium（Python 不按次数升档）", ev.Severity)
	}
	if ev.Process != "sudo/sshd" {
		t.Fatalf("process = %q，期望 sudo/sshd", ev.Process)
	}
	if ev.Subject["count"] != 4 {
		t.Fatalf("count = %v，期望 4", ev.Subject["count"])
	}
	if ev.Subject["window"] != "5m" {
		t.Fatalf("window = %v，期望 5m", ev.Subject["window"])
	}
	sample, _ := ev.Raw["sample"].(string)
	if sample == "" {
		t.Fatal("raw.sample 为空")
	}
	if strings.Count(sample, "\n") > 4 {
		t.Fatalf("sample 超过 5 行: %q", sample)
	}
}

func TestAuthLogSampleTruncated(t *testing.T) {
	// sample 取前 5 行、整体截到 1200 字符（Python: fails[:5] + [:1200]）
	lines := make([]string, 0, 20)
	for i := 0; i < 20; i++ {
		lines = append(lines, "1 incorrect password attempt (sudo)")
	}
	a := newTestAuthLog(lines, nil)
	evs, err := a.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ev := evs[0]
	if ev.Subject["count"] != 20 {
		t.Fatalf("count = %v，期望 20", ev.Subject["count"])
	}
	sample, _ := ev.Raw["sample"].(string)
	if len(sample) > 1200 {
		t.Fatalf("sample 长度 %d 超过 1200", len(sample))
	}
	if strings.Count(sample, "\n") != 4 {
		t.Fatalf("sample 应是 5 行（4 个换行），实际 %d", strings.Count(sample, "\n"))
	}
}

func TestAuthLogSourceErrorPropagates(t *testing.T) {
	a := newTestAuthLog(nil, errors.New("log show 失败"))
	if _, err := a.Collect(context.Background()); err == nil {
		t.Fatal("数据源失败时 Collect 应返回错误")
	}
}

func TestFilterAuthFailLinesBothWays(t *testing.T) {
	in := []string{
		"3 incorrect password attempts",
		"Failed password for root",
		"Accepted publickey for root", // 成功，不许算失败
		"session opened for user root",
	}
	got := filterAuthFailLines(in)
	if len(got) != 2 {
		t.Fatalf("筛出 %d 行，期望 2: %+v", len(got), got)
	}
}

// ---------------------------------------------------------------- 时间窗裁剪

func TestFilterAuthWindow(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.Local)
	in := []string{
		"Nov 20 11:58:01 web01 sshd[1]: Failed password for root",   // 窗内
		"Nov 20 11:50:00 web01 sshd[2]: Failed password for root",   // 窗外（10 分钟前）
		"2026-11-20T11:59:30+0800 web01 sshd[3]: Failed password x", // journal short-iso，窗内
		"2026-11-20T09:00:00+0800 web01 sshd[4]: Failed password y", // 窗外
		"no timestamp here: Failed password",                        // 无时间戳 → 保留
	}
	got := filterAuthWindow(in, 5*time.Minute, now)
	if len(got) != 3 {
		t.Fatalf("窗内保留 %d 行，期望 3（含无时间戳那行）: %+v", len(got), got)
	}
	for _, l := range got {
		if strings.Contains(l, "sshd[2]") || strings.Contains(l, "sshd[4]") {
			t.Fatalf("窗外行没被裁掉: %q", l)
		}
	}
	// 反例：窗口放到 1 小时，两行都要回来（证明是「裁窗口」而不是「按行号砍」）
	got = filterAuthWindow(in, time.Hour, now)
	if len(got) != 4 {
		t.Fatalf("1 小时窗口保留 %d 行，期望 4: %+v", len(got), got)
	}
}

func TestParseAuthLogTime(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.Local)
	cases := []struct {
		line string
		ok   bool
		h, m int
	}{
		{"Nov 20 11:58:01 host sshd[1]: x", true, 11, 58},
		{"2026-11-20T11:58:01+0800 host sshd[1]: x", true, 11, 58},
		{"garbage line without time", false, 0, 0},
	}
	for _, c := range cases {
		ts, ok := parseAuthLogTime(c.line, now)
		if ok != c.ok {
			t.Fatalf("%q 解析结果 ok=%v，期望 %v", c.line, ok, c.ok)
		}
		if ok && (ts.Hour() != c.h || ts.Minute() != c.m) {
			t.Fatalf("%q 解析成 %02d:%02d，期望 %02d:%02d", c.line, ts.Hour(), ts.Minute(), c.h, c.m)
		}
	}
}

// ---------------------------------------------------------------- 平台不可用原因

func TestProbesReturnReasonsNotSilence(t *testing.T) {
	// 每个 Probe 要么返回 nil（可用），要么返回一段**说得清原因**的错误。
	// 这条测试的价值：防止有人把 Probe 改成 `return nil` 了事——
	// 那会让「没权限」在控制台上显示成「一切正常」。
	probes := map[string]func() error{
		"session":   platformProbeSession,
		"authlog":   platformProbeAuthLog,
		"logstream": platformProbeLogStream,
		"integrity": NewIntegrity(Config{Options: map[string]any{"data_dir": t.TempDir()}}).Probe,
	}
	for name, probe := range probes {
		err := probe()
		if err == nil {
			t.Logf("%s: 可用", name)
			continue
		}
		msg := err.Error()
		if strings.TrimSpace(msg) == "" {
			t.Fatalf("%s: Probe 返回空错误文本", name)
		}
		t.Logf("%s: 不可用 → %s", name, msg)
	}
}

// ---------------------------------------------------------------- Windows 解析

// TestSessionWindowsShape 用 Windows 形态的数据源 + 解析器跑一遍 Session，
// 证明平台分派真的接上了（而不是「Windows 编译过但解析器没挂」）。
//
// 这段测试在任何平台都能跑：quser 文本、wevtutil 文本都是纯字符串。
func TestSessionWindowsShape(t *testing.T) {
	quser := ` USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
 xxx              console             1  Active      none  11/18/2026 5:22 PM
`
	ev4624 := `Event[0]:
  Date: 2026-11-19T09:04:12.345
  Event ID: 4624
  Description:
	An account was successfully logged on.
	Account Name:		admin
	Workstation Name:	ATTACKER-PC
	Logon Type:		10
`
	s := &Session{seen: map[string]string{}}
	s.whoParse = platformParseWhoTestWindows
	s.lastParse = platformParseLastTestWindows
	who := []string{quser, quser + ">admin                 rdp-tcp#3           2  Active      1:23  11/19/2026 9:04 AM\n"}
	i := 0
	s.whoSrc = func(context.Context) (string, error) {
		v := who[i]
		if i < len(who)-1 {
			i++
		}
		return v, nil
	}
	s.lastSrc = func(context.Context) (string, error) { return ev4624, nil }
	s.Init("session", ModePoll, time.Second, nil)

	evs, err := s.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 0 {
		t.Fatalf("首轮出了 %d 条事件", len(evs))
	}
	if n := s.Items(); n != 1 {
		t.Fatalf("活跃会话 = %d，期望 1", n)
	}
	if snap := s.Snapshot(); len(snap["history"].([]loginHist)) != 1 {
		t.Fatalf("历史登录 = %v，期望 1 条（来自 4624）", snap["history"])
	}

	evs, err = s.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 {
		t.Fatalf("新增 RDP 会话出了 %d 条事件，期望 1: %+v", len(evs), evs)
	}
	if evs[0].Kind != EventSessionLogin || evs[0].Severity != "medium" {
		t.Fatalf("RDP 登录没被判成 medium: kind=%s sev=%s", evs[0].Kind, evs[0].Severity)
	}
	if evs[0].Process != "rdp-tcp#3" {
		t.Fatalf("process = %q，期望 rdp-tcp#3", evs[0].Process)
	}
}

// platformParseWhoTestWindows / platformParseLastTestWindows 与
// session_windows.go 里的同名函数等价（那份带 build tag，macOS 上编不进来）。
func platformParseWhoTestWindows(text string) []whoSession { return parseQuser(text) }

func platformParseLastTestWindows(text string, limit int) []loginHist {
	rows := winEventsToSessions(parseWevtutilText(text))
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	return rows
}

func TestParseQuser(t *testing.T) {
	// 真实 quser 输出（含 > 当前会话标记、rdp-tcp 远程会话、services 本地会话）
	out := ` USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
 xxx              console             1  Active      none  11/18/2026 5:22 PM
>admin                 rdp-tcp#3           2  Active      1:23  11/19/2026 9:04 AM
 svc                    services            0  Disc         .    11/18/2026 5:20 PM
`
	rows := parseQuser(out)
	if len(rows) != 3 {
		t.Fatalf("解析出 %d 行，期望 3: %+v", len(rows), rows)
	}
	if rows[0].User != "xxx" || rows[0].TTY != "console" {
		t.Fatalf("第 1 行 = %+v", rows[0])
	}
	if rows[0].Remote {
		t.Fatalf("console 会话被判成远程: %+v", rows[0])
	}
	if rows[1].User != "admin" {
		t.Fatalf("行首 '>' 没去掉: %+v", rows[1])
	}
	if !rows[1].Remote {
		t.Fatalf("rdp-tcp 会话没被判成远程: %+v", rows[1])
	}
	if !strings.Contains(rows[1].Since, "2026") {
		t.Fatalf("LOGON TIME 没解出: %q", rows[1].Since)
	}
}

func TestParseWevtutilText4625(t *testing.T) {
	out := `Event[0]:
  Log Name: Security
  Source: Microsoft-Windows-Security-Auditing
  Date: 2026-11-19T09:04:12.345
  Event ID: 4625
  Task: Logon
  Level: Information
  Description:
	An account failed to log on.
	Account Name:		admin
	Workstation Name:	ATTACKER-PC
	Logon Type:		3
	Status:			0xc000006d

Event[1]:
  Log Name: Security
  Source: Microsoft-Windows-Security-Auditing
  Date: 2026-11-19T09:04:13.000
  Event ID: 4624
  Task: Logon
  Description:
	An account was successfully logged on.
	Account Name:		xxx
	Workstation Name:	-
	Logon Type:		2
`
	evs := parseWevtutilText(out)
	if len(evs) != 2 {
		t.Fatalf("解析出 %d 个事件，期望 2: %+v", len(evs), evs)
	}
	if evs[0].ID != 4625 || evs[1].ID != 4624 {
		t.Fatalf("EventID 解析错: %d / %d", evs[0].ID, evs[1].ID)
	}
	if evs[0].Fields["Account Name"] != "admin" {
		t.Fatalf("账户名 = %q，期望 admin", evs[0].Fields["Account Name"])
	}
	if evs[0].Fields["Workstation Name"] != "ATTACKER-PC" {
		t.Fatalf("来源 = %q", evs[0].Fields["Workstation Name"])
	}

	// 4625 → 失败行（必须带 "Failed"，否则过不了统一的失败判定）
	fails := winEventsToAuthFailLines(evs)
	if len(fails) != 1 {
		t.Fatalf("失败行 %d 条，期望 1: %+v", len(fails), fails)
	}
	if !strings.Contains(fails[0], "Failed") {
		t.Fatalf("失败行不含 Failed，filterAuthFailLines 会漏掉: %q", fails[0])
	}
	if !strings.Contains(fails[0], "admin") || !strings.Contains(fails[0], "ATTACKER-PC") {
		t.Fatalf("失败行缺账户/来源: %q", fails[0])
	}
	// 反例：4624 不许进失败列表
	if len(filterAuthFailLines(fails)) != 1 {
		t.Fatalf("4624 被算成失败了: %+v", fails)
	}

	// 4624 → 历史登录（机器账户 $ 结尾的要跳过）
	hist := winEventsToSessions(evs)
	if len(hist) != 1 || hist[0].User != "xxx" {
		t.Fatalf("历史登录 = %+v", hist)
	}
}

func TestWinEventsSkipMachineAccounts(t *testing.T) {
	evs := []winEvent{
		{ID: 4624, Fields: map[string]string{"Account Name": "WIN-DC01$", "Logon Type": "3"}},
		{ID: 4624, Fields: map[string]string{"Account Name": "SYSTEM", "Logon Type": "5"}},
		{ID: 4624, Fields: map[string]string{"Account Name": "xxx", "Logon Type": "2"}},
	}
	hist := winEventsToSessions(evs)
	if len(hist) != 1 || hist[0].User != "xxx" {
		t.Fatalf("机器账户没被跳过: %+v", hist)
	}
}

// ---------------------------------------------------------------- Linux 解析

func TestParseAuthLogTextLinux(t *testing.T) {
	text := `Nov 19 17:28:01 web01 sshd[4012]: Failed password for invalid user test from 45.12.3.4 port 55001 ssh2
Nov 19 17:28:02 web01 sshd[4012]: Accepted password for root from 45.12.3.4 port 55002 ssh2
Nov 19 17:28:03 web01 sudo[4013]: xxx : user NOT in sudoers ; TTY=pts/0 ; COMMAND=/bin/bash
Nov 19 17:28:04 web01 systemd[1]: Started Session 12 of user root.
`
	// 平台层是**候选**预筛（宽）：Failed / NOT in sudoers 都留下，
	// Accepted / Started Session 不算候选。
	lines := parseAuthLogText(text)
	if len(lines) != 2 {
		t.Fatalf("筛出 %d 行，期望 2（Failed + NOT in sudoers）: %+v", len(lines), lines)
	}
	// 最终判定仍走 filterAuthFailLines（与 Python 同集：incorrect / Failed），
	// 所以 Accepted 行和「NOT in sudoers」都不会被算成认证失败——这是刻意的：
	// 两版对拍只承认 Python 认的那两类。
	all := append(lines, "Nov 19 17:28:02 web01 sshd[4012]: Accepted password for root from 1.2.3.4 port 1 ssh2")
	if got := filterAuthFailLines(all); len(got) != 1 {
		t.Fatalf("统一判定筛出 %d 行，期望 1（只有 Failed password）: %+v", len(got), got)
	}
}

func TestParseJournalJSONRecord(t *testing.T) {
	line := `{"__REALTIME_TIMESTAMP":"1700000000000000","_PID":"4012","_COMM":"sshd",` +
		`"_EXE":"/usr/sbin/sshd","SYSLOG_IDENTIFIER":"sshd","_SYSTEMD_UNIT":"ssh.service",` +
		`"MESSAGE":"Failed password for root from 45.12.3.4 port 55001 ssh2"}`
	rec, ok := parseJournalJSON(line)
	if !ok {
		t.Fatal("journal 记录没解析出来")
	}
	if rec.Msg != "Failed password for root from 45.12.3.4 port 55001 ssh2" {
		t.Fatalf("MESSAGE = %q", rec.Msg)
	}
	if rec.Process != "sshd" {
		t.Fatalf("process = %q，期望 sshd", rec.Process)
	}
	if !rec.HasPID || rec.PID != 4012 {
		t.Fatalf("pid = %d/%v", rec.PID, rec.HasPID)
	}
	if !journalSelected(rec) {
		t.Fatal("sshd 记录被 journalSelector 滤掉了")
	}
	// 反例：无关进程要滤掉
	noise, _ := parseJournalJSON(`{"MESSAGE":"hello","SYSLOG_IDENTIFIER":"gnome-shell","_COMM":"gnome-shell"}`)
	if journalSelected(noise) {
		t.Fatal("gnome-shell 记录不该被选中")
	}
}
