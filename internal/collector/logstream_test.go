package collector

// logstream_test.go —— 实时日志流的签名匹配 / 噪声 / 限速 双向测试。
//
// 双向的含义：
//
//	每个签名都配一条命中样本（kind + severity + note 全比）
//	**每个签名都配一条近似但不该命中的样本**（Accepted 不许被当成 Failed）
//	噪声前缀的行 → 0 事件
//	无关键字的正常行 → 0 事件
//	超限速 → 丢弃并计数（不是静默丢、也不是无限缓冲）
//	一条日志只产一个事件（首个命中即 break，不许多重归类）
//
// 平台无关：ndjson（macOS）、journal json（Linux）、wevtutil text（Windows）
// 三种输入形状都在这里被验证，所以 Windows 的解析不只有「能编译」一条证据。

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func newTestLogStream() *LogStream {
	ls := &LogStream{maxRate: 40, kind: "ndjson"}
	ls.Init("logstream", ModeStream, time.Second, nil)
	return ls
}

// ndjson 造一条 macOS unified log 记录。
func ndjsonLine(proc, msg, subsystem string) string {
	rec := map[string]any{
		"eventMessage":     msg,
		"process":          proc,
		"processImagePath": "/usr/sbin/" + proc,
		"processID":        1234,
		"subsystem":        subsystem,
		"category":         "test",
	}
	b, _ := json.Marshal(rec)
	return string(b)
}

func TestLogStreamSignaturesHit(t *testing.T) {
	cases := []struct {
		proc, msg, kind, sev, note string
	}{
		{"sudo", "xxx : 3 incorrect password attempts", EventAuthFail, "medium", "认证失败"},
		{"sshd", "Accepted publickey for xxx from 10.0.0.5 port 51234 ssh2: ED25519", EventAuthSuccess, "medium", "远程登录成功"},
		{"sshd", "Failed password for root from 10.0.0.9 port 40001 ssh2", EventAuthFail, "high", "SSH 爆破迹象"},
		{"tccd", "Deny file-read-data /Users/x/Library/Mail", EventTCCDeny, "medium", "TCC 权限被拒（疑似越权访问）"},
		{"XProtect", "XProtect detected malware in /Users/x/Downloads/x.dmg", EventAVDetect, "critical", "XProtect 恶意软件告警"},
		{"spctl", "gatekeeper assessment failed for /Applications/Evil.app", EventDefenseEvent, "medium", "Gatekeeper 相关事件"},
		{"securityd", "keychain access denied for login.keychain", EventCredentialAccess, "medium", "钥匙串访问异常"},
	}
	for _, c := range cases {
		t.Run(c.kind+"-"+c.proc, func(t *testing.T) {
			ls := newTestLogStream()
			ls.handleLine(ndjsonLine(c.proc, c.msg, "com.apple.test"))
			evs, err := ls.Collect(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(evs) != 1 {
				t.Fatalf("签名没命中（或命中多次）: %d 条事件，输入 %q", len(evs), c.msg)
			}
			ev := evs[0]
			if ev.Kind != c.kind {
				t.Fatalf("kind = %q，期望 %q（输入 %q）", ev.Kind, c.kind, c.msg)
			}
			if ev.Severity != c.sev {
				t.Fatalf("severity = %q，期望 %q（输入 %q）", ev.Severity, c.sev, c.msg)
			}
			if ev.Subject["note"] != c.note {
				t.Fatalf("note = %v，期望 %q", ev.Subject["note"], c.note)
			}
			if ev.Source != "logstream" {
				t.Fatalf("source = %q", ev.Source)
			}
			if ev.Process != c.proc {
				t.Fatalf("process = %q，期望 %q", ev.Process, c.proc)
			}
			if ev.Path != "/usr/sbin/"+c.proc {
				t.Fatalf("path = %q", ev.Path)
			}
			if ev.PID == nil || *ev.PID != 1234 {
				t.Fatalf("pid = %v，期望 1234", ev.PID)
			}
			if msg, _ := ev.Raw["eventMessage"].(string); msg != c.msg {
				t.Fatalf("raw.eventMessage = %q", msg)
			}
			for _, k := range []string{"note", "subsystem", "category", "raw_process"} {
				if _, ok := ev.Subject[k]; !ok {
					t.Fatalf("subject 缺键 %q: %+v", k, ev.Subject)
				}
			}
		})
	}
}

func TestLogStreamSignatureNearMisses(t *testing.T) {
	// 反例：这些行「长得像」但绝对不能命中——只测正向会奖励「什么都报」
	negatives := []string{
		"Accepted connection from 10.0.0.5",               // 不是登录成功
		"pam_unix(sshd:session): session opened for user", // 不是失败
		"Starting periodic command scheduler: cron.",      // 正常启动日志
		"mds: indexed 42 files",                           // 正常索引
		"kernel: AppleUSBXHCI::start: attached",           // 正常驱动
		"sshd[123]: Connection closed by 10.0.0.5",        // 正常断开
	}
	for _, msg := range negatives {
		ls := newTestLogStream()
		ls.handleLine(ndjsonLine("launchd", msg, "com.apple.test"))
		evs, _ := ls.Collect(context.Background())
		if len(evs) != 0 {
			t.Fatalf("正常日志被归类成事件: kind=%q msg=%q", evs[0].Kind, msg)
		}
	}
}

func TestLogStreamNoiseFiltered(t *testing.T) {
	// 噪声表里的 subsystem / 片段：即使消息含关键字也要丢掉
	cases := []struct{ proc, msg, subsys string }{
		{"cfprefsd", "Deny file-write-data (ignored)", "com.apple.cfprefsd"},
		{"mdworker", "Failed to index volume", "com.apple.mdworker"},
		{"tccd", "tccd Request prompt from client", ""},
		{"sandboxd", "Sandbox: something denied", "com.apple.sandbox"},
		{"UIKit", "something with UIKit", ""},
	}
	for _, c := range cases {
		ls := newTestLogStream()
		ls.handleLine(ndjsonLine(c.proc, c.msg, c.subsys))
		evs, _ := ls.Collect(context.Background())
		if len(evs) != 0 {
			t.Fatalf("噪声没被过滤: proc=%q msg=%q → %+v", c.proc, c.msg, evs[0])
		}
	}
	// 反向：同一条消息去掉噪声片段后必须命中，证明过滤是「片段」而不是「进程」
	ls := newTestLogStream()
	ls.handleLine(ndjsonLine("tccd", "Deny file-read-data /Users/x/Documents", "com.apple.TCC"))
	if evs, _ := ls.Collect(context.Background()); len(evs) != 1 {
		t.Fatalf("清白的 TCC 拒绝没命中: %d 条", len(evs))
	}
}

func TestLogStreamEmptyOrJunkLineIgnored(t *testing.T) {
	ls := newTestLogStream()
	for _, line := range []string{
		"", "   ", "not json at all", "{", "{}",
		`{"process":"sshd"}`, // 没有消息正文
		`{"eventMessage":""}`,
	} {
		ls.handleLine(line)
	}
	evs, _ := ls.Collect(context.Background())
	if len(evs) != 0 {
		t.Fatalf("垃圾行产出了 %d 条事件: %+v", len(evs), evs)
	}
}

func TestLogStreamOneEventPerLine(t *testing.T) {
	// 一行同时命中「Accepted」和「Failed」类关键字时，只按签名表顺序归第一类
	ls := newTestLogStream()
	ls.handleLine(ndjsonLine("sshd", "Accepted password for root; Failed password earlier", ""))
	evs, _ := ls.Collect(context.Background())
	if len(evs) != 1 {
		t.Fatalf("一行产出了 %d 个事件，期望 1（首个命中即 break）", len(evs))
	}
	if evs[0].Kind != EventAuthSuccess {
		t.Fatalf("归到了 %q，期望 auth.success（签名表第 2 条先命中）", evs[0].Kind)
	}
}

func TestLogStreamRateLimitDrops(t *testing.T) {
	ls := &LogStream{maxRate: 3, kind: "ndjson"}
	ls.Init("logstream", ModeStream, time.Second, nil)
	for i := 0; i < 10; i++ {
		ls.handleLine(ndjsonLine("sshd", "Failed password for root from 10.0.0.9 port 40"+string(rune('0'+i)), ""))
	}
	evs, _ := ls.Collect(context.Background())
	if len(evs) != 3 {
		t.Fatalf("限速后剩 %d 条，期望 3", len(evs))
	}
	snap := ls.Snapshot()
	if snap["drops"].(int64) != 7 {
		t.Fatalf("drops = %v，期望 7（超限的必须计数，不能静默丢）", snap["drops"])
	}
}

func TestLogStreamRateWindowResets(t *testing.T) {
	// 限速是「每秒」而不是「总共」：窗口翻过之后必须继续收
	ls := &LogStream{maxRate: 2, kind: "ndjson"}
	ls.Init("logstream", ModeStream, time.Second, nil)
	// 把窗口起点拨到过去 → 下一次 handleLine 会重置计数
	ls.rateWin = time.Now().Add(-2 * time.Second)
	ls.rate = 99
	ls.handleLine(ndjsonLine("sshd", "Failed password for root", ""))
	evs, _ := ls.Collect(context.Background())
	if len(evs) != 1 {
		t.Fatalf("窗口翻页后仍被限速: %d 条", len(evs))
	}
}

func TestLogStreamBufferCappedAt400(t *testing.T) {
	ls := newTestLogStream()
	ls.maxRate = 10000
	for i := 0; i < 450; i++ {
		ls.handleLine(ndjsonLine("sshd", "Failed password for root from 10.0.0.9", ""))
	}
	evs, _ := ls.Collect(context.Background())
	if len(evs) != 400 {
		t.Fatalf("取走 %d 条，期望 400（Python: buf[-400:]）", len(evs))
	}
	// 取走之后再取必须是空（缓冲区已被 swap 走）
	evs, _ = ls.Collect(context.Background())
	if len(evs) != 0 {
		t.Fatalf("缓冲区没被清空: 又取出 %d 条", len(evs))
	}
}

func TestLogStreamCmdlineAndRawTruncated(t *testing.T) {
	ls := newTestLogStream()
	long := "Failed password for " + strings.Repeat("x", 2000)
	ls.handleLine(ndjsonLine("sshd", long, ""))
	evs, _ := ls.Collect(context.Background())
	if len(evs) != 1 {
		t.Fatalf("没命中: %d", len(evs))
	}
	if n := len(evs[0].Cmdline); n != 400 {
		t.Fatalf("cmdline 长度 = %d，期望 400（Python: msg[:400]）", n)
	}
	msg, _ := evs[0].Raw["eventMessage"].(string)
	if len(msg) != 800 {
		t.Fatalf("raw.eventMessage 长度 = %d，期望 800（Python: msg[:800]）", len(msg))
	}
}

// ---------------------------------------------------------------- 平台输入形状

func TestParseNDJSONFields(t *testing.T) {
	line := `{"eventMessage":"hello","process":"sshd","processImagePath":"/usr/sbin/sshd",` +
		`"processID":4321,"subsystem":"com.apple.sshd","category":"auth"}`
	rec, ok := parseNDJSON(line)
	if !ok {
		t.Fatal("ndjson 没解析出来")
	}
	if rec.Msg != "hello" || rec.Process != "sshd" || rec.Image != "/usr/sbin/sshd" {
		t.Fatalf("字段解析错: %+v", rec)
	}
	if !rec.HasPID || rec.PID != 4321 {
		t.Fatalf("pid = %d/%v", rec.PID, rec.HasPID)
	}
	// composedMessage 是 legacy 字段名，也要认
	rec, ok = parseNDJSON(`{"composedMessage":"legacy msg","process":"sudo"}`)
	if !ok || rec.Msg != "legacy msg" || rec.Process != "sudo" {
		t.Fatalf("composedMessage 没兜住: %+v ok=%v", rec, ok)
	}
	// 反例：非 JSON 行
	if _, ok := parseNDJSON("Filtering the log data using \"process == \\\"sshd\\\"\""); ok {
		t.Fatal("log stream 的 stderr 提示行被当成数据了")
	}
}

func TestParseWindowsEventTextRecords(t *testing.T) {
	block := `Event[0]:
  Log Name: Security
  Source: Microsoft-Windows-Security-Auditing
  Event ID: 4625
  Task: Logon
  Description:
	An account failed to log on.
	Account Name:		admin
`
	recs := parseWindowsEventText(block)
	if len(recs) != 1 {
		t.Fatalf("解析出 %d 条，期望 1", len(recs))
	}
	rec := recs[0]
	if rec.Process == "" {
		t.Fatalf("process 为空: %+v", rec)
	}
	if !strings.Contains(rec.Msg, "failed to log on") {
		t.Fatalf("消息没取到: %q", rec.Msg)
	}
	// 这条消息里没有 Python 签名表的关键字 → 不该命中
	if len(logSignaturesHit(rec)) != 0 {
		t.Fatalf("Windows 4625 被签名表命中: %+v", logSignaturesHit(rec))
	}
}

// logSignaturesHit 测试辅助：返回一条记录命中的签名 kind 列表。
func logSignaturesHit(rec logRecord) []string {
	blob := rec.Process + " " + rec.Msg
	var hits []string
	for _, sig := range logSignatures {
		if sig.Re.MatchString(blob) {
			hits = append(hits, sig.Kind)
		}
	}
	return hits
}

func TestParseWindowsEventBlockWithFailedKeyword(t *testing.T) {
	// wevtutil 的 Description 里带 "Failed" 时应当命中 auth.fail/high
	block := `Event[0]:
  Source: Microsoft-Windows-Security-Auditing
  Event ID: 4625
  Description:
	An account failed to log on.
	Failed password for admin
`
	ls := &LogStream{maxRate: 40, kind: "wevtutil"}
	ls.Init("logstream", ModeStream, time.Second, nil)
	ls.handleLine(block)
	evs, _ := ls.Collect(context.Background())
	if len(evs) != 1 {
		t.Fatalf("wevtutil 块没命中签名: %d 条", len(evs))
	}
	if evs[0].Kind != EventAuthFail {
		t.Fatalf("kind = %q，期望 auth.fail", evs[0].Kind)
	}
}

func TestParseLogLineDispatch(t *testing.T) {
	jd := `{"MESSAGE":"Failed password for root","SYSLOG_IDENTIFIER":"sshd"}`
	if rec, ok := parseLogLine(jd, "journal"); !ok || rec.Msg != "Failed password for root" {
		t.Fatalf("journal 分派失败: %+v ok=%v", rec, ok)
	}
	nd := ndjsonLine("sshd", "Failed password for root", "")
	if rec, ok := parseLogLine(nd, "ndjson"); !ok || rec.Process != "sshd" {
		t.Fatalf("ndjson 分派失败: %+v ok=%v", rec, ok)
	}
	// 反例：journal 的 json 不能喂给 ndjson 解析器（字段名不同 → 空消息）
	if rec, ok := parseLogLine(jd, "ndjson"); ok && rec.Msg != "" {
		t.Fatalf("journal json 被 ndjson 解析器误读: %+v", rec)
	}
}

func TestLogStreamProbeUnavailableReturnsReason(t *testing.T) {
	// 平台不支持时 Probe 必须给原因，而不是「可用但 0 事件」。
	// 这里直接验平台实现：macOS 上 /usr/bin/log 存在 → 可用；
	// 若不存在（被裁剪的系统）→ 原因里必须提到缺什么。
	err := platformProbeLogStream()
	if err != nil {
		if !strings.Contains(err.Error(), "log") && !strings.Contains(err.Error(), "journalctl") &&
			!strings.Contains(err.Error(), "wevtutil") {
			t.Fatalf("不可用原因没说清缺什么: %v", err)
		}
	}
}
