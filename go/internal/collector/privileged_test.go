package collector

// privileged_test.go —— 提权判定的双向测试。
//
// 双向的含义（与 process_test.go / persistence_test.go 同规矩）：
//
//	每条规则都有一个「该报的报」样本：kind + severity 逐字比对
//	每条规则都有一个「不该报的不报」样本：judge 必须返回 ok=false
//	三平台解析器各有一组样本（eslogger NDJSON / audit.log / wevtutil text），
//	所以 Windows 与 Linux 的解析不是「能编译」，而是「在本机被真实文本验证过」
//
// 最后两条是**本机实测**：非 root 下 probe 的报错文本、以及真机 ps 出来的
// 进程是否会被误判成提权（噪音测试）。

import (
	"context"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

// ---- 判定：提权成功 ----

func TestPrivJudgeElevate(t *testing.T) {
	cases := []struct {
		name string
		rec  privRecord
		want bool
		kind string
		sev  string
	}{
		{
			name: "sudo 带 TTY（人正常提权）→ medium",
			rec: privRecord{
				Action: privActElevate, Exe: "/usr/bin/sudo", User: "x",
				Target: "root", TTY: "ttys001", HasTTY: true, PID: 900, HasPID: true,
			},
			want: true, kind: EventPrivEscalate, sev: "medium",
		},
		{
			name: "sudo 无 TTY（脚本/服务在提权）→ high",
			rec: privRecord{
				Action: privActElevate, Exe: "/usr/bin/sudo", User: "x",
				Target: "root", TTY: "", HasTTY: true, PID: 901, HasPID: true,
			},
			want: true, kind: EventPrivEscalate, sev: "high",
		},
		{
			name: "临时目录里的 sudo（伪装提权程序）→ high",
			rec: privRecord{
				Action: privActElevate, Exe: "/tmp/sudo", User: "x",
				Target: "root", TTY: "ttys002", HasTTY: true, PID: 902, HasPID: true,
			},
			want: true, kind: EventPrivEscalate, sev: "high",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev, ok := judgePriv(c.rec)
			if ok != c.want {
				t.Fatalf("judgePriv ok=%v want %v", ok, c.want)
			}
			if ev.Kind != c.kind {
				t.Errorf("kind=%q want %q", ev.Kind, c.kind)
			}
			if ev.Severity != c.sev {
				t.Errorf("severity=%q want %q", ev.Severity, c.sev)
			}
			if ev.Source != "privileged" {
				t.Errorf("source=%q want privileged", ev.Source)
			}
		})
	}
}

// TestPrivJudgeSilent 反例：这些记录一条都不许报。
func TestPrivJudgeSilent(t *testing.T) {
	cases := []struct {
		name string
		rec  privRecord
	}{
		{"普通 exec 不进提权采集器", privRecord{Action: "exec", Exe: "/bin/ls"}},
		{"空动作", privRecord{Exe: "/bin/ls"}},
		{"setuid 到自己的 uid（守护进程降权）", privRecord{Action: privActSetuid, Exe: "/usr/sbin/foo", Target: "501"}},
		{"setuid(0) 失败", privRecord{Action: privActSetuid, Exe: "/usr/bin/foo", Target: "0", Success: false, HasSuccess: true}},
		{"非敏感路径的文件写入（下载目录）", privRecord{Action: privActFileWrite, Target: "/Users/x/Downloads/a.txt", Exe: "/bin/bash"}},
		{"非敏感路径的文件读取（系统日志）", privRecord{Action: privActFileOpen, Target: "/var/log/system.log", Exe: "/usr/bin/tail"}},
		{"认证成功不报（login 由 session 采集器管）", privRecord{Action: "auth_ok", Exe: "/usr/bin/sudo"}},
		{"文件事件没有目标路径（无从判定）", privRecord{Action: privActFileWrite, Target: "", Exe: "/bin/sh"}},
		{"未归一的动作（signal/xpc 等）不报", privRecord{Action: "signal", Target: "", Exe: "/bin/kill"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if ev, ok := judgePriv(c.rec); ok {
				t.Fatalf("不该报却报了: kind=%s sev=%s subject=%v", ev.Kind, ev.Severity, ev.Subject)
			}
		})
	}
}

func TestPrivJudgeSetuidToRoot(t *testing.T) {
	ev, ok := judgePriv(privRecord{
		Action: privActSetuid, Exe: "/usr/bin/sudo", Target: "0", HasSuccess: true, Success: true,
		PID: 77, HasPID: true, User: "x",
	})
	if !ok || ev.Kind != EventCredSetuid || ev.Severity != "medium" {
		t.Fatalf("setuid(0) 应报 cred.setuid/medium，得到 ok=%v kind=%s sev=%s", ok, ev.Kind, ev.Severity)
	}
	ev, ok = judgePriv(privRecord{Action: privActSeteuid, Exe: "/Users/x/.hidden/su", Target: "0"})
	if !ok || ev.Kind != EventCredSeteuid || ev.Severity != "high" {
		t.Fatalf("隐藏目录里的 seteuid(0) 应为 high，得到 ok=%v kind=%s sev=%s", ok, ev.Kind, ev.Severity)
	}
}

func TestPrivJudgeSensitiveFiles(t *testing.T) {
	cases := []struct {
		name   string
		action string
		target string
		kind   string
		sev    string
	}{
		{"写 sudoers（critical）", privActFileWrite, "/etc/sudoers", EventFileWrite, "high"},
		{"写 sudoers.d（critical）", privActFileCreate, "/etc/sudoers.d/evil", EventFileCreate, "high"},
		{"写 LaunchDaemon（critical）", privActFileCreate, "/Library/LaunchDaemons/x.plist", EventFileCreate, "high"},
		{"写 authorized_keys（critical）", privActFileWrite, "/Users/x/.ssh/authorized_keys", EventFileWrite, "high"},
		{"删 /tmp 下的文件（敏感但非关键）", privActFileDelete, "/tmp/x.sh", EventFileDelete, "medium"},
		{"改 /etc/hosts（critical）", privActFileRename, "/etc/hosts", EventFileRename, "high"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev, ok := judgePriv(privRecord{Action: c.action, Target: c.target, Exe: "/bin/sh"})
			if !ok {
				t.Fatalf("敏感路径 %s 应上报", c.target)
			}
			if ev.Kind != c.kind || ev.Severity != c.sev {
				t.Errorf("kind/sev = %s/%s want %s/%s", ev.Kind, ev.Severity, c.kind, c.sev)
			}
			if ev.Path != c.target {
				t.Errorf("path=%q want %q", ev.Path, c.target)
			}
		})
	}
}

func TestPrivJudgeDefenseEvents(t *testing.T) {
	cases := []struct {
		action string
		kind   string
		sev    string
	}{
		{privActKextload, EventSystemKextload, "high"},
		{privActCSInvalid, EventDefenseCSInv, "high"},
		{privActGKOverride, EventDefenseGKOver, "medium"},
		{privActLogCleared, EventDefenseLogClr, "critical"},
		{privActPrivAssigned, EventPrivAssigned, "medium"},
		{privActAuditRuleOff, EventDefenseEvent, "high"},
	}
	for _, c := range cases {
		t.Run(c.action, func(t *testing.T) {
			ev, ok := judgePriv(privRecord{Action: c.action, Exe: "/usr/bin/x", User: "root"})
			if !ok {
				t.Fatalf("动作 %s 应上报", c.action)
			}
			if ev.Kind != c.kind || ev.Severity != c.sev {
				t.Errorf("kind/sev = %s/%s want %s/%s", ev.Kind, ev.Severity, c.kind, c.sev)
			}
		})
	}
}

// ---- 解析：eslogger ----

func TestParseESLoggerLine(t *testing.T) {
	// 老形状：event.event 是字符串
	oldShape := `{"time":"1700000000.25","event":{"event":"setuid","setuid":{"uid":0,"success":true}},"process":{"audit_id":4242,"ppid":4200,"uid":501,"name":"sudo","executable":{"path":"/usr/bin/sudo","args":["sudo","-i"]},"signing_id":"com.apple.sudo"}}`
	rec, ok := parseESLoggerLine(oldShape)
	if !ok {
		t.Fatal("老形状 eslogger 行应解析成功")
	}
	if rec.Action != privActSetuid || rec.Target != "0" || !rec.Success || !rec.HasSuccess {
		t.Fatalf("解析结果不对: action=%s target=%q success=%v has=%v", rec.Action, rec.Target, rec.Success, rec.HasSuccess)
	}
	if rec.PID != 4242 || rec.PPID != 4200 || rec.Exe != "/usr/bin/sudo" {
		t.Errorf("pid/ppid/exe = %d/%d/%q", rec.PID, rec.PPID, rec.Exe)
	}
	if rec.Cmdline != "sudo -i" {
		t.Errorf("cmdline=%q want \"sudo -i\"", rec.Cmdline)
	}

	// 新形状：event 下的键就是事件类型
	newShape := `{"event":{"write":{"target":{"path":"/etc/sudoers"}}},"process":{"audit_id":55,"ppid":1,"executable":{"path":"/bin/sh","args":["sh","-c","echo x >> /etc/sudoers"]}}}`
	rec, ok = parseESLoggerLine(newShape)
	if !ok || rec.Action != privActFileWrite || rec.Target != "/etc/sudoers" {
		t.Fatalf("新形状解析失败: ok=%v action=%s target=%q", ok, rec.Action, rec.Target)
	}
	ev, ok := judgePriv(rec)
	if !ok || ev.Severity != "high" {
		t.Fatalf("写 sudoers 应为 high，得到 ok=%v sev=%s", ok, ev.Severity)
	}

	// 反例：exec / 坏 JSON / 非 JSON
	for _, line := range []string{
		`{"event":{"event":"exec"},"process":{"audit_id":1}}`,
		`{"event":`,
		`not json at all`,
		``,
	} {
		if _, ok := parseESLoggerLine(line); ok {
			t.Fatalf("不该解析成功: %q", line)
		}
	}
}

// ---- 解析：auditd ----

const auditSample = `type=SYSCALL msg=audit(1700000001.100:900): arch=c000003e syscall=59 success=yes exit=0 a0=7ffd a1=7ffe ppid=1000 pid=1001 auid=1000 uid=1000 gid=1000 euid=1000 tty=pts0 ses=3 comm="ls" exe="/usr/bin/ls" key="exec"
type=EXECVE msg=audit(1700000001.100:900): argc=2 a0="ls" a1="-la"
type=USER_CMD msg=audit(1700000002.200:901): pid=2001 uid=1000 auid=1000 ses=4 msg='cwd="/home/x" cmd=7375202D69 terminal=pts/1 res=success'
type=USER_AUTH msg=audit(1700000003.300:902): pid=3001 uid=1000 auid=1000 ses=5 msg='op=PAM:authentication grantors=pam_unix acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/2 res=failed'
type=SYSCALL msg=audit(1700000004.400:903): arch=c000003e syscall=105 success=yes exit=0 a0=0 a1=0 a2=0 a3=0 items=0 ppid=1 pid=4001 auid=1000 uid=1000 euid=0 tty=pts3 ses=6 comm="setup" exe="/tmp/setup" key="priv"
type=CONFIG_CHANGE msg=audit(1700000005.500:904): auid=1000 ses=7 op=remove_rule key="watched" list=4 res=1
type=SYSCALL msg=audit(1700000006.600:905): arch=c000003e syscall=105 success=no exit=-1 a0=0 ppid=1 pid=5001 uid=1000 euid=1000 comm="failer" exe="/usr/bin/failer"`

func TestParseAuditLog(t *testing.T) {
	recs := parseAuditLog(auditSample)
	if len(recs) != 4 {
		t.Fatalf("应解析出 4 条记录（exec 组丢弃、失败 setuid 丢弃），得到 %d: %+v", len(recs), recs)
	}
	byAction := map[string]privRecord{}
	for _, r := range recs {
		byAction[r.Action] = r
	}
	// 1) sudo 执行命令（USER_CMD，hex 解码）
	el, ok := byAction[privActElevate]
	if !ok {
		t.Fatal("缺 elevate 记录（USER_CMD）")
	}
	if el.Cmdline != "su -i" {
		t.Errorf("cmd 解码 = %q want \"su -i\"", el.Cmdline)
	}
	if el.PID != 2001 || !el.HasTTY || el.TTY != "pts/1" {
		t.Errorf("pid/tty = %d/%q (has=%v)", el.PID, el.TTY, el.HasTTY)
	}
	// 2) 认证失败
	af, ok := byAction[privActAuthFail]
	if !ok || af.Target != "root" {
		t.Fatalf("缺 auth_fail 或 target 不对: %+v", af)
	}
	// 3) setuid(0)（a0=0）
	su, ok := byAction[privActSetuid]
	if !ok || su.Target != "0" || su.Exe != "/tmp/setup" {
		t.Fatalf("setuid 记录不对: %+v", su)
	}
	ev, ok := judgePriv(su)
	if !ok || ev.Severity != "high" {
		t.Fatalf("临时目录里的 setuid(0) 应为 high，得到 ok=%v sev=%s", ok, ev.Severity)
	}
	// 4) 审计规则被删
	ar, ok := byAction[privActAuditRuleOff]
	if !ok {
		t.Fatal("缺 audit_rule_removed 记录")
	}
	if ev, ok := judgePriv(ar); !ok || ev.Kind != EventDefenseEvent || ev.Severity != "high" {
		t.Fatalf("删审计规则应为 defense.event/high，得到 ok=%v kind=%s sev=%s", ok, ev.Kind, ev.Severity)
	}
}

func TestParseAuditLogNegative(t *testing.T) {
	// 普通 exec（syscall 59）不该有任何记录；格式不对的行也不该 panic
	for _, text := range []string{
		"",
		"type=SYSCALL msg=audit(1.0:1): syscall=59 exe=\"/usr/bin/ls\" euid=1000",
		"garbage line\n\n",
		"type=EXECVE msg=audit(1.0:2): argc=1 a0=\"ls\"",
	} {
		if recs := parseAuditLog(text); len(recs) != 0 {
			t.Fatalf("不该有记录: %q → %+v", text, recs)
		}
	}
}

func TestDecodeAuditHex(t *testing.T) {
	cases := map[string]string{
		"7375202D69": "su -i",
		"dead":       "dead", // 是合法 hex("ޭ") 但不可打印 → 原样返回
		"abc":        "abc",  // 奇数长度
		"not-hex":    "not-hex",
	}
	for in, want := range cases {
		if got := decodeAuditHex(in); got != want {
			t.Errorf("decodeAuditHex(%q)=%q want %q", in, got, want)
		}
	}
}

// ---- 解析：Windows Security 事件文本 ----

const winSample = `Event[0]:
  Log Name: Security
  Source: Microsoft-Windows-Security-Auditing
  Date: 2026-11-21T02:31:07.123
  Event ID: 4672
  Task: Special Logon
  Level: Information
  Description:
	Special privileges assigned to new logon.

	Subject:
		Security ID:		S-1-5-18
		Account Name:		SYSTEM
		Account Domain:		NT AUTHORITY

	Privileges:		SeDebugPrivilege

Event[1]:
  Log Name: Security
  Date: 2026-11-21T02:31:08.500
  Event ID: 4688
  Description:
	A new process has been created.

	Creator Subject:
		Account Name:		x

	Process Information:
		New Process Name:	C:\Windows\System32\runas.exe
		Process Command Line:	runas /user:Administrator cmd

Event[2]:
  Log Name: Security
  Date: 2026-11-21T02:31:09.900
  Event ID: 4688
  Description:
	Process Information:
		New Process Name:	C:\Windows\System32\notepad.exe
		Process Command Line:	notepad.exe C:\Users\x\notes.txt
		Mandatory Label:		S-1-16-8192

Event[3]:
  Log Name: Security
  Date: 2026-11-21T02:31:10.000
  Event ID: 4688
  Description:
	Process Information:
		New Process Name:	C:\Users\x\AppData\Local\Temp\evil.exe
		Process Command Line:	evil.exe
		Mandatory Label:		S-1-16-12288

Event[4]:
  Log Name: Security
  Date: 2026-11-21T02:31:11.000
  Event ID: 1102
  Description:
	The audit log was cleared.
	Subject:
		Account Name:		x
`

func TestParseWinSecurityEvents(t *testing.T) {
	recs := parseWinSecurityEvents(winSample)
	if len(recs) != 4 {
		t.Fatalf("应解析 4 条（4672 + runas + 临时目录高完整性 + 1102；notepad 必须被丢弃），得到 %d", len(recs))
	}
	var got []string
	for _, r := range recs {
		ev, ok := judgePriv(r)
		if !ok {
			t.Fatalf("解析出的记录应能判定: %+v", r)
		}
		got = append(got, ev.Kind+"/"+ev.Severity)
	}
	want := []string{
		EventPrivAssigned + "/medium",
		EventPrivEscalate + "/medium", // runas：无 TTY 信息、程序在系统目录 → medium
		EventPrivEscalate + "/high",   // %TEMP% 里的高完整性进程：路径可疑 → high
		EventDefenseLogClr + "/critical",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("kind/sev 序列\n got: %v\nwant: %v", got, want)
	}
}

func TestParseWinSecurityNegative(t *testing.T) {
	// 只有普通 4688 的日志：一条都不该报（这正是 4688 默认策略下的世界）
	only := `Event[0]:
  Log Name: Security
  Event ID: 4688
  Description:
	Process Information:
		New Process Name:	C:\Windows\System32\notepad.exe
		Process Command Line:	notepad.exe
		Mandatory Label:		S-1-16-8192
`
	if recs := parseWinSecurityEvents(only); len(recs) != 0 {
		t.Fatalf("普通 notepad 启动不该上报: %+v", recs)
	}
	if recs := parseWinSecurityEvents(""); len(recs) != 0 {
		t.Fatal("空文本不该有记录")
	}
}

// ---- 采集器行为：去重 / 限速 / 状态 ----

func newTestPrivileged() *Privileged {
	p := &Privileged{
		seen:       map[string]float64{},
		maxRate:    3,
		autoSyncOn: false,
		src:        func(ctx context.Context, sink func(privRecord)) error { return nil },
		limits:     "test",
	}
	p.Init("privileged", ModeStream, time.Second, func() error { return nil })
	return p
}

func TestPrivilegedDedupAndRate(t *testing.T) {
	p := newTestPrivileged()
	rec := privRecord{Action: privActElevate, Exe: "/usr/bin/sudo", Target: "root", PID: 10, HasPID: true, HasTTY: true, TTY: "ttys000"}

	p.handleRecord(rec)
	p.handleRecord(rec) // 同 key 同 TTL 内 → 抑制
	if n := len(p.buf); n != 1 {
		t.Fatalf("去重失效：buf=%d want 1", n)
	}
	if p.suppressed != 1 {
		t.Fatalf("suppressed=%d want 1", p.suppressed)
	}

	// 不同 pid → 新事件
	rec2 := rec
	rec2.PID = 11
	p.handleRecord(rec2)
	if n := len(p.buf); n != 2 {
		t.Fatalf("不同 pid 应各自入库：buf=%d want 2", n)
	}

	// 限速：maxRate=3，再来 5 条独立事件，只有第 3 条能进（前两条已占 2）
	for i := 12; i < 17; i++ {
		r := rec
		r.PID = i
		p.handleRecord(r)
	}
	if p.drops == 0 {
		t.Fatal("超过 maxRate 应计数丢弃")
	}
	if n := len(p.buf); n != 3 {
		t.Fatalf("限速后 buf=%d want 3", n)
	}

	// Snapshot 必须带 limits：控制台要能看见「能用，但只到这一步」
	snap := p.Snapshot()
	if snap["limits"] != "test" {
		t.Fatalf("snapshot.limits=%v", snap["limits"])
	}
}

func TestPrivilegedCollectDrains(t *testing.T) {
	p := newTestPrivileged()
	p.handleRecord(privRecord{Action: privActLogCleared, Exe: "eventlog", PID: 1, HasPID: true})
	evs, err := p.Collect(nil)
	if err != nil || len(evs) != 1 || evs[0].Kind != EventDefenseLogClr {
		t.Fatalf("Collect = %v, %v", evs, err)
	}
	// 取走后再取应为空（缓冲已清）
	evs, _ = p.Collect(nil)
	if len(evs) != 0 {
		t.Fatalf("第二次 Collect 应为空，得到 %d", len(evs))
	}
}

// TestPrivilegedSyncOnceStream 走「流式源 → 归一 → 入缓冲」这条链路。
// 平台源被替换成合成函数：要验的是 SyncOnce/Collect 的接线，不是 eslogger。
func TestPrivilegedSyncOnceStream(t *testing.T) {
	p := newTestPrivileged()
	p.src = func(ctx context.Context, sink func(privRecord)) error {
		sink(privRecord{Action: privActElevate, Exe: "/usr/bin/sudo", Target: "root", PID: 5, HasPID: true, HasTTY: true, TTY: "ttys000"})
		sink(privRecord{Action: privActKextload, Exe: "/sbin/kextload"})
		sink(privRecord{Action: "exec", Exe: "/bin/ls"}) // 必须被判定层丢掉
		return nil
	}
	if n := p.SyncOnce(context.Background(), time.Second); n != 2 {
		t.Fatalf("SyncOnce 入缓冲 %d 条，want 2", n)
	}
	evs, err := p.Collect(context.Background())
	if err != nil || len(evs) != 2 {
		t.Fatalf("Collect = %d 条, %v (want 2)", len(evs), err)
	}
	kinds := map[string]bool{evs[0].Kind: true, evs[1].Kind: true}
	if !kinds[EventPrivEscalate] || !kinds[EventSystemKextload] {
		t.Fatalf("kinds=%v", kinds)
	}
}

// TestPrivilegedStartSetsState Start 必须把 started/connected 置上，
// 并且在 ctx 取消后退出（否则 --once 之外的模式会漏 goroutine）。
func TestPrivilegedStartSetsState(t *testing.T) {
	p := newTestPrivileged()
	closed := make(chan struct{})
	p.src = func(ctx context.Context, sink func(privRecord)) error {
		sink(privRecord{Action: privActLogCleared, Exe: "eventlog"})
		close(closed)
		<-ctx.Done() // 像真实流一样挂着，等取消
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.Start(ctx)
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("Start 没有启动数据源")
	}
	// 等 Start 把 started 置上
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		snap := p.Snapshot()
		if snap["started"] == true {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if snap := p.Snapshot(); snap["started"] != true {
		t.Fatalf("started 未置位: %v", snap)
	}
	evs, _ := p.Collect(context.Background())
	if len(evs) != 1 || evs[0].Kind != EventDefenseLogClr {
		t.Fatalf("Collect = %v", evs)
	}
	cancel()
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestPrivilegedProbeDarwinNonRoot 本机实测：非 root 下 Probe 的原因必须
// 明确指向 root/Full Disk Access，而不是 nil 或一句英文报错。
func TestPrivilegedProbeDarwinNonRoot(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("只在 macOS 上验证 eslogger 的探测文本")
	}
	if os.Geteuid() == 0 {
		t.Skip("root 下 probe 会真的去起 eslogger，单元测试不跑")
	}
	err := platformProbePrivileged()
	if err == nil {
		t.Fatal("非 root 下 Probe 必须报不可用，不许返回 nil")
	}
	msg := err.Error()
	for _, want := range []string{"root", "Full Disk Access"} {
		if !strings.Contains(msg, want) {
			t.Errorf("原因里应含 %q，实际: %s", want, msg)
		}
	}
	// 采集器层面：不可用时 Status.Available=false 且 Reason 有内容
	p := NewPrivileged(Config{})
	if p.(*Privileged).Status.Available {
		t.Fatal("非 root 下 privileged 不该显示为可用")
	}
	if p.(*Privileged).Status.Reason == "" {
		t.Fatal("Status.Reason 不能为空（控制台要显示原因）")
	}
	// 不可用时 Collect 不许报错（错误已进 Reason，重复报错会污染轮询循环）
	if evs, err := p.Collect(context.Background()); err != nil || evs != nil {
		t.Fatalf("不可用采集器的 Collect 应为 (nil,nil)，得到 (%v,%v)", evs, err)
	}
}
