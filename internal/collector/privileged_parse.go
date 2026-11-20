package collector

// privileged_parse.go —— 三平台原生遥测的解析器（不带 build tag）。
//
// 为什么解析器要跨平台：Windows 的 wevtutil 文本、Linux 的 audit.log 行、
// macOS 的 eslogger NDJSON，本机（darwin）一台机器就能全测。放到 _windows.go
// 里就只能「能编译」——那不是证据。persistence_parse.go / session_parse.go
// 用的是同一套办法，这里保持一致。
//
// 解析器的唯一职责：把原生字段搬进 privRecord，并把「原生动作」翻译成
// privAct* 之一。任何判定（severity、要不要报）都不许写在这里。

import (
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// ---- eslogger ----

// esActionMap eslogger 事件类型 → 归一动作。
// 与 Python 版 ES_INTEREST 的键集合一致，但值只保留「有提权语义」的那几个：
// exec/fork/exit/open/signal/xpc_connect 不在表里 → 解析层直接丢，
// 理由见 privileged.go 文件头的「刻意分歧」。
var esActionMap = map[string]string{
	"setuid":                   privActSetuid,
	"seteuid":                  privActSeteuid,
	"create":                   privActFileCreate,
	"write":                    privActFileWrite,
	"unlink":                   privActFileDelete,
	"rename":                   privActFileRename,
	"open":                     privActFileOpen,
	"kextload":                 privActKextload,
	"mount":                    privActMount,
	"cs_invalidated":           privActCSInvalid,
	"gatekeeper_user_override": privActGKOverride,
}

// parseESLoggerLine 解析一行 eslogger NDJSON。
//
// eslogger 的输出形状随版本变过一次：老版是 {"event":{"event":"exec",...}}，
// 新版把事件类型直接做成键 {"event":{"exec":{...}}}。两种都认，
// 因为「升级 macOS 就静默采不到数据」是这类采集器最常见的死法。
func parseESLoggerLine(line string) (privRecord, bool) {
	line = strings.TrimSpace(line)
	if line == "" || line[0] != '{' {
		return privRecord{}, false
	}
	var root map[string]any
	if err := json.Unmarshal([]byte(line), &root); err != nil {
		return privRecord{}, false
	}
	evObj, _ := root["event"].(map[string]any)
	if evObj == nil {
		return privRecord{}, false
	}

	etype := strings.ToLower(str(evObj["event"]))
	if etype == "" {
		// 新版形状：event 下第一个对象键就是事件类型
		for k, v := range evObj {
			if _, ok := v.(map[string]any); ok {
				etype = strings.ToLower(k)
				break
			}
		}
	}
	action, ok := esActionMap[etype]
	if !ok {
		return privRecord{}, false
	}

	proc, _ := root["process"].(map[string]any)
	exeObj, _ := proc["executable"].(map[string]any)
	exe := str(exeObj["path"])
	rec := privRecord{
		Source:  "eslogger",
		EType:   etype,
		Action:  action,
		TS:      numToF(str(root["time"])),
		PID:     int(numToF(str(proc["audit_id"]))),
		PPID:    int(numToF(str(proc["ppid"]))),
		HasPID:  proc["audit_id"] != nil,
		User:    "",
		Process: str(proc["name"]),
		Exe:     exe,
		Argv:    strSlice(exeObj["args"]),
		Signing: str(proc["signing_id"]),
		Raw:     line,
	}
	// 用户名：eslogger 在 process 里给 auid/uid 的数字，也可能给 user 名字。
	if u := str(proc["user"]); u != "" {
		rec.User = u
	} else if uid := str(proc["uid"]); uid != "" {
		rec.User = "uid:" + uid
	}
	rec.Cmdline = strings.Join(rec.Argv, " ")
	if rec.Cmdline == "" {
		rec.Cmdline = exe
	}

	// 目标：文件类取 file/target 的 path；setuid 取 uid。
	// 新形状把目标嵌在事件对象里（{"write":{"target":{"path":..}}}），
	// 所以先看事件对象内部，再看 evObj 顶层。
	evBody, _ := evObj[etype].(map[string]any)
	if f, ok := evBody["file"].(map[string]any); ok {
		rec.Target = str(f["path"])
	}
	if rec.Target == "" {
		if t, ok := evBody["target"].(map[string]any); ok {
			rec.Target = str(t["path"])
		}
	}
	if f, ok := evObj["file"].(map[string]any); ok && rec.Target == "" {
		rec.Target = str(f["path"])
	}
	if rec.Target == "" {
		if t, ok := evObj["target"].(map[string]any); ok {
			rec.Target = str(t["path"])
		}
	}
	if action == privActSetuid || action == privActSeteuid {
		if s, ok := evObj[etype].(map[string]any); ok {
			rec.Target = firstNonEmpty(str(s["uid"]), str(s["target_uid"]), str(evObj["uid"]), rec.Target)
			if v, ok := s["success"].(bool); ok {
				rec.Success, rec.HasSuccess = v, true
			}
		}
		if rec.Target == "" {
			rec.Target = str(evObj["uid"])
		}
	}
	return rec, true
}

// numToF 宽松取数：eslogger 的时间戳是浮点秒（"time":"1700000000.123"）。
func numToF(s string) float64 {
	if s == "" {
		return 0
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return v
}

// strSlice JSON 数组 → []string。
func strSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		if s := str(x); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// ---- auditd ----

// auditHead 匹配 audit.log 的每条记录头：type=SYSCALL msg=audit(1700000000.123:4567):
var auditHead = mustRe(`^type=([A-Z0-9_]+) msg=audit\((\d+\.\d+):(\d+)\):\s*(.*)$`)

// auditKV 匹配 "k=v" 与带引号的 "k=\"v v\""。
var auditKV = mustRe(`([A-Za-z0-9_]+)=("([^"]*)"|\S+)`)

// auditSetuidSyscalls setuid 家族的系统调用号（x86_64 与 aarch64 两套）。
//
//	105 setuid / 113 setreuid / 117 setresuid   (x86_64)
//	146 setuid / 147 setreuid / 149 setresuid   (aarch64)
var auditSetuidSyscalls = map[string]bool{
	"105": true, "113": true, "117": true,
	"146": true, "147": true, "149": true,
}

// auditElevatorNames 提权程序的 comm/exe 基名。
var auditElevatorNames = map[string]bool{
	"sudo": true, "su": true, "doas": true, "pkexec": true, "runuser": true,
}

// auditGroup 同一个 audit 事件 ID 下的多条记录（SYSCALL + EXECVE + USER_CMD …）。
type auditGroup struct {
	id      string
	ts      float64
	syscall map[string]string
	argv    []string
	userCmd string
	authRes string
	authAcc string
	authExe string
	confOp  string
	confKey string
	raw     []string
	// 记录顺序里第一次出现的 type（诊断用）
	firstType string
}

// parseAuditLog 解析 audit.log 文本 → 提权记录。
//
// 合并规则：auditd 把「一次系统调用」拆成多条记录（SYSCALL 给进程与结果，
// EXECVE 给参数，USER_CMD/USER_AUTH 给 sudo 的语义）。按 msg=audit(ts:id)
// 的 id 合并，一个 id 最多产一条记录（优先级 USER_CMD > USER_AUTH >
// setuid 系统调用 > CONFIG_CHANGE），否则同一个 sudo 会变成三条告警。
func parseAuditLog(text string) []privRecord {
	groups := map[string]*auditGroup{}
	var order []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		m := auditHead.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		typ, ts, id, body := m[1], m[2], m[3], m[4]
		g := groups[id]
		if g == nil {
			// syscall 留 nil：初始化成空 map 会让后面的 `if g.syscall == nil`
			// 永远不成立，USER_CMD 那条的 pid/tty 就再也填不进去
			// （第一版就是这么错的，单测里 pid=0 暴露）。
			g = &auditGroup{id: id, ts: numToF(ts), firstType: typ}
			groups[id] = g
			order = append(order, id)
		}
		if g.ts == 0 {
			g.ts = numToF(ts)
		}
		g.raw = append(g.raw, line)

		kv := map[string]string{}
		for _, mm := range auditKV.FindAllStringSubmatch(body, -1) {
			// 单引号也要剥：auditd 把 USER_CMD/USER_AUTH 的整个 msg 用 '...' 包起来，
			// 于是 res=failed' 这种尾巴会带引号——第一版只 Trim 了双引号，
			// 结果 sudo 认证失败永远匹配不上（测试里的反例当场发现）。
			if mm[3] != "" {
				kv[mm[1]] = mm[3]
			} else {
				kv[mm[1]] = strings.Trim(mm[2], `"'`)
			}
		}
		switch typ {
		case "SYSCALL":
			g.syscall = kv
		case "EXECVE":
			g.argv = auditArgv(kv)
		case "USER_CMD":
			if cmd, ok := kv["cmd"]; ok {
				g.userCmd = decodeAuditHex(cmd)
			}
			if g.syscall == nil {
				g.syscall = kv
			}
		case "USER_AUTH":
			g.authRes = strings.ToLower(kv["res"])
			g.authAcc = kv["acct"]
			g.authExe = kv["exe"]
		case "CONFIG_CHANGE":
			g.confOp = strings.ToLower(kv["op"])
			g.confKey = kv["key"]
		}
	}

	var out []privRecord
	for _, id := range order {
		g := groups[id]
		if rec, ok := auditRecord(g); ok {
			out = append(out, rec)
		}
	}
	return out
}

// auditArgv 从 EXECVE 记录里按 argc 顺序取 a0..aN。
// 注意 a0_len/a1[0] 这类分段字段（参数里有换行时 auditd 会拆）——
// 只取不带下标的键，够用且不会拼错。
func auditArgv(kv map[string]string) []string {
	n, err := strconv.Atoi(kv["argc"])
	if err != nil || n <= 0 || n > 64 {
		n = 0
	}
	var out []string
	for i := 0; i < n; i++ {
		k := "a" + strconv.Itoa(i)
		if v, ok := kv[k]; ok {
			out = append(out, decodeAuditHex(v))
		}
	}
	return out
}

// decodeAuditHex auditd 对含特殊字符的参数用十六进制编码（cmd=7375202D69）。
// 不含十六进制的原样返回；奇数长度或非 hex 也原样返回（宁可留编码，不要丢内容）。
func decodeAuditHex(s string) string {
	if len(s) < 4 || len(s)%2 != 0 {
		return s
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return s
		}
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return s
	}
	// 解出来必须可打印，否则说明它本来就是个普通单词（如 "dead"）。
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return s
		}
	}
	return string(b)
}

// auditRecord 把一个 audit 事件组翻成一条 privRecord。
func auditRecord(g *auditGroup) (privRecord, bool) {
	kv := g.syscall
	exe := firstNonEmpty(kv["exe"], g.authExe)
	comm := kv["comm"]
	pid, _ := strconv.Atoi(firstNonEmpty(kv["pid"], "0"))
	ppid, _ := strconv.Atoi(firstNonEmpty(kv["ppid"], "0"))
	rec := privRecord{
		Source:  "auditd",
		EType:   g.firstType,
		TS:      g.ts,
		PID:     pid,
		PPID:    ppid,
		HasPID:  pid > 0,
		User:    firstNonEmpty(kv["acct"], kv["auid"]),
		Process: comm,
		Exe:     exe,
		Argv:    g.argv,
		TTY:     firstNonEmpty(kv["terminal"], kv["tty"]),
		Raw:     strings.Join(g.raw, "\n"),
	}
	rec.HasTTY = kv["tty"] != "" || kv["terminal"] != ""
	if rec.User != "" && rec.User != "4294967295" && !strings.HasPrefix(rec.User, "uid:") {
		// auid 是数字时标一下，控制台能分清「账户名」和「uid」。
		if _, err := strconv.Atoi(rec.User); err == nil {
			rec.User = "uid:" + rec.User
		}
	}
	rec.Cmdline = strings.Join(rec.Argv, " ")

	// 1) sudo 执行命令（最干净的提权证据）
	if g.userCmd != "" {
		rec.Action = privActElevate
		rec.Cmdline = g.userCmd
		rec.Target = "root"
		return rec, true
	}
	// 2) 提权认证失败
	if g.authRes != "" {
		if g.authRes == "failed" {
			rec.Action = privActAuthFail
			rec.Target = g.authAcc
			rec.Cmdline = firstNonEmpty(rec.Cmdline, exe)
			return rec, true
		}
		return privRecord{}, false
	}
	// 3) setuid 家族系统调用 → 只有目标 uid 为 0 才算
	if sc := kv["syscall"]; sc != "" && auditSetuidSyscalls[sc] {
		if strings.ToLower(kv["success"]) != "yes" {
			return privRecord{}, false
		}
		target := firstNonEmpty(kv["a0"], kv["euid"])
		if target != "0" {
			return privRecord{}, false
		}
		rec.Target = "0"
		if sc == "117" || sc == "149" { // setresuid 只看第一参
			rec.Target = firstNonEmpty(kv["a0"], "0")
		}
		rec.Action = privActSetuid
		rec.Success, rec.HasSuccess = true, true
		return rec, true
	}
	// 4) 审计规则被删（先关摄像头再动手）
	if g.confOp != "" {
		if strings.Contains(g.confOp, "remove_rule") || strings.Contains(g.confOp, "del_rule") {
			rec.Action = privActAuditRuleOff
			rec.Target = g.confKey
			return rec, true
		}
		return privRecord{}, false
	}
	// 5) 提权程序 exec（sudo/su/doas 出现在 execve 上，且已经是 root）
	if auditElevatorNames[strings.ToLower(baseName(exe))] && kv["euid"] == "0" {
		rec.Action = privActElevate
		rec.Target = "root"
		return rec, true
	}
	return privRecord{}, false
}

// ---- Windows ----

// winPrivElevators Windows 上「提权动作」的可执行文件名。
var winPrivElevators = map[string]bool{"runas.exe": true, "consent.exe": true}

// baseNameAnyOS 取可执行文件名，POSIX 与 Windows 两种分隔符都认。
//
// 不能用 filepath.Base：它在 darwin/linux 上只认 '/'，
// "C:\Windows\System32\runas.exe" 会被原样返回，runas 永远匹配不上
// （Windows 事件文本要在 macOS 上单测，就必须自己切两种分隔符）。
// 顺带剥掉内核加的 " (deleted)" 后缀，与 process.go 的 baseName 同语义。
func baseNameAnyOS(p string) string {
	if p == "" {
		return ""
	}
	p = strings.TrimSuffix(p, " (deleted)")
	p = strings.TrimRight(p, `\/`)
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// parseWinSecurityEvents 解析 wevtutil /f:text 输出里的 4672/4688/1102。
//
// 只认这三类：
//
//	4672  特权分配给新登录（管理员等价登录）
//	4688  进程创建（runas / 高完整性 + 临时目录）
//	1102  审计日志被清空
//
// 4688 默认策略下是**关闭**的（「审核进程创建」未开就一条都没有）。
// 这一点写进 Limits，不假装能看见。
func parseWinSecurityEvents(text string) []privRecord {
	var out []privRecord
	for _, ev := range parseWevtutilText(text) {
		user := lastNonEmpty(ev.Fields["Subject User Name"], ev.Fields["Account Name"], ev.Fields["New Logon Account Name"])
		ts := winEventTS(ev)
		switch ev.ID {
		case 4672:
			out = append(out, privRecord{
				Source: "security-log", EType: "4672", Action: privActPrivAssigned,
				TS: ts, User: user, Process: "winlogon", Target: user,
				Raw: strings.Join(ev.Lines, "\n"),
			})
		case 1102:
			out = append(out, privRecord{
				Source: "security-log", EType: "1102", Action: privActLogCleared,
				TS: ts, User: user, Process: "eventlog",
				Raw: strings.Join(ev.Lines, "\n"),
			})
		case 4688:
			newProc := ev.Fields["New Process Name"]
			cmd := ev.Fields["Process Command Line"]
			creator := ev.Fields["Creator Process Name"]
			label := ev.Fields["Mandatory Label"]
			rec := privRecord{
				Source: "security-log", EType: "4688",
				TS: ts, User: user, Process: baseNameAnyOS(newProc), Exe: newProc,
				Cmdline: cmd, Target: creator, Raw: strings.Join(ev.Lines, "\n"),
			}
			lowCmd := strings.ToLower(cmd)
			switch {
			case winPrivElevators[strings.ToLower(baseNameAnyOS(newProc))]:
				rec.Action = privActElevate
				rec.Target = "elevated"
			case strings.Contains(lowCmd, "-verb runas"), strings.Contains(lowCmd, "runas /user:"):
				rec.Action = privActElevate
				rec.Target = "elevated"
			case privTempAnyOS(newProc) && strings.Contains(label, "S-1-16-12288"):
				// 临时目录里的进程却拿着高完整性令牌：UAC 提权后的落地执行。
				rec.Action = privActElevate
				rec.Target = "high-integrity"
			default:
				continue
			}
			out = append(out, rec)
		}
	}
	return out
}

// winEventTS wevtutil text 里的时间只有秒级字符串（"2026-11-21T02:31:07.123"），
// 解析失败就返回 0（judge 层会用当前时间兜底）。
func winEventTS(ev winEvent) float64 {
	s := strings.TrimSpace(ev.Time)
	if s == "" {
		return 0
	}
	for _, layout := range []string{"2006-01-02T15:04:05.999999999", "2006-01-02T15:04:05", "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return float64(t.UnixNano()) / 1e9
		}
	}
	return 0
}

// lastNonEmpty 取最后一个非空值。
//
// 为什么是「最后一个」：4624/4672 的文本里 Subject 与 Target 都有
// "Account Name"，先出现的永远是发起者（SYSTEM），要的是目标账户。
func lastNonEmpty(vals ...string) string {
	for i := len(vals) - 1; i >= 0; i-- {
		if strings.TrimSpace(vals[i]) != "" {
			return vals[i]
		}
	}
	return ""
}
