package collector

// session_parse.go —— 会话/认证日志各平台原生输出的解析器。
//
// 这一层故意**不带 build tag**：在 macOS 上 `go test ./...` 也能验证
// Windows 的 `quser` / `wevtutil` 输出、Linux 的 `auth.log` 行能不能被正确
// 归一。否则「Windows 会话采集器」在本机永远只有「编译通过」这一条证据。
//
// 与 persistence_parse.go 同一套纪律：解析器只做「原生格式 → 归一结构」，
// 判定（isRemoteSource / filterAuthFailLines）在 session.go 里只有一份。

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------- Windows quser

// parseQuser 解析 `quser` 输出（Windows 会话盘点）。
//
// 典型输出（列宽随用户名变化，所以只能按 token 走）：
//
//	 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
//	 xu.                   console             1  Active      none  11/18/2026 5:22 PM
//	 xxx              rdp-tcp#3           2  Active      1:23  11/19/2026 9:04 AM
//	>admin                 services            0  Disc         .    11/18/2026 5:20 PM
//
// 映射到 who 语义：
//
//	user    = 第 1 列（去掉行首的 `>`，那是「当前会话」标记）
//	tty     = SESSIONNAME 列（console / rdp-tcp#N / services）
//	from    = 同 SESSIONNAME —— Windows 的 who 不带来源地址，而会话名本身
//	          就够判定远程/本地：console 是本地，rdp-tcp#N 是远程
//	since   = LOGON TIME 列（最后 2~3 个 token：日期 + 时间 + AM/PM）
//
// 为什么 tty 用 SESSIONNAME 而不是 ID：ID 在重启后会重排，而
// user@sessionname 与 Python 版 user@tty 的稳定性语义一致，登出差分才可靠。
func parseQuser(out string) []whoSession {
	var rows []whoSession
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// 表头 / 本地化表头（中文系统是「用户名 会话名 ID 状态 ...」）
		if strings.Contains(trimmed, "USERNAME") || strings.Contains(trimmed, "SESSIONNAME") ||
			strings.Contains(trimmed, "用户名") || strings.Contains(trimmed, "会话名") {
			continue
		}
		line = strings.TrimPrefix(line, ">")
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		user := fields[0]
		session := fields[1]
		if user == "" || session == "" {
			continue
		}
		// LOGON TIME 在行尾：英文系统是「11/19/2026 9:04 AM」三个 token，
		// 24 小时制/中文系统只有两个。按「末 token 是不是 AM/PM」判断，
		// 不按列数猜——猜列数在 12 小时制但无 AM/PM 的系统上会切错。
		since := ""
		if n := len(fields); n >= 6 {
			if n >= 7 && isMeridiem(fields[n-1]) {
				since = strings.Join(fields[n-3:], " ")
			} else {
				since = strings.Join(fields[n-2:], " ")
			}
		}
		rows = append(rows, whoSession{
			User: user, TTY: session, From: session, Since: since,
			Remote: isRemoteSource(session),
		})
	}
	return rows
}

// ---------------------------------------------------------------- Windows 事件日志

// winEvent 一条 `wevtutil qe ... /f:text` 事件的最小模型。
type winEvent struct {
	ID   int
	Time string
	// Fields 事件里所有 "Key:\tValue" 形式的行（同名键后者覆盖前者：
	// 4624 里有多个 "Account Name"（Subject / New Logon），我们只要最后一个
	// 出现的目标账户——那正是登录成功的那个账户）。
	Fields map[string]string
	// Lines 原始文本行（按出现顺序），给"样本"用。
	Lines []string
}

var winEventHead = regexp.MustCompile(`^Event\[\d+\]:`)

// parseWevtutilText 解析 wevtutil 的 /f:text 输出。
//
// 分块规则：`Event[N]:` 起头，到下一个 `Event[N]:` 或 EOF 结束。
// 字段行规则：`Key:` 后面跟制表符或多个空格再跟值。值里可以有冒号
// （时间戳），所以只在**第一个**冒号处切。
func parseWevtutilText(text string) []winEvent {
	var out []winEvent
	var cur *winEvent
	flush := func() {
		if cur != nil {
			out = append(out, *cur)
		}
		cur = nil
	}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, "\r")
		if winEventHead.MatchString(strings.TrimSpace(line)) {
			flush()
			cur = &winEvent{Fields: map[string]string{}}
			continue
		}
		if cur == nil {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		cur.Lines = append(cur.Lines, trimmed)
		key, val, ok := splitEventField(trimmed)
		if !ok {
			continue
		}
		switch key {
		case "Event ID":
			if n, err := strconv.Atoi(strings.TrimSpace(val)); err == nil {
				cur.ID = n
			}
		case "Date":
			cur.Time = strings.TrimSpace(val)
		}
		cur.Fields[key] = strings.TrimSpace(val)
	}
	flush()
	return out
}

// splitEventField 切 "Key:\tValue"。键名限定为不含中文/空格的短串，
// 避免把描述正文里 "An account was successfully logged on." 这种句子误当字段。
func splitEventField(line string) (key, val string, ok bool) {
	i := strings.Index(line, ":")
	if i <= 0 || i > 40 {
		return "", "", false
	}
	key = line[:i]
	if strings.ContainsAny(key, "\t") {
		return "", "", false
	}
	for _, r := range key {
		if r > 127 {
			return "", "", false
		}
	}
	rest := line[i+1:]
	if rest != "" && rest[0] != ' ' && rest[0] != '\t' {
		return "", "", false // 形如 "9:04" 的时间值，不是字段
	}
	return key, strings.TrimSpace(rest), true
}

// winEventUser 从 4624/4625 事件里取账户名。
//
// 4625（失败）只有一个 "Account Name"（被拒的账户），直接取。
// 4624（成功）有两个：Subject（执行登录的机器账户）与 New Logon（登录的
// 账户），后者才是我们想要的，所以取**最后**一次出现——parseWevtutilText
// 的同名键覆盖语义正好给出这个结果。
func winEventUser(ev winEvent) string {
	if u := ev.Fields["Account Name"]; u != "" {
		return u
	}
	if u := ev.Fields["Target User Name"]; u != "" {
		return u
	}
	return ""
}

// winEventSource 4624/4625 的来源工作站；空表示本地。
func winEventSource(ev winEvent) string {
	for _, k := range []string{"Workstation Name", "IpAddress", "Source Network Address"} {
		if v := ev.Fields[k]; v != "" && v != "-" {
			return v
		}
	}
	return ""
}

// winEventsToSessions 4624（成功登录）→ 历史登录列表。
// 与 last 的语义对齐：只做态势，不告警。
func winEventsToSessions(evs []winEvent) []loginHist {
	var rows []loginHist
	for _, ev := range evs {
		if ev.ID != 4624 {
			continue
		}
		user := winEventUser(ev)
		if user == "" || strings.EqualFold(user, "SYSTEM") ||
			strings.HasSuffix(strings.ToLower(user), "$") {
			continue // 机器账户的登录是服务行为，不是人在登录
		}
		src := winEventSource(ev)
		rows = append(rows, loginHist{
			User: user,
			TTY:  firstNonEmpty(ev.Fields["Logon Type"], "security-log"),
			From: src,
			Raw:  fmt.Sprintf("%s logon=%s from=%s type=%s", ev.Time, user, firstNonEmpty(src, "local"), ev.Fields["Logon Type"]),
		})
	}
	return rows
}

// winEventsToAuthFailLines 4625（失败登录）→ 归一文本行。
//
// 关键：行里必须带 "Failed" 字样，才能被 session.go 里**唯一**的
// filterAuthFailLines 判为失败。这样三平台的失败判定只有一份实现，
// 不会出现「Windows 判得比 macOS 松」这种漂移。
func winEventsToAuthFailLines(evs []winEvent) []string {
	var lines []string
	for _, ev := range evs {
		if ev.ID != 4625 {
			continue
		}
		user := firstNonEmpty(winEventUser(ev), "(unknown)")
		src := firstNonEmpty(winEventSource(ev), "local")
		lines = append(lines, fmt.Sprintf("%s Failed logon user=%s from=%s type=%s status=%s",
			firstNonEmpty(ev.Time, "-"), user, src,
			firstNonEmpty(ev.Fields["Logon Type"], "-"),
			firstNonEmpty(ev.Fields["Status"], ev.Fields["Sub Status"], "-")))
	}
	return lines
}

// ---------------------------------------------------------------- Linux

// authLogCandidateRE Linux 认证日志的**预筛**条件（宽）。
//
// 为什么预筛宽、判定窄：
//   - 预筛只是「少读日志正文」的性能措施，宽一点无害（多读几行而已）；
//   - **最终判定始终是 filterAuthFailLines**（Failed / incorrect），
//     与 Python 版的集合逐字相同。
//
// 所以 pam_unix 的 "authentication failure"、sudo 的 "NOT in sudoers"
// 可以被预筛捞进来，但不会被算成 auth.fail——那会把 Go 版的 count 系统性
// 抬到 Python 版之上，对拍时看起来像「实现了额外逻辑」。要加它们必须先改
// Python 侧，两版一起改（MIGRATION.md「判定只有一份」的纪律）。
var authLogCandidateRE = regexp.MustCompile(`(?i)(failed|incorrect|authentication failure|not in sudoers)`)

// parseAuthLogText 从 /var/log/auth.log（或 /var/log/secure）正文里挑候选行。
// 返回值仍是「候选」，最终判定交给 filterAuthFailLines。
func parseAuthLogText(text string) []string {
	var out []string
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if authLogCandidateRE.MatchString(line) {
			out = append(out, line)
		}
	}
	return out
}

// journalAuthPredicate journalctl 的 grep 过滤（journalctl 的 --grep 只支持
// 单条扩展正则，多个词用 | 串起来）。
const journalAuthPredicate = "Failed|incorrect"

// parseJournalText journalctl 输出里挑候选行（与 parseAuthLogText 同规则，
// 单独留一个函数是为了让测试能分别钉住两种输入形状）。
func parseJournalText(text string) []string { return parseAuthLogText(text) }

// authLogTimeLayouts 认证日志行首时间戳的候选格式（按命中率排序）。
//
//	Jan _2 15:04:05   syslog / auth.log 经典格式（无年份）
//	2006-01-02T15:04:05            journal short-iso
//	2006-01-02 15:04:05            log show compact / rsyslog 高精度变体
//	2006-01-02T15:04:05Z07:00      RFC3339
var authLogTimeLayouts = []string{
	"Jan _2 15:04:05",
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05",
	time.RFC3339,
}

// parseAuthLogTime 从行首解析时间戳。
//
// 无年份的 syslog 格式按「今年」补：认证日志窗口是 5 分钟，跨年只会在
// 12/31-01/01 那一瞬间出错，那时把去年的 12/31 当今年会导致窗口内多算几行，
// 属于可接受误差（而且两版共用同一处判定）。
func parseAuthLogTime(line string, now time.Time) (time.Time, bool) {
	line = strings.TrimSpace(line)
	// 先截到 "Jan _2 15:04:05" 的定长 15 字符（syslog 的经典宽度）
	if len(line) >= 15 {
		if ts, err := time.ParseInLocation("Jan _2 15:04:05", line[:15], now.Location()); err == nil {
			return time.Date(now.Year(), ts.Month(), ts.Day(), ts.Hour(), ts.Minute(), ts.Second(), 0, now.Location()), true
		}
	}
	for _, layout := range authLogTimeLayouts[1:] {
		n := len(layout)
		if layout == time.RFC3339 {
			n = 25 // "2006-01-02T15:04:05-07:00"
		}
		if len(line) < n {
			continue
		}
		if ts, err := time.ParseInLocation(layout, line[:n], now.Location()); err == nil {
			return ts, true
		}
	}
	return time.Time{}, false
}

// filterAuthWindow 只保留窗口内的行（Linux 路径用：auth.log 的尾巴可能
// 横跨几小时，不裁窗口的话 subject.count 会远大于「5m」的语义，
// 与 macOS 的 `log show --last 5m` 不可比）。
//
// 解析不出时间戳的行**保留**：宁可多算，也不要把「时间格式没认出来」
// 静默变成「这段时间没有失败」。这类行会在 subject.count 里体现，
// 排障时能看出来。
func filterAuthWindow(lines []string, window time.Duration, now time.Time) []string {
	cut := now.Add(-window)
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		ts, ok := parseAuthLogTime(l, now)
		if !ok {
			out = append(out, l)
			continue
		}
		if !ts.Before(cut) {
			out = append(out, l)
		}
	}
	return out
}

// ---------------------------------------------------------------- 小工具

// isMeridiem 12 小时制的 AM/PM 标记（本地化系统可能是「上午/下午」）。
func isMeridiem(s string) bool {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "AM", "PM":
		return true
	}
	return s == "上午" || s == "下午"
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
