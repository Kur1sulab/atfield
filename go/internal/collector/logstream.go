package collector

// logstream.go —— 实时遥测流采集器：订阅系统日志流，按签名表把原始行
// 归成 UEM 事件。
//
// 对标 Python 版 atfield/collectors/logstream.py（178 行）。对齐关系：
//
//	签名表 SIGNATURES  7 条（正则, kind, severity, note），顺序即优先级
//	噪声表 NOISE       与 Python 同一条正则
//	判定顺序           先噪声过滤 → 再限速 → 再逐条签名匹配 → **首个命中即 break**
//	字段               kind/source/process/cmdline(≤400)/severity/pid/user("")/
//	                   path/subject{note,subsystem,category,raw_process}/
//	                   raw{eventMessage(≤800)}
//	限速               max_per_second（默认 40），超了 drops++ 并丢
//	缓冲               collect() 每轮取走全部，返回最后 400 条
//
// 数据源按平台分流（logstream_<platform>.go）：
//	macOS    `log stream --style ndjson --predicate ...`
//	Linux    `journalctl -f -o json --no-pager`（+ 客户端谓词过滤）
//	Windows  `wevtutil qe Security /f:text /rd:true` 轮询
//	          （没有「流」可用；Windows 的事件流要么需要 ETW 的
//	           EvtSubscribe API（cgo/syscall），要么自己轮询。
//	           零依赖约束下选轮询，并在 Probe 里说清楚这是轮询不是流。）
//
// 平台不支持时的处理：Probe 返回具体原因（缺命令 / 缺权限 / 平台无此能力），
// 由 Base.Init 标记 Available=false 并把原因写进 Status.Reason，控制台直接显示。
// 绝不静默返回空事件——「logstream 正常，0 事件」和「根本没接上」在控制台上
// 必须长得不一样。

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Kur1sulab/atfield/go/internal/model"
)

// 事件类型（与 Python 签名表右列逐字一致）。
const (
	EventAuthSuccess      = "auth.success"
	EventTCCDeny          = "tcc.deny"
	EventAVDetect         = "av.detect"
	EventDefenseEvent     = "defense.event"
	EventCredentialAccess = "credential.access"
)

// logSignature 一条事件签名。顺序即优先级：先命中先出，一条日志只归一类。
type logSignature struct {
	Re   *regexp.Regexp
	Kind string
	Sev  string
	Note string
}

// logSignatures 与 Python SIGNATURES 逐条对应（正则文本、kind、severity、
// note 全同）。注意第 1 条与第 3 条都产 auth.fail，只是 severity 不同：
// 泛化的 "authentication failure" 是 medium，明确的 SSH 爆破迹象是 high。
var logSignatures = []logSignature{
	{mustRe(`SUDO|sudo.*incorrect|authentication failure`), EventAuthFail, "medium", "认证失败"},
	{mustRe(`Accepted publickey|Accepted password`), EventAuthSuccess, "medium", "远程登录成功"},
	{mustRe(`Invalid user|Failed publickey|Failed password`), EventAuthFail, "high", "SSH 爆破迹象"},
	{mustRe(`Deny .*file|Deny .*process|TCC.*denied|deny\(1\)`), EventTCCDeny, "medium", "TCC 权限被拒（疑似越权访问）"},
	{mustRe(`XProtect|malware|MalwareRemoved|Remediat`), EventAVDetect, "critical", "XProtect 恶意软件告警"},
	{mustRe(`gatekeeper|spctl|notariz`), EventDefenseEvent, "medium", "Gatekeeper 相关事件"},
	{mustRe(`securityd.*(fail|error)|keychain.*denied`), EventCredentialAccess, "medium", "钥匙串访问异常"},
}

// logNoise 噪声过滤，与 Python NOISE 同一条正则。
// 拆成多段拼接是为了保持与原文逐字可比（Go 的 raw string 里不能有 \n 折叠）。
var logNoise = mustRe(`(com\.apple\.(distnoted|cfprefsd|mdworker|xpcservice|spotlight|coreduet)|` +
	`Connection invalid|promiscuous|_LSContextUpdate|Sandbox: |` +
	`UIKit|CoreAnalytics|tccd.*(Request|Prompt|grant))`)

func mustRe(expr string) *regexp.Regexp {
	re, err := regexp.Compile("(?i)" + expr)
	if err != nil {
		// 正则写错是编码错误，不是运行时错误：直接 panic 让测试第一轮就炸，
		// 而不是带着空签名表静默跑（那会让 logstream 变成「永远 0 事件」）。
		panic("logstream: 非法正则 " + expr + ": " + err.Error())
	}
	return re
}

// logRecord 一条原始日志记录（ndjson / journal json 归一）。
type logRecord struct {
	Msg     string // eventMessage | composedMessage | MESSAGE
	Process string // 进程名（已取 basename，进 ev.Process）
	// RawProc 是**未取 basename** 的原始 process 字段，进 subject.raw_process。
	// 与 Python 对齐：`subject.raw_process = rec.get("process") or ""` 用的是
	// 原始值（"sshd"），不是 basename（"/usr/sbin/sshd" → "sshd" 恰好相同，
	// 但 log stream 的 process 字段有时带参数，两者会不等）。
	RawProc  string
	Image    string // processImagePath（进 ev.Path）
	Subsys   string
	Category string
	PID      int
	HasPID   bool
	TS       float64 // 事件时间（日志自带），0 = 用采集时间
}

// parseNDJSON 解析 macOS `log stream --style ndjson` 的一行。
// 与 Python 的 _norm/_msg/_proc 同口径：
//
//	msg  = eventMessage || composedMessage
//	proc = basename(processImagePath || process)
func parseNDJSON(line string) (logRecord, bool) {
	line = strings.TrimSpace(line)
	if line == "" || !strings.HasPrefix(line, "{") {
		return logRecord{}, false
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return logRecord{}, false
	}
	rec := logRecord{
		Msg:      firstNonEmpty(str(raw["eventMessage"]), str(raw["composedMessage"])),
		Image:    str(raw["processImagePath"]),
		RawProc:  str(raw["process"]),
		Subsys:   str(raw["subsystem"]),
		Category: str(raw["category"]),
	}
	proc := firstNonEmpty(rec.Image, rec.RawProc)
	rec.Process = baseName(proc)
	if v, ok := raw["processID"]; ok {
		if n, ok := v.(float64); ok {
			rec.PID, rec.HasPID = int(n), true
		}
	}
	return rec, rec.Msg != ""
}

// parseJournalJSON 解析 `journalctl -o json` 的一行。
// journal 的字段名是 _PID / SYSLOG_IDENTIFIER / _COMM / MESSAGE。
// 归一成与 macOS 相同的 logRecord，判定因此只有一份。
func parseJournalJSON(line string) (logRecord, bool) {
	line = strings.TrimSpace(line)
	if line == "" || !strings.HasPrefix(line, "{") {
		return logRecord{}, false
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return logRecord{}, false
	}
	rec := logRecord{
		Msg:      firstNonEmpty(str(raw["MESSAGE"]), str(raw["SYSLOG_IDENTIFIER"])),
		RawProc:  firstNonEmpty(str(raw["SYSLOG_IDENTIFIER"]), str(raw["_COMM"])),
		Image:    str(raw["_EXE"]),
		Subsys:   str(raw["_SYSTEMD_UNIT"]),
		Category: str(raw["SYSLOG_FACILITY"]),
	}
	rec.Process = baseName(firstNonEmpty(rec.Image, rec.RawProc))
	if v := str(raw["_PID"]); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			rec.PID, rec.HasPID = n, true
		}
	}
	return rec, rec.Msg != ""
}

// parseWindowsEventText 把 wevtutil 的 /f:text 输出块转成 logRecord。
// 复用 session_parse.go 的 parseWevtutilText，避免两套事件解析。
func parseWindowsEventText(text string) []logRecord {
	var out []logRecord
	for _, ev := range parseWevtutilText(text) {
		msg := firstNonEmpty(ev.Fields["Message"], ev.Fields["Description"])
		if msg == "" && len(ev.Lines) > 0 {
			// 没有 Message 字段时退化成「所有字段行拼起来」：
			// 签名匹配只要能看到关键字，不需要结构化。
			msg = strings.Join(ev.Lines, " | ")
		}
		if msg == "" {
			continue
		}
		rec := logRecord{
			Msg:      msg,
			Process:  firstNonEmpty(ev.Fields["Provider Name"], ev.Fields["Source"], "eventlog"),
			Subsys:   firstNonEmpty(ev.Fields["Channel"], "Security"),
			Category: firstNonEmpty(ev.Fields["Task"], str(ev.Fields["Event ID"])),
		}
		rec.RawProc = rec.Process
		out = append(out, rec)
	}
	return out
}

// str map 里取字符串（json.Unmarshal 到 any 后统一走这里）。
func str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		// 整数值的 float 去掉小数点，免得 pid 变成 "1234.000000"
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x))
		}
		return fmt.Sprintf("%v", x)
	case json.Number:
		return x.String()
	}
	return ""
}

// journalSelector 客户端谓词：进程名或 unit 命中即保留。
// 与 macOS 的 predicate 同语义（sudo/sshd/authd/securityd/tccd/内核审计），
// 外加 Linux 特有的 sshd-session / polkitd / audit。
var journalSelector = []string{
	"sudo", "sshd", "sshd-session", "authd", "securityd", "tccd",
	"polkitd", "audit", "systemd-logind", "gdm", "login", "su", "cron",
	"xprotect", "clamd", "freshclam",
}

// journalSelected 判断一条 journal 记录是否属于关注面。
// identifier / _COMM / unit 任一命中即保留；全部缺失时保守保留
// （宁可多过滤一层签名，也不要把真正的事件漏在入口）。
func journalSelected(rec logRecord) bool {
	if rec.Process == "" && rec.Subsys == "" {
		return true
	}
	hay := strings.ToLower(rec.Process + " " + rec.Subsys)
	for _, sel := range journalSelector {
		if strings.Contains(hay, sel) {
			return true
		}
	}
	return false
}

// LogStream 实时遥测采集器。
type LogStream struct {
	Base

	mu        sync.Mutex
	buf       []model.Event
	drops     int64
	connected bool
	buffered  int // 上一次 Collect 取走的条数（Python: state["buffered"]）
	maxRate   int
	rate      int
	rateWin   time.Time

	// src 平台数据源：把原始行推给 handle 直到 ctx 取消
	src  func(context.Context, func(string)) error
	kind string // "stream"（macOS/Linux 长驻）| "poll"（Windows 轮询）

	started    bool // Start() 是否已起过长驻 goroutine
	autoSyncOn bool // 是否允许「首轮补采」（只有 NewLogStream 打开；测试构造的不开）
	autoSync   bool // 是否已补采过（补采只做一次）
}

// defaultLogPredicate macOS 的订阅谓词。
// 与 Python config.py 的 logstream.predicate 逐字相同：只订阅有安全语义的
// 子系统/进程，否则系统噪声会把签名表淹掉。
const defaultLogPredicate = `process == "sudo" OR process == "sshd" OR process == "authd" ` +
	`OR process == "securityd" OR process == "tccd" ` +
	`OR subsystem == "com.apple.TCC" OR process == "XProtect" ` +
	`OR process == "XProtectRemediator" OR process == "coreduetd"`

// NewLogStream 构造并自检。
func NewLogStream(cfg Config) Collector {
	ls := &LogStream{maxRate: 40, kind: "stream", autoSyncOn: true}
	predicate := defaultLogPredicate
	if v, ok := cfg.Options["predicate"].(string); ok && strings.TrimSpace(v) != "" {
		predicate = v
	}
	ls.src = func(ctx context.Context, sink func(string)) error {
		return platformLogSource(ctx, predicate, sink)
	}
	ls.kind = platformLogSourceKind()
	if v, ok := cfg.Options["max_per_second"].(int); ok && v > 0 {
		ls.maxRate = v
	}
	// Python interval = 0（流式采集器没有周期，collect 只是把缓冲取走）。
	// Go 版 ModeStream + 1s 的「取缓冲」节奏：RunOnce 需要一个周期来驱动，
	// 0 会被 Base.Init 兜成 5s，缓冲最多积压 5 秒，太钝。
	ls.Init("logstream", ModeStream, time.Second, platformProbeLogStream)
	if !cfg.WantEnabled() {
		ls.Status.Enabled = false
	}
	return ls
}

// Items 本轮取走的事件数（清点用）。
func (ls *LogStream) Items() int {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	return len(ls.buf)
}

// Start 启动长驻订阅（对应 Python 的 Collector.start()）。
// 由 main 在 --once 之外的场景调用；--once 下走 SyncOnce。
func (ls *LogStream) Start(ctx context.Context) {
	if ls.Probe() != nil {
		return
	}
	ls.mu.Lock()
	ls.started = true
	ls.mu.Unlock()
	go func() {
		for ctx.Err() == nil {
			ls.mu.Lock()
			ls.connected = true
			ls.mu.Unlock()
			err := ls.src(ctx, ls.handleLine)
			ls.mu.Lock()
			ls.connected = false
			ls.mu.Unlock()
			if err == nil || ctx.Err() != nil {
				return
			}
			// 断流重连（Python: time.sleep(3)）
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
			}
		}
	}()
}

// SyncOnce 单轮拉取：给 `--once` / 测试用。
// 平台数据源是「流」时用一个短超时的子 context 拉一小段就返回，
// 这样 `atfieldd --once` 也能拿到真实事件而不是空。
func (ls *LogStream) SyncOnce(ctx context.Context, window time.Duration) int {
	if ls.Probe() != nil {
		return 0
	}
	cctx, cancel := context.WithTimeout(ctx, window)
	defer cancel()
	_ = ls.src(cctx, ls.handleLine)
	ls.mu.Lock()
	defer ls.mu.Unlock()
	return len(ls.buf)
}

// handleLine 处理一行原始日志：噪声 → 限速 → 签名。
// 判定顺序与 Python 的 _handle 完全一致，包括「首个命中即 break」。
func (ls *LogStream) handleLine(line string) {
	rec, ok := parseLogLine(line, ls.kind)
	if !ok || rec.Msg == "" {
		return
	}
	// 噪声过滤：消息或 subsystem 命中噪声表就丢（Python 同条件）
	if logNoise.MatchString(rec.Msg) || (rec.Subsys != "" && logNoise.MatchString(rec.Subsys)) {
		return
	}

	ls.mu.Lock()
	now := time.Now()
	if now.Sub(ls.rateWin) >= time.Second {
		ls.rate = 0
		ls.rateWin = now
	}
	ls.rate++
	if ls.rate > ls.maxRate {
		ls.drops++
		ls.mu.Unlock()
		return
	}
	ls.mu.Unlock()

	blob := rec.Process + " " + rec.Msg
	for _, sig := range logSignatures {
		if !sig.Re.MatchString(blob) {
			continue
		}
		ev := model.NewEvent(sig.Kind, "logstream")
		if rec.TS > 0 {
			ev.TS = rec.TS
		}
		ev.Process = rec.Process
		ev.Cmdline = clip(rec.Msg, 400)
		ev.Severity = sig.Sev
		ev.Path = rec.Image
		if rec.HasPID {
			pid := rec.PID
			ev.PID = &pid
		}
		ev.Subject = map[string]any{
			"note":        sig.Note,
			"subsystem":   rec.Subsys,
			"category":    rec.Category,
			"raw_process": rec.RawProc,
		}
		ev.Raw = map[string]any{"eventMessage": clip(rec.Msg, 800)}

		ls.mu.Lock()
		ls.buf = append(ls.buf, *ev)
		ls.mu.Unlock()
		break // 首个命中即止：一条日志只归一类，与 Python 同
	}
}

// parseLogLine 按数据源类型选解析器。
func parseLogLine(line, kind string) (logRecord, bool) {
	switch kind {
	case "journal":
		return parseJournalJSON(line)
	case "wevtutil":
		recs := parseWindowsEventText(line)
		if len(recs) == 0 {
			return logRecord{}, false
		}
		return recs[0], true
	default:
		return parseNDJSON(line)
	}
}

// Collect 取走缓冲（Python: buf[-400:]）。
//
// **与 Python 的一处有意差异（必须记下来）**：Python 的 core.start() 会先给
// 所有 mode=="stream" 的采集器调 start() 起线程，主循环才 collect()。Go 版
// 的 atfieldd 目前只有 `--once` 这一条驱动路径（服务模式的主循环还没落地），
// 没人调 Start() → 缓冲永远是空的 → `--once` 下 logstream 恒定 0 事件，
// 审机器的人看到的是「接了但没数据」，分不清是安静还是没接上。
//
// 所以这里做一次**惰性补采**：没 Start 过、缓冲为空、且还没补采过 → 现场跑
// 3 秒真实订阅再取。只做一次（autoSync 标记），否则轮询循环每轮都会阻塞 3s。
// 服务模式（Start 已调用）不会走到这条分支，行为与 Python 一致。
func (ls *LogStream) Collect(ctx context.Context) ([]model.Event, error) {
	ls.mu.Lock()
	needSync := ls.autoSyncOn && !ls.started && !ls.autoSync && len(ls.buf) == 0
	if needSync {
		ls.autoSync = true
	}
	ls.mu.Unlock()
	if needSync {
		ls.SyncOnce(ctx, 3*time.Second)
	}

	ls.mu.Lock()
	defer ls.mu.Unlock()
	if len(ls.buf) == 0 {
		ls.buffered = 0 // Python：缓冲空时状态里也写 buffered=0
		return nil, nil
	}
	buf := ls.buf
	ls.buf = nil
	ls.buffered = len(buf) // 与 Python 一致：记「取走多少」而不是「截断后剩多少」
	if len(buf) > 400 {
		buf = buf[len(buf)-400:]
	}
	return buf, nil
}

// Snapshot 等价于 Python 的 store.set_state("logstream", ...)，键名相同。
func (ls *LogStream) Snapshot() map[string]any {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	return map[string]any{
		"connected": ls.connected,
		"buffered":  ls.buffered,
		"drops":     ls.drops,
		"ts":        nowSeconds(),
	}
}

// Close 停订阅。数据源靠 ctx 取消退出，这里只清状态。
func (ls *LogStream) Close() error {
	ls.mu.Lock()
	ls.connected = false
	ls.mu.Unlock()
	return nil
}

// readLines 把 Reader 按行喂给 sink，ctx 取消即返回。
// 三平台数据源共用（bufio.Scanner 的默认 64KB 上限对日志行足够，
// 超长行会被截断——日志行超过 64KB 只可能是二进制垃圾）。
func readLines(ctx context.Context, r interface{ Read([]byte) (int, error) }, sink func(string)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		sink(sc.Text())
	}
	if err := sc.Err(); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}
