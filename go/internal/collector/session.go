package collector

// session.go —— 会话采集（SessionCollector）与认证失败回捞（AuthLogCollector）
// 的通用部分：解析、差分、事件组装都在这里；取原始数据按平台实现
// （session_darwin.go / session_linux.go / session_windows.go）。
//
// 对标 Python 版 atfield/collectors/session.py（109 行，两个类）。字段名、
// 判定条件、严重度分支逐条对齐：
//
//	who 行       user / tty / from(括号内来源) / since / remote
//	remote 判据  from 非空且 from ∉ {console, loginwindow}   → medium，否则 low
//	last 行      user / tty / from(最后一个字段，仅当字段数 > 6) / raw
//	首轮         只建基线，不把已有会话报成新登录（Python: if not self._seeded）
//	登录事件      session.login  subject{tty,from,remote,since}  process=tty
//	登出事件      session.logout subject{key}                    process=key 的 tty 段
//	认证失败      auth.fail      subject{count,window}           process="sudo/sshd"
//
// 为什么解析层不带 build tag：Linux 的 `who` / `last` 输出、Windows 的 `quser`
// 输出都能在 macOS 上被测试喂进去。否则「Windows 采集器」在本机永远只有
// 「编译通过」这一条证据，等于没测。
//
// 与 Python 版的四处有意差异（都写在这里，对拍脚本按此豁免）：
//  1. Python 把活跃会话/历史写进 store.set_state("sessions", ...)；Go 版 store
//     层还没落地，改为进程内快照 + Snapshot() 暴露同样键名（active/history/
//     ts/remote），将来接 store 时直接原样落盘。
//  2. AuthLog 的原始数据源按平台分流（macOS unified log / Linux auth.log 或
//     journal / Windows 安全日志 4625），事件形状保持与 Python 一致。
//  3. 非 macOS 平台在 raw 里多一个 origin 键，标明「这条是从哪个日志源捞的」。
//     raw 不参与对拍（对拍只比 kind/source/severity/subject），加它换来的是
//     排障时不用猜数据来源。
//  4. **who 取失败时 Python 会静默返回空列表**（_run 吞异常 → ""），后果是
//     「who 崩了」被读成「所有会话都退出了」，一次性刷出一串假 session.logout。
//     Go 版把 who 的错误抛上去（RunOnce 记 errors、本轮不出事件），宁可不报
//     也不报假的。这条差异在 who 正常的机器上不可观测，只在故障时表现不同。

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/Kur1sulab/atfield/go/internal/model"
)

// 事件类型（与 Python 版字面量一致）。
const (
	EventSessionLogin  = "session.login"
	EventSessionLogout = "session.logout"
	EventAuthFail      = "auth.fail"
)

// 本地控制台来源：这两个出现在 who 的括号里不算远程。
// 与 Python 版 `src not in ("console", "loginwindow")` 同一集合。
var localConsoleSources = map[string]bool{"console": true, "loginwindow": true}

// whoSession 一条活跃会话（who / quser 归一）。
type whoSession struct {
	User   string `json:"user"`
	TTY    string `json:"tty"`
	From   string `json:"from"`
	Since  string `json:"since"`
	Remote bool   `json:"remote"`
}

// loginHist 一条历史登录（last / 事件日志归一）。
type loginHist struct {
	User string `json:"user"`
	TTY  string `json:"tty"`
	From string `json:"from"`
	Raw  string `json:"raw"`
}

// key 会话稳定键，与 Python 的 f"{user}@{tty}" 同构。
func (s whoSession) key() string { return s.User + "@" + s.TTY }

// nowSeconds 与 Python time.time() 同精度（秒，浮点）。
func nowSeconds() float64 { return float64(time.Now().UnixNano()) / 1e9 }

// isRemoteSource 远程来源判定——**这是 session 采集器唯一的判定分支**，
// 三平台共用，绝不下放到平台文件里（下放就会长出三套阈值）。
func isRemoteSource(from string) bool {
	if from == "" {
		return false
	}
	return !localConsoleSources[from]
}

// parseWho 解析 `who` 输出。
//
// 刻意照抄 Python 的**字节偏移**取法（line[len(user)+len(tty):]）而不是重新
// tokenize：macOS 的 who 用空格对齐，两种做法结果相同；而 Linux 某些
// 发行版会输出制表符，此时 Python 的行为是「rest 里混进空白」，Go 版若
// 改成 tokenize 就会与 Python 不等，对拍当场失效。宁可保留怪癖。
func parseWho(out string) []whoSession {
	var rows []whoSession
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		user, tty := parts[0], parts[1]
		cut := len(user) + len(tty)
		if cut > len(line) {
			cut = len(line)
		}
		rest := strings.TrimSpace(line[cut:])
		src := ""
		if i := strings.LastIndex(rest, "("); i >= 0 && strings.HasSuffix(rest, ")") {
			src = rest[i+1 : len(rest)-1]
		}
		when := rest
		if src != "" {
			if i := strings.LastIndex(rest, "("); i >= 0 {
				when = strings.TrimSpace(rest[:i])
			}
		}
		rows = append(rows, whoSession{
			User: user, TTY: tty, From: src, Since: when,
			Remote: isRemoteSource(src),
		})
	}
	return rows
}

// parseLast 解析 `last` 输出（历史登录，只做态势不做告警）。
//
// 三处照抄 Python 的过滤：
//   - 空行跳过
//   - 以 "wtmp" 开头跳过（那是 last 自己打印的 wtmp 起始标记）
//   - 前 20 个字符里出现 "reboot" 跳过（重启记录不是登录）
//
// from 取「最后一个字段且字段数 > 6」：Python 原文是
// `parts[-1] if len(parts) > 6 else ""`，所以 still logged in 的行会拿到
// 时间字段而不是来源。这是原版怪癖，照抄，不「修正」——修了就对不上。
func parseLast(out string, limit int) []loginHist {
	var rows []loginHist
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if strings.HasPrefix(line, "wtmp") {
			continue
		}
		head := line
		if len(head) > 20 {
			head = head[:20]
		}
		if strings.Contains(head, "reboot") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 5 {
			continue
		}
		from := ""
		if len(parts) > 6 {
			from = parts[len(parts)-1]
		}
		rows = append(rows, loginHist{User: parts[0], TTY: parts[1], From: from, Raw: strings.TrimSpace(line)})
		if limit > 0 && len(rows) >= limit {
			break
		}
	}
	return rows
}

// Session 会话采集器（对标 Python SessionCollector）。
type Session struct {
	Base

	mu     sync.Mutex
	seen   map[string]string // key -> user
	order  []string          // seen 的插入顺序（登出事件按它出，保持稳定）
	seeded bool

	active  []whoSession
	history []loginHist
	remote  int

	// 数据源（测试注入假实现，生产走平台实现）
	whoSrc  func(context.Context) (string, error)
	lastSrc func(context.Context) (string, error)
	// 解析器也按平台分：Windows 的 quser / wevtutil 输出与 Unix 的
	// who / last 完全不同形，解析必须跟着数据源走，否则会话表会是空的。
	whoParse  func(string) []whoSession
	lastParse func(string, int) []loginHist
}

// NewSession 构造并自检。
func NewSession(cfg Config) Collector {
	s := &Session{seen: map[string]string{}}
	interval := 20 * time.Second // Python interval = 20.0
	if cfg.Interval > 0 {
		interval = cfg.Interval
	}
	s.whoSrc = platformWho
	s.lastSrc = platformLast
	s.whoParse = platformParseWho
	s.lastParse = platformParseLast
	s.Init("session", ModePoll, interval, platformProbeSession)
	if !cfg.WantEnabled() {
		s.Status.Enabled = false
	}
	return s
}

// Items 当前活跃会话数（控制台清点用，main.go 的 Items() 接口）。
func (s *Session) Items() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.active)
}

// Snapshot 等价于 Python 的 store.set_state("sessions", ...)：键名逐个相同。
func (s *Session) Snapshot() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	hist := s.history
	if len(hist) > 20 {
		hist = hist[:20]
	}
	return map[string]any{
		"active":  s.active,
		"history": hist,
		"ts":      nowSeconds(),
		"remote":  s.remote,
	}
}

// Collect 采一轮会话。
//
// 差分口径与 Python 完全一致：
//   - 首轮（!seeded）：只登记现状，一条事件都不出。否则服务重启时
//     会把「本来就登录着的 3 个会话」报成 3 次新登录。
//   - 之后：新出现的 key 出 session.login；消失的 key 出 session.logout。
//   - 已知 key 不重复报（只更新来源/时间等上下文）。
func (s *Session) Collect(ctx context.Context) ([]model.Event, error) {
	whoOut, err := s.whoSrc(ctx)
	if err != nil {
		return nil, err
	}
	whoParse := s.whoParse
	if whoParse == nil { // 零值构造（测试/嵌入）时回落到 Unix who 解析
		whoParse = parseWho
	}
	sessions := whoParse(whoOut)

	// 历史登录只用于态势：取不到不算失败（容器里没有 wtmp 是常态），
	// 与 Python 的 _run() 吞掉异常返回空串同口径。
	lastOut, _ := s.lastSrc(ctx)
	lastParse := s.lastParse
	if lastParse == nil {
		lastParse = parseLast
	}
	hist := lastParse(lastOut, 20)

	s.mu.Lock()
	defer s.mu.Unlock()

	now := nowSeconds()
	var events []model.Event
	present := make(map[string]bool, len(sessions))
	remote := 0

	for _, cur := range sessions {
		if cur.Remote {
			remote++
		}
		key := cur.key()
		present[key] = true
		if _, known := s.seen[key]; known {
			continue
		}
		s.seen[key] = cur.User
		s.order = append(s.order, key)
		if !s.seeded {
			continue // 首轮只记录现状
		}
		sev := "low"
		if cur.Remote {
			sev = "medium"
		}
		ev := model.NewEvent(EventSessionLogin, "session")
		ev.TS = now
		ev.User = cur.User
		ev.Process = cur.TTY
		ev.Severity = sev
		ev.Subject = map[string]any{
			"tty":    cur.TTY,
			"from":   cur.From,
			"remote": cur.Remote,
			"since":  cur.Since,
		}
		events = append(events, *ev)
	}

	// 登出：上一轮见过、这一轮 who 里没有。
	// 按 order 顺序遍历而不是 map 随机序——否则同一批登出在两版里顺序不同。
	kept := s.order[:0]
	for _, key := range s.order {
		if present[key] {
			kept = append(kept, key)
			continue
		}
		user := s.seen[key]
		delete(s.seen, key)
		tty := key
		if i := strings.LastIndex(key, "@"); i >= 0 {
			tty = key[i+1:]
		}
		ev := model.NewEvent(EventSessionLogout, "session")
		ev.TS = now
		ev.User = user
		ev.Process = tty
		ev.Severity = "info"
		ev.Subject = map[string]any{"key": key}
		events = append(events, *ev)
	}
	s.order = kept

	s.active = sessions
	s.history = hist
	s.remote = remote
	s.seeded = true
	return events, nil
}

// AuthLog 认证失败回捞采集器（对标 Python AuthLogCollector）。
//
// 语义：把「最近一个窗口内的认证失败」聚成**一条** auth.fail 事件，
// 带失败条数与样本。为什么不是每条一事件：认证失败的原始日志在爆破时
// 一秒几十条，逐条上报会把事件池冲干净；聚合成一条 + count 反而能直接
// 触发「失败次数异常」这类规则。
type AuthLog struct {
	Base

	mu        sync.Mutex
	lastCount int

	window string // 采样窗口（Python 固定 "5m"）
	origin string // 数据源标识（写进 raw.origin，非 macOS 才有）

	// src 返回窗口内的失败行（已按平台语义过滤）。返回空切片 = 没失败。
	src func(context.Context) ([]string, error)
}

// NewAuthLog 构造并自检。
func NewAuthLog(cfg Config) Collector {
	a := &AuthLog{window: "5m"}
	interval := 60 * time.Second // Python interval = 60.0
	if cfg.Interval > 0 {
		interval = cfg.Interval
	}
	a.src = platformAuthFailLines
	a.Init("authlog", ModePoll, interval, platformProbeAuthLog)
	if !cfg.WantEnabled() {
		a.Status.Enabled = false
	}
	return a
}

// Items 本轮失败条数（清点用）。
func (a *AuthLog) Items() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastCount
}

// Collect 采一轮认证失败。
//
// 判定与 Python 一字不差：窗口内没有失败行 → 返回空（不出事件）。
// 有失败 → 恰好一条 auth.fail，severity=medium（Python 不按次数升档，
// 升档交给 detect 层的规则，采集器只管事实）。
func (a *AuthLog) Collect(ctx context.Context) ([]model.Event, error) {
	lines, err := a.src(ctx)
	if err != nil {
		return nil, err
	}
	lines = filterAuthFailLines(lines)

	a.mu.Lock()
	a.lastCount = len(lines)
	a.mu.Unlock()

	if len(lines) == 0 {
		return nil, nil
	}
	sample := lines
	if len(sample) > 5 {
		sample = sample[:5]
	}
	joined := clip(strings.Join(sample, "\n"), 1200)

	ev := model.NewEvent(EventAuthFail, "authlog")
	ev.TS = nowSeconds()
	ev.Severity = "medium"
	ev.Process = "sudo/sshd"
	ev.Subject = map[string]any{
		"count":  len(lines),
		"window": a.window,
	}
	raw := map[string]any{"sample": joined}
	if a.origin != "" {
		raw["origin"] = a.origin
	}
	ev.Raw = raw
	return []model.Event{*ev}, nil
}

// authFailMarkers 与 Python 的失败判定同集：行里出现 "incorrect" 或 "Failed"。
// Windows 事件日志由平台层先归一成同样带这两个词的文本行，判定因此只有一份。
var authFailMarkers = []string{"incorrect", "Failed"}

// filterAuthFailLines 复刻 Python 的
// `[l for l in out.splitlines() if "incorrect" in l or "Failed" in l]`。
func filterAuthFailLines(lines []string) []string {
	var out []string
	for _, l := range lines {
		for _, m := range authFailMarkers {
			if strings.Contains(l, m) {
				out = append(out, l)
				break
			}
		}
	}
	return out
}
