// Package detect 规则引擎与内建规则集。
//
// 逐函数移植自 Python 版 atfield/detect/engine.py（518 行）与
// atfield/detect/rules_builtin.py（436 行）。移植铁律：**一条规则都不能漏**——
// 检测产品掉一条规则就是一类漏报，比崩溃更隐蔽。
//
// 判定语义必须与 Python 侧一致，否则「同一份事件流喂两版、告警集合相等」的
// 验收标准就失效。改动这里请同步跑 MIGRATION-RULES.md 里的对照表。
package detect

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Kur1sulab/atfield/go/internal/model"
)

// ---------------- 冷却分级（engine.py:23-36） ----------------
const (
	// CooldownOneshot 一次性行为（诱饵、篡改、凭据访问）：保持短冷却，不漏独立事件。
	CooldownOneshot = 20.0
	// CooldownRecurring 周期行为（侦察、外联、爆破）：10 分钟。
	CooldownRecurring = 600.0
	// CooldownPeriodic 常驻/持久化类：15 分钟。
	CooldownPeriodic = 900.0
	// SuppressReviewDays 抑制条目默认复审周期。
	SuppressReviewDays = 90
	// DedupMax 去重表上限，超过后按 24 小时活跃窗口裁剪。
	DedupMax = 20000

	onceDefaultCooldown = 300.0
)

// CooldownTags 标签 → 冷却秒数（engine.py:27-34）。
var CooldownTags = map[string]float64{
	"persistence":       CooldownPeriodic,
	"discovery":         CooldownRecurring,
	"command_control":   CooldownRecurring,
	"lateral_movement":  CooldownRecurring,
	"credential_access": CooldownRecurring,
	"ueba":              CooldownRecurring,
}

// CooldownForTags 无 Rule 对象时（融合层）按 tags 取冷却等级（engine.py:54-61）。
func CooldownForTags(tags []string) float64 {
	best := CooldownOneshot
	for _, t := range tags {
		if v, ok := CooldownTags[strings.ToLower(t)]; ok && v > best {
			best = v
		}
	}
	return best
}

// CooldownFor 规则冷却：显式 cooldown 优先，否则按 tags 分级，缺省一次性短冷却
// （engine.py:39-51）。
func CooldownFor(r *Rule) float64 {
	if r == nil {
		return CooldownOneshot
	}
	if r.Cooldown != nil {
		v := *r.Cooldown
		if v < 0 {
			v = 0
		}
		return v
	}
	return CooldownForTags(r.Tags)
}

// ---------------- Rule（engine.py:110-127） ----------------
//
// 字段与 Python dataclass 一一对应，唯一改名是 enabled → Disabled：
// Go 的零值 bool 是 false，若沿用 Enabled，任何忘记显式赋值的规则都会静默失效——
// 这正是「漏一条规则」的最短路径。取反后零值 = 启用，安全方向正确。
type Rule struct {
	ID       string
	Name     string
	Severity string
	When     func(*model.Event, *Ctx) bool
	// Detail 动态描述；为 nil 时用 DetailText（对应 Python 的 detail: str）。
	Detail     func(*model.Event, *Ctx) string
	DetailText string
	Advice     string
	Tags       []string
	MITRE      []string
	// Cooldown nil = 按 tags 分级。
	Cooldown *float64
	Actor    func(*model.Event, *Ctx) string

	// Disabled = !Python.enabled。
	Disabled bool

	// SeverityFn 动态定级（情报闸门类规则）：给了它就以它的返回值为最终等级，
	// **不再与 ev.Severity 取 max**——否则事件自带的 high 会把保留网段的 IOC 抬回去。
	// 返回 "" 表示闸门判定「不再计分」，调用方跳过该条（对应 Python 返回 None）。
	SeverityFn func(*model.Event, *Ctx) string

	Description string
}

// ---------------- Ctx（engine.py:64-107） ----------------
//
// 规则可用的上下文：滑动窗口计数、状态读取、一次性触发、情报闸门。
type Ctx struct {
	store Store
	cfg   Config

	freq  map[string][]float64
	fired map[string]float64

	// Intel 情报闸门（可选），由 Engine.AttachIntel 注入。
	Intel Intel

	// Now 时钟注入点，默认 wallClock。Python 直接调 time.time()，
	// 这里抽成函数只为让频率窗口/冷却的测试可确定性推进，语义不变。
	Now func() float64
}

func wallClock() float64 { return float64(time.Now().UnixNano()) / 1e9 }

func (c *Ctx) clock() float64 {
	if c != nil && c.Now != nil {
		return c.Now()
	}
	return wallClock()
}

// Config 引擎配置（Python cfg dict 的强类型版）。
type Config struct {
	// DataDir 去重/抑制状态落盘目录，空则 ~/.atfield（engine.py:223-233）。
	DataDir string
	// Suppress 抑制条目（cfg["detect"]["suppress"]），文件不存在时的兜底来源。
	Suppress []SuppressItem
	// IOCIPS / IOCDomains 明文情报名单（cfg["ioc"]），intel 不可用时的最低置信兜底。
	IOCIPS     []string
	IOCDomains []string
}

// ConfigFromMap 接受 Python 版同构的配置字典，便于对拍脚本直接喂原配置。
func ConfigFromMap(m map[string]any) Config {
	var cfg Config
	if m == nil {
		return cfg
	}
	cfg.DataDir = strOf(m["data_dir"])
	if d, ok := m["detect"].(map[string]any); ok {
		if items, ok := d["suppress"].([]any); ok {
			for _, it := range items {
				if mm, ok := it.(map[string]any); ok {
					cfg.Suppress = append(cfg.Suppress, suppressFromMap(mm))
				}
			}
		} else if items, ok := d["suppress"].([]SuppressItem); ok {
			cfg.Suppress = append(cfg.Suppress, items...)
		}
	}
	if ioc, ok := m["ioc"].(map[string]any); ok {
		cfg.IOCIPS = strSlice(ioc["ips"])
		cfg.IOCDomains = strSlice(ioc["domains"])
	}
	return cfg
}

// Freq 维护滑动窗口，返回窗口内次数（engine.py:75-82）。
func (c *Ctx) Freq(key string, window float64) int {
	if c.freq == nil {
		c.freq = map[string][]float64{}
	}
	now := c.clock()
	dq := c.freq[key]
	for len(dq) > 0 && now-dq[0] > window {
		dq = dq[1:]
	}
	dq = append(dq, now)
	c.freq[key] = dq
	return len(dq)
}

// Reached 窗口内达到阈值，且在 window 内只返回一次 true（避免刷屏）
// （engine.py:84-94）。
func (c *Ctx) Reached(key string, window float64, threshold int) bool {
	n := c.Freq(key, window)
	if n < threshold {
		return false
	}
	onceKey := "reached:" + key
	if c.fired == nil {
		c.fired = map[string]float64{}
	}
	last := c.fired[onceKey]
	now := c.clock()
	if now-last < window {
		return false
	}
	c.fired[onceKey] = now
	return true
}

// Once 一次性触发（engine.py:96-101）。
func (c *Ctx) Once(key string, cooldown float64) bool {
	if c.fired == nil {
		c.fired = map[string]float64{}
	}
	last := c.fired[key]
	now := c.clock()
	if now-last < cooldown {
		return false
	}
	c.fired[key] = now
	return true
}

// State 读取采集层状态（进程表等）。
func (c *Ctx) State(name string) any {
	if c == nil || c.store == nil {
		return nil
	}
	return c.store.State(name)
}

// Counters 计数器快照。
func (c *Ctx) Counters() map[string]int {
	if c == nil || c.store == nil {
		return nil
	}
	return c.store.Counters()
}

// ---------------- 进程链归属（engine.py:130-155） ----------------

// ProcessRow 采集层 processes 状态的一行（pid/ppid/exe）。
type ProcessRow struct {
	PID  int
	PPID int
	Exe  string
}

func procRows(ctx *Ctx) []ProcessRow {
	if ctx == nil {
		return nil
	}
	return normalizeRows(ctx.State("processes"))
}

func normalizeRows(raw any) []ProcessRow {
	if raw == nil {
		return nil
	}
	if m, ok := raw.(map[string]any); ok {
		raw = m["rows"]
	}
	switch v := raw.(type) {
	case []ProcessRow:
		return v
	case []map[string]any:
		out := make([]ProcessRow, 0, len(v))
		for _, r := range v {
			out = append(out, rowFromMap(r))
		}
		return out
	case []any:
		out := make([]ProcessRow, 0, len(v))
		for _, it := range v {
			if m, ok := it.(map[string]any); ok {
				out = append(out, rowFromMap(m))
			}
		}
		return out
	}
	return nil
}

func rowFromMap(m map[string]any) ProcessRow {
	return ProcessRow{PID: intOf(m["pid"]), PPID: intOf(m["ppid"]), Exe: strOf(m["exe"])}
}

// RootPID 沿 ppid 上溯到最近的「根基」进程，作为攻击链归属键
// （engine.py:134-146）。
func RootPID(pid *int, ctx *Ctx) string {
	if pid == nil || *pid == 0 {
		return "host"
	}
	parent := map[int]int{}
	for _, r := range procRows(ctx) {
		parent[r.PID] = r.PPID
	}
	cur := *pid
	seen := map[int]bool{}
	for {
		p := parent[cur]
		if p == 0 || p == 1 || seen[p] || len(seen) > 12 {
			return fmt.Sprintf("pid:%d", cur)
		}
		seen[cur] = true
		cur = p
	}
}

// ExeOf 取 pid 对应的可执行文件路径（engine.py:149-155）。
func ExeOf(pid *int, ctx *Ctx) string {
	if pid == nil || *pid == 0 {
		return ""
	}
	for _, r := range procRows(ctx) {
		if r.PID == *pid {
			return r.Exe
		}
	}
	return ""
}

// DedupKey 稳定身份键：不含 detail / cmdline / ts 等易变文本
// （engine.py:158-163）。
func DedupKey(ruleID, actor string, ev *model.Event) string {
	process, path := "", ""
	if ev != nil {
		process, path = ev.Process, ev.Path
	}
	return fmt.Sprintf("%s|%s|%s|%s", ruleID, actor, process, path)
}

// ---------------- 抑制条件字段求值（engine.py:167-210） ----------------

func evField(ev *model.Event, name, detail string) string {
	name = strings.TrimSpace(name)
	if name == "" || ev == nil {
		return ""
	}
	if name == "detail" {
		return detail
	}
	if strings.HasPrefix(name, "subject.") {
		v := ev.Subject[strings.TrimPrefix(name, "subject.")]
		if !truthy(v) {
			return ""
		}
		return pyStr(v)
	}
	if name == "pid" {
		// Python: str(ev.pid or "") —— 无 pid 是空串，不是 "None"
		if ev.PID == nil {
			return ""
		}
		return strconv.Itoa(*ev.PID)
	}
	if v, ok := eventScalar(ev, name); ok {
		if s, _ := v.(string); s == "" {
			return ""
		}
		return pyStr(v)
	}
	v, ok := ev.Subject[name]
	if !ok || v == nil {
		return ""
	}
	return pyStr(v)
}

func eventScalar(ev *model.Event, name string) (any, bool) {
	switch name {
	case "process":
		return ev.Process, true
	case "path":
		return ev.Path, true
	case "cmdline":
		return ev.Cmdline, true
	case "user":
		return ev.User, true
	case "host":
		return ev.Host, true
	case "kind":
		return ev.Kind, true
	case "severity":
		return ev.Severity, true
	}
	return nil, false
}

// matchCond 单个字段条件：字符串=等值；map 支持 eq/equals/re/regex/in/contains/ne
// （engine.py:183-210）。未知算子按不匹配处理——抑制条件写错时宁可少抑制（多报），
// 也不静默放宽成「全抑制」（漏报）。
func matchCond(value string, cond any) bool {
	switch c := cond.(type) {
	case map[string]any:
		keys := make([]string, 0, len(c))
		for k := range c {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			op := strings.ToLower(k)
			arg := c[k]
			switch op {
			case "eq", "equals", "=":
				if value != pyStr(arg) {
					return false
				}
			case "re", "regex", "~":
				re, err := regexp.Compile(pyStr(arg))
				if err != nil || !re.MatchString(value) {
					return false
				}
			case "in", "oneof":
				found := false
				for _, v := range anySlice(arg) {
					if value == pyStr(v) {
						found = true
						break
					}
				}
				if !found {
					return false
				}
			case "contains", "substr":
				if !strings.Contains(value, pyStr(arg)) {
					return false
				}
			case "ne", "not":
				if value == pyStr(arg) {
					return false
				}
			default:
				return false
			}
		}
		return true
	case nil:
		return value == "None"
	}
	return value == pyStr(cond)
}

// ---------------- Python 语义小工具 ----------------

// pyStr 复刻 Python str() 的可观察行为（None → "None"）。
// detail 文本要与 Python 逐字一致，缺键不能渲染成空串。
func pyStr(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case string:
		return x
	case bool:
		if x {
			return "True"
		}
		return "False"
	case float64:
		return pyFloat(x)
	case float32:
		return pyFloat(float64(x))
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case []string:
		return "[" + strings.Join(quoteAll(x), ", ") + "]"
	}
	return fmt.Sprint(v)
}

func quoteAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = "'" + s + "'"
	}
	return out
}

// pyFloat 数字渲染。
//
// Python 的 subject 里 128 是 int（json 解析保留整型），detail 渲染成 "128"；
// Go 的 encoding/json 一律给 float64，若不抹掉整数值的 ".0" 就会渲染成 "128.0"，
// 与 Python 的 detail 逐字不一致（对拍会挂）。subject 里的字节数/端口/计数
// 都是整型，所以整数值按整数渲染是正确方向。
func pyFloat(f float64) string {
	if f == math.Trunc(f) && math.Abs(f) < 1e16 {
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

func strOf(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return pyStr(v)
}

func intOf(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(x))
		if err != nil {
			return 0
		}
		return n
	}
	return 0
}

// intSubOr0 复刻 `int(ev.subject.get(k) or 0)`：缺省为 0；非数字时 ok=false
// （Python 抛异常 → 规则整条跳过）。
func intSubOr0(ev *model.Event, key string) (int, bool) {
	return intSub(ev, key)
}

// intSub 读取 subject 里的整数，ok=false 表示 Python 侧会抛异常（规则整条跳过）。
func intSub(ev *model.Event, key string) (int, bool) {
	if ev == nil {
		return 0, true
	}
	v, ok := ev.Subject[key]
	if !ok || v == nil {
		return 0, true
	}
	switch x := v.(type) {
	case int:
		return x, true
	case int64:
		return int(x), true
	case float64:
		return int(x), true
	case string:
		s := strings.TrimSpace(x)
		if s == "" {
			return 0, true
		}
		n, err := strconv.Atoi(s)
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

// truthy 复刻 Python 真值判断。
func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case int:
		return x != 0
	case int64:
		return x != 0
	case float64:
		return x != 0
	case []any:
		return len(x) > 0
	case []string:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

func anySlice(v any) []any {
	switch x := v.(type) {
	case []any:
		return x
	case []string:
		out := make([]any, len(x))
		for i, s := range x {
			out[i] = s
		}
		return out
	}
	return []any{v}
}

func strSlice(v any) []string {
	switch x := v.(type) {
	case []string:
		return append([]string(nil), x...)
	case []any:
		out := make([]string, 0, len(x))
		for _, it := range x {
			out = append(out, pyStr(it))
		}
		return out
	}
	return nil
}

// cut 按码点截断，与 Python 的 s[:n] 一致（不能按字节切，中文会切坏）。
func cut(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

func pidStr(p *int) string {
	if p == nil {
		return "None"
	}
	return strconv.Itoa(*p)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// subStr 取 subject 值并按 Python str() 渲染（缺键 = "None"）。
func subStr(ev *model.Event, key string) string {
	if ev == nil {
		return "None"
	}
	return pyStr(ev.Subject[key])
}

// subOr 取第一个非空的 subject 值（对应 `sub.get("a") or sub.get("b") or dflt`）。
func subOr(ev *model.Event, dflt string, keys ...string) string {
	if ev != nil {
		for _, k := range keys {
			v, ok := ev.Subject[k]
			if !ok || v == nil {
				continue
			}
			s := pyStr(v)
			if s != "" {
				return s
			}
		}
	}
	return dflt
}

// subStrOr 单键取值，缺失/空则用默认（对应 `sub.get(k) or dflt`）。
func subStrOr(ev *model.Event, key, dflt string) string {
	return subOr(ev, dflt, key)
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func containsStr(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func validSeverity(s string) bool {
	switch s {
	case "info", "low", "medium", "high", "critical":
		return true
	}
	return false
}

// sevMax 取更高等级（model.py:36-37 sev_max）。
func sevMax(a, b string) string {
	if model.SeverityRank(a) >= model.SeverityRank(b) {
		return a
	}
	return b
}
