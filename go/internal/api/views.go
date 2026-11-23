package api

// views.go —— 线上格式（wire format）适配层。
//
// Go 的 model.Event / model.Finding 是为「对拍与内部计算」设计的结构，
// 与 Python 版 Event.to_dict() / Finding.to_dict() 的键并不完全一样：
//
//	model.Event   没有 time/clock/severity_cn/text —— 这些是 Python 侧派生出来的展示字段
//	model.Finding 用 id，而 Python 用 fid；且没有内嵌 event
//
// 直接 json.Marshal(model.Finding) 会得到 id/status/verify_state 这类前端不认识
// （也不该认识）的键，同时缺 fid —— 前端 `f.fid` 变 undefined，列表整块空白。
// 所以 API 层必须做一次显式映射：**键名照 Python，值来自 Go 结构**。
//
// 映射不上的字段（Python Finding 内嵌的 event 对象）策略是「能解析就填、解析不到就
// 显式 null」——绝不编造一个空对象假装有数据。

import (
	"strconv"
	"strings"
	"time"

	"github.com/Kur1sulab/atfield/internal/model"
)

// sevCN 严重度中文（与 Python model.SEVERITY_CN 同字面量）。
var sevCN = map[string]string{
	"info":     "信息",
	"low":      "低危",
	"medium":   "中危",
	"high":     "高危",
	"critical": "严重",
}

// severityCN 未识别档位原样返回（Python 同：SEVERITY_CN.get(sev, sev)）。
func severityCN(s string) string {
	if v, ok := sevCN[s]; ok {
		return v
	}
	return s
}

// iso 本地时间 "2006-01-02 15:04:05"（对应 Python model.iso）。
func iso(ts float64) string {
	if ts <= 0 {
		return ""
	}
	return unix(ts).Format("2006-01-02 15:04:05")
}

// hhmmss 本地时间 "15:04:05"（对应 Python model.hhmmss）。
func hhmmss(ts float64) string {
	if ts <= 0 {
		return ""
	}
	return unix(ts).Format("15:04:05")
}

func unix(ts float64) time.Time {
	sec := int64(ts)
	nsec := int64((ts - float64(sec)) * 1e9)
	return time.Unix(sec, nsec).Local()
}

// eventView 一条事件的线上形状。键与顺序参照 Python Event.to_dict()：
// dataclass 字段全集 + time/clock/severity_cn/text 四个派生字段。
//
// 注意字段**没有** omitempty：Python 的 asdict 会把空字符串也序列化出来，
// 前端有 `if (e.host)` 这类判断，缺键和空串在前端是两种行为（undefined vs ""）。
type eventView struct {
	Kind       string         `json:"kind"`
	Source     string         `json:"source"`
	TS         float64        `json:"ts"`
	Host       string         `json:"host"`
	User       string         `json:"user"`
	PID        *int           `json:"pid"`
	PPID       *int           `json:"ppid"`
	Process    string         `json:"process"`
	Cmdline    string         `json:"cmdline"`
	Path       string         `json:"path"`
	Severity   string         `json:"severity"`
	Subject    map[string]any `json:"subject"`
	Raw        map[string]any `json:"raw"`
	EID        string         `json:"eid"`
	Time       string         `json:"time"`
	Clock      string         `json:"clock"`
	SeverityCN string         `json:"severity_cn"`
	Text       string         `json:"text"`
}

// eventText 搜索用扁平文本。与 Python Event.text 同构成：
// kind/process/cmdline/path/user/pid/host + subject 的所有值，空格连接。
//
// 为什么在 API 层重算而不是用 store 的 q 过滤：store 的 q 只匹配
// process/path/cmdline/kind（见 store.SnapshotEvents 注释），漏掉 user/host/subject，
// 而 Python 匹配的是 text。要跟 Python 对齐就得按 text 过滤。
func eventText(e model.Event) string {
	parts := []string{e.Kind, e.Process, e.Cmdline, e.Path, e.User, hostOf(e), pidStr(e.PID)}
	for _, v := range e.Subject {
		if s := anyStr(v); s != "" {
			parts = append(parts, s)
		}
	}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, " ")
}

func hostOf(e model.Event) string { return e.Host }

func pidStr(p *int) string {
	if p == nil || *p == 0 {
		return ""
	}
	return itoa(*p)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// anyStr 把 subject 里的任意值转成可搜索文本（Python 用 str(v)）。
func anyStr(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool:
		if x {
			return "True"
		}
		return "False"
	case float64:
		return trimFloat(x)
	case int:
		return itoa(x)
	case int64:
		return itoa(int(x))
	default:
		return ""
	}
}

// trimFloat 数字转文本。-1 精度：3 而不是 3.000000，够搜索用。
func trimFloat(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// newEventView 把 model.Event 转成线上形状。
func newEventView(e model.Event) eventView {
	return eventView{
		Kind:       e.Kind,
		Source:     e.Source,
		TS:         e.TS,
		Host:       e.Host,
		User:       e.User,
		PID:        e.PID,
		PPID:       e.PPID,
		Process:    e.Process,
		Cmdline:    e.Cmdline,
		Path:       e.Path,
		Severity:   e.Severity,
		Subject:    e.Subject,
		Raw:        e.Raw,
		EID:        e.EID,
		Time:       iso(e.TS),
		Clock:      hhmmss(e.TS),
		SeverityCN: severityCN(e.Severity),
		Text:       eventText(e),
	}
}

// findingView 一条告警的线上形状。键与 Python Finding.to_dict() 一一对应。
//
// event 字段是 Python 侧内嵌的触发事件对象。Go 的 model.Finding 只存 EventID，
// 因此这里靠调用方传入的索引解析；解析不到就给 null（前端已有 `if (f.event)` 保护）。
type findingView struct {
	FID         string     `json:"fid"`
	RuleID      string     `json:"rule_id"`
	Name        string     `json:"name"`
	Severity    string     `json:"severity"`
	SeverityCN  string     `json:"severity_cn"`
	Actor       string     `json:"actor"`
	Tags        []string   `json:"tags"`
	MITRE       []string   `json:"mitre"`
	Detail      string     `json:"detail"`
	Advice      string     `json:"advice"`
	TS          float64    `json:"ts"`
	Time        string     `json:"time"`
	Event       *eventView `json:"event"`
	Count       int        `json:"count"`
	DedupKey    string     `json:"dedup_key"`
	FirstDetail string     `json:"first_detail"`
	LastDetail  string     `json:"last_detail"`
	FirstTS     float64    `json:"first_ts"`
	LastTS      float64    `json:"last_ts"`
}

// newFindingView 把 model.Finding 转成线上形状。index 可为 nil（不解析 event）。
func newFindingView(f *model.Finding, index map[string]model.Event) findingView {
	if f == nil {
		return findingView{}
	}
	ts := f.TS
	if ts <= 0 {
		ts = f.LastTS
	}
	later := func(a, b float64) float64 {
		if a > 0 {
			return a
		}
		return b
	}
	detail := firstNonEmpty(f.Detail, f.FirstDetail, f.LastDetail)
	var ev *eventView
	if index != nil && f.EventID != "" {
		if e, ok := index[f.EventID]; ok {
			v := newEventView(e)
			ev = &v
		}
	}
	return findingView{
		FID:         f.ID,
		RuleID:      f.RuleID,
		Name:        f.Name,
		Severity:    f.Severity,
		SeverityCN:  severityCN(f.Severity),
		Actor:       f.Actor,
		Tags:        nonNil(f.Tags),
		MITRE:       nonNil(f.MITRE),
		Detail:      detail,
		Advice:      f.Advice,
		TS:          ts,
		Time:        iso(ts),
		Event:       ev,
		Count:       maxInt(1, f.Count),
		DedupKey:    f.DedupKey,
		FirstDetail: firstNonEmpty(f.FirstDetail, detail),
		LastDetail:  firstNonEmpty(f.LastDetail, detail),
		FirstTS:     later(f.FirstTS, ts),
		LastTS:      later(f.LastTS, ts),
	}
}

// nonNil 让空切片序列化成 [] 而不是 null（Python list 永远序列化成 []）。
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// tmplIDKey Python Incident.to_dict 里那条「模板 id」的键。
//
// 用拼接写法而不是字面量：文档/技能库把 "templ"+"ate" 这个字符串当占位符
// 处理，直接写进源码会在复制粘贴时被替换成别的东西。拼接能保证编译出来的
// JSON 键与 Python 侧完全一致，同时不被文本处理工具误伤。
const tmplIDKey = "templ" + "ate_id"

// newIncidentView 攻击链的线上形状。
//
// 键与 Python Incident.to_dict() 一致：iid / title / <tmpl>_id / severity /
// severity_cn / host / actor / first_seen / last_seen / first_time / last_time /
// score / summary / advice / stages。
//
// 值来源说明（不编造）：
//   - iid/title/severity/summary 直接来自 model.Incident；
//   - first_seen/last_seen 都用 inc.TS —— Go 侧只有单一时间戳；
//   - <tmpl>_id / host / actor / advice 留空，score 留 0：关联器尚未迁移，
//     Go 的 Incident 里没有这些信息，留空比填假值诚实；
//   - stages 恒为 []：Python 的 stages 是带规则与时间的字典列表，
//     Go 只存了 findings 的 ID 列表，硬凑会造出前端读不懂的结构。
//
// 用 map 而不是 struct 是刻意的：键里有拼接常量，struct tag 写不了。
func newIncidentView(inc model.Incident) map[string]any {
	ts := inc.TS
	return map[string]any{
		"iid":         inc.ID,
		"title":       inc.Title,
		tmplIDKey:     "",
		"severity":    inc.Severity,
		"severity_cn": severityCN(inc.Severity),
		"host":        "",
		"actor":       "",
		"first_seen":  ts,
		"last_seen":   ts,
		"first_time":  iso(ts),
		"last_time":   iso(ts),
		"score":       0,
		"summary":     inc.Summary,
		"advice":      "",
		"stages":      []any{},
	}
}
