// Package parity 是 Python↔Go 告警集合对拍的比较内核。
//
// 迁移的唯一验收标准（MIGRATION.md 第二节）是「同一份事件流喂两版，
// 告警集合完全一致」。这个包只做一件事：把两侧的告警规范化成同一个
// Row 形状，按 (rule_id, actor, path) 对齐，然后逐字段比对——包括
// reasons 数组的顺序。
//
// 设计取舍：
//   - **只比较、不修正**。任何不一致都是迁移缺口，由人决策，这里绝不
//     替 Go 引擎「抹平」差异（否则对拍就变成了自证）。
//   - **对齐键按出现次序编号**。同一 (rule_id, actor, path) 在一次事件流里
//     可能产出多条（例如被冷却切开的两次命中），用 Occurrence 做序号，
//     避免用 map 把重复键吃掉。
//   - **subject 深比较**。Finding 层的 detail 只覆盖部分文本，reasons
//     这类结构化证据在 subject 里；两侧都做一次规范化 JSON 再比，
//     数组保持顺序，浮点按 1e-6 归一。
package parity

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// FloatEpsilon 时间戳/浮点字段的容差。
// 两侧都从同一份 JSONL 读同一个字面量，理论上逐位相同；留 1e-6
// 是为了吸收 Python 侧 json 往返可能引入的最后一位误差。
const FloatEpsilon = 1e-6

// Row 一条告警的规范化视图。字段名沿用 Python Finding.to_dict()，
// 因为那是两版对外的既有契约。
type Row struct {
	RuleID     string
	Actor      string
	Process    string
	Path       string
	Occurrence int // 同一 Key 内的第几条，1 起

	Name        string
	Severity    string
	Detail      string
	Advice      string
	DedupKey    string
	Count       int
	FirstDetail string
	LastDetail  string
	TS          float64
	FirstTS     float64
	LastTS      float64
	EventID     string
	Tags        []string
	MITRE       []string
	Reasons     []string
	Subject     map[string]any
}

// Key 对齐键：(rule_id, actor, path)。
//
// path 不直接出现在 Finding 上，统一从 dedup_key（rule|actor|process|path）
// 的第 4 段取；dedup_key 缺失时退回事件自身的 path（见 cmd/parity 的构造）。
func (r Row) Key() string { return r.RuleID + "|" + r.Actor + "|" + r.Path }

// Slot 便于报告里定位：Key + 序号。
func (r Row) Slot() string {
	if r.Occurrence > 1 {
		return fmt.Sprintf("%s#%d", r.Key(), r.Occurrence)
	}
	return r.Key()
}

// Mismatch 一个字段的差异（两侧原值都留着，方便直接定位）。
type Mismatch struct {
	Field  string `json:"field"`
	Python string `json:"python"`
	Go     string `json:"go"`
}

// FieldDiff 一条对齐上了、但字段不一致的告警。
type FieldDiff struct {
	Slot       string     `json:"slot"`
	RuleID     string     `json:"rule_id"`
	Actor      string     `json:"actor"`
	Path       string     `json:"path"`
	Occurrence int        `json:"occurrence"`
	Fields     []Mismatch `json:"fields"`
}

// Result 一次对拍的全部结论。
type Result struct {
	PythonRows int         `json:"python_rows"`
	GoRows     int         `json:"go_rows"`
	Total      int         `json:"total"`   // 对齐后的槽位总数 = Matched + PyOnly + GoOnly + Diffs
	Matched    int         `json:"matched"` // 全字段一致的条数
	PyOnly     []Row       `json:"py_only"`
	GoOnly     []Row       `json:"go_only"`
	Diffs      []FieldDiff `json:"field_diffs"`
}

// Rate 对齐率 = 一致条数 / 总条数。空集合按 1.0 处理（两侧都空确实是相等的）。
func (r Result) Rate() float64 {
	if r.Total == 0 {
		return 1.0
	}
	return float64(r.Matched) / float64(r.Total)
}

// Perfect 是否 100% 一致。
func (r Result) Perfect() bool { return r.Total > 0 && r.Matched == r.Total }

// Compare 对齐并逐字段比对。py / go 都按事件流顺序传入。
func Compare(py, goRows []Row) Result {
	res := Result{PythonRows: len(py), GoRows: len(goRows)}

	// 按 Key 分组，组内保持输入顺序；Occurrence 由调用方或这里补齐。
	group := func(rows []Row) map[string][]Row {
		m := map[string][]Row{}
		for i, r := range rows {
			if r.Occurrence == 0 {
				r.Occurrence = len(m[r.Key()]) + 1
				rows[i] = r
			}
			k := r.Key()
			m[k] = append(m[k], r)
		}
		return m
	}
	pg := group(py)
	gg := group(goRows)

	keys := make([]string, 0, len(pg)+len(gg))
	seen := map[string]bool{}
	for k := range pg {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	for k := range gg {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	// 稳定顺序：按首次出现位置排（先 Python 后 Go），而不是字典序——
	// 报告读起来要跟事件流时间线一致。
	order := map[string]int{}
	n := 0
	for _, r := range py {
		if _, ok := order[r.Key()]; !ok {
			order[r.Key()] = n
			n++
		}
	}
	for _, r := range goRows {
		if _, ok := order[r.Key()]; !ok {
			order[r.Key()] = n
			n++
		}
	}
	sort.SliceStable(keys, func(i, j int) bool { return order[keys[i]] < order[keys[j]] })

	for _, k := range keys {
		p, g := pg[k], gg[k]
		for i := 0; i < len(p) && i < len(g); i++ {
			res.Total++
			if d := diffRows(p[i], g[i]); len(d) > 0 {
				res.Diffs = append(res.Diffs, FieldDiff{
					Slot: p[i].Slot(), RuleID: p[i].RuleID, Actor: p[i].Actor,
					Path: p[i].Path, Occurrence: p[i].Occurrence, Fields: d,
				})
				continue
			}
			res.Matched++
		}
		if len(p) > len(g) {
			res.PyOnly = append(res.PyOnly, p[len(g):]...)
			res.Total += len(p) - len(g)
		}
		if len(g) > len(p) {
			res.GoOnly = append(res.GoOnly, g[len(p):]...)
			res.Total += len(g) - len(p)
		}
	}
	return res
}

// fieldOrder 固定比对顺序：先等级（最影响处置），再文本，再结构化证据。
// 顺序固定是为了报告可 diff、可回归。
var fieldOrder = []string{
	"severity", "name", "detail", "advice",
	"tags", "mitre", "reasons", "subject",
	"dedup_key", "count", "ts", "first_ts", "last_ts",
	"first_detail", "last_detail", "event_id",
}

func diffRows(p, g Row) []Mismatch {
	var out []Mismatch
	add := func(field, pv, gv string) {
		if pv != gv {
			out = append(out, Mismatch{Field: field, Python: pv, Go: gv})
		}
	}
	for _, f := range fieldOrder {
		switch f {
		case "severity":
			add(f, p.Severity, g.Severity)
		case "name":
			add(f, p.Name, g.Name)
		case "detail":
			add(f, p.Detail, g.Detail)
		case "advice":
			add(f, p.Advice, g.Advice)
		case "tags":
			add(f, canonList(p.Tags), canonList(g.Tags))
		case "mitre":
			add(f, canonList(p.MITRE), canonList(g.MITRE))
		case "reasons":
			add(f, canonList(p.Reasons), canonList(g.Reasons))
		case "subject":
			add(f, Canon(p.Subject), Canon(g.Subject))
		case "dedup_key":
			add(f, p.DedupKey, g.DedupKey)
		case "count":
			add(f, strconv.Itoa(p.Count), strconv.Itoa(g.Count))
		case "ts":
			add(f, num(p.TS), num(g.TS))
		case "first_ts":
			add(f, num(p.FirstTS), num(g.FirstTS))
		case "last_ts":
			add(f, num(p.LastTS), num(g.LastTS))
		case "first_detail":
			add(f, p.FirstDetail, g.FirstDetail)
		case "last_detail":
			add(f, p.LastDetail, g.LastDetail)
		case "event_id":
			add(f, p.EventID, g.EventID)
		}
	}
	return out
}

// num 浮点规范化：按 1e-6 截断到 6 位，避免最后一位抖动被当成不一致。
func num(v float64) string {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return fmt.Sprint(v)
	}
	r := math.Round(v*1e6) / 1e6
	return strconv.FormatFloat(r, 'f', -1, 64)
}

func canonList(v []string) string {
	if len(v) == 0 {
		return "[]"
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// Canon 把任意 JSON 值规范化成可逐字比较的字符串：
// map 键排序、浮点 6 位、数组保持顺序（reasons 顺序就在这里被钉住）。
func Canon(v any) string {
	if v == nil {
		return "null"
	}
	b, err := json.Marshal(normalize(v))
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

func normalize(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = normalize(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = normalize(val)
		}
		return out
	case []string:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = val
		}
		return out
	case float64:
		if t == math.Trunc(t) && math.Abs(t) < 1e15 {
			// 1.0 → 1，与 Python 的 int 侧写法对齐；两侧都过同一条路径。
			return t
		}
		return math.Round(t*1e6) / 1e6
	case float32:
		return normalize(float64(t))
	case int:
		return float64(t)
	case int64:
		return float64(t)
	case json.Number:
		if f, err := t.Float64(); err == nil {
			return normalize(f)
		}
		return t.String()
	}
	return v
}

// ReasonsOf 从 subject 里取 reasons 数组（兼容单数字段 reason）。
// 顺序原样保留——这是「reasons 数组顺序必须一致」的落点。
func ReasonsOf(subject map[string]any) []string {
	if subject == nil {
		return nil
	}
	if raw, ok := subject["reasons"]; ok {
		if list := toStrings(raw); len(list) > 0 {
			return list
		}
	}
	if raw, ok := subject["reason"]; ok {
		if s := strings.TrimSpace(fmt.Sprint(raw)); s != "" {
			return []string{s}
		}
	}
	return nil
}

func toStrings(raw any) []string {
	switch v := raw.(type) {
	case []string:
		return append([]string(nil), v...)
	case []any:
		out := make([]string, 0, len(v))
		for _, it := range v {
			out = append(out, fmt.Sprint(it))
		}
		return out
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	}
	return nil
}

// SplitDedupKey 拆 dedup_key = rule_id|actor|process|path。
// path 可能含 '|'（极少见），所以只切前 3 段，剩下全归 path。
func SplitDedupKey(k string) (rule, actor, process, path string) {
	parts := strings.SplitN(k, "|", 4)
	for len(parts) < 4 {
		parts = append(parts, "")
	}
	return parts[0], parts[1], parts[2], parts[3]
}
