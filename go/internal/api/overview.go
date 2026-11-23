package api

// overview.go —— 统计汇总（/api/overview）与它的两块「量化」算法。
//
// 这些数字不是拍脑袋的装饰品：health 决定运行人员要不要先补配置，
// risk 决定要不要立刻处置。所以算法**逐行照抄** Python 版 scoring.py：
// 同样的基线结果、同样的告警集合，两版必须算出同一个 health / risk，
// 否则迁移就成了「换了个产品」。
//
// 刻意保留的两处取舍：
//  1. Go 的 model.Incident 没有 Python 的 last_seen/score 字段，
//     用 inc.TS 当 last_seen、score 取 Python 的默认值 50（Python 代码里
//     就是 `float(inc.get("score") or 50)`）——这是默认值对齐，不是编造。
//  2. 未迁子系统（intel/ueba/canary/credscan/decoy/ndr/playbooks/inventory）
//     不在 fusion 里出现。宁缺，不填一个 {"ok":true} 之类的假状态。

import (
	"encoding/json"
	"math"
	"sort"
	"strings"

	"github.com/Kur1sulab/atfield/go/internal/model"
	"github.com/Kur1sulab/atfield/go/internal/store"
)

// dimension 健康度维度（Python DIMENSIONS）。
type dimension struct{ Key, Name, Desc string }

var dimensions = []dimension{
	{"identity", "身份与会话", "账户、登录、提权与认证"},
	{"execution", "执行与持久化", "进程行为、常驻项与启动链"},
	{"network", "网络与暴露面", "监听服务、外联行为与边界"},
	{"data", "数据与凭据", "磁盘加密、凭据与敏感权限"},
	{"detection", "防护与检测能力", "系统加固、更新与安全组件"},
}

// categoryMap 基线检查 category → 维度（Python CATEGORY_MAP）。
var categoryMap = map[string]string{
	"身份与会话":  "identity",
	"执行与持久化": "execution",
	"暴露面":    "network",
	"网络防线":   "network",
	"数据保护":   "data",
	"补丁管理":   "detection",
	"系统安全":   "detection",
	"恶意代码防护": "detection",
}

var statusScore = map[string]float64{"pass": 100, "warn": 62, "fail": 18, "unknown": 70}

var sevWeight = map[string]float64{
	"info": 0.2, "low": 1.0, "medium": 3.0, "high": 8.0, "critical": 18.0,
}

// buildOverview 组装 /api/overview。键名与 Python core.overview() 一致。
func (s *Server) buildOverview() map[string]any {
	st := s.cfg.Store
	baseline := asMap(st.GetState("baseline", nil))
	posture := computePosture(baseline)

	fs := st.SnapshotFindings(500, "")
	incs := st.SnapshotIncidents(50)
	threat := computeThreat(fs, incs, s.ts())

	procs := asMap(st.GetState("processes", nil))
	netState := asMap(st.GetState("connections", nil))
	sess := asMap(st.GetState("sessions", nil))
	pers := asMap(st.GetState("persistence", nil))
	integ := asMap(st.GetState("integrity", nil))
	priv := asMap(st.GetState("privileged", nil))
	ls := asMap(st.GetState("logstream", nil))
	base := baseline
	meta := st.Meta()

	// top_findings / recent_incidents 转成线上视图（前端直接渲染）。
	idx := s.eventIndex(neededEIDs(fs))
	top := make([]findingView, 0, 12)
	for i, f := range fs {
		if i >= 12 {
			break
		}
		top = append(top, newFindingView(f, idx))
	}
	recent := make([]map[string]any, 0, 6)
	for i, inc := range incs {
		if i >= 6 {
			break
		}
		recent = append(recent, newIncidentView(inc))
	}

	ticketsRow := st.SnapshotTickets(80)
	if ticketsRow == nil {
		ticketsRow = []store.Ticket{}
	}
	timelineRow := st.Timeline(120)
	if timelineRow == nil {
		timelineRow = []store.TimelineRow{}
	}

	return map[string]any{
		"product":      Product,
		"version":      s.cfg.Version,
		"host":         s.cfg.Host,
		"user":         s.cfg.User,
		"platform":     platformName(),
		"uptime":       int64(s.ts() - s.t0),
		"started_at":   iso(s.t0),
		"now":          iso(s.ts()),
		"health":       posture,
		"threat":       threat,
		"threat_color": threatColor(asFloat(threat["risk"])),
		"counters":     st.Counters(),
		"totals": map[string]any{
			"events":                 meta.EventsTotal,
			"findings":               meta.FindingsTotal,
			"incidents":              meta.IncidentsTotal,
			"processes":              asInt(procs["count"]),
			"connections":            asInt(netState["active"]),
			"public_connections":     asInt(netState["public"]),
			"listeners":              len(asSlice(netState["listeners"])),
			"sessions":               len(asSlice(sess["active"])),
			"persistence":            asInt(pers["count"]),
			"persistence_suspicious": len(asSlice(pers["suspicious"])),
			"baseline_fail":          asInt(asMap(base["counts"])["fail"]),
			"baseline_warn":          asInt(asMap(base["counts"])["warn"]),
			"integrity_watched":      len(asSlice(integ["files"])),
			"integrity_missing":      len(asSlice(integ["missing"])),
		},
		"collectors": s.collectorRows(meta),
		"telemetry": map[string]any{
			"logstream":     ls,
			"privileged":    priv,
			"eslogger_root": asBool(priv["enabled"]),
		},
		"top_findings":     top,
		"recent_incidents": recent,
		"fusion": map[string]any{
			"tickets":  ticketsRow,
			"timeline": timelineRow,
		},
		"governance": s.governance(),
		"verdict":    s.verdict(posture, threat, base, procs, netState),
	}
}

// collectorRows 采集器状态行。Python 每行还有 mode/interval/available/reason，
// 那些信息在采集器对象上，store 只存运行统计——因此这里只输出 store 确实有的字段，
// 不拿空串去填 mode/interval（前端用 `mode || '-'` 能降级）。
func (s *Server) collectorRows(meta store.Meta) []map[string]any {
	names := make([]string, 0, len(meta.Collectors))
	for n := range meta.Collectors {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]map[string]any, 0, len(names))
	for _, n := range names {
		c := meta.Collectors[n]
		out = append(out, map[string]any{
			"name":       n,
			"runs":       c.Runs,
			"errors":     c.Errors,
			"last_error": c.LastError,
			"last_ms":    c.LastMS,
			"last_ts":    c.LastTS,
		})
	}
	return out
}

// governance 治理快照。键沿用 Python：audit/rules/version（auth、updates 未迁，故不出现）。
func (s *Server) governance() map[string]any {
	out := map[string]any{"version": s.cfg.Version}
	if a := s.audit(); a != nil {
		out["audit"] = a.Stats()
	}
	total := 0
	packs := []any{}
	if s.cfg.Engine != nil {
		total = len(s.cfg.Engine.Catalog())
	}
	out["rules"] = map[string]any{"total": total, "packs": packs}
	return out
}

// computePosture 防护健康度（Python scoring.posture）。
//
// 权重来自检查项自身（基线里每条检查都有 weight），维度分 = 加权平均，
// 总分 = 各维度按各自权重再平均。空维度给 70 分（Python 同）——
// 不是「满分」也不是「零分」，而是「没有证据，别下结论」。
func computePosture(baseline map[string]any) map[string]any {
	results := asSlice(baseline["results"])
	buckets := map[string][]map[string]any{}
	for _, r := range results {
		item := asMap(r)
		key := categoryMap[asStr(item["category"])]
		if key == "" {
			key = "detection"
		}
		buckets[key] = append(buckets[key], item)
	}

	dims := make([]map[string]any, 0, len(dimensions))
	totalW, totalS := 0.0, 0.0
	for _, d := range dimensions {
		items := buckets[d.Key]
		wsum := 0.0
		for _, it := range items {
			wsum += weightOf(it)
		}
		if wsum == 0 {
			wsum = 1.0
		}
		score := 70.0
		if len(items) > 0 {
			sum := 0.0
			for _, it := range items {
				sum += statusScoreOf(asStr(it["status"])) * weightOf(it)
			}
			score = sum / wsum
		}
		var fails []map[string]any
		for _, it := range items {
			if asStr(it["status"]) == "fail" {
				fails = append(fails, it)
			}
		}
		topIssue := ""
		if len(fails) > 0 {
			topIssue = asStr(fails[0]["name"])
		}
		dims = append(dims, map[string]any{
			"key": d.Key, "name": d.Name, "desc": d.Desc,
			"score":     round1(score),
			"checks":    len(items),
			"failed":    len(fails),
			"top_issue": topIssue,
		})
		totalW += wsum
		totalS += score * wsum
	}
	health := 70.0
	if totalW > 0 {
		health = totalS / totalW
	}
	return map[string]any{
		"health":     round1(health),
		"dimensions": dims,
		"grade":      grade(health),
	}
}

// computeThreat 风险指数（Python scoring.threat）。
//
// 半衰期 6 小时：一小时前的 critical 比现在的不值钱，但也不是不值钱。
// 对数饱和：单次严重事件就该把指数顶起来，但长尾不能让指数永远 100。
func computeThreat(fs []*model.Finding, incs []model.Incident, now float64) map[string]any {
	const halfLife = 6.0 // 小时
	raw := 0.0
	recent := 0
	bySev := map[string]int{"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
	for _, f := range fs {
		if f == nil {
			continue
		}
		sev := f.Severity
		if sev == "" {
			sev = "info"
		}
		bySev[sev]++
		ts := f.TS
		if ts <= 0 {
			ts = f.LastTS
		}
		if ts <= 0 {
			ts = now
		}
		ageH := (now - ts) / 3600.0
		if ageH < 0 {
			ageH = 0
		}
		decay := math.Pow(0.5, ageH/halfLife)
		w, ok := sevWeight[sev]
		if !ok {
			w = 0.5 // Python SEV_WEIGHT.get(sev, 0.5)
		}
		raw += w * decay
		if ageH <= 1.0 {
			recent++
		}
	}
	for _, inc := range incs {
		ts := inc.TS
		if ts <= 0 {
			ts = now
		}
		ageH := (now - ts) / 3600.0
		if ageH < 0 {
			ageH = 0
		}
		decay := math.Pow(0.5, ageH/halfLife)
		// Go 的 Incident 没有 score 字段 → 用 Python 的缺省 50。
		raw += (50.0 / 10.0) * decay * 1.6
	}

	risk := 100.0 * (1 - math.Exp(-raw/45.0))
	if risk > 100 {
		risk = 100
	}
	level := "平静"
	switch {
	case risk >= 75:
		level = "严重"
	case risk >= 50:
		level = "高"
	case risk >= 25:
		level = "中"
	case risk >= 8:
		level = "低"
	}
	return map[string]any{
		"risk":            round1(risk),
		"level":           level,
		"raw":             round1(raw),
		"recent_1h":       recent,
		"by_severity":     bySev,
		"findings_total":  len(fs),
		"incidents_total": len(incs),
	}
}

// threatColor 风险 → 前端色档（Python scoring.threat_level_color）。
func threatColor(risk float64) string {
	switch {
	case risk >= 75:
		return "critical"
	case risk >= 50:
		return "high"
	case risk >= 25:
		return "medium"
	case risk >= 8:
		return "low"
	default:
		return "calm"
	}
}

// grade 健康度评级（Python scoring._grade）。
func grade(v float64) string {
	switch {
	case v >= 92:
		return "优秀"
	case v >= 80:
		return "良好"
	case v >= 65:
		return "一般"
	case v >= 45:
		return "薄弱"
	default:
		return "危险"
	}
}

// verdict 一句话结论（Python core._verdict）。
func (s *Server) verdict(posture, threat map[string]any, base, procs, netState map[string]any) string {
	var parts []string
	risk := asFloat(threat["risk"])
	switch {
	case risk >= 75:
		parts = append(parts, "风险指数 "+numStr(risk)+"（严重）：已出现高置信攻击链，按应急流程处置")
	case risk >= 50:
		parts = append(parts, "风险指数 "+numStr(risk)+"（高）：存在多个高危行为，需要人工复核")
	case risk >= 25:
		parts = append(parts, "风险指数 "+numStr(risk)+"（中）：有可疑行为，建议核查告警来源")
	case risk >= 8:
		parts = append(parts, "风险指数 "+numStr(risk)+"（低）：偶发异常，处于可观测状态")
	default:
		parts = append(parts, "风险指数 "+numStr(risk)+"（平静）：未发现攻击行为特征")
	}

	health := asFloat(posture["health"])
	var worst map[string]any
	for _, d := range asSlice(posture["dimensions"]) {
		dm := asMap(d)
		if asInt(dm["failed"]) > 0 {
			if worst == nil || asFloat(dm["score"]) < asFloat(worst["score"]) {
				worst = dm
			}
		}
	}
	if worst != nil {
		parts = append(parts, "防护健康度 "+numStr(health)+"（"+asStr(posture["grade"])+"），短板在「"+
			asStr(worst["name"])+"」——"+asStr(worst["top_issue"]))
	} else {
		parts = append(parts, "防护健康度 "+numStr(health)+"（"+asStr(posture["grade"])+"），基线检查未见不合格项")
	}

	if u := asInt(asMap(base["counts"])["unknown"]); u > 0 {
		parts = append(parts, "另有 "+itoa(u)+" 项因权限不足无法判定（非特权模式下的正常降级）")
	}
	if p := asInt(netState["public"]); p > 0 {
		parts = append(parts, "当前 "+itoa(p)+" 条公网连接在观测中")
	}
	return strings.Join(parts, "；") + "。"
}

// ---------------- 类型宽松访问器 ----------------
//
// store 里的 state 是 any：可能来自采集器的原始结构（[]baselineCheck），
// 也可能来自 JSON 回填（[]any / map[string]any）。统一用 reflect 走一遍
// 太绕，这里先尝试直接断言，失败就走一次 JSON 往返——状态对象都很小。

func asMap(v any) map[string]any {
	switch x := v.(type) {
	case nil:
		return map[string]any{}
	case map[string]any:
		return x
	}
	return roundTripMap(v)
}

func asSlice(v any) []any {
	switch x := v.(type) {
	case nil:
		return nil
	case []any:
		return x
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var out []any
	if json.Unmarshal(b, &out) != nil {
		return nil
	}
	return out
}

func asStr(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	}
	return ""
}

func asFloat(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case float32:
		return float64(x)
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case int32:
		return float64(x)
	case json.Number:
		f, _ := x.Float64()
		return f
	}
	return 0
}

func asInt(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	case json.Number:
		i, _ := x.Int64()
		return int(i)
	}
	return 0
}

func asBool(v any) bool {
	b, _ := v.(bool)
	return b
}

// weightOf 检查项权重，缺省 1（Python `float(i.get("weight") or 1)`）。
func weightOf(item map[string]any) float64 {
	w := asFloat(item["weight"])
	if w == 0 {
		return 1.0
	}
	return w
}

func statusScoreOf(s string) float64 {
	if v, ok := statusScore[s]; ok {
		return v
	}
	return 70 // Python STATUS_SCORE.get(status, 70)
}

func round1(f float64) float64 {
	return math.Round(f*10) / 10
}

// numStr 数字 → 文本，整数不带小数点（与 Python f-string 的显示习惯一致）。
func numStr(f float64) string {
	if f == math.Trunc(f) {
		return itoa(int(f))
	}
	return trimFloat(f)
}

func platformName() string {
	return platformOS() + " " + platformArch()
}

// roundTripMap 任意结构 → map[string]any（走一次 JSON，兼容未被断言命中的类型）。
func roundTripMap(v any) map[string]any {
	b, err := json.Marshal(v)
	if err != nil {
		return map[string]any{}
	}
	var out map[string]any
	if json.Unmarshal(b, &out) != nil {
		return map[string]any{}
	}
	if out == nil {
		return map[string]any{}
	}
	return out
}
