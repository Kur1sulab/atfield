package api

// handlers.go —— 各 GET 端点。逐个对应 Python 版 server.py 的分支，
// 查询参数名、默认值、响应外层键全部照抄。
//
// 每个 handler 的结构都刻意保持「读参数 → 取快照 → 转视图 → 写出」四步，
// 不放业务判断：判断在 detect/store 里，这里只做协议适配。

import (
	"net/http"
	"os"
	"runtime"
	"strings"

	"github.com/Kur1sulab/atfield/go/internal/model"
	"github.com/Kur1sulab/atfield/go/internal/store"
)

// handlePing 健康检查。{"ok":true,"version":...,"ts":...}
func (s *Server) handlePing(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "version": s.cfg.Version, "ts": s.ts(),
	})
}

// handleVersion 版本与运行环境。
//
// 与 Python 版唯一的字段差异：Python 有 "python"（解释器版本），Go 版没有，
// 换成 "go"（runtime 版本）。其余 name/executable/platform/themes/ts 同名同义。
func (s *Server) handleVersion(w http.ResponseWriter, _ *http.Request) {
	exe, err := os.Executable()
	if err != nil {
		exe = ""
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name":       Product,
		"version":    s.cfg.Version,
		"go":         goVersion(),
		"executable": exe,
		"platform":   runtime.GOOS + "/" + runtime.GOARCH,
		"themes":     []string{"dark", "light"},
		"ts":         s.ts(),
	})
}

// handleAuthMe 当前会话。鉴权未接入时返回开放模式的 admin 会话，
// 这样前端 can() 判断全部放行、不会卡在登录页。
func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Auth == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "user": "system", "role": "admin",
			"expires_at": 0, "must_change": false,
			// 与 Python ROLE_CAPS["admin"] 同集合（排序后）
			"caps":         []string{"admin", "read", "respond", "triage"},
			"auth_enabled": false,
			"hint":         "鉴权层未接入：当前为开放模式，请只监听回环地址",
		})
		return
	}
	sess := s.cfg.Auth.Session(s.token(r))
	if sess == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"ok": false, "login_required": true,
			"auth_enabled": s.cfg.Auth.Enabled(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "user": sess.User, "role": sess.Role,
		"expires_at": sess.ExpiresAt, "must_change": sess.MustChange,
		"caps": s.cfg.Auth.Caps(sess.Role),
	})
}

// handleOverview 统计汇总。整个对象由 buildOverview 组装（见 overview.go），
// 这里只负责鉴权与写出。
func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	if s.guard(w, r, "read") == nil {
		return
	}
	writeJSON(w, http.StatusOK, s.buildOverview())
}

// handleEvents 事件列表。
//
// 参数：limit(200) / offset(0, Go 追加) / kind / q / min_sev
// 外层键：{"events": [...]}
//
// 过滤顺序与 Python 一致：kind → min_sev → q → 分页。
// q 在视图层按 text 匹配（含 user/host/subject），而不是交给 store 的
// 窄口径过滤——否则「按用户名搜」会搜不到。
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if s.guard(w, r, "read") == nil {
		return
	}
	q := r.URL.Query()
	limit := qInt(q, "limit", 200)
	offset := qInt(q, "offset", 0)
	kind := qStr(q, "kind", "")
	minSev := qStr(q, "min_sev", "")
	kw := strings.ToLower(strings.TrimSpace(qStr(q, "q", "")))

	// limit=0 → 空列表（Python items[:0] 同义）；取全量由 store(0) 表示，
	// 所以这里先用 0 取全量再自己切片，保证 offset 语义正确。
	all := s.cfg.Store.SnapshotEvents(0, kind, minSev, "")
	out := make([]eventView, 0, 64)
	if limit == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"events": out})
		return
	}
	skipped := 0
	for _, ev := range all {
		v := newEventView(ev)
		if kw != "" && !strings.Contains(strings.ToLower(v.Text), kw) {
			continue
		}
		if skipped < offset {
			skipped++
			continue
		}
		out = append(out, v)
		if len(out) >= limit {
			break
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": out})
}

// handleEventDetail 单条事件详情（Go 新增端点，Python 无）。
//
// 前端点「事件详情」需要按 eid 取一条，而 Python 版只能拉列表前端过滤。
// 这里补上，字段结构完全沿用 /api/events 的元素形状（eventView），不新增字段。
func (s *Server) handleEventDetail(w http.ResponseWriter, r *http.Request) {
	if s.guard(w, r, "read") == nil {
		return
	}
	eid := strings.TrimSpace(r.URL.Query().Get("eid"))
	if eid == "" {
		writeErr(w, http.StatusBadRequest, "缺少 eid 参数")
		return
	}
	for _, ev := range s.cfg.Store.SnapshotEvents(0, "", "", "") {
		if ev.EID == eid {
			writeJSON(w, http.StatusOK, map[string]any{"event": newEventView(ev)})
			return
		}
	}
	writeErr(w, http.StatusNotFound, "事件不存在")
}

// handleFindings 告警列表。参数 limit(200) / min_sev(Go 追加)。外层键 {"findings": []}
func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	if s.guard(w, r, "read") == nil {
		return
	}
	q := r.URL.Query()
	limit := qInt(q, "limit", 200)
	minSev := qStr(q, "min_sev", "")
	out := make([]findingView, 0, 16)
	if limit > 0 {
		fs := s.cfg.Store.SnapshotFindings(limit, minSev)
		idx := s.eventIndex(neededEIDs(fs))
		for _, f := range fs {
			out = append(out, newFindingView(f, idx))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": out})
}

// handleIncidents 攻击链列表。外层键 {"incidents": []}
func (s *Server) handleIncidents(w http.ResponseWriter, r *http.Request) {
	if s.guard(w, r, "read") == nil {
		return
	}
	limit := qInt(r.URL.Query(), "limit", 50)
	out := make([]map[string]any, 0, 8)
	if limit > 0 {
		for _, inc := range s.cfg.Store.SnapshotIncidents(limit) {
			out = append(out, newIncidentView(inc))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"incidents": out})
}

// handleActions 处置动作（内存环，权威副本在 actions.jsonl / 审计链）。
func (s *Server) handleActions(w http.ResponseWriter, r *http.Request) {
	if s.guard(w, r, "read") == nil {
		return
	}
	limit := qInt(r.URL.Query(), "limit", 200)
	out := []store.Action{}
	if limit > 0 {
		out = s.cfg.Store.SnapshotActions(limit)
	}
	writeJSON(w, http.StatusOK, map[string]any{"actions": nonNilActions(out)})
}

// handleTickets 处置工单。
func (s *Server) handleTickets(w http.ResponseWriter, r *http.Request) {
	if s.guard(w, r, "read") == nil {
		return
	}
	limit := qInt(r.URL.Query(), "limit", 200)
	out := []store.Ticket{}
	if limit > 0 {
		out = s.cfg.Store.SnapshotTickets(limit)
	}
	if out == nil {
		out = []store.Ticket{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"tickets": out})
}

// handleTimeline 统一取证时间线。
func (s *Server) handleTimeline(w http.ResponseWriter, r *http.Request) {
	if s.guard(w, r, "read") == nil {
		return
	}
	limit := qInt(r.URL.Query(), "limit", 300)
	out := []store.TimelineRow{}
	if limit > 0 {
		out = s.cfg.Store.Timeline(limit)
	}
	if out == nil {
		out = []store.TimelineRow{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"timeline": out})
}

// handleRules 规则目录。外层键 {"rules": [...], "chains": [...]}。
//
// chains 恒为 []：Python 侧的关联器（correlator）尚未迁到 Go，
// 返回空数组而不是省略键——前端按数组遍历，缺键会抛异常。
func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	if s.guard(w, r, "read") == nil {
		return
	}
	rules := []any{}
	if s.cfg.Engine != nil {
		for _, c := range s.cfg.Engine.Catalog() {
			rules = append(rules, c)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules, "chains": []any{}})
}

// handleAssets 资产态势：把采集层写进 store 的状态原样透出。
//
// 与 Python 完全一致——它不是「重新采集」，只是把同一份 state 换个出口，
// 所以键名就是 store.set_state 的键名，值不做任何加工（采集层已保证结构）。
func (s *Server) handleAssets(w http.ResponseWriter, r *http.Request) {
	if s.guard(w, r, "read") == nil {
		return
	}
	st := s.cfg.Store
	writeJSON(w, http.StatusOK, map[string]any{
		"processes":   orEmpty(st.GetState("processes", nil)),
		"connections": orEmpty(st.GetState("connections", nil)),
		"sessions":    orEmpty(st.GetState("sessions", nil)),
		"persistence": orEmpty(st.GetState("persistence", nil)),
		"integrity":   orEmpty(st.GetState("integrity", nil)),
		"security_sw": orEmpty(st.GetState("security_sw", nil)),
		"baseline":    orEmpty(st.GetState("baseline", nil)),
	})
}

// orEmpty nil 状态统一成空对象（Python 用 `or {}` 得到同样的形状）。
func orEmpty(v any) map[string]any {
	if v == nil {
		return map[string]any{}
	}
	return asMap(v)
}

// handleGovernance 治理状态。键沿用 Python governance()：
// auth / audit / updates / rules / version。
// 未迁的子模块（auth、updates）不出现——宁缺，不填假值。
func (s *Server) handleGovernance(w http.ResponseWriter, r *http.Request) {
	if s.guard(w, r, "read") == nil {
		return
	}
	writeJSON(w, http.StatusOK, s.governance())
}

// handleAudit 审计链尾部。参数 limit(100) / action / actor。
// 外层键 {"records": [], "stats": {}, "anchor": {}}
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if s.guard(w, r, "read") == nil {
		return
	}
	q := r.URL.Query()
	limit := qInt(q, "limit", 100)
	action := qStr(q, "action", "")
	actor := qStr(q, "actor", "")

	records := []store.AuditRecord{}
	var stats store.AuditStats
	var anchor store.Anchor
	if a := s.audit(); a != nil {
		if limit > 0 {
			records = a.Tail(limit, action, actor)
		}
		stats = a.Stats()
		anchor = a.Anchor()
	}
	if records == nil {
		records = []store.AuditRecord{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"records": records, "stats": stats, "anchor": anchor,
	})
}

// handleAuditVerify 验链。GET 与 POST 都接受（Python 两处都有分支）。
// 需要 triage 能力：验链会读全量分片，属于研判动作。
func (s *Server) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	if s.guard(w, r, "triage") == nil {
		return
	}
	a := s.audit()
	if a == nil {
		writeJSON(w, http.StatusOK, store.VerifyResult{
			OK: false, Problems: []string{"审计链未启用（audit 未注入）"},
		})
		return
	}
	writeJSON(w, http.StatusOK, a.Verify())
}

// eventIndex 建 eid → Event 索引，只为给定的 eid 集合服务。
// 空集合直接返回 nil（不扫 2 万条事件）。
func (s *Server) eventIndex(want map[string]bool) map[string]model.Event {
	if len(want) == 0 {
		return nil
	}
	idx := make(map[string]model.Event, len(want))
	for _, ev := range s.cfg.Store.SnapshotEvents(0, "", "", "") {
		if want[ev.EID] {
			idx[ev.EID] = ev
			if len(idx) == len(want) {
				break
			}
		}
	}
	return idx
}

// neededEIDs 收集一批告警要解析的触发事件 ID。
func neededEIDs(fs []*model.Finding) map[string]bool {
	out := make(map[string]bool, len(fs))
	for _, f := range fs {
		if f != nil && f.EventID != "" {
			out[f.EventID] = true
		}
	}
	return out
}

func nonNilActions(a []store.Action) []store.Action {
	if a == nil {
		return []store.Action{}
	}
	return a
}
