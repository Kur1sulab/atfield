package api

// views_api.go —— GET /api/views：视图层一次取齐（Go 新增端点，Python 无）。
//
// 为什么要有它：前端每个面板都在做「先请求 /api/findings，再按 eid 回查
// /api/events」的两段式拼装，回归测试与排障时也必须照着拼一遍才能验
// 「字段映射对不对」。这个端点把 views.go 那层映射的结果一次性吐出来，
// 形态与各分端点**逐字段一致**（同一个 newFindingView / newEventView），
// 所以它不能成为第二套真相——只做聚合，不做任何新的计算。
//
// 与分端点的区别只有两点：limit 同时作用于四类，且事件按「告警引用到的 eid
// 优先」排序，方便直接肉眼对照 views 里的 finding.event 是否解析成功。

import (
	"net/http"

	"github.com/Kur1sulab/atfield/go/internal/store"
)

// handleViews 聚合视图。参数 limit(50) / min_sev。
//
// 外层键刻意与分端点同名（events/findings/incidents/timeline），
// 前端可以把它当「四个请求的合并结果」直接用。
func (s *Server) handleViews(w http.ResponseWriter, r *http.Request) {
	if s.guard(w, r, "read") == nil {
		return
	}
	q := r.URL.Query()
	limit := qInt(q, "limit", 50)
	minSev := qStr(q, "min_sev", "")
	if limit < 0 {
		limit = 0
	}

	fs := s.cfg.Store.SnapshotFindings(limit, minSev)
	idx := s.eventIndex(neededEIDs(fs))
	fviews := make([]findingView, 0, len(fs))
	for _, f := range fs {
		fviews = append(fviews, newFindingView(f, idx))
	}

	incs := s.cfg.Store.SnapshotIncidents(limit)
	iviews := make([]map[string]any, 0, len(incs))
	for _, inc := range incs {
		iviews = append(iviews, newIncidentView(inc))
	}

	evs := s.cfg.Store.SnapshotEvents(limit, "", "", "")
	eviews := make([]eventView, 0, len(evs))
	for _, ev := range evs {
		eviews = append(eviews, newEventView(ev))
	}

	timeline := s.cfg.Store.Timeline(limit)
	if timeline == nil {
		timeline = []store.TimelineRow{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"version":      s.cfg.Version,
		"generated_at": iso(s.ts()),
		"counts": map[string]any{
			"events":    len(eviews),
			"findings":  len(fviews),
			"incidents": len(iviews),
			"timeline":  len(timeline),
		},
		"events":    eviews,
		"findings":  fviews,
		"incidents": iviews,
		"timeline":  timeline,
	})
}
