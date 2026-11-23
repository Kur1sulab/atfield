package parity

import (
	"testing"

	"github.com/Kur1sulab/atfield/go/internal/model"
)

// kind 覆盖统计：事件按 kind 计数、告警按 EventID 归回 kind，
// 「有事件、0 告警」的 kind 必须能被点名（这正是 process.suspicious 那类
// 采集器契约问题在对拍里唯一的暴露口）。
func TestCoverage(t *testing.T) {
	mk := func(kind, eid string) *model.Event {
		return &model.Event{Kind: kind, EID: eid, TS: 1}
	}
	events := []*model.Event{
		mk("net.connect", "e1"),
		mk("net.connect", "e2"),
		mk("process.suspicious", "e3"),
		mk("process.suspicious", "e4"),
		mk("tcc.deny", "e5"),
	}
	rows := []Row{
		{RuleID: "AEG-041", EventID: "e1"},
		{RuleID: "AEG-041", EventID: "e2"},
		{RuleID: "AEG-041", EventID: "e2"}, // 同一事件两条告警也要都算
		{RuleID: "AEG-999", EventID: "not-in-stream"},
	}

	cov := Coverage(events, rows)
	if len(cov) != 4 { // 3 个 kind + 1 个「找不到事件」的空 kind
		t.Fatalf("kind 数 = %d，期望 4: %+v", len(cov), cov)
	}
	byKind := map[string]KindCoverage{}
	for _, c := range cov {
		byKind[c.Kind] = c
	}
	if c := byKind["net.connect"]; c.Events != 2 || c.Findings != 3 || c.Silent() {
		t.Fatalf("net.connect = %+v，期望 2 事件 / 3 告警且非 silent", c)
	}
	if c := byKind["process.suspicious"]; c.Events != 2 || c.Findings != 0 || !c.Silent() {
		t.Fatalf("process.suspicious = %+v，期望 2 事件 / 0 告警且 silent", c)
	}
	if c := byKind["tcc.deny"]; !c.Silent() {
		t.Fatalf("tcc.deny 只有 1 条事件 0 告警，应判为 silent: %+v", c)
	}
	if c := byKind[""]; c.Events != 0 || c.Findings != 1 {
		t.Fatalf("找不到事件的告警应落进空 kind 分组: %+v", c)
	}
	// 排序：事件多的在前，同量按名字。
	if cov[0].Kind != "net.connect" && cov[0].Kind != "process.suspicious" {
		t.Fatalf("排序异常: %+v", cov)
	}
}

// 空流不应该 panic，也不应该造出「幽灵 kind」。
func TestCoverageEmpty(t *testing.T) {
	if got := Coverage(nil, nil); len(got) != 0 {
		t.Fatalf("空输入应返回空结果，实得 %+v", got)
	}
}
