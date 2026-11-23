package parity

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Kur1sulab/atfield/go/internal/model"
)

// Python 侧 to_dict() → Row：subject/reasons/path/event_id 都要能取到。
func TestRowsFromPyDicts(t *testing.T) {
	dict := map[string]any{
		"fid":          "abc123",
		"rule_id":      "AEG-060",
		"name":         "启动项完整性变化",
		"severity":     "high",
		"severity_cn":  "高",
		"actor":        "pid:300",
		"tags":         []any{"persistence"},
		"mitre":        []any{"T1547"},
		"detail":       "内容哈希变化",
		"advice":       "核对变更来源",
		"ts":           1700000000.25,
		"count":        float64(2),
		"dedup_key":    "AEG-060|pid:300|launchctl|/tmp/x.plist",
		"first_detail": "内容哈希变化",
		"last_detail":  "内容哈希变化",
		"first_ts":     1700000000.1,
		"last_ts":      1700000000.25,
		"event": map[string]any{
			"kind":    "integrity.change",
			"eid":     "e42",
			"path":    "/tmp/x.plist",
			"process": "launchctl",
			"subject": map[string]any{
				"reason": "内容哈希变化",
			},
		},
	}

	rows := RowsFromPyDicts([]map[string]any{dict})
	if len(rows) != 1 {
		t.Fatalf("rows = %d", len(rows))
	}
	r := rows[0]
	if r.Path != "/tmp/x.plist" || r.Process != "launchctl" {
		t.Fatalf("path/process 取自 dedup_key 失败: %q %q", r.Path, r.Process)
	}
	if r.EventID != "e42" {
		t.Fatalf("event_id 应取 event.eid，实际 %q", r.EventID)
	}
	if len(r.Reasons) != 1 || r.Reasons[0] != "内容哈希变化" {
		t.Fatalf("reasons 取不到: %v", r.Reasons)
	}
	if r.Count != 2 || r.TS != 1700000000.25 {
		t.Fatalf("count/ts 解析不对: %d %.2f", r.Count, r.TS)
	}
	if len(r.Tags) != 1 || r.Tags[0] != "persistence" {
		t.Fatalf("tags 解析不对: %v", r.Tags)
	}
}

// Go 侧 Finding → Row：同一套口径。
func TestRowsFromGo(t *testing.T) {
	f := &model.Finding{
		ID:       "f1",
		RuleID:   "AEG-060",
		Name:     "启动项完整性变化",
		Severity: "high",
		Actor:    "pid:300",
		Detail:   "内容哈希变化",
		Advice:   "核对变更来源",
		Tags:     []string{"persistence"},
		MITRE:    []string{"T1547"},
		TS:       1700000000.25,
		Count:    2,
		DedupKey: "AEG-060|pid:300|launchctl|/tmp/x.plist",
		EventID:  "e42",
		Subject:  map[string]any{"reason": "内容哈希变化"},
	}
	rows := RowsFromGo([]*model.Finding{f})
	if len(rows) != 1 {
		t.Fatalf("rows = %d", len(rows))
	}
	r := rows[0]
	if r.Path != "/tmp/x.plist" || r.Actor != "pid:300" || r.EventID != "e42" {
		t.Fatalf("字段映射不对: %+v", r)
	}
	if len(r.Reasons) != 1 || r.Reasons[0] != "内容哈希变化" {
		t.Fatalf("reasons 取不到: %v", r.Reasons)
	}
}

// 两侧同一份内容 → 逐字段一致（这条是「两侧映射口径一致」的回归钉子）。
func TestRowsBothSidesAgree(t *testing.T) {
	f := &model.Finding{
		RuleID: "AEG-003", Name: "n", Severity: "high", Actor: "pid:200",
		Detail: "d", Advice: "a", DedupKey: "AEG-003|pid:200|bash|/tmp/x.sh",
		Count: 1, TS: 1.5, FirstTS: 1.5, LastTS: 1.5, EventID: "e1",
		Subject: map[string]any{"reasons": []any{"b", "a"}},
	}
	pyDict := map[string]any{
		"rule_id": "AEG-003", "name": "n", "severity": "high", "actor": "pid:200",
		"detail": "d", "advice": "a", "dedup_key": "AEG-003|pid:200|bash|/tmp/x.sh",
		"count": float64(1), "ts": 1.5, "first_ts": 1.5, "last_ts": 1.5,
		"event": map[string]any{"eid": "e1", "path": "/tmp/x.sh", "process": "bash",
			"subject": map[string]any{"reasons": []any{"b", "a"}}},
	}
	res := Compare(RowsFromPyDicts([]map[string]any{pyDict}), RowsFromGo([]*model.Finding{f}))
	if !res.Perfect() {
		t.Fatalf("两侧映射不一致: %+v", res.Diffs)
	}
}

// JSONL 读回：两侧格式都能解析，坏行报错带行号。
func TestReadFindingsJSONL(t *testing.T) {
	dir := t.TempDir()
	pyPath := filepath.Join(dir, "py.jsonl")
	content := `{"rule_id":"AEG-003","actor":"pid:200","dedup_key":"AEG-003|pid:200|bash|/tmp/x.sh","event":{"eid":"e1","path":"/tmp/x.sh","subject":{"reasons":["a","b"]}}}
{"rule_id":"AEG-070","actor":"pid:400","dedup_key":"AEG-070|pid:400|bash|/x","event":{"eid":"e2","path":"/x"}}
`
	if err := os.WriteFile(pyPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	rows, err := ReadFindingsJSONL(pyPath, true)
	if err != nil {
		t.Fatalf("读回失败: %v", err)
	}
	if len(rows) != 2 || rows[0].Reasons[0] != "a" {
		t.Fatalf("读回内容不对: %+v", rows)
	}

	bad := filepath.Join(dir, "bad.jsonl")
	if err := os.WriteFile(bad, []byte("{not json}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFindingsJSONL(bad, true); err == nil {
		t.Fatalf("坏行应报错")
	}
}
