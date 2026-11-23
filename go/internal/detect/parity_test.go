package detect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Kur1sulab/atfield/internal/model"
)

// TestPythonParity 对拍：同一份事件语料，Go 输出必须与 Python 版**逐条逐字段**一致。
//
// 这是本项目唯一的验收标准（MIGRATION.md 第二节）：
//
//	同一份真实事件流 → Python 版告警集合 == Go 版告警集合
//
// 黄金文件 testdata/parity_expected_py.json 由 Python 版
// atfield 1.1.3（detect/engine.py + detect/rules_builtin.py）在同一份语料上生成，
// 进程表也一致（pid 100←200←300、400=/tmp/backdoor、500=/usr/bin/curl）。
// 语料覆盖 32 条规则各自的命中样本 + 10 条反例噪声，共 79 个事件。
//
// 任何一处 detail 文本、severity、actor、dedup_key 漂移都会在这里挂——
// 这正是我们想要的：告警文本对不上，前端/报告/对拍就都失去意义。
func TestPythonParity(t *testing.T) {
	type corpusEvent struct {
		Kind     string         `json:"kind"`
		PID      *int           `json:"pid"`
		Process  string         `json:"process"`
		Cmdline  string         `json:"cmdline"`
		Path     string         `json:"path"`
		Severity string         `json:"severity"`
		Subject  map[string]any `json:"subject"`
		User     string         `json:"user"`
	}
	type wantRow struct {
		RuleID   string `json:"rule_id"`
		Severity string `json:"severity"`
		Actor    string `json:"actor"`
		Detail   string `json:"detail"`
		DedupKey string `json:"dedup_key"`
	}

	readJSON := func(name string, dst any) {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatalf("读 %s: %v", name, err)
		}
		if err := json.Unmarshal(raw, dst); err != nil {
			t.Fatalf("解析 %s: %v", name, err)
		}
	}

	var corpus []corpusEvent
	readJSON("parity_corpus.json", &corpus)
	var want []wantRow
	readJSON("parity_expected_py.json", &want)

	events := make([]*model.Event, 0, len(corpus))
	for i, c := range corpus {
		events = append(events, &model.Event{
			Kind: c.Kind, Source: "parity", TS: float64(i + 1), EID: "e",
			PID: c.PID, Process: c.Process, Cmdline: c.Cmdline, Path: c.Path,
			Severity: c.Severity, Subject: c.Subject, User: c.User,
		})
	}

	store := newMemStore()
	store.states["processes"] = testProcTable()
	e := New(Config{DataDir: t.TempDir(), IOCIPS: []string{"203.0.113.9"}}, store, BuiltinRules())
	// 冻结时钟：整批事件在 Python 侧是毫秒内跑完，冷却窗口不会过期；
	// 冻结后 Go 侧同样不会过期，且不受机器快慢影响（确定性）。
	frozen := 1_700_000_000.0
	e.Now = func() float64 { return frozen }

	got := e.Observe(events)
	if len(got) != len(want) {
		t.Fatalf("告警条数 = %d，Python 版 = %d", len(got), len(want))
	}
	for i := range want {
		g := got[i]
		w := want[i]
		if g.RuleID != w.RuleID || g.Severity != w.Severity || g.Actor != w.Actor ||
			g.Detail != w.Detail || g.DedupKey != w.DedupKey {
			t.Fatalf("第 %d 条与 Python 不一致\n  py: %+v\n  go: rule=%s sev=%s actor=%s dedup=%s detail=%q",
				i, w, g.RuleID, g.Severity, g.Actor, g.DedupKey, g.Detail)
		}
	}
	t.Logf("对拍一致：%d 个事件 → %d 条告警", len(events), len(got))
}
