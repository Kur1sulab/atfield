package detect

import (
	"testing"

	"github.com/Kur1sulab/atfield/internal/model"
)

// ---------------- 测试脚手架 ----------------

type fakeClock struct{ t float64 }

func newClock() *fakeClock { return &fakeClock{t: 1_700_000_000} }

func (c *fakeClock) Now() float64      { return c.t }
func (c *fakeClock) Advance(d float64) { c.t += d }

type memStore struct {
	states  map[string]any
	actions []string
	dedup   map[string]DedupEntry
}

func newMemStore() *memStore {
	return &memStore{states: map[string]any{}, dedup: map[string]DedupEntry{}}
}

func (m *memStore) State(name string) any                { return m.states[name] }
func (m *memStore) Counters() map[string]int             { return map[string]int{} }
func (m *memStore) ReapplyDedup(e map[string]DedupEntry) { m.dedup = e }
func (m *memStore) LogAction(actor, action, detail, note string) {
	m.actions = append(m.actions, actor+"|"+action+"|"+detail+"|"+note)
}

// testProcTable 固定进程树：
//
//	100 ← 200 ← 300      400(/tmp/backdoor)   500(/usr/bin/curl)
func testProcTable() map[string]any {
	rows := []any{
		map[string]any{"pid": 100, "ppid": 1, "exe": "/sbin/launchd"},
		map[string]any{"pid": 200, "ppid": 100, "exe": "/bin/zsh"},
		map[string]any{"pid": 300, "ppid": 200, "exe": "/usr/bin/whoami"},
		map[string]any{"pid": 400, "ppid": 200, "exe": "/tmp/backdoor"},
		map[string]any{"pid": 500, "ppid": 200, "exe": "/usr/bin/curl"},
	}
	return map[string]any{"rows": rows}
}

func newEngineCfg(t *testing.T, rules []Rule, cfg Config) (*Engine, *fakeClock, *memStore) {
	t.Helper()
	if cfg.DataDir == "" {
		cfg.DataDir = t.TempDir()
	}
	clk := newClock()
	st := newMemStore()
	st.states["processes"] = testProcTable()
	e := New(cfg, st, rules)
	e.Now = clk.Now
	return e, clk, st
}

func newEngine(t *testing.T, rules []Rule) (*Engine, *fakeClock, *memStore) {
	return newEngineCfg(t, rules, Config{})
}

// feed 逐条灌事件，每条推进 1 秒（频率窗口类规则依赖真实时间差）。
func feed(e *Engine, clk *fakeClock, evs []*model.Event) []*model.Finding {
	var out []*model.Finding
	for _, ev := range evs {
		clk.Advance(1)
		ev.TS = clk.Now()
		out = append(out, e.Observe([]*model.Event{ev})...)
	}
	return out
}

func ev(kind string) *model.Event {
	return &model.Event{Kind: kind, Severity: "info", TS: 1, EID: "evt", Subject: map[string]any{}}
}

func withPID(e *model.Event, pid int) *model.Event {
	e.PID = &pid
	return e
}

func withSubject(e *model.Event, kv map[string]any) *model.Event {
	for k, v := range kv {
		e.Subject[k] = v
	}
	return e
}

func withCmd(e *model.Event, cmd string) *model.Event {
	e.Cmdline = cmd
	return e
}

func withPath(e *model.Event, p string) *model.Event {
	e.Path = p
	return e
}

func withProc(e *model.Event, name string) *model.Event {
	e.Process = name
	return e
}

// ruleByID 从内建规则集中取一条（不存在直接 Fatal，防止测试静默跑空）。
func ruleByID(t *testing.T, id string) Rule {
	t.Helper()
	for _, r := range BuiltinRules() {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("规则 %s 不在内建规则集里", id)
	return Rule{}
}

func idsOf(fs []*model.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.RuleID)
	}
	return out
}
