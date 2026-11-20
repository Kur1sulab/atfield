package store_test

// detect_compat_test.go —— 把「存储层的接线面」钉死在检测引擎的真实接口上。
//
// 这层断言放在外部测试包里，是为了让**生产代码不 import detect**：
// 存储层是叶子包，靠结构同形对接；这里用真实接口做一次编译期体检。
// 哪天 detect.Store 加/改方法，这个文件先编译失败，而不是等到 main 里接线
// 才发现「引擎调了 Store 没有的方法」。

import (
	"testing"

	"github.com/Kur1sulab/atfield/internal/detect"
	"github.com/Kur1sulab/atfield/internal/model"
	"github.com/Kur1sulab/atfield/internal/store"
)

// adapter 把 *store.Store 包成 detect.Store 的最小实现（wiring 层就长这样）。
type adapter struct{ s *store.Store }

func (a adapter) State(name string) any    { return a.s.State(name) }
func (a adapter) Counters() map[string]int { return a.s.Counters() }
func (a adapter) LogAction(actor, action, detail, note string) {
	a.s.LogAction(actor, action, detail, note)
}
func (a adapter) ReapplyDedup(entries map[string]detect.DedupEntry) {
	rows := make(map[string]store.DedupState, len(entries))
	for k, v := range entries {
		rows[k] = store.DedupState{
			FID: v.FID, Count: v.Count, FirstTS: v.FirstTS, LastTS: v.LastTS,
			FirstDetail: v.FirstDetail, LastDetail: v.LastDetail, LastEmit: v.LastEmit,
		}
	}
	_, _ = a.s.ReapplyDedup(rows)
}

// 编译期：适配器必须满足引擎的接口。
var _ detect.Store = adapter{}

// TestEngineAcceptsStore 让真引擎跑在真存储上。
//
// 这是「两层能接上」的端到端证据，不只是能编译：
//   - 引擎的 Ctx 通过 State/Counters 读存储；
//   - 引擎的抑制/情报动作通过 LogAction 落进存储的审计；
//   - 引擎产出的 detect.Merge 能无损映射成 store.Bump。
func TestEngineAcceptsStore(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(store.Config{DataDir: dir})
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	defer st.Close()

	eng := detect.New(detect.Config{DataDir: dir}, adapter{s: st}, detect.BuiltinRules())
	if n := len(eng.Rules()); n == 0 {
		t.Fatal("引擎没有规则")
	}

	// 引擎读存储：Ctx 拿到刚写进去的采集状态
	st.SetState("processes", []any{})
	if v := st.State("processes"); v == nil {
		t.Fatal("State 没读到")
	}

	// 引擎写存储：抑制动作要落成审计记录，且 actor 原样保留
	eng.AddSuppress("AEG-001", "", "测试抑制", nil, "responder", nil, nil)
	acts := st.SnapshotActions(10)
	if len(acts) == 0 {
		t.Fatal("引擎调 LogAction 后存储没有记录")
	}
	// 引擎当前仍硬编码 "analyst"（engine.go:322/346，Python 版 15 处硬编码的
	// 遗留）。存储层不改写它——改写等于伪造证据——但要把它标成「角色不是人」，
	// 这样 `grep actor_is_role` 就能把所有未整改的调用点捞出来。
	if acts[0].Actor != "analyst" {
		t.Fatalf("动作记录 = %q；存储层不该改写引擎传的 actor", acts[0].Actor)
	}
	if !acts[0].ActorIsRole {
		t.Error("硬编码角色名没有被标记：ActorIsRole 应为 true")
	}

	// 引擎产出的 Merge 结构 → store.Bump 的字段映射必须无损
	m := detect.Merge{
		FID: "f-x", Count: 7, LastDetail: "第七次", LastTS: 1234.5,
		DedupKey: "AEG-001|pid:1|bash|/tmp/x",
	}
	b := store.Bump{
		FID: m.FID, Count: m.Count, LastDetail: m.LastDetail,
		LastTS: m.LastTS, DedupKey: m.DedupKey,
	}
	if b.FID != "f-x" || b.Count != 7 || b.LastTS != 1234.5 ||
		b.LastDetail != "第七次" || b.DedupKey != m.DedupKey {
		t.Fatalf("Merge→Bump 映射丢字段：%+v", b)
	}

	// 真跑一遍：建行 → 用引擎形状的增量并入 → 计数正确
	if _, _, err := st.AddFindings([]*model.Finding{{
		ID: "f-x", RuleID: "AEG-001", Name: "n", Severity: "high",
		Status: "open", TS: 100, Actor: "pid:1", Detail: "首",
		DedupKey: "AEG-001|pid:1|bash|/tmp/x", FirstDetail: "首",
		LastDetail: "首", FirstTS: 100, LastTS: 100, Count: 1,
	}}); err != nil {
		t.Fatalf("AddFindings: %v", err)
	}
	if n, err := st.SaveMerges([]store.Bump{b}); err != nil || n != 1 {
		t.Fatalf("SaveMerges: n=%d err=%v", n, err)
	}
	f := st.GetFinding("f-x")
	if f.Count != 7 || f.LastDetail != "第七次" || f.FirstDetail != "首" {
		t.Fatalf("并入结果不对：%+v", f)
	}
}

// TestReapplyDedupTypeMapping detect.DedupEntry → store.DedupState 逐字段对齐。
//
// 两个结构体是手工镜像的，最容易出的错是「加了一边忘了另一边」。
// 这里逐个字段赋值再读回，任何字段漂移都会红。
func TestReapplyDedupTypeMapping(t *testing.T) {
	st, err := store.New(store.Config{MemoryOnly: true})
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	defer st.Close()

	key := "AEG-002|pid:2|bash|/tmp/y"
	if _, _, err := st.AddFindings([]*model.Finding{{
		ID: "f-y", RuleID: "AEG-002", Severity: "low", TS: 10,
		DedupKey: key, Count: 1, FirstDetail: "首", FirstTS: 10,
	}}); err != nil {
		t.Fatalf("AddFindings: %v", err)
	}

	e := detect.DedupEntry{
		FID: "f-y", Count: 42, FirstTS: 10, LastTS: 99,
		FirstDetail: "首", LastDetail: "末", LastEmit: 99.5,
	}
	adapter{s: st}.ReapplyDedup(map[string]detect.DedupEntry{key: e})

	f := st.GetFinding("f-y")
	if f == nil {
		t.Fatal("回填后告警不见了")
	}
	if f.Count != 42 {
		t.Errorf("Count = %d，期望 42", f.Count)
	}
	if f.LastTS != 99 || f.LastDetail != "末" {
		t.Errorf("last 没回填：%v/%q", f.LastTS, f.LastDetail)
	}
	if f.FirstTS != 10 || f.FirstDetail != "首" {
		t.Errorf("first 被覆盖：%v/%q", f.FirstTS, f.FirstDetail)
	}
}
