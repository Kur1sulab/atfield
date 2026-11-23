package store

// store_test.go —— 三条硬指标的测试：重启可读回、并发安全、去重语义。
//
// 测试哲学（与 collector/detect 两个包一致）：**双向**。既要证明该合并的
// 合并了，也要证明不相关的没被误合并；既要证明重启后读得回，也要证明
// 读回的是同一份数据而不是「碰巧 count 对」。

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/Kur1sulab/atfield/go/internal/model"
)

// newTestStore 在临时目录建一个落盘存储。
func newTestStore(t *testing.T, cfg Config) *Store {
	t.Helper()
	if cfg.DataDir == "" {
		cfg.DataDir = t.TempDir()
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// mkEvent 造一条事件。
func mkEvent(kind, process, path string, ts float64) model.Event {
	pid := 4242
	ppid := 1
	return model.Event{
		Kind: kind, Source: "test", TS: ts,
		Host: "h1", User: "u1", PID: &pid, PPID: &ppid,
		Process: process, Path: path, Cmdline: process + " --x",
		Severity: "medium",
		Subject:  map[string]any{"ppid": ppid},
		Raw:      map[string]any{"src": "unit"},
		EID:      "eid-" + process,
	}
}

// mkFinding 造一条告警。
func mkFinding(id, ruleID, actor, key, detail string, ts float64) *model.Finding {
	return &model.Finding{
		ID: id, RuleID: ruleID, Name: "规则 " + ruleID, Severity: "high",
		Status: "open", TS: ts, Actor: actor, Detail: detail,
		DedupKey: key, FirstTS: ts, LastTS: ts,
		FirstDetail: detail, LastDetail: detail, Count: 1,
		Subject: map[string]any{"actor": actor},
		Tags:    []string{"persistence"},
		MITRE:   []string{"T1543"},
	}
}

// ---------------- 1. 重启后可读回 ----------------

// TestRestartReadbackEvents 写事件 → 关掉 → 新建实例读回，逐字段比对。
//
// Python 版在这里翻车：events.jsonl 写了从不读，且只写 8 个字段，
// 重启后 snapshot_events 是空的。这条测试就是钉死那个回归。
func TestRestartReadbackEvents(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{DataDir: dir}

	s1, err := New(cfg)
	if err != nil {
		t.Fatalf("New#1: %v", err)
	}
	want := []model.Event{
		mkEvent("process", "/tmp/x", "/tmp/x", 1000.5),
		mkEvent("network", "curl", "/usr/bin/curl", 1001.5),
		mkEvent("persistence", "launchctl", "/bin/launchctl", 1002.5),
	}
	if err := s1.AddEvents(want); err != nil {
		t.Fatalf("AddEvents: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// 新建实例 = 进程重启
	s2, err := New(cfg)
	if err != nil {
		t.Fatalf("New#2: %v", err)
	}
	defer s2.Close()

	got := s2.SnapshotEvents(10, "", "", "")
	if len(got) != len(want) {
		t.Fatalf("重启后事件数 = %d，期望 %d（事件没落盘或没读回）", len(got), len(want))
	}
	// SnapshotEvents 最新在前，逐字段反序比对
	for i := range want {
		w := want[len(want)-1-i]
		g := got[i]
		if g.EID != w.EID {
			t.Errorf("[%d] EID = %q，期望 %q", i, g.EID, w.EID)
		}
		if g.Kind != w.Kind || g.Process != w.Process || g.Path != w.Path {
			t.Errorf("[%d] kind/process/path = %q/%q/%q，期望 %q/%q/%q",
				i, g.Kind, g.Process, g.Path, w.Kind, w.Process, w.Path)
		}
		if g.TS != w.TS {
			t.Errorf("[%d] TS = %v，期望 %v", i, g.TS, w.TS)
		}
		// Python 版丢的就是这些字段
		if g.Cmdline != w.Cmdline {
			t.Errorf("[%d] Cmdline 丢了：%q，期望 %q", i, g.Cmdline, w.Cmdline)
		}
		if g.User != w.User || g.Host != w.Host {
			t.Errorf("[%d] user/host = %q/%q，期望 %q/%q", i, g.User, g.Host, w.User, w.Host)
		}
		if g.PID == nil || *g.PID != *w.PID {
			t.Errorf("[%d] PID 丢了", i)
		}
		// JSON 往返后数字变成 float64，按数值比较而不是按类型
		if fmt.Sprint(g.Subject["ppid"]) != fmt.Sprint(w.Subject["ppid"]) {
			t.Errorf("[%d] Subject 丢了：%v", i, g.Subject)
		}
		if fmt.Sprint(g.Raw["src"]) != fmt.Sprint(w.Raw["src"]) {
			t.Errorf("[%d] Raw 丢了：%v", i, g.Raw)
		}
	}

	// 计数也要跟着回来
	if m := s2.Meta(); m.EventsTotal != int64(len(want)) {
		t.Errorf("EventsTotal = %d，期望 %d", m.EventsTotal, len(want))
	}
	if c := s2.Counters(); c["process"] != 1 || c["network"] != 1 || c["persistence"] != 1 {
		t.Errorf("Counters 没回填：%v", c)
	}
}

// TestRestartReadbackFindingsCount 告警的 count/首末样本必须跨重启存活。
//
// 这是 Python 版第二个坑：bump 只改内存，注释说「dedup.json 会回填」，
// 但 CLI 单次进程（月报/cron）从不加载 dedup.json，于是 count 永远是 1。
func TestRestartReadbackFindingsCount(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{DataDir: dir}

	s1, err := New(cfg)
	if err != nil {
		t.Fatalf("New#1: %v", err)
	}
	base := mkFinding("f-1", "AEG-001", "pid:100", "AEG-001|pid:100|bash|/tmp/x",
		"首次命中：/tmp/x", 2000.0)
	if _, _, err := s1.AddFindings([]*model.Finding{base}); err != nil {
		t.Fatalf("AddFindings: %v", err)
	}
	// 连续并入 4 次，detail 每次抖动
	for i := 1; i <= 4; i++ {
		ok, f := s1.BumpByDedupKey("AEG-001|pid:100|bash|/tmp/x",
			fmt.Sprintf("第 %d 次命中：/tmp/x", i), 2000.0+float64(i))
		if !ok {
			t.Fatalf("第 %d 次并入应命中已有告警", i)
		}
		if f.Count != i+1 {
			t.Fatalf("第 %d 次并入后 count = %d，期望 %d", i, f.Count, i+1)
		}
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2, err := New(cfg)
	if err != nil {
		t.Fatalf("New#2: %v", err)
	}
	defer s2.Close()

	got := s2.GetFindingByDedup("AEG-001|pid:100|bash|/tmp/x")
	if got == nil {
		t.Fatal("重启后告警不见了")
	}
	if got.Count != 5 {
		t.Errorf("重启后 count = %d，期望 5（Python 版在这里退回 1）", got.Count)
	}
	if got.FirstDetail != "首次命中：/tmp/x" {
		t.Errorf("first_detail 被覆盖了：%q", got.FirstDetail)
	}
	if got.FirstTS != 2000.0 {
		t.Errorf("first_ts 被覆盖了：%v", got.FirstTS)
	}
	if got.LastDetail != "第 4 次命中：/tmp/x" {
		t.Errorf("last_detail = %q，期望最后一条", got.LastDetail)
	}
	if got.LastTS != 2004.0 {
		t.Errorf("last_ts = %v，期望 2004", got.LastTS)
	}
	// 重启后还能继续并入，说明索引也回来了
	ok, f := s2.BumpByDedupKey("AEG-001|pid:100|bash|/tmp/x", "重启后第 6 次", 2005.0)
	if !ok {
		t.Fatal("重启后并入失败：findIdx 没回填")
	}
	if f.Count != 6 {
		t.Errorf("重启后继续并入 count = %d，期望 6", f.Count)
	}
}

// TestRestartReadbackAllKinds 事件/告警/攻击链/工单/动作五类都要读得回。
func TestRestartReadbackAllKinds(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{DataDir: dir}

	s1, err := New(cfg)
	if err != nil {
		t.Fatalf("New#1: %v", err)
	}
	if err := s1.AddEvents([]model.Event{mkEvent("process", "a", "/a", 1.0)}); err != nil {
		t.Fatalf("AddEvents: %v", err)
	}
	if _, _, err := s1.AddFindings([]*model.Finding{
		mkFinding("f-1", "AEG-001", "pid:1", "k1", "d1", 10.0),
		mkFinding("f-2", "AEG-002", "pid:2", "k2", "d2", 11.0),
	}); err != nil {
		t.Fatalf("AddFindings: %v", err)
	}
	if err := s1.AddIncident(model.Incident{
		ID: "inc-1", Title: "横向移动", Severity: "critical", TS: 20.0,
		Findings: []string{"f-1", "f-2"}, Summary: "两跳",
	}); err != nil {
		t.Fatalf("AddIncident: %v", err)
	}
	tk, err := s1.CreateTicket("处置 /tmp/x", "high", "f-1", "隔离主机", "rule")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	if _, err := s1.UpdateTicket(tk.TID, TicketAck, "已联系值班", "alice"); err != nil {
		t.Fatalf("UpdateTicket: %v", err)
	}
	s1.LogAction("responder", "terminate", "pid=4242 /tmp/x", "ok")
	if err := s1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2, err := New(cfg)
	if err != nil {
		t.Fatalf("New#2: %v", err)
	}
	defer s2.Close()

	if n := len(s2.SnapshotEvents(10, "", "", "")); n != 1 {
		t.Errorf("事件 = %d，期望 1", n)
	}
	fs := s2.SnapshotFindings(10, "")
	if len(fs) != 2 {
		t.Fatalf("告警 = %d，期望 2", len(fs))
	}
	incs := s2.SnapshotIncidents(10)
	if len(incs) != 1 || incs[0].ID != "inc-1" || len(incs[0].Findings) != 2 {
		t.Errorf("攻击链读回不对：%+v", incs)
	}
	tks := s2.SnapshotTickets(10)
	if len(tks) != 1 {
		t.Fatalf("工单 = %d，期望 1", len(tks))
	}
	if tks[0].TID != tk.TID || tks[0].Status != TicketAck || tks[0].Owner != "alice" {
		t.Errorf("工单读回不对：%+v", tks[0])
	}
	if len(tks[0].Notes) != 1 || tks[0].Notes[0].Text != "已联系值班" {
		t.Errorf("工单备注读回不对：%+v", tks[0].Notes)
	}
	acts := s2.SnapshotActions(10)
	if len(acts) != 1 || acts[0].Actor != "responder" || acts[0].Action != "terminate" {
		t.Errorf("处置动作读回不对：%+v", acts)
	}

	// 续号：新建工单不能撞已有编号
	tk2, err := s2.CreateTicket("第二单", "low", "", "", "")
	if err != nil {
		t.Fatalf("CreateTicket#2: %v", err)
	}
	if tk2.TID == tk.TID {
		t.Fatalf("重启后工单编号撞号：%s", tk2.TID)
	}
	if tk2.TID != "T0002" {
		t.Errorf("续号 = %s，期望 T0002", tk2.TID)
	}
}

// TestRestartEmptyDirIsClean 空目录首次启动不能报错，也不能造出假数据。
func TestRestartEmptyDirIsClean(t *testing.T) {
	s := newTestStore(t, Config{})
	if n := len(s.SnapshotEvents(10, "", "", "")); n != 0 {
		t.Errorf("空目录事件 = %d，期望 0", n)
	}
	if n := len(s.SnapshotFindings(10, "")); n != 0 {
		t.Errorf("空目录告警 = %d，期望 0", n)
	}
	if m := s.Meta(); m.EventsTotal != 0 || m.FindingsTotal != 0 {
		t.Errorf("空目录 meta 不为零：%+v", m)
	}
}

// TestRestartToleratesCorruptLines 坏行只跳过，不能让启动失败。
func TestRestartToleratesCorruptLines(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{DataDir: dir}

	s1, err := New(cfg)
	if err != nil {
		t.Fatalf("New#1: %v", err)
	}
	if err := s1.AddEvents([]model.Event{mkEvent("process", "good", "/good", 1.0)}); err != nil {
		t.Fatalf("AddEvents: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// 手工注入坏行（模拟掉电写了半行）
	fh, err := os.OpenFile(filepath.Join(dir, FileEvents), os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := fh.WriteString("{\"kind\":\"process\",\"trunc\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	fh.Close()

	s2, err := New(cfg)
	if err != nil {
		t.Fatalf("坏行让 New 失败了：%v", err)
	}
	defer s2.Close()
	if n := len(s2.SnapshotEvents(10, "", "", "")); n != 1 {
		t.Errorf("好行应该读回 1 条，实得 %d", n)
	}
}

// TestRingOverflowKeepsNewest 环形缓冲溢出丢最旧、留最新。
func TestRingOverflowKeepsNewest(t *testing.T) {
	s := newTestStore(t, Config{MaxEvents: 3})
	var evs []model.Event
	for i := 0; i < 10; i++ {
		evs = append(evs, mkEvent("process", fmt.Sprintf("p%d", i), "/p", float64(i)))
	}
	if err := s.AddEvents(evs); err != nil {
		t.Fatalf("AddEvents: %v", err)
	}
	got := s.SnapshotEvents(10, "", "", "")
	if len(got) != 3 {
		t.Fatalf("容量 3 实得 %d 条", len(got))
	}
	// 最新在前：p9, p8, p7
	for i, want := range []string{"p9", "p8", "p7"} {
		if got[i].Process != want {
			t.Errorf("[%d] = %q，期望 %q（环形缓冲丢了最新的）", i, got[i].Process, want)
		}
	}
}

// TestBumpFindingsPersistsAcrossRestart 批量增量（引擎 TakeMerges 路径）也要跨重启存活。
//
// 这条单独钉住 BumpFindings：它和 BumpByDedupKey 是两条独立的写入路径，
// 只有一条落了盘的话，走另一条的功能在重启后就会静默退回 count=1。
func TestBumpFindingsPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{DataDir: dir}
	key := "AEG-011|pid:11|bash|/tmp/b"

	s1, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, _, err := s1.AddFindings([]*model.Finding{
		mkFinding("f-11", "AEG-011", "pid:11", key, "首", 10.0),
	}); err != nil {
		t.Fatalf("AddFindings: %v", err)
	}
	if n, err := s1.BumpFindings([]Bump{
		{FID: "f-11", Count: 2, LastDetail: "二", LastTS: 20.0, DedupKey: key},
		{FID: "f-11", Count: 3, LastDetail: "三", LastTS: 30.0, DedupKey: key},
	}); err != nil || n != 2 {
		t.Fatalf("BumpFindings: n=%d err=%v", n, err)
	}
	s1.Close()

	s2, err := New(cfg)
	if err != nil {
		t.Fatalf("New#2: %v", err)
	}
	defer s2.Close()
	f := s2.GetFinding("f-11")
	if f == nil {
		t.Fatal("重启后告警丢了")
	}
	if f.Count != 3 {
		t.Errorf("重启后 count = %d，期望 3（BumpFindings 没落盘）", f.Count)
	}
	if f.LastDetail != "三" || f.LastTS != 30.0 {
		t.Errorf("last 没回填：%q/%v", f.LastDetail, f.LastTS)
	}
	if f.FirstDetail != "首" || f.FirstTS != 10.0 {
		t.Errorf("first 被覆盖：%q/%v", f.FirstDetail, f.FirstTS)
	}
}

// TestSnapshotLimitEdgeCases limit 边界语义：<=0 表示「全要」，超容量不 panic。
func TestSnapshotLimitEdgeCases(t *testing.T) {
	s := newTestStore(t, Config{MaxEvents: 10, MaxFindings: 10})
	if err := s.AddEvents([]model.Event{
		mkEvent("process", "a", "/a", 1), mkEvent("process", "b", "/b", 2),
	}); err != nil {
		t.Fatalf("AddEvents: %v", err)
	}
	if _, _, err := s.AddFindings([]*model.Finding{
		mkFinding("f-1", "R", "pid:1", "k1", "d", 1),
		mkFinding("f-2", "R", "pid:2", "k2", "d", 2),
	}); err != nil {
		t.Fatalf("AddFindings: %v", err)
	}
	for _, limit := range []int{0, -1, 1 << 30} {
		if n := len(s.SnapshotEvents(limit, "", "", "")); n != 2 {
			t.Errorf("SnapshotEvents(%d) = %d 条，期望 2", limit, n)
		}
		if n := len(s.SnapshotFindings(limit, "")); n != 2 {
			t.Errorf("SnapshotFindings(%d) = %d 条，期望 2", limit, n)
		}
		if n := len(s.SnapshotActions(limit)); n != 0 {
			t.Errorf("SnapshotActions(%d) = %d 条，期望 0", limit, n)
		}
		if n := len(s.SnapshotIncidents(limit)); n != 0 {
			t.Errorf("SnapshotIncidents(%d) = %d 条，期望 0", limit, n)
		}
		if n := len(s.SnapshotTickets(limit)); n != 0 {
			t.Errorf("SnapshotTickets(%d) = %d 条，期望 0", limit, n)
		}
	}
	if n := len(s.SnapshotEvents(1, "", "", "")); n != 1 {
		t.Errorf("SnapshotEvents(1) = %d 条，期望 1", n)
	}
}

// TestAddFindingsDoesNotRetainCallerPointer 存储不得保留调用方的指针。
//
// 上层（引擎 Observe）会把同一个 *Finding 继续拿去渲染/判断/再改。
// 存储如果直接存这个指针，上层一改就等于越过锁改了存储里的数据——
// 单线程看不出来，-race 一连并发就炸。
func TestAddFindingsDoesNotRetainCallerPointer(t *testing.T) {
	s := newTestStore(t, Config{})
	f := mkFinding("f-p", "AEG-001", "pid:1", "k-p", "原始", 1.0)
	if _, _, err := s.AddFindings([]*model.Finding{f}); err != nil {
		t.Fatalf("AddFindings: %v", err)
	}
	// 调用方事后乱改
	f.Count = 999
	f.Detail = "被改了"
	f.Subject["polluted"] = true
	f.Tags[0] = "polluted"

	got := s.GetFinding("f-p")
	if got.Count != 1 {
		t.Errorf("存储被调用方改到了：count = %d", got.Count)
	}
	if got.Detail != "原始" {
		t.Errorf("存储被调用方改到了：detail = %q", got.Detail)
	}
	if _, ok := got.Subject["polluted"]; ok {
		t.Error("Subject 被共享")
	}
	if got.Tags[0] == "polluted" {
		t.Error("Tags 被共享")
	}
}

// TestEvictedFindingLeavesIndex 被环形缓冲淘汰的告警要从索引里摘掉。
//
// 不摘的话 GetFinding 会查到一条「缓冲里早就不存在」的告警：面板点进去
// 能看到，再并入就改到一个死对象上，重启后彻底消失——最难查的一类不一致。
func TestEvictedFindingLeavesIndex(t *testing.T) {
	s := newTestStore(t, Config{MaxFindings: 3})
	for i := 0; i < 5; i++ {
		if _, _, err := s.AddFindings([]*model.Finding{
			mkFinding(fmt.Sprintf("f-%d", i), "AEG-001", "pid:1",
				fmt.Sprintf("k-%d", i), "d", float64(i)),
		}); err != nil {
			t.Fatalf("AddFindings: %v", err)
		}
	}
	// f-0、f-1 被挤出
	if f := s.GetFinding("f-0"); f != nil {
		t.Errorf("已淘汰的 f-0 还能查到：%+v", f)
	}
	if f := s.GetFinding("f-1"); f != nil {
		t.Errorf("已淘汰的 f-1 还能查到：%+v", f)
	}
	// 还在缓冲里的必须查得到
	for i := 2; i < 5; i++ {
		if s.GetFinding(fmt.Sprintf("f-%d", i)) == nil {
			t.Errorf("f-%d 不该被淘汰", i)
		}
	}
	// 淘汰的 dedup_key 也不该再命中（否则会并到一个不存在的对象上）
	if ok, _ := s.BumpByDedupKey("k-0", "x", 9); ok {
		t.Error("已淘汰的 dedup_key 还能并入")
	}
}

// TestEvictedFindingDoesNotResurrect 淘汰后再并入不会把死对象塞回缓冲。
func TestEvictedFindingDoesNotResurrect(t *testing.T) {
	s := newTestStore(t, Config{MaxFindings: 4})
	for i := 0; i < 4; i++ {
		if _, _, err := s.AddFindings([]*model.Finding{
			mkFinding(fmt.Sprintf("f-%d", i), "R", "pid:1", fmt.Sprintf("k-%d", i), "d", float64(i)),
		}); err != nil {
			t.Fatalf("AddFindings: %v", err)
		}
	}
	// 再写一条挤掉 f-0
	if _, _, err := s.AddFindings([]*model.Finding{
		mkFinding("f-new", "R", "pid:1", "k-new", "d", 99),
	}); err != nil {
		t.Fatalf("AddFindings: %v", err)
	}
	ok, f := s.BumpByDedupKey("k-0", "想并入已淘汰的", 100)
	if ok || f != nil {
		t.Fatalf("并入了已淘汰的告警：ok=%v f=%+v", ok, f)
	}
	if n := len(s.SnapshotFindings(100, "")); n != 4 {
		t.Errorf("缓冲条数 = %d，期望 4（死对象被塞回来了？）", n)
	}
}

// ---------------- 2. 去重语义（双向） ----------------

// TestDedupMergesSameKey 同一 dedup_key 重复命中：count+1、last 更新、first 保留。
func TestDedupMergesSameKey(t *testing.T) {
	s := newTestStore(t, Config{})
	key := "AEG-001|pid:100|bash|/tmp/x"

	added, merged, err := s.AddFindings([]*model.Finding{
		mkFinding("f-1", "AEG-001", "pid:100", key, "首次", 100.0),
	})
	if err != nil {
		t.Fatalf("AddFindings: %v", err)
	}
	if added != 1 || merged != 0 {
		t.Fatalf("首次写入 added=%d merged=%d，期望 1/0", added, merged)
	}

	// 第二次：同一 dedup_key，detail 抖动
	ok, f := s.BumpByDedupKey(key, "第二次", 200.0)
	if !ok {
		t.Fatal("同一 dedup_key 应命中已有告警")
	}
	if f.Count != 2 {
		t.Errorf("count = %d，期望 2", f.Count)
	}
	if f.FirstDetail != "首次" || f.FirstTS != 100.0 {
		t.Errorf("first 被覆盖：detail=%q ts=%v", f.FirstDetail, f.FirstTS)
	}
	if f.LastDetail != "第二次" || f.LastTS != 200.0 {
		t.Errorf("last 没更新：detail=%q ts=%v", f.LastDetail, f.LastTS)
	}

	// 第三次：AddFindings 走同一 key 也必须并入，不能新开一行
	added, merged, err = s.AddFindings([]*model.Finding{
		mkFinding("f-dup", "AEG-001", "pid:100", key, "第三次", 300.0),
	})
	if err != nil {
		t.Fatalf("AddFindings#3: %v", err)
	}
	if added != 0 || merged != 1 {
		t.Errorf("重复 dedup_key 又新开了一行：added=%d merged=%d", added, merged)
	}
	if n := len(s.SnapshotFindings(100, "")); n != 1 {
		t.Errorf("告警条数 = %d，期望 1（去重失效）", n)
	}
	f = s.GetFindingByDedup(key)
	if f.Count != 3 {
		t.Errorf("count = %d，期望 3", f.Count)
	}
	if f.FirstDetail != "首次" {
		t.Errorf("first_detail = %q，期望保留「首次」", f.FirstDetail)
	}
}

// TestDedupDoesNotMergeDifferentKeys 不相关的告警不许误合并。
//
// 只测「该合并的合并了」是自欺——把一切都并成一条也能让那条测试全绿。
func TestDedupDoesNotMergeDifferentKeys(t *testing.T) {
	s := newTestStore(t, Config{})
	fs := []*model.Finding{
		mkFinding("f-1", "AEG-001", "pid:100", "AEG-001|pid:100|bash|/tmp/x", "A", 100.0),
		mkFinding("f-2", "AEG-001", "pid:200", "AEG-001|pid:200|bash|/tmp/x", "B", 101.0),
		mkFinding("f-3", "AEG-002", "pid:100", "AEG-002|pid:100|bash|/tmp/x", "C", 102.0),
		mkFinding("f-4", "AEG-001", "pid:100", "AEG-001|pid:100|bash|/etc/x", "D", 103.0),
	}
	added, merged, err := s.AddFindings(fs)
	if err != nil {
		t.Fatalf("AddFindings: %v", err)
	}
	if added != 4 || merged != 0 {
		t.Fatalf("四条不同身份 added=%d merged=%d，期望 4/0（误合并了）", added, merged)
	}
	if n := len(s.SnapshotFindings(100, "")); n != 4 {
		t.Errorf("告警条数 = %d，期望 4", n)
	}
	// 并入其中一条，其余三条必须纹丝不动
	ok, _ := s.BumpByDedupKey("AEG-001|pid:100|bash|/tmp/x", "A2", 200.0)
	if !ok {
		t.Fatal("应命中")
	}
	for _, c := range []struct{ id, key string }{
		{"f-2", "AEG-001|pid:200|bash|/tmp/x"},
		{"f-3", "AEG-002|pid:100|bash|/tmp/x"},
		{"f-4", "AEG-001|pid:100|bash|/etc/x"},
	} {
		f := s.GetFinding(c.id)
		if f == nil {
			t.Fatalf("%s 丢了", c.id)
		}
		if f.Count != 1 {
			t.Errorf("%s count = %d，期望 1（被误并入）", c.id, f.Count)
		}
	}
	if f := s.GetFinding("f-1"); f.Count != 2 {
		t.Errorf("f-1 count = %d，期望 2", f.Count)
	}
}

// TestBumpUnknownKeyDoesNotCreate BumpByDedupKey 对未知 key 返回 false 且不造行。
func TestBumpUnknownKeyDoesNotCreate(t *testing.T) {
	s := newTestStore(t, Config{})
	ok, f := s.BumpByDedupKey("never-seen", "x", 1.0)
	if ok || f != nil {
		t.Fatalf("未知 key 不该命中：ok=%v f=%+v", ok, f)
	}
	if n := len(s.SnapshotFindings(10, "")); n != 0 {
		t.Errorf("未知 key 造出了 %d 条告警", n)
	}
}

// TestBumpRowsAppliesIncrement BumpFindings 批量增量路径（对应 detect.TakeMerges）。
func TestBumpRowsAppliesIncrement(t *testing.T) {
	s := newTestStore(t, Config{})
	key := "AEG-003|host|zsh|/tmp/y"
	if _, _, err := s.AddFindings([]*model.Finding{
		mkFinding("f-9", "AEG-003", "host", key, "首", 50.0),
	}); err != nil {
		t.Fatalf("AddFindings: %v", err)
	}
	n, err := s.BumpFindings([]Bump{
		{FID: "f-9", Count: 2, LastDetail: "二", LastTS: 60.0, DedupKey: key},
		{FID: "f-9", Count: 3, LastDetail: "三", LastTS: 70.0, DedupKey: key},
		{FID: "ghost", Count: 99, LastDetail: "不存在", LastTS: 80.0},
	})
	if err != nil {
		t.Fatalf("BumpFindings: %v", err)
	}
	if n != 2 {
		t.Errorf("实际更新 %d 条，期望 2（ghost 应被跳过）", n)
	}
	f := s.GetFinding("f-9")
	if f.Count != 3 || f.LastDetail != "三" || f.LastTS != 70.0 {
		t.Errorf("批量增量结果不对：count=%d last=%q/%v", f.Count, f.LastDetail, f.LastTS)
	}
	if f.FirstDetail != "首" || f.FirstTS != 50.0 {
		t.Errorf("first 被动了：%q/%v", f.FirstDetail, f.FirstTS)
	}
}

// TestReapplyDedupFromExternal 外部 dedup.json 回填（两版共库兼容路径）。
func TestReapplyDedupFromExternal(t *testing.T) {
	s := newTestStore(t, Config{})
	key := "AEG-004|pid:7|bash|/tmp/z"
	if _, _, err := s.AddFindings([]*model.Finding{
		mkFinding("f-x", "AEG-004", "pid:7", key, "首", 10.0),
	}); err != nil {
		t.Fatalf("AddFindings: %v", err)
	}
	n, err := s.ReapplyDedup(map[string]DedupState{
		key: {FID: "f-x", Count: 17, FirstTS: 10.0, LastTS: 99.0,
			FirstDetail: "首", LastDetail: "末"},
	})
	if err != nil {
		t.Fatalf("ReapplyDedup: %v", err)
	}
	if n != 1 {
		t.Errorf("回填 %d 条，期望 1", n)
	}
	f := s.GetFinding("f-x")
	if f.Count != 17 || f.LastDetail != "末" || f.LastTS != 99.0 {
		t.Errorf("回填结果不对：%+v", f)
	}
	if f.FirstDetail != "首" {
		t.Errorf("回填动了 first：%q", f.FirstDetail)
	}
}

// ---------------- 3. 并发安全（配 -race） ----------------

// TestConcurrentWriters 多采集器/多检测线程同时写，不能丢数据也不能竞争。
//
// 断言三件事：事件总数不少、告警不重复也不丢、每个 dedup_key 的 count
// 等于实际命中次数（丢了就是少加，重复就是多加）。
func TestConcurrentWriters(t *testing.T) {
	dir := t.TempDir()
	s, err := New(Config{DataDir: dir, MaxEvents: 50000})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	const (
		writers   = 8
		perWriter = 60
	)
	var wg sync.WaitGroup

	// 采集线程：各写各的事件
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				ev := mkEvent("process", fmt.Sprintf("w%d-p%d", w, i), "/tmp/x",
					float64(w*1000+i))
				if err := s.AddEvents([]model.Event{ev}); err != nil {
					t.Errorf("AddEvents: %v", err)
					return
				}
				s.NoteCollector(fmt.Sprintf("c%d", w), i%7 != 0, float64(i), "")
				_ = s.Counters()
				_ = s.SnapshotEvents(5, "", "", "")
			}
		}(w)
	}

	// 检测线程：同一个 dedup_key 被多线程争抢并入
	sharedKey := "AEG-100|pid:999|bash|/tmp/shared"
	if _, _, err := s.AddFindings([]*model.Finding{
		mkFinding("f-shared", "AEG-100", "pid:999", sharedKey, "首", 1.0),
	}); err != nil {
		t.Fatalf("AddFindings: %v", err)
	}
	const bumpers = 8
	const bumpsEach = 50
	for b := 0; b < bumpers; b++ {
		wg.Add(1)
		go func(b int) {
			defer wg.Done()
			for i := 0; i < bumpsEach; i++ {
				s.BumpByDedupKey(sharedKey, fmt.Sprintf("b%d-%d", b, i), 1000.0)
				s.LogAction("responder", "probe", "pid=1", "ok")
				_ = s.SnapshotFindings(5, "")
			}
		}(b)
	}

	// 各自独立的告警（并发建行，不能互相吞掉）
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				key := fmt.Sprintf("AEG-200|pid:%d|bash|/tmp/u%d", w, i)
				if _, _, err := s.AddFindings([]*model.Finding{
					mkFinding(fmt.Sprintf("g-%d-%d", w, i), "AEG-200",
						fmt.Sprintf("pid:%d", w), key, "d", 5.0),
				}); err != nil {
					t.Errorf("AddFindings: %v", err)
				}
			}
		}(w)
	}

	wg.Wait()

	// 事件：一条不少
	if n := len(s.SnapshotEvents(100000, "", "", "")); n != writers*perWriter {
		t.Errorf("事件 = %d，期望 %d（并发丢事件）", n, writers*perWriter)
	}
	// 共享告警：count = 1 + 总并入次数
	f := s.GetFinding("f-shared")
	if f == nil {
		t.Fatal("共享告警丢了")
	}
	if want := 1 + bumpers*bumpsEach; f.Count != want {
		t.Errorf("共享告警 count = %d，期望 %d（并发并入丢了或重复加）", f.Count, want)
	}
	// 独立告警：writers*20 条，一条不多一条不少
	indep := 0
	for _, x := range s.SnapshotFindings(100000, "") {
		if x.RuleID == "AEG-200" {
			indep++
		}
	}
	if indep != writers*20 {
		t.Errorf("独立告警 = %d，期望 %d", indep, writers*20)
	}
	// 动作日志一条不少
	if n := len(s.SnapshotActions(100000)); n != bumpers*bumpsEach {
		t.Errorf("处置动作 = %d，期望 %d", n, bumpers*bumpsEach)
	}
}

// TestConcurrentReadWriteNoAliasing 读路径必须返回副本：改快照不能污染存储。
//
// 这条测试在 -race 下也能抓住「返回内部指针」——两个 goroutine 一个改
// 快照一个读存储，共享同一块内存就是 data race。
func TestConcurrentReadWriteNoAliasing(t *testing.T) {
	s := newTestStore(t, Config{})
	if _, _, err := s.AddFindings([]*model.Finding{
		mkFinding("f-a", "AEG-001", "pid:1", "k-a", "首", 1.0),
	}); err != nil {
		t.Fatalf("AddFindings: %v", err)
	}
	if err := s.AddEvents([]model.Event{mkEvent("process", "p", "/p", 1.0)}); err != nil {
		t.Fatalf("AddEvents: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				// 故意改快照
				for _, f := range s.SnapshotFindings(10, "") {
					f.Count = -999
					f.Subject["polluted"] = true
					f.Tags = append(f.Tags, "polluted")
				}
				for _, ev := range s.SnapshotEvents(10, "", "", "") {
					ev.Subject["polluted"] = true
					if ev.PID != nil {
						*ev.PID = -1
					}
				}
				_ = s.Counters()
				_ = s.Meta()
			}
		}()
	}
	wg.Wait()

	f := s.GetFinding("f-a")
	if f.Count == -999 {
		t.Fatal("快照是内部指针：调用方改到了存储")
	}
	if _, ok := f.Subject["polluted"]; ok {
		t.Fatal("Subject map 被共享：调用方改到了存储")
	}
	if len(f.Tags) != 1 {
		t.Fatalf("Tags 被共享：%v", f.Tags)
	}
	ev := s.SnapshotEvents(1, "", "", "")[0]
	if _, ok := ev.Subject["polluted"]; ok {
		t.Fatal("事件 Subject map 被共享")
	}
	if *ev.PID != 4242 {
		t.Fatalf("事件 PID 指针被共享：%d", *ev.PID)
	}
}

// TestConcurrentAuditChain 审计链在多线程追加后仍然自洽且不丢条。
func TestConcurrentAuditChain(t *testing.T) {
	dir := t.TempDir()
	a, err := OpenAudit(AuditConfig{Dir: dir, Enabled: true, AnchorEvery: 20})
	if err != nil {
		t.Fatalf("OpenAudit: %v", err)
	}
	defer a.Close()

	const workers, each = 8, 40
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				r := a.Append(AuditInput{
					Action: "terminate", Actor: "responder", Role: "responder",
					Target: fmt.Sprintf("pid=%d", w), Result: "ok",
				})
				if !r.OK {
					t.Errorf("Append 失败：%+v", r)
					return
				}
			}
		}(w)
	}
	wg.Wait()

	res := a.Verify()
	if !res.OK {
		t.Fatalf("并发追加后链不自洽：%v", res.Problems)
	}
	if res.Records != workers*each {
		t.Errorf("审计记录 = %d，期望 %d", res.Records, workers*each)
	}
	if res.LastSeq != workers*each {
		t.Errorf("最后 seq = %d，期望 %d（seq 重复或跳号）", res.LastSeq, workers*each)
	}
}

// ---------------- 过滤 / 时间线 ----------------

// TestSnapshotFilters 过滤条件双向验证：命中该有的有，不该有的没有。
func TestSnapshotFilters(t *testing.T) {
	s := newTestStore(t, Config{})
	if err := s.AddEvents([]model.Event{
		{Kind: "process", Process: "curl", Path: "/usr/bin/curl", Severity: "high", TS: 1.0},
		{Kind: "network", Process: "curl", Path: "/usr/bin/curl", Severity: "low", TS: 2.0},
		{Kind: "process", Process: "sshd", Path: "/usr/sbin/sshd", Severity: "info", TS: 3.0},
	}); err != nil {
		t.Fatalf("AddEvents: %v", err)
	}
	if n := len(s.SnapshotEvents(10, "process", "", "")); n != 2 {
		t.Errorf("kind=process 得 %d，期望 2", n)
	}
	if n := len(s.SnapshotEvents(10, "network", "", "")); n != 1 {
		t.Errorf("kind=network 得 %d，期望 1", n)
	}
	if n := len(s.SnapshotEvents(10, "", "high", "")); n != 1 {
		t.Errorf("minSev=high 得 %d，期望 1", n)
	}
	if n := len(s.SnapshotEvents(10, "", "", "CURL")); n != 2 {
		t.Errorf("关键字 CURL 得 %d，期望 2（大小写不敏感）", n)
	}
	if n := len(s.SnapshotEvents(10, "", "", "sshd")); n != 1 {
		t.Errorf("关键字 sshd 得 %d，期望 1", n)
	}
	if n := len(s.SnapshotEvents(10, "", "", "nothing")); n != 0 {
		t.Errorf("不存在的关键字得 %d，期望 0", n)
	}
	if n := len(s.SnapshotEvents(2, "", "", "")); n != 2 {
		t.Errorf("limit=2 得 %d", n)
	}
}

// TestTimelineMergesAllSources 时间线要覆盖五类数据源，且按时间倒序。
func TestTimelineMergesAllSources(t *testing.T) {
	s := newTestStore(t, Config{})
	if err := s.AddEvents([]model.Event{mkEvent("process", "p", "/p", 100.0)}); err != nil {
		t.Fatalf("AddEvents: %v", err)
	}
	if _, _, err := s.AddFindings([]*model.Finding{
		mkFinding("f-1", "AEG-001", "pid:1", "k1", "d", 200.0),
	}); err != nil {
		t.Fatalf("AddFindings: %v", err)
	}
	if err := s.AddIncident(model.Incident{ID: "i-1", Title: "链", TS: 300.0}); err != nil {
		t.Fatalf("AddIncident: %v", err)
	}
	s.LogAction("responder", "terminate", "pid=1", "ok")
	if _, err := s.CreateTicket("t", "high", "f-1", "", "rule"); err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}

	rows := s.Timeline(100)
	types := map[string]int{}
	for _, r := range rows {
		types[r.Type]++
	}
	for _, want := range []string{"event", "finding", "incident", "action", "ticket"} {
		if types[want] == 0 {
			t.Errorf("时间线缺 %s 类型：%v", want, types)
		}
	}
	for i := 1; i < len(rows); i++ {
		if rows[i-1].TS < rows[i].TS {
			t.Errorf("时间线未按时间倒序：%v < %v", rows[i-1].TS, rows[i].TS)
			break
		}
	}
	if n := len(s.Timeline(2)); n != 2 {
		t.Errorf("Timeline(2) = %d 行", n)
	}
}

// ---------------- 状态 / meta ----------------

// TestStateAndMeta 共享状态与采集器统计。
func TestStateAndMeta(t *testing.T) {
	s := newTestStore(t, Config{})
	if v := s.State("nope"); v != nil {
		t.Errorf("未设置的 state 应为 nil，实得 %v", v)
	}
	if v := s.GetState("nope", 42); v != 42 {
		t.Errorf("GetState 缺省值失效：%v", v)
	}
	s.SetState("processes", []int{1, 2, 3})
	if v, ok := s.State("processes").([]int); !ok || len(v) != 3 {
		t.Errorf("state 读写不对：%v", s.State("processes"))
	}

	s.NoteCollector("proc", true, 12.5, "")
	s.NoteCollector("proc", false, 30.0, "需要 root")
	m := s.Meta()
	c := m.Collectors["proc"]
	if c.Runs != 2 {
		t.Errorf("Runs = %d，期望 2（失败也要计 runs）", c.Runs)
	}
	if c.Errors != 1 {
		t.Errorf("Errors = %d，期望 1", c.Errors)
	}
	if c.LastError != "需要 root" {
		t.Errorf("LastError = %q", c.LastError)
	}
	// meta 是副本：改它不影响存储
	m.Collectors["proc"] = CollectorStat{Runs: 999}
	if got := s.Meta().Collectors["proc"].Runs; got != 2 {
		t.Errorf("Meta 返回了内部 map：Runs = %d", got)
	}
}

// TestMemoryOnlyStaysInMemory MemoryOnly=true 时不落盘也不建目录。
func TestPersistDisabledStaysInMemory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "should-not-exist")
	s, err := New(Config{DataDir: dir, MemoryOnly: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()
	if err := s.AddEvents([]model.Event{mkEvent("process", "p", "/p", 1.0)}); err != nil {
		t.Fatalf("AddEvents: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("MemoryOnly=true 却建了目录 %s", dir)
	}
	if n := len(s.SnapshotEvents(10, "", "", "")); n != 1 {
		t.Errorf("内存模式事件 = %d，期望 1", n)
	}
}

// TestCloseIdempotentAndGuards 重复 Close 不报错，关闭后写入返回错误。
func TestCloseIdempotentAndGuards(t *testing.T) {
	s := newTestStore(t, Config{})
	if err := s.Close(); err != nil {
		t.Fatalf("首次 Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("重复 Close: %v", err)
	}
	if err := s.AddEvents([]model.Event{mkEvent("process", "p", "/p", 1.0)}); err == nil {
		t.Error("关闭后 AddEvents 应返回错误")
	}
	if _, _, err := s.AddFindings([]*model.Finding{mkFinding("f", "R", "a", "k", "d", 1.0)}); err == nil {
		t.Error("关闭后 AddFindings 应返回错误")
	}
}

// TestFindingsJSONShape findings.jsonl 的行必须是可解析的完整 Finding，
// 增量行必须带 op —— 否则重启回放会把它当成全量行解析出一堆零值。
func TestFindingsJSONShape(t *testing.T) {
	dir := t.TempDir()
	s, err := New(Config{DataDir: dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	key := "AEG-001|pid:1|bash|/tmp/x"
	if _, _, err := s.AddFindings([]*model.Finding{
		mkFinding("f-1", "AEG-001", "pid:1", key, "d", 1.0),
	}); err != nil {
		t.Fatalf("AddFindings: %v", err)
	}
	s.BumpByDedupKey(key, "d2", 2.0)
	s.SetFindingStatus("f-1", "closed")
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines, err := readJSONL(filepath.Join(dir, FileFindings))
	if err != nil {
		t.Fatalf("readJSONL: %v", err)
	}
	if len(lines) != 3 {
		t.Fatalf("findings.jsonl 行数 = %d，期望 3（1 全量 + 1 bump + 1 status）", len(lines))
	}
	var full model.Finding
	if err := json.Unmarshal(lines[0], &full); err != nil {
		t.Fatalf("首行不是合法 Finding：%v", err)
	}
	if full.ID != "f-1" || full.DedupKey != key {
		t.Errorf("全量行内容不对：%+v", full)
	}
	for i, want := range []string{"bump", "status"} {
		var probe struct {
			Op string `json:"op"`
		}
		if err := json.Unmarshal(lines[i+1], &probe); err != nil {
			t.Fatalf("第 %d 行解析失败：%v", i+1, err)
		}
		if probe.Op != want {
			t.Errorf("第 %d 行 op = %q，期望 %q", i+1, probe.Op, want)
		}
	}

	// 重启后状态也要读回
	s2, err := New(Config{DataDir: dir})
	if err != nil {
		t.Fatalf("New#2: %v", err)
	}
	defer s2.Close()
	if f := s2.GetFinding("f-1"); f == nil || f.Status != "closed" {
		t.Errorf("状态没读回：%+v", f)
	}
}
