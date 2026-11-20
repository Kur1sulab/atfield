package store

// invariant_test.go —— 「内存态 == 磁盘态」这条不变式。
//
// 这是整套测试里最重要的一条：Python 版所有翻车都是同一个模式——
// 内存里改了、磁盘上没改，然后重启回到旧值，**没有任何报错**。
// 所以这里用随机操作序列跑一遍，把内存快照与「重建后的快照」逐条对齐。
//
// 任何写路径只要忘了落盘，这条测试就会红，而不用等到线上重启才发现
// 月报里的 count 全是 1。

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/Kur1sulab/atfield/internal/model"
)

// TestMemoryEqualsDiskAfterReopen 随机操作后，重开实例的内存态必须与关前一致。
func TestMemoryEqualsDiskAfterReopen(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{DataDir: dir, MaxEvents: 500, MaxFindings: 200}

	s1, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rng := rand.New(rand.NewSource(20261120))
	keys := []string{"k-0", "k-1", "k-2", "k-3", "k-4"}

	// 随机混合四种写：新事件、新告警、并入、状态变更
	for step := 0; step < 300; step++ {
		switch rng.Intn(4) {
		case 0:
			if err := s1.AddEvents([]model.Event{
				mkEvent("process", fmt.Sprintf("p%d", step), "/tmp/x", float64(step)),
			}); err != nil {
				t.Fatalf("AddEvents: %v", err)
			}
		case 1:
			key := keys[rng.Intn(len(keys))]
			if _, _, err := s1.AddFindings([]*model.Finding{{
				ID:       fmt.Sprintf("f-%d", step),
				RuleID:   "AEG-001",
				Name:     "规则",
				Severity: "high",
				Status:   "open",
				TS:       float64(step),
				Actor:    "pid:1",
				Detail:   fmt.Sprintf("首次-%d", step),
				DedupKey: key,
				Count:    1,
			}}); err != nil {
				t.Fatalf("AddFindings: %v", err)
			}
		case 2:
			// 按 key 并入（可能没命中，命中就要落盘）
			key := keys[rng.Intn(len(keys))]
			s1.BumpByDedupKey(key, fmt.Sprintf("并入-%d", step), float64(step))
		case 3:
			if rng.Intn(4) == 0 {
				// 改一条已有告警的状态
				for _, f := range s1.SnapshotFindings(50, "") {
					s1.SetFindingStatus(f.ID, "closed")
					break
				}
			}
			s1.LogAction("alice", "probe", fmt.Sprintf("step=%d", step), "ok")
		}
	}

	// 关前快照
	before := s1.SnapshotFindings(1000, "")
	beforeEvents := len(s1.SnapshotEvents(10000, "", "", ""))
	beforeActs := len(s1.SnapshotActions(10000))
	beforeCounters := s1.Counters()
	if err := s1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// 重开
	s2, err := New(cfg)
	if err != nil {
		t.Fatalf("New#2: %v", err)
	}
	defer s2.Close()
	after := s2.SnapshotFindings(1000, "")

	// 逐条对齐：条数、ID、count、首末样本、状态
	if len(after) != len(before) {
		t.Fatalf("告警条数：重启前 %d，重启后 %d", len(before), len(after))
	}
	for i := range before {
		b, a := before[i], after[i]
		if b.ID != a.ID {
			t.Fatalf("[%d] ID 顺序变了：%s vs %s", i, b.ID, a.ID)
		}
		if b.Count != a.Count {
			t.Errorf("%s count：重启前 %d，重启后 %d（并入没落盘）", b.ID, b.Count, a.Count)
		}
		if b.FirstDetail != a.FirstDetail {
			t.Errorf("%s first_detail：%q vs %q", b.ID, b.FirstDetail, a.FirstDetail)
		}
		if b.LastDetail != a.LastDetail {
			t.Errorf("%s last_detail：%q vs %q", b.ID, b.LastDetail, a.LastDetail)
		}
		if b.FirstTS != a.FirstTS {
			t.Errorf("%s first_ts：%v vs %v", b.ID, b.FirstTS, a.FirstTS)
		}
		if b.LastTS != a.LastTS {
			t.Errorf("%s last_ts：%v vs %v", b.ID, b.LastTS, a.LastTS)
		}
		if b.Status != a.Status {
			t.Errorf("%s status：%q vs %q", b.ID, b.Status, a.Status)
		}
		if b.DedupKey != a.DedupKey {
			t.Errorf("%s dedup_key：%q vs %q", b.ID, b.DedupKey, a.DedupKey)
		}
	}

	if n := len(s2.SnapshotEvents(10000, "", "", "")); n != beforeEvents {
		t.Errorf("事件：重启前 %d，重启后 %d", beforeEvents, n)
	}
	if n := len(s2.SnapshotActions(10000)); n != beforeActs {
		t.Errorf("处置动作：重启前 %d，重启后 %d", beforeActs, n)
	}
	afterCounters := s2.Counters()
	if len(afterCounters) != len(beforeCounters) {
		t.Errorf("计数器种类：%d vs %d", len(beforeCounters), len(afterCounters))
	}
	for k, v := range beforeCounters {
		if afterCounters[k] != v {
			t.Errorf("计数器 %s：重启前 %d，重启后 %d", k, v, afterCounters[k])
		}
	}
}

// TestBumpPersistsOnDuplicateAdd AddFindings 命中重复 dedup_key 时也必须落盘。
//
// 这条单独测：它是混合随机测试里最容易被忽略的一条路径，而且错了以后
// 内存完全自洽、只有重启才暴露。
func TestBumpPersistsOnDuplicateAdd(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{DataDir: dir}
	key := "AEG-009|pid:9|bash|/tmp/z"

	s1, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// 同一个 dedup_key 走三次 AddFindings，全部应并入
	for i := 0; i < 3; i++ {
		if _, _, err := s1.AddFindings([]*model.Finding{{
			ID: fmt.Sprintf("dup-%d", i), RuleID: "AEG-009", Severity: "high",
			TS: float64(i), Detail: fmt.Sprintf("第%d次", i), DedupKey: key, Count: 1,
		}}); err != nil {
			t.Fatalf("AddFindings[%d]: %v", i, err)
		}
	}
	if f := s1.GetFindingByDedup(key); f.Count != 3 {
		t.Fatalf("内存 count = %d，期望 3", f.Count)
	}
	s1.Close()

	s2, err := New(cfg)
	if err != nil {
		t.Fatalf("New#2: %v", err)
	}
	defer s2.Close()
	f := s2.GetFindingByDedup(key)
	if f == nil {
		t.Fatal("重启后告警丢了")
	}
	if f.Count != 3 {
		t.Errorf("重启后 count = %d，期望 3（AddFindings 的并入没落盘）", f.Count)
	}
	if f.FirstDetail != "第0次" {
		t.Errorf("first_detail = %q，期望「第0次」", f.FirstDetail)
	}
	if f.LastDetail != "第2次" {
		t.Errorf("last_detail = %q，期望「第2次」", f.LastDetail)
	}
}
