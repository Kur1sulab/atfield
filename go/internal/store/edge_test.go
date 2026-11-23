package store

// edge_test.go —— 边界与默认值：ID 生成、截断、采集器状态、配置归一。
//
// 这些不是「防御性编程的样板」：每条都对应一个真实入口。
// 告警 ID 由外部构造时可能为空；截断处理的是中文（按 rune，不按字节）。

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Kur1sulab/atfield/internal/model"
)

// TestFindingWithoutIDGetsOne 外部构造的告警没给 ID 时必须补一个。
//
// 不补的后果：多条无 ID 告警会在 findIdx 里互相覆盖，面板上只剩最后一条，
// 而且 DedupKey 并入会改错对象。
func TestFindingWithoutIDGetsOne(t *testing.T) {
	s := newTestStore(t, Config{})
	added, _, err := s.AddFindings([]*model.Finding{
		{RuleID: "AEG-001", Severity: "high", TS: 1, Detail: "无 ID 甲", DedupKey: "k1"},
		{RuleID: "AEG-001", Severity: "high", TS: 2, Detail: "无 ID 乙", DedupKey: "k2"},
	})
	if err != nil {
		t.Fatalf("AddFindings: %v", err)
	}
	if added != 2 {
		t.Fatalf("added = %d，期望 2", added)
	}
	got := s.SnapshotFindings(10, "")
	if len(got) != 2 {
		t.Fatalf("告警 = %d 条，期望 2", len(got))
	}
	if got[0].ID == "" || got[1].ID == "" {
		t.Fatal("有告警没被补 ID")
	}
	if got[0].ID == got[1].ID {
		t.Fatalf("两条无 ID 告警补出了同一个 ID：%s", got[0].ID)
	}
	// 补的 ID 要能被索引到
	for _, f := range got {
		if s.GetFinding(f.ID) == nil {
			t.Errorf("补的 ID %s 不在索引里", f.ID)
		}
	}
	// 首次入库时 count/first/last 要补齐
	for _, f := range got {
		if f.Count != 1 {
			t.Errorf("%s count = %d，期望 1", f.ID, f.Count)
		}
		if f.FirstDetail == "" || f.LastDetail == "" {
			t.Errorf("%s 首末样本没补：%+v", f.ID, f)
		}
		if f.Status != "open" {
			t.Errorf("%s status = %q，期望 open", f.ID, f.Status)
		}
	}
}

// TestTruncateKeepsRunesIntact 截断按 rune，不能把一个汉字劈成半个。
//
// 按字节截断会产出非法 UTF-8：JSON 序列化后变成 U+FFFD，
// 审计里的目标名、工单标题都会变成乱码——而且是永久写进磁盘的乱码。
func TestTruncateKeepsRunesIntact(t *testing.T) {
	zh := strings.Repeat("中", 10)
	got := truncate(zh, 4)
	if utf8.RuneCountInString(got) != 4 {
		t.Errorf("截断后 %d 个 rune，期望 4", utf8.RuneCountInString(got))
	}
	if !utf8.ValidString(got) {
		t.Error("截断产生了非法 UTF-8")
	}
	if got != "中中中中" {
		t.Errorf("截断结果 = %q", got)
	}
	// 短串原样返回
	if truncate("ab", 10) != "ab" {
		t.Error("短串被改了")
	}
	// 恰好等于上限
	if truncate("abcd", 4) != "abcd" {
		t.Error("恰好等于上限时被截断了")
	}
}

// TestSaveCollectorStatus 采集层累计状态写入（不是累加，是覆盖）。
func TestSaveCollectorStatus(t *testing.T) {
	s := newTestStore(t, Config{})
	s.SaveCollectorStatus([]CollectorStatus{
		{Name: "proc", Runs: 100, Errors: 3, LastTS: 1000, LastMS: 12.5, LastError: "需要 root"},
		{Name: "net", Runs: 50, Errors: 0, LastTS: 1001, LastMS: 4.0, OkSince: 900},
	})
	m := s.Meta()
	p := m.Collectors["proc"]
	if p.Runs != 100 || p.Errors != 3 || p.LastError != "需要 root" {
		t.Errorf("proc 状态不对：%+v", p)
	}
	n := m.Collectors["net"]
	if n.Runs != 50 || n.OkSince != 900 {
		t.Errorf("net 状态不对：%+v", n)
	}

	// 再写一次是覆盖而不是累加（采集层给的是累计值）
	s.SaveCollectorStatus([]CollectorStatus{{Name: "proc", Runs: 200, Errors: 4}})
	if got := s.Meta().Collectors["proc"].Runs; got != 200 {
		t.Errorf("重复写入后 Runs = %d，期望 200（不该累加）", got)
	}
	// 和 NoteCollector 混用不该翻倍：这里只验证两条路径各自独立
	s.NoteCollector("proc", true, 1, "")
	if got := s.Meta().Collectors["proc"].Runs; got != 201 {
		t.Errorf("NoteCollector 后 Runs = %d，期望 201", got)
	}
}

// TestConfigDefaults 零值配置要落成可用默认值。
func TestConfigDefaults(t *testing.T) {
	cfg := Config{}.withDefaults()
	if cfg.MaxEvents != DefaultMaxEvents || cfg.MaxFindings != DefaultMaxFindings {
		t.Errorf("容量默认值不对：%+v", cfg)
	}
	if cfg.MaxIncidents != DefaultMaxIncidents || cfg.MaxTickets != DefaultMaxTickets {
		t.Errorf("容量默认值不对：%+v", cfg)
	}
	if cfg.PersistMaxMB != DefaultPersistMaxMB {
		t.Errorf("PersistMaxMB = %d，期望 %d", cfg.PersistMaxMB, DefaultPersistMaxMB)
	}
	if cfg.DataDir == "" {
		t.Error("DataDir 没有兜底到 ~/.atfield")
	}
	// 显式值不被覆盖
	custom := Config{MaxEvents: 7, PersistMaxMB: 3}.withDefaults()
	if custom.MaxEvents != 7 || custom.PersistMaxMB != 3 {
		t.Errorf("显式配置被覆盖：%+v", custom)
	}
	// Store.Config() 返回生效值
	s := newTestStore(t, Config{MaxEvents: 7})
	if s.Config().MaxEvents != 7 {
		t.Errorf("Config() 返回 %d，期望 7", s.Config().MaxEvents)
	}
}

// TestAuditConfigDefaults 审计默认值。
func TestAuditConfigDefaults(t *testing.T) {
	got := AuditConfig{}.withDefaults()
	def := DefaultAuditConfig()
	if got.MaxMB != def.MaxMB || got.RetainDays != def.RetainDays {
		t.Errorf("默认值不对：%+v", got)
	}
	if got.RetainTotalMB != def.RetainTotalMB || got.AnchorEvery != def.AnchorEvery {
		t.Errorf("默认值不对：%+v", got)
	}
	// 关掉 Enabled 不会被 withDefaults 强行打开
	if (AuditConfig{Enabled: false}).withDefaults().Enabled {
		t.Error("Enabled=false 被覆盖成 true 了")
	}
}
