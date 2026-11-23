package store

// rotation_test.go —— 轮转与损坏恢复。
//
// 轮转是最容易写出「静默丢数据」的地方：文件改名之后如果只读当前文件，
// 上一代的告警就再也回不来了，而且不会有任何报错——面板上只是少了几天数据。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Kur1sulab/atfield/internal/model"
)

// TestRotationKeepsPreviousGeneration 轮转后 .1 里的历史仍要读得回。
func TestRotationKeepsPreviousGeneration(t *testing.T) {
	dir := t.TempDir()
	// 极小的轮转阈值：写几条就触发
	s, err := New(Config{DataDir: dir, PersistMaxMB: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// 手工把阈值调小：让 40 条数据触发 1–2 次轮转（不是 30 次——
	// 留存代数有上限，超过就按设计淘汰最老的一代）。
	s.fFindings.maxBytes = 6000
	s.fEvents.maxBytes = 3000

	const n = 40
	for i := 0; i < n; i++ {
		key := "AEG-001|pid:" + itoa(i) + "|bash|/tmp/x"
		if _, _, err := s.AddFindings([]*model.Finding{
			mkFinding("f-"+itoa(i), "AEG-001", "pid:"+itoa(i), key, "d", float64(i)),
		}); err != nil {
			t.Fatalf("AddFindings[%d]: %v", i, err)
		}
		if err := s.AddEvents([]model.Event{mkEvent("process", "p"+itoa(i), "/p", float64(i))}); err != nil {
			t.Fatalf("AddEvents[%d]: %v", i, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// 确认真的发生过轮转
	if _, err := os.Stat(filepath.Join(dir, FileFindings+".1")); err != nil {
		t.Fatalf("没发生轮转：%v", err)
	}

	s2, err := New(Config{DataDir: dir})
	if err != nil {
		t.Fatalf("New#2: %v", err)
	}
	defer s2.Close()

	// 关键：.1 + 当前文件合起来，最近的一批必须都在
	got := s2.SnapshotFindings(1000, "")
	if len(got) == 0 {
		t.Fatal("轮转后告警全丢了")
	}
	// 最新一条必须读回（它在当前文件里）
	if s2.GetFinding("f-"+itoa(n-1)) == nil {
		t.Error("轮转后最新告警丢了")
	}
	// 淘汰语义：容量内应该保留最新的若干条（这里容量足够，全都要在）
	if len(got) != n {
		t.Errorf("告警 = %d 条，期望 %d（轮转后丢了历史）", len(got), n)
	}
	evs := s2.SnapshotEvents(1000, "", "", "")
	if len(evs) != n {
		t.Errorf("事件 = %d 条，期望 %d", len(evs), n)
	}
}

// TestCorruptFindingsLinesSkipped 告警文件里的坏行不影响其余行。
func TestCorruptFindingsLinesSkipped(t *testing.T) {
	dir := t.TempDir()
	s, err := New(Config{DataDir: dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, _, err := s.AddFindings([]*model.Finding{
			mkFinding("f-"+itoa(i), "AEG-001", "pid:1", "k"+itoa(i), "d", float64(i)),
		}); err != nil {
			t.Fatalf("AddFindings: %v", err)
		}
	}
	s.Close()

	// 在中间插一行坏 JSON
	fh, _ := os.OpenFile(filepath.Join(dir, FileFindings), os.O_WRONLY|os.O_APPEND, 0o600)
	fh.WriteString("{not json at all\n")
	fh.Close()

	s2, err := New(Config{DataDir: dir})
	if err != nil {
		t.Fatalf("New#2: %v", err)
	}
	defer s2.Close()
	if n := len(s2.SnapshotFindings(100, "")); n != 3 {
		t.Errorf("告警 = %d 条，期望 3（坏行把好行带走了）", n)
	}
}

// TestCorruptTicketsFileNotFatal 工单文件损坏时启动照常，工单为空。
func TestCorruptTicketsFileNotFatal(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, FileTickets), []byte("{broken"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	s, err := New(Config{DataDir: dir})
	if err != nil {
		t.Fatalf("坏工单文件让 New 失败了：%v", err)
	}
	defer s.Close()
	if n := len(s.SnapshotTickets(10)); n != 0 {
		t.Errorf("工单 = %d，期望 0", n)
	}
	// 还能继续正常建单
	if _, err := s.CreateTicket("新单", "low", "", "", ""); err != nil {
		t.Fatalf("坏文件后 CreateTicket 失败：%v", err)
	}
}

// TestTicketSeqContinuesAfterGap 中间工单被删后，续号不能撞号。
func TestTicketSeqContinuesAfterGap(t *testing.T) {
	dir := t.TempDir()
	s, err := New(Config{DataDir: dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < 5; i++ {
		if _, err := s.CreateTicket("t", "low", "", "", ""); err != nil {
			t.Fatalf("CreateTicket: %v", err)
		}
	}
	s.Close()

	// 模拟运维手工删掉了前三条（只留 T0004/T0005）
	raw, _ := os.ReadFile(filepath.Join(dir, FileTickets))
	var list []Ticket
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var kept []Ticket
	for _, tk := range list {
		if tk.TID == "T0004" || tk.TID == "T0005" {
			kept = append(kept, tk)
		}
	}
	if len(kept) != 2 {
		t.Fatalf("测试前置条件不成立：留了 %d 条（%+v）", len(kept), list)
	}
	if err := os.WriteFile(filepath.Join(dir, FileTickets), mustJSON(kept), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	s2, err := New(Config{DataDir: dir})
	if err != nil {
		t.Fatalf("New#2: %v", err)
	}
	defer s2.Close()
	tk, err := s2.CreateTicket("新单", "low", "", "", "")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	if tk.TID != "T0006" {
		t.Errorf("续号 = %s，期望 T0006（按磁盘最大编号，不是 len+1）", tk.TID)
	}
	// 不能和已有编号重复
	for _, old := range kept {
		if old.TID == tk.TID {
			t.Fatalf("撞号：%s", tk.TID)
		}
	}
}

// TestIncidentEvolutionKeepsLatest 同一攻击链演进：只保留最新一份，位置提前。
func TestIncidentEvolutionKeepsLatest(t *testing.T) {
	s := newTestStore(t, Config{})
	if err := s.AddIncident(model.Incident{ID: "i-1", Title: "阶段一", TS: 10, Findings: []string{"f-1"}}); err != nil {
		t.Fatalf("AddIncident: %v", err)
	}
	if err := s.AddIncident(model.Incident{ID: "i-2", Title: "另一条", TS: 20}); err != nil {
		t.Fatalf("AddIncident: %v", err)
	}
	if err := s.AddIncident(model.Incident{ID: "i-1", Title: "阶段二", TS: 30, Findings: []string{"f-1", "f-2"}}); err != nil {
		t.Fatalf("AddIncident: %v", err)
	}

	incs := s.SnapshotIncidents(10)
	if len(incs) != 2 {
		t.Fatalf("攻击链 = %d 条，期望 2（同一 ID 不该重复）", len(incs))
	}
	if incs[0].ID != "i-1" || incs[0].Title != "阶段二" {
		t.Errorf("最新演进没排在最前：%+v", incs[0])
	}
	if len(incs[0].Findings) != 2 {
		t.Errorf("演进后的 findings 没更新：%v", incs[0].Findings)
	}
	if incs[1].ID != "i-2" {
		t.Errorf("第二条 = %s，期望 i-2", incs[1].ID)
	}

	// 重启后同样只留最新一份
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// itoa 小工具（避免为一行引入 strconv 到测试的 import 列表里打架）。
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [8]byte
	p := len(buf)
	for i > 0 {
		p--
		buf[p] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[p:])
}
