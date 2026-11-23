package store

// load_test.go —— 启动回填的边界：容量截断、跨代取尾、空文件。

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Kur1sulab/atfield/internal/model"
)

// TestRestartKeepsNewestEventsOnly 容量小于历史条数时，只留最新的一批。
//
// 语义与 Python 的 deque(maxlen=N) 一致：淘汰最旧。这里额外验证跨轮转代
// 也是按「最新优先」取的——如果先读旧代再截断，留下的会是旧数据。
func TestRestartKeepsNewestEventsOnly(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{DataDir: dir, MaxEvents: 10}

	s1, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s1.fEvents.maxBytes = 400 // 强制多次轮转
	const n = 60
	for i := 0; i < n; i++ {
		if err := s1.AddEvents([]model.Event{
			mkEvent("process", fmt.Sprintf("p%02d", i), "/p", float64(i)),
		}); err != nil {
			t.Fatalf("AddEvents: %v", err)
		}
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// 确认确实发生过轮转
	if _, err := os.Stat(filepath.Join(dir, FileEvents+".1")); err != nil {
		t.Fatalf("没发生轮转：%v", err)
	}

	s2, err := New(cfg)
	if err != nil {
		t.Fatalf("New#2: %v", err)
	}
	defer s2.Close()
	got := s2.SnapshotEvents(1000, "", "", "")
	if len(got) != 10 {
		t.Fatalf("事件 = %d 条，期望 10（容量）", len(got))
	}
	// 最新在前：p59 … p50
	for i := 0; i < 10; i++ {
		want := fmt.Sprintf("p%02d", n-1-i)
		if got[i].Process != want {
			t.Errorf("[%d] = %q，期望 %q（回填取了旧数据）", i, got[i].Process, want)
		}
	}
}

// TestRestartOnEmptyFiles 空文件（0 字节）不能让启动失败或 panic。
func TestRestartOnEmptyFiles(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{FileEvents, FileFindings, FileIncidents, FileActions} {
		if err := os.WriteFile(filepath.Join(dir, f), nil, 0o600); err != nil {
			t.Fatalf("write %s: %v", f, err)
		}
	}
	s, err := New(Config{DataDir: dir})
	if err != nil {
		t.Fatalf("空文件让 New 失败了：%v", err)
	}
	defer s.Close()
	if e, f, i, tk := s.Len(); e != 0 || f != 0 || i != 0 || tk != 0 {
		t.Errorf("空文件读出了数据：events=%d findings=%d incidents=%d tickets=%d", e, f, i, tk)
	}
}

// TestBumpWithoutBaseRow 增量行对应的全量行被淘汰时，仍要还原出可用告警。
//
// 取证现场：findings.jsonl 被轮转切掉了前半段，剩下全是 bump 行。
// 丢整条告警比丢部分字段更糟——宁可只留 ID 和 count。
func TestBumpWithoutBaseRow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, FileFindings)
	lines := `{"op":"bump","fid":"orphan","dedup_key":"K1","count":9,"last_detail":"末","last_ts":99}
`
	if err := os.WriteFile(path, []byte(lines), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	s, err := New(Config{DataDir: dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()
	f := s.GetFinding("orphan")
	if f == nil {
		t.Fatal("孤立的 bump 行被整条丢掉了")
	}
	if f.Count != 9 || f.LastDetail != "末" || f.LastTS != 99 {
		t.Errorf("还原结果不对：%+v", f)
	}
	if f.DedupKey != "K1" {
		t.Errorf("dedup_key = %q，期望 K1（否则重启后再并入就找不到它）", f.DedupKey)
	}
}

// TestUnknownDedupKeyAfterRestart 重启后按 dedup_key 并入仍要命中。
func TestUnknownDedupKeyAfterRestart(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{DataDir: dir}
	key := "AEG-7|pid:7|zsh|/tmp/q"

	s1, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, _, err := s1.AddFindings([]*model.Finding{
		mkFinding("f-7", "AEG-7", "pid:7", key, "首", 1.0),
	}); err != nil {
		t.Fatalf("AddFindings: %v", err)
	}
	s1.Close()

	s2, err := New(cfg)
	if err != nil {
		t.Fatalf("New#2: %v", err)
	}
	defer s2.Close()
	ok, f := s2.BumpByDedupKey(key, "重启后", 2.0)
	if !ok {
		t.Fatal("重启后按 dedup_key 并入没命中：索引没回填")
	}
	if f.Count != 2 || f.LastDetail != "重启后" || f.FirstDetail != "首" {
		t.Errorf("并入结果不对：%+v", f)
	}
}
