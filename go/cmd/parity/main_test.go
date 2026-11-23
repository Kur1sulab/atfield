package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Kur1sulab/atfield/go/internal/parity"
)

// 事件流读取 + 重放归一：缺 eid/host 要补齐，缺 ts 要拒绝。
func TestReadEventsNormalization(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ev.jsonl")
	body := `{"kind":"process.start","ts":100.5,"process":"bash","path":"/tmp/x.sh","severity":"high"}
{"kind":"net.connect","ts":101.5,"eid":"kept","host":"H1","severity":"info"}
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	patchedEID, patchedHost = 0, 0
	events, err := readEvents(path)
	if err != nil {
		t.Fatalf("读事件失败: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("事件数 = %d", len(events))
	}
	if events[0].EID != "ln:1" {
		t.Fatalf("缺 eid 应按行号补齐，实际 %q", events[0].EID)
	}
	if events[0].Host != replayHost {
		t.Fatalf("缺 host 应补占位值，实际 %q", events[0].Host)
	}
	if events[1].EID != "kept" || events[1].Host != "H1" {
		t.Fatalf("已有 eid/host 不应被改: %q %q", events[1].EID, events[1].Host)
	}
	if patchedEID != 1 || patchedHost != 1 {
		t.Fatalf("归一计数 = %d/%d，期望 1/1", patchedEID, patchedHost)
	}

	noTS := filepath.Join(dir, "nots.jsonl")
	if err := os.WriteFile(noTS, []byte(`{"kind":"process.start"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readEvents(noTS); err == nil {
		t.Fatalf("缺 ts 的事件必须拒绝")
	}
}

// realStream 一条真实事件流的对拍输入。
//
// 三条流来自不同采集方向，见 testdata/parity/STREAMS.md：
//   - live_go：Go 采集器 --once --all 连跑 3 轮
//   - live_py：Python 采集器 --once 连跑 3 轮（同一进程，常驻语义）
//   - history_py：Python 守护进程真实落盘 events.jsonl 的非噪声种类全集
//
// 每条流都**两侧同源**（同一份归一后的 JSONL + 同一份进程表 + 同一份 IOC）。
type realStream struct {
	name      string
	events    string
	proctable string
	ioc       string
	heavy     bool // 大流：-short 时跳过
}

func realStreams(root string) []realStream {
	return []realStream{
		{
			name:      "corpus",
			events:    filepath.Join(root, "events.jsonl"),
			proctable: filepath.Join(root, "proctable.json"),
		},
		{
			name:      "live_go",
			events:    filepath.Join(root, "streams", "live_go_events.jsonl"),
			proctable: filepath.Join(root, "streams", "live_go_proctable.json"),
			ioc:       filepath.Join(root, "streams", "live_ioc.json"),
		},
		{
			name:      "live_py",
			events:    filepath.Join(root, "streams", "live_py_events.jsonl"),
			proctable: filepath.Join(root, "streams", "live_py_proctable.json"),
			ioc:       filepath.Join(root, "streams", "live_ioc.json"),
		},
		{
			name:      "history_py",
			events:    filepath.Join(root, "streams", "history_py_events.jsonl"),
			proctable: filepath.Join(root, "proctable.json"),
			ioc:       filepath.Join(root, "streams", "live_ioc.json"),
			heavy:     true,
		},
	}
}

// 端到端：真实事件流喂两版引擎，断言逐字段一致。
//
// 这条测试就是 MIGRATION.md 第二节的验收标准本身。缺 Python 版仓库、
// 适配器或 python3 时跳过（Go 侧的规则单测仍会跑）。
func TestRealStreamParity(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "parity")
	pyDir := os.Getenv("AEGIS_PY_DIR")
	if pyDir == "" {
		home, _ := os.UserHomeDir()
		pyDir = filepath.Join(home, "aegis")
	}
	adapter := filepath.Join(pyDir, "parity_cli.py")
	if _, err := os.Stat(adapter); err != nil {
		t.Skipf("缺 Python 适配器 %s", adapter)
	}

	for _, s := range realStreams(root) {
		s := s
		t.Run(s.name, func(t *testing.T) {
			if s.heavy && testing.Short() {
				t.Skip("-short：跳过大流量真实流")
			}
			if _, err := os.Stat(s.events); err != nil {
				t.Skipf("缺事件流 %s（先跑 testdata/parity/tools/capture_*）", s.events)
			}
			o := options{
				events:    s.events,
				proctable: s.proctable,
				ioc:       s.ioc,
				python:    "python3",
				adapter:   adapter,
				pyDir:     pyDir,
				timeout:   5 * time.Minute,
			}

			patchedEID, patchedHost = 0, 0
			events, err := readEvents(o.events)
			if err != nil {
				t.Fatalf("读事件流: %v", err)
			}
			work := t.TempDir()
			normPath := filepath.Join(work, "events.normalized.jsonl")
			if err := writeEventsJSONL(normPath, events); err != nil {
				t.Fatalf("写归一事件流: %v", err)
			}
			o.events = normPath

			proctable, err := readProctable(o.proctable)
			if err != nil {
				t.Fatalf("读进程表: %v", err)
			}
			ioc, err := readIOC(o.ioc)
			if err != nil {
				t.Fatalf("读 IOC: %v", err)
			}
			goFindings, err := runGo(events, proctable, ioc, filepath.Join(work, "go"))
			if err != nil {
				t.Fatalf("Go 引擎: %v", err)
			}

			pyPath := filepath.Join(work, "py_findings.jsonl")
			if err := runPython(o, filepath.Join(work, "pystate"), pyPath); err != nil {
				t.Fatalf("Python 引擎: %v", err)
			}
			pyRows, err := parity.ReadFindingsJSONL(pyPath, true)
			if err != nil {
				t.Fatalf("读 Python 告警: %v", err)
			}

			res := parity.Compare(pyRows, parity.RowsFromGo(goFindings))
			if res.Total == 0 {
				t.Fatalf("事件流没产出告警，对拍无效")
			}
			if !res.Perfect() {
				t.Fatalf("对齐率 %.2f%%（%d/%d）：仅Python %d，仅Go %d，字段不一致 %d\n前几条：%+v",
					res.Rate()*100, res.Matched, res.Total,
					len(res.PyOnly), len(res.GoOnly), len(res.Diffs),
					firstDiffs(res.Diffs, 5))
			}
			t.Logf("真实事件流 %d 条 → 告警 %d 条，逐字段一致（含 subject/reason 顺序）",
				len(events), res.Total)
		})
	}
}

func firstDiffs(d []parity.FieldDiff, n int) []parity.FieldDiff {
	if len(d) <= n {
		return d
	}
	return d[:n]
}
