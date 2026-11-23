// Command parity 是 Python 版 ↔ Go 版告警集合的对拍工具。
//
// 迁移的唯一验收标准（MIGRATION.md 第二节）：
//
//	同一份真实事件流喂进去，Python 版告警集合 == Go 版告警集合，
//	字段名、判定顺序、reasons 数组顺序都必须一致。
//
// 这个命令把那条标准变成可执行的检查：
//
//	parity -events fixtures/events.jsonl
//	  1. 逐条喂 Go 检测引擎（internal/detect），产出 go_findings.jsonl
//	  2. 调 Python 适配器（~/aegis/parity_cli.py）喂同一份事件，产出 py_findings.jsonl
//	  3. 按 (rule_id, actor, path) 对齐、逐字段比对（含 reasons 顺序）
//	  4. 打印对齐率 + 三张明细表；100% 一致退出码 0，否则 2
//
// 它**只报告不修正**：任何不一致都是迁移缺口，由人决策。
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Kur1sulab/atfield/go/internal/detect"
	"github.com/Kur1sulab/atfield/go/internal/model"
	"github.com/Kur1sulab/atfield/go/internal/parity"
)

const (
	exitOK       = 0
	exitMismatch = 2
	exitError    = 3
)

// 重放归一计数（只为在输出里如实交代「改了什么」）。
var (
	patchedEID  int
	patchedHost int
)

func main() { os.Exit(run()) }

type options struct {
	events    string
	proctable string
	ioc       string
	out       string
	python    string
	adapter   string
	pyDir     string
	pyFrom    string // 复用已有的 Python 告警 JSONL（不重跑 Python，审查/复现用）
	maxRows   int
	allowZero bool
	keep      bool
	quiet     bool
	timeout   time.Duration
}

func run() int {
	var o options
	home, _ := os.UserHomeDir()
	flag.StringVar(&o.events, "events", filepath.Join("testdata", "parity", "events.jsonl"),
		"事件流 JSONL（每行一个 model.Event）")
	flag.StringVar(&o.proctable, "proctable", filepath.Join("testdata", "parity", "proctable.json"),
		"进程表 JSON（{\"rows\":[{pid,ppid,exe}]}），两侧共用；不存在则视为空表")
	flag.StringVar(&o.ioc, "ioc", "", "明文 IOC 名单 JSON（{\"ips\":[],\"domains\":[]}），两侧共用")
	flag.StringVar(&o.out, "out", filepath.Join("out", "parity"), "产物目录")
	flag.StringVar(&o.python, "python", "python3", "Python 解释器")
	flag.StringVar(&o.adapter, "adapter", "", "Python 适配器路径（默认 <py-dir>/parity_cli.py）")
	flag.StringVar(&o.pyDir, "py-dir", filepath.Join(home, "aegis"), "Python 版仓库根目录")
	flag.StringVar(&o.pyFrom, "py-from", "", "复用已有的 Python 告警 JSONL（不重跑 Python，审查/复现差异用）")
	flag.IntVar(&o.maxRows, "max-rows", 50, "终端/报告里每张表最多列多少条（0=全列）")
	flag.BoolVar(&o.allowZero, "allow-empty", false, "事件流产出 0 条告警时仍返回 0（默认视为无效对拍）")
	flag.BoolVar(&o.keep, "keep", true, "保留中间产物（go/py 告警 JSONL）")
	flag.BoolVar(&o.quiet, "quiet", false, "只打印对齐率")
	flag.DurationVar(&o.timeout, "timeout", 10*time.Minute, "Python 侧超时")
	flag.Parse()

	if o.adapter == "" {
		o.adapter = filepath.Join(o.pyDir, "parity_cli.py")
	}
	if err := os.MkdirAll(o.out, 0o755); err != nil {
		return fail("建产物目录: %v", err)
	}
	work := filepath.Join(o.out, "work")
	if err := os.RemoveAll(work); err != nil {
		return fail("清理工作目录: %v", err)
	}
	if err := os.MkdirAll(work, 0o755); err != nil {
		return fail("建工作目录: %v", err)
	}

	events, err := readEvents(o.events)
	if err != nil {
		return fail("%v", err)
	}
	if len(events) == 0 {
		return fail("事件流为空: %s", o.events)
	}
	// 归一后的事件流落盘：Python 侧必须读**同一份**（补过 eid/host 的）文件，
	// 否则两侧看到的事件不是同一个东西，对拍无从谈起。
	normPath := filepath.Join(work, "events.normalized.jsonl")
	if err := writeEventsJSONL(normPath, events); err != nil {
		return fail("写归一事件流: %v", err)
	}
	o.events = normPath
	if patchedEID > 0 || patchedHost > 0 {
		fmt.Printf("重放归一：%d 条补 eid，%d 条补 host（两侧同源：%s）\n",
			patchedEID, patchedHost, normPath)
	}

	proctable, err := readProctable(o.proctable)
	if err != nil {
		return fail("%v", err)
	}
	ioc, err := readIOC(o.ioc)
	if err != nil {
		return fail("%v", err)
	}

	// ---- Go 侧 ----
	goFindings, err := runGo(events, proctable, ioc, filepath.Join(work, "go"))
	if err != nil {
		return fail("Go 引擎: %v", err)
	}
	goPath := filepath.Join(o.out, "go_findings.jsonl")
	if err := writeJSONL(goPath, goFindings); err != nil {
		return fail("写 %s: %v", goPath, err)
	}

	// ---- Python 侧 ----
	pyPath := filepath.Join(o.out, "py_findings.jsonl")
	if o.pyFrom != "" {
		// 复用已有产物：不重跑 Python，用现成的告警集合比对（审别人的报告、
		// 复现一次具体差异时用；正常对拍不要带这个参数）。
		raw, err := os.ReadFile(o.pyFrom)
		if err != nil {
			return fail("读 -py-from: %v", err)
		}
		if err := os.WriteFile(pyPath, raw, 0o644); err != nil {
			return fail("复制 -py-from: %v", err)
		}
		fmt.Printf("复用 Python 告警：%s（未重跑 Python 引擎）\n", o.pyFrom)
	} else if err := runPython(o, filepath.Join(work, "py"), pyPath); err != nil {
		return fail("%v", err)
	}

	// ---- 对拍 ----
	goRows := parity.RowsFromGo(goFindings)
	pyRows, err := parity.ReadFindingsJSONL(pyPath, true)
	if err != nil {
		return fail("读 Python 告警: %v", err)
	}
	res := parity.Compare(pyRows, goRows)

	// kind 覆盖：对齐率只说明「两侧一致」，不说明「事件被规则看见」。
	// 两侧都 0 告警的 kind 要单独摆出来（详见 parity.Coverage 注释）。
	allRows := make([]parity.Row, 0, len(pyRows)+len(goRows))
	allRows = append(allRows, pyRows...)
	allRows = append(allRows, goRows...)
	cov := parity.Coverage(events, allRows)

	rep := parity.Report{
		Result: res, Events: len(events), MaxRows: o.maxRows,
		PythonRules: countRules(pyRows), GoRules: countRules(goRows),
	}
	if !o.quiet {
		rep.WriteConsole(os.Stdout)
		printCoverage(cov)
	} else {
		fmt.Printf("%.2f%%\n", res.Rate()*100)
	}

	mdPath := filepath.Join(o.out, "report.md")
	jsonPath := filepath.Join(o.out, "report.json")
	if err := writeReport(mdPath, jsonPath, rep); err != nil {
		return fail("写报告: %v", err)
	}
	covPath := filepath.Join(o.out, "coverage.json")
	if raw, err := json.MarshalIndent(cov, "", "  "); err == nil {
		if err := os.WriteFile(covPath, raw, 0o644); err != nil {
			return fail("写 kind 覆盖: %v", err)
		}
	}
	if !o.quiet {
		fmt.Printf("\n产物：\n  %s\n  %s\n  %s\n  %s\n  %s\n",
			mdPath, jsonPath, goPath, pyPath, covPath)
	}

	switch {
	case res.Total == 0 && !o.allowZero:
		fmt.Fprintln(os.Stderr, "事件流没有产出任何告警：对拍无效（用 -allow-empty 放行）")
		return exitError
	case res.Perfect():
		if !o.quiet {
			fmt.Printf("\n对齐率 100%%（%d/%d）—— 两版告警集合完全一致\n", res.Matched, res.Total)
		}
		return exitOK
	default:
		if !o.quiet {
			fmt.Printf("\n对齐率 %.2f%%（%d/%d）—— %d 处缺口，见报告\n",
				res.Rate()*100, res.Matched, res.Total,
				len(res.PyOnly)+len(res.GoOnly)+len(res.Diffs))
		}
		return exitMismatch
	}
}

// countRules 统计每条规则出了多少告警，用来交代「这次事件流压到了哪些规则」。
func countRules(rows []parity.Row) map[string]int {
	out := make(map[string]int, len(rows))
	for _, r := range rows {
		out[r.RuleID]++
	}
	return out
}

func fail(format string, args ...any) int {
	fmt.Fprintf(os.Stderr, "parity: "+format+"\n", args...)
	return exitError
}

// readEvents 逐行解析事件流，行号带进错误信息。
func readEvents(path string) ([]*model.Event, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("读事件流: %w", err)
	}
	defer fh.Close()

	dec := json.NewDecoder(fh)
	var out []*model.Event
	line := 0
	for {
		var ev model.Event
		err := dec.Decode(&ev)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%s:%d 解析失败: %w", path, line+1, err)
		}
		line++
		if ev.Kind == "" {
			return nil, fmt.Errorf("%s:%d 缺 kind 字段", path, line)
		}
		if ev.TS <= 0 {
			// 缺 ts 的事件没法重放：Python 侧会用墙钟补，Go 侧留 0，必然假不一致。
			return nil, fmt.Errorf("%s:%d 缺 ts（事件流必须带时间戳）", path, line)
		}
		// 重放归一：真实落盘的事件流不带 eid/host（Store 会丢掉空字段），
		// 两侧对「缺 eid」的处理不同（Python 生成随机 uuid、Go 留空），
		// 会让 event_id 永远对不上。这里在**喂进去之前**按行号补一个确定性 eid、
		// 给空 host 一个占位值——两侧拿到的是同一份，比较才有意义。
		if ev.EID == "" {
			ev.EID = fmt.Sprintf("ln:%d", line)
			patchedEID++
		}
		if ev.Host == "" {
			ev.Host = replayHost
			patchedHost++
		}
		out = append(out, &ev)
	}
	return out, nil
}

const replayHost = "REPLAY-HOST"

func readProctable(path string) (map[string]any, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("读进程表: %w", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("解析进程表 %s: %w", path, err)
	}
	return m, nil
}

type iocList struct {
	IPS     []string `json:"ips"`
	Domains []string `json:"domains"`
}

func readIOC(path string) (iocList, error) {
	var out iocList
	if path == "" {
		return out, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return out, fmt.Errorf("读 IOC 名单: %w", err)
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, fmt.Errorf("解析 IOC 名单 %s: %w", path, err)
	}
	return out, nil
}

// fixtureStore 把进程表当成唯一状态喂给引擎；其余状态为空，
// 保证两侧看到的是同一份、且不读本机 ~/.atfield 的历史状态。
type fixtureStore struct{ states map[string]any }

func (s *fixtureStore) State(name string) any                     { return s.states[name] }
func (s *fixtureStore) Counters() map[string]int                  { return map[string]int{} }
func (s *fixtureStore) LogAction(_, _, _, _ string)               {}
func (s *fixtureStore) ReapplyDedup(map[string]detect.DedupEntry) {}

// runGo 逐条喂事件。一条事件一次 Observe：Python 侧 observe() 在函数入口
// 取一次 now，Go 侧在 Admit 里取；按条喂 + 时钟对齐到事件 ts，
// 两侧的冷却/频率窗口才算同一把尺子。
func runGo(events []*model.Event, proctable map[string]any, ioc iocList, dataDir string) ([]*model.Finding, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	st := &fixtureStore{states: map[string]any{}}
	if proctable != nil {
		st.states["processes"] = proctable
	}
	e := detect.New(detect.Config{
		DataDir:    dataDir,
		IOCIPS:     ioc.IPS,
		IOCDomains: ioc.Domains,
	}, st, detect.BuiltinRules())

	clock := 0.0
	e.Now = func() float64 { return clock }

	out := make([]*model.Finding, 0, 64)
	for _, ev := range events {
		if ev.TS > 0 {
			clock = ev.TS
		}
		out = append(out, e.Observe([]*model.Event{ev})...)
	}
	return out, nil
}

func runPython(o options, dataDir, outPath string) error {
	if _, err := os.Stat(o.adapter); err != nil {
		return fmt.Errorf("找不到 Python 适配器 %s（用 -adapter 指定）: %w", o.adapter, err)
	}
	args := []string{
		o.adapter,
		"--events", abs(o.events),
		"--out", abs(outPath),
		"--data-dir", abs(dataDir),
		"--py-dir", abs(o.pyDir),
	}
	if o.proctable != "" {
		if _, err := os.Stat(o.proctable); err == nil {
			args = append(args, "--proctable", abs(o.proctable))
		}
	}
	if o.ioc != "" {
		args = append(args, "--ioc", abs(o.ioc))
	}
	cmd := exec.Command(o.python, args...)
	cmd.Env = append(os.Environ(), "PYTHONPATH="+abs(o.pyDir))
	var stderr strings.Builder
	cmd.Stderr = &stderr
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动 Python 适配器: %w", err)
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("Python 适配器失败: %v\n%s", err, tail(stderr.String(), 4000))
		}
	case <-time.After(o.timeout):
		_ = cmd.Process.Kill()
		return fmt.Errorf("Python 适配器超时（%s）\n%s", o.timeout, tail(stderr.String(), 2000))
	}
	return nil
}

// writeEventsJSONL 把归一后的事件流落盘，供 Python 侧读同一份。
func writeEventsJSONL(path string, events []*model.Event) error {
	fh, err := os.Create(path)
	if err != nil {
		return err
	}
	defer fh.Close()
	enc := json.NewEncoder(fh)
	enc.SetEscapeHTML(false)
	for _, ev := range events {
		if err := enc.Encode(ev); err != nil {
			return err
		}
	}
	return nil
}

func writeJSONL(path string, findings []*model.Finding) error {
	fh, err := os.Create(path)
	if err != nil {
		return err
	}
	defer fh.Close()
	enc := json.NewEncoder(fh)
	enc.SetEscapeHTML(false)
	for _, f := range findings {
		if err := enc.Encode(f); err != nil {
			return err
		}
	}
	return nil
}

func writeReport(mdPath, jsonPath string, rep parity.Report) error {
	if fh, err := os.Create(mdPath); err == nil {
		rep.WriteMarkdown(fh)
		_ = fh.Close()
	} else {
		return err
	}
	raw, err := json.MarshalIndent(rep.Result, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(jsonPath, raw, 0o644)
}

func abs(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}

// printCoverage 打印 kind 覆盖。
//
// 为什么要单独打印：对齐率 100% 只说明「两侧看到的是同一批告警」，
// 不说明「这批事件被任何规则看过」。真实流里出现过 process.suspicious /
// persistence.suspicious 这种没有任何规则消费的 kind——两侧都 0 告警，
// 对齐率满分，检测却完全没发生。把「事件有量、告警为 0」的 kind 点名，
// 才能把采集器契约问题从「完美对齐」里挖出来。
func printCoverage(cov []parity.KindCoverage) {
	kinds, events := len(cov), 0
	silent := make([]parity.KindCoverage, 0, len(cov))
	for _, c := range cov {
		events += c.Events
		if c.Silent() {
			silent = append(silent, c)
		}
	}
	fmt.Printf("\nkind 覆盖：%d 种 kind / %d 条事件；其中 %d 种事件有量但两侧 0 告警\n",
		kinds, events, len(silent))
	if len(silent) == 0 {
		return
	}
	for i, c := range silent {
		if i >= 10 {
			fmt.Printf("  … 另有 %d 种\n", len(silent)-10)
			break
		}
		fmt.Printf("  %-24s %6d 条事件  0 告警\n", c.Kind, c.Events)
	}
	fmt.Println("  （0 告警未必是缺陷：先对照采集器契约，确认这些 kind 是否在规则消费范围内）")
}
