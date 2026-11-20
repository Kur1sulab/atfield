package parity

import (
	"strings"
	"testing"
)

// baseRow 一份「两侧一致」的基准告警，各用例在它上面改一个字段。
func baseRow() Row {
	return Row{
		RuleID:      "AEG-003",
		Actor:       "pid:200",
		Process:     "bash",
		Path:        "/tmp/x.sh",
		Name:        "可写目录内的可执行文件",
		Severity:    "high",
		Detail:      "执行路径位于临时/共享目录: /tmp/x.sh",
		Advice:      "先取证再清理",
		DedupKey:    "AEG-003|pid:200|bash|/tmp/x.sh",
		Count:       1,
		FirstDetail: "执行路径位于临时/共享目录: /tmp/x.sh",
		LastDetail:  "执行路径位于临时/共享目录: /tmp/x.sh",
		TS:          1700000000.5,
		FirstTS:     1700000000.5,
		LastTS:      1700000000.5,
		EventID:     "e1",
		Tags:        []string{"execution"},
		MITRE:       []string{"T1036", "T1105"},
		Reasons:     []string{"路径在 /tmp", "父进程是 shell", "无签名"},
		Subject: map[string]any{
			"suspicious_path": true,
			"reasons":         []any{"路径在 /tmp", "父进程是 shell", "无签名"},
			"depth":           float64(2),
		},
	}
}

func clone(r Row) Row {
	out := r
	out.Tags = append([]string(nil), r.Tags...)
	out.MITRE = append([]string(nil), r.MITRE...)
	out.Reasons = append([]string(nil), r.Reasons...)
	sub := make(map[string]any, len(r.Subject))
	for k, v := range r.Subject {
		sub[k] = v
	}
	out.Subject = sub
	return out
}

// 完全一致 → 100%，Perfect。
func TestCompareIdentical(t *testing.T) {
	a, b, c := baseRow(), baseRow(), baseRow()
	c.RuleID = "AEG-070"
	c.Actor = "pid:400"
	c.Path = "/usr/local/bin/x"
	c.DedupKey = "AEG-070|pid:400|bash|/usr/local/bin/x"
	c.Detail = "进程隐藏: 400"
	c.FirstDetail, c.LastDetail = c.Detail, c.Detail

	res := Compare([]Row{a, b, c}, []Row{clone(a), clone(b), clone(c)})
	if res.Total != 3 || res.Matched != 3 {
		t.Fatalf("total/matched = %d/%d，期望 3/3", res.Total, res.Matched)
	}
	if res.Rate() != 1.0 || !res.Perfect() {
		t.Fatalf("rate=%.3f perfect=%v，期望 1.0/true", res.Rate(), res.Perfect())
	}
	if len(res.PyOnly)+len(res.GoOnly)+len(res.Diffs) != 0 {
		t.Fatalf("不应有差异: pyOnly=%d goOnly=%d diffs=%d",
			len(res.PyOnly), len(res.GoOnly), len(res.Diffs))
	}
}

// 字段不一致必须被抓到，且两侧原值都留着。
func TestCompareFieldMismatch(t *testing.T) {
	py := baseRow()
	goRow := clone(py)
	goRow.Severity = "medium"
	goRow.Detail = "执行路径位于临时目录: /tmp/x.sh"
	goRow.Count = 2

	res := Compare([]Row{py}, []Row{goRow})
	if res.Total != 1 || res.Matched != 0 || len(res.Diffs) != 1 {
		t.Fatalf("total/matched/diffs = %d/%d/%d，期望 1/0/1", res.Total, res.Matched, len(res.Diffs))
	}
	d := res.Diffs[0]
	got := map[string][2]string{}
	for _, f := range d.Fields {
		got[f.Field] = [2]string{f.Python, f.Go}
	}
	for _, field := range []string{"severity", "detail", "count"} {
		if _, ok := got[field]; !ok {
			t.Fatalf("没抓到 %s 的差异，实际抓到: %v", field, keys(got))
		}
	}
	if got["severity"][0] != "high" || got["severity"][1] != "medium" {
		t.Fatalf("severity 两侧值不对: %v", got["severity"])
	}
	if got["count"] != [2]string{"1", "2"} {
		t.Fatalf("count 两侧值不对: %v", got["count"])
	}
	if res.Perfect() {
		t.Fatalf("有差异时不应 Perfect")
	}
}

// reasons 数组顺序不一致必须单独报出来（这是验收标准里点名的字段）。
func TestCompareReasonsOrder(t *testing.T) {
	py := baseRow()
	goRow := clone(py)
	// 内容相同、顺序不同
	goRow.Reasons = []string{"无签名", "路径在 /tmp", "父进程是 shell"}
	goRow.Subject["reasons"] = []any{"无签名", "路径在 /tmp", "父进程是 shell"}

	res := Compare([]Row{py}, []Row{goRow})
	if len(res.Diffs) != 1 {
		t.Fatalf("顺序不同应产生 1 条字段差异，实际 %d", len(res.Diffs))
	}
	var reasons *Mismatch
	for i := range res.Diffs[0].Fields {
		if res.Diffs[0].Fields[i].Field == "reasons" {
			reasons = &res.Diffs[0].Fields[i]
		}
	}
	if reasons == nil {
		t.Fatalf("没抓到 reasons 顺序差异，实际: %+v", res.Diffs[0].Fields)
	}
	if !strings.Contains(reasons.Python, "路径在 /tmp") || !strings.HasPrefix(reasons.Python, `["路径`) {
		t.Fatalf("Python 侧 reasons 原值不对: %s", reasons.Python)
	}
	if !strings.HasPrefix(reasons.Go, `["无签名"`) {
		t.Fatalf("Go 侧 reasons 原值不对: %s", reasons.Go)
	}
	// 顺序不同但集合相同：集合比较会漏掉，这里必须靠位置比较抓到。
	if res.Matched != 0 {
		t.Fatalf("顺序不同不应算一致")
	}
}

// 仅一侧有的告警，分别进两张表。
func TestCompareOnlyOneSide(t *testing.T) {
	a := baseRow()
	b := clone(a)
	b.RuleID = "AEG-040"
	b.DedupKey = "AEG-040|pid:200|bash|/tmp/x.sh"
	b.Path = "/tmp/x.sh"

	res := Compare([]Row{a, b}, []Row{clone(a)})
	if len(res.PyOnly) != 1 || res.PyOnly[0].RuleID != "AEG-040" {
		t.Fatalf("PyOnly 不对: %+v", res.PyOnly)
	}
	if len(res.GoOnly) != 0 || res.Matched != 1 || res.Total != 2 {
		t.Fatalf("goOnly=%d matched=%d total=%d，期望 0/1/2", len(res.GoOnly), res.Matched, res.Total)
	}

	res2 := Compare([]Row{clone(a)}, []Row{a, b})
	if len(res2.GoOnly) != 1 || res2.GoOnly[0].RuleID != "AEG-040" {
		t.Fatalf("GoOnly 不对: %+v", res2.GoOnly)
	}
}

// 同一个 (rule_id, actor, path) 出现多条时，按出现次序对齐，不能被 map 吃掉。
func TestCompareDuplicateKeys(t *testing.T) {
	first := baseRow()
	first.Count = 1
	second := clone(first)
	second.Count = 2
	second.Detail = "第二次命中"

	py := []Row{first, second}
	goRows := []Row{clone(first), func() Row { r := clone(second); r.Count = 3; return r }()}

	res := Compare(py, goRows)
	if res.Total != 2 || res.Matched != 1 || len(res.Diffs) != 1 {
		t.Fatalf("total/matched/diffs = %d/%d/%d，期望 2/1/1", res.Total, res.Matched, len(res.Diffs))
	}
	if res.Diffs[0].Occurrence != 2 {
		t.Fatalf("差异应落在第 2 条，实际 occurrence=%d", res.Diffs[0].Occurrence)
	}
	if got := res.Diffs[0].Fields[0]; got.Field != "count" || got.Python != "2" || got.Go != "3" {
		t.Fatalf("差异字段不对: %+v", got)
	}

	// 一侧多一条：多出来的进 PyOnly，而不是覆盖前一条
	res2 := Compare(py, []Row{clone(first)})
	if res2.Matched != 1 || len(res2.PyOnly) != 1 || res2.PyOnly[0].Count != 2 {
		t.Fatalf("重复键多出条目的处理不对: matched=%d pyOnly=%+v", res2.Matched, res2.PyOnly)
	}
}

// 对齐率 = 一致/总数（含两侧独有的条目）。
func TestRateMath(t *testing.T) {
	a, b := baseRow(), baseRow()
	c := clone(a)
	c.RuleID = "AEG-050"
	c.DedupKey = "AEG-050|pid:200|bash|/tmp/x.sh"

	res := Compare([]Row{a, b, c}, []Row{clone(a), clone(b)})
	if res.Total != 3 || res.Matched != 2 {
		t.Fatalf("total/matched = %d/%d，期望 3/2", res.Total, res.Matched)
	}
	if got := res.Rate(); got < 0.6666 || got > 0.6667 {
		t.Fatalf("rate = %.4f，期望 0.6667", got)
	}
}

// subject 的 map 键序不影响比较，数组顺序影响。
func TestCanonSubject(t *testing.T) {
	a := map[string]any{"x": float64(1), "y": []any{"b", "a"}}
	b := map[string]any{"y": []any{"b", "a"}, "x": float64(1)}
	if Canon(a) != Canon(b) {
		t.Fatalf("map 键序不该影响: %s vs %s", Canon(a), Canon(b))
	}
	c := map[string]any{"y": []any{"a", "b"}, "x": float64(1)}
	if Canon(a) == Canon(c) {
		t.Fatalf("数组顺序必须影响比较")
	}
}

// 浮点按 1e-6 归一：末位抖动不算不一致，真差异算。
func TestFloatTolerance(t *testing.T) {
	py := baseRow()
	goRow := clone(py)
	goRow.TS = py.TS + 1e-9
	goRow.FirstTS = py.FirstTS + 1e-9
	goRow.LastTS = py.LastTS + 1e-9
	if res := Compare([]Row{py}, []Row{goRow}); !res.Perfect() {
		t.Fatalf("1e-9 的抖动不该算差异: %+v", res.Diffs)
	}

	goRow.TS = py.TS + 0.01
	res := Compare([]Row{py}, []Row{goRow})
	if len(res.Diffs) != 1 || res.Diffs[0].Fields[0].Field != "ts" {
		t.Fatalf("0.01 的差异必须抓到: %+v", res.Diffs)
	}
}

// dedup_key 里 path 带 '|' 时不能被切坏。
func TestSplitDedupKey(t *testing.T) {
	rule, actor, process, path := SplitDedupKey("AEG-003|pid:200|bash|/tmp/a|b.sh")
	if rule != "AEG-003" || actor != "pid:200" || process != "bash" || path != "/tmp/a|b.sh" {
		t.Fatalf("拆解不对: %q %q %q %q", rule, actor, process, path)
	}
	rule, actor, process, path = SplitDedupKey("")
	if rule+actor+process+path != "" {
		t.Fatalf("空键应全空: %q %q %q %q", rule, actor, process, path)
	}
}

// reasons 取值：复数数组优先、单数兼容、顺序原样。
func TestReasonsOf(t *testing.T) {
	if got := ReasonsOf(map[string]any{"reasons": []any{"b", "a"}}); len(got) != 2 || got[0] != "b" {
		t.Fatalf("reasons 数组顺序被改了: %v", got)
	}
	if got := ReasonsOf(map[string]any{"reason": "仅 ps 可见"}); len(got) != 1 || got[0] != "仅 ps 可见" {
		t.Fatalf("单数 reason 兼容失败: %v", got)
	}
	if got := ReasonsOf(map[string]any{"note": "x"}); got != nil {
		t.Fatalf("没有 reasons 时应为 nil: %v", got)
	}
}

func keys(m map[string][2]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
