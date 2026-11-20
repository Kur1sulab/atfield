package parity

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// Report 对拍报告的人类可读渲染。
//
// 三张明细表是核心产出：仅 Python 有 / 仅 Go 有 / 字段不一致。
// 迁移缺口由人按这三张表决策，工具不做任何「修正」。
type Report struct {
	Result  Result
	Title   string
	Events  int
	MaxRows int // 每张表最多列多少条，0 = 全列

	// 规则覆盖（rule_id -> 告警条数）。空流不填也能正常出报告。
	PythonRules map[string]int
	GoRules     map[string]int
}

// WriteMarkdown 输出 Markdown 报告（落盘给人看/贴 PR）。
func (r Report) WriteMarkdown(w io.Writer) {
	res := r.Result
	title := r.Title
	if title == "" {
		title = "Python ↔ Go 告警集合对拍"
	}
	fmt.Fprintf(w, "# %s\n\n", title)
	fmt.Fprintf(w, "- 事件流条数：%d\n", r.Events)
	fmt.Fprintf(w, "- Python 告警：%d 条 / Go 告警：%d 条\n", res.PythonRows, res.GoRows)
	fmt.Fprintf(w, "- 对齐槽位：%d；一致：%d；**对齐率 %.2f%%**\n",
		res.Total, res.Matched, res.Rate()*100)
	fmt.Fprintf(w, "- 仅 Python 有：%d；仅 Go 有：%d；字段不一致：%d\n\n",
		len(res.PyOnly), len(res.GoOnly), len(res.Diffs))

	if res.Perfect() {
		fmt.Fprintf(w, "结论：**完全一致**（%d/%d 条逐字段相同，含 reasons 顺序）。\n\n", res.Matched, res.Total)
	} else {
		fmt.Fprintf(w, "结论：**存在迁移缺口**，共 %d 处，明细见下。\n\n",
			len(res.PyOnly)+len(res.GoOnly)+len(res.Diffs))
	}

	// 表一：仅 Python 有
	fmt.Fprintf(w, "## 1. 仅 Python 有（Go 漏报）—— %d 条\n\n", len(res.PyOnly))
	if len(res.PyOnly) == 0 {
		fmt.Fprintf(w, "_无_\n\n")
	} else {
		fmt.Fprintf(w, "| # | rule_id | actor | path | severity | detail |\n|---|---|---|---|---|---|\n")
		for i, row := range limit(res.PyOnly, r.MaxRows) {
			fmt.Fprintf(w, "| %d | %s | %s | %s | %s | %s |\n", i+1,
				md(row.RuleID), md(row.Actor), md(row.Path), md(row.Severity), md(row.Detail))
		}
		fmt.Fprintf(w, "\n")
	}

	// 表二：仅 Go 有
	fmt.Fprintf(w, "## 2. 仅 Go 有（Go 多报/误报）—— %d 条\n\n", len(res.GoOnly))
	if len(res.GoOnly) == 0 {
		fmt.Fprintf(w, "_无_\n\n")
	} else {
		fmt.Fprintf(w, "| # | rule_id | actor | path | severity | detail |\n|---|---|---|---|---|---|\n")
		for i, row := range limit(res.GoOnly, r.MaxRows) {
			fmt.Fprintf(w, "| %d | %s | %s | %s | %s | %s |\n", i+1,
				md(row.RuleID), md(row.Actor), md(row.Path), md(row.Severity), md(row.Detail))
		}
		fmt.Fprintf(w, "\n")
	}

	// 表三：字段不一致
	fmt.Fprintf(w, "## 3. 字段不一致 —— %d 条\n\n", len(res.Diffs))
	if len(res.Diffs) == 0 {
		fmt.Fprintf(w, "_无_\n\n")
	} else {
		fmt.Fprintf(w, "| # | rule_id | actor | path | 字段 | Python | Go |\n|---|---|---|---|---|---|---|\n")
		shown := 0
		for i, d := range res.Diffs {
			if r.MaxRows > 0 && shown >= r.MaxRows {
				break
			}
			for _, f := range d.Fields {
				fmt.Fprintf(w, "| %d | %s | %s | %s | `%s` | %s | %s |\n", i+1,
					md(d.RuleID), md(d.Actor), md(d.Path), f.Field, md(f.Python), md(f.Go))
			}
			shown++
		}
		fmt.Fprintf(w, "\n")
	}

	// 规则覆盖：这次事件流到底压到了哪些规则。覆盖率低的流不能算「对拍通过」，
	// 只能说「压到的这些规则一致」——把话说清楚，别让人误以为 32 条都验过了。
	if len(r.PythonRules)+len(r.GoRules) > 0 {
		ids := make([]string, 0, len(r.PythonRules)+len(r.GoRules))
		seen := map[string]bool{}
		for id := range r.PythonRules {
			seen[id] = true
			ids = append(ids, id)
		}
		for id := range r.GoRules {
			if !seen[id] {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		fmt.Fprintf(w, "## 规则覆盖 —— 命中 %d 条规则\n\n", len(ids))
		fmt.Fprintf(w, "| rule_id | Python | Go |\n|---|---|---|\n")
		for _, id := range ids {
			fmt.Fprintf(w, "| %s | %d | %d |\n", id, r.PythonRules[id], r.GoRules[id])
		}
		fmt.Fprintf(w, "\n")
	}

	// 字段漂移汇总：哪一类字段最容易对不上，一眼看出系统性偏差。
	if len(res.Diffs) > 0 {
		counts := map[string]int{}
		for _, d := range res.Diffs {
			for _, f := range d.Fields {
				counts[f.Field]++
			}
		}
		type kv struct {
			k string
			v int
		}
		list := make([]kv, 0, len(counts))
		for k, v := range counts {
			list = append(list, kv{k, v})
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].v != list[j].v {
				return list[i].v > list[j].v
			}
			return list[i].k < list[j].k
		})
		fmt.Fprintf(w, "## 4. 字段漂移汇总\n\n| 字段 | 出现次数 |\n|---|---|\n")
		for _, it := range list {
			fmt.Fprintf(w, "| `%s` | %d |\n", it.k, it.v)
		}
		fmt.Fprintf(w, "\n")
	}
}

// WriteConsole 终端摘要：先给结论，再给最该看的前几条差异。
func (r Report) WriteConsole(w io.Writer) {
	res := r.Result
	fmt.Fprintf(w, "事件 %d 条 → Python %d 告警 / Go %d 告警\n", r.Events, res.PythonRows, res.GoRows)
	fmt.Fprintf(w, "对齐槽位 %d：一致 %d，仅Python %d，仅Go %d，字段不一致 %d\n",
		res.Total, res.Matched, len(res.PyOnly), len(res.GoOnly), len(res.Diffs))
	fmt.Fprintf(w, "对齐率 %.2f%%\n", res.Rate()*100)

	n := 5
	if r.MaxRows > 0 {
		n = r.MaxRows
	}
	if len(res.PyOnly) > 0 {
		fmt.Fprintf(w, "\n仅 Python 有（前 %d 条）：\n", min(n, len(res.PyOnly)))
		for _, row := range limit(res.PyOnly, n) {
			fmt.Fprintf(w, "  - %s actor=%s path=%s | %s\n", row.RuleID, row.Actor, row.Path, row.Detail)
		}
	}
	if len(res.GoOnly) > 0 {
		fmt.Fprintf(w, "\n仅 Go 有（前 %d 条）：\n", min(n, len(res.GoOnly)))
		for _, row := range limit(res.GoOnly, n) {
			fmt.Fprintf(w, "  - %s actor=%s path=%s | %s\n", row.RuleID, row.Actor, row.Path, row.Detail)
		}
	}
	if len(res.Diffs) > 0 {
		fmt.Fprintf(w, "\n字段不一致（前 %d 条）：\n", min(n, len(res.Diffs)))
		for _, d := range limit2(res.Diffs, n) {
			fmt.Fprintf(w, "  - %s %s\n", d.RuleID, d.Slot)
			for _, f := range d.Fields {
				fmt.Fprintf(w, "      %-12s py=%q go=%q\n", f.Field, trunc(f.Python, 120), trunc(f.Go, 120))
			}
		}
	}
}

func limit(rows []Row, n int) []Row {
	if n <= 0 || n >= len(rows) {
		return rows
	}
	return rows[:n]
}

func limit2(rows []FieldDiff, n int) []FieldDiff {
	if n <= 0 || n >= len(rows) {
		return rows
	}
	return rows[:n]
}

func md(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
