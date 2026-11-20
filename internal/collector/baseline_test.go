package collector

// baseline_test.go —— 安全基线判定的**双向**测试。
//
// 为什么必须双向（与 process_test.go / network_test.go 同一条纪律）：
// 只测「该报的报」会奖励「全判可疑」的实现——把 17 条判定全改成 fail，
// 正例照样全绿。所以这里的主力用例是 TestBaselineDegradesOneCheckAtATime：
// 在一份「健康机器」的输入上，**每次只把一个检查项推坏**，然后要求
//   1) 目标项确实变成预期的 warn/fail（该报的报）；
//   2) 其余 16 项的判定一字不变（不该报的不报）。
// 第 2 条是防「判定互相串味」的唯一手段：真实事故里最常见的不是漏规则，
// 而是某条规则顺手改了共享状态，导致一片检查跟着变。
//
// 平台无关：判定在 baseline.go（无 build tag），解析在 baseline_parse.go
// （无 build tag），所以这些断言在 darwin / linux / windows 上跑的是同一批。

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// healthyFacts 一台「该开都开、该关都关」的 macOS 机器的输入。
//
// 唯一不是 pass 的是 TCC：Python 版的设计就是「读到授权记录 → warn（让人定期
// 清理）」，没有 pass 分支。所以基线值里 TCC 是 warn/low，其余全 pass。
//
// 这里刻意用真实命令的原文（含句号、括号、大小写），判定改成大小写敏感或
// 把 "FileVault is On." 写成 "FileVault is on" 都会让本用例先红。
func healthyFacts() baselineFacts {
	return baselineFacts{
		SIP:        cmdResult{RC: 0, Text: "System Integrity Protection status: enabled."},
		Gatekeeper: cmdResult{RC: 0, Text: "assessments enabled"},
		FileVault:  cmdResult{RC: 0, Text: "FileVault is On."},
		Firewall:   cmdResult{RC: 0, Text: "Firewall is enabled. (State = 1)"},
		// 注意：socketfilterfw --getstealthmode 实际打印的是 "Firewall stealth
		// mode is on/off"，而 Python 版只认 "enabled"/"disabled" 两个词——
		// 也就是说**隐身模式真的开着时，Python 版也会判 warn**。这是 Python
		// 侧的缺陷，但验收标准是「两版告警一致」，所以这里保持同一口径，
		// 不动单边。夹具用 "enabled" 这种它能识别的写法代表「健康机器」，
		// 真实 "on" 写法的行为另有 TestBaselineStealthOnFormIsPythonParity 钉住。
		// 要修就两版一起修（Python 侧同样加上 "on"/"off"）。
		Stealth:    cmdResult{RC: 0, Text: "Firewall stealth mode is enabled"},
		Ports:      map[int]bool{80: true, 443: true, 8080: true},
		PortsKnown: true,

		AutoUpdate:          cmdResult{RC: 0, Text: "1"},
		AutoLogin:           cmdResult{RC: 1, Text: "The domain/default pair of (com.apple.loginwindow, autoLoginUser) does not exist"},
		Guest:               cmdResult{RC: 0, Text: "0"},
		AskForPassword:      cmdResult{RC: 0, Text: "1"},
		AskForPasswordDelay: cmdResult{RC: 0, Text: "0"},

		XProtect: cmdResult{RC: 0, Text: "package-id: com.apple.pkg.XProtectPlistConfigData\nversion: 5270\nvolume: /\n"},

		EDRPresent: []string{"/Applications/CrowdStrike Falcon.app"},
		EDRKnown:   true,

		ARDKnown: true, ARDExists: false,

		TimeSyncKnown: true, TimeSyncOn: true,
		AuthFails: 0,

		TCCKnown: true, TCCExists: true,
		TCC: cmdResult{RC: 0, Text: "kTCCServiceScreenCapture\tcom.apple.Terminal\t2\n"},
	}
}

// statusMap 把结果折叠成 id → status。
func statusMap(results []baselineCheck) map[string]string {
	m := make(map[string]string, len(results))
	for _, r := range results {
		m[r.ID] = r.Status
	}
	return m
}

func checkByID(t *testing.T, results []baselineCheck, id string) baselineCheck {
	t.Helper()
	for _, r := range results {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("结果里没有 %s", id)
	return baselineCheck{}
}

// TestBaselineSpecsContract 钉死检查表：ID / 中文名 / 分类 / 权重 / 顺序。
//
// 顺序参与对拍（results 数组顺序 → counts → 告警顺序），改名或重排都会让
// 两版对不上，所以用一张硬编码表当契约。
func TestBaselineSpecsContract(t *testing.T) {
	want := []struct {
		id, name, cat string
		weight        int
	}{
		{"SIP", "系统完整性保护 SIP", "系统安全", 12},
		{"GATEKEEPER", "Gatekeeper 应用公证校验", "系统安全", 10},
		{"FILEVAULT", "磁盘加密 FileVault", "数据保护", 12},
		{"FIREWALL", "应用层防火墙", "网络防线", 10},
		{"FW_STEALTH", "防火墙隐身模式", "网络防线", 4},
		{"SSH_EXPOSED", "SSH 远程登录", "暴露面", 8},
		{"SHARING", "文件共享 / 屏幕共享 / RDP", "暴露面", 10},
		{"AUTOUPDATE", "自动检查更新", "补丁管理", 8},
		{"AUTOLOGIN", "自动登录（免密进桌面）", "身份与会话", 10},
		{"GUEST", "访客账户", "身份与会话", 5},
		{"SCREENLOCK", "唤醒需密码", "身份与会话", 8},
		{"XPROTECT", "XProtect 恶意软件特征库", "恶意代码防护", 6},
		{"EDR_AGENT", "第三方 EDR / 安全代理", "恶意代码防护", 6},
		{"ARD", "Apple 远程管理 ARD", "暴露面", 8},
		{"TIMESYNC", "时间同步", "系统安全", 3},
		{"PRIVMON", "提权与认证失败监控", "身份与会话", 5},
		{"TCC", "敏感权限授权（TCC）", "数据保护", 6},
	}
	if len(baselineSpecs) != len(want) {
		t.Fatalf("检查项数量 %d，Python 版是 %d", len(baselineSpecs), len(want))
	}
	for i, w := range want {
		got := baselineSpecs[i]
		if got.ID != w.id || got.Name != w.name || got.Category != w.cat || got.Weight != w.weight {
			t.Fatalf("第 %d 项不符：got %+v want %+v", i+1, got, w)
		}
	}
}

// TestBaselineJSONFields 字段名是 Python 契约的一部分（store.state 原样落盘，
// UI/评分/合规映射都按这些键读），少一个键就等于断了下游。
func TestBaselineJSONFields(t *testing.T) {
	raw, err := json.Marshal(baselineCheck{})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	var got []string
	for k := range m {
		got = append(got, k)
	}
	sort.Strings(got)
	want := []string{"advice", "category", "evidence", "id", "name", "severity", "status", "ts", "weight"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("字段名与 Python dict 不一致:\n got %v\nwant %v", got, want)
	}
}

// TestBaselineHealthyMachineIsQuiet 健康机器上不许有 fail / 额外 warn。
func TestBaselineHealthyMachineIsQuiet(t *testing.T) {
	results := judgeBaseline(healthyFacts(), 1)
	if len(results) != 17 {
		t.Fatalf("期望 17 项，得到 %d", len(results))
	}
	for _, r := range results {
		if r.Status == baselineFail {
			t.Errorf("%s 在健康机器上被判 fail（evidence=%q）", r.ID, r.Evidence)
		}
		if r.Status == baselineUnknown {
			t.Errorf("%s 在健康机器上被判 unknown（evidence=%q）", r.ID, r.Evidence)
		}
	}
	// TCC 是设计上的 warn（读到授权就要提醒清理），其余 16 项必须 pass。
	counts := countStatuses(results)
	if counts[baselinePass] != 16 || counts[baselineWarn] != 1 {
		t.Fatalf("期望 16 pass / 1 warn，得到 %+v", counts)
	}
	if c := checkByID(t, results, "TCC"); c.Severity != "low" {
		t.Fatalf("TCC 应为 low，得到 %q", c.Severity)
	}
	// 所有 pass 项的 severity 必须是 info（Python 的 _check 默认值）。
	for _, r := range results {
		if r.Status == baselinePass && r.Severity != "info" {
			t.Errorf("%s pass 但 severity=%q（Python 恒为 info）", r.ID, r.Severity)
		}
	}
}

// TestBaselineDegradesOneCheckAtATime 双向主用例。
//
// 每一项：把健康输入推坏 → 目标项必须按 Python 的档位变红，其余 16 项必须
// 与健康基线逐字相同。两侧任一不满足都算失败：
//   - 只测「变红」→ 全判 fail 的实现也能过；
//   - 只测「其余不变」→ 什么都不报的实现也能过。
func TestBaselineDegradesOneCheckAtATime(t *testing.T) {
	base := healthyFacts()
	baseStatuses := statusMap(judgeBaseline(base, 1))

	cases := []struct {
		name       string
		id         string
		mutate     func(*baselineFacts)
		wantStatus string
		wantSev    string
		wantEvid   string // 子串；空 = 不检查
	}{
		{
			name: "SIP 关掉", id: "SIP",
			mutate:     func(f *baselineFacts) { f.SIP.Text = "System Integrity Protection status: disabled." },
			wantStatus: baselineFail, wantSev: "high", wantEvid: "disabled",
		},
		{
			name: "Gatekeeper 关掉", id: "GATEKEEPER",
			mutate:     func(f *baselineFacts) { f.Gatekeeper.Text = "assessments disabled" },
			wantStatus: baselineFail, wantSev: "medium", wantEvid: "assessments disabled",
		},
		{
			name: "FileVault 关掉", id: "FILEVAULT",
			mutate:     func(f *baselineFacts) { f.FileVault.Text = "FileVault is Off." },
			wantStatus: baselineFail, wantSev: "high", wantEvid: "FileVault is Off.",
		},
		{
			name: "应用防火墙关掉", id: "FIREWALL",
			mutate:     func(f *baselineFacts) { f.Firewall.Text = "Firewall is disabled. (State = 0)" },
			wantStatus: baselineFail, wantSev: "medium", wantEvid: "disabled",
		},
		{
			name: "隐身模式关掉", id: "FW_STEALTH",
			mutate:     func(f *baselineFacts) { f.Stealth.Text = "Firewall stealth mode is off" },
			wantStatus: baselineWarn, wantSev: "low", wantEvid: "stealth mode is off",
		},
		{
			name: "SSH 对外监听", id: "SSH_EXPOSED",
			mutate:     func(f *baselineFacts) { f.Ports[22] = true },
			wantStatus: baselineWarn, wantSev: "medium", wantEvid: "22/tcp 正在监听",
		},
		{
			name: "SMB 在监听", id: "SHARING",
			mutate:     func(f *baselineFacts) { f.Ports[445] = true },
			wantStatus: baselineFail, wantSev: "high", wantEvid: "445/SMB",
		},
		{
			name: "自动更新关掉", id: "AUTOUPDATE",
			mutate:     func(f *baselineFacts) { f.AutoUpdate.Text = "0" },
			wantStatus: baselineWarn, wantSev: "medium", wantEvid: "AutomaticCheckEnabled=0",
		},
		{
			name: "配了自动登录", id: "AUTOLOGIN",
			mutate:     func(f *baselineFacts) { f.AutoLogin = cmdResult{RC: 0, Text: "alice"} },
			wantStatus: baselineFail, wantSev: "high", wantEvid: "autoLoginUser=alice",
		},
		{
			name: "访客账户开启", id: "GUEST",
			mutate:     func(f *baselineFacts) { f.Guest = cmdResult{RC: 0, Text: "1"} },
			wantStatus: baselineWarn, wantSev: "medium", wantEvid: "GuestEnabled=1",
		},
		{
			name: "唤醒不要密码", id: "SCREENLOCK",
			mutate:     func(f *baselineFacts) { f.AskForPassword = cmdResult{RC: 0, Text: "0"} },
			wantStatus: baselineFail, wantSev: "high", wantEvid: "askForPassword=0",
		},
		{
			name: "锁屏 5 分钟后才要密码", id: "SCREENLOCK",
			mutate: func(f *baselineFacts) {
				f.AskForPassword = cmdResult{RC: 0, Text: "1"}
				f.AskForPasswordDelay = cmdResult{RC: 0, Text: "300"}
			},
			wantStatus: baselineWarn, wantSev: "medium", wantEvid: "300s",
		},
		{
			name: "XProtect 特征库偏旧", id: "XPROTECT",
			mutate: func(f *baselineFacts) {
				f.XProtect = cmdResult{RC: 0, Text: "package-id: x\nversion: 5000\nvolume: /\n"}
			},
			wantStatus: baselineWarn, wantSev: "medium", wantEvid: "XProtect 特征库偏旧: 5000",
		},
		{
			name: "没装 EDR", id: "EDR_AGENT",
			mutate:     func(f *baselineFacts) { f.EDRPresent = nil },
			wantStatus: baselineWarn, wantSev: "low", wantEvid: "未发现常见商用 EDR 代理",
		},
		{
			name: "ARD 放开所有本地用户", id: "ARD",
			mutate:     func(f *baselineFacts) { f.ARDExists, f.ARDAllUsers = true, true },
			wantStatus: baselineFail, wantSev: "high", wantEvid: "ARD 允许任意本地用户被远程控制",
		},
		{
			name: "ARD 只是部署了", id: "ARD",
			mutate:     func(f *baselineFacts) { f.ARDExists, f.ARDAllUsers = true, false },
			wantStatus: baselineWarn, wantSev: "medium", wantEvid: "ARD 已部署",
		},
		{
			name: "时间同步没跑", id: "TIMESYNC",
			mutate:     func(f *baselineFacts) { f.TimeSyncOn = false },
			wantStatus: baselineWarn, wantSev: "low", wantEvid: "未检测到 timed",
		},
		{
			name: "认证失败堆积", id: "PRIVMON",
			mutate:     func(f *baselineFacts) { f.AuthFails = 7 },
			wantStatus: baselineFail, wantSev: "high", wantEvid: "捕获 7 次认证失败",
		},
		{
			name: "认证失败少量", id: "PRIVMON",
			mutate:     func(f *baselineFacts) { f.AuthFails = 2 },
			wantStatus: baselineWarn, wantSev: "low", wantEvid: "捕获 2 次认证失败",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := healthyFacts()
			tc.mutate(&f)
			results := judgeBaseline(f, 1)

			got := checkByID(t, results, tc.id)
			if got.Status != tc.wantStatus {
				t.Fatalf("%s 状态 %q，期望 %q（evidence=%q）", tc.id, got.Status, tc.wantStatus, got.Evidence)
			}
			if got.Severity != tc.wantSev {
				t.Fatalf("%s severity %q，期望 %q", tc.id, got.Severity, tc.wantSev)
			}
			if tc.wantEvid != "" && !strings.Contains(got.Evidence, tc.wantEvid) {
				t.Fatalf("%s evidence %q 不含 %q", tc.id, got.Evidence, tc.wantEvid)
			}

			// 反向断言：其余检查项必须与健康基线逐字相同。
			statuses := statusMap(results)
			for id, want := range baseStatuses {
				if id == tc.id {
					continue
				}
				if statuses[id] != want {
					t.Fatalf("推坏 %s 时 %s 跟着从 %q 变成 %q —— 判定串味了",
						tc.id, id, want, statuses[id])
				}
			}
		})
	}
}

// TestBaselineStealthOnFormIsPythonParity 把 Python 版的一个已知缺陷钉在这里：
// socketfilterfw --getstealthmode 打印 "Firewall stealth mode is on/off"，
// 而 Python 的判定只认 "enabled"/"disabled"，所以「隐身模式开着」也会被判 warn。
//
// 为什么 Go 版跟着错：验收是「同一事件流两版告警逐条一致」。单边修好会制造
// 一条只在 Go 侧消失的告警，对拍立刻不成立。要修必须两版一起改，改完把这个
// 用例一起改掉（它存在的意义就是提醒「这里是有意为之」）。
func TestBaselineStealthOnFormIsPythonParity(t *testing.T) {
	f := healthyFacts()
	f.Stealth = cmdResult{RC: 0, Text: "Firewall stealth mode is on"}
	if c := checkByID(t, judgeBaseline(f, 1), "FW_STEALTH"); c.Status != baselineWarn {
		t.Fatalf("Python 版对这种输出判 warn，Go 侧必须一致，实际 %q", c.Status)
	}
	f.Stealth = cmdResult{RC: 0, Text: "Firewall stealth mode is off"}
	if c := checkByID(t, judgeBaseline(f, 1), "FW_STEALTH"); c.Status != baselineWarn {
		t.Fatalf("关闭隐身模式应 warn，实际 %q", c.Status)
	}
}

// TestBaselineStrictFirstRoundMatchesPython 对拍开关：strictFirstRound 打开时
// 首轮只建基线、一条事件都不出——这才是 Python 的原样语义。
// 两版对拍（同一事件流比告警集合）时应当用这个模式跑。
func TestBaselineStrictFirstRoundMatchesPython(t *testing.T) {
	c := NewBaseline(Config{Options: map[string]any{"first_round_audit": false}}).(*Baseline)
	facts := healthyFacts()
	c.gather = func(context.Context) (baselineFacts, error) { return facts, nil }
	ctx := context.Background()

	evs, err := c.Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 0 {
		t.Fatalf("严格模式首轮必须 0 事件（Python: prev is None → continue），得到 %d", len(evs))
	}
	// 但检查结论照样落进 results（Python 也会 set_state）
	if len(c.Results()) != 17 {
		t.Fatalf("严格模式首轮仍须产出 17 条结论，得到 %d", len(c.Results()))
	}
	facts.Guest = cmdResult{RC: 0, Text: "1"}
	evs, _ = c.Collect(ctx)
	if len(evs) != 1 || evs[0].Path != "GUEST" {
		t.Fatalf("第二轮应报 GUEST 一条，得到 %d 条", len(evs))
	}
}

// TestBaselineFirstRoundAuditOnlyNonPass 默认模式的首轮审计：只报已经
// 不合格/需关注的项，不许给 pass 项发事件（否则一次 --once 就是 17 条噪声）。
func TestBaselineFirstRoundAuditOnlyNonPass(t *testing.T) {
	facts := healthyFacts()
	facts.SIP = cmdResult{RC: 0, Text: "System Integrity Protection status: disabled."}
	b := newBaselineForTest(func(context.Context) (baselineFacts, error) { return facts, nil })
	evs, err := b.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, ev := range evs {
		if ev.Subject["to"] == baselinePass {
			t.Fatalf("首轮给 pass 项发了事件: %+v", ev.Subject)
		}
		ids = append(ids, ev.Path)
	}
	sort.Strings(ids)
	if !reflect.DeepEqual(ids, []string{"SIP", "TCC"}) {
		t.Fatalf("首轮审计应只报 SIP(fail) 与 TCC(warn)，得到 %v", ids)
	}
	for _, ev := range evs {
		if ev.Subject["from"] != baselineUnknown {
			t.Fatalf("首轮事件的 from 必须是 unknown，得到 %v", ev.Subject["from"])
		}
		if ev.Subject["baselined"] != false {
			t.Fatalf("首轮事件必须带 baselined=false")
		}
	}
}

// TestBaselineUnknownWhenDataUnavailable 采不到数据的项必须 unknown，
// 绝不许变成 pass 或 fail。这条错了，Linux/Windows 版会自带一片假告警。
func TestBaselineUnknownWhenDataUnavailable(t *testing.T) {
	f := healthyFacts()
	f.PortsKnown = false // 连接表读不到
	f.SIP = notApplicable("Linux 无 SIP")
	f.ARDKnown = false
	f.TCCKnown = false
	f.TimeSyncKnown = false
	f.EDRKnown = false

	results := judgeBaseline(f, 1)
	for _, id := range []string{"SSH_EXPOSED", "SHARING", "SIP", "ARD", "TCC", "TIMESYNC", "EDR_AGENT"} {
		c := checkByID(t, results, id)
		if c.Status != baselineUnknown {
			t.Fatalf("%s 在数据不可用时应为 unknown，得到 %q（evidence=%q）", id, c.Status, c.Evidence)
		}
		if strings.TrimSpace(c.Evidence) == "" {
			t.Fatalf("%s 置 unknown 但没写原因——控制台看不出是「不适用」还是「漏采」", id)
		}
	}
}

// TestBaselineCountsAndOrder counts 的键与顺序语义（UI/评分的入参）。
func TestBaselineCountsAndOrder(t *testing.T) {
	f := healthyFacts()
	f.SIP.Text = "disabled"
	f.Ports[22] = true
	results := judgeBaseline(f, 1)

	// 顺序必须是 baselineSpecs 的顺序
	for i, sp := range baselineSpecs {
		if results[i].ID != sp.ID {
			t.Fatalf("第 %d 项是 %s，期望 %s", i+1, results[i].ID, sp.ID)
		}
	}
	counts := countStatuses(results)
	if counts[baselineFail] != 1 || counts[baselineWarn] != 2 || counts[baselinePass] != 14 {
		t.Fatalf("计数不符: %+v", counts)
	}
	if len(counts) != 4 {
		t.Fatalf("counts 必须固定四个键（Python 的 counts 字典），得到 %+v", counts)
	}
}

// ---------------------------------------------------------------- 差分

// newBaselineForTest 造一个注入数据源的采集器（不起任何外部命令）。
func newBaselineForTest(gather func(context.Context) (baselineFacts, error)) *Baseline {
	b := &Baseline{prev: map[string]string{}, counts: map[string]int{}}
	b.gather = gather
	b.Init("baseline", ModePoll, time.Second, nil)
	return b
}

// TestBaselineDriftOnlyOnWorsening 差分语义：只有由好转坏才出事件。
//
// Python: `worse[status] <= worse[prev] → continue`。所以
//
//	pass → fail   出
//	pass → unknown 出（unknown 排 1，比 pass 差）
//	warn → pass    不出（好转）
//	fail → warn    不出（好转）
//	pass → pass    不出（持平）
func TestBaselineDriftOnlyOnWorsening(t *testing.T) {
	facts := healthyFacts()
	b := newBaselineForTest(func(context.Context) (baselineFacts, error) { return facts, nil })
	ctx := context.Background()

	// 第 1 轮：健康机器上只有 TCC 是 warn → 首轮审计事件 1 条（baselined=false）
	evs, err := b.Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 || evs[0].Path != "TCC" {
		t.Fatalf("首轮应只有 TCC 一条审计事件，得到 %d 条", len(evs))
	}
	if evs[0].Subject["baselined"] != false {
		t.Fatalf("首轮事件必须标 baselined=false，实际 %v", evs[0].Subject["baselined"])
	}

	// 第 2 轮：状态没变 → 一条都不出
	evs, _ = b.Collect(ctx)
	if len(evs) != 0 {
		t.Fatalf("状态未变不应出事件，得到 %d 条", len(evs))
	}

	// 第 3 轮：SIP 由 pass 变 fail → 出 1 条
	facts.SIP.Text = "System Integrity Protection status: disabled."
	evs, _ = b.Collect(ctx)
	if len(evs) != 1 || evs[0].Path != "SIP" {
		t.Fatalf("SIP 变坏应出 1 条，得到 %d 条", len(evs))
	}
	if _, ok := evs[0].Subject["baselined"]; ok {
		t.Fatalf("非首轮事件不该带 baselined 键")
	}
	if evs[0].Subject["from"] != "pass" || evs[0].Subject["to"] != "fail" {
		t.Fatalf("from/to 不对: %v → %v", evs[0].Subject["from"], evs[0].Subject["to"])
	}
	if evs[0].Severity != "high" {
		t.Fatalf("SIP fail 的 severity 应为 high，得到 %q", evs[0].Severity)
	}

	// 第 4 轮：修好（fail → pass）→ 不出事件（好转不报）
	facts.SIP.Text = "System Integrity Protection status: enabled."
	evs, _ = b.Collect(ctx)
	if len(evs) != 0 {
		t.Fatalf("好转不该出事件，得到 %d 条", len(evs))
	}

	// 第 5 轮：pass → unknown（例如 csrutil 输出变了）→ 出（unknown 比 pass 差）
	facts.SIP.Text = "System Integrity Protection status: unknown."
	evs, _ = b.Collect(ctx)
	if len(evs) != 1 || evs[0].Path != "SIP" || evs[0].Subject["to"] != "unknown" {
		t.Fatalf("pass→unknown 应出 1 条，得到 %d 条", len(evs))
	}
	// unknown 的 severity 是 info（Python 的默认值），事件也必须是 info
	if evs[0].Severity != "info" {
		t.Fatalf("unknown 事件 severity 应为 info，得到 %q", evs[0].Severity)
	}
}

// TestBaselineEventShape 事件字段与 Python 逐字对齐：
// kind/source/process(=name)/path(=id)/subject{check,name,from,to,evidence}。
// 少一个 subject 键，detect 层的 AEG-069 规则（读 name/from/to）就废了。
func TestBaselineEventShape(t *testing.T) {
	facts := healthyFacts()
	b := newBaselineForTest(func(context.Context) (baselineFacts, error) { return facts, nil })
	ctx := context.Background()
	if _, err := b.Collect(ctx); err != nil { // 首轮建基线
		t.Fatal(err)
	}
	facts.Ports[3389] = true
	evs, err := b.Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 {
		t.Fatalf("期望 1 条，得到 %d", len(evs))
	}
	ev := evs[0]
	if ev.Kind != "baseline.drift" || ev.Source != "baseline" {
		t.Fatalf("kind/source 不对: %q/%q", ev.Kind, ev.Source)
	}
	if ev.Process != "文件共享 / 屏幕共享 / RDP" {
		t.Fatalf("process 应为检查项中文名，得到 %q", ev.Process)
	}
	if ev.Path != "SHARING" {
		t.Fatalf("path 应为检查项 ID，得到 %q", ev.Path)
	}
	if ev.Severity != "high" {
		t.Fatalf("severity 应为 high，得到 %q", ev.Severity)
	}
	want := []string{"check", "evidence", "from", "name", "to"} // 已排序
	var got []string
	for k := range ev.Subject {
		got = append(got, k)
	}
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("subject 键不符:\n got %v\nwant %v", got, want)
	}
	if ev.Subject["check"] != "SHARING" || ev.Subject["to"] != "fail" {
		t.Fatalf("subject 内容不对: %+v", ev.Subject)
	}
	if !strings.Contains(ev.Subject["evidence"].(string), "3389/RDP") {
		t.Fatalf("evidence 应带上命中的端口: %q", ev.Subject["evidence"])
	}
}

// TestBaselineAccountsOnlyWorseningOnce 同一次恶化只报一次：
// 连续两轮都是 fail 时第二轮必须静默，否则每 120s 刷一条，告警就没人看了。
func TestBaselineAccountsOnlyWorseningOnce(t *testing.T) {
	facts := healthyFacts()
	b := newBaselineForTest(func(context.Context) (baselineFacts, error) { return facts, nil })
	ctx := context.Background()
	_, _ = b.Collect(ctx)
	facts.Guest = cmdResult{RC: 0, Text: "1"}
	for i := 0; i < 3; i++ {
		evs, err := b.Collect(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 && len(evs) != 1 {
			t.Fatalf("第一次恶化应出 1 条，得到 %d", len(evs))
		}
		if i > 0 && len(evs) != 0 {
			t.Fatalf("第 %d 轮重复告警了（%d 条）", i+1, len(evs))
		}
	}
}

// TestBaselineStateAndCounts 采集后的 State/Results/Items 供 store/UI 读取。
func TestBaselineStateAndCounts(t *testing.T) {
	facts := healthyFacts()
	b := newBaselineForTest(func(context.Context) (baselineFacts, error) { return facts, nil })
	if _, err := b.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := b.State()
	if _, ok := st["results"]; !ok {
		t.Fatal("State 缺 results")
	}
	if _, ok := st["counts"]; !ok {
		t.Fatal("State 缺 counts")
	}
	if _, ok := st["ts"]; !ok {
		t.Fatal("State 缺 ts")
	}
	if b.Items() != 17 {
		t.Fatalf("Items 应为 17，得到 %d", b.Items())
	}
	if c := b.Counts(); len(c) != 4 {
		t.Fatalf("Counts 应有四个键，得到 %+v", c)
	}
}

// TestBaselineAuthFailCounter PRIVMON 的输入来自事件流计数器（Python 读
// store.counters["auth.fail"]）。注入函数必须被真正调用。
func TestBaselineAuthFailCounter(t *testing.T) {
	b := newBaselineForTest(func(context.Context) (baselineFacts, error) { return healthyFacts(), nil })
	b.SetCounters(func(kind string) int {
		if kind == "auth.fail" {
			return 9
		}
		return 0
	})
	_, err := b.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c := checkByID(t, b.Results(), "PRIVMON")
	if c.Status != baselineFail || !strings.Contains(c.Evidence, "9") {
		t.Fatalf("PRIVMON 应读到 9 次失败并判 fail，实际 %q / %q", c.Status, c.Evidence)
	}
}

// ---------------------------------------------------------------- 解析器

func TestParsePkgutilVersion(t *testing.T) {
	cases := []struct {
		name string
		in   string
		ver  string
		ok   bool
	}{
		{"真实输出", "package-id: com.apple.pkg.XProtectPlistConfigData_10_15.16U4463\nversion: 5270\nvolume: /\n", "5270", true},
		{"带小版本", "version: 5270.100.1\n", "5270.100.1", true},
		{"没有收据（macOS 26 的实测输出）", "No receipt for 'com.apple.pkg.XProtectPlistConfigData' found at '/'.\n", "", false},
		{"空输出", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ver, ok := parsePkgutilVersion(tc.in)
			if ok != tc.ok || ver != tc.ver {
				t.Fatalf("got (%q,%v) want (%q,%v)", ver, ok, tc.ver, tc.ok)
			}
		})
	}
}

// TestVersionNum 复刻 Python 的 `int(re.sub(r"\D","",ver)[:6] or 0)`。
// 注意它数的是数字字符前 6 位，不是 semver —— 这是 Python 的原样语义，
// 对拍要的是两边一致。改这里必须两版一起改。
func TestVersionNum(t *testing.T) {
	cases := map[string]int{
		"5270":       5270,
		"5271":       5271,
		"5270.100.1": 527010, // "5270100 1" → 前 6 位 527010
		"16U4463":    164463,
		"5000":       5000,
		"":           0,
		"abc":        0,
	}
	for in, want := range cases {
		if got := versionNum(in); got != want {
			t.Fatalf("versionNum(%q)=%d want %d", in, got, want)
		}
	}
}

// TestNormalizeFirewallText 三平台防火墙输出的归一，正反都测。
func TestNormalizeFirewallText(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"macOS 开", "Firewall is enabled. (State = 1)\n", fwEnabled},
		{"macOS 关", "Firewall is disabled. (State = 0)\n", fwDisabled},
		{"ufw 开", "Status: active\n", fwEnabled},
		{"ufw 关", "Status: inactive\n", fwDisabled}, // inactive 含 active，顺序错了就翻车
		{"firewalld 开", "running\n", fwEnabled},
		{"firewalld 关", "not running\n", fwDisabled},
		{"netsh 全开", "Domain Profile Settings:\nState                                 ON\nPrivate Profile Settings:\nState                                 ON\n", fwEnabled},
		{"netsh 有一路关", "Domain Profile Settings:\nState                                 ON\nPublic Profile Settings:\nState                                 OFF\n", fwDisabled},
		{"读不懂", "some unexpected text", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeFirewallText(tc.in); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestParseBooleanPref(t *testing.T) {
	cases := map[string]string{
		"1": "1", "0": "0", "true": "1", "TRUE": "1", "false": "0",
		"yes": "1", "no": "0", "0x1": "1", "0x0": "0", " 1 \n": "1",
		"maybe": "", "": "",
	}
	for in, want := range cases {
		if got := parseBooleanPref(in); got != want {
			t.Fatalf("parseBooleanPref(%q)=%q want %q", in, got, want)
		}
	}
}

func TestParseRegDword(t *testing.T) {
	txt := "\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Test\\Key\n" +
		"    AutoAdminLogon    REG_SZ    1\n" +
		"    DefaultUserName    REG_SZ    alice\n"
	if v, ok := parseRegDword(txt, "AutoAdminLogon"); !ok || v != "1" {
		t.Fatalf("AutoAdminLogon=%q ok=%v", v, ok)
	}
	if v, ok := parseRegDword(txt, "DefaultUserName"); !ok || v != "alice" {
		t.Fatalf("DefaultUserName=%q ok=%v", v, ok)
	}
	// 反向：不存在的键不许瞎给值
	if v, ok := parseRegDword(txt, "AUOptions"); ok || v != "" {
		t.Fatalf("不存在的键返回了 (%q,%v)", v, ok)
	}
}

func TestParseScreenSaverSecure(t *testing.T) {
	cases := []struct{ active, secure, want string }{
		{"1", "1", "1"},
		{"1", "0", "0"}, // 屏保开着但不要密码
		{"0", "1", "0"}, // 屏保根本没开
		{"", "", "0"},
		{"0x1", "0x1", "1"},
	}
	for _, tc := range cases {
		if got := parseScreenSaverSecure(tc.active, tc.secure); got != tc.want {
			t.Fatalf("(%q,%q)=%q want %q", tc.active, tc.secure, got, tc.want)
		}
	}
}

func TestParseAutologinConf(t *testing.T) {
	on := "[daemon]\n#AutomaticLoginEnable=true\nAutomaticLoginEnable=True\nAutomaticLogin=alice\n"
	if got := parseAutologinConf(on); got != "alice" {
		t.Fatalf("got %q", got)
	}
	// 反向三例：注释掉、开关没开、只有用户名没开开关
	for name, txt := range map[string]string{
		"全注释":    "#AutomaticLoginEnable=true\n#AutomaticLogin=alice\n",
		"开关为假":   "[daemon]\nAutomaticLoginEnable=false\nAutomaticLogin=alice\n",
		"缺开关":    "[daemon]\nAutomaticLogin=alice\n",
		"空文件":    "",
		"没有该段内容": "[daemon]\n",
	} {
		if got := parseAutologinConf(txt); got != "" {
			t.Fatalf("%s 误判为自动登录（%q）", name, got)
		}
	}
}

// TestListenPortSet 端口投影：只认 TCP + LISTEN，UDP/ESTABLISHED 一律不算。
func TestListenPortSet(t *testing.T) {
	rows := []netRow{
		{Proto: "TCP", State: "LISTEN", LPort: 22},
		{Proto: "TCP", State: "LISTEN", LPort: 445},
		{Proto: "TCP", State: "ESTABLISHED", LPort: 5432},
		{Proto: "UDP", State: "", LPort: 5353},
		{Proto: "TCP", State: "LISTEN", LPort: 0},
	}
	got := listenPortSet(rows)
	if len(got) != 2 || !got[22] || !got[445] {
		t.Fatalf("投影结果不对: %+v", got)
	}
	if got[5432] || got[5353] {
		t.Fatalf("把非 LISTEN / UDP 也算进来了: %+v", got)
	}
}

// TestTruncRunes 截断按字符（Python 的 [:200]），中文不许切半个字。
func TestTruncRunes(t *testing.T) {
	s := strings.Repeat("中", 250)
	got := truncRunes(s, 200)
	if len([]rune(got)) != 200 {
		t.Fatalf("截断后 %d 个字符", len([]rune(got)))
	}
	short := "短"
	if truncRunes(short, 200) != short {
		t.Fatal("短串不该被改")
	}
}
