// Package service 把心之壁的各层接成一台可常驻的真服务：
//
//	采集器（轮询/流式） → store 落盘 → detect 规则引擎 → findings 入库
//	                                              ↓
//	                        api.Handler()（/api/*）+ webui（embed 前端）
//	                                              ↓
//	                        enforcer（只读能力枚举 + 人工确认的封禁入口）
//
// 为什么单独开一个包而不是把逻辑塞进 cmd/atfieldd：
//
//  1. cmd 里测不了。「HTTP 拿到的 overview 是真数据」这条验收只能通过
//     httptest 打真 handler 来断言；写在 main 里就只能靠 fork 子进程 + curl。
//  2. 常驻服务的难点全在生命周期：流式采集器的订阅、首轮采集、周期调度、
//     SIGTERM 之后的收尾顺序。这些放在一起才看得清，散在 main 里会变成
//     一堆「先 sleep 一下」的补丁。
//
// 与 Python 版的关系：Python 是单线程事件循环（core.py 的 cycle()），
// 所以它天然没有并发问题。Go 这边每个采集器一条协程，因此这里显式用
// 一把 pipeMu 把「事件入库 → 规则判定 → 告警入库 → 并入回写」串成临界区
// ——detect.Engine 的内部去重/CD 表没有锁，Engine 的契约就是单写者。
package service

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Kur1sulab/atfield/go/internal/api"
	"github.com/Kur1sulab/atfield/go/internal/collector"
	"github.com/Kur1sulab/atfield/go/internal/detect"
	"github.com/Kur1sulab/atfield/go/internal/enforcer"
	"github.com/Kur1sulab/atfield/go/internal/store"
	"github.com/Kur1sulab/atfield/go/internal/webui"
)

// DefaultAddr 默认监听地址。只绑回环是产品前提：控制台没有独立的
// 传输层防护（明文 HTTP + Cookie），暴露到网络上等于把态势数据公开。
const DefaultAddr = "127.0.0.1:8866"

// DefaultDataDirName Go 版默认数据目录名（~/.atfield-go）。
//
// 为什么不与 Python 版共用 ~/.atfield：两边的 events.jsonl / findings.jsonl
// 字段集不同（Go 的 history.go 写完整 Event，Python 版写的是精简行），
// 同一个文件被两边交替追加之后，双方各自的重放都会读出半截记录——
// 那是不可逆的数据损坏。等两版 schema 真正统一（见 MIGRATION.md）再合并目录。
const DefaultDataDirName = ".atfield-go"

// Options 服务装配参数。零值可用（除了测试想注入的采集器）。
type Options struct {
	// Addr 监听地址，空用 DefaultAddr。
	Addr string
	// DataDir 落盘目录，空用 store 的默认（~/.atfield，与 Python 版同）。
	DataDir string
	// Version 版本号，空用 api.DefaultVersion。
	Version string
	// Token 非空则启用 Bearer/Cookie 令牌鉴权；空 = 开放模式（仅回环允许）。
	Token string
	// AllowRemote 显式允许非回环监听；不与 Token 同时设置时直接拒绝启动。
	AllowRemote bool
	// LiveEnforce 允许真的下发封禁规则。默认 false = dry-run：
	// 服务自己永远不会改系统防火墙，只有人从控制台点「封禁」才会；
	// 而即便点了，dry-run 下也只打印命令。两道闸门都必须由人打开。
	LiveEnforce bool
	// Collectors 采集器集合；nil 时按平台注册表构造。测试注入假采集器用。
	Collectors []collector.Collector
	// Logger 日志出口；nil 用标准库默认（stderr）。
	Logger *log.Logger
	// ShutdownGrace 优雅退出等待上限，空用 8s。
	ShutdownGrace time.Duration
	// Now 时钟注入点（测试用）；nil 用 time.Now。
	Now func() time.Time
}

// Service 一台常驻服务。构造后所有依赖已就绪，Run 只负责生命周期。
type Service struct {
	opts Options
	log  *log.Logger

	st      *store.Store
	audit   *store.AuditLog
	engine  *detect.Engine
	backend enforcer.Backend
	srv     *api.Server

	cols  []collector.Collector
	stats map[string]*colStat
	stMu  sync.Mutex

	// 采集器可用性只在**第一次**用到时 Probe 一次。
	// 为什么必须缓存：privileged.Probe 会真的起一个 eslogger 试跑（最长 6 秒），
	// 不缓存就是「每 1 秒 spawn 一个 eslogger」——比采集本身还费资源，
	// 而且每个周期都会把 collect 协程卡住 6 秒。
	availMu sync.Mutex
	probed  map[string]bool
	avail   map[string]bool
	reason  map[string]string

	// pipeMu 串行化「入库 → 判定 → 告警入库 → 并入」。
	// 见包注释：detect.Engine 的契约是单写者，多采集器并发进管道会踩踏
	// 去重表（map 并发写 = fatal，不是脏读）。
	pipeMu sync.Mutex

	ln       net.Listener
	lnMu     sync.Mutex // 保护 ln：Run 写、Addr 读（测试/运维都要读真实端口）
	httpSrv  *http.Server
	started  float64
	closeOne sync.Once
	closeErr error
}

// colStat 采集器的累计运行统计（写入 store meta 的那一份）。
//
// 为什么服务层自己记而不复用 collector.Base.Status：Base 在接口后面取不到
// （Collector 接口没有暴露它），而 store.SaveCollectorStatus 要的是累计值；
// 用 store.NoteCollector 按次累加会把计数翻倍（bridge.go 里写明了这个坑）。
type colStat struct {
	runs     int64
	errors   int64
	lastMS   float64
	lastTS   float64
	okSince  float64
	lastErr  string
	lastNote time.Time
}

// New 装配服务：store / audit / detect / enforcer / api 一次成型。
//
// 任何一步失败都返回错误而不是降级运行：审计链打不开、存储目录不可写，
// 这些在常驻服务里都是「跑起来也是错的」，早失败比半夜发现没有数据好。
func New(opts Options) (*Service, error) {
	if opts.Addr == "" {
		opts.Addr = DefaultAddr
	}
	if err := checkBind(opts); err != nil {
		return nil, err
	}
	if opts.Version == "" {
		opts.Version = api.DefaultVersion
	}
	if opts.ShutdownGrace <= 0 {
		opts.ShutdownGrace = 8 * time.Second
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	// 数据目录在这里就定下来（而不是留给 store 的零值默认）：
	// 后面的日志、审计子目录、检测引擎状态都按这个路径拼，三处必须一致。
	if opts.DataDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("取用户主目录: %w", err)
		}
		opts.DataDir = filepath.Join(home, DefaultDataDirName)
	}
	logger := opts.Logger
	if logger == nil {
		logger = log.New(os.Stderr, "atfieldd ", log.LstdFlags|log.Lmsgprefix)
	}

	st, err := store.New(store.Config{DataDir: opts.DataDir})
	if err != nil {
		return nil, fmt.Errorf("打开存储: %w", err)
	}

	auditCfg := store.DefaultAuditConfig()
	auditCfg.Dir = filepath.Join(st.Config().DataDir, "audit")
	audit, err := store.OpenAudit(auditCfg)
	if err != nil {
		_ = st.Close()
		return nil, fmt.Errorf("打开审计链: %w", err)
	}
	st.AttachAudit(audit)

	// 引擎与 store 共用同一个 data_dir：Python 版的 dedup.json / suppress.json
	// 就落在 data_dir 根下，分开会让两版读到不同的降噪状态。
	engine := detect.New(
		detect.Config{DataDir: st.Config().DataDir},
		detectStore{st: st, log: logger},
		detect.BuiltinRules(),
	)

	// 封禁后端：默认 dry-run。这里**只构造**，不调用 Block——
	// 服务自己永不自作主张封禁，能力枚举走 GET /api/firewall，
	// 真封禁必须由人带着 CSRF 头 POST /api/firewall/block。
	backend := enforcer.New(enforcer.Options{DryRun: !opts.LiveEnforce})

	cols := opts.Collectors
	if cols == nil {
		builders := collector.Registry()
		cols = make([]collector.Collector, 0, len(builders))
		for _, build := range builders {
			cols = append(cols, build(collector.Config{}))
		}
	}
	// baseline 的「认证失败次数」判据吃的是事件流计数器，注入真 store 的。
	for _, c := range cols {
		if b, ok := c.(interface{ SetCounters(func(string) int) }); ok {
			b.SetCounters(func(kind string) int { return st.Counters()[kind] })
		}
	}

	var auth api.Authorizer
	if opts.Token != "" {
		auth = tokenAuth{token: opts.Token}
	}

	svc := &Service{
		opts:    opts,
		log:     logger,
		st:      st,
		audit:   audit,
		engine:  engine,
		backend: backend,
		cols:    cols,
		stats:   make(map[string]*colStat, len(cols)),
		probed:  make(map[string]bool, len(cols)),
		avail:   make(map[string]bool, len(cols)),
		reason:  make(map[string]string, len(cols)),
		started: float64(opts.Now().UnixNano()) / 1e9,
	}
	for _, c := range cols {
		svc.stats[c.Name()] = &colStat{}
	}

	svc.srv = api.New(api.Config{
		Store:      st,
		Audit:      audit,
		Engine:     engine,
		Web:        webui.Handler(), // embed 前端：单二进制分发的前提
		Enforcer:   backend,
		Auth:       auth,
		Collectors: svc, // 采集器画像来源：/api/overview 的 mode/interval/available
		Version:    opts.Version,
		StartedAt:  svc.started,
		Now:        opts.Now,
	})
	return svc, nil
}

// CollectorInfo 实现 api.CollectorInfoSource：每次调用读当前缓存。
// 未探测过的采集器 Probed=false、Available=true（不预判不可用）。
func (s *Service) CollectorInfo() []api.CollectorInfo {
	s.availMu.Lock()
	defer s.availMu.Unlock()
	out := make([]api.CollectorInfo, 0, len(s.cols))
	for _, c := range s.cols {
		name := c.Name()
		ci := api.CollectorInfo{
			Name: name, Mode: c.Mode(), Interval: c.Interval().String(),
			Probed: s.probed[name],
		}
		if s.probed[name] {
			ci.Available = s.avail[name]
			ci.Reason = s.reason[name]
		} else {
			ci.Available = true // 还没探过，不预判
		}
		out = append(out, ci)
	}
	return out
}

// Handler 暴露 HTTP handler（测试用 httptest 直接打，不必真监听端口）。
func (s *Service) Handler() http.Handler { return s.srv.Handler() }

// Addr 实际监听地址（:0 起服务时用来取真实端口）。
func (s *Service) Addr() string {
	s.lnMu.Lock()
	ln := s.ln
	s.lnMu.Unlock()
	if ln != nil {
		return ln.Addr().String()
	}
	return s.opts.Addr
}

// Store 暴露存储层（排障/测试断言用）。
func (s *Service) Store() *store.Store { return s.st }

// Engine 暴露规则引擎（排障/测试断言用）。
func (s *Service) Engine() *detect.Engine { return s.engine }

// Backend 暴露封禁后端（只读能力枚举；服务内部不会调用它的 Block）。
func (s *Service) Backend() enforcer.Backend { return s.backend }

// Collectors 本服务托管的采集器清单。
func (s *Service) Collectors() []collector.Collector { return s.cols }

// Run 启动服务并阻塞到 ctx 取消（或 HTTP 监听出错）。
//
// 顺序刻意是「先监听 → 再起采集 → 再进循环」：控制台在采集器第一轮还没
// 跑完时就能打开（overview 里各维度为 0 但 HTTP 是通的），比「采集 30 秒
// 后才开始监听」好排查得多。
func (s *Service) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.opts.Addr)
	if err != nil {
		return fmt.Errorf("监听 %s: %w", s.opts.Addr, err)
	}
	s.lnMu.Lock()
	s.ln = ln
	s.lnMu.Unlock()

	// 可取消的派生 ctx：退出时先取消它，采集协程与流式订阅一起收。
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// 流式采集器（logstream / privileged）先起订阅：它们的事件是「填缓冲」，
	// 订阅不先起来，Collect 每轮取到的永远是空。
	for _, c := range s.cols {
		if st, ok := c.(interface{ Start(context.Context) }); ok {
			st.Start(runCtx)
			s.log.Printf("流式采集器已启动: %s（%s）", c.Name(), c.Interval())
		}
	}

	s.httpSrv = &http.Server{
		Handler:           s.srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// 不设 WriteTimeout：SSE（/api/stream）单连接最长 300 秒，
		// 写超时会把长连接按固定时限掐断，前端会当成后端抖动。
	}
	errCh := make(chan error, 1)
	go func() { errCh <- s.httpSrv.Serve(ln) }()
	s.log.Printf("控制台已监听 http://%s（数据目录 %s，鉴权 %s，封禁 %s）",
		ln.Addr(), s.st.Config().DataDir, s.authMode(), s.enforceMode())

	// 采集循环。首轮错开 200ms/采集器：十个采集器同时打 lsof/ps 会让
	// 首屏 CPU 尖峰，错开后总延迟差不多但很平滑。
	var wg sync.WaitGroup
	for i, c := range s.cols {
		wg.Add(1)
		go func(idx int, col collector.Collector) {
			defer wg.Done()
			s.loop(runCtx, col, time.Duration(idx)*200*time.Millisecond)
		}(i, c)
	}

	var runErr error
	select {
	case <-ctx.Done():
		s.log.Printf("收到退出信号，开始收尾：停止采集 → 落盘")
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			runErr = err
			s.log.Printf("HTTP 服务异常退出: %v", err)
		}
	}

	cancel()
	s.shutdownHTTP()
	// 等采集协程退出再关采集器：先关采集器会让正在 Collect 的协程
	// 拿到「closed」错误，日志里会多出一串假故障。
	waitTimeout(&wg, s.opts.ShutdownGrace)
	s.closeCollectors()
	// 计数要在 Close 之前取：Close 之后 store 拒绝一切访问，计数会变成 0，
	// 日志里就会写成「事件 0 条已落盘」——正好违反这条日志想证明的事。
	// 注意用 Meta().EventsTotal 而不是 Counters()：后者是**按 kind 的计数器**
	// （"net.connect": 210 …），没有 "events" 这个键，取出来恒为 0。
	meta := s.st.Meta()
	if err := s.Close(); err != nil && runErr == nil {
		runErr = err
	}
	s.log.Printf("已退出（本次运行：事件 %d 条、告警 %d 条已落盘）", meta.EventsTotal, meta.FindingsTotal)
	return runErr
}

// shutdownHTTP 先停 HTTP：还在跑的 SSE 连接会被切断，但那之前
// 已经发出去的数据是完整的；反过来先停采集会让 overview 在最后几秒里
// 变成一张不动的旧图，看的人以为服务卡死了。
func (s *Service) shutdownHTTP() {
	if s.httpSrv == nil {
		return
	}
	shCtx, cancel := context.WithTimeout(context.Background(), s.opts.ShutdownGrace)
	defer cancel()
	if err := s.httpSrv.Shutdown(shCtx); err != nil {
		s.log.Printf("HTTP 优雅退出超时，强制关闭: %v", err)
		_ = s.httpSrv.Close()
	}
}

// Close 关闭存储与审计（幂等）。落盘在这里发生：store.Close 刷 jsonl。
func (s *Service) Close() error {
	s.closeOne.Do(func() {
		if err := s.st.Close(); err != nil {
			s.closeErr = err
		}
		if err := s.audit.Close(); err != nil && s.closeErr == nil {
			s.closeErr = err
		}
	})
	return s.closeErr
}

func (s *Service) closeCollectors() {
	for _, c := range s.cols {
		if err := c.Close(); err != nil {
			s.log.Printf("关闭采集器 %s: %v", c.Name(), err)
		}
	}
}

func (s *Service) authMode() string {
	if s.opts.Token != "" {
		return "令牌"
	}
	return "开放（仅回环）"
}

func (s *Service) enforceMode() string {
	if s.opts.LiveEnforce {
		return "LIVE（人可下发真规则）"
	}
	return "dry-run（只构造命令，不改系统）"
}

// checkBind 绑定地址的安全闸门。
//
// 为什么把它做成启动期硬错误而不是警告：控制台没有独立传输层防护，
// 一旦监听到公网，任何人打开浏览器就能读到主机全部态势（进程/连接/
// 持久化项）。「先跑起来再说」在这里是不可接受的默认值。
func checkBind(opts Options) error {
	host, _, err := net.SplitHostPort(opts.Addr)
	if err != nil {
		return fmt.Errorf("地址 %q 不合法（要 host:port）: %w", opts.Addr, err)
	}
	if hostIsLoopback(host) {
		return nil
	}
	if !opts.AllowRemote {
		return fmt.Errorf("拒绝监听非回环地址 %q：控制台无传输层加密。确需对外开放请同时加 --allow-remote 与 --token", opts.Addr)
	}
	if opts.Token == "" {
		return fmt.Errorf("监听非回环地址 %q 必须设置 --token（或 ATFIELD_TOKEN），否则等于公开态势数据", opts.Addr)
	}
	return nil
}

func hostIsLoopback(host string) bool {
	if host == "" {
		return false // 空 host = 全网卡绑定，不是回环
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// tokenAuth 最小令牌鉴权。
//
// 为什么不是完整的 users.json + RBAC：Python 的 auth.py 是账号/口令/角色/
// 锁定/首启口令一整套，Go 侧还没迁。这里只做「有没有令牌」一件事，
// 但它把 api.guard 的 401/403 分支真正激活了——未带令牌访问 /api/overview
// 得到的是与 Python 同形的 {"ok":false,"error":"未登录","login_required":true}，
// 而不是开放模式下的一屏数据。
type tokenAuth struct{ token string }

func (a tokenAuth) Session(token string) *api.Session {
	if token == "" {
		return nil
	}
	// 常量时间比较：普通 == 会在第一个不同字节处返回，可被按字节计时爆破。
	if subtle.ConstantTimeCompare([]byte(token), []byte(a.token)) != 1 {
		return nil
	}
	return &api.Session{User: "token", Role: "admin"}
}

func (a tokenAuth) Caps(string) []string { return []string{"read", "triage", "respond", "admin"} }

func (a tokenAuth) Can(role, capability string) bool {
	if role != "admin" {
		return false
	}
	switch capability {
	case "read", "triage", "respond", "admin", "":
		return true
	}
	return false
}

func (a tokenAuth) Enabled() bool { return true }

// waitTimeout 等一组协程退出，最多等 d。超时就不是「优雅」了，
// 记一条日志继续往下走——卡在退出流程里比重启慢更糟。
func waitTimeout(wg *sync.WaitGroup, d time.Duration) {
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
	}
}
