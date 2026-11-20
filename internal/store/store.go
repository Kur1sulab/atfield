// Package store 是心之壁的持久层：内存环形缓冲 + append-only JSONL + 不可篡改审计链。
//
// 对标 Python 版 atfield/store.py（384 行）与 atfield/audit.py（368 行），
// 但**不是逐行直译**——Python 版有三处已知缺陷，Go 版按下面口径改掉：
//
//  1. 重启后读不回事件。Python `_load_history()` 只回填 findings/incidents/
//     actions/tickets，events.jsonl 写了却从不读；events.jsonl 还只写 8 个字段
//     （丢了 user/cmdline/raw/eid），读回来也无法还原成 Event。
//     Go 版写完整 Event，并在启动时回填环形缓冲——重启后 `SnapshotEvents`
//     拿到的就是重启前的内容。
//
//  2. 告警计数只在内存里加一。Python 的 `bump_findings` 明确写着「落盘不在每条
//     上做——dedup.json 保存了同一份计数，重启时由 Engine._load_dedup 回填」。
//     这条链断一处就回到 count=1：CLI 单次进程（--monthly / cron 月报）根本没
//     跑过 Engine，dedup.json 也没被加载，于是月报永远是 1 条。
//     Go 版把「并入」写成 findings.jsonl 里的 `{"op":"bump", ...}` 追加记录，
//     存储层自己就能自愈，不依赖上层引擎是否加载过 dedup 状态。
//
//  3. actor 硬编码。Python 侧 15 处调用 `log_action("analyst", ...)`（respond.py
//     7 处、engine.py 2 处、canary.py 2 处、intel.py/ueba.py/inventory.py/
//     playbook.py 各 1 处），导致「谁按下了终止进程」在审计里永远是 analyst，
//     responder/admin 的处置行为无法追责。
//     Go 版 LogAction 的 actor 是必填参数，空值落 `system` 并打 `actor_defaulted`
//     标记——缺陷留在链上可见，绝不编造一个人名把它洗白。
//
// 线程模型：一个 Store 供采集线程、检测线程、HTTP 线程共享。所有写路径持写锁，
// 所有读路径返回**深拷贝**——调用方拿到快照后随便改，不会污染存储也不会与
// 写入方竞争（`go test -race` 钉住了这一条）。
//
// 零第三方依赖：只用标准库。
package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Kur1sulab/atfield/internal/model"
)

// 默认容量。与 Python 版 cfg["store"] 的缺省值一致——
// 对拍时容量不同会改变溢出淘汰点，告警集合就对不上了。
const (
	DefaultMaxEvents    = 20000
	DefaultMaxFindings  = 4000
	DefaultMaxIncidents = 400
	DefaultMaxTickets   = 1000
	// DefaultMaxActions 处置动作内存环。审计权威副本在 actions.jsonl，
	// 内存环只服务于控制台「最近动作」面板——留 2000 条足够，
	// 但也不能太小：一次批量隔离（几十台主机）就会把它冲干净。
	DefaultMaxActions   = 2000
	DefaultPersistMaxMB = 64
)

// 落盘文件名（与 Python 版同名，便于两版共用一个 data_dir 做对拍）。
const (
	FileEvents    = "events.jsonl"
	FileFindings  = "findings.jsonl"
	FileIncidents = "incidents.jsonl"
	FileActions   = "actions.jsonl"
	FileTickets   = "tickets.json"
	dirAudit      = "audit"
)

// Config 存储层配置。
type Config struct {
	// DataDir 落盘目录。为空时退回 ~/.atfield（与 Python 版同）。
	DataDir string
	// MemoryOnly 纯内存模式：不建目录、不落盘、不读历史。
	//
	// 注意这里是「关掉落盘」而不是「打开落盘」：Python 版默认 persist=True，
	// Go 若用 Persist bool，零值就是「不落盘」——调用方少写一个字段，
	// 生产上就静默变成重启全丢。默认值必须朝着安全的方向倒。
	MemoryOnly bool

	MaxEvents    int
	MaxFindings  int
	MaxIncidents int
	MaxTickets   int
	MaxActions   int

	// PersistMaxMB 单文件轮转阈值（MB）。超过后轮转出 <name>.1 … <name>.5。
	PersistMaxMB int
}

// withDefaults 补缺省值。零值 Config 就是「落盘到 ~/.atfield、全部默认容量」。
func (c Config) withDefaults() Config {
	if c.DataDir == "" {
		if home, err := os.UserHomeDir(); err == nil {
			c.DataDir = filepath.Join(home, ".atfield")
		}
	}
	if c.MaxEvents <= 0 {
		c.MaxEvents = DefaultMaxEvents
	}
	if c.MaxFindings <= 0 {
		c.MaxFindings = DefaultMaxFindings
	}
	if c.MaxIncidents <= 0 {
		c.MaxIncidents = DefaultMaxIncidents
	}
	if c.MaxTickets <= 0 {
		c.MaxTickets = DefaultMaxTickets
	}
	if c.MaxActions <= 0 {
		c.MaxActions = DefaultMaxActions
	}
	if c.PersistMaxMB <= 0 {
		c.PersistMaxMB = DefaultPersistMaxMB
	}
	return c
}

// CollectorStat 单个采集器的运行统计（对应 Python meta["collectors"][name]）。
type CollectorStat struct {
	Runs      int64   `json:"runs"`
	Errors    int64   `json:"errors"`
	LastTS    float64 `json:"last_ts,omitempty"`
	LastMS    float64 `json:"last_ms,omitempty"`
	LastError string  `json:"last_error,omitempty"`
	OkSince   float64 `json:"ok_since,omitempty"`
}

// Meta 存储层的累计元信息（态势面板 / 月报直接读它）。
//
// 计数语义要看清：这些是「当前实例知道的条数」，不是「历史上发生过的总数」。
// 重启后从磁盘回填，因此等于**缓冲里保留的条数**（受 Max* 上限约束），
// 而不是建库以来的累计值。Python 版是纯进程内计数，重启直接归零——
// 面板上「今天采集了多少」会莫名其妙变小，比一个诚实的上界更误导。
type Meta struct {
	StartedAt      float64                  `json:"started_at"`
	EventsTotal    int64                    `json:"events_total"`
	FindingsTotal  int64                    `json:"findings_total"`
	IncidentsTotal int64                    `json:"incidents_total"`
	TicketsTotal   int64                    `json:"tickets_total"`
	ActionsTotal   int64                    `json:"actions_total"`
	MergedTotal    int64                    `json:"merged_total"`
	Collectors     map[string]CollectorStat `json:"collectors"`
}

// Store 线程安全的存储层。
type Store struct {
	mu  sync.RWMutex
	cfg Config

	events    ring[model.Event]
	findings  ring[*model.Finding]
	incidents ring[model.Incident]
	tickets   ring[Ticket]
	actions   ring[Action]

	// findIdx fid → 告警指针。存指针而不是下标：环形缓冲淘汰时切片会前移，
	// 下标全部失效；指针在底层数组扩容时也只是被复制，指向的仍是同一对象。
	findIdx map[string]*model.Finding
	// dedupIdx dedup_key → 告警。去重命中是热路径，不能每次线性扫 4000 条。
	dedupIdx map[string]*model.Finding

	state    map[string]any
	counters map[string]int
	meta     Meta

	ticketSeq int

	fEvents    *jsonlFile
	fFindings  *jsonlFile
	fIncidents *jsonlFile
	fActions   *jsonlFile
	ticketsPt  string

	audit *AuditLog

	now    func() time.Time
	closed bool
}

// New 打开（或新建）一个存储实例，并回填磁盘上的历史数据。
//
// 历史数据坏行只跳过不报错：历史不能挡住启动（Python 同口径）。
func New(cfg Config) (*Store, error) {
	cfg = cfg.withDefaults()
	s := &Store{
		cfg:      cfg,
		events:   ring[model.Event]{max: cfg.MaxEvents},
		findings: ring[*model.Finding]{max: cfg.MaxFindings},
		incidents: ring[model.Incident]{
			max: cfg.MaxIncidents,
		},
		tickets:  ring[Ticket]{max: cfg.MaxTickets},
		actions:  ring[Action]{max: cfg.MaxActions},
		findIdx:  map[string]*model.Finding{},
		dedupIdx: map[string]*model.Finding{},
		state:    map[string]any{},
		counters: map[string]int{},
		now:      time.Now,
		meta: Meta{
			StartedAt:  nowTS(),
			Collectors: map[string]CollectorStat{},
		},
	}

	if cfg.MemoryOnly {
		return s, nil
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("store: 创建数据目录 %s: %w", cfg.DataDir, err)
	}
	maxBytes := int64(cfg.PersistMaxMB) * 1024 * 1024
	var err error
	if s.fEvents, err = openJSONL(filepath.Join(cfg.DataDir, FileEvents), maxBytes); err != nil {
		return nil, err
	}
	if s.fFindings, err = openJSONL(filepath.Join(cfg.DataDir, FileFindings), maxBytes); err != nil {
		s.closeFiles()
		return nil, err
	}
	if s.fIncidents, err = openJSONL(filepath.Join(cfg.DataDir, FileIncidents), maxBytes); err != nil {
		s.closeFiles()
		return nil, err
	}
	if s.fActions, err = openJSONL(filepath.Join(cfg.DataDir, FileActions), maxBytes); err != nil {
		s.closeFiles()
		return nil, err
	}
	s.ticketsPt = filepath.Join(cfg.DataDir, FileTickets)
	s.loadHistory()
	return s, nil
}

// AttachAudit 挂上审计链：此后 LogAction 除了写 actions.jsonl，还会往
// 哈希链追加一条不可篡改记录。传 nil 即摘除。可随时调用（内部加锁）。
//
// 所有权：Store **不** 负责关闭 audit。审计链可能被多个 Store（或 CLI 子命令）
// 共用，谁打开谁关闭；Store.Close 只关自己的 JSONL 句柄。
func (s *Store) AttachAudit(a *AuditLog) {
	s.mu.Lock()
	s.audit = a
	s.mu.Unlock()
}

// Audit 返回已挂载的审计链（可能为 nil）。
func (s *Store) Audit() *AuditLog {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.audit
}

// Config 返回生效配置（补过默认值的那份）。
func (s *Store) Config() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

// Close 关闭所有文件句柄。可重复调用。
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.closeFiles()
}

func (s *Store) closeFiles() error {
	var errs []error
	for _, f := range []*jsonlFile{s.fEvents, s.fFindings, s.fIncidents, s.fActions} {
		if f == nil {
			continue
		}
		if err := f.close(); err != nil {
			errs = append(errs, err)
		}
	}
	s.fEvents, s.fFindings, s.fIncidents, s.fActions = nil, nil, nil, nil
	return errors.Join(errs...)
}

// ---------------- 事件 ----------------

// AddEvents 写入一批事件：进环形缓冲、累加计数、落盘。
//
// 落盘写的是**完整** Event JSON（Python 只写 8 个字段且从不读回），
// 这样重启后能原样还原，不丢 user/cmdline/raw/eid。
func (s *Store) AddEvents(evs []model.Event) error {
	if len(evs) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errClosed
	}

	rows := make([][]byte, 0, len(evs))
	for i := range evs {
		ev := cloneEvent(evs[i])
		ev.Normalize()
		s.events.append(ev)
		s.meta.EventsTotal++
		s.counters[ev.Kind]++
		rows = append(rows, mustJSON(ev))
	}
	if s.fEvents != nil {
		// 落盘失败不回滚内存态：内存是权威，磁盘是尽力而为
		// （磁盘满不该让检测停摆）。错误仍然回传给调用方记账。
		return s.fEvents.appendRows(rows)
	}
	return nil
}

// SnapshotEvents 取事件快照（最新在前），可按 kind / 最低严重度 / 关键字过滤。
//
// q 匹配 process/path/cmdline/kind 的拼接串。Python 侧匹配的是 e["text"]，
// Go 模型没有 text 字段——这是有意差异，见包注释。
func (s *Store) SnapshotEvents(limit int, kind, minSev, q string) []model.Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	limit = normLimit(limit, len(s.events.buf))
	thr := model.SeverityRank(minSev)
	ql := lower(q)
	out := make([]model.Event, 0, limit)
	for i := len(s.events.buf) - 1; i >= 0 && len(out) < limit; i-- {
		ev := s.events.buf[i]
		if kind != "" && ev.Kind != kind {
			continue
		}
		if minSev != "" && model.SeverityRank(ev.Severity) < thr {
			continue
		}
		if ql != "" && !containsFold(ev.Process+"\n"+ev.Path+"\n"+ev.Cmdline+"\n"+ev.Kind, ql) {
			continue
		}
		out = append(out, cloneEvent(ev))
	}
	return out
}

// Counters 按 kind 的事件计数快照（返回副本，调用方可随意改）。
func (s *Store) Counters() map[string]int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]int, len(s.counters))
	for k, v := range s.counters {
		out[k] = v
	}
	return out
}

// ---------------- state / meta ----------------

// SetState 写一个跨模块共享状态（采集层的进程表、引擎的抑制表等）。
func (s *Store) SetState(key string, v any) {
	s.mu.Lock()
	s.state[key] = v
	s.mu.Unlock()
}

// State 读共享状态。未设置返回 nil（与 detect.NopStore 行为一致）。
func (s *Store) State(key string) any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state[key]
}

// GetState 带缺省值的读。
func (s *Store) GetState(key string, def any) any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if v, ok := s.state[key]; ok {
		return v
	}
	return def
}

// NoteCollector 记一次采集结果。失败也计 runs——
// 只统计成功次数会让「一直失败」看起来像「从没跑过」。
func (s *Store) NoteCollector(name string, ok bool, ms float64, errText string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.meta.Collectors[name]
	c.Runs++
	c.LastTS = nowTS()
	c.LastMS = round1(ms)
	if ok {
		c.LastError = ""
		c.OkSince = nowTS()
	} else {
		c.Errors++
		c.LastError = truncate(errText, 400)
	}
	s.meta.Collectors[name] = c
}

// Meta 返回元信息快照。
func (s *Store) Meta() Meta {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := s.meta
	m.Collectors = make(map[string]CollectorStat, len(s.meta.Collectors))
	for k, v := range s.meta.Collectors {
		m.Collectors[k] = v
	}
	return m
}

// Len 返回各环当前条数（诊断用）。
func (s *Store) Len() (events, findings, incidents, tickets int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.events.buf), len(s.findings.buf), len(s.incidents.buf), len(s.tickets.buf)
}

// ---------------- 环形缓冲 ----------------

// ring 定长环形缓冲（等价 Python collections.deque(maxlen=N)）。
//
// 只保留**时间正序**的 append + 溢出丢最旧；「最新在前」的对外语义由
// Snapshot 反向遍历实现。这样 append 是 O(1)，不必每次往头部插。
type ring[T any] struct {
	buf []T
	max int
}

// append 追加并返回被淘汰的最旧元素（没有淘汰时 ok=false）。
//
// 返回淘汰项是必须的：调用方靠它维护 fid/dedup_key 索引。不清理的话，
// 索引会一直指着已经被挤出缓冲的对象——GetFinding 能查到早已不存在的告警，
// 而且那张 map 只增不减。
func (r *ring[T]) append(v T) (evicted T, ok bool) {
	if r.max <= 0 {
		return evicted, false
	}
	r.buf = append(r.buf, v)
	if over := len(r.buf) - r.max; over > 0 {
		evicted = r.buf[0]
		ok = true
		// 前移切片丢弃最旧：不搬数据，容量自然复用。
		r.buf = r.buf[over:]
		// 底层数组只增不减时定期压缩，避免长期运行时无限增长。
		if cap(r.buf) > 2*r.max+16 {
			nb := make([]T, len(r.buf))
			copy(nb, r.buf)
			r.buf = nb
		}
	}
	return evicted, ok
}

// removeAt 删除下标 i（保持顺序）。
func (r *ring[T]) removeAt(i int) {
	if i < 0 || i >= len(r.buf) {
		return
	}
	r.buf = append(r.buf[:i], r.buf[i+1:]...)
}

// normLimit 把 limit 归一到 [0, max]。
//
// limit<=0 表示「全要」而不是「不要」：快照接口的调用方经常传 0 表示不限，
// 直接拿它当 make 的 cap 会 panic（负 cap），当循环上界又会返回空列表——
// 两种都不该发生。上限封到缓冲容量，避免调用方传 1e9 时先分配一个巨数组。
func normLimit(limit, max int) int {
	if limit <= 0 || limit > max {
		return max
	}
	return limit
}

// cloneEvent 深拷贝事件。
//
// Subject/Raw 是 map，按值拷贝结构体只会复制 map 头——两个 Event 仍指向
// 同一张表。采集器写完后如果继续复用那块 map（很常见：一次采集循环里
// 反复重置），存储里的事件内容会跟着变；多线程下就是数据竞争。
// 所以入口和出口都克隆。
func cloneEvent(e model.Event) model.Event {
	c := e
	if e.Subject != nil {
		c.Subject = make(map[string]any, len(e.Subject))
		for k, v := range e.Subject {
			c.Subject[k] = v
		}
	}
	if e.Raw != nil {
		c.Raw = make(map[string]any, len(e.Raw))
		for k, v := range e.Raw {
			c.Raw[k] = v
		}
	}
	if e.PID != nil {
		p := *e.PID
		c.PID = &p
	}
	if e.PPID != nil {
		p := *e.PPID
		c.PPID = &p
	}
	return c
}
