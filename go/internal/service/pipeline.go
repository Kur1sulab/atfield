package service

// pipeline.go —— 采集循环与「事件 → 告警」管道。
//
// 这条链路的顺序不是随便排的，每一步都有 Python 版的对应物（core.py:287-320）：
//
//	store.add_events(events)
//	findings = engine.observe(events)
//	if findings: store.add_findings(findings)
//	store.bump_findings(engine.take_merges())
//
// 其中「并入」必须晚于「新增」、早于下一批事件入库：并入落到一条还没入库的
// 告警上会被静默跳过，count 永久丢失（store/bridge.go:58 记着这个坑）。
// 所以整段包在 pipeMu 里，绝不允许两个采集器的事件交错进来。

import (
	"context"
	"time"

	"github.com/Kur1sulab/atfield/go/internal/collector"
	"github.com/Kur1sulab/atfield/go/internal/detect"
	"github.com/Kur1sulab/atfield/go/internal/model"
	"github.com/Kur1sulab/atfield/go/internal/store"
)

// stateKeys 采集器名 → store state 键。键名照 Python 的 set_state 调用，
// 控制台的每个面板都按这些键取数（api/overview.go）。
var stateKeys = map[string]string{
	"process":     "processes",
	"network":     "connections",
	"session":     "sessions",
	"persistence": "persistence",
	"integrity":   "integrity",
	"baseline":    "baseline",
	"logstream":   "logstream",
	"privileged":  "privileged",
	"fileless":    "fileless",
	// authlog 没有对应的 state：Python 侧也只产事件、不发布快照，
	// 这里保持一致，不做「Go 多出来的一份状态」。
}

// snapshotter 采集器自报状态（大多数采集器实现的是这个）。
type snapshotter interface{ Snapshot() map[string]any }

// stater baseline 用的是 State()（历史命名，保持不动以免动到已对拍代码）。
type stater interface{ State() map[string]any }

// loop 单个采集器的周期循环。
//
// delay 是错峰量：十个采集器同时起跑会让首屏出现一次 lsof/ps 风暴，
// 错开后总延迟几乎一样，但 CPU 曲线平滑得多。
func (s *Service) loop(ctx context.Context, c collector.Collector, delay time.Duration) {
	if delay > 0 {
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
	for {
		s.cycle(ctx, c)
		iv := c.Interval()
		if iv < time.Second {
			// 采集器自报 0/负数（配置错）时兜底 1s：否则就是死循环打满一个核。
			iv = time.Second
		}
		t := time.NewTimer(iv)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// cycle 跑一轮：采集 → 归一化 → 入库/判定 → 发布状态 → 回写采集器统计。
//
// Collect 的 error 不外抛：一个采集器炸掉不该拖垮整台服务（Python 同口径）。
func (s *Service) cycle(ctx context.Context, c collector.Collector) {
	if !s.available(c) {
		return
	}
	t0 := time.Now()
	evs, err := c.Collect(ctx)
	s.note(c.Name(), time.Since(t0), err)
	if err != nil {
		s.log.Printf("采集器 %s 失败: %v", c.Name(), err)
	}
	for i := range evs {
		evs[i].Normalize()
	}
	if len(evs) > 0 {
		s.ingest(evs)
	}
	s.publishState(c)
	s.flushStatus()
}

// Round 让所有采集器各跑一轮（同步）。首轮预热与测试用：
// 「服务起来了但首屏全是 0」是最常见的误判来源。
func (s *Service) Round(ctx context.Context) {
	for _, c := range s.cols {
		s.cycle(ctx, c)
	}
}

// ingest 事件入库 + 规则判定 + 告警入库 + 并入回写。整段串行（见包注释）。
func (s *Service) ingest(evs []model.Event) {
	s.pipeMu.Lock()
	defer s.pipeMu.Unlock()

	if err := s.st.AddEvents(evs); err != nil {
		s.log.Printf("事件入库失败（%d 条）: %v", len(evs), err)
		// 入库失败仍然继续判定：告警本身有取证价值，落盘问题要单独修，
		// 但不能因此把这一批信号一起丢掉。
	}
	ptrs := make([]*model.Event, len(evs))
	for i := range evs {
		ptrs[i] = &evs[i]
	}
	findings := s.engine.Observe(ptrs)
	if len(findings) > 0 {
		if _, _, err := s.st.AddFindings(findings); err != nil {
			s.log.Printf("告警入库失败（%d 条）: %v", len(findings), err)
		}
	}
	// 并入必须紧接着 observe、且在下一批事件入库之前（bridge.go:58）。
	if merges := s.engine.TakeMerges(); len(merges) > 0 {
		rows := make([]store.Bump, 0, len(merges))
		for _, m := range merges {
			rows = append(rows, store.Bump{
				FID: m.FID, Count: m.Count, LastDetail: m.LastDetail,
				LastTS: m.LastTS, DedupKey: m.DedupKey,
			})
		}
		if _, err := s.st.SaveMerges(rows); err != nil {
			s.log.Printf("告警并入回写失败: %v", err)
		}
	}
}

// publishState 把采集器的自报快照写进 store state。
//
// 缺快照的采集器**不写**空对象：空 map 会让 overview 里 `asInt(procs["count"])`
// 得到 0，看起来像「采到了 0 个进程」；不写这个键时前端显示的是「没有数据」，
// 两种语义必须分开。
func (s *Service) publishState(c collector.Collector) {
	key, ok := stateKeys[c.Name()]
	if !ok {
		return
	}
	var snap map[string]any
	switch v := c.(type) {
	case snapshotter:
		snap = v.Snapshot()
	case stater:
		snap = v.State()
	default:
		return
	}
	if snap == nil {
		return
	}
	s.st.SetState(key, snap)
}

// note 记一次采集结果（累计值）。
//
// ok 时把 lastErr 清掉：否则面板会永远挂着一条早已恢复的历史错误，
// 运维照着它排查会走错方向。okSince 记录「从什么时候开始一直正常」。
func (s *Service) note(name string, d time.Duration, err error) {
	now := float64(s.opts.Now().UnixNano()) / 1e9
	s.stMu.Lock()
	defer s.stMu.Unlock()
	cs := s.stats[name]
	if cs == nil {
		cs = &colStat{}
		s.stats[name] = cs
	}
	cs.runs++
	cs.lastMS = float64(d.Milliseconds())
	cs.lastTS = now
	if err != nil {
		cs.errors++
		cs.lastErr = err.Error()
		cs.okSince = 0
		return
	}
	cs.lastErr = ""
	if cs.okSince == 0 {
		cs.okSince = now
	}
}

// flushStatus 把累计统计写进 store meta（面板/月报读它）。
func (s *Service) flushStatus() {
	s.stMu.Lock()
	rows := make([]store.CollectorStatus, 0, len(s.stats))
	for _, c := range s.cols {
		cs := s.stats[c.Name()]
		if cs == nil {
			continue
		}
		rows = append(rows, store.CollectorStatus{
			Name: c.Name(), Runs: cs.runs, Errors: cs.errors,
			LastTS: cs.lastTS, LastMS: cs.lastMS,
			LastError: cs.lastErr, OkSince: cs.okSince,
		})
	}
	s.stMu.Unlock()
	// 不持锁调 store：SaveCollectorStatus 自己会拿 store 的锁，
	// 两把锁嵌套的次序一旦反过来就是死锁。
	s.st.SaveCollectorStatus(rows)
}

// available 采集器是否可用。不可用的（缺 root / 缺命令）直接跳过，
// 免得每个周期都去 spawn 一个注定失败的子进程。
//
// 探测结果缓存：Probe 可能是秒级操作（privileged 会试跑 eslogger），
// 每个周期都探等于把采集循环变成「反复自检」。环境变化（后来拿到 root）
// 由采集器自己的 Reprobe 处理，服务层不重复探。
func (s *Service) available(c collector.Collector) bool {
	name := c.Name()
	s.availMu.Lock()
	if s.probed[name] {
		ok := s.avail[name]
		s.availMu.Unlock()
		return ok
	}
	s.availMu.Unlock()

	// Probe 放在锁外：privileged 最长 6 秒，拿着锁探会把所有采集器一起卡住。
	err := c.Probe()

	s.availMu.Lock()
	defer s.availMu.Unlock()
	if s.probed[name] { // 并发首轮：以先到者的结论为准
		return s.avail[name]
	}
	s.probed[name] = true
	s.avail[name] = err == nil
	if err != nil {
		s.reason[name] = err.Error()
		s.log.Printf("采集器 %s 不可用，本次运行跳过: %v", name, err)
	}
	return err == nil
}

// detectStore 把 *store.Store 适配成 detect.Store。
//
// 为什么要适配而不让 store 直接实现：两边的方法签名差一个返回值
// （store.LogAction 返回 Action，detect 要求无返回），而且 detect.DedupEntry
// 与 store.DedupState 是两个包各自的类型——让 store 反过来 import detect
// 会把存储层变成非叶子包（bridge.go 顶部解释了为什么不这么做）。
type detectStore struct {
	st  *store.Store
	log interface{ Printf(string, ...any) }
}

func (d detectStore) State(name string) any    { return d.st.State(name) }
func (d detectStore) Counters() map[string]int { return d.st.Counters() }
func (d detectStore) LogAction(actor, action, detail, note string) {
	// store 的字段叫 target/result，语义上是同两个位置：谁被操作、结果如何。
	d.st.LogAction(actor, action, detail, note)
}
func (d detectStore) ReapplyDedup(in map[string]detect.DedupEntry) {
	if len(in) == 0 {
		return
	}
	out := make(map[string]store.DedupState, len(in))
	for k, v := range in {
		out[k] = store.DedupState{
			FID: v.FID, Count: v.Count, FirstTS: v.FirstTS, LastTS: v.LastTS,
			FirstDetail: v.FirstDetail, LastDetail: v.LastDetail, LastEmit: v.LastEmit,
		}
	}
	if _, err := d.st.ReapplyDedup(out); err != nil && d.log != nil {
		d.log.Printf("回填去重状态失败: %v", err)
	}
}
