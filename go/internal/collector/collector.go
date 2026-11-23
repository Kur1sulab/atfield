// Package collector 定义采集器契约与运行器。
//
// 设计要点（跨平台必须）：采集器按「能不能用」自报，而不是假装成功。
// 一个平台没有 EndpointSecurity、没有 ETW、没有 auditd 都是常态——
// 把不可用原因显式报给控制台，比静默少采一片数据安全得多。
package collector

import (
	"context"
	"time"

	"github.com/Kur1sulab/atfield/internal/model"
)

// 采集模式。
const (
	ModePoll   = "poll"   // 按 Interval 周期拉
	ModeStream = "stream" // 长驻订阅，事件驱动
)

// Collector 所有采集器的契约。
type Collector interface {
	Name() string
	Mode() string
	Interval() time.Duration
	// Probe 做一次可用性自检：返回 nil 表示可用；
	// 返回错误表示不可用，错误文本会原样显示在控制台（如「需要 root」）。
	Probe() error
	Collect(ctx context.Context) ([]model.Event, error)
	Close() error
}

// Status 采集器运行状态（对拍时按字段逐项比对）。
type Status struct {
	Name      string `json:"name"`
	Mode      string `json:"mode"`
	Interval  string `json:"interval"`
	Enabled   bool   `json:"enabled"`
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
	Runs      int64  `json:"runs"`
	Errors    int64  `json:"errors"`
	LastMS    int64  `json:"last_ms"`
	LastError string `json:"last_error,omitempty"`
}

// Base 通用实现，嵌入到具体采集器里即可获得状态管理与默认行为。
type Base struct {
	CollectorName string
	PollMode      string
	PollEvery     time.Duration
	Status        Status

	probeFn func() error
}

// Init 绑定名字/模式/周期并跑一次 Probe。
// 探测失败不等于进程该崩：标记不可用、记原因，其余采集器照跑。
func (b *Base) Init(name, mode string, every time.Duration, probe func() error) {
	b.CollectorName = name
	b.PollMode = mode
	b.PollEvery = every
	b.probeFn = probe
	if b.PollEvery <= 0 {
		b.PollEvery = 5 * time.Second
	}
	b.Status = Status{
		Name: name, Mode: mode, Interval: b.PollEvery.String(),
		Enabled: true, Available: true,
	}
	if err := b.Probe(); err != nil {
		b.Status.Available = false
		b.Status.Enabled = false
		b.Status.Reason = err.Error()
	}
}

// Probe 执行可用性自检（未注入时视为可用）。
func (b *Base) Probe() error {
	if b.probeFn == nil {
		return nil
	}
	return b.probeFn()
}

func (b *Base) Name() string            { return b.CollectorName }
func (b *Base) Mode() string            { return b.PollMode }
func (b *Base) Interval() time.Duration { return b.PollEvery }
func (b *Base) Close() error            { return nil }

// Note 由 RunOnce 调用，记录一次采集结果。失败也记 runs——
// 只统计成功次数会让「一直失败」看起来像「从没跑过」。
func (b *Base) Note(ok bool, ms int64, err error) {
	b.Status.Runs++
	b.Status.LastMS = ms
	if !ok {
		b.Status.Errors++
		if err != nil {
			b.Status.LastError = err.Error()
		}
	}
}

// RunOnce 跑一次采集并归一化事件。采集器内部报错不外抛——
// 一个采集器炸掉不该拖垮整个轮询循环（Python 版同口径）。
func RunOnce(ctx context.Context, c Collector, b *Base) []model.Event {
	t0 := time.Now()
	evs, err := c.Collect(ctx)
	b.Note(err == nil, time.Since(t0).Milliseconds(), err)
	if err != nil {
		return nil
	}
	for i := range evs {
		evs[i].Normalize()
	}
	return evs
}

// Config 采集配置（对应 Python 版 cfg["collectors"][name]）。
type Config struct {
	Enabled  *bool          `json:"enabled,omitempty"`
	Interval time.Duration  `json:"interval,omitempty"`
	Options  map[string]any `json:"options,omitempty"`
}

// WantEnabled 判断某采集器是否被配置启用（缺省启用）。
func (c Config) WantEnabled() bool {
	if c.Enabled == nil {
		return true
	}
	return *c.Enabled
}
