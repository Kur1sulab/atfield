package parity

import (
	"sort"

	"github.com/Kur1sulab/atfield/go/internal/model"
)

// KindCoverage 一种 kind 在事件流里的条数，以及它一共产出多少条告警（两侧合计）。
type KindCoverage struct {
	Kind     string `json:"kind"`
	Events   int    `json:"events"`
	Findings int    `json:"findings"`
}

// Silent 事件有量、却一条告警都没出的 kind。
//
// 这类 kind 是「对拍看不见的盲区」：两侧都 0 告警，对齐率仍然是 100%，
// 但检测根本没发生。它可能是设计如此（process.exit 这类纯清点事件），
// 也可能是采集器契约不符（Go 采集器一度把可疑进程发成 process.suspicious，
// 而规则只认 process.start）。工具负责把名单摆出来，判断交给人。
func (k KindCoverage) Silent() bool { return k.Events > 0 && k.Findings == 0 }

// Coverage 按 kind 统计事件数与告警数。
//
// 告警按 EventID 归到 kind：两侧读的是同一份归一事件流（eid 相同），
// 一条事件触发的多条告警都会计到它的 kind 上；找不到对应事件的行
// （例如 -py-from 复用了别的流）计入 Kind 为空的分组，不丢。
func Coverage(events []*model.Event, rows []Row) []KindCoverage {
	counts := map[string]*KindCoverage{}
	bump := func(kind string) *KindCoverage {
		c := counts[kind]
		if c == nil {
			c = &KindCoverage{Kind: kind}
			counts[kind] = c
		}
		return c
	}
	kindOf := make(map[string]string, len(events))
	for _, ev := range events {
		if ev == nil {
			continue
		}
		bump(ev.Kind).Events++
		if ev.EID != "" {
			kindOf[ev.EID] = ev.Kind
		}
	}
	for _, r := range rows {
		kind, ok := kindOf[r.EventID]
		if !ok {
			kind = ""
		}
		bump(kind).Findings++
	}
	out := make([]KindCoverage, 0, len(counts))
	for _, c := range counts {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Events != out[j].Events {
			return out[i].Events > out[j].Events
		}
		return out[i].Kind < out[j].Kind
	})
	return out
}
