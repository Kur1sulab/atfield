// Command atfieldd 是心之壁 Go 版的服务入口。
//
// 当前阶段定位：**骨架 + 采集层**。HTTP 控制台、检测引擎、治理层按迁移
// 计划逐步接入；每一步都以「与 Python 版对拍一致」为验收，而不是
// 「能编译就算完」。
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Kur1sulab/atfield/internal/collector"
)

// Version 由构建时 ldflags 注入：
//
//	go build -ldflags "-X main.Version=v1.0.0-go"
var Version = "0.1.0-go"

func main() {
	var (
		once     = flag.Bool("once", false, "跑一轮采集并把事件以 JSON 输出")
		selftest = flag.Bool("selftest", false, "只跑采集器可用性自检")
		asJSON   = flag.Bool("json", true, "JSON 输出（--selftest 时同样适用）")
		allEv    = flag.Bool("all", false, "--once 时输出全部事件而非只给样本（对拍/统计用）")
		showVer  = flag.Bool("version", false, "打印版本")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("atfieldd %s (%s)\n", Version, collector.Platform)
		return
	}

	builders := collector.Registry()
	collectors := make([]collector.Collector, 0, len(builders))
	for _, build := range builders {
		collectors = append(collectors, build(collector.Config{}))
	}

	if *selftest {
		type row struct {
			Name      string `json:"name"`
			Mode      string `json:"mode"`
			Interval  string `json:"interval"`
			Available bool   `json:"available"`
			Reason    string `json:"reason,omitempty"`
		}
		rows := make([]row, 0, len(collectors))
		for _, c := range collectors {
			var reason string
			avail := c.Probe() == nil
			if !avail {
				reason = c.Probe().Error()
			}
			rows = append(rows, row{c.Name(), c.Mode(), c.Interval().String(), avail, reason})
		}
		if *asJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(map[string]any{"platform": collector.Platform, "collectors": rows})
			return
		}
		for _, r := range rows {
			state := "可用"
			if !r.Available {
				state = "不可用：" + r.Reason
			}
			fmt.Printf("%-14s %-7s %-8s %s\n", r.Name, r.Mode, r.Interval, state)
		}
		return
	}

	if *once {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		var all []map[string]any
		for _, c := range collectors {
			t0 := time.Now()
			evs, err := c.Collect(ctx)
			ms := time.Since(t0).Milliseconds()
			entry := map[string]any{
				"collector": c.Name(), "ms": ms, "events": len(evs),
			}
			// 清点条数：persistence 这类「全量清点、少数命中」的采集器，
			// 只报事件数会让人以为只看了几条。
			if ic, ok := c.(interface{ Items() int }); ok {
				entry["items"] = ic.Items()
			}
			if err != nil {
				entry["error"] = err.Error()
			}
			if len(evs) > 0 {
				if *allEv {
					entry["events_list"] = evs
				} else {
					entry["sample"] = evs[:min(3, len(evs))]
				}
			}
			all = append(all, entry)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{"platform": collector.Platform, "version": Version, "runs": all})
		return
	}

	flag.Usage()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
