// Command atfieldd 是心之壁 Go 版的服务入口。
//
// 两种形态：
//
//	atfieldd --serve --addr 127.0.0.1:8866   常驻服务（采集 + 检测 + HTTP 控制台）
//	atfieldd --once [--all]                  一次性采集，把事件打到 stdout（对拍/排障）
//
// 常驻形态的全部装配在 internal/service：main 只负责解析参数、装信号、
// 把退出码翻译给人看。服务内部永远不自动封禁——封禁要么由人从控制台点，
// 要么根本不存在（默认 dry-run，见 service.Options.LiveEnforce）。
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Kur1sulab/atfield/go/internal/collector"
	"github.com/Kur1sulab/atfield/go/internal/service"
)

// Version 由构建时 ldflags 注入：
//
//	go build -ldflags "-X main.Version=v1.0.0-go"
var Version = "0.2.0-go"

func main() {
	var (
		once     = flag.Bool("once", false, "跑一轮采集并把事件以 JSON 输出")
		selftest = flag.Bool("selftest", false, "只跑采集器可用性自检")
		asJSON   = flag.Bool("json", true, "JSON 输出（--selftest 时同样适用）")
		allEv    = flag.Bool("all", false, "--once 时输出全部事件而非只给样本（对拍/统计用）")
		showVer  = flag.Bool("version", false, "打印版本")

		// 常驻服务
		serve       = flag.Bool("serve", false, "常驻服务：采集 + 规则检测 + HTTP 控制台")
		addr        = flag.String("addr", service.DefaultAddr, "监听地址（仅回环；对外开放需 --allow-remote + --token）")
		dataDir     = flag.String("data-dir", "", "数据目录（默认 ~/.atfield-go；与 Python 版 ~/.atfield 隔离，两边落盘 schema 不同）")
		token       = flag.String("token", os.Getenv("ATFIELD_TOKEN"), "访问令牌；设置后 /api/* 需 Bearer 或 atfield_session Cookie")
		allowRemote = flag.Bool("allow-remote", false, "显式允许监听非回环地址（必须同时给 --token）")
		enforceLive = flag.Bool("enforce-live", false, "允许人从控制台下发**真实**防火墙规则（默认 dry-run）")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("atfieldd %s (%s)\n", Version, collector.Platform)
		return
	}

	if *serve && (*once || *selftest) {
		fmt.Fprintln(os.Stderr, "--serve 与 --once/--selftest 互斥：常驻服务请单独用 --serve")
		os.Exit(2)
	}
	if *serve {
		os.Exit(runServe(serveOptions{
			Addr: *addr, DataDir: *dataDir, Token: *token,
			AllowRemote: *allowRemote, LiveEnforce: *enforceLive,
		}))
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

// serveOptions 常驻形态的命令行参数（单独一个结构体是为了让 runServe
// 不用读全局 flag：测试/将来子命令化时能直接构造）。
type serveOptions struct {
	Addr        string
	DataDir     string
	Token       string
	AllowRemote bool
	LiveEnforce bool
}

// runServe 起常驻服务，返回进程退出码。
//
// 信号处理放在这里而不是 service 里：service 只认 context，不知道
// SIGINT/SIGTERM 是什么——这样它才能在测试里被 cancel 掉而不牵扯信号。
func runServe(o serveOptions) int {
	logger := log.New(os.Stderr, "atfieldd ", log.LstdFlags|log.Lmsgprefix)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	svc, err := service.New(service.Options{
		Addr: o.Addr, DataDir: o.DataDir, Version: Version,
		Token: o.Token, AllowRemote: o.AllowRemote, LiveEnforce: o.LiveEnforce,
		Logger: logger,
	})
	if err != nil {
		// 启动失败就是失败：不降级成「只跑采集不提供控制台」，
		// 那种半残状态在生产上比直接退出更难排查。
		logger.Printf("启动失败: %v", err)
		return 1
	}
	if err := svc.Run(ctx); err != nil {
		logger.Printf("运行失败: %v", err)
		return 1
	}
	return 0
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
