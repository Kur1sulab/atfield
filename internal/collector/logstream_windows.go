//go:build windows

package collector

// Windows 实时日志流：**轮询** wevtutil（不是真流）。
//
// 为什么不是真流：Windows 的事件订阅要么走 EvtSubscribe（wevtapi.dll，
// 需要 syscall/cgo），要么走 ETW（需要管理员 + 会话管理）。零第三方依赖
// 且不引 syscall 的前提下，只剩「周期性查最新 N 条」这一条路。
// 这不是偷懒，是平台能力的实话，所以 Probe 的可用性说明里会写
// 「轮询模式，最小延迟 = 轮询间隔」，控制台不会把它当成实时流展示。
//
// 轮询策略：
//   每 2s 查一次 Security 通道最新 30 条（/rd:true 从新到旧）
//   用 EventRecordID 去重，只把新记录喂给签名表
//   首次轮询只建基线（不把历史事件当新事件报）
//
// 通道选择：Security（4624/4625/4672/4688 都在这里）。System 通道的
// 服务安装/驱动加载事件价值也高，但它需要另一次查询，且 4688（进程创建）
// 在默认策略下是关的——先只接 Security，把「看得到的那部分」做准。
//
// 权限：读 Security 通道需要管理员。非管理员时 Probe 明确报错。

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"os/exec"
	"strings"
	"time"
)

func platformLogSourceKind() string { return "wevtutil" }

// winPollInterval 轮询间隔。2s 是「延迟可接受 + wevtutil 冷启动 ~40ms
// 不吃满 CPU」的折中：30 条/2s 的查询在本机实测 ~55ms。
const winPollInterval = 2 * time.Second

func platformProbeLogStream() error {
	if _, err := exec.LookPath("wevtutil.exe"); err != nil {
		return errors.New("缺少 wevtutil.exe，无法读取事件日志")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if _, err := winQueryChannel(ctx, "Security", 1); err != nil {
		return fmt.Errorf("读不到 Security 事件日志（需要管理员权限）: %v", err)
	}
	return nil
}

// winQueryChannel 查某通道最新 n 条（从新到旧）。
func winQueryChannel(ctx context.Context, channel string, n int) (string, error) {
	out, err := runUTF8(ctx, "wevtutil.exe", "qe", channel,
		"/f:text", "/rd:true", fmt.Sprintf("/c:%d", n))
	if err != nil {
		return "", err
	}
	return decodeWinOutput(out), nil
}

// platformLogSource 轮询循环。ctx 取消即返回。
//
// 去重键：事件块内容的 FNV-64。不用 EventRecordID 是因为 /f:text 默认
// 不打印 Record ID（要 /f:xml 才有），而 XML 解析在这里没必要——
// 同一批事件每 2s 重查一次，内容哈希足以判重。代价：完全相同的两条
// 事件（同一秒、同账户、同来源）会被当成一条。对签名匹配来说可接受
// （爆破场景下账户/时间至少有一个不同）。
func platformLogSource(ctx context.Context, predicate string, sink func(string)) error {
	if _, err := exec.LookPath("wevtutil.exe"); err != nil {
		return errors.New("缺少 wevtutil.exe")
	}
	seen := map[uint64]bool{}
	seeded := false

	tick := time.NewTicker(winPollInterval)
	defer tick.Stop()

	poll := func() error {
		text, err := winQueryChannel(ctx, "Security", 30)
		if err != nil {
			return err
		}
		for _, block := range splitEventBlocks(text) {
			h := fnv.New64a()
			_, _ = h.Write([]byte(block))
			key := h.Sum64()
			if seen[key] {
				continue
			}
			seen[key] = true
			if !seeded {
				continue // 首轮只建基线
			}
			sink(block)
		}
		seeded = true
		// 防止 map 无限增长：超过 4096 条就清（只在长跑进程里会到）
		if len(seen) > 4096 {
			seen = map[uint64]bool{}
		}
		return nil
	}

	if err := poll(); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			if err := poll(); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
		}
	}
}

// splitEventBlocks 按 "Event[N]:" 把 wevtutil 输出切块。
// 与 session_parse.go 的 parseWevtutilText 同一分块规则，这里返回原文块
// （logstream 要的是「一行输入」，原文块本身就能被 parseWindowsEventText 吃）。
func splitEventBlocks(text string) []string {
	var blocks []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			blocks = append(blocks, cur.String())
			cur.Reset()
		}
	}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, "\r")
		if winEventHead.MatchString(strings.TrimSpace(line)) {
			flush()
			cur.WriteString(line)
			cur.WriteString("\n")
			continue
		}
		if cur.Len() > 0 {
			cur.WriteString(line)
			cur.WriteString("\n")
		}
	}
	flush()
	return blocks
}
