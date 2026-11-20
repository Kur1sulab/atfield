//go:build windows

package collector

// privileged_windows.go —— Security 事件日志取数（4672 / 4688 / 1102）。
//
// **这不是 ETW，是轮询 wevtutil。** 说清楚：
//
//	真 ETW 要 EvtSubscribe（wevtapi.dll → syscall/cgo）或 TraceEvent 会话，
//	前者要么引 x/sys/windows 的一大票绑定、要么自己写 syscall 桩；
//	后者需要管理员 + 会话管理 + 手动 EnableTraceEx2。本版都不做。
//
// 所以能力边界是硬的：
//
//	4688（进程创建）**默认策略下是关的**。管理员没开「审核进程创建」，
//	     一条也拿不到——Probe 无法区分「策略关闭」和「真的没有进程创建」，
//	     这个已知盲区写进 Limits，不假装能看见。
//	4672（特权分配）默认就开，等同于「管理员等价登录」。
//	1102（日志清空）默认就开，攻击者收尾必踩。
//
// 轮询间隔 3 秒：wevtutil 冷启动 ~40ms、查 40 条 ~60ms（与 logstream 的
// 实测同数量级），3 秒一次对 CPU 无感，对「提权后 3 秒内看到」够用。

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"os/exec"
	"time"
)

// winPrivQuery 一次查询三类事件（XPath 里 or 连接；wevtutil 支持）。
const winPrivQuery = "*[System[(EventID=4672 or EventID=4688 or EventID=1102)]]"

// winPrivPollInterval 轮询周期。
const winPrivPollInterval = 3 * time.Second

// winPrivSeenCap 去重表上限（文本指纹，见 winPrivFingerprint）。
const winPrivSeenCap = 600

func platformPrivLimits() string {
	return "Security 事件日志轮询（wevtutil，非 ETW 实时）；需要管理员；" +
		"4688 依赖「审核进程创建」策略（默认关闭，关闭时只能看到 4672/1102）"
}

func platformProbePrivileged() error {
	if _, err := exec.LookPath("wevtutil.exe"); err != nil {
		return errors.New("缺少 wevtutil.exe，无法读取安全事件日志")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := winQueryChannel(ctx, "Security", 1); err != nil {
		return fmt.Errorf("读不到 Security 事件日志（需要管理员权限运行 atfieldd）: %v", err)
	}
	return nil
}

// platformPrivSource 轮询：每次查最新 N 条，按文本指纹去重后喂给 sink。
//
// 为什么要文本指纹而不是 RecordID：wevtutil /f:text 的输出不含 RecordID
// （/f:xml 才有）。为了不引 XML 解析，这里对「事件正文」做 FNV 指纹——
// 同一秒内出现两条正文完全相同的 4672 几乎不可能，指纹足够当去重键。
func platformPrivSource(ctx context.Context, sink func(privRecord)) error {
	emitted := map[uint64]bool{}
	var order []uint64

	for ctx.Err() == nil {
		ctxQ, cancel := context.WithTimeout(ctx, 12*time.Second)
		out, err := winQueryPriv(ctxQ, 40)
		cancel()
		if err != nil {
			return err
		}
		for _, rec := range parseWinSecurityEvents(out) {
			fp := winRecordFingerprint(rec)
			if emitted[fp] {
				continue
			}
			emitted[fp] = true
			order = append(order, fp)
			if len(order) > winPrivSeenCap {
				delete(emitted, order[0])
				order = order[1:]
			}
			sink(rec)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(winPrivPollInterval):
		}
	}
	return nil
}

// winQueryPriv 查最新的 n 条（含 4672/4688/1102）。
func winQueryPriv(ctx context.Context, n int) (string, error) {
	out, err := runUTF8(ctx, "wevtutil.exe", "qe", "Security",
		"/q:"+winPrivQuery,
		"/f:text", "/rd:true", fmt.Sprintf("/c:%d", n))
	if err != nil {
		return "", fmt.Errorf("查询 Security 事件日志失败: %w", err)
	}
	return decodeWinOutput(out), nil
}

// winRecordFingerprint 事件正文指纹（跨轮去重）：与 parseWinSecurityEvents
// 写进 rec.Raw 的文本同源，所以「同一事件」每轮算出的指纹一致。
func winRecordFingerprint(rec privRecord) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(rec.Raw))
	return h.Sum64()
}
