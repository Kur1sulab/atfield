//go:build windows

package collector

// Windows 连接表：`netstat -ano`（首版）。
//
// 为什么先用 netstat：它自带 `-o` 给出 PID，能立刻把「连接」和「进程」对上，
// 不需要任何 syscall 胶水，四条命令就能跑起来；对拍阶段要的是**能出数据**，
// 不是最优实现。
//
// **完整方案是 GetExtendedTcpTable / GetExtendedUdpTable（iphlpapi.dll）**，
// 本版未做。差别很实在，写在这里免得后来人以为 netstat 够用：
//   1. netstat 是枚举 + 文本输出，10k 连接时单次 200–800ms，而且会漏掉短连接
//      （采样窗口内的瞬态连接抓不到）；GetExtendedTcpTable 是一次 ioctl 拿
//      全表，微秒级，且能拿到 create time、module（PID 之外的 owner）。
//   2. netstat 给不了进程**路径**，只能 `tasklist` 二次查名；GetExtendedTcpTable
//      配合 GetExtendedTcpTable 的 owning PID 直接查 process path。
//   3. 非英文 Windows 的 netstat 表头/状态文本随代码页变化，文本解析天然脆；
//      结构化 API 没有这个问题。
// 迁移到 IP Helper 时，只需替换 platformConns 的实现，parse/judgement 不动。
//
// 已知边界：`netstat -ano` 需要能读到全表，普通用户可见（不像 macOS 的 lsof
// 那样按用户裁剪），但 UDP 已连接套接字同样记在表里，状态列为空，按「无对端」
// 处理（不产出事件），与 Python 版 psutil 的输出一致。

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

func platformProbeNet() error {
	if _, err := exec.LookPath("netstat"); err != nil {
		return errors.New("找不到 netstat（System32 自带，缺失说明 PATH 被裁剪）")
	}
	return nil
}

func platformConns(ctx context.Context) ([]netRow, error) {
	out, err := exec.CommandContext(ctx, "netstat", "-ano").Output()
	if err != nil {
		return nil, fmt.Errorf("netstat -ano 执行失败: %w", err)
	}
	rows := parseNetstat(string(out))
	if len(rows) == 0 {
		return rows, nil
	}
	names := windowsPidNames(ctx)
	for i := range rows {
		rows[i].Process = names[rows[i].PID]
		if rows[i].User == "" {
			// netstat 不给用户名；Python 版在 Windows 上从 psutil 拿，
			// 首版留空（对拍时按空串比较，已写进 MIGRATION 的差异清单）。
			rows[i].User = ""
		}
	}
	return rows, nil
}

// windowsPidNames 一次 tasklist 拿 pid→进程名。
// 每轮多一次 fork，但比逐 PID 查便宜得多；拿不到就留空，不影响判定。
func windowsPidNames(ctx context.Context) map[int]string {
	m := map[int]string{}
	out, err := exec.CommandContext(ctx, "tasklist", "/fo", "csv", "/nh").Output()
	if err != nil {
		return m
	}
	r := csv.NewReader(strings.NewReader(string(out)))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	for {
		rec, err := r.Read()
		if err != nil {
			break
		}
		if len(rec) < 2 {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(rec[1]))
		if err != nil {
			continue
		}
		m[pid] = strings.TrimSpace(rec[0])
	}
	return m
}
