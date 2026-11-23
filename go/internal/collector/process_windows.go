//go:build windows

package collector

// Windows 进程表：tasklist /fo csv /nh。
//
// 已知边界（首版，明确写出来而不是假装完整）：
//   - tasklist 不提供 PPID 与命令行 → 本平台 procInfo.PPID 恒为 0、Args 只有
//     映像名。这两项缺失会削弱「父进程异常」和「命令行含反弹 shell 特征」两类
//     判定。补齐需要走 Get-CimInstance（慢 1-2s）或 syscall 调 NtQueryInformationProcess，
//     留作后续；在此之前 Windows 版的判定强度低于 macOS，控制台会标注。
//   - 映像名不是完整路径，因此「从临时目录启动」「exe 已删除」两类在
//     Windows 首版不可用（Windows 也没有 Unix 的 "(deleted)" 语义）。

import (
	"context"
	"encoding/csv"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

func platformProbeProc() error {
	if _, err := exec.LookPath("tasklist"); err != nil {
		return fmt.Errorf("缺少 tasklist 命令（非 Windows 系统？）")
	}
	return nil
}

// windowsSystemPrefixes 系统目录：这些进程不做命令行特征匹配。
var windowsSystemPrefixes = []string{
	`C:\Windows\`, `C:\Program Files\`, `C:\Program Files (x86)\`,
}

func isSystemExe(path string) bool {
	low := strings.ToLower(path)
	for _, p := range windowsSystemPrefixes {
		if strings.HasPrefix(low, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

func platformProcs(ctx context.Context) ([]procInfo, error) {
	out, err := exec.CommandContext(ctx, "tasklist", "/fo", "csv", "/nh").Output()
	if err != nil {
		return nil, fmt.Errorf("tasklist 执行失败: %w", err)
	}
	return parseTasklist(string(out)), nil
}

// parseTasklist 解析 CSV：`"Image","PID","Session","#","Mem"`。
func parseTasklist(text string) []procInfo {
	var out []procInfo
	r := csv.NewReader(strings.NewReader(text))
	r.FieldsPerRecord = -1
	for {
		rec, err := r.Read()
		if err != nil {
			break
		}
		if len(rec) < 2 {
			continue
		}
		pid, perr := strconv.Atoi(strings.TrimSpace(rec[1]))
		if perr != nil {
			continue
		}
		name := strings.TrimSpace(rec[0])
		out = append(out, procInfo{PID: pid, PPID: 0, User: "", Comm: name, Args: name})
	}
	return out
}
