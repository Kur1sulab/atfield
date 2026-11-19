//go:build linux

package collector

// Linux 进程表：直接读 /proc，不依赖 ps（容器/最小化镜像里常常没有 ps）。
//
// /proc/<pid>/stat 的第 2 列是带括号的进程名，可能含空格与括号，
// 所以不能简单按空格切——必须先找到最后一个 ')'，再切后续字段。

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func platformProbeProc() error {
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		return fmt.Errorf("/proc 不可用（容器未挂载 procfs？）")
	}
	return nil
}

// linuxSystemPrefixes 系统二进制目录：这些进程不做命令行特征匹配。
var linuxSystemPrefixes = []string{
	"/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/libexec/",
	"/bin/", "/sbin/", "/lib/", "/lib64/",
}

func isSystemExe(path string) bool {
	for _, p := range linuxSystemPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func platformProcs(ctx context.Context) ([]procInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("读 /proc 失败: %w", err)
	}
	var out []procInfo
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, perr := strconv.Atoi(e.Name())
		if perr != nil {
			continue // 非数字目录（self、sys 等）
		}
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		default:
		}
		pi, ok := readProc(pid)
		if ok {
			out = append(out, pi)
		}
	}
	return out, nil
}

func readProc(pid int) (procInfo, bool) {
	base := filepath.Join("/proc", strconv.Itoa(pid))
	stat, err := os.ReadFile(filepath.Join(base, "stat"))
	if err != nil {
		return procInfo{}, false // 进程在这一瞬间消失了，正常
	}
	comm, ppid, ok := parseLinuxStat(string(stat))
	if !ok {
		return procInfo{}, false
	}
	args := ""
	if raw, err := os.ReadFile(filepath.Join(base, "cmdline")); err == nil && len(raw) > 0 {
		// cmdline 用 \0 分隔
		parts := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
		args = strings.Join(parts, " ")
	}
	exe := ""
	if link, err := os.Readlink(filepath.Join(base, "exe")); err == nil {
		exe = link
	}
	if exe == "" {
		exe = comm // 无权限读 exe 时退化为进程名
	}
	user := ""
	if uidRaw, err := os.ReadFile(filepath.Join(base, "status")); err == nil {
		for _, line := range strings.Split(string(uidRaw), "\n") {
			if strings.HasPrefix(line, "Uid:") {
				user = strings.TrimSpace(strings.TrimPrefix(line, "Uid:"))
				break
			}
		}
	}
	if args == "" {
		args = exe
	}
	return procInfo{PID: pid, PPID: ppid, User: user, Comm: exe, Args: args}, true
}

// parseLinuxStat 从 stat 行取 (comm, ppid)。
// 形如：`1234 (my proc) S 1 1234 ...` —— comm 可含空格与括号。
func parseLinuxStat(line string) (string, int, bool) {
	open := strings.Index(line, "(")
	closeIdx := strings.LastIndex(line, ")")
	if open < 0 || closeIdx <= open {
		return "", 0, false
	}
	comm := line[open+1 : closeIdx]
	rest := strings.Fields(line[closeIdx+1:])
	// rest[0] 是 state，rest[1] 是 ppid
	if len(rest) < 2 {
		return "", 0, false
	}
	ppid, err := strconv.Atoi(rest[1])
	if err != nil {
		return "", 0, false
	}
	return comm, ppid, true
}
