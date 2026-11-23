//go:build darwin

package collector

// macOS 进程表：ps -ww -axo pid=,ppid=,user=,command=
//
// 为什么不用 comm=：ps 的 comm 列有宽度限制，实测把
// /System/Library/.../com.apple.CloudDocs.iCloudDriveFileProvider 截成
// "/System/Library/"，连可执行文件名都丢了。改用 command=（完整命令行，
// 配 -ww 禁止折行），可执行文件路径从命令行第一段提取。
//
// macOS 26+ 的 netstat 已不再输出常规 TCP/UDP 表，但 ps 仍可用；
// 这里只依赖 ps，不引入 cgo，交叉编译与静态链接都不受影响。
import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// darwinSystemPrefixes 系统二进制所在目录：这些进程命令行里的 base64
// 属于系统正常行为（LaunchArguments/XPC 参数），不做特征匹配。
var darwinSystemPrefixes = []string{
	"/System/", "/usr/libexec/", "/usr/sbin/", "/usr/bin/",
	"/sbin/", "/bin/", "/Library/Apple/",
}

func isSystemExe(path string) bool {
	for _, p := range darwinSystemPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func platformProbeProc() error {
	if _, err := exec.LookPath("ps"); err != nil {
		return fmt.Errorf("缺少 ps 命令，无法采集进程表")
	}
	return nil
}

func platformProcs(ctx context.Context) ([]procInfo, error) {
	out, err := exec.CommandContext(ctx, "ps", "-ww", "-axo", "pid=,ppid=,user=,command=").Output()
	if err != nil {
		return nil, fmt.Errorf("ps 执行失败: %w", err)
	}
	return parsePS(string(out)), nil
}

// parsePS 解析 ps 输出：PID PPID USER COMMAND...
// 前三列定长切分，剩余全部归 command（命令行含空格是常态）。
func parsePS(text string) []procInfo {
	var out []procInfo
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		pid, err1 := strconv.Atoi(fields[0])
		ppid, err2 := strconv.Atoi(fields[1])
		if err1 != nil || err2 != nil {
			continue
		}
		cmd := strings.Join(fields[3:], " ")
		if cmd == "" {
			continue
		}
		out = append(out, procInfo{
			PID: pid, PPID: ppid, User: fields[2],
			Comm: exeFromCmdline(cmd), Args: cmd,
		})
	}
	return out
}

// exeFromCmdline 取命令行第一段作为可执行路径。
// 内核线程形如 `[kernel_task]`，没有真实路径，原样返回。
func exeFromCmdline(cmd string) string {
	if cmd == "" {
		return ""
	}
	if i := strings.IndexByte(cmd, ' '); i > 0 {
		return cmd[:i]
	}
	return cmd
}
