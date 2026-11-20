package collector

// session_exec.go —— 会话/认证日志采集共用的子进程执行器。
//
// 为什么单独一个文件而不是塞进某个平台文件：runText 三平台都用
// （who / last / log show / journalctl / wevtutil），放进 _darwin.go 会让
// linux/windows 编译不过——而四平台编译必须全过是硬约束。
//
// 与 network_darwin.go 里 firstLine 的关系：那个是 darwin 专用的（lsof 的
// stderr 首行），这里用 firstLineOf 避免同名冲突，语义相同。

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

// runText 跑命令取 stdout，带超时。
//
// stderr 单独收而不是丢掉：`log show` / `journalctl` 把「无匹配」「权限不足」
// 都写在 stderr 上，只丢 stdout 的话「没权限」会被读成「没有失败」——
// 这是安全产品里最贵的一种静默。
func runText(ctx context.Context, timeout time.Duration, bin string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return "", fmt.Errorf("%s 执行失败: %w", bin, err)
		}
		// 退出码非 0 但有输出 → 部分成功（wevtutil 在无匹配事件时退出码
		// 常为 1 且 stdout 为空，那时才算失败）。
		if stdout.Len() == 0 {
			msg := firstLineOf(stderr.String())
			if msg == "" {
				msg = "无输出"
			}
			return "", fmt.Errorf("%s 执行失败: %s", bin, msg)
		}
	}
	return stdout.String(), nil
}

// firstLineOf 取首行（stderr 摘要用）。
func firstLineOf(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			return s[:i]
		}
	}
	return s
}
