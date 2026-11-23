//go:build darwin

package collector

// privileged_darwin.go —— EndpointSecurity 取数（eslogger）。
//
// 为什么是 eslogger 而不是自己写 ES 客户端：ES 的 C API 要在进程启动前
// 申请 entitlement（com.apple.developer.endpoint-security.client）并由
// 系统在 TCC 里批准，Go 侧只能走 cgo + 签名流程。eslogger 是 Apple 自带的
// 订阅工具，输出 NDJSON，一行一个事件——正好是解析器需要的形状，
// 而且不需要我们给二进制加 entitlement。
//
// 代价是 eslogger 的输出格式不承诺稳定（见 parseESLoggerLine 的两种形状），
// 所以升级 macOS 后要重跑 privileged_test.go 的样本用例。
//
// 权限事实（本机 macOS 27.3 arm64 实测）：
//
//	非 root：eslogger 退出码 1，stderr =
//	  "Failed to create ES client: Not privileged to create an ES client,
//	   need to be superuser (ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED)"
//	root 但没给完全磁盘访问：ES client 能建，但拿不到其他进程的路径类字段，
//	  eslogger 会在 stderr 打授权提示。Probe 用 5 秒试跑把它抓出来。

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// darwinEslogger eslogger 的绝对路径。不用 LookPath：
// PATH 里可能有一个同名的用户态程序，安全采集器不该被 PATH 劫持。
const darwinEslogger = "/usr/bin/eslogger"

// darwinESSubscriptions 订阅的事件类型。
//
// 刻意不订阅 exec/fork/exit/open/signal/xpc_connect：它们在繁忙机器上
// 每秒数百条（实测编译时 exec 峰值 400+/s），而提权判定用不到。
// 少订阅一类，就少一类把缓冲冲干净的风险。
var darwinESSubscriptions = []string{
	"setuid", "seteuid",
	"create", "write", "unlink", "rename",
	"kextload", "mount",
	"cs_invalidated", "gatekeeper_user_override",
}

// platformPrivLimits 本平台能力边界（控制台原样展示）。
func platformPrivLimits() string {
	return "EndpointSecurity 事件级遥测（eslogger）；不含 exec/fork（噪声，见 privileged.go）；" +
		"需要 root 与完全磁盘访问；文件类事件只保留敏感路径"
}

// platformProbePrivileged 可用性自检。
//
// 顺序有意为之：先查 euid，再查二进制，最后才试跑。
// 非 root 时直接给结论，不起子进程——控制台要的是「为什么不能用」，
// 不是一条 eslogger 的英文报错。
func platformProbePrivileged() error {
	if os.Geteuid() != 0 {
		return errors.New("需要 root 与 Full Disk Access：EndpointSecurity 只允许 root 建 ES client" +
			"（实测非 root 下 eslogger 报 ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED）")
	}
	st, err := os.Stat(darwinEslogger)
	if err != nil {
		return fmt.Errorf("系统无 %s（EndpointSecurity 订阅需要 macOS 11+）", darwinEslogger)
	}
	if st.IsDir() || st.Mode()&0o111 == 0 {
		return fmt.Errorf("%s 不可执行（权限位异常）", darwinEslogger)
	}
	// root 下再验一次「真的能建 client」：没有完全磁盘访问时 eslogger 会
	// 非 0 退出，这里必须把它变成明确的不可用原因，而不是等到 Collect 才空转。
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if _, err := runText(ctx, 6*time.Second, darwinEslogger, "exec"); err != nil {
		return fmt.Errorf("eslogger 授权失败（系统设置 → 隐私与安全性 → 完全磁盘访问 里勾选 atfieldd）: %v", err)
	}
	return nil
}

// platformPrivSource 起一个 eslogger 子进程，逐行解析喂给 sink。
// 返回 nil 表示正常结束（ctx 取消），非 nil 表示需要重连。
func platformPrivSource(ctx context.Context, sink func(privRecord)) error {
	cmd := exec.CommandContext(ctx, darwinEslogger, darwinESSubscriptions...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("eslogger 管道创建失败: %w", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("eslogger 启动失败: %w", err)
	}

	err = readLines(ctx, stdout, func(line string) {
		if rec, ok := parseESLoggerLine(line); ok {
			sink(rec)
		}
	})
	waitErr := cmd.Wait()

	if errors.Is(ctx.Err(), context.Canceled) {
		return nil
	}
	if err != nil {
		return err
	}
	if waitErr != nil {
		msg := strings.TrimSpace(firstLineOf(stderr.String()))
		if msg == "" {
			msg = waitErr.Error()
		}
		return fmt.Errorf("eslogger 退出: %s", msg)
	}
	return nil
}
