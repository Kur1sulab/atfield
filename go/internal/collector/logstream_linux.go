//go:build linux

package collector

// Linux 实时日志流：`journalctl -f -o json --no-pager`。
//
// 为什么不是 /var/log/syslog 的 tail：syslog 的格式取决于 rsyslog/syslog-ng
// 的模板，字段位置不固定；journal 的 JSON 有稳定的 MESSAGE/_PID/_COMM/
// SYSLOG_IDENTIFIER 字段，能归一成与 macOS ndjson 相同的 logRecord，
// 判定因此只有一份实现。
//
// 谓词：journalctl 没有 macOS 那种 predicate 语言。这里不用 --grep
// （它会把多行上下文一起吞掉，且无法表达「进程 OR 子系统」）。做法是
// 全量订阅 + 客户端过滤，过滤条件由 journalSelector 决定——只保留与安全
// 相关的 syslog identifier / unit，等价于 macOS 的 predicate。
//
// 权限：普通用户只能看到自己的 journal（systemd 的默认策略是
// Storage=persistent + 用户可读部分），要读全量需要加入 systemd-journal
// 组或 root。Probe 会实际跑一次 `journalctl -n 0` 判断能不能读——
// 「装了 journalctl」和「能读」是两件事。
//
// 容器：很多容器镜像里根本没有 journalctl（alpine/distroless）。
// 这时 Probe 明确返回原因，而不是「可用但 0 事件」。

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

func platformLogSourceKind() string { return "journal" }

func platformProbeLogStream() error {
	bin, err := exec.LookPath("journalctl")
	if err != nil {
		return errors.New("缺少 journalctl（systemd 未装，容器里很常见）")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	// -n 0 不输出任何行，只验证「能不能打开 journal」。
	cmd := exec.CommandContext(ctx, bin, "-n", "0", "--no-pager", "-o", "json")
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("journalctl 无法读取 journal（需要 systemd-journal 组或 root）: %s", firstLineOf(msg))
	}
	return nil
}

func platformLogSource(ctx context.Context, predicate string, sink func(string)) error {
	bin, err := exec.LookPath("journalctl")
	if err != nil {
		return errors.New("缺少 journalctl")
	}
	args := []string{"-f", "-o", "json", "--no-pager", "-n", "0"}
	// 用户自定义谓词时按 --grep 走（journalctl 的 grep 是扩展正则，
	// 语义最接近；空谓词就用默认选择器）。
	if strings.TrimSpace(predicate) != "" && predicate != defaultLogPredicate {
		args = append(args, "--grep", predicate)
	}

	cmd := exec.CommandContext(ctx, bin, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("journalctl 管道创建失败: %w", err)
	}
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("journalctl 启动失败: %w", err)
	}

	var once sync.Once
	kill := func() {
		once.Do(func() {
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
		})
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			kill()
		case <-done:
		}
	}()

	err = readLines(ctx, stdout, func(line string) {
		rec, ok := parseJournalJSON(line)
		if !ok || !journalSelected(rec) {
			return
		}
		sink(line)
	})
	close(done)
	kill()
	waitErr := cmd.Wait()

	if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
		return nil
	}
	if err != nil {
		return err
	}
	if waitErr != nil {
		return fmt.Errorf("journalctl 退出: %w", waitErr)
	}
	return nil
}
