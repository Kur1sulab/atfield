//go:build darwin

package collector

// macOS 实时日志流：`log stream --style ndjson --predicate <p>`。
//
// 为什么用 ndjson 而不是默认的 syslog 风格：默认输出是给人看的，
// 字段顺序随进程变化，processImagePath 会被空格截断。ndjson 每行是一个
// JSON 对象，字段名稳定（eventMessage/processImagePath/subsystem/processID），
// 与 Python 版用的是同一种格式，解析可以逐字段对齐。
//
// 非特权可用：`log stream` 对普通用户开放，这是本项目在不拿 root 的前提下
// 拿到「接近 EDR」实时视野的关键通道。
//
// 断流重连策略与 Python 一致：进程退出发起重连（3s 退避），并由调用方
// （LogStream.Start）负责循环，这里只负责「一次订阅跑到退出」。

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
)

func platformLogSourceKind() string { return "ndjson" }

func platformProbeLogStream() error {
	st, err := os.Stat(darwinLogPath)
	if err != nil {
		return fmt.Errorf("缺少 %s：macOS 10.12+ 的实时日志只能从这里取", darwinLogPath)
	}
	if st.IsDir() {
		return fmt.Errorf("%s 不是可执行文件", darwinLogPath)
	}
	if st.Mode()&0o111 == 0 {
		return fmt.Errorf("%s 不可执行（权限位异常）", darwinLogPath)
	}
	return nil
}

// platformLogSource 起一个 `log stream` 子进程，逐行喂给 sink，直到 ctx 取消
// 或子进程退出。返回 nil 表示「正常结束」，非 nil 表示需要重连。
func platformLogSource(ctx context.Context, predicate string, sink func(string)) error {
	if predicate == "" {
		predicate = defaultLogPredicate
	}
	cmd := exec.CommandContext(ctx, darwinLogPath,
		"stream", "--style", "ndjson", "--predicate", predicate)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("log stream 管道创建失败: %w", err)
	}
	// stderr 接到 /dev/null：log stream 会往 stderr 打一行
	// "Filtering the log data using ..."，那不是数据。
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("log stream 启动失败: %w", err)
	}

	var once sync.Once
	kill := func() {
		once.Do(func() {
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
		})
	}
	// ctx 取消 → 杀掉子进程（CommandContext 只杀主进程，Pipe 的读端会被
	// 关掉，所以 readLines 能返回）
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			kill()
		case <-done:
		}
	}()

	err = readLines(ctx, stdout, sink)
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
		return fmt.Errorf("log stream 退出: %w", waitErr)
	}
	return nil
}
