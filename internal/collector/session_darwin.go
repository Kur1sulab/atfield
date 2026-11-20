//go:build darwin

package collector

// macOS 会话 / 认证日志数据源。
//
// session：`who` + `last -20`（与 Python 版同一条命令、同一组参数）。
// authlog：unified log 回捞（`log show`），predicate 与 Python 版逐字相同。
//
// 为什么不用 /var/log/auth.log：macOS 从 10.12 起不再写它，机器上那个文件
// 即使存在也是空的。认证事件只在 unified log 里，所以只能 `log show`。
//
// 权限事实（必须写进产品口径）：`log show` 读系统日志需要
// com.apple.logd 的读取权限。普通用户能读到 sudo/sshd 这类进程的公开事件，
// 但读不到受保护子系统（如部分 TCC 明细）。拿不到时 Probe 不判不可用——
// 「能读到一部分」比「什么都不报」有用，但控制台要标明口径。

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"
)

const (
	darwinWhoPath  = "/usr/bin/who"
	darwinLastPath = "/usr/bin/last"
	darwinLogPath  = "/usr/bin/log"
)

// darwinAuthPredicate 与 Python 版 session.py 第 98-99 行的 predicate 逐字相同。
// 改它等于改采集口径，必须两版一起改。
const darwinAuthPredicate = `(process == "sudo" AND eventMessage CONTAINS "incorrect") ` +
	`OR (process == "sshd" AND eventMessage CONTAINS "Failed")`

func platformProbeSession() error {
	for _, p := range []string{darwinWhoPath, darwinLastPath} {
		if st, err := os.Stat(p); err != nil || st.IsDir() {
			return fmt.Errorf("缺少 %s，无法盘点登录会话", p)
		}
	}
	// who 在没有任何登录会话时也返回 0（只打印空），所以跑一次看能不能执行即可。
	if _, err := exec.Command(darwinWhoPath).Output(); err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return fmt.Errorf("who 无法执行: %w", err)
		}
	}
	return nil
}

// platformParseWho macOS 的 who 输出就是 BSD who 格式，直接用共用解析器。
func platformParseWho(text string) []whoSession { return parseWho(text) }

// platformParseLast macOS 的 last 输出是 BSD last 格式。
func platformParseLast(text string, limit int) []loginHist { return parseLast(text, limit) }

func platformWho(ctx context.Context) (string, error) {
	return runText(ctx, 6*time.Second, darwinWhoPath)
}

func platformLast(ctx context.Context) (string, error) {
	// Python: ["/usr/bin/last", "-20"]
	return runText(ctx, 6*time.Second, darwinLastPath, "-20")
}

func platformProbeAuthLog() error {
	if st, err := os.Stat(darwinLogPath); err != nil || st.IsDir() {
		return fmt.Errorf("缺少 %s，无法回捞认证日志（macOS 10.12+ 认证事件只在 unified log 里）", darwinLogPath)
	}
	return nil
}

// platformAuthFailLines 跑 `log show --last 5m`。
//
// 超时给 25s（与 Python 一致）：unified log 在日志量大的机器上要几秒才
// 吐完 5 分钟窗口，超时太短会拿到半截输出——半截输出会被当成「失败变少了」，
// 比明确报错更危险。
func platformAuthFailLines(ctx context.Context) ([]string, error) {
	out, err := runText(ctx, 25*time.Second, darwinLogPath,
		"show", "--last", "5m", "--style", "compact", "--predicate", darwinAuthPredicate)
	if err != nil {
		return nil, err
	}
	return parseAuthLogText(out), nil
}

// runText 见 session_exec.go（三平台共用）。
