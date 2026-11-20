//go:build linux

package collector

// Linux 会话 / 认证日志数据源。
//
// session：`who` + `last -20`。与 macOS 同一组命令、同一套解析——Linux 的
// util-linux who 输出格式与 BSD 一致（user / tty / 时间 / (来源)），所以
// parseWho 不需要分叉。容器里 who 常为空（没有 utmp），那不是错误。
//
// authlog：三条路，按可信度依次尝试
//  1. /var/log/auth.log   Debian/Ubuntu 系
//  2. /var/log/secure     RHEL/CentOS 系
//  3. journalctl -u ssh -u sudo --since 5m --grep ...
//     （systemd 系可能根本不写文本日志，只留 journal）
//
// 全都不通时 Probe 明确返回原因，而不是「可用但永远 0 事件」——后者会让
// 控制台显示「authlog 正常，无失败」，把「看不见」伪装成「很干净」。
//
// 已知边界：auth.log 通常 0640 root:adm，普通用户读不到。读不到时
// 直接报「需要 root 或 adm 组」，不静默降级成空。

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// linuxAuthLogPaths 文本认证日志的候选路径（按顺序）。
var linuxAuthLogPaths = []string{"/var/log/auth.log", "/var/log/secure", "/var/log/auth.log.1"}

func platformProbeSession() error {
	who, err := exec.LookPath("who")
	if err != nil {
		return errors.New("缺少 who（util-linux 未装？），无法盘点登录会话")
	}
	if _, err := exec.Command(who).Output(); err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return fmt.Errorf("who 无法执行: %w", err)
		}
	}
	return nil
}

// platformParseWho Linux 的 util-linux who 与 BSD who 同格式。
func platformParseWho(text string) []whoSession { return parseWho(text) }

// platformParseLast Linux 的 last 与 BSD last 同格式（列宽略有差异，
// parseLast 只取前两列与末列，不受影响）。
func platformParseLast(text string, limit int) []loginHist { return parseLast(text, limit) }

func platformWho(ctx context.Context) (string, error) {
	bin, err := exec.LookPath("who")
	if err != nil {
		return "", errors.New("缺少 who")
	}
	return runText(ctx, 6*time.Second, bin)
}

func platformLast(ctx context.Context) (string, error) {
	bin, err := exec.LookPath("last")
	if err != nil {
		// 容器里没有 last 是常态：历史登录拿不到不影响活跃会话采集，
		// 返回空串（不是错误），与 Python 的 _run() 吞异常同口径。
		return "", nil
	}
	return runText(ctx, 6*time.Second, bin, "-20")
}

// linuxAuthLogReadable 返回第一个可读的认证日志路径。
func linuxAuthLogReadable() (string, error) {
	var seen []string
	for _, p := range linuxAuthLogPaths {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		if fi.IsDir() {
			continue
		}
		seen = append(seen, p)
		fh, err := os.Open(p)
		if err != nil {
			continue // 存在但读不到（root:adm 0640）
		}
		fh.Close()
		return p, nil
	}
	if len(seen) > 0 {
		return "", fmt.Errorf("%s 存在但当前用户读不到（需要 root 或 adm 组）", strings.Join(seen, "/"))
	}
	return "", errors.New("没有 /var/log/auth.log 或 /var/log/secure")
}

func platformProbeAuthLog() error {
	_, textErr := linuxAuthLogReadable()
	if textErr == nil {
		return nil
	}
	// 文本日志不可用 → 看 journal 这条路
	if _, err := exec.LookPath("journalctl"); err == nil {
		return nil
	}
	return fmt.Errorf("%v，且没有 journalctl（systemd 未装）", textErr)
}

// platformAuthFailLines 取最近 5 分钟候选认证失败行。
func platformAuthFailLines(ctx context.Context) ([]string, error) {
	if p, err := linuxAuthLogReadable(); err == nil {
		text, rerr := tailFile(ctx, p, 256*1024)
		if rerr != nil {
			return nil, rerr
		}
		// auth.log 的尾巴可能横跨几小时，必须裁到 5m 窗口才与
		// macOS 的 `log show --last 5m` 同语义（subject.count 才可比）。
		return filterAuthWindow(parseAuthLogText(text), 5*time.Minute, time.Now()), nil
	}
	bin, err := exec.LookPath("journalctl")
	if err != nil {
		return nil, errors.New("认证日志与 journalctl 都不可用")
	}
	// --since "5 min ago" 与 macOS 的 --last 5m 对齐；--no-pager 免得
	// journalctl 在非 tty 环境下仍尝试调分页器。
	out, err := runText(ctx, 25*time.Second, bin,
		"--since", "5 min ago", "--no-pager", "--output", "short-iso",
		"--grep", journalAuthPredicate)
	if err != nil {
		return nil, err
	}
	return parseJournalText(out), nil
}

// tailFile 读文件末尾 n 字节。
// 不整读 /var/log/auth.log 的理由：被入侵的机器上这个文件可以有几个 GB
// （攻击者灌日志掩盖痕迹是常规手法），整读会把内存打爆。
// 从末尾读的代价是可能切到一行中间，parseAuthLogText 会把它当普通行——
// 那行大概率不含失败关键字，不影响判定。
func tailFile(ctx context.Context, path string, n int64) (string, error) {
	fh, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("打开 %s 失败: %w", path, err)
	}
	defer fh.Close()
	fi, err := fh.Stat()
	if err != nil {
		return "", err
	}
	off := fi.Size() - n
	if off < 0 {
		off = 0
	}
	if _, err := fh.Seek(off, 0); err != nil {
		return "", err
	}
	// 上下文取消也要能中断（大文件读 256KB 很快，但保持一致的取消语义）
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}
	data, err := io.ReadAll(io.LimitReader(fh, fi.Size()-off))
	if err != nil {
		return "", err
	}
	return string(data), nil
}
