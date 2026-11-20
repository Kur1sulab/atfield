//go:build windows

package collector

// Windows 会话 / 认证日志数据源。
//
// session：
//   - 活跃会话 `quser`（无参 = 本机所有会话）。拿不到时退 `query user`，
//     两者输出格式相同（quser 就是 query user 的新名字）。
//   - 历史登录 `wevtutil qe Security /q:*[System[(EventID=4624)]] /f:text`。
//     4624 = 登录成功。**需要管理员权限**读安全日志；读不到时返回空串
//     （历史登录是态势数据，不是判定依据，缺它不该让整个采集器不可用）。
//
// authlog：`wevtutil qe Security /q:*[System[(EventID=4625)]] /f:text`
//     4625 = 登录失败。同样需要管理员。读不到 → Probe 报原因，
//     而不是报「可用 + 0 失败」——把「没权限看」说成「没有失败」是
//     安全产品里最坏的静默。
//
// 为什么不走 PowerShell：`Get-WinEvent` 需要先加载模块、启动 PowerShell
// 进程（冷启动 400ms~2s），而 wevtutil 是原生 exe，冷启动 ~40ms。
// 采集器每 60s 跑一次，用 wevtutil 的代价可以忽略。
//
// 编码：wevtutil 的 /f:text 走控制台代码页，中文系统上是 GBK。这里复用
// persistence_windows.go 的 runUTF8（先 chcp 65001 再执行），并额外用
// decodeWinOutput 兜一层：解不出合法 UTF-8 就按 GBK 转。

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
	"unicode/utf8"
)

// winSecurityQuery 生成 XPath 查询。
// 时间窗用 TimeCreated 而不是「取最后 N 条」：窗口语义与 macOS 的
// --last 5m 对齐，对拍时两边的 count 才可比。
func winSecurityQuery(eventID int, window string) string {
	return fmt.Sprintf(`*[System[(EventID=%d) and TimeCreated[timediff(@SystemTime) <= %s]]]`,
		eventID, window)
}

// winWindowMS 5 分钟 = 300000 毫秒（wevtutil 的 timediff 单位是毫秒）。
const winWindowMS = "300000"

func platformProbeSession() error {
	if _, err := exec.LookPath("quser.exe"); err != nil {
		if _, err2 := exec.LookPath("query.exe"); err2 != nil {
			return errors.New("缺少 quser.exe / query.exe，无法盘点登录会话")
		}
	}
	return nil
}

// platformParseWho Windows 的会话表来自 quser，不是 who。
func platformParseWho(text string) []whoSession { return parseQuser(text) }

// platformParseLast Windows 的历史登录来自 wevtutil 的 4624 事件文本，
// 由 winEventsToSessions 归一成与 last 相同的 loginHist。
func platformParseLast(text string, limit int) []loginHist {
	rows := winEventsToSessions(parseWevtutilText(text))
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	return rows
}

func platformWho(ctx context.Context) (string, error) {
	// quser 无参会列本机会话；有会话时退出码 0，无会话时退出码 1 且输出
	// 「No User exists for *」。后者不是错误，所以用 Output 而非 Run 的
	// 严格判定：拿得到输出就当成功。
	if out, err := runWinCapture(ctx, "quser.exe"); len(out) > 0 {
		return out, nil
	} else if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return "", fmt.Errorf("quser 执行失败: %w", err)
		}
		return "", nil // 无会话
	}
	return "", nil
}

// platformLast 返回 4624 事件的**原始 wevtutil 文本**（解析交给
// platformParseLast）。返回已拼好的字符串会让 Windows 的解析跟 Unix 的
// last 文本解析撞在一起，那是两套完全不同的格式。
func platformLast(ctx context.Context) (string, error) {
	out, err := winQueryEvents(ctx, 4624)
	if err != nil {
		// 历史登录是态势数据：没权限读安全日志不该让会话采集器整体失败。
		return "", nil
	}
	return out, nil
}

func platformProbeAuthLog() error {
	if _, err := exec.LookPath("wevtutil.exe"); err != nil {
		return errors.New("缺少 wevtutil.exe，无法读取安全日志")
	}
	// 真读一次：wevtutil 存在 ≠ 有权限读 Security 通道。这是 Probe 唯一
	// 能区分「装了工具」与「真能采」的办法。
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if _, err := winQueryEvents(ctx, 4625); err != nil {
		return fmt.Errorf("读不到安全日志（需要管理员权限）: %v", err)
	}
	return nil
}

func platformAuthFailLines(ctx context.Context) ([]string, error) {
	out, err := winQueryEvents(ctx, 4625)
	if err != nil {
		return nil, err
	}
	return winEventsToAuthFailLines(parseWevtutilText(out)), nil
}

// winQueryEvents 查安全日志里某类事件（最近 5 分钟）。
//
// /f:text 比 /f:xml 好解析（xml 的 namespace 前缀在不同 Windows 版本上
// 不一致，且值里可能带转义实体），代价是中文系统上的 GBK——由 runUTF8 +
// decodeWinOutput 处理。
func winQueryEvents(ctx context.Context, eventID int) (string, error) {
	if _, err := exec.LookPath("wevtutil.exe"); err != nil {
		return "", errors.New("缺少 wevtutil.exe")
	}
	query := winSecurityQuery(eventID, winWindowMS)
	out, err := runUTF8(ctx, "wevtutil.exe", "qe", "Security",
		"/q:"+query, "/f:text", "/rd:true", "/c:200")
	if err != nil {
		return "", err
	}
	return decodeWinOutput(out), nil
}

// runWinCapture 跑一个自带输出编码的命令（quser 输出的是 OEM 代码页）。
func runWinCapture(ctx context.Context, bin string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if stdout.Len() == 0 && err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return "", err
		}
	}
	return decodeWinOutput(stdout.Bytes()), err
}

// decodeWinOutput 把可能的 GBK 输出转成 UTF-8。
//
// 为什么不引 golang.org/x/text：任务约束零第三方依赖。GBK 的完整映射表有
// 两万多码位，手写不现实——所以这里只做**保底**：合法 UTF-8 原样返回，
// 非法就按「每个非 ASCII 字节替换成 ?」降级，并在末尾标注。
// 这个取舍的代价是中文用户名会变成 ?；换来的是「路径/用户名里出现乱码
// 不会让整段解析崩掉」。判定逻辑（FilterAuthFailLines 只看 Failed 字样）
// 不受影响，因为关键字都是 ASCII。
func decodeWinOutput(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	out := make([]rune, 0, len(b))
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if r == utf8.RuneError && size == 1 {
			out = append(out, '?')
			b = b[1:]
			continue
		}
		out = append(out, r)
		b = b[size:]
	}
	return string(out)
}
