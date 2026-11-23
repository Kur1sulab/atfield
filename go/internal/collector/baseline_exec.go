package collector

// baseline_exec.go —— 基线采集的通用执行/文件助手，**不带 build tag**。
//
// 三平台的 baseline_<os>.go 都只做「跑命令 / 读文件 → baselineFacts」，
// 跑命令这件事本身平台无关（os/exec 就是跨平台的），所以放这里一份。
// 唯一要注意的是 Windows 上命令名不带 .exe 也能被 exec 解析（Go 会自动补
// PATHEXT），所以平台层可以直接写 "netsh"、"reg"、"sc"。

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"
)

// runBaselineCmd 跑一条命令，返回 (rc, stdout+stderr)。
//
// 语义对齐 Python 的 `_cmd`：合并输出（evidence 取它）、失败给非零 rc。
// 具体地：
//   - 命令退出非零：rc = 真实退出码，Text = 合并输出（Python 同）；
//   - 命令跑不起来（不存在 / 无权限 / 超时）：rc = 127，Text = 异常文本
//     （Python 里就是 `return 127, f"{type(exc).__name__}: {exc}"`）。
//
// 为什么合并 stderr：`defaults read` 把 "key not found" 写 stderr，
// `spctl --status` 把结论写 stdout，Python 版一律 `stdout + stderr`。
// 只取 stdout 会让 "无法读取偏好" 那类分支拿到空文本，判定就变了。
func runBaselineCmd(ctx context.Context, timeout time.Duration, name string, args ...string) cmdResult {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return cmdResult{RC: 0, Text: string(out)}
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		// 退出码可信：Unix 上是 0-255，Windows 上是进程返回码。
		return cmdResult{RC: ee.ExitCode(), Text: string(out)}
	}
	// 启动失败 / 超时：Python 侧同样是「异常 → rc=127」。
	text := string(out)
	if text == "" {
		text = fmt.Sprintf("%T: %v", err, err)
	}
	return cmdResult{RC: 127, Text: text}
}

// notApplicable 本平台没有这个机制。判定层会把它降成 unknown 并把理由
// 原样写进 evidence——UI 上显示为「不适用」而不是「不合格」。
//
// 这一条很重要：Linux 上没有 SIP 不等于「SIP 被关闭了」。把缺失当成 fail
// 会让 Linux 版一上来就自带 6 条 high 假告警，那样的产品没法用。
func notApplicable(reason string) cmdResult {
	return cmdResult{RC: 127, Text: reason, Missing: true}
}

// presentPaths 过滤出存在的路径（Python: [p for p in known if os.path.exists(p)]）。
func presentPaths(paths []string) []string {
	var out []string
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// anyProcNameHas 进程名（基名）包含子串即命中。
// Python 的 TIMESYNC 检查是 `any("timed" in p.info["name"])`，psutil 的 name
// 是基名；这里同样先取基名，避免 /usr/libexec/timed 这种完整路径参与匹配时
// 把 "/usr/libexec/time..." 里的巧合也吃进来。
func anyProcNameHas(procs []procInfo, sub string) bool {
	for _, p := range procs {
		if strings.Contains(baseName(p.Comm), sub) {
			return true
		}
	}
	return false
}

// anyProcNameHasAny 多关键词版本（Linux 的时间同步实现有 timesyncd/chronyd/ntpd）。
func anyProcNameHasAny(procs []procInfo, subs []string) bool {
	for _, s := range subs {
		if anyProcNameHas(procs, s) {
			return true
		}
	}
	return false
}

// readTextFile 读文本文件，读不到返回 ok=false（调用方据此置 Missing）。
func readTextFile(p string) (string, bool) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "", false
	}
	return string(b), true
}

// globBaseNames 返回某个目录下匹配 pattern 的基名列表（Linux 的配置文件探测用）。
func globBaseNames(dir, pattern string) []string {
	m, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range m {
		if e.IsDir() {
			continue
		}
		if ok, _ := path.Match(pattern, e.Name()); ok {
			out = append(out, e.Name())
		}
	}
	return out
}
