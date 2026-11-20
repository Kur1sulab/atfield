//go:build darwin

package collector

// macOS 安全基线：跑 17 条原生命令/读取，把结果填进 baselineFacts。
//
// 这一层**不做任何判定**——判定在 baseline.go（四平台共用一份）。这里只负责
// 「命令 → 文本」，这样同一份判定在三平台上不可能漂移。
//
// 命令路径写死绝对路径（/usr/bin/csrutil 等），不用 exec.LookPath：
//   - 对拍要求两版读到同一个二进制。PATH 里如果有个同名脚本，LookPath 会
//     把它捡走，Python 版写死绝对路径则不会，两边结论就会不一致；
//   - 这些工具都是系统自带、路径固定（SIP 保护），不存在装到别处的可能。
//
// 采集口径（必须写进产品说明，不许假装完整）：
//   - 非 root 运行时 lsof 只能看到当前用户的 socket。sshd（launchd 持有）
//     这类 root 监听看不到 → SSH_EXPOSED / SHARING 可能漏报，不会误报。
//   - TCC.db 自 Catalina 起受 SIP 保护，没有「完全磁盘访问」授权时读不到，
//     一律 unknown（Python 版同样）。
//   - fdesetup status 不需要 root；socketfilterfw --getglobalstate 也不需要。

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// /usr/bin/sqlite3 在部分精简系统上不存在（只剩 Xcode CLT 的那份），
// 所以 TCC 查询单独走 LookPath 兜底：读不到就 unknown，不猜。
const (
	pathCSRUtil       = "/usr/bin/csrutil"
	pathSpctl         = "/usr/sbin/spctl"
	pathFdesetup      = "/usr/bin/fdesetup"
	pathSocketFilter  = "/usr/libexec/applicationfirewall/socketfilterfw"
	pathDefaults      = "/usr/bin/defaults"
	pathPkgutil       = "/usr/sbin/pkgutil"
	pathPlutil        = "/usr/bin/plutil"
	ardPlistPath      = "/Library/Preferences/com.apple.RemoteManagement.plist"
	defaultsLoginWin  = "/Library/Preferences/com.apple.loginwindow"
	defaultsSoftware  = "/Library/Preferences/com.apple.SoftwareUpdate"
	darwinTCCRelPath  = "Library/Application Support/com.apple.TCC/TCC.db"
	sqlite3Fallback   = "/usr/bin/sqlite3"
	tccQuery          = "select service,client,auth_value from access where auth_value!=0 limit 40;"
	baselineCmdTimout = 8 * time.Second
	defaultsTimeout   = 5 * time.Second
)

// darwinEDRPaths Python 版 known 列表逐字对齐（顺序决定 evidence 里的枚举顺序）。
var darwinEDRPaths = []string{
	"/Applications/CrowdStrike Falcon.app",
	"/Applications/SentinelOne.app",
	"/Library/Application Support/JAMF",
	"/Applications/Cisco Secure Client.app",
	"/Applications/Netskope Client.app",
}

// platformProbeBaseline 可用性自检：只要 SIP 状态能读，就算基线可用——
// 其余检查项各自降级（unknown），不该因为某一个工具缺失就整块不采。
func platformProbeBaseline() error {
	if _, err := os.Stat(pathCSRUtil); err != nil {
		return fmt.Errorf("缺少 %s，无法读取 SIP 状态（非 macOS 系统？）", pathCSRUtil)
	}
	return nil
}

func platformBaselineFacts(ctx context.Context) (baselineFacts, error) {
	var f baselineFacts

	f.SIP = runBaselineCmd(ctx, baselineCmdTimout, pathCSRUtil, "status")
	f.Gatekeeper = runBaselineCmd(ctx, baselineCmdTimout, pathSpctl, "--status")
	f.FileVault = runBaselineCmd(ctx, baselineCmdTimout, pathFdesetup, "status")
	f.Firewall = runBaselineCmd(ctx, baselineCmdTimout, pathSocketFilter, "--getglobalstate")
	f.Stealth = runBaselineCmd(ctx, baselineCmdTimout, pathSocketFilter, "--getstealthmode")

	f.AutoUpdate = runBaselineCmd(ctx, defaultsTimeout, pathDefaults, "read", defaultsSoftware, "AutomaticCheckEnabled")
	f.AutoLogin = runBaselineCmd(ctx, defaultsTimeout, pathDefaults, "read", defaultsLoginWin, "autoLoginUser")
	f.Guest = runBaselineCmd(ctx, defaultsTimeout, pathDefaults, "read", defaultsLoginWin, "GuestEnabled")

	// -currentHost：Python 版同一参数。新版 macOS 已把这两个键搬到别的域，
	// 读不到（rc!=0）→ unknown，与 Python 的 elif rc1 != 0 分支一致。
	f.AskForPassword = runBaselineCmd(ctx, defaultsTimeout, pathDefaults, "-currentHost", "read",
		"com.apple.screensaver", "askForPassword")
	f.AskForPasswordDelay = runBaselineCmd(ctx, defaultsTimeout, pathDefaults, "-currentHost", "read",
		"com.apple.screensaver", "askForPasswordDelay")

	// 已知：macOS 26 上 XProtect 的收据包名带版本后缀
	// （com.apple.pkg.XProtectPlistConfigData_10_15.16U4463），Python 版写死的
	// 老包名会读不到 → unknown。这里**故意保持同一个包名**：Go 版如果自己
	// 去 glob 新版包名，会得到 pass，而 Python 是 unknown，对拍直接不成立。
	// 要修就两版一起修（Python 侧同样改成 glob），不许单边改。
	f.XProtect = runBaselineCmd(ctx, baselineCmdTimout, pathPkgutil, "--pkg-info",
		"com.apple.pkg.XProtectPlistConfigData")

	// 监听端口：复用 network 采集器的连接表（lsof），只做投影。
	if rows, err := platformConns(ctx); err == nil {
		f.Ports = listenPortSet(rows)
		f.PortsKnown = true
	}

	f.EDRPresent, f.EDRKnown = presentPaths(darwinEDRPaths), true
	f.ARDExists, f.ARDAllUsers = darwinARDFlags()
	f.ARDKnown = true

	f.TimeSyncKnown, f.TimeSyncOn = darwinTimeSyncRunning(ctx)
	f.TCCExists, f.TCC = darwinTCC(ctx)
	f.TCCKnown = true
	return f, nil
}

// runBaselineCmd / presentPaths / anyProcNameHas 在 baseline_exec.go（无 tag），
// 三平台共用一份。

// darwinARDFlags 读 ARD 偏好，返回 (是否存在, 是否放开任意本地用户)。
//
// Python 用 plistlib.load（能吃二进制 plist），这里先试 plutil 转 XML 再
// 用共享的 parsePlistXML——不引第三方库，也不自己写 bplist 解析器。
// plutil 拒绝解析时退回目录判断：文件在、读不懂 → 只算「已部署」（warn），
// 不升级成 fail——「读不懂」不能当成「放开了」。
func darwinARDFlags() (bool, bool) {
	if _, err := os.Stat(ardPlistPath); err != nil {
		return false, false
	}
	out, err := exec.Command(pathPlutil, "-convert", "xml1", "-o", "-", ardPlistPath).Output()
	if err != nil || len(out) == 0 {
		return true, false
	}
	dict, err := parsePlistXML(out)
	if err != nil {
		return true, false
	}
	return true, plistTruthy(dict["ARD_AllLocalUsers"]) || plistTruthy(dict["AllowAllUsers"])
}

// plistTruthy 复刻 Python 的 `if pl.get(k)` 语义。
func plistTruthy(v pval) bool {
	switch v.kind {
	case "bool":
		return v.b
	case "integer", "real":
		return v.n != 0
	case "string", "date", "data":
		return v.s != ""
	case "array", "dict":
		return true
	}
	return false
}

// darwinTimeSyncRunning Python 版是 `any("timed" in name for p in process_iter())`。
// 这里复用进程采集器的平台实现（ps -ww -axo），只取基名做子串判断，语义一致。
func darwinTimeSyncRunning(ctx context.Context) (bool, bool) {
	procs, err := platformProcs(ctx)
	if err != nil {
		return false, false
	}
	return true, anyProcNameHas(procs, "timed")
}

// anyProcNameHas 进程名（基名）包含子串即命中。
// Python 的 TIMESYNC 检查是 `any("timed" in p.info["name"])`，psutil 的 name
// 是基名；这里同样先取基名，避免 /usr/libexec/timed 这种完整路径参与匹配时
// 把 "/usr/libexec/time..." 里的巧合也吃进来。
// （定义在 baseline_exec.go，三平台共用。）

// darwinTCC 读用户 TCC 库。存在即返回 exists=true；读不到（无完全磁盘访问）
// 时 rc!=0，判定层据此置 unknown——与 Python 同一口径。
func darwinTCC(ctx context.Context) (bool, cmdResult) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return false, cmdResult{}
	}
	db := filepath.Join(home, darwinTCCRelPath)
	if _, err := os.Stat(db); err != nil {
		return false, cmdResult{}
	}
	bin := sqlite3Fallback
	if _, err := os.Stat(bin); err != nil {
		if p, err := exec.LookPath("sqlite3"); err == nil {
			bin = p
		} else {
			return true, cmdResult{RC: 127, Text: "缺少 sqlite3，无法读取 TCC 库"}
		}
	}
	return true, runBaselineCmd(ctx, 10*time.Second, bin, db, tccQuery)
}
