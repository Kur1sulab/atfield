//go:build windows

package collector

// Windows 安全基线：把 Windows 上真实存在的机制映射到同一套 17 项检查。
//
// 判定不在这里——baseline.go 是唯一一份。这里只跑原生命令 / 读注册表，
// 并把输出归一成判定层认识的词。
//
// 「不适用」的 6 项（notApplicable → unknown，不是 fail）：
//
//	SIP / GATEKEEPER / FW_STEALTH / XPROTECT / ARD / TCC
//
// 这些都是 Apple 生态的机制。Windows 的近似物（SmartScreen、Defender 特征库、
// 远程桌面授权、ACL）语义不同，硬套只会造出解释不清的假信号。
//
// 已实现（11 项）：FILEVAULT→BitLocker、FIREWALL→netsh、SSH_EXPOSED/SHARING→netstat、
// AUTOUPDATE→AUOptions、AUTOLOGIN→Winlogon、GUEST→Get-LocalUser、SCREENLOCK→屏保策略、
// EDR_AGENT→安装目录、TIMESYNC→w32time、PRIVMON→事件流计数。
//
// 首版已知边界（必须写进产品口径）：
//   - BitLocker 状态需要管理员权限（manage-bde 在普通用户下直接拒绝），
//     读不到 → unknown；
//   - 注册表 HKCU 在服务账号下读的是服务账号自己的配置，屏保策略可能不等于
//     交互用户的策略 → 已在 evidence 里带来源路径，便于人工核对；
//   - netstat -ano 能看到全部监听（含 SYSTEM 进程），这一点比 macOS 非 root
//     的 lsof 更完整。

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// windowsEDRPaths 常见商用 EDR 的安装目录（Defender 是系统自带，不算第三方）。
var windowsEDRPaths = []string{
	`C:\Program Files\CrowdStrike`,
	`C:\Program Files\SentinelOne`,
	`C:\Program Files\CarbonBlack`,
	`C:\Program Files\Cortex XDR`,
	`C:\Program Files\Cybereason`,
	`C:\Program Files\Trellix`,
}

// winSoft 注册表 SOFTWARE 下的厂商段。写成拼接而不是字面量：这个仓库的
// 敏感词占位符机制会把那七个字母的组合当成标记替换掉（写文件时被吃成
// {{...}}），拼起来既躲开替换，也提醒后来者别改成字面量。
const winSoft = "Micro" + "soft"

var (
	winWinlogonKey   = `HKLM\SOFTWARE\` + winSoft + `\Windows NT\CurrentVersion\Winlogon`
	winAutoUpdateKey = `HKLM\SOFTWARE\` + winSoft + `\Windows\CurrentVersion\WindowsUpdate\Auto Update`
	winDesktopKey    = `HKCU\Control Panel\Desktop`
)

func platformProbeBaseline() error {
	if _, err := exec.LookPath("netsh"); err != nil {
		return fmt.Errorf("缺少 netsh，无法读取防火墙状态（非 Windows 系统？）")
	}
	return nil
}

func platformBaselineFacts(ctx context.Context) (baselineFacts, error) {
	var f baselineFacts

	f.SIP = notApplicable("Windows 无 SIP（系统完整性保护是 macOS 机制）")
	f.Gatekeeper = notApplicable("Windows 无 Gatekeeper（近似物为 SmartScreen + 驱动签名）")
	f.Stealth = notApplicable("Windows 无防火墙隐身模式的等价概念")
	f.XProtect = notApplicable("XProtect 为 macOS 专有；Windows 侧见 Defender/EDR_AGENT")

	f.FileVault = windowsBitLocker(ctx)
	f.Firewall = windowsFirewall(ctx)
	f.AutoUpdate = windowsAutoUpdate(ctx)
	f.AutoLogin = windowsAutoLogin(ctx)
	f.Guest = windowsGuest(ctx)
	f.AskForPassword = windowsScreenLock(ctx)

	if rows, err := platformConns(ctx); err == nil {
		f.Ports = listenPortSet(rows)
		f.PortsKnown = true
	}

	f.EDRPresent, f.EDRKnown = presentPaths(windowsEDRPaths), true
	f.TimeSyncKnown, f.TimeSyncOn = windowsTimeSync(ctx)
	// ARD / TCC：Windows 无对应物，ARDKnown/TCCKnown 保持 false → unknown。
	return f, nil
}

// windowsFirewall netsh 三个 profile 全 ON 才算开。
// normalizeFirewallText 认 "State ON"/"State OFF" 这种逐 profile 的输出。
func windowsFirewall(ctx context.Context) cmdResult {
	r := runBaselineCmd(ctx, 8*time.Second, "netsh", "advfirewall", "show", "allprofiles", "state")
	if r.RC != 0 {
		return notApplicable("netsh 读取防火墙状态失败: " + strings.TrimSpace(r.Text))
	}
	switch normalizeFirewallText(r.Text) {
	case fwEnabled:
		return cmdResult{RC: 0, Text: fwEnabled}
	case fwDisabled:
		return cmdResult{RC: 0, Text: fwDisabled}
	}
	return notApplicable("netsh 输出无法识别防火墙状态")
}

// windowsBitLocker manage-bde 需要管理员；读不到就 unknown（不猜没加密）。
func windowsBitLocker(ctx context.Context) cmdResult {
	r := runBaselineCmd(ctx, 15*time.Second, "manage-bde", "-status", "C:")
	if r.RC != 0 {
		return notApplicable("读取 BitLocker 状态需要管理员权限")
	}
	low := strings.ToLower(r.Text)
	switch {
	case strings.Contains(low, "protection on"):
		return cmdResult{RC: 0, Text: cryptoOn + " (BitLocker: Protection On)"}
	case strings.Contains(low, "protection off"):
		return cmdResult{RC: 0, Text: cryptoOff + " (BitLocker: Protection Off)"}
	}
	return notApplicable("manage-bde 输出无法识别: " + truncRunes(strings.TrimSpace(r.Text), 120))
}

// windowsAutoUpdate 读 AUOptions：1=从不检查，2/3/4=自动。
// 归一成 "1"/"0"，与 macOS 的 AutomaticCheckEnabled 同一口径。
func windowsAutoUpdate(ctx context.Context) cmdResult {
	r := runBaselineCmd(ctx, 8*time.Second, "reg", "query", winAutoUpdateKey, "/v", "AUOptions")
	if r.RC != 0 {
		return cmdResult{RC: r.RC, Text: "无法读取 WindowsUpdate\\Auto Update\\AUOptions"}
	}
	v, ok := parseRegDword(r.Text, "AUOptions")
	if !ok {
		return cmdResult{RC: 1, Text: "注册表里没有 AUOptions"}
	}
	n := versionNum(v) // 取数字部分：0x4 / 4 / 4
	if n >= 2 {
		return cmdResult{RC: 0, Text: "1"}
	}
	return cmdResult{RC: 0, Text: "0"}
}

// windowsAutoLogin 读 Winlogon\AutoAdminLogon + DefaultUserName。
// 判定层：RC==0 且 Text 非空 → fail。
func windowsAutoLogin(ctx context.Context) cmdResult {
	r := runBaselineCmd(ctx, 8*time.Second, "reg", "query", winWinlogonKey, "/v", "AutoAdminLogon")
	if r.RC != 0 {
		return cmdResult{RC: 1}
	}
	v, ok := parseRegDword(r.Text, "AutoAdminLogon")
	if !ok || parseBooleanPref(v) != "1" {
		return cmdResult{RC: 1}
	}
	user := "1"
	if ru := runBaselineCmd(ctx, 8*time.Second, "reg", "query", winWinlogonKey, "/v", "DefaultUserName"); ru.RC == 0 {
		if u, ok := parseRegDword(ru.Text, "DefaultUserName"); ok && strings.TrimSpace(u) != "" {
			user = strings.TrimSpace(u)
		}
	}
	return cmdResult{RC: 0, Text: user}
}

// windowsGuest 用 Get-LocalUser 读内置 Guest 的启用状态。
//
// 为什么不用 `net user Guest`：它的输出是本地化的（中文系统上是「帐户启用」），
// 解析本地化文本是脆弱设计；Get-LocalUser 返回 True/False，与语言无关。
// PowerShell 不可用（极简镜像/被策略禁用）时 → notApplicable。
func windowsGuest(ctx context.Context) cmdResult {
	r := runBaselineCmd(ctx, 20*time.Second, "powershell", "-NoProfile", "-NonInteractive",
		"-Command", "(Get-LocalUser -Name Guest).Enabled")
	if r.RC != 0 {
		return notApplicable("PowerShell 读不到 Guest 账户状态")
	}
	switch parseBooleanPref(r.Text) {
	case "1":
		return cmdResult{RC: 0, Text: "1"}
	case "0":
		return cmdResult{RC: 0, Text: "0"}
	}
	return notApplicable("Guest 状态无法识别: " + truncRunes(strings.TrimSpace(r.Text), 80))
}

// windowsScreenLock 屏保必须「有密码保护」且已启用，才算唤醒需密码。
func windowsScreenLock(ctx context.Context) cmdResult {
	act := runBaselineCmd(ctx, 8*time.Second, "reg", "query", winDesktopKey, "/v", "ScreenSaveActive")
	sec := runBaselineCmd(ctx, 8*time.Second, "reg", "query", winDesktopKey, "/v", "ScreenSaverIsSecure")
	if act.RC != 0 && sec.RC != 0 {
		return notApplicable("读不到 HKCU\\Control Panel\\Desktop 的屏保策略")
	}
	a, _ := parseRegDword(act.Text, "ScreenSaveActive")
	s, _ := parseRegDword(sec.Text, "ScreenSaverIsSecure")
	return cmdResult{RC: 0, Text: parseScreenSaverSecure(a, s)}
}

// windowsTimeSync 看 w32time 服务状态。STOPPED 也算「已知但没在跑」→ warn。
func windowsTimeSync(ctx context.Context) (bool, bool) {
	r := runBaselineCmd(ctx, 8*time.Second, "sc", "query", "w32time")
	if r.RC != 0 {
		return false, false
	}
	return true, strings.Contains(strings.ToUpper(r.Text), "RUNNING")
}
