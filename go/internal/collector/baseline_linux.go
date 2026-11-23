//go:build linux

package collector

// Linux 安全基线：把 Linux 上真实存在的机制映射到同一套 17 项检查。
//
// 判定不在这里——baseline.go 是唯一一份。这里只做两件事：
//  1. 跑对应的原生命令 / 读配置文件；
//  2. 把输出归一成判定层认识的词（enabled/disabled、1/0、encryption: on/off）。
//
// 哪些项在 Linux 上「不适用」（notApplicable，判定为 unknown 而不是 fail）：
//   SIP        系统完整性保护是 macOS 的机制。Linux 侧的近似物是 Secure Boot
//              + 模块签名，但语义不同（SIP 保护的是整个 /System），硬套会造出
//              一堆需要解释的假信号，所以标不适用。
//   GATEKEEPER 应用公证是 Apple 的生态机制；Linux 侧没有对应物。
//   FW_STEALTH 防火墙隐身模式是 pf/socketfilterfw 的概念。
//   GUEST      访客账户由显示管理器决定，各发行版不一致，不做猜测。
//   XPROTECT   Apple 的特征库；Linux 的恶意代码防护由 EDR/ClamAV 承担（EDR_AGENT 项覆盖）。
//   ARD        Apple 远程管理，Linux 无对应物。
//   TCC        Apple 的隐私权限数据库，Linux 无对应物（近似物是 AppArmor/SELinux 策略）。
//
// 这是可对外的差异说明：Linux 版覆盖 11/17 项，6 项显式标注「不适用」，
// 不做「假装检查过」。

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// linuxEDRPaths 常见商用 EDR/安全代理的安装位置。
var linuxEDRPaths = []string{
	"/opt/CrowdStrike",
	"/opt/sentinelone",
	"/usr/lib/sentinelone",
	"/opt/rapid7",
	"/opt/osquery",
	"/usr/local/bin/wazuh-agentd",
}

// linuxTimeSyncProcs 时间同步实现（systemd-timesyncd / chrony / ntp / openntpd）。
var linuxTimeSyncProcs = []string{"timesyncd", "chronyd", "ntpd", "timed"}

func platformProbeBaseline() error {
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		return fmt.Errorf("/proc 不可用，无法采集基线（容器未挂载 procfs？）")
	}
	return nil
}

func platformBaselineFacts(ctx context.Context) (baselineFacts, error) {
	var f baselineFacts

	f.SIP = notApplicable("Linux 无 SIP（系统完整性保护是 macOS 机制；近似物为 Secure Boot + 模块签名）")
	f.Gatekeeper = notApplicable("Linux 无 Gatekeeper（应用公证校验是 macOS 机制）")
	f.Stealth = notApplicable("Linux 无防火墙隐身模式的等价概念")
	f.Guest = notApplicable("Linux 无系统级访客账户（由显示管理器决定，各发行版不一致）")
	f.XProtect = notApplicable("XProtect 为 macOS 专有；Linux 侧恶意代码防护见 EDR_AGENT 项")

	f.FileVault = linuxDiskEncryption()
	f.Firewall = linuxFirewall(ctx)
	f.AutoUpdate = linuxAutoUpdate()
	f.AutoLogin = linuxAutoLogin()
	f.AskForPassword = linuxScreenLock(ctx)

	if rows, err := platformConns(ctx); err == nil {
		f.Ports = listenPortSet(rows)
		f.PortsKnown = true
	}

	f.EDRPresent, f.EDRKnown = presentPaths(linuxEDRPaths), true
	// ARD / TCC 在 Linux 上不存在：留 ARDKnown/TCCKnown=false，
	// 判定层给 unknown 而不是「未部署 = pass」。
	f.TimeSyncKnown, f.TimeSyncOn = linuxTimeSyncRunning(ctx)
	return f, nil
}

// linuxDiskEncryption 用 /etc/crypttab 判 LUKS。
//
// 为什么不是 lsblk：lsblk 的输出列顺序/字段名随 util-linux 版本变，而且
// 容器里常常没有；/etc/crypttab 是「配置层」的唯一事实来源——它非空就说明
// 系统在开机时确实要解锁加密卷。根分区未加密但数据盘加密的机器会给 pass，
// 这与「有加密」的语义一致（和 FileVault 只看根卷不完全等价，已在产品口径标注）。
func linuxDiskEncryption() cmdResult {
	data, ok := readTextFile("/etc/crypttab")
	if !ok {
		return notApplicable("读不到 /etc/crypttab，无法判断磁盘加密（容器/最小化镜像常见）")
	}
	for _, raw := range strings.Split(data, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name := strings.Fields(line)[0]
		return cmdResult{RC: 0, Text: fmt.Sprintf("%s (/etc/crypttab: %s)", cryptoOn, name)}
	}
	return cmdResult{RC: 0, Text: cryptoOff}
}

// linuxFirewall 依次试 ufw / firewalld / nft，把结论归一成 enabled/disabled。
//
// 顺序有讲究：ufw 在 Ubuntu 上是主开关，firewalld 在 RHEL 系是主开关；
// 两者都不在时才看 nft 有没有 ruleset（Debian 最小装常见裸 nftables）。
// 全都读不到 → notApplicable，不猜「没开」。
func linuxFirewall(ctx context.Context) cmdResult {
	if p, err := exec.LookPath("ufw"); err == nil {
		r := runBaselineCmd(ctx, 5*time.Second, p, "status")
		if r.RC == 0 {
			if n := normalizeFirewallText(r.Text); n != "" {
				return cmdResult{RC: 0, Text: n + " (ufw)"}
			}
		}
	}
	if p, err := exec.LookPath("firewall-cmd"); err == nil {
		r := runBaselineCmd(ctx, 5*time.Second, p, "--state")
		if n := normalizeFirewallText(r.Text); n != "" {
			return cmdResult{RC: 0, Text: n + " (firewalld)"}
		}
	}
	if p, err := exec.LookPath("nft"); err == nil {
		r := runBaselineCmd(ctx, 5*time.Second, p, "list", "ruleset")
		if r.RC == 0 && strings.Contains(r.Text, "table") {
			return cmdResult{RC: 0, Text: fwEnabled + " (nftables ruleset)"}
		}
		if r.RC == 0 {
			return cmdResult{RC: 0, Text: fwDisabled + " (nftables 无 ruleset)"}
		}
	}
	return notApplicable("本机没有 ufw/firewalld/nft，无法判断防火墙状态")
}

// linuxAutoUpdate 判自动更新：Debian 系看 unattended-upgrades，RHEL 系看 dnf-automatic。
// 归一成 "1"/"0"（判定层与 macOS 的 defaults 1/0 同一口径）。
func linuxAutoUpdate() cmdResult {
	// Debian/Ubuntu：20auto-upgrades 里 Update-Package-Lists "1" 才会真的检查更新
	if txt, ok := readTextFile("/etc/apt/apt.conf.d/20auto-upgrades"); ok {
		if strings.Contains(txt, `Update-Package-Lists "1"`) {
			return cmdResult{RC: 0, Text: "1"}
		}
		return cmdResult{RC: 0, Text: "0"}
	}
	if txt, ok := readTextFile("/etc/apt/apt.conf.d/10periodic"); ok {
		if strings.Contains(txt, `Update-Package-Lists "1"`) {
			return cmdResult{RC: 0, Text: "1"}
		}
		return cmdResult{RC: 0, Text: "0"}
	}
	// RHEL/Fedora：dnf-automatic 的 timer 启用即视为自动更新
	for _, p := range []string{
		"/etc/systemd/system/timers.target.wants/dnf-automatic.timer",
		"/usr/lib/systemd/system/dnf-automatic.timer",
	} {
		if _, err := os.Stat(p); err == nil {
			return cmdResult{RC: 0, Text: "1"}
		}
	}
	return notApplicable("未找到 apt/dnf 的自动更新配置，无法判断")
}

// linuxAutoLogin 读 GDM/LightDM 配置判自动登录。
//
// 判定层口径：RC==0 且 Text 非空 → fail（有人能免密进桌面）。
// 没配置文件 = 没开自动登录 → RC=1 空文本 → pass。
func linuxAutoLogin() cmdResult {
	candidates := []string{
		"/etc/gdm3/custom.conf",
		"/etc/gdm/custom.conf",
		"/etc/lightdm/lightdm.conf",
	}
	for _, p := range candidates {
		txt, ok := readTextFile(p)
		if !ok {
			continue
		}
		if user := parseAutologinConf(txt); user != "" {
			return cmdResult{RC: 0, Text: user}
		}
	}
	if _, err := os.Stat("/etc/gdm3"); err != nil {
		if _, err2 := os.Stat("/etc/lightdm"); err2 != nil {
			return notApplicable("本机未安装 GDM/LightDM，无法判断自动登录")
		}
	}
	return cmdResult{RC: 1}
}

// linuxScreenLock 用 gsettings 读 GNOME 的锁屏开关，归一成 "1"/"0"。
// gsettings 需要用户会话总线；服务态（root、无 DBus）下读不到 → notApplicable。
func linuxScreenLock(ctx context.Context) cmdResult {
	p, err := exec.LookPath("gsettings")
	if err != nil {
		return notApplicable("本机没有 gsettings，无法判断锁屏策略")
	}
	r := runBaselineCmd(ctx, 5*time.Second, p, "get", "org.gnome.desktop.screensaver", "lock-enabled")
	if r.RC != 0 {
		return notApplicable("gsettings 读不到锁屏配置（需要用户会话 DBus）")
	}
	switch parseBooleanPref(r.Text) {
	case "1":
		return cmdResult{RC: 0, Text: "1"}
	case "0":
		return cmdResult{RC: 0, Text: "0"}
	}
	return notApplicable("gsettings 返回值无法识别: " + strings.TrimSpace(r.Text))
}

// linuxTimeSyncRunning 看进程表里有没有时间同步实现。
func linuxTimeSyncRunning(ctx context.Context) (bool, bool) {
	procs, err := platformProcs(ctx)
	if err != nil {
		return false, false
	}
	return true, anyProcNameHasAny(procs, linuxTimeSyncProcs)
}
