package collector

// baseline_parse.go —— 基线检查用到的原生输出解析 / 归一化，**不带 build tag**。
//
// 为什么放无 tag 文件：这些函数都是「一段有格式的文本 → 判定需要的值」，
// 把 lsof / netsh / ufw / defaults / pkgutil 的样例贴进表驱动测试，在 macOS
// 上就能验证 Linux/Windows 的解析（本仓库 network_parse.go、
// persistence_parse.go 都是这个路子）。平台文件只负责跑命令，不做字符串手术。
//
// 归一化的用途：判定层（baseline.go）只有一份实现，它按 Python 版的口径
// 对 "enabled"/"disabled"/"1"/"0" 这类词做判断。非 macOS 平台把各自的原生
// 输出归一成同一套词，判定就不用复制第二份——复制就会漂移。

import (
	"regexp"
	"strconv"
	"strings"
)

// pkgVersionRe 对应 Python 的 `re.search(r"version:\s*(\S+)", txt)`。
var pkgVersionRe = regexp.MustCompile(`version:\s*(\S+)`)

// parsePkgutilVersion 从 `pkgutil --pkg-info` 的输出里取 version 字段。
//
//	package-id: com.apple.pkg.XProtectPlistConfigData_10_15.16U4463
//	version: 5270
//	volume: /
//
// 取不到返回 ok=false（判定层据此置 unknown，与 Python 同口径）。
func parsePkgutilVersion(text string) (string, bool) {
	m := pkgVersionRe.FindStringSubmatch(text)
	if m == nil || m[1] == "" {
		return "", false
	}
	return m[1], true
}

// versionNum 对应 Python 的 `int(re.sub(r"\D", "", ver)[:6] or 0)`：
// 去掉所有非数字字符、取前 6 位、空串按 0。
//
// 注意这是 Python 版的原样语义（"5270.100.1" → "52701001"[:6] = "527010"），
// 不是语义化版本比较。对拍要的是两边一致，不是「更正确」，所以照抄；
// 真要改成 semver 比较，必须两版一起改。
func versionNum(ver string) int {
	var b strings.Builder
	for _, r := range ver {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	d := b.String()
	if len(d) > 6 {
		d = d[:6]
	}
	if d == "" {
		return 0
	}
	n, err := strconv.Atoi(d)
	if err != nil {
		return 0
	}
	return n
}

// listenPortSet 从连接表里抽 TCP LISTEN 端口集合。
//
// 三平台的连接表已经由 platformConns() 归一成 netRow（lsof / /proc/net/tcp /
// netstat -ano，各自的解析器在 network_parse.go 且有测试），这里只做投影，
// 不再写第二套 lsof/netstat 解析器——两份解析必然漂移。
//
// 已知边界：非 root 时 lsof 只看得到当前用户的 socket，root 进程（例如
// launchd 持有的 sshd 22 端口）不会出现。Python 版在同样权限下同样是残缺
// 视图——这是数据源的权限语义，不是实现缺陷；产品口径要写明「非 root 采集」。
func listenPortSet(rows []netRow) map[int]bool {
	ports := map[int]bool{}
	for _, r := range rows {
		if r.Proto != "TCP" {
			continue
		}
		if r.State != "LISTEN" || r.LPort <= 0 {
			continue
		}
		ports[r.LPort] = true
	}
	return ports
}

// 状态词。判定层认这些词，平台层负责把原生输出翻译过来。
const (
	fwEnabled  = "enabled"
	fwDisabled = "disabled"
	// 磁盘加密的归一词汇。macOS 走 fdesetup 原文，其余平台翻成这两个词，
	// 判定只有一份（baseline.go 的 FILEVAULT 分支）。
	cryptoOn  = "encryption: on"
	cryptoOff = "encryption: off"
)

// normalizeFirewallText 把各平台防火墙状态输出归一成
// "enabled" / "disabled"（判定层按 Python 的口径只认这两个词）。
//
// 支持的输入：
//
//	macOS  socketfilterfw: "Firewall is enabled. (State = 1)" / "Firewall is disabled. (State = 0)"
//	Linux  ufw:            "Status: active" / "Status: inactive"
//	Linux  firewalld:      "running" / "not running"
//	Linux  nft:            有 ruleset 输出即视为启用
//	Windows netsh:         "State                                 ON" / "OFF"
//
// 判不准一律返回 "disabled"？不——返回空串，让调用方填 Missing，
// 免得把「读不懂」当成「没开」。
func normalizeFirewallText(text string) string {
	low := strings.ToLower(text)
	switch {
	case strings.Contains(low, "not running"):
		return fwDisabled
	case strings.Contains(low, "inactive"), strings.Contains(low, "disabled"):
		return fwDisabled
	case strings.Contains(low, "active"), strings.Contains(low, "running"),
		strings.Contains(low, "enabled"):
		return fwEnabled
	}
	// netsh: 逐 profile 打印 "State  ON"/"State  OFF"，全 ON 才算开
	on, off := countWord(low, "on"), countWord(low, "off")
	switch {
	case on > 0 && off == 0:
		return fwEnabled
	case off > 0:
		return fwDisabled
	}
	return ""
}

// countWord 数「独立单词」出现次数（避免 "on" 命中 "connection"）。
func countWord(s, word string) int {
	n, from := 0, 0
	for {
		i := strings.Index(s[from:], word)
		if i < 0 {
			return n
		}
		i += from
		beforeOK := i == 0 || !isWordByte(s[i-1])
		end := i + len(word)
		afterOK := end >= len(s) || !isWordByte(s[end])
		if beforeOK && afterOK {
			n++
		}
		from = i + 1
		if from >= len(s) {
			return n
		}
	}
}

// parseBooleanPref 把 defaults / 注册表读出来的布尔值归一成 "1" / "0"。
//
//	macOS defaults: "1" / "0" / "true" / "TRUE"
//	Windows REG_DWORD: "0x1" / "0x0"
//	文本: "yes"/"no"/"on"/"off"
//
// 认不出来返回空串（调用方据此置 unknown，不猜）。
func parseBooleanPref(text string) string {
	v := strings.ToLower(strings.TrimSpace(text))
	switch v {
	case "1", "true", "yes", "on", "enabled":
		return "1"
	case "0", "false", "no", "off", "disabled":
		return "0"
	}
	if strings.HasPrefix(v, "0x") {
		if n, err := strconv.ParseInt(v[2:], 16, 64); err == nil {
			if n == 0 {
				return "0"
			}
			return "1"
		}
	}
	if n, err := strconv.Atoi(v); err == nil {
		if n == 0 {
			return "0"
		}
		return "1"
	}
	return ""
}

// parseRegDword 从 `reg query ... /v NAME` 的输出里取指定值的原始文本。
//
//	HKEY_LOCAL_MACHINE\SOFTWARE\...\Winlogon
//	    AutoAdminLogon    REG_SZ    1
//
// 复用 parseRegQuery（persistence_parse.go）保证两处认同一套格式。
func parseRegDword(text, name string) (string, bool) {
	for _, e := range parseRegQuery(text) {
		if strings.EqualFold(strings.TrimSpace(e.Name), name) {
			return e.Value, true
		}
	}
	return "", false
}

// parseScreenSaverSecure 判定 Windows 的「唤醒需密码」：
// ScreenSaverIsSecure=1 且 ScreenSaveActive=1。
// 两个键都可能缺失（缺 = 默认不安全），返回归一后的 "1"/"0"。
func parseScreenSaverSecure(active, secure string) string {
	a := parseBooleanPref(active)
	s := parseBooleanPref(secure)
	if a == "1" && s == "1" {
		return "1"
	}
	return "0"
}

// parseAutologinConf 从 Linux 的 GDM/LightDM 配置里取自动登录用户名。
// 命中返回用户名；没配置返回空串。注释行（#）跳过。
//
//	[daemon]
//	AutomaticLoginEnable=True
//	AutomaticLogin=alice
func parseAutologinConf(text string) string {
	enabled := false
	user := ""
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch strings.ToLower(k) {
		case "automaticloginenable", "autologin-enable":
			enabled = parseBooleanPref(v) == "1"
		case "automaticlogin", "autologin-user":
			user = v
		}
	}
	if enabled && user != "" {
		return user
	}
	return ""
}
