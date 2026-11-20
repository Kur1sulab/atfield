// baseline.go —— 安全基线（加固姿态 / 暴露面）的判定与差分。
//
// 对标 Python 版 atfield/collectors/baseline.py（319 行）。
//
// 关于「8 项暴露面检查（secheaders/webfiles 等）」：当前 Python 版里已经
// 没有 secheaders / webfiles 这两项——那一批检查随外联/Web 模块一起删掉了
// （`grep -rn "secheaders\|webfiles" ~/aegis` 零命中）。以实际代码为准，
// 现在是 17 项，全部是本地姿态检查：
//
//	SIP GATEKEEPER FILEVAULT FIREWALL FW_STEALTH SSH_EXPOSED SHARING
//	AUTOUPDATE AUTOLOGIN GUEST SCREENLOCK XPROTECT EDR_AGENT ARD
//	TIMESYNC PRIVMON TCC
//
// 一项都不能少：验收标准是「同一事件流两版告警集合逐条一致」，少一项
// 就是少一路告警。
//
// 分层纪律（与 network/persistence 同一套）：
//
//	baseline.go           检查表 + 判定 + 状态差分 + 事件组装（无 build tag）
//	baseline_parse.go     原生输出的纯文本解析（无 build tag）
//	baseline_<os>.go      只做「跑命令 / 读文件 → baselineFacts」
//
// **平台层不允许决定 status**。判定只有这一份实现，否则三平台各写一遍，
// 三份必然各自漂移，对拍就失去意义。平台层唯一被允许表达的是「本平台没有
// 这个机制」——填 cmdResult.Missing=true，判定统一降为 unknown。
//
// 为什么「命令缺失」必须判 unknown 而不是 fail：Python 版跑在 macOS 上，
// csrutil/socketfilterfw 一定存在，所以它的 fail 分支是可信的。Go 版要跑
// Linux/Windows，`spctl` 在那里根本不存在；若把「命令不存在」当成
// 「输出里没有 enabled」，Linux 上会凭空冒出 6 条 high 级假告警。宁可
// unknown（UI 会标成「不适用」），也不许造假信号。
//
// ── 真机实测与降噪记录（macOS 26 / darwin-arm64 / 非 root，2026-11）──
//
// 17 项 → 9 pass / 3 warn / 1 fail / 4 unknown，首轮审计事件 4 条，耗时 151ms。
// 逐条核对过，4 条都是真的，**没有加白名单**：
//
//	FIREWALL   fail   "Firewall is disabled. (State = 0)"   本机防火墙确实没开
//	FW_STEALTH warn   "Firewall stealth mode is off"        确实没开
//	EDR_AGENT  warn   五个商用 EDR 路径都不存在              确实没装
//	ARD        warn   ARDAgent 正在监听 3283，属已部署       确实是部署状态
//
// 4 条 unknown 也不是漏采，而是「采到了但读不懂/读不到」，与 Python 版逐条一致：
//
//	AUTOUPDATE  键在 macOS 26 已迁移，defaults 读不到（Python 同样 unknown）
//	SCREENLOCK  com.apple.screensaver 域已不存在（Python 同样 unknown）
//	XPROTECT    收据包名带版本后缀，老包名读不到（**故意不 glob**，见 darwin 文件注释）
//	TCC         本机没有 TCC.db（Python 同样 unknown）
//
// 所以这一版没有引入任何白名单/阈值收敛。真要收敛，位置只能是
// judgeBaseline 里对应分支的判据（不是在平台层过滤数据——那会让 evidence
// 与 Python 对不上）。历史上 process.go 那三次降噪（ps 截断、隐藏目录白名单、
// base64 条件化）是因为它做的是「可疑性推断」；基线检查做的是「配置事实
// 核对」，事实不需要收敛，只需要把读不到的情况说清楚。
package collector

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Kur1sulab/atfield/internal/model"
)

// EventBaselineDrift 基线状态由好转坏（与 Python 版 kind 完全一致）。
const EventBaselineDrift = "baseline.drift"

// 检查状态。顺序即严重方向，差分靠 statusRank 比较。
const (
	baselinePass    = "pass"
	baselineWarn    = "warn"
	baselineFail    = "fail"
	baselineUnknown = "unknown"
)

// statusRank 与 Python 版 `worse = {"pass":0,"unknown":1,"warn":2,"fail":3}` 同值。
// 未识别的状态按 0 处理（Python 用 .get(status, 0)，宁可漏报也不误报）。
func statusRank(s string) int {
	switch s {
	case baselineWarn:
		return 2
	case baselineFail:
		return 3
	case baselineUnknown:
		return 1
	}
	return 0
}

// cmdResult 一条外部命令 / 文件读取的结果，对应 Python 的 (rc, stdout+stderr)。
//
//	RC      退出码；Python 版命令不可执行时返回 127
//	Text    合并输出（stdout+stderr，Python 版就是这么拼的，evidence 取它）
//	Missing 本平台没有这个命令/机制。判定一律 unknown，理由写 Text
type cmdResult struct {
	RC      int
	Text    string
	Missing bool
}

// baselineFacts 平台层采集到的原始事实。判定层只读这里，不看平台。
type baselineFacts struct {
	// SIP / Gatekeeper / FileVault：原生命令输出原文
	SIP        cmdResult
	Gatekeeper cmdResult
	FileVault  cmdResult

	// 防火墙总开关 / 隐身模式。非 macOS 平台可以在平台层把输出归一成
	// 含 "enabled" / "disabled" 的一行文本——判定逻辑不变（Python 就是
	// 对 "enabled"/"disabled" 做子串判断）。
	Firewall cmdResult
	Stealth  cmdResult

	// 监听端口（TCP LISTEN）。PortsKnown=false 表示这轮压根没读到连接表，
	// 此时两条端口类检查必须 unknown——不能因为「没看见 22」就说「没开 SSH」。
	Ports      map[int]bool
	PortsKnown bool

	// defaults 读出来的偏好项（非 macOS 平台用各自的等价来源填充）
	AutoUpdate          cmdResult
	AutoLogin           cmdResult
	Guest               cmdResult
	AskForPassword      cmdResult
	AskForPasswordDelay cmdResult

	// XProtect 特征库（pkgutil 原文）
	XProtect cmdResult

	// EDR 代理：已命中的路径（Python 版是 os.path.exists 的过滤结果）
	EDRPresent []string
	EDRKnown   bool // false = 本平台没有可查的 EDR 清单

	// ARD：plist 是否存在 / 是否放开 All Local Users。
	// ARDKnown=false 表示本平台没有 ARD 这个概念（Linux/Windows），判定置
	// unknown 而不是「未部署 = pass」——pass 会被评分层读成「这项检查过了」。
	ARDKnown    bool
	ARDExists   bool
	ARDAllUsers bool

	// 时间同步服务是否在跑（Python 判 psutil 进程名含 "timed"）
	TimeSyncKnown bool
	TimeSyncOn    bool

	// 本会话捕获的认证失败次数（Python: store.counters["auth.fail"]）
	AuthFails int

	// TCC 数据库。TCCKnown=false 表示本平台没有 TCC（Linux/Windows）。
	TCCKnown  bool
	TCCExists bool
	TCC       cmdResult
}

// baselineSpec 检查项元数据。顺序、ID、中文名、分类、权重与 Python 版逐字一致
// ——顺序决定 results 数组顺序，进而决定 counts 与告警输出顺序，对拍会比。
type baselineSpec struct {
	ID       string
	Name     string
	Category string
	Weight   int
}

var baselineSpecs = []baselineSpec{
	{"SIP", "系统完整性保护 SIP", "系统安全", 12},
	{"GATEKEEPER", "Gatekeeper 应用公证校验", "系统安全", 10},
	{"FILEVAULT", "磁盘加密 FileVault", "数据保护", 12},
	{"FIREWALL", "应用层防火墙", "网络防线", 10},
	{"FW_STEALTH", "防火墙隐身模式", "网络防线", 4},
	{"SSH_EXPOSED", "SSH 远程登录", "暴露面", 8},
	{"SHARING", "文件共享 / 屏幕共享 / RDP", "暴露面", 10},
	{"AUTOUPDATE", "自动检查更新", "补丁管理", 8},
	{"AUTOLOGIN", "自动登录（免密进桌面）", "身份与会话", 10},
	{"GUEST", "访客账户", "身份与会话", 5},
	{"SCREENLOCK", "唤醒需密码", "身份与会话", 8},
	{"XPROTECT", "XProtect 恶意软件特征库", "恶意代码防护", 6},
	{"EDR_AGENT", "第三方 EDR / 安全代理", "恶意代码防护", 6},
	{"ARD", "Apple 远程管理 ARD", "暴露面", 8},
	{"TIMESYNC", "时间同步", "系统安全", 3},
	{"PRIVMON", "提权与认证失败监控", "身份与会话", 5},
	{"TCC", "敏感权限授权（TCC）", "数据保护", 6},
}

// baselineCheck 一条检查结论。字段名与顺序对齐 Python 的 dict 字面量
// （id,name,category,weight,status,severity,evidence,advice,ts），
// 这份 JSON 会原样进 store.state["baseline"]，UI/评分/合规映射都读它。
type baselineCheck struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`
	Category string  `json:"category"`
	Weight   int     `json:"weight"`
	Status   string  `json:"status"`
	Severity string  `json:"severity"`
	Evidence string  `json:"evidence"`
	Advice   string  `json:"advice"`
	TS       float64 `json:"ts"`
}

func newCheck(s baselineSpec, ts float64) baselineCheck {
	// Python: {"status":"unknown","severity":"info","evidence":"","advice":""}
	return baselineCheck{
		ID: s.ID, Name: s.Name, Category: s.Category, Weight: s.Weight,
		Status: baselineUnknown, Severity: "info", TS: ts,
	}
}

// riskySharePorts 高危共享服务。顺序 = Python 版 dict 的插入顺序
// （445,548,5900,3389,139）——evidence 里的枚举顺序参与对拍，别重排。
var riskySharePorts = []struct {
	Port int
	Name string
}{
	{445, "SMB"},
	{548, "AFP"},
	{5900, "屏幕共享(VNC)"},
	{3389, "RDP"},
	{139, "NetBIOS"},
}

// stealthAdvice 隐身模式建议文案。Python 用 f-string 拼了完整路径，
// 对拍是逐字比 evidence/advice，所以路径必须写死同一份。
const stealthAdvice = "/usr/libexec/applicationfirewall/socketfilterfw --setstealthmode on —— 减少被局域网扫描发现"

// xprotectMinVersion Python 版用「特征库版本号里的数字前 6 位 >= 5270」判断新旧。
// 5270 是 2023 年 XProtect 的版本水位；低于它就是长期没更新过系统。
const xprotectMinVersion = 5270

// judgeBaseline 把原始事实判成 17 条检查结论。纯函数，四平台共用。
func judgeBaseline(f baselineFacts, now float64) []baselineCheck {
	out := make([]baselineCheck, 0, len(baselineSpecs))

	// 1. SIP
	c := newCheck(baselineSpecs[0], now)
	switch {
	case f.SIP.Missing:
		c.Evidence = f.SIP.Text
	case strings.Contains(f.SIP.Text, "enabled") && !strings.Contains(f.SIP.Text, "disabled"):
		c.Status = baselinePass
		c.Evidence = "csrutil: enabled"
	case strings.Contains(f.SIP.Text, "disabled"):
		c.Status = baselineFail
		c.Severity = "high"
		c.Evidence = strings.TrimSpace(f.SIP.Text)
		c.Advice = "csrutil enable（需恢复模式）——攻击者可任意改写系统文件与内核扩展"
	}
	// 其余情况保持 unknown、evidence 留空——Python 版这里没有 else 分支，
	// 逐字对齐：宁可显示「未知」也不猜。
	out = append(out, c)

	// 2. Gatekeeper
	c = newCheck(baselineSpecs[1], now)
	switch {
	case f.Gatekeeper.Missing:
		c.Evidence = f.Gatekeeper.Text
	case strings.Contains(f.Gatekeeper.Text, "assessments enabled"):
		c.Status = baselinePass
		c.Evidence = strings.TrimSpace(f.Gatekeeper.Text)
	default:
		c.Status = baselineFail
		c.Severity = "medium"
		c.Evidence = strings.TrimSpace(f.Gatekeeper.Text)
		c.Advice = "spctl --global-enable —— 当前可运行未公证/未签名应用"
	}
	out = append(out, c)

	// 3. 磁盘加密
	//
	// macOS 的口径是 fdesetup 原文（"FileVault is On." / "FileVault is Off."）。
	// 非 macOS 平台在平台层把各自的磁盘加密状态归一成 "encryption: on/off"
	// （Linux: LUKS，Windows: BitLocker），判定仍走这一份，不复制第二份逻辑。
	c = newCheck(baselineSpecs[2], now)
	switch {
	case f.FileVault.Missing:
		c.Evidence = f.FileVault.Text
	case strings.Contains(f.FileVault.Text, "FileVault is On"),
		strings.Contains(f.FileVault.Text, cryptoOn):
		c.Status = baselinePass
		c.Evidence = "FileVault is On"
		if !strings.Contains(f.FileVault.Text, "FileVault is On") {
			c.Evidence = strings.TrimSpace(f.FileVault.Text) // 非 macOS：保留平台原文，便于人工核对
		}
	case strings.Contains(f.FileVault.Text, "Off"),
		strings.Contains(f.FileVault.Text, cryptoOff):
		c.Status = baselineFail
		c.Severity = "high"
		c.Evidence = strings.TrimSpace(f.FileVault.Text)
		c.Advice = "启用 FileVault —— 设备丢失即等于数据泄露"
	default:
		c.Evidence = truncRunes(strings.TrimSpace(f.FileVault.Text), 200)
	}
	out = append(out, c)

	// 4. 应用层防火墙
	c = newCheck(baselineSpecs[3], now)
	switch {
	case f.Firewall.Missing:
		c.Evidence = f.Firewall.Text
	default:
		low := strings.ToLower(f.Firewall.Text)
		if strings.Contains(low, "enabled") && !strings.Contains(low, "disabled") {
			c.Status = baselinePass
			c.Evidence = strings.TrimSpace(f.Firewall.Text)
		} else {
			c.Status = baselineFail
			c.Severity = "medium"
			c.Evidence = orDefault(strings.TrimSpace(f.Firewall.Text), "未启用")
			c.Advice = "系统设置 → 网络 → 防火墙 → 打开"
		}
	}
	out = append(out, c)

	// 5. 防火墙隐身模式
	c = newCheck(baselineSpecs[4], now)
	switch {
	case f.Stealth.Missing:
		c.Evidence = f.Stealth.Text
	default:
		low := strings.ToLower(f.Stealth.Text)
		if strings.Contains(low, "enabled") && !strings.Contains(low, "disabled") {
			c.Status = baselinePass
			c.Evidence = strings.TrimSpace(f.Stealth.Text)
		} else {
			c.Status = baselineWarn
			c.Severity = "low"
			c.Evidence = orDefault(strings.TrimSpace(f.Stealth.Text), "未开启")
			c.Advice = stealthAdvice
		}
	}
	out = append(out, c)

	// 6. SSH 暴露面
	//
	// 与 Python 唯一的语义差异（只影响「连接表压根没读到」这一种情况）：
	// Python 的 _listening_ports() 把异常吞掉后返回空集合，于是 lsof 失败
	// 也会得出「未监听 22/tcp = pass」——那是把自己没看见当成没发生。
	// 这里改成 unknown 并写清原因。正常机器上 PortsKnown 恒为 true，
	// 事件集合与 Python 完全一致。
	c = newCheck(baselineSpecs[5], now)
	switch {
	case !f.PortsKnown:
		c.Evidence = "读不到连接表，无法判断 SSH 是否对外监听"
	case f.Ports[22]:
		c.Status = baselineWarn
		c.Severity = "medium"
		c.Evidence = "22/tcp 正在监听"
		c.Advice = "确认确有远程运维需求；否则关闭「远程登录」，并限制来源 IP"
	default:
		c.Status = baselinePass
		c.Evidence = "未监听 22/tcp"
	}
	out = append(out, c)

	// 7. 文件共享 / 屏幕共享 / RDP
	c = newCheck(baselineSpecs[6], now)
	if !f.PortsKnown {
		c.Evidence = "读不到连接表，无法判断共享服务是否对外监听"
	} else {
		var live []string
		for _, rp := range riskySharePorts {
			if f.Ports[rp.Port] {
				live = append(live, fmt.Sprintf("%d/%s", rp.Port, rp.Name))
			}
		}
		if len(live) > 0 {
			c.Status = baselineFail
			c.Severity = "high"
			c.Evidence = "正在监听: " + strings.Join(live, ", ")
			c.Advice = "关闭不用的共享服务；确需使用则绑定内网并加白名单"
		} else {
			c.Status = baselinePass
			c.Evidence = "未发现 SMB/AFP/VNC/RDP 监听"
		}
	}
	out = append(out, c)

	// 8. 自动检查更新
	c = newCheck(baselineSpecs[7], now)
	upd := strings.TrimSpace(f.AutoUpdate.Text)
	switch {
	case f.AutoUpdate.Missing:
		c.Evidence = f.AutoUpdate.Text
	case upd == "1" || upd == "true" || upd == "TRUE":
		c.Status = baselinePass
		c.Evidence = "AutomaticCheckEnabled=1"
	case f.AutoUpdate.RC != 0:
		c.Status = baselineUnknown
		c.Evidence = "无法读取 SoftwareUpdate 偏好"
	default:
		c.Status = baselineWarn
		c.Severity = "medium"
		c.Evidence = "AutomaticCheckEnabled=" + upd
		c.Advice = "启用自动更新，降低「补丁滞后 N 个月」类风险"
	}
	out = append(out, c)

	// 9. 自动登录
	c = newCheck(baselineSpecs[8], now)
	login := strings.TrimSpace(f.AutoLogin.Text)
	switch {
	case f.AutoLogin.Missing:
		c.Evidence = f.AutoLogin.Text
	case f.AutoLogin.RC == 0 && login != "":
		c.Status = baselineFail
		c.Severity = "high"
		c.Evidence = "autoLoginUser=" + login
		c.Advice = "关闭自动登录 —— 物理接触即等于登录成功"
	default:
		c.Status = baselinePass
		c.Evidence = "未配置自动登录"
	}
	out = append(out, c)

	// 10. 访客账户
	c = newCheck(baselineSpecs[9], now)
	guest := strings.TrimSpace(f.Guest.Text)
	switch {
	case f.Guest.Missing:
		c.Evidence = f.Guest.Text
	case f.Guest.RC == 0 && (guest == "1" || guest == "true" || guest == "TRUE"):
		c.Status = baselineWarn
		c.Severity = "medium"
		c.Evidence = "GuestEnabled=1"
		c.Advice = "关闭访客账户，避免无凭据本地访问"
	default:
		c.Status = baselinePass
		c.Evidence = "访客账户未启用"
	}
	out = append(out, c)

	// 11. 唤醒需密码
	c = newCheck(baselineSpecs[10], now)
	ask := strings.TrimSpace(f.AskForPassword.Text)
	switch {
	case f.AskForPassword.Missing:
		c.Evidence = f.AskForPassword.Text
	case ask == "1":
		delay := strings.TrimSpace(f.AskForPasswordDelay.Text)
		if delay == "" {
			delay = "0"
		}
		d := parseFloatOr(delay, 0)
		if d <= 60 {
			c.Status = baselinePass
			c.Evidence = fmt.Sprintf("askForPassword=1 delay=%ss", delay)
		} else {
			c.Status = baselineWarn
			c.Severity = "medium"
			c.Evidence = fmt.Sprintf("锁屏 %ss 后才要求密码", delay)
			c.Advice = "把「需要密码」设为立即"
		}
	case f.AskForPassword.RC != 0:
		c.Status = baselineUnknown
		c.Evidence = "该 macOS 版本改由 MDM/新 API 管理锁屏策略"
	default:
		c.Status = baselineFail
		c.Severity = "high"
		c.Evidence = "askForPassword=" + ask
		c.Advice = "开启「进入睡眠或屏幕保护后立即要求密码」"
	}
	out = append(out, c)

	// 12. XProtect 特征库
	c = newCheck(baselineSpecs[11], now)
	if f.XProtect.Missing {
		c.Evidence = f.XProtect.Text
	} else if ver, ok := parsePkgutilVersion(f.XProtect.Text); ok {
		if versionNum(ver) >= xprotectMinVersion {
			c.Status = baselinePass
			c.Evidence = "XProtect 特征库 " + ver
		} else {
			c.Status = baselineWarn
			c.Severity = "medium"
			c.Evidence = "XProtect 特征库偏旧: " + ver
			c.Advice = "保持系统更新以刷新特征库"
		}
	} else {
		c.Evidence = truncRunes(strings.TrimSpace(f.XProtect.Text), 200)
	}
	out = append(out, c)

	// 13. 第三方 EDR
	c = newCheck(baselineSpecs[12], now)
	switch {
	case !f.EDRKnown:
		c.Evidence = "本平台没有可查的 EDR 清单"
	case len(f.EDRPresent) > 0:
		names := make([]string, 0, len(f.EDRPresent))
		for _, p := range f.EDRPresent {
			names = append(names, filepath.Base(p))
		}
		c.Status = baselinePass
		c.Evidence = "已装: " + strings.Join(names, ", ")
	default:
		c.Status = baselineWarn
		c.Severity = "low"
		c.Evidence = "未发现常见商用 EDR 代理"
		c.Advice = "本机安全依赖 心之壁 自身检测能力，建议叠加一层商业 EDR 做纵深"
	}
	out = append(out, c)

	// 14. ARD
	c = newCheck(baselineSpecs[13], now)
	switch {
	case !f.ARDKnown:
		c.Evidence = "本平台无 Apple 远程管理（ARD）"
	case f.ARDExists && f.ARDAllUsers:
		c.Status = baselineFail
		c.Severity = "high"
		c.Evidence = "ARD 允许任意本地用户被远程控制"
		c.Advice = "关闭「远程管理」中的 All Local Users 授权"
	case f.ARDExists:
		c.Status = baselineWarn
		c.Severity = "medium"
		c.Evidence = "ARD 已部署"
		c.Advice = "确认远程管理需求与授权用户清单"
	default:
		c.Status = baselinePass
		c.Evidence = "未部署 ARD"
	}
	out = append(out, c)

	// 15. 时间同步
	c = newCheck(baselineSpecs[14], now)
	switch {
	case !f.TimeSyncKnown:
		c.Evidence = "本平台无法枚举进程表"
	case f.TimeSyncOn:
		c.Status = baselinePass
		c.Evidence = "timed 时间同步服务在运行"
	default:
		c.Status = baselineWarn
		c.Severity = "low"
		c.Evidence = "未检测到 timed"
		c.Advice = "时间漂移会导致日志时间线失真与证书校验失败"
	}
	out = append(out, c)

	// 16. 提权 / 认证失败监控
	c = newCheck(baselineSpecs[15], now)
	switch {
	case f.AuthFails == 0:
		c.Status = baselinePass
		c.Evidence = "本会话未捕获认证失败事件"
	case f.AuthFails < 5:
		c.Status = baselineWarn
		c.Severity = "low"
		c.Evidence = fmt.Sprintf("捕获 %d 次认证失败", f.AuthFails)
		c.Advice = "核对是否人为输错；持续失败即口令喷洒迹象"
	default:
		c.Status = baselineFail
		c.Severity = "high"
		c.Evidence = fmt.Sprintf("捕获 %d 次认证失败", f.AuthFails)
		c.Advice = "立即排查来源 IP，必要时封禁"
	}
	out = append(out, c)

	// 17. TCC
	c = newCheck(baselineSpecs[16], now)
	switch {
	case !f.TCCKnown:
		c.Evidence = "本平台无 TCC 权限数据库"
	case !f.TCCExists:
		c.Evidence = "未找到用户 TCC 数据库"
	case f.TCC.RC != 0 || strings.TrimSpace(f.TCC.Text) == "":
		c.Evidence = "无完全磁盘访问权限，TCC 库不可读"
	default:
		rows := splitNonEmptyLines(f.TCC.Text)
		c.Status = baselineWarn
		c.Severity = "low"
		c.Evidence = fmt.Sprintf("已授权 %d 条 TCC 记录（示例: %s）",
			len(rows), truncRunes(rows[0], 80))
		c.Advice = "定期清理不再需要的「屏幕录制/辅助功能/完全磁盘访问」授权"
	}
	out = append(out, c)

	return out
}

// countStatuses 与 Python 的 counts 字典同键同义（UI/评分读它）。
func countStatuses(results []baselineCheck) map[string]int {
	counts := map[string]int{
		baselinePass: 0, baselineWarn: 0, baselineFail: 0, baselineUnknown: 0,
	}
	for _, r := range results {
		counts[r.Status]++
	}
	return counts
}

// ---------------------------------------------------------------- 采集器

// Baseline 安全基线采集器（poll，默认 120s，与 Python 版 interval 一致）。
type Baseline struct {
	Base

	gather func(context.Context) (baselineFacts, error)
	// counters 认证失败计数来源（Python 读 store.counters["auth.fail"]）。
	// Go 版采集层还没有 store 依赖，用注入函数解耦；未注入时恒为 0，
	// 与 Python 在「本会话还没抓到失败事件」时完全一致。
	counters func(kind string) int
	// strictFirstRound 首轮不出任何事件 —— Python 的原样语义
	// （`if prev is None: continue`）。默认关闭：--once 跑一次就退出，
	// 严格模式下永远零输出。对拍时用 Options["first_round_audit"]=false 打开，
	// 两边事件集合即可逐条比较。
	strictFirstRound bool

	mu      sync.Mutex
	prev    map[string]string
	results []baselineCheck
	counts  map[string]int
	stateTS float64
}

// NewBaseline 构造并自检。
func NewBaseline(cfg Config) Collector {
	b := &Baseline{
		prev:   map[string]string{},
		counts: map[string]int{},
	}
	b.gather = platformBaselineFacts
	interval := 120 * time.Second
	if cfg.Interval > 0 {
		interval = cfg.Interval
	}
	b.Init("baseline", ModePoll, interval, platformProbeBaseline)
	if !cfg.WantEnabled() {
		b.Status.Enabled = false
	}
	// 对拍开关：Options["first_round_audit"]=false 即恢复 Python 的首轮静默。
	if v, ok := cfg.Options["first_round_audit"].(bool); ok && !v {
		b.strictFirstRound = true
	}
	return b
}

// SetCounters 注入事件流计数器（认证失败次数等）。
// 签名与 store.Counters 对齐：传 store.Counters 即可。
func (b *Baseline) SetCounters(fn func(kind string) int) { b.counters = fn }

// Items 本轮的检查项条数（main.go 的 --once 会打印，
// 否则「17 项检查出了 0 条事件」会被读成「什么都没查」）。
func (b *Baseline) Items() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.results) == 0 {
		return len(baselineSpecs)
	}
	return len(b.results)
}

// Results 最近一轮的检查结论（副本）。UI/合规映射用。
func (b *Baseline) Results() []baselineCheck {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]baselineCheck, len(b.results))
	copy(out, b.results)
	return out
}

// Counts 最近一轮的 pass/warn/fail/unknown 统计（副本）。
func (b *Baseline) Counts() map[string]int {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make(map[string]int, len(b.counts))
	for k, v := range b.counts {
		out[k] = v
	}
	return out
}

// State 与 Python 版 store.set_state("baseline", {...}) 同结构，
// 供未来的 store 层原样写入（键：results / ts / counts）。
func (b *Baseline) State() map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	results := make([]baselineCheck, len(b.results))
	copy(results, b.results)
	counts := make(map[string]int, len(b.counts))
	for k, v := range b.counts {
		counts[k] = v
	}
	return map[string]any{"results": results, "ts": b.stateTS, "counts": counts}
}

// Collect 采一轮：采集 → 判定 → 状态差分 → 事件。
//
// 差分的语义与 Python 完全一致：**只有由好转坏**才出事件，好转/持平不出，
// 免得每轮刷屏。worse 排序 pass(0) < unknown(1) < warn(2) < fail(3)。
//
// 与 Python 的一处有意差异（沿用 persistence.go 已经立下的先例）：
// Python 首轮只建基线、一条事件都不出（`prev is None: continue`）。那在
// 常驻服务里没问题，但 `atfieldd --once` 跑一次就退出，等于永远零输出，
// 审机器的人什么也看不到。所以首轮把「初始态」当成 unknown：
// unknown→warn/fail 本身就是 Python 定义里的变坏方向，事件照发，并在
// subject.baselined=false 里标明这是首轮审计而不是真漂移。对拍时按这个
// 键过滤掉首轮事件，两边集合即可逐条一致（persistence 用的是同一约定）。
func (b *Baseline) Collect(ctx context.Context) ([]model.Event, error) {
	facts, err := b.gather(ctx)
	if err != nil {
		return nil, err
	}
	if b.counters != nil {
		facts.AuthFails = b.counters("auth.fail")
	}
	now := float64(time.Now().UnixNano()) / 1e9
	results := judgeBaseline(facts, now)

	b.mu.Lock()
	defer b.mu.Unlock()
	if b.prev == nil {
		b.prev = map[string]string{}
	}

	var out []model.Event
	for i := range results {
		r := &results[i]
		prev, seen := b.prev[r.ID]
		b.prev[r.ID] = r.Status

		from := prev
		baselined := true
		if !seen {
			if b.strictFirstRound {
				continue // Python 原样语义：首轮只建基线
			}
			from, baselined = baselineUnknown, false
		}
		if from == r.Status {
			continue
		}
		if statusRank(r.Status) <= statusRank(from) {
			continue // 好转或持平：不出事件
		}
		ev := model.NewEvent(EventBaselineDrift, "baseline")
		ev.TS = now
		ev.Severity = r.Severity
		// Python: process=r["name"], path=r["id"]
		ev.Process = r.Name
		ev.Path = r.ID
		ev.Subject = map[string]any{
			"check": r.ID, "name": r.Name, "from": from,
			"to": r.Status, "evidence": r.Evidence,
		}
		if !baselined {
			ev.Subject["baselined"] = false
		}
		out = append(out, *ev)
	}

	b.results = results
	b.counts = countStatuses(results)
	b.stateTS = now
	return out, nil
}

// ---------------------------------------------------------------- 小工具

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// truncRunes 按字符截断（Python 的 txt[:200] 数的是字符不是字节，
// 中文 stderr 按字节切会切出半个字）。
func truncRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

func splitNonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

// parseFloatOr 解析浮点，失败给默认值（Python 的 try/except float() or 0.0）。
func parseFloatOr(s string, def float64) float64 {
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return def
	}
	return f
}
