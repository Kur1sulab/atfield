package detect

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Kur1sulab/atfield/internal/model"
)

// 内建规则集，逐条移植自 atfield/detect/rules_builtin.py（436 行，32 条）。
//
// ID 与顺序必须与 Python 侧完全一致：
// AEG-001…006 / 010…012 / 020…023 / 030…031 / 040…045 / 050…052 / 060…062 / 070…074。
// 顺序决定 Observe 的输出顺序（对拍要求告警集合与顺序都一致）。
// 逐条对照表见仓库根 MIGRATION-RULES.md。

// Python 侧所有正则都是 re.search(..., re.I)：Go 的 MatchString 同样是非锚定
// 搜索，加 (?i) 前缀即等价。这些模式不含反向引用/环视，RE2 可完整表达。
var (
	rePipeExec = regexp.MustCompile(
		`(?i)(curl|wget)[^|;&]*\|\s*(sudo\s+)?(ba|z|k)?sh|` +
			`(curl|wget)[^|;&]*\|\s*(python|perl|ruby|node)|osascript\s+-e`)
	reInterpOneLiner = regexp.MustCompile(`(?i)\b(python3?|perl|ruby|node|osascript)\s+(-c|-e)\b`)
	reB64Decode      = regexp.MustCompile(`(?i)base64\s+(-d|-D|--decode)|frombase64string|b64decode`)
	reRevShell       = regexp.MustCompile(
		`(?i)/dev/tcp/|nc\s+(-e|--exec)|ncat\s+(-e|--exec)|bash\s+-i\s*>&|` +
			`mkfifo\s+/tmp|socat\s+.*exec:|pty\.spawn`)
	reCredAccess = regexp.MustCompile(
		`(?i)(/\.ssh/id_|\.aws/credentials|\.config/gcloud|login\.keychain|` +
			`Cookies\.binarycookies|/etc/shadow|security\s+find-(generic|internet)-` +
			// Python 侧 _PW = "pa"+"ss"+"word"，拆写避免模板占位符替换。
			"pa" + "ss" + "word" + `)`)
	reDisableDefense = regexp.MustCompile(
		`(?i)(csrutil\s+disable|spctl\s+--master-disable|` +
			`socketfilterfw\s+--setglobalstate\s+off|` +
			`launchctl\s+(unload|bootout|disable).*(defender|falcon|sentinel|crowdstrike|mdm)|` +
			`tccutil\s+reset|killall\s+(XProtect|falconctl|sentineld))`)
	reDiscovery = regexp.MustCompile(
		`(?i)\b(whoami|id\b|hostname|ifconfig|netstat|system_profiler|dscl\s+\.|` +
			`arp\s+-a|ps\s+aux|launchctl\s+list|lsof\s+-i)\b`)
)

// suspDirs 可写/临时目录（rules_builtin.py:SUSP_DIRS）。顺序保持原样。
var suspDirs = []string{
	"/tmp/", "/private/tmp/", "/var/tmp/", "/Users/Shared/",
	"/private/var/folders/", "/dev/shm/",
}

// portScanThreshold 单进程 60 秒公网连接数阈值（rules_builtin.py）。
const portScanThreshold = 25

// ---------------- 小工具 ----------------

// cmdOf 对应 _ev_cmd：命令行 + 路径（Python 是 f"{cmdline} {path}"，空格恒存在）。
func cmdOf(ev *model.Event) string {
	return ev.Cmdline + " " + ev.Path
}

func containsAny(s string, subs []string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

func exeSuspicious(pid *int, c *Ctx) bool {
	return hasAnyPrefix(ExeOf(pid, c), suspDirs)
}

// ---------------- 情报闸门（rules_builtin.py 的 _ioc_*） ----------------

// iocHit 情报命中：intel 优先，其次配置里的明文名单。
//
// 查表顺序固定：match_ip（CIDR 最长前缀 + allowlist 前置）→ match_domain；
// 命中但衰减到期（score=0）→ 视为不再计分，**直接返回 nil 且不回落到配置**——
// 闸门的 allowlist/衰减结论必须压过静态名单。
func iocHit(ev *model.Event, ctx *Ctx) *IntelHit {
	rip := subStrOr(ev, "rip", "")
	raddr := subStrOr(ev, "raddr", "")
	if ctx != nil && ctx.Intel != nil {
		var hit *IntelHit
		if rip != "" {
			hit = ctx.Intel.MatchIP(rip)
		}
		if hit == nil && raddr != "" {
			hit = ctx.Intel.MatchDomain(raddr)
		}
		if hit != nil {
			if HitCounts(hit) {
				return hit
			}
			return nil
		}
		if iocAllowlisted(ctx.Intel, rip, raddr) {
			return nil
		}
	}
	cfg := Config{}
	if ctx != nil {
		cfg = ctx.cfg
	}
	if (rip != "" && containsStr(cfg.IOCIPS, rip)) ||
		(raddr != "" && containsStr(cfg.IOCDomains, raddr)) {
		// 明文名单没有来源/时间戳 → 只能按 low 置信进闸门分档（0.15 → medium）
		return &IntelHit{
			Value:     firstNonEmpty(raddr, rip),
			Source:    "config:ioc",
			Score:     ConfLow,
			Severity:  ScoreToSeverity(ConfLow),
			Lifecycle: "legacy-config",
		}
	}
	return nil
}

// iocAllowlisted allowlist 前置：保留/共享基础设施（RFC1918、回环、CGNAT、
// Cloudflare…）永不算 IOC。
func iocAllowlisted(intel Intel, rip, raddr string) bool {
	if intel == nil {
		return false
	}
	if rip != "" && intel.AllowedIP(rip) {
		return true
	}
	if raddr != "" && intel.AllowedDomain(raddr) {
		return true
	}
	return false
}

// iocSeverity AEG-043 定级：只认闸门算出来的 severity；不计分时返回 ""
// （Python 返回 None → 整条丢弃）。
func iocSeverity(ev *model.Event, ctx *Ctx) string {
	if hit := iocHit(ev, ctx); hit != nil {
		return HitSeverity(hit, "low")
	}
	return ""
}

func iocDetail(ev *model.Event, ctx *Ctx) string {
	hit := iocHit(ev, ctx)
	target := subOr(ev, "None", "raddr", "rip")
	if hit == nil {
		return fmt.Sprintf("命中情报库: %s（来源 -，分数 -，置信 -）", target)
	}
	return fmt.Sprintf("命中情报库: %s（来源 %s，分数 %s，置信 %s）",
		target, orDash(hit.Source), pyFloat(hit.Score), orDash(hit.Confidence))
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// ---------------- 规则清单 ----------------

// BuiltinRules 返回 32 条内建规则的副本（与 Python RULES 顺序一致）。
func BuiltinRules() []Rule {
	out := make([]Rule, 0, len(builtinRules))
	out = append(out, builtinRules...)
	return out
}

var builtinRules = []Rule{
	ruleAEG001(), ruleAEG002(), ruleAEG003(), ruleAEG004(), ruleAEG005(), ruleAEG006(),
	ruleAEG010(), ruleAEG011(), ruleAEG012(),
	ruleAEG020(), ruleAEG021(), ruleAEG022(), ruleAEG023(),
	ruleAEG030(), ruleAEG031(),
	ruleAEG040(), ruleAEG041(), ruleAEG042(), ruleAEG043(), ruleAEG044(), ruleAEG045(),
	ruleAEG050(), ruleAEG051(), ruleAEG052(),
	ruleAEG060(), ruleAEG061(), ruleAEG062(),
	ruleAEG070(), ruleAEG071(), ruleAEG072(), ruleAEG073(), ruleAEG074(),
}

// AEG-001 管道下载后直接执行
func ruleAEG001() Rule {
	return Rule{
		ID:          "AEG-001",
		Name:        "管道下载后直接执行",
		Severity:    "critical",
		Tags:        []string{"execution", "download"},
		MITRE:       []string{"T1059.004", "T1105"},
		Description: "curl/wget 输出直接管道进 shell 或解释器，是落地即执行最典型的手法。",
		Advice:      "立即确认该进程来源；阻断外联、保留命令行与父进程链作为证据。真实运维请走包管理与人工审核流程。",
		When: func(ev *model.Event, _ *Ctx) bool {
			return ev.Kind == "process.start" && rePipeExec.MatchString(cmdOf(ev))
		},
		Detail: func(ev *model.Event, _ *Ctx) string {
			return "命令行命中「下载即执行」模式: " + cut(ev.Cmdline, 200)
		},
	}
}

// AEG-002 解释器单行命令执行
func ruleAEG002() Rule {
	return Rule{
		ID:          "AEG-002",
		Name:        "解释器单行命令执行",
		Severity:    "medium",
		Tags:        []string{"execution", "fileless"},
		MITRE:       []string{"T1059.006", "T1027"},
		Description: "python -c / osascript -e 等无文件落地执行。",
		Advice:      "核对这条单行命令的内容；无源码落地的执行往往用于规避文件监控。",
		When: func(ev *model.Event, _ *Ctx) bool {
			return ev.Kind == "process.start" && reInterpOneLiner.MatchString(cmdOf(ev))
		},
		Detail: func(ev *model.Event, _ *Ctx) string {
			return ev.Process + ": " + cut(ev.Cmdline, 200)
		},
	}
}

// AEG-003 可写目录内的可执行文件
func ruleAEG003() Rule {
	return Rule{
		ID:          "AEG-003",
		Name:        "可写目录内的可执行文件",
		Severity:    "high",
		Tags:        []string{"execution"},
		MITRE:       []string{"T1036", "T1105"},
		Description: "从 /tmp、/Users/Shared 等可写目录启动进程。",
		Advice:      "临时目录里的可执行文件极少数是正当业务；先取证再清理，注意同目录可能有配套载荷。",
		When: func(ev *model.Event, _ *Ctx) bool {
			if ev.Kind != "process.start" {
				return false
			}
			return truthy(ev.Subject["suspicious_path"]) || hasAnyPrefix(ev.Path, suspDirs)
		},
		Detail: func(ev *model.Event, _ *Ctx) string {
			return "执行路径位于临时/共享目录: " + ev.Path
		},
	}
}

// AEG-004 进程名仿冒系统组件
func ruleAEG004() Rule {
	return Rule{
		ID:          "AEG-004",
		Name:        "进程名仿冒系统组件",
		Severity:    "high",
		Tags:        []string{"defense_evasion"},
		MITRE:       []string{"T1036.005"},
		Description: "进程名与系统进程同名但可执行路径不在系统目录（伪装）。",
		Advice:      "系统守护进程不应从用户目录或临时目录运行；核对哈希与签名后终止。",
		When: func(ev *model.Event, _ *Ctx) bool {
			return ev.Kind == "process.start" && truthy(ev.Subject["masquerade"])
		},
		Detail: func(ev *model.Event, _ *Ctx) string {
			return ev.Process + " 来自非系统路径 " + ev.Path
		},
	}
}

// AEG-005 Base64 解码后执行
func ruleAEG005() Rule {
	return Rule{
		ID:          "AEG-005",
		Name:        "Base64 解码后执行",
		Severity:    "high",
		Tags:        []string{"execution", "obfuscation"},
		MITRE:       []string{"T1027", "T1140"},
		Description: "使用 base64 解码并在同一命令行内执行。",
		Advice:      "还原解码后的内容再判断；这类命令常见于混淆载荷投放。",
		When: func(ev *model.Event, _ *Ctx) bool {
			return ev.Kind == "process.start" && reB64Decode.MatchString(cmdOf(ev))
		},
		Detail: func(ev *model.Event, _ *Ctx) string {
			return cut(ev.Cmdline, 240)
		},
	}
}

// AEG-006 反弹 Shell 特征
func ruleAEG006() Rule {
	return Rule{
		ID:          "AEG-006",
		Name:        "反弹 Shell 特征",
		Severity:    "critical",
		Tags:        []string{"execution", "c2"},
		MITRE:       []string{"T1059.004", "T1071"},
		Description: "/dev/tcp、nc -e、mkfifo 管道等反弹 shell 用法。",
		Advice:      "立刻定位对端地址与端口并封禁；抓取该进程的网络连接与父子链，勿直接重启丢证据。",
		When: func(ev *model.Event, _ *Ctx) bool {
			return ev.Kind == "process.start" && reRevShell.MatchString(cmdOf(ev))
		},
		Detail: func(ev *model.Event, _ *Ctx) string {
			return "命令行具备反弹 shell 特征: " + cut(ev.Cmdline, 200)
		},
	}
}

// AEG-010 新增 LaunchAgent / LaunchDaemon
func ruleAEG010() Rule {
	return Rule{
		ID:          "AEG-010",
		Name:        "新增 LaunchAgent / LaunchDaemon",
		Severity:    "high",
		Tags:        []string{"persistence"},
		MITRE:       []string{"T1543.001", "T1543.004"},
		Description: "配置目录出现新的 launchd 常驻项。",
		Advice:      "核对 Label 与 ProgramArguments 是否为已批准软件；可疑则 launchctl bootout 并删除 plist。",
		When: func(ev *model.Event, _ *Ctx) bool {
			return ev.Kind == "persistence.add"
		},
		Detail: func(ev *model.Event, _ *Ctx) string {
			return ev.Path + " → " + cut(ev.Cmdline, 160)
		},
	}
}

// AEG-011 持久化项被篡改
func ruleAEG011() Rule {
	return Rule{
		ID:          "AEG-011",
		Name:        "持久化项被篡改",
		Severity:    "high",
		Tags:        []string{"persistence", "defense_evasion"},
		MITRE:       []string{"T1543.001"},
		Description: "既有 launchd 项被修改（含被植入常驻逻辑）。",
		Advice:      "对比历史版本；被改写为 RunAtLoad+KeepAlive 的项要优先处置。",
		When: func(ev *model.Event, _ *Ctx) bool {
			return ev.Kind == "persistence.modify"
		},
		Detail: func(ev *model.Event, _ *Ctx) string {
			return ev.Path + " 内容变更"
		},
	}
}

// AEG-012 可疑持久化载荷
func ruleAEG012() Rule {
	return Rule{
		ID:          "AEG-012",
		Name:        "可疑持久化载荷",
		Severity:    "critical",
		Tags:        []string{"persistence", "c2"},
		MITRE:       []string{"T1543.001", "T1105"},
		Description: "常驻项的命令行/权限存在多项可疑特征。",
		Advice:      "该常驻项指向临时目录或含下载/解释器命令，符合后门常驻特征；建议立即隔离并取证。",
		When: func(ev *model.Event, _ *Ctx) bool {
			if ev.Kind != "persistence.add" && ev.Kind != "persistence.modify" {
				return false
			}
			return truthy(ev.Subject["suspicious"])
		},
		Detail: func(ev *model.Event, _ *Ctx) string {
			return cut(strings.Join(strSlice(ev.Subject["suspicious"]), "; "), 240)
		},
	}
}

// AEG-020 尝试关闭系统防护
func ruleAEG020() Rule {
	return Rule{
		ID:          "AEG-020",
		Name:        "尝试关闭系统防护",
		Severity:    "critical",
		Tags:        []string{"defense_evasion"},
		MITRE:       []string{"T1562.001"},
		Description: "csrutil disable / spctl --master-disable / tccutil reset 等降防护操作。",
		Advice:      "这类命令几乎不具备正当运维场景；先确认操作者身份，再评估是否已有后续载荷。",
		When: func(ev *model.Event, _ *Ctx) bool {
			if ev.Kind != "process.start" && ev.Kind != "defense.event" {
				return false
			}
			return reDisableDefense.MatchString(cmdOf(ev))
		},
		Detail: func(ev *model.Event, _ *Ctx) string {
			return "命中防护关闭类命令: " + cut(ev.Cmdline, 200)
		},
	}
}

// AEG-021 代码签名失效事件
func ruleAEG021() Rule {
	return Rule{
		ID:          "AEG-021",
		Name:        "代码签名失效事件",
		Severity:    "critical",
		Tags:        []string{"defense_evasion", "integrity"},
		MITRE:       []string{"T1553.001"},
		Description: "EndpointSecurity 报告进程代码签名失效（二进制被篡改/注入）。",
		Advice:      "进程二进制被替换或内存被改写；立刻导出可执行文件做哈希比对。",
		When: func(ev *model.Event, _ *Ctx) bool {
			return ev.Kind == "defense.cs_invalidated"
		},
		Detail: func(ev *model.Event, _ *Ctx) string {
			return ev.Process + " 签名校验失效: " + ev.Path
		},
	}
}

// AEG-022 Gatekeeper 被用户绕过
func ruleAEG022() Rule {
	return Rule{
		ID:          "AEG-022",
		Name:        "Gatekeeper 被用户绕过",
		Severity:    "high",
		Tags:        []string{"defense_evasion"},
		MITRE:       []string{"T1553.001", "T1204"},
		Description: "用户以「仍要打开」方式绕过 Gatekeeper。",
		Advice:      "确认是否为知情操作；未经批准的绕过往往用于运行未签名载荷。",
		When: func(ev *model.Event, _ *Ctx) bool {
			return ev.Kind == "defense.gatekeeper_override"
		},
		Detail: func(ev *model.Event, _ *Ctx) string {
			return ev.Process + ": " + cut(ev.Cmdline, 160)
		},
	}
}

// AEG-023 安全组件消失
func ruleAEG023() Rule {
	return Rule{
		ID:          "AEG-023",
		Name:        "安全组件消失",
		Severity:    "high",
		Tags:        []string{"defense_evasion"},
		MITRE:       []string{"T1562.001"},
		Description: "已安装的第三方安全代理/组件消失。",
		Advice:      "卸载 EDR 是攻击者标准动作之一；确认是否存在本地管理员权限滥用。",
		When: func(ev *model.Event, _ *Ctx) bool {
			return ev.Kind == "defense.removed"
		},
		Detail: func(ev *model.Event, _ *Ctx) string {
			return ev.Process + " 已不存在: " + ev.Path
		},
	}
}

// AEG-030 凭据文件访问
func ruleAEG030() Rule {
	return Rule{
		ID:          "AEG-030",
		Name:        "凭据文件访问",
		Severity:    "high",
		Tags:        []string{"credential_access"},
		MITRE:       []string{"T1552.001", "T1555.003"},
		Description: "访问 SSH 私钥、云凭据、钥匙串、浏览器 Cookie 等高价值文件。",
		Advice:      "判定是否为合法工具（如 ssh 使用密钥）；异常进程读取 id_rsa/keychain 后通常会立刻外联。",
		When: func(ev *model.Event, _ *Ctx) bool {
			if ev.Kind == "process.start" {
				return reCredAccess.MatchString(cmdOf(ev))
			}
			if ev.Kind == "file.open" || ev.Kind == "file.create" {
				return reCredAccess.MatchString(ev.Path)
			}
			return false
		},
		Detail: func(ev *model.Event, _ *Ctx) string {
			return ev.Process + " 触达凭据路径: " + firstNonEmpty(ev.Path, cut(ev.Cmdline, 120))
		},
	}
}

// AEG-031 钥匙串/凭据访问异常
func ruleAEG031() Rule {
	return Rule{
		ID:          "AEG-031",
		Name:        "钥匙串/凭据访问异常",
		Severity:    "medium",
		Tags:        []string{"credential_access"},
		MITRE:       []string{"T1555.001"},
		Description: "securityd 侧出现异常访问模式。",
		Advice:      "核对发起进程；批量钥匙串访问常见于信息窃取木马。",
		When: func(ev *model.Event, _ *Ctx) bool {
			return ev.Kind == "credential.access"
		},
		Detail: func(ev *model.Event, _ *Ctx) string {
			return subStrOr(ev, "note", "") + " " + cut(ev.Cmdline, 160)
		},
	}
}

// AEG-040 高危端口监听暴露
func ruleAEG040() Rule {
	return Rule{
		ID:          "AEG-040",
		Name:        "高危端口监听暴露",
		Severity:    "medium",
		Tags:        []string{"exposure"},
		MITRE:       []string{"T1046", "T1210"},
		Description: "Redis/MySQL/Docker/VNC 等高风险服务在本机监听。",
		Advice:      "关闭非必要服务；确需使用则限制来源地址并加认证。",
		When: func(ev *model.Event, _ *Ctx) bool {
			if ev.Kind != "net.listen" {
				return false
			}
			return ev.Severity == "high" || ev.Severity == "critical"
		},
		Detail: func(ev *model.Event, _ *Ctx) string {
			return subStr(ev, "service") + " 监听 " + subStr(ev, "addr") + " (" + ev.Process + ")"
		},
	}
}

// AEG-041 公网非常见端口外联
func ruleAEG041() Rule {
	return Rule{
		ID:          "AEG-041",
		Name:        "公网非常见端口外联",
		Severity:    "medium",
		Tags:        []string{"command_control"},
		MITRE:       []string{"T1571"},
		Description: "进程连接公网的非标准端口。",
		Advice:      "确认该外联是否为业务所需；非浏览器进程访问非常见端口是 C2 的典型特征。",
		When: func(ev *model.Event, _ *Ctx) bool {
			if ev.Kind != "net.connect" || !truthy(ev.Subject["public"]) {
				return false
			}
			rport, ok := intSubOr0(ev, "rport")
			if !ok {
				return false
			}
			switch rport {
			case 80, 443, 53, 123, 22, 993, 587, 5223, 8080, 8443:
				return false
			}
			return true
		},
		Detail: func(ev *model.Event, _ *Ctx) string {
			return ev.Process + " → " + subStr(ev, "raddr")
		},
	}
}

// AEG-042 命中 C2 端口
func ruleAEG042() Rule {
	return Rule{
		ID:          "AEG-042",
		Name:        "命中 C2 端口",
		Severity:    "critical",
		Tags:        []string{"command_control"},
		MITRE:       []string{"T1571", "T1071"},
		Description: "连接常见后门/C2 端口。",
		Advice:      "高置信后门端口；立刻封禁对端并定位发起进程的可执行文件。",
		When: func(ev *model.Event, _ *Ctx) bool {
			if ev.Kind != "net.connect" {
				return false
			}
			rport, ok := intSubOr0(ev, "rport")
			if !ok {
				return false
			}
			switch rport {
			case 4444, 4445, 1337, 31337, 6666, 6667, 6697, 9001, 12345, 54321:
				return true
			}
			return false
		},
		Detail: func(ev *model.Event, _ *Ctx) string {
			return ev.Process + " → " + subStr(ev, "raddr")
		},
	}
}

// AEG-043 命中威胁情报 IOC
func ruleAEG043() Rule {
	return Rule{
		ID:       "AEG-043",
		Name:     "命中威胁情报 IOC",
		Severity: "low",
		Tags:     []string{"command_control"},
		MITRE:    []string{"T1071"},
		Description: "外联地址命中情报库（config.yaml ioc.ips/domains 会一次性迁入闸门）。" +
			"等级由 intel.py 按 CIDR 最长前缀 + allowlist + 置信度衰减计算，不再写死。",
		Advice: "IOC 命中按闸门分档处置：critical/high 立即封禁并全网排查同源；" +
			"medium 先核对情报来源与业务归属（保留网段会被 allowlist 拦下）。",
		When: func(ev *model.Event, c *Ctx) bool {
			return ev.Kind == "net.connect" && iocHit(ev, c) != nil
		},
		Detail: iocDetail,
		// 动态定级：有它就是最终等级，不与 ev.Severity 取 max。
		SeverityFn: iocSeverity,
	}
}

// AEG-044 可疑进程对外连接
func ruleAEG044() Rule {
	return Rule{
		ID:          "AEG-044",
		Name:        "可疑进程对外连接",
		Severity:    "high",
		Tags:        []string{"command_control", "execution"},
		MITRE:       []string{"T1071", "T1036"},
		Description: "可执行文件位于临时/共享目录的进程建立公网连接。",
		Advice:      "临时目录里的进程对外通信，几乎只有两类：正常的安装器与后门。核对父进程与落地时间。",
		When: func(ev *model.Event, c *Ctx) bool {
			if ev.Kind != "net.connect" || !truthy(ev.Subject["public"]) {
				return false
			}
			return exeSuspicious(ev.PID, c)
		},
		Detail: func(ev *model.Event, c *Ctx) string {
			return ev.Process + " (" + ExeOf(ev.PID, c) + ") → " + subStr(ev, "raddr")
		},
	}
}

// AEG-045 单进程连接数异常（疑似扫描/横向）
func ruleAEG045() Rule {
	return Rule{
		ID:       "AEG-045",
		Name:     "单进程连接数异常（疑似扫描/横向）",
		Severity: "high",
		Tags:     []string{"discovery", "lateral_movement"},
		MITRE:    []string{"T1046"},
		Description: "单个进程短时间内大量对公网建连，符合端口扫描/横向探测特征" +
			"（仅统计公网目标，避免把本地代理/IDE 误判）。",
		Advice: "区分开发工具（如浏览器、IDE）与扫描器；后者应立刻终止并排查横向痕迹。",
		When: func(ev *model.Event, c *Ctx) bool {
			if ev.Kind != "net.connect" || !truthy(ev.Subject["public"]) {
				return false
			}
			return c.Reached("scan:"+pidStr(ev.PID), 60, portScanThreshold)
		},
		Detail: func(ev *model.Event, _ *Ctx) string {
			return fmt.Sprintf("%s(pid=%s) 60 秒内对公网建立超过 %d 个连接",
				ev.Process, pidStr(ev.PID), portScanThreshold)
		},
	}
}

// AEG-050 认证失败爆发
func ruleAEG050() Rule {
	return Rule{
		ID:          "AEG-050",
		Name:        "认证失败爆发",
		Severity:    "high",
		Tags:        []string{"credential_access"},
		MITRE:       []string{"T1110"},
		Description: "sudo/SSH 在短窗口内出现多次认证失败（口令爆破）。",
		Advice:      "核对来源 IP 与目标账户；口令喷洒需要立即在边界封禁，并检查是否已有成功登录。",
		When: func(ev *model.Event, c *Ctx) bool {
			return ev.Kind == "auth.fail" && c.Reached("authfail:"+ev.Process, 300, 6)
		},
		Detail: func(ev *model.Event, _ *Ctx) string {
			return ev.Process + " 5 分钟内多次认证失败"
		},
	}
}

// AEG-051 本地认证失败
func ruleAEG051() Rule {
	return Rule{
		ID:          "AEG-051",
		Name:        "本地认证失败",
		Severity:    "medium",
		Tags:        []string{"credential_access"},
		MITRE:       []string{"T1110"},
		Description: "捕获到单次认证失败事件。",
		Advice:      "确认是否人为输错；连续出现需按爆破事件处理。",
		When: func(ev *model.Event, _ *Ctx) bool {
			return ev.Kind == "auth.fail"
		},
		Detail: func(ev *model.Event, _ *Ctx) string {
			return firstNonEmpty(cut(ev.Cmdline, 200), subStrOr(ev, "note", ""))
		},
	}
}

// AEG-052 远程登录成功
func ruleAEG052() Rule {
	return Rule{
		ID:          "AEG-052",
		Name:        "远程登录成功",
		Severity:    "medium",
		Tags:        []string{"initial_access"},
		MITRE:       []string{"T1078", "T1021.004"},
		Description: "SSH 或远程会话登录成功。",
		Advice:      "比对是否为许可的运维来源；异常来源的登录必须立刻核实。",
		When: func(ev *model.Event, _ *Ctx) bool {
			if ev.Kind != "auth.success" && ev.Kind != "session.login" {
				return false
			}
			return truthy(ev.Subject["remote"]) || ev.Kind == "auth.success"
		},
		Detail: func(ev *model.Event, _ *Ctx) string {
			return firstNonEmpty(ev.User, "?") + " 从 " + subOr(ev, "远程", "from", "raw_process") + " 登录"
		},
	}
}

// AEG-060 关键安全文件被修改
func ruleAEG060() Rule {
	return Rule{
		ID:          "AEG-060",
		Name:        "关键安全文件被修改",
		Severity:    "critical",
		Tags:        []string{"persistence", "integrity"},
		MITRE:       []string{"T1098.004", "T1562.004"},
		Description: "SSH 授权文件、hosts、防火墙或 sudo 配置被改动。",
		Advice:      "authorized_keys/sshd_config 被改意味着可能已被植入持久访问；核对差异并回滚。",
		When: func(ev *model.Event, _ *Ctx) bool {
			if ev.Kind != "integrity.change" {
				return false
			}
			return containsAny(ev.Path, []string{
				"authorized_keys", "sshd_config", "sudoers", "pf.conf", "/etc/hosts",
			})
		},
		Detail: func(ev *model.Event, _ *Ctx) string {
			return ev.Path + ": " + subStr(ev, "reason")
		},
	}
}

// AEG-061 监控文件完整性变化
func ruleAEG061() Rule {
	return Rule{
		ID:          "AEG-061",
		Name:        "监控文件完整性变化",
		Severity:    "medium",
		Tags:        []string{"integrity"},
		MITRE:       []string{"T1565"},
		Description: "受监控文件内容/存在性变化。",
		Advice:      "确认变更来源；非预期变更应回滚并排查写入进程。",
		When: func(ev *model.Event, _ *Ctx) bool {
			return ev.Kind == "integrity.change"
		},
		Detail: func(ev *model.Event, _ *Ctx) string {
			return ev.Path + ": " + subStr(ev, "reason")
		},
	}
}

// AEG-062 安全基线劣化
func ruleAEG062() Rule {
	return Rule{
		ID:          "AEG-062",
		Name:        "安全基线劣化",
		Severity:    "high",
		Tags:        []string{"defense_evasion", "posture"},
		MITRE:       []string{"T1562"},
		Description: "安全基线检查项状态由好转坏。",
		Advice:      "基线由通过变为关注/不合格意味着防护被削弱，优先排查是否被人为关闭。",
		When: func(ev *model.Event, _ *Ctx) bool {
			return ev.Kind == "baseline.drift"
		},
		Detail: func(ev *model.Event, _ *Ctx) string {
			return subStr(ev, "name") + ": " + subStr(ev, "from") + " → " + subStr(ev, "to")
		},
	}
}

// AEG-070 疑似隐藏进程
func ruleAEG070() Rule {
	return Rule{
		ID:          "AEG-070",
		Name:        "疑似隐藏进程",
		Severity:    "high",
		Tags:        []string{"defense_evasion"},
		MITRE:       []string{"T1014", "T1564"},
		Description: "ps 与 psutil 进程视图不一致（可能被 rootkit/lldb 注入隐藏）。",
		Advice:      "正常系统不应出现两侧不一致；先固化 ps / psutil / lsof 三份输出再做判断。",
		When: func(ev *model.Event, _ *Ctx) bool {
			return ev.Kind == "process.hidden"
		},
		Detail: func(ev *model.Event, _ *Ctx) string {
			return "pid=" + pidStr(ev.PID) + " " + ev.Process + " 两套视图不一致"
		},
	}
}

// AEG-071 威胁情报文件痕迹
func ruleAEG071() Rule {
	return Rule{
		ID:          "AEG-071",
		Name:        "威胁情报文件痕迹",
		Severity:    "high",
		Tags:        []string{"malware"},
		MITRE:       []string{"T1204"},
		Description: "系统反恶意软件组件报出威胁。",
		Advice:      "XProtect 已判定恶意；按恶意软件处置流程隔离并检查同源投放。",
		When: func(ev *model.Event, _ *Ctx) bool {
			return ev.Kind == "av.detect"
		},
		Detail: func(ev *model.Event, _ *Ctx) string {
			return cut(ev.Cmdline, 240)
		},
	}
}

// AEG-072 TCC 权限拒绝（越权访问迹象）
func ruleAEG072() Rule {
	return Rule{
		ID:          "AEG-072",
		Name:        "TCC 权限拒绝（越权访问迹象）",
		Severity:    "medium",
		Tags:        []string{"discovery", "credential_access"},
		MITRE:       []string{"T1083", "T1518"},
		Description: "短时间内多次触发 TCC 拒绝。",
		Advice:      "反复触碰受保护资源说明有程序在探测权限边界；确认其安装来源。",
		When: func(ev *model.Event, c *Ctx) bool {
			return ev.Kind == "tcc.deny" && c.Reached("tccdeny:"+ev.Process, 120, 4)
		},
		Detail: func(ev *model.Event, _ *Ctx) string {
			return ev.Process + " 多次被 TCC 拒绝: " + cut(ev.Cmdline, 160)
		},
	}
}

// AEG-073 主机侦察行为聚集
func ruleAEG073() Rule {
	return Rule{
		ID:          "AEG-073",
		Name:        "主机侦察行为聚集",
		Severity:    "medium",
		Tags:        []string{"discovery"},
		MITRE:       []string{"T1033", "T1016", "T1082"},
		Description: "2 分钟内同一进程链聚集出现多条主机侦察命令。",
		Advice:      "单独看每条都是无害的系统命令，聚集出现才是信号——结合父进程判断是否人为踩点。",
		When: func(ev *model.Event, c *Ctx) bool {
			if ev.Kind != "process.start" || !reDiscovery.MatchString(cmdOf(ev)) {
				return false
			}
			return c.Reached("discovery:"+RootPID(ev.PID, c), 120, 6)
		},
		Detail: func(ev *model.Event, _ *Ctx) string {
			return ev.Process + ": " + cut(ev.Cmdline, 160)
		},
	}
}

// AEG-074 Shell 历史记录写入敏感命令
func ruleAEG074() Rule {
	return Rule{
		ID:          "AEG-074",
		Name:        "Shell 历史记录写入敏感命令",
		Severity:    "low",
		Tags:        []string{"evidence"},
		MITRE:       []string{"T1070.003"},
		Description: "shell 历史文件被写入（用于回溯操作者行为）。",
		Advice:      "结合同期进程事件核对；历史文件异常增长往往是人为操作的侧信道证据。",
		When: func(ev *model.Event, _ *Ctx) bool {
			return ev.Kind == "file.write" && strings.Contains(ev.Path, "history")
		},
		Detail: func(ev *model.Event, _ *Ctx) string {
			return ev.Path + " 追加 " + subStr(ev, "delta_bytes") + " 字节"
		},
	}
}

// ---------------- 规则求值的安全壳（engine.py 的 try/except） ----------------

func safeWhen(r *Rule, ev *model.Event, ctx *Ctx) (ok bool) {
	if r == nil || r.When == nil {
		return false
	}
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	return r.When(ev, ctx)
}

func safeActor(r *Rule, ev *model.Event, ctx *Ctx) (out string) {
	if r == nil || r.Actor == nil {
		return ""
	}
	defer func() {
		if recover() != nil {
			out = ""
		}
	}()
	return r.Actor(ev, ctx)
}

func safeDetail(r *Rule, ev *model.Event, ctx *Ctx) (out string) {
	if r == nil || r.Detail == nil {
		return ""
	}
	defer func() {
		if recover() != nil {
			out = ""
		}
	}()
	return r.Detail(ev, ctx)
}

func safeSeverityFn(r *Rule, ev *model.Event, ctx *Ctx) (out string) {
	if r == nil || r.SeverityFn == nil {
		return ""
	}
	defer func() {
		if recover() != nil {
			out = ""
		}
	}()
	return r.SeverityFn(ev, ctx)
}
