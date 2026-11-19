"""内建检测规则集（macOS 终端行为）。

设计原则：
1. 每条规则都能解释「为什么可疑」——给出证据串与整改建议，不做黑盒打分；
2. 覆盖 MITRE ATT&CK 主要执行/持久化/防御规避/凭据访问/外联阶段；
3. 默认低误报：宁可分级到「关注」，也不把用户日常操作报成攻击。
"""
from __future__ import annotations

import os
import re
from typing import List

from .engine import Ctx, Rule, exe_of, root_pid
from ..model import Event
from ..intel import CONF_MAP, hit_counts, hit_severity, score_to_severity

HOME = os.path.expanduser("~")
_PW = "pa" + "ss" + "word"   # 拆写，避免模板占位符替换

# ---------------- 工具判定 ----------------
PIPE_EXEC = re.compile(
    r"(curl|wget)[^|;&]*\|\s*(sudo\s+)?(ba|z|k)?sh|"
    r"(curl|wget)[^|;&]*\|\s*(python|perl|ruby|node)|"
    r"osascript\s+-e", re.I)
INTERP_ONE_LINER = re.compile(
    r"\b(python3?|perl|ruby|node|osascript)\s+(-c|-e)\b", re.I)
B64_DECODE = re.compile(r"base64\s+(-d|-D|--decode)|frombase64string|b64decode", re.I)
REVSHELL = re.compile(
    r"/dev/tcp/|nc\s+(-e|--exec)|ncat\s+(-e|--exec)|bash\s+-i\s*>&|"
    r"mkfifo\s+/tmp|socat\s+.*exec:|pty\.spawn", re.I)
CRED_ACCESS = re.compile(
    r"(/\.ssh/id_|\.aws/credentials|\.config/gcloud|login\.keychain|"
    r"Cookies\.binarycookies|/etc/shadow|security\s+find-(generic|internet)-" + _PW + r")", re.I)
DISABLE_DEFENSE = re.compile(
    r"(csrutil\s+disable|spctl\s+--master-disable|socketfilterfw\s+--setglobalstate\s+off|"
    r"launchctl\s+(unload|bootout|disable).*(defender|falcon|sentinel|crowdstrike|mdm)|"
    r"tccutil\s+reset|killall\s+(XProtect|falconctl|sentineld))", re.I)
DISCOVERY = re.compile(
    r"\b(whoami|id\b|hostname|ifconfig|netstat|system_profiler|dscl\s+\.|"
    r"arp\s+-a|ps\s+aux|launchctl\s+list|lsof\s+-i)\b", re.I)

SUSP_DIRS = ("/tmp/", "/private/tmp/", "/var/tmp/", "/Users/Shared/",
             "/private/var/folders/", "/dev/shm/")

PORT_SCAN_THRESHOLD = 25


# ---------------- 规则定义 ----------------
def _ev_cmd(ev: Event) -> str:
    return f"{ev.cmdline} {ev.path}"


RULES: List[Rule] = []


def rule(**kw):
    RULES.append(Rule(**kw))


# ---- 执行阶段 ----
rule(
    id="AEG-001", name="管道下载后直接执行", severity="critical",
    when=lambda ev, c: ev.kind == "process.start" and bool(PIPE_EXEC.search(_ev_cmd(ev))),
    detail=lambda ev, c: f"命令行命中「下载即执行」模式: {ev.cmdline[:200]}",
    advice="立即确认该进程来源；阻断外联、保留命令行与父进程链作为证据。真实运维请走包管理与人工审核流程。",
    tags=("execution", "download"), mitre=("T1059.004", "T1105"),
    description="curl/wget 输出直接管道进 shell 或解释器，是落地即执行最典型的手法。",
)

rule(
    id="AEG-002", name="解释器单行命令执行", severity="medium",
    when=lambda ev, c: ev.kind == "process.start" and bool(INTERP_ONE_LINER.search(_ev_cmd(ev))),
    detail=lambda ev, c: f"{ev.process}: {ev.cmdline[:200]}",
    advice="核对这条单行命令的内容；无源码落地的执行往往用于规避文件监控。",
    tags=("execution", "fileless"), mitre=("T1059.006", "T1027"),
    description="python -c / osascript -e 等无文件落地执行。",
)

rule(
    id="AEG-003", name="可写目录内的可执行文件", severity="high",
    when=lambda ev, c: (ev.kind == "process.start"
                        and (ev.subject.get("suspicious_path")
                             or any((ev.path or "").startswith(d) for d in SUSP_DIRS))),
    detail=lambda ev, c: f"执行路径位于临时/共享目录: {ev.path}",
    advice="临时目录里的可执行文件极少数是正当业务；先取证再清理，注意同目录可能有配套载荷。",
    tags=("execution",), mitre=("T1036", "T1105"),
    description="从 /tmp、/Users/Shared 等可写目录启动进程。",
)

rule(
    id="AEG-004", name="进程名仿冒系统组件", severity="high",
    when=lambda ev, c: ev.kind == "process.start" and bool(ev.subject.get("masquerade")),
    detail=lambda ev, c: f"{ev.process} 来自非系统路径 {ev.path}",
    advice="系统守护进程不应从用户目录或临时目录运行；核对哈希与签名后终止。",
    tags=("defense_evasion",), mitre=("T1036.005",),
    description="进程名与系统进程同名但可执行路径不在系统目录（伪装）。",
)

rule(
    id="AEG-005", name="Base64 解码后执行", severity="high",
    when=lambda ev, c: ev.kind == "process.start" and bool(B64_DECODE.search(_ev_cmd(ev))),
    detail=lambda ev, c: ev.cmdline[:240],
    advice="还原解码后的内容再判断；这类命令常见于混淆载荷投放。",
    tags=("execution", "obfuscation"), mitre=("T1027", "T1140"),
    description="使用 base64 解码并在同一命令行内执行。",
)

rule(
    id="AEG-006", name="反弹 Shell 特征", severity="critical",
    when=lambda ev, c: ev.kind == "process.start" and bool(REVSHELL.search(_ev_cmd(ev))),
    detail=lambda ev, c: f"命令行具备反弹 shell 特征: {ev.cmdline[:200]}",
    advice="立刻定位对端地址与端口并封禁；抓取该进程的网络连接与父子链，勿直接重启丢证据。",
    tags=("execution", "c2"), mitre=("T1059.004", "T1071"),
    description="/dev/tcp、nc -e、mkfifo 管道等反弹 shell 用法。",
)

# ---- 持久化阶段 ----
rule(
    id="AEG-010", name="新增 LaunchAgent / LaunchDaemon", severity="high",
    when=lambda ev, c: ev.kind == "persistence.add",
    detail=lambda ev, c: f"{ev.path} → {ev.cmdline[:160]}",
    advice="核对 Label 与 ProgramArguments 是否为已批准软件；可疑则 launchctl bootout 并删除 plist。",
    tags=("persistence",), mitre=("T1543.001", "T1543.004"),
    description="配置目录出现新的 launchd 常驻项。",
)

rule(
    id="AEG-011", name="持久化项被篡改", severity="high",
    when=lambda ev, c: ev.kind == "persistence.modify",
    detail=lambda ev, c: f"{ev.path} 内容变更",
    advice="对比历史版本；被改写为 RunAtLoad+KeepAlive 的项要优先处置。",
    tags=("persistence", "defense_evasion"), mitre=("T1543.001",),
    description="既有 launchd 项被修改（含被植入常驻逻辑）。",
)

rule(
    id="AEG-012", name="可疑持久化载荷", severity="critical",
    when=lambda ev, c: ev.kind in ("persistence.add", "persistence.modify")
    and bool(ev.subject.get("suspicious")),
    detail=lambda ev, c: "; ".join(ev.subject.get("suspicious") or [])[:240],
    advice="该常驻项指向临时目录或含下载/解释器命令，符合后门常驻特征；建议立即隔离并取证。",
    tags=("persistence", "c2"), mitre=("T1543.001", "T1105"),
    description="常驻项的命令行/权限存在多项可疑特征。",
)

# ---- 防御规避 ----
rule(
    id="AEG-020", name="尝试关闭系统防护", severity="critical",
    when=lambda ev, c: ev.kind in ("process.start", "defense.event")
    and bool(DISABLE_DEFENSE.search(_ev_cmd(ev))),
    detail=lambda ev, c: f"命中防护关闭类命令: {ev.cmdline[:200]}",
    advice="这类命令几乎不具备正当运维场景；先确认操作者身份，再评估是否已有后续载荷。",
    tags=("defense_evasion",), mitre=("T1562.001",),
    description="csrutil disable / spctl --master-disable / tccutil reset 等降防护操作。",
)

rule(
    id="AEG-021", name="代码签名失效事件", severity="critical",
    when=lambda ev, c: ev.kind == "defense.cs_invalidated",
    detail=lambda ev, c: f"{ev.process} 签名校验失效: {ev.path}",
    advice="进程二进制被替换或内存被改写；立刻导出可执行文件做哈希比对。",
    tags=("defense_evasion", "integrity"), mitre=("T1553.001",),
    description="EndpointSecurity 报告进程代码签名失效（二进制被篡改/注入）。",
)

rule(
    id="AEG-022", name="Gatekeeper 被用户绕过", severity="high",
    when=lambda ev, c: ev.kind == "defense.gatekeeper_override",
    detail=lambda ev, c: f"{ev.process}: {ev.cmdline[:160]}",
    advice="确认是否为知情操作；未经批准的绕过往往用于运行未签名载荷。",
    tags=("defense_evasion",), mitre=("T1553.001", "T1204"),
    description="用户以「仍要打开」方式绕过 Gatekeeper。",
)

rule(
    id="AEG-023", name="安全组件消失", severity="high",
    when=lambda ev, c: ev.kind == "defense.removed",
    detail=lambda ev, c: f"{ev.process} 已不存在: {ev.path}",
    advice="卸载 EDR 是攻击者标准动作之一；确认是否存在本地管理员权限滥用。",
    tags=("defense_evasion",), mitre=("T1562.001",),
    description="已安装的第三方安全代理/组件消失。",
)

# ---- 凭据访问 ----
rule(
    id="AEG-030", name="凭据文件访问", severity="high",
    when=lambda ev, c: (ev.kind == "process.start" and bool(CRED_ACCESS.search(_ev_cmd(ev))))
    or (ev.kind in ("file.open", "file.create") and bool(CRED_ACCESS.search(ev.path or ""))),
    detail=lambda ev, c: f"{ev.process} 触达凭据路径: {ev.path or ev.cmdline[:120]}",
    advice="判定是否为合法工具（如 ssh 使用密钥）；异常进程读取 id_rsa/keychain 后通常会立刻外联。",
    tags=("credential_access",), mitre=("T1552.001", "T1555.003"),
    description="访问 SSH 私钥、云凭据、钥匙串、浏览器 Cookie 等高价值文件。",
)

rule(
    id="AEG-031", name="钥匙串/凭据访问异常", severity="medium",
    when=lambda ev, c: ev.kind == "credential.access",
    detail=lambda ev, c: ev.subject.get("note", "") + " " + ev.cmdline[:160],
    advice="核对发起进程；批量钥匙串访问常见于信息窃取木马。",
    tags=("credential_access",), mitre=("T1555.001",),
    description="securityd 侧出现异常访问模式。",
)

# ---- 网络 / 外联 ----
rule(
    id="AEG-040", name="高危端口监听暴露", severity="medium",
    when=lambda ev, c: ev.kind == "net.listen" and ev.severity in ("high", "critical"),
    detail=lambda ev, c: f"{ev.subject.get('service')} 监听 {ev.subject.get('addr')} ({ev.process})",
    advice="关闭非必要服务；确需使用则限制来源地址并加认证。",
    tags=("exposure",), mitre=("T1046", "T1210"),
    description="Redis/MySQL/Docker/VNC 等高风险服务在本机监听。",
)

rule(
    id="AEG-041", name="公网非常见端口外联", severity="medium",
    when=lambda ev, c: (ev.kind == "net.connect" and ev.subject.get("public")
                        and int(ev.subject.get("rport") or 0) not in (80, 443, 53, 123, 22, 993, 587, 5223, 8080, 8443)),
    detail=lambda ev, c: f"{ev.process} → {ev.subject.get('raddr')}",
    advice="确认该外联是否为业务所需；非浏览器进程访问非常见端口是 C2 的典型特征。",
    tags=("command_control",), mitre=("T1571",),
    description="进程连接公网的非标准端口。",
)

rule(
    id="AEG-042", name="命中 C2 端口", severity="critical",
    when=lambda ev, c: ev.kind == "net.connect" and int(ev.subject.get("rport") or 0) in
    (4444, 4445, 1337, 31337, 6666, 6667, 6697, 9001, 12345, 54321),
    detail=lambda ev, c: f"{ev.process} → {ev.subject.get('raddr')}",
    advice="高置信后门端口；立刻封禁对端并定位发起进程的可执行文件。",
    tags=("command_control",), mitre=("T1571", "T1071"),
    description="连接常见后门/C2 端口。",
)

def _ioc_allowlisted(intel, rip: str, raddr: str) -> bool:
    """allowlist 前置：保留/共享基础设施（RFC1918、回环、CGNAT、Cloudflare…）永不算 IOC。"""
    try:
        if rip and intel.warnings.check_ip(rip) is not None:
            return True
        if raddr and intel.warnings.check_domain(raddr) is not None:
            return True
    except Exception:
        return False
    return False


def _ioc_hit(ev: Event, c: Ctx) -> "dict | None":
    """AEG-043 的闸门查表 —— 三处写死定级的其中一处就在原地把这里短路掉。

    查表顺序固定：intel.match_ip（CIDR 最长前缀 + allowlist 前置）→ intel.match_domain；
    命中但衰减到期（score=0）→ 视为不再计分，返回 None；
    intel 不可用（独立引擎/单测）才退回 config 明文名单，且只给最低置信分档。
    """
    sub = ev.subject or {}
    rip = str(sub.get("rip") or "")
    raddr = str(sub.get("raddr") or "")
    intel = getattr(c, "intel", None)
    if intel is not None:
        hit = None
        try:
            if rip:
                hit = intel.match_ip(rip)
            if hit is None and raddr:
                hit = intel.match_domain(raddr)
        except Exception:
            hit = None
        if hit is not None:
            return hit if hit_counts(hit) else None
        if _ioc_allowlisted(intel, rip, raddr):
            return None
    icfg = c.cfg.get("ioc") if isinstance(c.cfg.get("ioc"), dict) else {}
    if (rip and rip in set(icfg.get("ips") or [])) or \
            (raddr and raddr in set(icfg.get("domains") or [])):
        # 明文名单没有来源/时间戳 → 只能按 low 置信进闸门分档（0.15 → medium）
        return {"value": raddr or rip, "source": "config:ioc",
                "score": CONF_MAP["low"], "severity": score_to_severity(CONF_MAP["low"]),
                "lifecycle": "legacy-config"}
    return None


def _ioc_severity(ev: Event, c: Ctx) -> "str | None":
    """AEG-043 定级：只认闸门算出来的 severity；不计分时返回 None（整条丢弃）。"""
    hit = _ioc_hit(ev, c)
    return hit_severity(hit, default="low") if hit else None


def _ioc_detail(ev: Event, c: Ctx) -> str:
    hit = _ioc_hit(ev, c) or {}
    sub = ev.subject or {}
    target = sub.get("raddr") or sub.get("rip")
    return (f"命中情报库: {target}（来源 {hit.get('source') or '-'}"
            f"，分数 {hit.get('score', '-')}，置信 {hit.get('confidence') or '-'}）")


rule(
    id="AEG-043", name="命中威胁情报 IOC", severity="low",
    when=lambda ev, c: ev.kind == "net.connect" and _ioc_hit(ev, c) is not None,
    severity_fn=_ioc_severity,
    detail=_ioc_detail,
    advice="IOC 命中按闸门分档处置：critical/high 立即封禁并全网排查同源；"
           "medium 先核对情报来源与业务归属（保留网段会被 allowlist 拦下）。",
    tags=("command_control",), mitre=("T1071",),
    description="外联地址命中情报库（config.yaml ioc.ips/domains 会一次性迁入闸门）。"
                "等级由 intel.py 按 CIDR 最长前缀 + allowlist + 置信度衰减计算，不再写死。",
)

rule(
    id="AEG-044", name="可疑进程对外连接", severity="high",
    when=lambda ev, c: (ev.kind == "net.connect" and ev.subject.get("public")
                        and any((exe_of(ev.pid, c) or "").startswith(d) for d in SUSP_DIRS)),
    detail=lambda ev, c: f"{ev.process} ({exe_of(ev.pid, c)}) → {ev.subject.get('raddr')}",
    advice="临时目录里的进程对外通信，几乎只有两类：正常的安装器与后门。核对父进程与落地时间。",
    tags=("command_control", "execution"), mitre=("T1071", "T1036"),
    description="可执行文件位于临时/共享目录的进程建立公网连接。",
)

rule(
    id="AEG-045", name="单进程连接数异常（疑似扫描/横向）", severity="high",
    when=lambda ev, c: (ev.kind == "net.connect"
                        and bool(ev.subject.get("public"))
                        and c.reached(f"scan:{ev.pid}", 60, PORT_SCAN_THRESHOLD)),
    detail=lambda ev, c: f"{ev.process}(pid={ev.pid}) 60 秒内对公网建立超过 {PORT_SCAN_THRESHOLD} 个连接",
    advice="区分开发工具（如浏览器、IDE）与扫描器；后者应立刻终止并排查横向痕迹。",
    tags=("discovery", "lateral_movement"), mitre=("T1046",),
    description="单个进程短时间内大量对公网建连，符合端口扫描/横向探测特征（仅统计公网目标，避免把本地代理/IDE 误判）。",
)

# ---- 认证 / 会话 ----
rule(
    id="AEG-050", name="认证失败爆发", severity="high",
    when=lambda ev, c: ev.kind == "auth.fail" and c.reached(f"authfail:{ev.process}", 300, 6),
    detail=lambda ev, c: f"{ev.process} 5 分钟内多次认证失败",
    advice="核对来源 IP 与目标账户；口令喷洒需要立即在边界封禁，并检查是否已有成功登录。",
    tags=("credential_access",), mitre=("T1110",),
    description="sudo/SSH 在短窗口内出现多次认证失败（口令爆破）。",
)

rule(
    id="AEG-051", name="本地认证失败", severity="medium",
    when=lambda ev, c: ev.kind == "auth.fail",
    detail=lambda ev, c: ev.cmdline[:200] or ev.subject.get("note", ""),
    advice="确认是否人为输错；连续出现需按爆破事件处理。",
    tags=("credential_access",), mitre=("T1110",),
    description="捕获到单次认证失败事件。",
)

rule(
    id="AEG-052", name="远程登录成功", severity="medium",
    when=lambda ev, c: ev.kind in ("auth.success", "session.login") and (
        ev.subject.get("remote") or ev.kind == "auth.success"),
    detail=lambda ev, c: f"{ev.user or '?'} 从 {ev.subject.get('from') or ev.subject.get('raw_process') or '远程'} 登录",
    advice="比对是否为许可的运维来源；异常来源的登录必须立刻核实。",
    tags=("initial_access",), mitre=("T1078", "T1021.004"),
    description="SSH 或远程会话登录成功。",
)

# ---- 完整性 / 基线 ----
rule(
    id="AEG-060", name="关键安全文件被修改", severity="critical",
    when=lambda ev, c: ev.kind == "integrity.change" and any(
        k in (ev.path or "") for k in ("authorized_keys", "sshd_config", "sudoers",
                                       "pf.conf", "/etc/hosts")),
    detail=lambda ev, c: f"{ev.path}: {ev.subject.get('reason')}",
    advice="authorized_keys/sshd_config 被改意味着可能已被植入持久访问；核对差异并回滚。",
    tags=("persistence", "integrity"), mitre=("T1098.004", "T1562.004"),
    description="SSH 授权文件、hosts、防火墙或 sudo 配置被改动。",
)

rule(
    id="AEG-061", name="监控文件完整性变化", severity="medium",
    when=lambda ev, c: ev.kind == "integrity.change",
    detail=lambda ev, c: f"{ev.path}: {ev.subject.get('reason')}",
    advice="确认变更来源；非预期变更应回滚并排查写入进程。",
    tags=("integrity",), mitre=("T1565",),
    description="受监控文件内容/存在性变化。",
)

rule(
    id="AEG-062", name="安全基线劣化", severity="high",
    when=lambda ev, c: ev.kind == "baseline.drift",
    detail=lambda ev, c: f"{ev.subject.get('name')}: {ev.subject.get('from')} → {ev.subject.get('to')}",
    advice="基线由通过变为关注/不合格意味着防护被削弱，优先排查是否被人为关闭。",
    tags=("defense_evasion", "posture"), mitre=("T1562",),
    description="安全基线检查项状态由好转坏。",
)

# ---- 反隐蔽 ----
rule(
    id="AEG-070", name="疑似隐藏进程", severity="high",
    when=lambda ev, c: ev.kind == "process.hidden",
    detail=lambda ev, c: f"pid={ev.pid} {ev.process} 两套视图不一致",
    advice="正常系统不应出现两侧不一致；先固化 ps / psutil / lsof 三份输出再做判断。",
    tags=("defense_evasion",), mitre=("T1014", "T1564"),
    description="ps 与 psutil 进程视图不一致（可能被 rootkit/lldb 注入隐藏）。",
)

rule(
    id="AEG-071", name="威胁情报文件痕迹", severity="high",
    when=lambda ev, c: ev.kind == "av.detect",
    detail=lambda ev, c: ev.cmdline[:240],
    advice="XProtect 已判定恶意；按恶意软件处置流程隔离并检查同源投放。",
    tags=("malware",), mitre=("T1204",),
    description="系统反恶意软件组件报出威胁。",
)

rule(
    id="AEG-072", name="TCC 权限拒绝（越权访问迹象）", severity="medium",
    when=lambda ev, c: ev.kind == "tcc.deny" and c.reached(f"tccdeny:{ev.process}", 120, 4),
    detail=lambda ev, c: f"{ev.process} 多次被 TCC 拒绝: {ev.cmdline[:160]}",
    advice="反复触碰受保护资源说明有程序在探测权限边界；确认其安装来源。",
    tags=("discovery", "credential_access"), mitre=("T1083", "T1518"),
    description="短时间内多次触发 TCC 拒绝。",
)

rule(
    id="AEG-073", name="主机侦察行为聚集", severity="medium",
    when=lambda ev, c: (ev.kind == "process.start" and bool(DISCOVERY.search(_ev_cmd(ev)))
                        and c.reached(f"discovery:{root_pid(ev.pid, c)}", 120, 6)),
    detail=lambda ev, c: f"{ev.process}: {ev.cmdline[:160]}",
    advice="单独看每条都是无害的系统命令，聚集出现才是信号——结合父进程判断是否人为踩点。",
    tags=("discovery",), mitre=("T1033", "T1016", "T1082"),
    description="2 分钟内同一进程链聚集出现多条主机侦察命令。",
)

rule(
    id="AEG-074", name="Shell 历史记录写入敏感命令", severity="low",
    when=lambda ev, c: ev.kind == "file.write" and "history" in (ev.path or ""),
    detail=lambda ev, c: f"{ev.path} 追加 {ev.subject.get('delta_bytes')} 字节",
    advice="结合同期进程事件核对；历史文件异常增长往往是人为操作的侧信道证据。",
    tags=("evidence",), mitre=("T1070.003",),
    description="shell 历史文件被写入（用于回溯操作者行为）。",
)


def load() -> List[Rule]:
    return list(RULES)
