"""心之壁 —— 边界完整性模型。

设定里，那道力场的本体就是心之壁：每个个体维持自我形态、隔绝他人的力场。
   （力场是外在表现，心之壁是本体——产品直接用品名承载这个语义。）
产品借用这个本体名承载**边界完整性**这个语义：

    终端上任何一次异常，本质都是某条边界被试探、或被穿透。

这不是新加一个并列模块，而是把已有检测能力（FIM/基线、NDR、UEBA、诱饵、
进程与信号监控）按「它守的是哪条边界」重新组织起来，让分析员一眼看到
**五条边界里哪条在漏**，而不是在一堆告警里自己拼。

五条边界（对齐终端上真实存在的隔离界面）：

    process     进程边界    谁能读写我的内存、挂调试器、注入代码
    file        文件边界    谁能改我的二进制、配置、凭证文件
    network     网络边界    我能连谁、谁能连我
    credential  凭据边界    身份使用与权限边界
    signal      信号边界    谁能给我发控制信号（kill/ptrace/调试附着）

边界状态：

    sealed   守住    有策略覆盖，且这段时间没观测到异常
    wave     波动    被试探过，但挡住了
    breach   穿透    已经发生真实越界
    quiet    静默    这段时间没观测到异常，也没有证据说守住了

注意 sealed 与 quiet 的区别：**没观测到异常 ≠ 边界稳固**。
没有覆盖证据时宁可标「静默」让分析员自己去确认，也不要给一个虚假的安心。

术语与技术的对应关系必须固定，否则「心之壁」会退化成中二贴皮：

    力场强度  = 五条边界防护得分的均值
    中和      = 用合法身份瓦解边界（注入 / 凭据窃取 / 白利用），最难防的一类
    穿透      = 真实发生的越界（critical，或高危且诱饵被实际踩中）
    波动      = 试探被挡下，边界仍在
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple

# 边界定义。kinds 是前缀匹配的 event.kind 集合 —— 事件属于哪条边界由它决定。
BARRIERS: Dict[str, Dict[str, Any]] = {
    "process": {
        "cn": "进程边界",
        "desc": "内存读写 · 调试附着 · 代码注入",
        "kinds": ("process.",),
    },
    "file": {
        "cn": "文件边界",
        "desc": "二进制 · 配置 · 凭证文件完整性",
        "kinds": ("file.", "integrity.", "persistence.", "canary."),
    },
    "network": {
        "cn": "网络边界",
        "desc": "出站外联 · 入站连接 · 隧道",
        "kinds": ("net.", "ndr.", "dns."),
    },
    "credential": {
        "cn": "凭据边界",
        "desc": "身份使用 · 权限边界 · 会话",
        "kinds": ("credential.", "auth.", "ueba.", "sudo.", "priv."),
    },
    "signal": {
        "cn": "信号边界",
        "desc": "控制信号 · 调试与注入的落地动作",
        "kinds": ("signal.", "ptrace.", "debug."),
    },
}

ORDER = ("process", "file", "network", "credential", "signal")

# 穿透判定用的严重度集合
_BREACH_SEV = {"critical"}
_WAVE_SEV = {"high", "medium"}

STATE_CN = {
    "sealed": "守住",
    "wave": "波动",
    "breach": "穿透",
    "quiet": "静默",
}

# 规则是函数式匹配（when 是 Callable），无法静态判断它守哪条边界。
# 退一步用 tag 做粗映射：够用来判断「这条边界有没有人守」，不追求精确归属。
TAG_BARRIER = {
    "persistence": "file",
    "integrity": "file",
    "canary": "file",
    "honeypot": "file",
    "command_control": "network",
    "c2": "network",
    "exfiltration": "network",
    "lateral_movement": "network",
    "execution": "process",
    "defense_evasion": "process",
    "discovery": "process",
    "impact": "process",
    "privilege_escalation": "credential",
    "credential_access": "credential",
}

GRADE_CN = {
    "solid": "稳固",
    "cracked": "有裂缝",
    "broken": "危险",
}


def classify(kind: str) -> Optional[str]:
    """event.kind → 边界 key。认不出来就返回 None（不硬塞）。"""
    k = str(kind or "")
    for key in ORDER:
        for prefix in BARRIERS[key]["kinds"]:
            if k.startswith(prefix):
                return key
    return None


def _is_breach(f: Dict[str, Any]) -> bool:
    """这条命中算不算「穿透」。

    判据收紧：只有 critical，或高危且诱饵被实际踩中（说明对方真的摸到了东西），
    才叫穿透。其余一切按波动处理 —— 宁可少喊穿透，也不要让力场强度变成噪音。
    """
    sev = str(f.get("severity") or "").lower()
    if sev in _BREACH_SEV:
        return True
    tags = [str(t).lower() for t in (f.get("tags") or [])]
    kind = str(((f.get("event") or {}).get("kind")) or "")
    if sev == "high" and ("canary" in tags or kind.startswith("canary.")):
        return True
    return False


def _score(state: str, waves: int, breaches: int) -> int:
    """单条边界的得分（0-100）。"""
    if state == "quiet":
        return 70                     # 没观测到异常，但也没证据说守住了：持保留
    if state == "breach":
        return max(0, 30 - breaches * 10)
    if state == "wave":
        return max(50, 100 - waves * 4)
    return 100


def assess(findings: Iterable[Dict[str, Any]],
           coverage: Optional[Dict[str, List[str]]] = None) -> Dict[str, Any]:
    """把一组 Finding 归到五条边界上，算出力场强度。

    coverage: {barrier_key: [rule_id, ...]} —— 该边界有哪些规则在守。
             没有覆盖且没有命中的边界，状态是 open（裸奔），不是 sealed。
    """
    coverage = coverage or {}
    buckets: Dict[str, Dict[str, Any]] = {
        k: {"waves": 0, "breaches": 0, "fids": [], "rules": set()} for k in ORDER
    }
    unknown = 0

    for f in findings or []:
        if not isinstance(f, dict):
            continue
        kind = ((f.get("event") or {}).get("kind")) or ""
        key = classify(kind)
        if not key:
            unknown += 1
            continue
        b = buckets[key]
        if _is_breach(f):
            b["breaches"] += 1
        elif str(f.get("severity") or "").lower() in _WAVE_SEV | _BREACH_SEV:
            b["waves"] += 1
        if len(b["fids"]) < 20:
            b["fids"].append(str(f.get("fid") or ""))
        rid = str(f.get("rule_id") or "")
        if rid:
            b["rules"].add(rid)

    rows: List[Dict[str, Any]] = []
    total = 0
    for key in ORDER:
        b = buckets[key]
        rules = set(coverage.get(key) or []) | b["rules"]
        if b["breaches"]:
            state = "breach"
        elif b["waves"]:
            state = "wave"
        elif rules:
            state = "sealed"
        else:
            state = "quiet"
        score = _score(state, b["waves"], b["breaches"])
        total += score
        rows.append({
            "key": key,
            "cn": BARRIERS[key]["cn"],
            "desc": BARRIERS[key]["desc"],
            "state": state,
            "state_cn": STATE_CN[state],
            "score": score,
            "waves": b["waves"],
            "breaches": b["breaches"],
            "rules": sorted(rules),
            "fids": b["fids"],
        })

    strength = int(round(total / len(ORDER)))
    if strength >= 80:
        grade = "solid"
    elif strength >= 50:
        grade = "cracked"
    else:
        grade = "broken"

    weakest = min(rows, key=lambda r: r["score"]) if rows else None
    return {
        "strength": strength,
        "grade": grade,
        "grade_cn": GRADE_CN[grade],
        "weakest": weakest["key"] if weakest else "",
        "weakest_cn": weakest["cn"] if weakest else "",
        "barriers": rows,
        "observed": sum(1 for r in rows if r["state"] != "quiet"),
        "breached": sum(1 for r in rows if r["state"] == "breach"),
        "unknown_kind": unknown,
    }


def coverage_from_rules(rules: Iterable[Any]) -> Dict[str, List[str]]:
    """从规则清单推断每条边界有哪些规则在守。

    规则对象/字典带 tags 或 event kinds 时用它归类；认不出的不硬塞。
    """
    cov: Dict[str, List[str]] = {k: [] for k in ORDER}
    for r in rules or []:
        if isinstance(r, dict):
            rid = str(r.get("id") or r.get("rule_id") or "")
            tags = r.get("tags") or []
            kinds = r.get("kinds") or r.get("event_kinds") or []
        else:
            rid = str(getattr(r, "id", "") or getattr(r, "rule_id", "") or "")
            tags = getattr(r, "tags", ()) or ()
            kinds = getattr(r, "kinds", ()) or getattr(r, "event_kinds", ()) or ()
        if not rid:
            continue
        hit = set()
        for k in kinds:
            key = classify(str(k))
            if key:
                hit.add(key)
        for t in tags:
            key = TAG_BARRIER.get(str(t).lower())
            if key:
                hit.add(key)
        for key in hit:
            cov[key].append(rid)
    return cov
