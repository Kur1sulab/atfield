"""出网脱敏网关：把判定数据送进云端模型之前的最后一道闸。

为什么必须有它
    云 AI 意味着「本机的进程名、路径、主机名、内网地址」会被发到别人的
    GPU 上。这些字段单独看无害，拼起来就是一份内网资产清单——正是攻击者
    最想拿的东西。所以流程被设计成单向的：

        Finding(本地原始) → redact() 脱敏 → 云端模型
                                    ↑
                            只放「语义」不放「身份」

    模型需要知道「一个非浏览器进程直连了外部 IP」，不需要知道那个 IP 是
    203.0.113.7、那个进程叫 /Users/alice/tools/evil。前者是判断依据，
    后者是情报泄露。

设计取舍
    - 只做确定性替换，不做「智能识别」：正则误伤可以接受（多打几个码），
      漏打不可接受（真把家目录发出去了）。
    - 保留可判断性：IP 换成 [IP:v4]、域名换成 [DOMAIN]，模型照样能推理
      协议与行为，只是拿不到具体值。
    - 数字类证据（端口、进程数、时间戳）尽量保留——这些是判断的关键，
      且不构成身份。
    - 每类替换都计数，回传给调用方写进审计，做到「发了什么、打了几个码」
      可复算。

不做的事
    - 不试图识别「哪个是真敏感」——拿不准的一律打码。
    - 不提供绕过开关。redact=False 只允许用于自建/本地端点（loopback），
      由 provider 层校验，不由调用方决定。
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Tuple

# ---------------------------------------------------------------- 替换表

# 顺序有意义：先长后短，先具体后泛化。前面的规则会「吃掉」后面的输入，
# 所以邮箱、URL 这种带结构的必须排在裸 IP / 裸路径之前。
RULES: List[Tuple[str, str, "re.Pattern[str]"]] = [
    # 邮箱
    ("email", "[EMAIL]",
     re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    # URL（保留 scheme+host 结构已无意义，整条打掉）
    ("url", "[URL]",
     re.compile(r"\b(?:https?|ftp|wss?)://[^\s\"'<>)\]]+", re.I)),
    # 凭据形态：Bearer / token= / password= / -p xxx / --api-key xxx
    ("secret", "[SECRET]",
     re.compile(r"(?i)\b(bearer\s+[A-Za-z0-9._\-]{12,}"
                r"|(?:password|passwd|pwd|token|secret|api[_\-]?key|access[_\-]?key)"
                r"\s*[=:]\s*\S+"
                r"|(?:^|\s)-p\s+\S+)")),
    # 常见 key 前缀（sk- / ghp_ / AKIA / xoxb- ...）
    # 长度给区间而非定值：截断显示、变体前缀都能命中，宁可多打码
    ("api_key", "[API_KEY]",
     re.compile(r"\b(?:sk-[A-Za-z0-9_\-]{16,}"
                r"|gh[pousr]_[A-Za-z0-9]{16,}"
                r"|glpat-[A-Za-z0-9_\-]{16,}"
                r"|(?:AKIA|ASIA)[0-9A-Z]{12,20}"
                r"|xox[baprs]-[A-Za-z0-9\-]{10,}"
                r"|AIza[0-9A-Za-z_\-]{30,}"
                r"|npm_[A-Za-z0-9]{30,}"
                r"|hf_[A-Za-z0-9]{30,}"
                r"|sk_(?:live|test)_[A-Za-z0-9]{16,})")),
    # JWT
    ("jwt", "[JWT]",
     re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
    # 家目录：/Users/xxx 与 /home/xxx（保留尾部一层，说明「在哪个子目录」）
    ("home", r"[HOME]",
     re.compile(r"(?:/Users|/home)/[^/\s\"'<>:]+")),
    # Windows 用户目录
    ("home", "[HOME]",
     re.compile(r"[A-Za-z]:\\Users\\[^\\\s\"'<>:]+")),
    # ------ MAC 必须先于 IP ------
    # 6 组双位 hex 与 IPv6 候选形态重叠；若让 IPv6 先跑，MAC 会被标成 [IP:v6]
    ("mac", "[MAC]",
     re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"
                r"|\b(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}\b")),
    # ------ IPv6 缩写形态：必须含 :: ------
    # 不用 \b（::1 以非单词字符开头，\b 不成立），改用负向断言。
    # 关键：不含 :: 的「3 组纯数字」是时间 19:50:00，绝不能吃——那是研判证据。
    ("ipv6", "[IP:v6]",
     re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?::"
                r"(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?(?![\w:])")),
    # ------ IPv6 全写：恰好 8 组 ------
    ("ipv6", "[IP:v6]",
     re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b")),
    # ------ IPv4（在 IPv6 之后：::ffff:1.2.3.4 不能被拆两半）------
    ("ipv4", "[IP]",
     re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
                r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
    # 域名（含 .local/.lan/.internal 等内网后缀）
    ("domain", "[DOMAIN]",
     re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+"
                r"(?:com|net|org|io|cn|co|me|dev|app|xyz|top|info|biz|ru|jp|hk|tw"
                r"|local|lan|internal|corp|home|arpa)\b", re.I)),
    # 长 hex（hash / GUID / 指纹）——截断保留前 8 位，够判断类型，不够反查
    ("hexid", None,
     re.compile(r"\b[0-9a-fA-F]{32,}\b")),
    # UUID
    ("uuid", "[UUID]",
     re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
                r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")),
]

# 从运行环境里动态取的「本机身份」——这些是本机独有的，必须无条件打码
_LOCAL_MARKERS_CACHE: Dict[str, str] = {}


def _local_markers() -> Dict[str, str]:
    """本机身份标记：主机名、用户名、家目录。每次现算，防止换用户后失效。"""
    global _LOCAL_MARKERS_CACHE
    out: Dict[str, str] = {}
    try:
        import socket
        hn = socket.gethostname()
        if hn and len(hn) >= 2:
            out[hn] = "[HOST]"
            out[hn.split(".")[0]] = "[HOST]"
    except Exception:
        pass
    for env in ("USER", "LOGNAME", "USERNAME"):
        val = os.environ.get(env)
        if val and len(val) >= 2:
            out[val] = "[USER]"
    home = os.path.expanduser("~")
    if home and home not in ("~", "/"):
        out[home] = "[HOME]"
        base = os.path.basename(home.rstrip("/"))
        if base and len(base) >= 2:
            out[base] = "[USER]"
    _LOCAL_MARKERS_CACHE = out
    return out


def redact_text(text: str) -> Tuple[str, Dict[str, int]]:
    """对单条文本脱敏。返回 (脱敏文本, 各类命中计数)。"""
    if not text:
        return "", {}
    counts: Dict[str, int] = {}
    out = text

    # 1) 本机身份优先（精确串，最长优先，避免短串先吃掉长串的一部分）
    for marker in sorted(_local_markers(), key=len, reverse=True):
        repl = _local_markers()[marker]
        if marker and marker in out:
            n = out.count(marker)
            out = out.replace(marker, repl)
            key = "host" if repl == "[HOST]" else ("user" if repl == "[USER]" else "home")
            counts[key] = counts.get(key, 0) + n

    # 2) 规则表按顺序套
    for name, repl, pat in RULES:
        if name == "hexid":
            def _trunc(m: "re.Match[str]") -> str:
                counts["hexid"] = counts.get("hexid", 0) + 1
                return "[HEX:" + m.group(0)[:8] + "]"
            out = pat.sub(_trunc, out)
            continue
        found = pat.findall(out)
        if found:
            out = pat.sub(repl, out)  # type: ignore[arg-type]
            counts[name] = counts.get(name, 0) + len(found)

    return out, counts


def redact_obj(obj: Any, _depth: int = 0) -> Tuple[Any, Dict[str, int]]:
    """递归脱敏任意 JSON 结构（dict/list/str）。数字与布尔原样保留。"""
    if _depth > 12:
        return "[DEPTH_LIMIT]", {"depth": 1}
    total: Dict[str, int] = {}

    def _merge(c: Dict[str, int]) -> None:
        for k, v in c.items():
            total[k] = total.get(k, 0) + v

    if isinstance(obj, str):
        s, c = redact_text(obj)
        _merge(c)
        return s, total
    if isinstance(obj, dict):
        out_d: Dict[str, Any] = {}
        for k, v in obj.items():
            ks, kc = redact_text(str(k))
            _merge(kc)
            vs, vc = redact_obj(v, _depth + 1)
            _merge(vc)
            out_d[ks] = vs
        return out_d, total
    if isinstance(obj, (list, tuple)):
        out_l = []
        for v in obj:
            vs, vc = redact_obj(v, _depth + 1)
            _merge(vc)
            out_l.append(vs)
        return out_l, total
    return obj, total


def is_loopback_url(url: str) -> bool:
    """判断端点是否在回环地址上——本地模型不必脱敏。"""
    from urllib.parse import urlparse
    try:
        host = (urlparse(url).hostname or "").strip().lower()
    except Exception:
        return False
    if host in ("localhost", "::1", "0.0.0.0"):
        return True
    return host.startswith("127.")


def mask_key(key: str) -> str:
    """凭据指纹：用于审计与界面显示，不可逆推原文。"""
    import hashlib
    if not key:
        return ""
    h = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
    return f"sha256:{h}…（长度{len(key)}）"
