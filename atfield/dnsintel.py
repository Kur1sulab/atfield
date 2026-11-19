"""DNS 异常判定：DGA 启发式 + 隧道启发式。

为什么单独一个模块：原来的 netintel 只会拿域名去撞 IOC 名单（`intel.match_domain`），
名单里没有的域名一律放过。而真实入侵里 C2 用的几乎都是当天新注册的随机域名——
名单永远追不上。这一层不看「这个域名坏不坏」，看「这个域名长得像不像人起的」。

两类要分开判，因为特征反着：

  DGA（域名生成算法）—— 单段随机串 + 正常 TLD，例如 `xkjvqpzmr.biz`
      · 辅音连缀长（人类的词有元音）
      · 元音比例低
      · 熵高但总长不长（8~25）
      · 数字比例偏高

  隧道（DNS tunneling）—— 把数据塞进子域，例如
      `aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q.exfil.example.com`
      · 单段极长（>40）
      · 段数多（>4）
      · 最长段的熵很高
      · 字符集像 base32/base64

判定只输出「可疑度 + 命中了哪几条」，不做定罪。是否告警由调用方按阈值决定——
这样冷启动期可以先只记录不告警（学 Darktrace 的教训：一上来就喊，喊多了就没人看）。

【纪律】纯计算，不做任何网络请求。域名从既有观测里来，不主动去查。
字符集判定（base64/base32/大小写混杂）一律用原始大小写——lower() 会吞掉
大写证据；只有白名单后缀、punycode 前缀这类比较才用小写。
"""
from __future__ import annotations

import math
import re
from typing import Any, Dict, List, Tuple

# 这些域名后缀下的随机串通常是 CDN/云厂商的自动命名，不该按 DGA 算
_BENIGN_SUFFIX = (
    "apple.com", "icloud.com", "mzstatic.com", "cdn-apple.com",
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
    "microsoft.com", "windows.com", "msedge.net", "live.com", "office.com",
    "amazonaws.com", "cloudfront.net", "akamai.net", "akamaiedge.net",
    "cloudflare.com", "fastly.net", "jsdelivr.net", "unpkg.com",
    "githubusercontent.com", "github.com", "npmjs.org", "pypi.org",
    "anthropic.com", "openai.com", "opencode.ai", "deepseek.com",
)

# 纯哈希式 CDN 主机名：32~40 位十六进制，也常被误判
_HEX_LABEL = re.compile(r"^[0-9a-f]{16,64}$", re.I)
# base32 / base64url 形态（隧道常用）
_B32 = re.compile(r"^[A-Z2-7]{16,}$")
_B64URL = re.compile(r"^[A-Za-z0-9_\-]{16,}$")
_VOWELS = set("aeiou")

# 阈值：可疑度 ≥ 此值判 suspicious，≥ WATCH 判 watch
SUSPICIOUS = 0.60
WATCH = 0.40

# 单段最短才算 DGA 候选；太短的随机串（4~7 位）人类也在用，误报高
DGA_MIN_LABEL = 8
DGA_MAX_LABEL = 30
TUNNEL_LABEL_MIN = 40
TUNNEL_LABEL_MID = 24      # 单段偏长门槛（base64/base32 载荷常见段长）
TUNNEL_LABEL_COUNT_MIN = 5


def shannon_entropy(text: str) -> float:
    """每个字符的平均信息量（bits/char）。随机串约 3.5~4.7，英文单词约 3.0~3.5。"""
    if not text:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _max_consonant_run(label: str) -> int:
    best = run = 0
    for ch in label:
        if ch.isalpha() and ch.lower() not in _VOWELS:
            run += 1
            best = max(best, run)
        elif ch.isalpha():          # 元音打断
            run = 0
        # 数字/连字符不打断，也不算辅音
    return best


def _digit_ratio(label: str) -> float:
    if not label:
        return 0.0
    return sum(1 for ch in label if ch.isdigit()) / len(label)


def _vowel_ratio(label: str) -> float:
    letters = [ch for ch in label if ch.isalpha()]
    if not letters:
        return 0.0
    return sum(1 for ch in letters if ch.lower() in _VOWELS) / len(letters)


def _is_benign(host: str) -> bool:
    host = host.lower().rstrip(".")
    return any(host == s or host.endswith("." + s) for s in _BENIGN_SUFFIX)


def _labels(host: str) -> List[str]:
    # 保留原始大小写：base64/大小写混杂判据要吃到大写证据（bug#1：原来整串
    # lower() 导致「必须含大写」永远不成立）。只有白名单/后缀比较才用小写。
    return [p for p in host.rstrip(".").split(".") if p]


def dga_score(host: str) -> Dict[str, Any]:
    """判「这个域名像不像 DGA 生成的」。只看注册域里最长的那一段。"""
    signals: List[str] = []
    score = 0.0

    if not host or _is_benign(host):
        return {"score": 0.0, "signals": [], "verdict": "ok", "kind": "dga"}

    labels = _labels(host)
    if len(labels) < 2:
        return {"score": 0.0, "signals": [], "verdict": "ok", "kind": "dga"}

    # 注册域的主体标签（example.com 里取 example；三级域名取第二段）
    body = labels[-2] if len(labels) >= 2 else labels[0]

    if body.lower().startswith("xn--"):  # 国际化域名，不按 ASCII 特征判
        return {"score": 0.0, "signals": [], "verdict": "ok", "kind": "dga"}
    if _HEX_LABEL.match(body):          # 哈希式 CDN，单列不判 DGA
        return {"score": 0.0, "signals": ["hex-label(cdn)"], "verdict": "ok", "kind": "dga"}

    if not (DGA_MIN_LABEL <= len(body) <= DGA_MAX_LABEL):
        return {"score": 0.0, "signals": [], "verdict": "ok", "kind": "dga"}

    run = _max_consonant_run(body)
    if run >= 5:
        score += 0.28
        signals.append(f"辅音连缀 {run} 位")

    vr = _vowel_ratio(body)
    if vr < 0.15:
        score += 0.24
        signals.append(f"元音比例 {vr:.2f}")
    # bug#2：「一个元音都没有」是独立强信号，不靠辅音连缀权重叠加。
    # 8 位以上、含字母却零元音的注册域主体，人类语言里几乎不存在。
    if vr == 0.0 and any(ch.isalpha() for ch in body):
        score += 0.25
        signals.append("完全无元音")

    dr = _digit_ratio(body)
    if dr >= 0.20:
        score += 0.18
        signals.append(f"数字比例 {dr:.2f}")

    ent = shannon_entropy(body)
    if ent >= 3.5:
        score += 0.16
        signals.append(f"熵 {ent:.2f} bits/char")

    # 大小写混杂在正常域名里几乎不出现（域名不区分大小写，人不会故意大写）
    if any(ch.isupper() for ch in body) and any(ch.islower() for ch in body):
        score += 0.10
        signals.append("大小写混杂")

    score = min(1.0, round(score, 3))
    verdict = "suspicious" if score >= SUSPICIOUS else ("watch" if score >= WATCH else "ok")
    return {"score": score, "signals": signals, "verdict": verdict, "kind": "dga",
            "label": body, "entropy": round(ent, 2)}


def tunnel_score(host: str) -> Dict[str, Any]:
    """判「这个域名像不像在往外搬数据」。隧道特征是超长段 + 段数多 + 高熵。"""
    signals: List[str] = []
    score = 0.0

    if not host or _is_benign(host):
        return {"score": 0.0, "signals": [], "verdict": "ok", "kind": "tunnel"}

    labels = _labels(host)
    if len(labels) < 3:
        return {"score": 0.0, "signals": [], "verdict": "ok", "kind": "tunnel"}

    longest = max(labels, key=len)
    if longest.lower().startswith("xn--"):   # IDN 段不按 ASCII 字符集判
        return {"score": 0.0, "signals": ["punycode"], "verdict": "ok", "kind": "tunnel"}
    ent = shannon_entropy(longest)

    # bug#3 重标定：单段 ≥40 字符本身就是极强隧道信号（正常子域几乎不会这么长），
    # 权重 0.32→0.40；中段门槛 30→24（base64/base32 载荷常见 24~32 字符段）。
    if len(longest) >= TUNNEL_LABEL_MIN:
        score += 0.40
        signals.append(f"单段长 {len(longest)} 字符")
    elif len(longest) >= TUNNEL_LABEL_MID:
        score += 0.20
        signals.append(f"单段偏长 {len(longest)} 字符")

    if len(labels) >= TUNNEL_LABEL_COUNT_MIN:
        score += 0.14
        signals.append(f"段数 {len(labels)}")

    if ent >= 4.0:
        score += 0.26
        signals.append(f"最长段熵 {ent:.2f}")
    elif ent >= 3.6:
        score += 0.12
        signals.append(f"最长段熵 {ent:.2f}")

    # 字符集判据用原始大小写（bug#1）。纯 hex 段是哈希形态（CDN/校验值），
    # 与 hex 隧道不可区分，不给 base32/base64 加权，避免误报。
    is_hex = bool(_HEX_LABEL.match(longest))
    if not is_hex and _B32.match(longest):
        score += 0.20
        signals.append("base32 字符集")
    elif not is_hex and _B64URL.match(longest) and (
            (any(c.isupper() for c in longest) and any(c.islower() for c in longest))
            or "_" in longest):
        # 大小写混杂的 base64url 是强证据（正常主机名约定全小写）；
        # 仅含连字符不算——hyphen 在正常子域里太常见，原来 0.14 的弱判据
        # 既漏报真 base64（被 lower 吞掉大写）又容易蹭到正常名，重标定为 0.30。
        score += 0.30
        signals.append("base64url 字符集(大小写混杂)")

    # 全是数字的段（十六进制外带）也算一条弱信号
    if longest.isdigit() and len(longest) >= 24:
        score += 0.10
        signals.append("纯数字长段")

    score = min(1.0, round(score, 3))
    verdict = "suspicious" if score >= SUSPICIOUS else ("watch" if score >= WATCH else "ok")
    return {"score": score, "signals": signals, "verdict": verdict, "kind": "tunnel",
            "label": longest, "entropy": round(ent, 2), "labels": len(labels)}


def analyze(host: str) -> Dict[str, Any]:
    """两类都判，取高的那个作为结论。返回结构直接可以进 Event.subject。"""
    host = host or ""
    d = dga_score(host)
    t = tunnel_score(host)
    best = d if d["score"] >= t["score"] else t
    return {
        "host": host,
        "score": best["score"],
        "verdict": best["verdict"],
        "kind": best["kind"],
        "signals": best["signals"],
        "dga": d,
        "tunnel": t,
    }


class DnsIntel:
    """把观测到的域名攒起来做统计，顺带记住基线。

    冷启动纪律：前 `warmup_observations` 个域名只记录不判定（verdict 仍是 ok），
    避免一上来满屏告警——报告里点了这条是 Darktrace 的教训。
    """

    def __init__(self, warmup_observations: int = 50):
        self.warmup_observations = max(0, int(warmup_observations))
        self.seen: Dict[str, Dict[str, Any]] = {}
        self.total = 0
        self.flagged: List[Dict[str, Any]] = []

    @property
    def warming_up(self) -> bool:
        return self.total < self.warmup_observations

    def observe(self, host: str, process: str = "") -> Dict[str, Any]:
        # bug#1 关联修复：原来这里先 lower() 再 analyze，大写证据在入口就被吞掉。
        # 现在判定吃原始大小写；去重键用小写（DNS 本身大小写不敏感）。
        host = (host or "").strip().rstrip(".")
        if not host:
            return {"host": "", "score": 0.0, "verdict": "ok", "kind": "", "signals": []}

        key = host.lower()
        rec = self.seen.get(key)
        if rec is None:
            rec = analyze(host)
            rec["first"] = self.total
            rec["hits"] = 0
            rec["processes"] = {}
            self.seen[key] = rec
        rec["hits"] += 1
        if process:
            rec["processes"][process] = rec["processes"].get(process, 0) + 1
        # 暖机判定用「自增前」的计数：前 N 个观察（1..N）一律只记录不报，
        # 第 N+1 个起才对外给真实判定。原来先 +=1 再判，第 N 个就会喊，差一位。
        warming = self.warming_up
        self.total += 1

        if warming:
            # 记录分数，但对外一律 ok —— 渐进观察期不喊。
            # 注意：不能改写 rec["verdict"] 本身，否则观察期结束后这些域名
            # 的判定永远停在 ok，再观测也不会报（暖机变成永久消音）。
            rec["suppressed"] = True
            out = dict(rec)
            out["verdict"] = "ok"
            return out
        rec["suppressed"] = False
        if rec.get("score", 0) >= WATCH:
            self.flagged.append({"host": rec["host"], "score": rec["score"],
                                 "verdict": rec["verdict"], "kind": rec["kind"],
                                 "signals": rec["signals"], "processes": dict(rec["processes"])})
            del self.flagged[:-200]
        return rec

    def status(self) -> Dict[str, Any]:
        suspicious = [r for r in self.seen.values() if r.get("score", 0) >= SUSPICIOUS]
        watch = [r for r in self.seen.values() if WATCH <= r.get("score", 0) < SUSPICIOUS]
        return {
            "domains": len(self.seen),
            "observations": self.total,
            "warming_up": self.warming_up,
            "warmup_remaining": max(0, self.warmup_observations - self.total),
            "suspicious": len(suspicious),
            "watch": len(watch),
            "top": sorted(self.seen.values(), key=lambda r: -r.get("score", 0))[:20],
            "flagged": self.flagged[-40:][::-1],
        }


def selftest() -> Tuple[bool, str]:
    """模块级自检：正例要判可疑，反例要放过。"""
    cases: List[Tuple[str, str, str]] = [
        # (域名, 期望最低判定, 说明)
        ("xkjvqpzmrt.biz", "watch", "随机辅音串"),
        ("qwrtypsdfgh.net", "suspicious", "无元音长串"),
        ("aGVsbG8gd29ybGQgdGhpcyBpcyBh.evil.example.com", "suspicious", "base64 隧道"),
        ("dGhpcy1pcy1hLXZlcnktbG9uZy1zdWJkb21haW4tZm9yLXR1bm5lbA.exfil.click", "suspicious", "超长段隧道"),
        ("example.com", "ok", "正常域名"),
        ("www.google.com", "ok", "正常域名"),
        ("github.com", "ok", "正常域名"),
        ("xn--fiqs8s.com", "ok", "punycode 不判"),
        ("a1b2c3d4e5f6a7b8c9d0.cloudfront.net", "ok", "哈希 CDN"),
        # 补充用例：大小写证据 / 零元音独立信号 / 重标定后的边界
        ("Xk7Qm9Zp2Rt4.com", "suspicious", "大小写混杂随机串（lower 不得吞掉大写）"),
        ("K7X3M2Q4Z2W5R6T3JBSWY3DPEHPK3PXPAB2CDE4F.tunnel.evil.net", "suspicious", "base32 隧道"),
        ("my-long-service-name.example.com", "ok", "正常连字符子域不误报"),
        ("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6.hash.example.org", "ok", "未知域下的 hex 哈希段"),
        ("", "ok", "空串"),
    ]
    rank = {"ok": 0, "watch": 1, "suspicious": 2}
    bad: List[str] = []
    for host, want, note in cases:
        got = analyze(host)
        if rank[got["verdict"]] < rank[want]:
            bad.append(f"{host} → {got['verdict']}({got['score']}) 期望 ≥{want}（{note}）")
    if bad:
        return False, "；".join(bad)
    return True, f"{len(cases)} 个用例全部符合预期"
