"""态势量化：健康度（配置/防护）与风险度（行为/告警）两个正交维度。

为什么分开：主机可能配置满分但正在被攻击（风险高），也可能毫无威胁但配置一塌糊涂。
只报一个数字就会误导决策。
"""
from __future__ import annotations

import math
import time
from typing import Any, Dict, List

DIMENSIONS = [
    {"key": "identity", "name": "身份与会话", "desc": "账户、登录、提权与认证"},
    {"key": "execution", "name": "执行与持久化", "desc": "进程行为、常驻项与启动链"},
    {"key": "network", "name": "网络与暴露面", "desc": "监听服务、外联行为与边界"},
    {"key": "data", "name": "数据与凭据", "desc": "磁盘加密、凭据与敏感权限"},
    {"key": "detection", "name": "防护与检测能力", "desc": "系统加固、更新与安全组件"},
]

# 基线检查 category -> 维度
CATEGORY_MAP = {
    "身份与会话": "identity",
    "执行与持久化": "execution",
    "暴露面": "network",
    "网络防线": "network",
    "数据保护": "data",
    "补丁管理": "detection",
    "系统安全": "detection",
    "恶意代码防护": "detection",
}

STATUS_SCORE = {"pass": 100, "warn": 62, "fail": 18, "unknown": 70}

SEV_WEIGHT = {"info": 0.2, "low": 1.0, "medium": 3.0, "high": 8.0, "critical": 18.0}
SEV_CN = {"info": "信息", "low": "低危", "medium": "中危", "high": "高危", "critical": "严重"}


def posture(baseline_state: Dict[str, Any]) -> Dict[str, Any]:
    results = (baseline_state or {}).get("results") or []
    buckets: Dict[str, List[dict]] = {d["key"]: [] for d in DIMENSIONS}
    for r in results:
        key = CATEGORY_MAP.get(r.get("category") or "", "detection")
        buckets.setdefault(key, []).append(r)

    dims: List[Dict[str, Any]] = []
    total_w = 0.0
    total_s = 0.0
    for d in DIMENSIONS:
        items = buckets.get(d["key"]) or []
        wsum = sum(float(i.get("weight") or 1) for i in items) or 1.0
        score = sum(STATUS_SCORE.get(i.get("status"), 70) * float(i.get("weight") or 1)
                    for i in items) / wsum if items else 70.0
        fails = [i for i in items if i.get("status") == "fail"]
        dims.append({
            "key": d["key"], "name": d["name"], "desc": d["desc"],
            "score": round(score, 1),
            "checks": len(items),
            "failed": len(fails),
            "top_issue": (fails[0]["name"] if fails else ""),
        })
        total_w += wsum
        total_s += score * wsum

    health = round(total_s / total_w, 1) if total_w else 70.0
    return {"health": health, "dimensions": dims, "grade": _grade(health)}


def _grade(v: float) -> str:
    if v >= 92:
        return "优秀"
    if v >= 80:
        return "良好"
    if v >= 65:
        return "一般"
    if v >= 45:
        return "薄弱"
    return "危险"


def threat(findings: List[dict], incidents: List[dict], half_life_h: float = 6.0) -> Dict[str, Any]:
    now = time.time()
    raw = 0.0
    recent = 0
    by_sev = {k: 0 for k in SEV_WEIGHT}
    for f in findings:
        sev = f.get("severity") or "info"
        by_sev[sev] = by_sev.get(sev, 0) + 1
        age_h = max(0.0, (now - float(f.get("ts") or now)) / 3600.0)
        decay = math.pow(0.5, age_h / half_life_h)
        raw += SEV_WEIGHT.get(sev, 0.5) * decay
        if age_h <= 1.0:
            recent += 1
    for inc in incidents:
        age_h = max(0.0, (now - float(inc.get("last_seen") or now)) / 3600.0)
        decay = math.pow(0.5, age_h / half_life_h)
        raw += (float(inc.get("score") or 50) / 10.0) * decay * 1.6

    # 对数饱和：单次严重事件就应该显著，但不让长尾把指数顶死
    risk = min(100.0, 100.0 * (1 - math.exp(-raw / 45.0)))
    level = ("严重" if risk >= 75 else "高" if risk >= 50 else
             "中" if risk >= 25 else "低" if risk >= 8 else "平静")
    return {
        "risk": round(risk, 1),
        "level": level,
        "raw": round(raw, 1),
        "recent_1h": recent,
        "by_severity": by_sev,
        "findings_total": len(findings),
        "incidents_total": len(incidents),
    }


def threat_level_color(risk: float) -> str:
    if risk >= 75:
        return "critical"
    if risk >= 50:
        return "high"
    if risk >= 25:
        return "medium"
    if risk >= 8:
        return "low"
    return "calm"
