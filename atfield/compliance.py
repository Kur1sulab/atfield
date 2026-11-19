"""合规矩阵：把现场基线结果映射到 CIS macOS Benchmark 与等保 2.0 三级主机要求。

不新采集数据——复用 baseline 采集器的检查结论，做「条款 ↔ 检查项」映射，
输出可直接进检查表的对照矩阵。未覆盖条款显式标 gap，不虚报通过。
"""
from __future__ import annotations

import time
from typing import Any, Dict, List

# control_id: (框架, 条款标题, [基线检查项 id 前缀/关键字], 权重)
CONTROLS: List[tuple] = [
    # ---- CIS Apple macOS Benchmark（核心子集）----
    ("CIS-1.1", "CIS", "确保所有软件均已更新", ["patch.", "update."], 3),
    ("CIS-1.5", "CIS", "启用 Gatekeeper 并禁止未知来源", ["exec.gatekeeper", "gatekeeper"], 3),
    ("CIS-1.6", "CIS", "启用系统完整性保护 SIP", ["system.sip", "sip"], 3),
    ("CIS-1.7", "CIS", "启用 FileVault 全盘加密", ["data.filevault", "filevault"], 3),
    ("CIS-2.1.1", "CIS", "启用防火墙", ["network.firewall", "firewall"], 3),
    ("CIS-2.1.2", "CIS", "启用隐身模式（Stealth）", ["network.stealth", "stealth"], 2),
    ("CIS-2.3", "CIS", "启用 XProtect 与恶意软件防护", ["av.", "xprotect", "malware"], 3),
    ("CIS-2.5", "CIS", "限制远程登录（SSH）", ["network.ssh", "ssh"], 2),
    ("CIS-2.6", "CIS", "禁用不必要的共享服务", ["network.share", "sharing"], 2),
    ("CIS-4.1", "CIS", "启用安全审计日志", ["identity.audit", "audit"], 2),
    ("CIS-4.2", "CIS", "启用屏幕锁定与自动锁屏", ["identity.screenlock", "screenlock"], 2),
    ("CIS-5.1", "CIS", "保护用户主目录权限", ["data.home_perm", "permission"], 2),
    ("CIS-5.2", "CIS", "无空口令账户", ["identity.empty_pw", "empty"], 3),
    ("CIS-5.3", "CIS", "管理员组最小化", ["identity.admin", "admin"], 2),
    # ---- 等保 2.0 三级 · 主机安全 ----
    ("DJ-3.1.4-1", "等保三级", "身份鉴别：口令复杂度与定期更换", ["identity.policy", "identity.admin"], 2),
    ("DJ-3.1.4-2", "等保三级", "身份鉴别：登录失败处理与超时退出", ["identity.screenlock", "identity.audit"], 2),
    ("DJ-3.1.4-3", "等保三级", "访问控制：最小权限与默认账户改名", ["identity.admin"], 2),
    ("DJ-3.1.4-4", "等保三级", "入侵防范：最小安装、关闭非必要服务", ["network.share", "network.ssh", "network.firewall"], 3),
    ("DJ-3.1.4-5", "等保三级", "恶意代码防范：安装并更新防恶意代码", ["av.", "xprotect"], 3),
    ("DJ-3.1.4-6", "等保三级", "可信验证：系统补丁及时更新", ["patch.", "update.", "system.sip"], 3),
    ("DJ-3.1.4-7", "等保三级", "数据完整性：重要文件完整性校验", ["integrity", "data.integrity", "atfield.fim"], 2),
    ("DJ-3.1.4-8", "等保三级", "数据保密性：重要数据加密存储", ["data.filevault", "filevault"], 3),
    ("DJ-3.1.4-9", "等保三级", "安全审计：审计记录保护与留存", ["identity.audit"], 2),
    ("DJ-3.1.4-10", "等保三级", "集中管控：日志集中与集中监测", [], 0),
]


def _match_checks(prefixes: List[str], checks: List[dict]) -> List[dict]:
    if not prefixes:
        return []
    out = []
    for c in checks:
        cid = (c.get("id") or "") + " " + (c.get("title") or "")
        low = cid.lower()
        for p in prefixes:
            if p.lower() in low:
                out.append(c)
                break
    return out


def build(base_state: Dict[str, Any], store=None) -> Dict[str, Any]:
    checks: List[dict] = list(base_state.get("checks") or base_state.get("results") or [])
    rows: List[dict] = []
    for cid, framework, title, prefixes, weight in CONTROLS:
        hits = _match_checks(prefixes, checks)
        if not hits:
            rows.append({"control": cid, "framework": framework, "title": title,
                         "status": "gap", "weight": weight,
                         "evidence": [], "note": "未覆盖：本框架条款无对应检查项"})
            continue
        statuses = [h.get("status") for h in hits]
        if "fail" in statuses:
            status = "fail"
        elif "warn" in statuses:
            status = "warn"
        elif all(s == "unknown" for s in statuses):
            status = "unknown"
        else:
            status = "pass"
        rows.append({
            "control": cid, "framework": framework, "title": title,
            "status": status, "weight": weight,
            "evidence": [{"id": h.get("id"), "title": h.get("name") or h.get("title"),
                          "status": h.get("status"),
                          "evidence": (h.get("evidence") or "")[:200],
                          "remediation": (h.get("remediation") or h.get("advice") or "")[:200]}
                         for h in hits[:4]],
            "note": "",
        })

    def score(framework: str) -> Dict[str, Any]:
        sub = [r for r in rows if r["framework"] == framework and r["weight"] > 0
               and r["status"] != "gap"]
        total = sum(r["weight"] for r in sub)
        got = sum(r["weight"] for r in sub
                  if r["status"] == "pass")
        got += sum(r["weight"] * 0.5 for r in sub if r["status"] == "unknown")
        got += sum(r["weight"] * 0.2 for r in sub if r["status"] == "warn")
        pct = round(100 * got / total, 1) if total else 0.0
        return {"score": pct, "count": len(sub),
                "pass": sum(1 for r in sub if r["status"] == "pass"),
                "fail": sum(1 for r in sub if r["status"] == "fail"),
                "warn": sum(1 for r in sub if r["status"] == "warn"),
                "unknown": sum(1 for r in sub if r["status"] == "unknown")}

    out = {
        "ts": time.time(),
        "generated_cn": time.strftime("%Y-%m-%d %H:%M:%S"),
        "frameworks": {"CIS": score("CIS"), "等保三级": score("等保三级")},
        "rows": rows,
        "gaps": [r["control"] for r in rows if r["status"] == "gap"],
        "basis": "映射自实时基线检查结果；unknown=权限不足未判定，gap=本产品未覆盖该条款",
    }
    if store is not None:
        store.set_state("compliance", out)
    return out
