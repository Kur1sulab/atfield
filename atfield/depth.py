"""纵深剖面 —— 把已有检测按「攻击推进到第几层」重新组织（只读投影）。

与 barrier.py（心之壁）同款模式：不是新检测、不是新数据源，业务逻辑一律不动，
本模块只读 store 里已经产出的 findings / incidents，把它们投影到四层纵深轴上：

    L0 外部   攻击者还在终端之外：暴露面与网络侧指示信号
    L1 边界   认证/执行边界的试探与跨越：爆破、登录成功、初始载荷执行
    L2 主机   立足点已建立：持久化、防御规避、C2、内部侦察、诱饵被触碰
    L3 核心   碰到皇冠珠宝：凭据、提权、信任锚、横向移动

层级语义按「攻击者的穿透深度」而不是「传感器位置」划分：NDR 在网络侧看到
心跳，说明主机上已有驻留体在活动，所以 NDR-BEACON 归 L2 而不是 L0。

映射优先级（每条判定都带 basis，原样返回前端展示——纵深视图必须能回答
「凭什么这么判」）：

    1. rule_id 直 hit（内建规则 + 融合规则，逐条人工审定）
    2. MITRE 标签兜底（自定义规则；按最深标签优先）
    3. 事件 kind 兜底（无规则无标签时按事件类型/来源）
    4. 保守默认 L2（未识别信号不往浅了放，避免虚假安心）

沉默区语义沿用 barrier 的 sealed/quiet 之辨：某层窗口内无事件时明确标
「沉默区」而不是画空白轨道；最内层沉默是好消息，但要附采集器可用性——
采集器掉线时的沉默可能只是观测盲区，不能冒充好消息。
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Tuple

from .model import SEVERITY_ORDER, iso

# ---------------- 层定义 ----------------
LAYERS: List[Dict[str, Any]] = [
    {"key": "L0", "order": 0, "cn": "外部", "name": "L0 · 外部",
     "desc": "攻击者尚在终端之外：暴露面、网络侧指示信号。未证明主机失陷。"},
    {"key": "L1", "order": 1, "cn": "边界", "name": "L1 · 边界",
     "desc": "认证与执行边界被试探或跨越：爆破、登录成功、初始载荷落地执行。"},
    {"key": "L2", "order": 2, "cn": "主机", "name": "L2 · 主机",
     "desc": "立足点已建立：持久化、防御规避、C2 外联、内部侦察、诱饵被触碰。"},
    {"key": "L3", "order": 3, "cn": "核心", "name": "L3 · 核心",
     "desc": "皇冠珠宝被触碰：凭据文件、钥匙串、提权、信任锚改写、横向移动。"},
]
LAYER_ORDER = {l["key"]: l["order"] for l in LAYERS}
LAYER_CN = {l["key"]: l["cn"] for l in LAYERS}

# ---------------- 规则 → 层（逐条审定，basis 即「凭什么这么判」） ----------------
RULE_LAYER: Dict[str, Tuple[str, str]] = {
    # ---- L0 外部：暴露面与网络侧弱信号 ----
    "AEG-040": ("L0", "高危端口监听是对外暴露面——说明攻击者可以从哪里进来，尚不代表有人已经进来。"),
    "NDR-DIRECT-IP": ("L0", "网络侧弱信号：直连 IP 绕过域名声誉体系，单独不构成主机失陷证据。"),
    "NDR-RISKY-DOMAIN": ("L0", "网络侧指示：动态 DNS / 隧道类域名，需结合进程证据才能定深度。"),
    "NDR-RISKY-PORT": ("L0", "网络侧指示：高危端口外联观测，属边界之外的连接信号。"),
    "UEBA-NEW-DEST": ("L0", "行为基线弱信号：首次出现的外联目的地，是观察项而非失陷证据。"),
    # ---- L1 边界：认证/执行边界的试探与跨越 ----
    "AEG-050": ("L1", "密集认证失败 = 有人在认证边界外爆破试探，尚未成功进入。"),
    "AEG-051": ("L1", "本地认证失败 = 跨越认证边界的尝试被拒（边界守住了一次）。"),
    "AEG-052": ("L1", "远程登录成功 = 认证边界被跨越，攻击者拿到交互式入口。"),
    "AEG-001": ("L1", "外部代码管道直接进本地执行 = 跨越「外→内」执行边界的瞬间。"),
    "AEG-002": ("L1", "无文件单行执行：外部输入直接变成本地代码，属执行边界跨越。"),
    "AEG-003": ("L1", "载荷落在可写目录并被执行 = 初始立足点正在建立。"),
    "AEG-005": ("L1", "外部载荷去混淆后执行 = 初始执行边界跨越。"),
    "AEG-022": ("L1", "Gatekeeper 执行边界控制被绕过，不可信代码拿到执行权。"),
    "AEG-071": ("L1", "恶意文件落地被 XProtect 检出——载荷已越过边界进入磁盘。"),
    # ---- L2 主机：立足点之后的活动 ----
    "AEG-004": ("L2", "伪装系统组件 = 立足点之后的防御规避。"),
    "AEG-006": ("L2", "反弹 shell = 攻击者在主机上拿到交互式控制通道。"),
    "AEG-010": ("L2", "新增 LaunchAgent/Daemon = 持久化立足点建立。"),
    "AEG-011": ("L2", "既有常驻项被篡改 = 立足点加固。"),
    "AEG-012": ("L2", "常驻项含下载/执行特征 = 带召回能力的立足点。"),
    "AEG-020": ("L2", "试图关闭系统保护 = 立足点之后清除防御。"),
    "AEG-021": ("L2", "代码签名失效 = 主机上的信任校验被绕过。"),
    "AEG-023": ("L2", "安全组件消失 = 主机防御被摘除。"),
    "AEG-041": ("L2", "主机进程外联非常用公网端口 = 疑似 C2 通道（主机已有活动实体）。"),
    "AEG-042": ("L2", "命中已知 C2 端口 = 主机上的控制通道特征明确。"),
    "AEG-043": ("L2", "主机外联命中威胁情报 IOC = 失陷主机与已知恶意基础设施通信。"),
    "AEG-044": ("L2", "可疑进程外联 = 执行实体与 C2 特征叠加。"),
    "AEG-045": ("L2", "主机发起的连接扇出/侦察：立足点后的内部活动；尚无横向成功证据，不放核心层。"),
    "AEG-061": ("L2", "受监控文件完整性变化 = 主机内的篡改痕迹（非信任锚文件）。"),
    "AEG-062": ("L2", "安全基线退化 = 主机防御姿态被削弱。"),
    "AEG-070": ("L2", "隐藏进程 = 立足点之后的隐匿行为。"),
    "AEG-072": ("L2", "进程试探 TCC 保护资源被系统拒绝——内部试探，尝试未得手。"),
    "AEG-073": ("L2", "主机侦察命令聚集 = 立足点后的内部测绘。"),
    "AEG-074": ("L2", "shell 历史出现敏感命令 = 主机上交互式操作的痕迹。"),
    "CANARY-TRIP": ("L2", "诱饵被触碰：正常业务永不该访问它，说明主机内已有活动实体在移动。"),
    "NDR-BEACON": ("L2", "高度规律的心跳外联 = 主机上疑似已有驻留 implant 在活动（网络侧看到，深度在主机）。"),
    "TI-IOC-IP": ("L2", "主机进程外联命中情报库 IP = 疑似 C2 通道已建立。"),
    "UEBA-NEW-PROC": ("L2", "首次出现的进程 = 主机上出现新执行实体（弱信号）。"),
    "UEBA-NEW-PERSIST": ("L2", "首次出现的常驻项 = 持久化集合发生变化。"),
    # ---- L3 核心：皇冠珠宝 ----
    "AEG-030": ("L3", "直接访问 SSH 私钥 / 云凭据等凭据文件 = 攻击已触及凭据核心。"),
    "AEG-031": ("L3", "试图读取系统钥匙串 = 触及凭据核心。"),
    "AEG-060": ("L3", "authorized_keys / sshd_config / sudoers 等信任锚被改写 = 触及主机信任核心。"),
}

# 标签兜底（自定义规则）：按最深优先匹配
TAG_LAYER: List[Tuple[str, Tuple[str, str]]] = [
    ("credential_access", ("L3", "标签含凭据访问（credential_access）：目标直指凭据核心。")),
    ("privilege_escalation", ("L3", "标签含提权（privilege_escalation）：正在夺取更高控制权。")),
    ("lateral_movement", ("L3", "标签含横向移动（lateral_movement）：攻击向核心资产蔓延。")),
    ("collection", ("L3", "标签含数据收集（collection）：正在聚拢核心数据。")),
    ("exfiltration", ("L3", "标签含数据外传（exfiltration）：核心数据正在离开。")),
    ("impact", ("L3", "标签含影响（impact）：核心资产面临破坏。")),
    ("persistence", ("L2", "标签含持久化（persistence）：立足点加固行为。")),
    ("defense_evasion", ("L2", "标签含防御规避（defense_evasion）：立足点后的隐匿。")),
    ("command_and_control", ("L2", "标签含 C2：主机上的控制通道。")),
    ("c2", ("L2", "标签含 C2：主机上的控制通道。")),
    ("discovery", ("L2", "标签含侦察（discovery）：立足点后的内部测绘。")),
    ("canary", ("L2", "标签含诱饵（canary）：主机内活动实体触碰蜜标。")),
    ("malware", ("L2", "标签含恶意软件（malware）：主机上已有恶意执行体。")),
    ("integrity", ("L2", "标签含完整性（integrity）：主机内篡改痕迹。")),
    ("initial_access", ("L1", "标签含初始访问（initial_access）：正在跨越边界。")),
    ("execution", ("L1", "标签含执行（execution）：代码跨越执行边界。")),
    ("download", ("L1", "标签含下载（download）：外部载荷进入。")),
    ("obfuscation", ("L1", "标签含混淆（obfuscation）：载荷去混淆执行。")),
    ("fileless", ("L1", "标签含无文件（fileless）：外部输入直接成代码。")),
    ("exposure", ("L0", "标签含暴露面（exposure）：对外可见的攻击面。")),
]

# 事件 kind 兜底（无规则 ID 也无标签时，按事件类型/来源）
KIND_LAYER: Dict[str, Tuple[str, str]] = {
    "auth.fail": ("L1", "认证失败事件：发生在认证边界上。"),
    "auth.success": ("L1", "认证成功事件：认证边界被跨越。"),
    "process.start": ("L1", "进程启动事件：执行边界上的活动。"),
    "net.connect": ("L0", "网络连接事件：网络侧观测。"),
    "net.listen": ("L0", "监听事件：对外暴露面。"),
    "ndr.direct_ip": ("L0", "NDR 直连 IP：网络侧弱信号。"),
    "ndr.risky_domain": ("L0", "NDR 风险域名：网络侧指示。"),
    "ndr.risky_port": ("L0", "NDR 风险端口：网络侧指示。"),
    "ueba.new_destination": ("L0", "UEBA 新目的地：行为基线弱信号。"),
    "ndr.beaconing": ("L2", "NDR 心跳：主机上疑似驻留体活动。"),
    "ndr.ioc_ip": ("L2", "NDR 情报命中：主机与已知恶意基础设施通信。"),
    "canary.trip": ("L2", "诱饵触碰：主机内活动实体。"),
    "ueba.new_process": ("L2", "UEBA 新进程：主机新执行实体。"),
    "ueba.new_persistence": ("L2", "UEBA 新常驻项：持久化变化。"),
    "tcc.deny": ("L2", "TCC 拒绝：主机内试探被挡。"),
    "baseline.drift": ("L2", "基线漂移：防御姿态变化。"),
    "integrity.change": ("L3", "完整性变化事件：文件核心被触碰。"),
}
DEFAULT_LAYER = ("L2", "未命中规则/标签/事件类型映射——保守归入主机层，待人工研判（不往浅了放，避免虚假安心）。")


def classify(f: Dict[str, Any]) -> Tuple[str, str, str]:
    """返回 (layer, basis, matched_by)。只读，不改 finding。"""
    rid = str(f.get("rule_id") or "")
    if rid in RULE_LAYER:
        layer, basis = RULE_LAYER[rid]
        return layer, basis, f"规则 {rid} 直 hit"
    tags = [str(t) for t in (f.get("tags") or [])]
    for tag, (layer, basis) in TAG_LAYER:
        if tag in tags:
            return layer, basis, f"标签 {tag} 兜底"
    kind = str((f.get("event") or {}).get("kind") or "")
    if kind in KIND_LAYER:
        layer, basis = KIND_LAYER[kind]
        return layer, basis, f"事件类型 {kind} 兜底"
    layer, basis = DEFAULT_LAYER
    return layer, basis, "保守默认"


def _sev_rank(s: str) -> int:
    return SEVERITY_ORDER.get(s, 0)


def build(core, hours: float = 6.0) -> Dict[str, Any]:
    """只读组装纵深剖面。数据源仅 store 快照 + 采集器 detail()，零写入。"""
    now = time.time()
    try:
        hours = float(hours)
    except (TypeError, ValueError):
        hours = 6.0
    hours = max(0.25, min(168.0, hours))
    since = now - hours * 3600.0
    st = core.store

    findings = [f for f in st.snapshot_findings(limit=4000)
                if float(f.get("ts") or 0) >= since]
    incidents = [i for i in st.snapshot_incidents(limit=200)
                 if float(i.get("last_seen") or 0) >= since]

    # ---- 攻击链节点：stage 按 (rule_id, ts, actor) 认领 finding ----
    by_fid = {f.get("fid"): f for f in findings}
    consumed: set = set()
    chains: List[Dict[str, Any]] = []
    chain_nodes: List[Dict[str, Any]] = []
    for inc in incidents:
        stages = inc.get("stages") or []
        node_ids: List[str] = []
        deepest = -1
        # 同 (rule, layer, ts) 的重复 stage 合并成一个节点（×N），避免重叠假影
        merged: Dict[Tuple, Dict[str, Any]] = {}
        for si, s in enumerate(stages):
            rid = str(s.get("rule_id") or "")
            ts = float(s.get("ts") or inc.get("first_seen") or now)
            # 认领对应 finding（同规则同 actor，时间容差 2s）
            match = None
            for f in findings:
                if f.get("fid") in consumed:
                    continue
                if str(f.get("rule_id") or "") == rid and \
                        abs(float(f.get("ts") or 0) - ts) <= 2.0 and \
                        (not s.get("actor") or f.get("actor") == s.get("actor")):
                    match = f
                    break
            layer, basis, matched_by = classify(match or {
                "rule_id": rid, "tags": [], "event": {"kind": ""}})
            if match is not None:
                consumed.add(match.get("fid"))
            key = (rid, layer, round(ts, 3))
            if key in merged:
                m = merged[key]
                m["count"] += 1
                m["stage_names"].append(str(s.get("stage") or ""))
                if match is not None:
                    m["fids"].append(match.get("fid"))
                continue
            nid = f"c{inc.get('iid', '')[:8]}-{si}"
            ev = (match or {}).get("event") or {}
            node = {
                "id": nid, "kind": "stage", "iid": inc.get("iid"),
                "fid": (match or {}).get("fid"),
                "fids": [match.get("fid")] if match is not None else [],
                "ts": ts, "time": iso(ts), "layer": layer,
                "severity": str(s.get("severity") or (match or {}).get("severity") or "info"),
                "severity_cn": str(s.get("severity_cn") or (match or {}).get("severity_cn") or "关注"),
                "rule_id": rid,
                "title": str(s.get("rule_name") or (match or {}).get("name") or rid),
                "stage": str(s.get("stage") or ""), "stage_names": [str(s.get("stage") or "")],
                "count": 1,
                "detail": str(s.get("detail") or (match or {}).get("detail") or ""),
                "advice": str((match or {}).get("advice") or inc.get("advice") or ""),
                "mitre": list((match or {}).get("mitre") or []),
                "tags": list((match or {}).get("tags") or []),
                "actor": str(s.get("actor") or (match or {}).get("actor") or inc.get("actor") or ""),
                "host": str(ev.get("host") or inc.get("host") or ""),
                "event": {k: ev.get(k) for k in ("kind", "source", "process", "pid", "user", "cmdline", "path")},
                "basis": basis, "matched_by": matched_by,
            }
            merged[key] = node
            chain_nodes.append(node)
            node_ids.append(nid)
            deepest = max(deepest, LAYER_ORDER[layer])
        if not node_ids:
            continue
        # 链按时间排序节点（合并后保持插入序≈时间序，显式排一次）
        node_ids.sort(key=lambda nid: next(n["ts"] for n in chain_nodes if n["id"] == nid))
        chains.append({
            "iid": inc.get("iid"), "title": inc.get("title"),
            "template_id": inc.get("template_id"),
            "severity": inc.get("severity"), "severity_cn": inc.get("severity_cn"),
            "summary": inc.get("summary"), "advice": inc.get("advice"),
            "actor": inc.get("actor"), "host": inc.get("host"),
            "first_ts": inc.get("first_seen"), "last_ts": inc.get("last_seen"),
            "first_time": inc.get("first_time"), "last_time": inc.get("last_time"),
            "deepest": LAYERS[deepest]["key"] if deepest >= 0 else None,
            "deepest_cn": LAYERS[deepest]["cn"] if deepest >= 0 else None,
            "node_ids": node_ids, "stage_count": len(stages),
        })

    # ---- 独立 finding 节点：按 (layer, rule_id) 聚合，避免数百重叠点 ----
    groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for f in findings:
        if f.get("fid") in consumed:
            continue
        layer, basis, matched_by = classify(f)
        groups.setdefault((layer, str(f.get("rule_id") or "")), []).append(f)
    solo_nodes: List[Dict[str, Any]] = []
    for (layer, rid), fs in groups.items():
        fs.sort(key=lambda x: float(x.get("ts") or 0))
        latest = fs[-1]
        worst = max(fs, key=lambda x: _sev_rank(str(x.get("severity") or "info")))
        ev = latest.get("event") or {}
        solo_nodes.append({
            "id": f"s{layer}-{rid or 'unknown'}", "kind": "finding",
            "iid": None, "fid": latest.get("fid"),
            "fids": [x.get("fid") for x in fs],
            "ts": float(latest.get("ts") or now), "time": latest.get("time") or iso(now),
            "first_ts": float(fs[0].get("ts") or now),
            "layer": layer,
            "severity": str(worst.get("severity") or "info"),
            "severity_cn": str(worst.get("severity_cn") or "关注"),
            "rule_id": rid, "title": str(latest.get("name") or rid),
            "stage": "", "stage_names": [], "count": len(fs),
            "detail": str(latest.get("detail") or ""),
            "advice": str(latest.get("advice") or ""),
            "mitre": list(latest.get("mitre") or []),
            "tags": list(latest.get("tags") or []),
            "actor": str(latest.get("actor") or ""),
            "host": str(ev.get("host") or ""),
            "event": {k: ev.get(k) for k in ("kind", "source", "process", "pid", "user", "cmdline", "path")},
            "basis": (RULE_LAYER.get(rid) or (None,))[1] or classify(latest)[1],
            "matched_by": classify(latest)[2],
        })

    nodes = chain_nodes + solo_nodes
    nodes.sort(key=lambda n: n["ts"])

    # ---- 每层统计 + 沉默区 ----
    per_layer: Dict[str, Any] = {}
    for l in LAYERS:
        ln = [n for n in nodes if n["layer"] == l["key"]]
        cnt = sum(n["count"] for n in ln)
        worst = max((n["severity"] for n in ln), key=_sev_rank, default=None)
        last_ts = max((n["ts"] for n in ln), default=None)
        per_layer[l["key"]] = {
            "count": cnt, "node_count": len(ln),
            "max_severity": worst,
            "max_severity_cn": next((n["severity_cn"] for n in ln if n["severity"] == worst), None),
            "last_ts": last_ts, "last_time": iso(last_ts) if last_ts else None,
            "silent": cnt == 0,
        }
    silent_layers = [l["key"] for l in LAYERS if per_layer[l["key"]]["silent"]]

    # ---- 当前最深 ----
    deepest_node = None
    if nodes:
        deepest_node = max(nodes, key=lambda n: (LAYER_ORDER[n["layer"]], _sev_rank(n["severity"]), n["ts"]))
    deepest = None
    if deepest_node is not None:
        inc = next((c for c in chains if c["iid"] == deepest_node.get("iid")), None)
        deepest = {
            "layer": deepest_node["layer"], "layer_cn": LAYER_CN[deepest_node["layer"]],
            "ts": deepest_node["ts"], "time": deepest_node["time"],
            "node_id": deepest_node["id"], "title": deepest_node["title"],
            "severity": deepest_node["severity"], "severity_cn": deepest_node["severity_cn"],
            "iid": deepest_node.get("iid"),
            "chain_title": inc.get("title") if inc else None,
        }

    # ---- 观测能力上下文：沉默 ≠ 一定安全，采集器掉线要注明 ----
    coll_ok, coll_total, down = 0, 0, []
    try:
        for c in core.collectors:
            d = c.detail()
            if not d.get("enabled", True):
                continue
            coll_total += 1
            if d.get("available"):
                coll_ok += 1
            else:
                down.append(str(d.get("name") or "?"))
    except Exception:
        pass
    watch = {
        "collectors_ok": coll_ok, "collectors_total": coll_total,
        "collectors_down": down,
        "findings_in_window": len(findings),
        "incidents_in_window": len(incidents),
        "full_coverage": coll_total > 0 and coll_ok == coll_total,
    }

    return {
        "ok": True, "now": iso(now), "ts": now,
        "window": {"hours": hours, "since_ts": since, "until_ts": now,
                   "since": iso(since), "until": iso(now)},
        "layers": LAYERS,
        "nodes": nodes, "chains": chains,
        "per_layer": per_layer, "silent_layers": silent_layers,
        "core_silent": per_layer["L3"]["silent"],
        "deepest": deepest, "watch": watch,
        "mapping": {
            "rules": [{"rule_id": k, "layer": v[0], "basis": v[1]}
                      for k, v in sorted(RULE_LAYER.items())],
            "tags": [{"tag": t, "layer": v[0], "basis": v[1]} for t, v in TAG_LAYER],
            "kinds": [{"kind": k, "layer": v[0], "basis": v[1]}
                      for k, v in sorted(KIND_LAYER.items())],
            "default": {"layer": DEFAULT_LAYER[0], "basis": DEFAULT_LAYER[1]},
            "priority": "rule_id 直 hit > MITRE 标签（最深优先）> 事件 kind > 保守默认 L2",
        },
    }
