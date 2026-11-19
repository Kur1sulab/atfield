"""攻击链关联：把离散的规则命中共编译成「一条可解释的攻击时序」。

这是把 EDR（单点行为）升级成态势感知（结构化攻击叙事）的核心一环：
单条规则命中只能说明「这里不对」，攻击链才能说明「对手在干什么、到哪一步了」。
"""
from __future__ import annotations

import collections
import time
from typing import Any, Deque, Dict, List, Optional

from ..model import Incident, SEVERITY_ORDER, sev_max

TEMPLATES: List[Dict[str, Any]] = [
    {
        "id": "CHAIN-001",
        "title": "植入链：执行 → 持久化 → 外联",
        "severity": "critical",
        "stages": [
            {"name": "初始执行", "tags": {"execution"}, "hint": "落地/执行可疑载荷"},
            {"name": "建立持久化", "tags": {"persistence"}, "hint": "写入 launchd/登录项常驻"},
            {"name": "对外通信", "tags": {"command_control"}, "hint": "与外部地址建立通道"},
        ],
        "advice": "这是最典型的完整入侵链条：先落地、再常驻、最后回连。立即断外联 → 固化证据 → 清理常驻项 → 排查同源投放。",
        "summary": "对手已经完成从落地到常驻再到外联的完整闭环，主机应视为已失陷。",
    },
    {
        "id": "CHAIN-002",
        "title": "凭据外泄链：凭据访问 → 对外通信",
        "severity": "critical",
        "stages": [
            {"name": "读取凭据", "tags": {"credential_access"}, "hint": "触达私钥/钥匙串/Cookie"},
            {"name": "数据外发", "tags": {"command_control"}, "hint": "对外建立连接"},
        ],
        "advice": "在任何清理动作之前，先假定凭据已泄露：轮换 SSH 密钥、云 AK/SK、浏览器会话，并审计这些凭据的后续使用。",
        "summary": "凭据被读取后紧接着发生对外通信，数据或凭据可能已经外流。",
    },
    {
        "id": "CHAIN-003",
        "title": "爆破得手链：认证失败爆发 → 登录成功",
        "severity": "critical",
        "stages": [
            {"name": "认证失败爆发", "tags": {"credential_access"}, "hint": "口令喷洒/爆破"},
            {"name": "登录成功", "tags": {"initial_access"}, "hint": "来自异常来源的会话"},
        ],
        "advice": "立刻核实登录来源 IP 与账户；如非本人操作，先踢会话、再改口令、最后查该账户落地了什么。",
        "summary": "短时间内先出现密集认证失败，随后出现成功登录——高度符合口令爆破得手。",
    },
    {
        "id": "CHAIN-004",
        "title": "防御规避链：削弱防护 → 执行载荷",
        "severity": "high",
        "stages": [
            {"name": "削弱防护", "tags": {"defense_evasion"}, "hint": "关闭 SIP/Gatekeeper/EDR 或绕过签名"},
            {"name": "执行载荷", "tags": {"execution"}, "hint": "在降防护状态下执行"},
        ],
        "advice": "攻击者先拆防线再动手，说明是有计划的入侵而非误操作；重点排查降防护之后写入的所有文件。",
        "summary": "防护被削弱后紧接着出现可疑执行，符合「先拆防线再落地」的操作顺序。",
    },
    {
        "id": "CHAIN-005",
        "title": "侦察推进链：主机踩点 → 横向/外联",
        "severity": "high",
        "stages": [
            {"name": "主机侦察", "tags": {"discovery"}, "hint": "聚集的信息收集命令"},
            {"name": "横向或外联", "tags": {"lateral_movement", "command_control"}, "hint": "扫描/建连"},
        ],
        "advice": "侦察之后建立连接通常意味着在找下一跳或回传数据；封禁对端并检查同网段其他主机。",
        "summary": "先密集踩点、后大量建连，是横向移动的典型前奏。",
    },
    {
        "id": "CHAIN-006",
        "title": "持久访问链：完整性篡改 → 常驻项落地",
        "severity": "critical",
        "stages": [
            {"name": "篡改安全配置", "tags": {"integrity"}, "hint": "authorized_keys/hosts/防火墙被改"},
            {"name": "写入常驻项", "tags": {"persistence"}, "hint": "launchd/登录项"},
        ],
        "advice": "同时改动授权文件与常驻项，意在长期驻留；按「已被植入持久访问」处置，回滚配置并轮换密钥。",
        "summary": "安全配置被篡改且伴随常驻项写入，属于持久化后门手法。",
    },
]


class Correlator:
    def __init__(self, cfg: Dict[str, Any], store):
        dcfg = cfg.get("detect") or {}
        self.window = float(dcfg.get("correlate_window", 1200))
        self.min_stages = int(dcfg.get("min_chain_stages", 2))
        self.store = store
        self._by_actor: Dict[str, Deque[dict]] = {}
        self._fired: Dict[str, float] = {}
        self._lock_budget = 400

    def ingest(self, findings: List[dict]) -> List[Incident]:
        """findings 为已落库的 dict（含 tags/actor/ts/severity）。"""
        incidents: List[Incident] = []
        for f in findings:
            actor = f.get("actor") or "host"
            dq = self._by_actor.setdefault(actor, collections.deque(maxlen=200))
            dq.append(f)
            for tpl in TEMPLATES:
                inc = self._try(tpl, actor, dq)
                if inc:
                    incidents.append(inc)
        if len(self._by_actor) > self._lock_budget:
            cutoff = time.time() - self.window * 2
            for actor in list(self._by_actor):
                dq = self._by_actor[actor]
                if not dq or dq[-1].get("ts", 0) < cutoff:
                    self._by_actor.pop(actor, None)
        return incidents

    def _try(self, tpl: Dict[str, Any], actor: str, dq: Deque[dict]) -> Optional[Incident]:
        now = time.time()
        recent = [f for f in dq if now - f.get("ts", 0) <= self.window]
        if len(recent) < len(tpl["stages"]):
            return None
        stages: List[dict] = []
        cursor = 0.0
        for stage in tpl["stages"]:
            hit = None
            for f in recent:
                if f.get("ts", 0) < cursor:
                    continue
                if set(f.get("tags") or []) & stage["tags"]:
                    hit = f
                    break
            if hit is None:
                return None
            cursor = hit.get("ts", 0)
            stages.append({
                "stage": stage["name"],
                "hint": stage["hint"],
                "rule_id": hit.get("rule_id"),
                "rule_name": hit.get("name"),
                "severity": hit.get("severity"),
                "severity_cn": hit.get("severity_cn"),
                "detail": hit.get("detail"),
                "time": hit.get("time"),
                "ts": hit.get("ts"),
                "actor": hit.get("actor"),
            })
        key = f"{tpl['id']}|{actor}"
        if now - self._fired.get(key, 0) < self.window:
            return None
        self._fired[key] = now

        sev = tpl["severity"]
        for s in stages:
            sev = sev_max(sev, s.get("severity") or "info")
        span = max(1.0, cursor - min(s.get("ts", now) for s in stages))
        score = {"info": 10, "low": 25, "medium": 45, "high": 70, "critical": 90}.get(sev, 30)
        score = min(100.0, score + min(10.0, len(stages) * 2.5) - max(0.0, span / self.window) * 5)
        return Incident(
            title=tpl["title"], template_id=tpl["id"], severity=sev,
            stages=stages, host=(stages[0].get("actor") or ""),
            actor=actor,
            first_seen=min(s.get("ts", now) for s in stages),
            last_seen=cursor, score=score,
            summary=tpl["summary"], advice=tpl["advice"],
        )

    def catalog(self) -> List[dict]:
        return [{"id": t["id"], "title": t["title"], "severity": t["severity"],
                 "stages": [s["name"] for s in t["stages"]], "advice": t["advice"]}
                for t in TEMPLATES]
