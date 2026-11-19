"""SOAR：声明式处置剧本（YAML）+ 审批门 + 审计。

剧本文件放 ~/.atfield/playbooks/*.yaml：

    id: PB-001
    name: 高危植入自动隔离
    enabled: true
    when:
      severity: [high, critical]      # 命中告警的最低等级
      tags: [persistence]             # 任一标签命中即可
      tags_mode: any                  # any | all
      chains: [CHAIN-001]             # 也可只对特定攻击链触发
    require_confirm: true             # true = 只生成待执行动作，需人工确认
    actions:
      - type: suspend_process
      - type: export_evidence
      - type: block_ip                 # 从告警事件里取对端地址
      - type: ticket
    cooldown: 300

设计原则：默认 require_confirm=true —— 自动处置可以建议，但动别人的进程要先留人工确认痕迹。
"""
from __future__ import annotations

import os
import time
import uuid
from typing import Any, Dict, List, Optional

try:
    import yaml as _pyyaml
    YAML_ENGINE = "PyYAML"
except Exception:      # 换了 python 解释器就可能没有；用内置解析器兜底
    _pyyaml = None
    YAML_ENGINE = "内置解析器"

from . import yamlite


def _parse(text: str):
    if _pyyaml is not None:
        return _pyyaml.safe_load(text)
    return yamlite.load(text)

DEFAULT_PLAYBOOK = """\
# 心之壁 默认剧本（可自由修改；改完在界面点「重载剧本」即可生效）
- id: PB-001
  name: 高危植入 → 挂起进程并取证
  enabled: true
  when:
    severity: [critical]
    tags: [persistence, command_control]
    tags_mode: any
  require_confirm: true
  cooldown: 300
  actions:
    - type: suspend_process
    - type: export_evidence
    - type: ticket

- id: PB-002
  name: 命中 C2 端口 → 生成封禁命令
  enabled: true
  when:
    severity: [critical, high]
    tags: [command_control]
  require_confirm: true
  cooldown: 600
  actions:
    - type: block_ip
    - type: ticket

- id: PB-003
  name: 诱饵被触碰 → 立即取证
  enabled: true
  when:
    severity: [critical]
    tags: [canary, honeypot]
  require_confirm: false          # 取证是只读动作，允许自动执行
  cooldown: 120
  actions:
    - type: export_evidence
    - type: ticket
"""

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class Playbooks:
    def __init__(self, cfg: Dict[str, Any], store, responder):
        self.cfg = cfg
        self.store = store
        self.responder = responder
        self.dir = os.path.join(cfg.get("data_dir") or os.path.expanduser("~/.atfield"),
                                "playbooks")
        os.makedirs(self.dir, exist_ok=True)
        self._ensure_default()
        self.items: List[dict] = []
        self._fired: Dict[str, float] = {}
        self.pending: List[dict] = []
        self.history: List[dict] = []
        self.reload()

    def _ensure_default(self) -> None:
        path = os.path.join(self.dir, "default.yaml")
        if not os.path.exists(path):
            try:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(DEFAULT_PLAYBOOK)
            except Exception:
                pass

    def reload(self) -> Dict[str, Any]:
        items: List[dict] = []
        errors: List[str] = []
        for name in sorted(os.listdir(self.dir)):
            if not name.endswith((".yaml", ".yml")):
                continue
            full = os.path.join(self.dir, name)
            try:
                with open(full, "r", encoding="utf-8") as fh:
                    data = _parse(fh.read()) or []
                if isinstance(data, dict):
                    data = [data]
                for pb in data:
                    if not isinstance(pb, dict) or not pb.get("id"):
                        continue
                    pb.setdefault("enabled", True)
                    pb.setdefault("require_confirm", True)
                    pb.setdefault("cooldown", 300)
                    pb["_file"] = name
                    items.append(pb)
            except Exception as exc:
                errors.append(f"{name}: {type(exc).__name__}: {exc}")
        self.items = items
        self.store.set_state("playbooks", self.status(errors))
        return {"ok": True, "count": len(items), "errors": errors, "engine": YAML_ENGINE}

    def status(self, errors: Optional[List[str]] = None) -> Dict[str, Any]:
        return {
            "count": len(self.items),
            "engine": YAML_ENGINE,
            "items": [{"id": p.get("id"), "name": p.get("name"),
                       "enabled": p.get("enabled"), "require_confirm": p.get("require_confirm"),
                       "actions": [a.get("type") for a in (p.get("actions") or [])],
                       "when": p.get("when") or {}, "file": p.get("_file")}
                      for p in self.items],
            "pending": self.pending[-50:],
            "history": self.history[-50:],
            "errors": errors or [],
            "ts": time.time(),
        }

    # ---------- 匹配 ----------
    def _match(self, pb: dict, finding: dict, incident: Optional[dict]) -> bool:
        when = pb.get("when") or {}
        if not pb.get("enabled", True):
            return False
        want = [s for s in (when.get("severity") or [])]
        if want:
            cur = SEV_ORDER.get(finding.get("severity") or "info", 0)
            if cur < min(SEV_ORDER.get(w, 0) for w in want):
                return False
        tags = set(when.get("tags") or [])
        if tags:
            have = set(finding.get("tags") or [])
            if incident:
                have |= set(incident.get("template_id") or []).union(
                    {s.get("stage") for s in (incident.get("stages") or [])})
            if when.get("tags_mode") == "all":
                if not tags.issubset(have):
                    return False
            elif not (tags & have):
                return False
        chains = when.get("chains") or []
        if chains and (not incident or incident.get("template_id") not in chains):
            return False
        return True

    # ---------- 触发 ----------
    def on_findings(self, findings: List[dict], incidents: List[dict]) -> List[dict]:
        now = time.time()
        triggered: List[dict] = []
        inc_by_actor: Dict[str, dict] = {i.get("actor"): i for i in incidents}
        for f in findings:
            inc = inc_by_actor.get(f.get("actor"))
            for pb in self.items:
                if not self._match(pb, f, inc):
                    continue
                key = f"{pb.get('id')}|{f.get('rule_id')}|{f.get('actor')}"
                if now - self._fired.get(key, 0) < float(pb.get("cooldown") or 300):
                    continue
                self._fired[key] = now
                run = {
                    "run_id": uuid.uuid4().hex[:8],
                    "playbook": pb.get("id"), "name": pb.get("name"),
                    "ts": now, "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "trigger": {"rule_id": f.get("rule_id"), "rule_name": f.get("name"),
                                "severity": f.get("severity"),
                                "severity_cn": f.get("severity_cn"),
                                "detail": f.get("detail"), "pid": (f.get("event") or {}).get("pid"),
                                "actor": f.get("actor")},
                    "incident": inc.get("template_id") if inc else None,
                    "require_confirm": bool(pb.get("require_confirm", True)),
                    "results": [],
                    "status": "pending" if pb.get("require_confirm", True) else "done",
                }
                if run["require_confirm"]:
                    self.pending.append(run)
                    self.store.log_action("playbook", "pending", pb.get("id") or "",
                                          f"待确认: {f.get('rule_id')}")
                else:
                    run["results"] = self._execute(pb, f, inc)
                self.history.append(run)
                triggered.append(run)
        self._trim()
        self.store.set_state("playbooks", self.status())
        return triggered

    def confirm(self, run_id: str) -> Dict[str, Any]:
        for run in self.pending:
            if run.get("run_id") != run_id:
                continue
            pb = next((p for p in self.items if p.get("id") == run.get("playbook")), None)
            if not pb:
                return {"ok": False, "detail": "剧本已不存在（可能已被删除）"}
            fake_finding = {
                "rule_id": (run.get("trigger") or {}).get("rule_id"),
                "severity": (run.get("trigger") or {}).get("severity"),
                "event": {"pid": (run.get("trigger") or {}).get("pid")},
                "actor": (run.get("trigger") or {}).get("actor"),
            }
            run["results"] = self._execute(pb, fake_finding, None)
            run["status"] = "done"
            self.pending.remove(run)
            self.store.set_state("playbooks", self.status())
            return {"ok": True, "run": run}
        return {"ok": False, "detail": "未找到待确认的动作"}

    def reject(self, run_id: str) -> Dict[str, Any]:
        for run in self.pending:
            if run.get("run_id") == run_id:
                run["status"] = "rejected"
                self.pending.remove(run)
                self.store.log_action("analyst", "playbook:reject", run.get("playbook") or "", run_id)
                self.store.set_state("playbooks", self.status())
                return {"ok": True, "detail": "已驳回，未执行任何动作"}
        return {"ok": False, "detail": "未找到待确认的动作"}

    # ---------- 执行 ----------
    def _execute(self, pb: dict, finding: dict, incident: Optional[dict]) -> List[dict]:
        out: List[dict] = []
        pid = int(((finding.get("event") or {}).get("pid")) or 0)
        for action in (pb.get("actions") or []):
            t = action.get("type")
            try:
                if t == "suspend_process":
                    out.append({"action": t, **(self.responder.suspend(pid) if pid else
                                                {"ok": False, "detail": "事件无 pid，跳过"})})
                elif t == "terminate_process":
                    out.append({"action": t, **(self.responder.terminate(pid) if pid else
                                                {"ok": False, "detail": "事件无 pid，跳过"})})
                elif t == "export_evidence":
                    out.append({"action": t, **self.responder.export_evidence(self.store)})
                elif t == "block_ip":
                    ip = ((finding.get("event") or {}).get("subject") or {}).get("rip") or ""
                    out.append({"action": t, **(self.responder.block_commands(ip) if ip else
                                                {"ok": False, "detail": "事件无对端 IP，跳过"})})
                elif t == "ticket":
                    tk = self.store.create_ticket(
                        title=f"[{pb.get('id')}] {(finding.get('rule_id') or '')} 命中",
                        severity=finding.get("severity") or "medium",
                        ref=finding.get("rule_id") or "",
                        detail=(finding.get("detail") or "")[:400],
                        source="playbook")
                    out.append({"action": t, "ok": True, "detail": f"工单 {tk['tid']} 已创建"})
                else:
                    out.append({"action": t, "ok": False, "detail": "未知动作类型"})
            except Exception as exc:
                out.append({"action": t, "ok": False, "detail": f"{type(exc).__name__}: {exc}"})
        return out

    def _trim(self) -> None:
        self.history = self.history[-200:]
        self.pending = self.pending[-50:]
        if len(self._fired) > 4000:
            cutoff = time.time() - 7200
            self._fired = {k: v for k, v in self._fired.items() if v > cutoff}
