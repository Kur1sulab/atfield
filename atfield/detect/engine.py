"""检测引擎：规则求值 + 去重/冷却 + 频率窗口。"""
from __future__ import annotations

import collections
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..model import Event, Finding, sev_max


class Ctx:
    """规则可用的上下文：滑动窗口计数、状态读取、一次性触发。"""

    def __init__(self, store, cfg: Dict[str, Any]):
        self.store = store
        self.cfg = cfg
        self._freq: Dict[str, collections.deque] = {}
        self._fired: Dict[str, float] = {}

    def freq(self, key: str, window: float, threshold: int) -> int:
        """维护滑动窗口，返回窗口内次数。"""
        now = time.time()
        dq = self._freq.setdefault(key, collections.deque())
        while dq and now - dq[0] > window:
            dq.popleft()
        dq.append(now)
        return len(dq)

    def reached(self, key: str, window: float, threshold: int) -> bool:
        """窗口内达到阈值，且在 window 内只返回一次 True（避免刷屏）。"""
        n = self.freq(key, window, threshold)
        if n < threshold:
            return False
        once_key = f"reached:{key}"
        last = self._fired.get(once_key, 0.0)
        if time.time() - last < window:
            return False
        self._fired[once_key] = time.time()
        return True

    def once(self, key: str, cooldown: float = 300.0) -> bool:
        last = self._fired.get(key, 0.0)
        if time.time() - last < cooldown:
            return False
        self._fired[key] = time.time()
        return True

    def state(self, name: str, default: Any = None) -> Any:
        return self.store.get_state(name, default)

    def counters(self) -> Dict[str, int]:
        return self.store.counters_snapshot()


@dataclass
class Rule:
    id: str
    name: str
    severity: str
    when: Callable[[Event, Ctx], bool]
    detail: Callable[[Event, Ctx], str] | str = ""
    advice: str = ""
    tags: Tuple[str, ...] = ()
    mitre: Tuple[str, ...] = ()
    cooldown: float = 20.0
    actor: Optional[Callable[[Event, Ctx], str]] = None
    enabled: bool = True
    description: str = ""


def _proc_rows(ctx: Ctx) -> List[dict]:
    return (ctx.state("processes") or {}).get("rows") or []


def root_pid(pid: Optional[int], ctx: Ctx) -> str:
    """沿 ppid 上溯到最近的「根基」进程，作为攻击链归属键。"""
    if not pid:
        return "host"
    parent = {r["pid"]: r.get("ppid") or 0 for r in _proc_rows(ctx)}
    cur = pid
    seen = set()
    while True:
        p = parent.get(cur)
        if not p or p in (0, 1) or p in seen or len(seen) > 12:
            return f"pid:{cur}"
        seen.add(cur)
        cur = p


def exe_of(pid: Optional[int], ctx: Ctx) -> str:
    if not pid:
        return ""
    for r in _proc_rows(ctx):
        if r["pid"] == pid:
            return r.get("exe") or ""
    return ""


class Engine:
    def __init__(self, cfg: Dict[str, Any], store, rules: List[Rule]):
        self.cfg = cfg
        self.store = store
        self.rules = [r for r in rules if r.enabled]
        self.ctx = Ctx(store, cfg)
        self._last_hit: Dict[str, float] = {}
        self.suppress: List[dict] = []
        self.suppressed = 0
        self._suppress_path = os.path.join(
            cfg.get("data_dir") or os.path.expanduser("~/.atfield"), "suppress.json")
        self.reload_suppress()

    # ---------- 误报抑制（真实 SOC 必备：抑制必须有据可查、可撤销） ----------
    def reload_suppress(self) -> int:
        items: List[dict] = []
        try:
            with open(self._suppress_path, "r", encoding="utf-8") as fh:
                items = json.load(fh) or []
        except Exception:
            items = list(((self.cfg.get("detect") or {}).get("suppress") or []))
        self.suppress = [s for s in items if isinstance(s, dict)]
        return len(self.suppress)

    def save_suppress(self) -> None:
        try:
            tmp = self._suppress_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.suppress, fh, ensure_ascii=False, indent=1)
            os.replace(tmp, self._suppress_path)
        except Exception:
            pass

    def add_suppress(self, rule_id: str, contains: str = "", note: str = "") -> Dict[str, Any]:
        if not rule_id and not contains:
            return {"ok": False, "detail": "至少需要规则 ID 或匹配关键字"}
        self.suppress.append({"rule_id": rule_id.strip(), "contains": contains.strip(),
                              "note": note.strip(), "added": time.time()})
        self.save_suppress()
        self.store.log_action("analyst", "suppress:add", f"{rule_id} {contains}", note)
        return {"ok": True, "count": len(self.suppress)}

    def remove_suppress(self, index: int) -> Dict[str, Any]:
        if 0 <= index < len(self.suppress):
            item = self.suppress.pop(index)
            self.save_suppress()
            self.store.log_action("analyst", "suppress:remove",
                                  f"{item.get('rule_id')} {item.get('contains')}", "")
            return {"ok": True, "count": len(self.suppress)}
        return {"ok": False, "detail": "索引不存在"}

    def _is_suppressed(self, rule_id: str, ev: Event, detail: str) -> bool:
        if not self.suppress:
            return False
        hay = f"{detail}\n{ev.process or ''}\n{ev.path or ''}\n{ev.cmdline or ''}"
        for s in self.suppress:
            rid = (s.get("rule_id") or "").strip()
            if rid and rid != rule_id:
                continue
            needle = (s.get("contains") or "").strip()
            if needle and needle not in hay:
                continue
            return True
        return False

    def observe(self, events: List[Event]) -> List[Finding]:
        out: List[Finding] = []
        for ev in events:
            for rule in self.rules:
                try:
                    if not rule.when(ev, self.ctx):
                        continue
                except Exception:
                    continue
                actor = ""
                if rule.actor is not None:
                    try:
                        actor = rule.actor(ev, self.ctx)
                    except Exception:
                        actor = ""
                if not actor:
                    actor = root_pid(ev.pid, self.ctx) if ev.pid else "host"

                # 冷却：同规则 + 同主体 + 同细节，避免重复刷屏
                detail = ""
                if callable(rule.detail):
                    try:
                        detail = rule.detail(ev, self.ctx) or ""
                    except Exception:
                        detail = ""
                else:
                    detail = str(rule.detail or "")

                if self._is_suppressed(rule.id, ev, detail):
                    self.suppressed += 1
                    continue

                dedup = f"{rule.id}|{actor}|{ev.process}|{ev.path}|{detail[:60]}"
                last = self._last_hit.get(dedup, 0.0)
                if time.time() - last < rule.cooldown:
                    continue
                self._last_hit[dedup] = time.time()

                out.append(Finding(
                    rule_id=rule.id, name=rule.name,
                    severity=sev_max(rule.severity, ev.severity),
                    event=ev, actor=actor, tags=list(rule.tags),
                    mitre=list(rule.mitre), detail=detail,
                    advice=rule.advice, ts=ev.ts,
                ))
        if len(self._last_hit) > 20000:
            cutoff = time.time() - 3600
            self._last_hit = {k: v for k, v in self._last_hit.items() if v > cutoff}
        return out

    def catalog(self) -> List[dict]:
        return [{
            "id": r.id, "name": r.name, "severity": r.severity,
            "tags": list(r.tags), "mitre": list(r.mitre),
            "advice": r.advice, "description": r.description,
        } for r in self.rules]
