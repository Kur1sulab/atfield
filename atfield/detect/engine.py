"""检测引擎：规则求值 + 去重/冷却 + 频率窗口。

降噪三件套（09-soc-soar §6.4 P0）：
1. 去重键 = rule.id|actor|process|path —— 稳定身份，**不含 detail**；
   detail 变化（同一行为的描述文本抖动）只并入已有告警并计数，不新开告警。
2. 冷却按规则类型分级：周期行为类 10–15 分钟，一次性行为类保持短冷却。
3. 抑制条件字段化：字段 equality/regex + 作用域(rule_id+actor) + 过期 + 复审提示，
   保留审计与命中计数；旧 contains 子串条目仍兼容（标记为 deprecated）。
"""
from __future__ import annotations

import collections
import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..model import Event, Finding, sev_max

# ---------------- 冷却分级 ----------------
COOLDOWN_ONESHOT = 20.0        # 一次性行为（诱饵、篡改、凭据访问）：保持短冷却，不漏独立事件
COOLDOWN_RECURRING = 600.0     # 周期行为（侦察、外联、爆破）：10 分钟
COOLDOWN_PERIODIC = 900.0      # 常驻/持久化类：15 分钟
# 对照：Wazuh ignore 级、Sentinel grouping 默认 5h（5min–7d）
COOLDOWN_TAGS: Dict[str, float] = {
    "persistence": COOLDOWN_PERIODIC,
    "discovery": COOLDOWN_RECURRING,
    "command_control": COOLDOWN_RECURRING,
    "lateral_movement": COOLDOWN_RECURRING,
    "credential_access": COOLDOWN_RECURRING,
    "ueba": COOLDOWN_RECURRING,
}
SUPPRESS_REVIEW_DAYS = 90      # 抑制条目默认复审周期
DEDUP_MAX = 20000


def cooldown_for(rule: "Rule") -> float:
    """规则冷却：显式 cooldown 优先，否则按 tags 分级，缺省为一次性短冷却。"""
    if getattr(rule, "cooldown", None) is not None:
        try:
            return max(0.0, float(rule.cooldown))
        except Exception:
            pass
    best = COOLDOWN_ONESHOT
    for t in (rule.tags or ()):
        v = COOLDOWN_TAGS.get(str(t).lower())
        if v and v > best:
            best = v
    return best


def cooldown_for_tags(tags) -> float:
    """无 Rule 对象时（融合层）按 tags 取冷却等级。"""
    best = COOLDOWN_ONESHOT
    for t in (tags or ()):
        v = COOLDOWN_TAGS.get(str(t).lower())
        if v and v > best:
            best = v
    return best


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
    cooldown: Optional[float] = None    # None = 按 tags 分级
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


def dedup_key(rule_id: str, actor: str, ev: Event) -> str:
    """稳定身份键：不含 detail / cmdline / ts 等易变文本。

    同一个行为只要 (规则, 主体, 进程, 路径) 不变，描述文本怎么抖都是同一条告警。
    """
    return f"{rule_id}|{actor}|{ev.process or ''}|{ev.path or ''}"


# ---------------- 抑制条件（字段化） ----------------
def _ev_field(ev: Event, name: str, detail: str = "") -> str:
    name = (name or "").strip()
    if not name:
        return ""
    if name == "detail":
        return detail or ""
    if name.startswith("subject."):
        return str((ev.subject or {}).get(name[len("subject."):]) or "")
    if name == "pid":
        return str(ev.pid or "")
    if name in ("process", "path", "cmdline", "user", "host", "kind", "severity"):
        return str(getattr(ev, name, "") or "")
    v = (ev.subject or {}).get(name)
    return "" if v is None else str(v)


def _match_cond(value: str, cond: Any) -> bool:
    """单个字段条件：字符串=等值；dict 支持 eq/equals/re/regex/in/contains。"""
    if isinstance(cond, dict):
        for op, arg in cond.items():
            op = str(op).lower()
            if op in ("eq", "equals", "="):
                if value != str(arg):
                    return False
            elif op in ("re", "regex", "~"):
                try:
                    if not re.search(str(arg), value):
                        return False
                except re.error:
                    return False
            elif op in ("in", "oneof"):
                vals = arg if isinstance(arg, (list, tuple, set)) else [arg]
                if value not in [str(v) for v in vals]:
                    return False
            elif op in ("contains", "substr"):
                if str(arg) not in value:
                    return False
            elif op in ("ne", "not"):
                if value == str(arg):
                    return False
            else:
                return False
        return True
    return value == str(cond)


class Engine:
    def __init__(self, cfg: Dict[str, Any], store, rules: List[Rule]):
        self.cfg = cfg
        self.store = store
        self.rules = [r for r in rules if r.enabled]
        self.ctx = Ctx(store, cfg)
        # 去重状态：key -> {fid, count, first_ts, last_ts, first_detail, last_detail, last_emit}
        self._dedup: Dict[str, dict] = {}
        self._merges: List[dict] = []
        self.merged_total = 0
        self._dd_path = os.path.join(
            cfg.get("data_dir") or os.path.expanduser("~/.atfield"), "dedup.json")
        self._dd_dirty = False
        self._dd_saved = 0.0
        self.suppress: List[dict] = []
        self.suppressed = 0
        self.suppress_hits = 0
        self._suppress_dirty = False
        self._suppress_saved = 0.0
        self._suppress_path = os.path.join(
            cfg.get("data_dir") or os.path.expanduser("~/.atfield"), "suppress.json")
        self.reload_suppress()
        self._load_dedup()

    # ---------- 去重状态持久化（重启后继续并入，而不是重新开一条） ----------
    def _load_dedup(self) -> None:
        try:
            with open(self._dd_path, "r", encoding="utf-8") as fh:
                d = json.load(fh) or {}
            if isinstance(d, dict):
                self._dedup = {k: v for k, v in d.items() if isinstance(v, dict)}
            # 重启后把计数回填到已载入的告警行（fid 相同 → 同一条告警继续计数）
            try:
                self.store.reapply_dedup(self._dedup)
            except Exception:
                pass
        except Exception:
            self._dedup = {}

    def save_dedup(self, force: bool = False) -> None:
        now = time.time()
        if not self._dd_dirty:
            return
        if not force and now - self._dd_saved < 10:
            return
        try:
            if len(self._dedup) > DEDUP_MAX:
                cut = now - 86400
                self._dedup = {k: v for k, v in self._dedup.items()
                               if float(v.get("last_emit") or 0) > cut}
            tmp = self._dd_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self._dedup, fh, ensure_ascii=False)
            os.replace(tmp, self._dd_path)
            self._dd_dirty = False
            self._dd_saved = now
        except Exception:
            pass

    def take_merges(self) -> List[dict]:
        """取走本批「并入已有告警」的增量，交给 store 更新计数。"""
        out, self._merges = self._merges, []
        self.save_dedup()
        return out

    # ---------- 误报抑制（真实 SOC 必备：抑制必须有据可查、可撤销） ----------
    def reload_suppress(self) -> int:
        items: List[dict] = []
        try:
            with open(self._suppress_path, "r", encoding="utf-8") as fh:
                items = json.load(fh) or []
        except Exception:
            items = list(((self.cfg.get("detect") or {}).get("suppress") or []))
        self.suppress = [s for s in items if isinstance(s, dict)]
        for s in self.suppress:
            s.setdefault("hits", 0)
        return len(self.suppress)

    def save_suppress(self) -> None:
        try:
            tmp = self._suppress_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.suppress, fh, ensure_ascii=False, indent=1)
            os.replace(tmp, self._suppress_path)
            self._suppress_dirty = False
        except Exception:
            pass

    def add_suppress(self, rule_id: str, contains: str = "", note: str = "",
                     fields: Optional[Dict[str, Any]] = None, actor: str = "",
                     expires_in: Optional[float] = None,
                     review_days: Optional[float] = None) -> Dict[str, Any]:
        """新增抑制条目。

        字段化写法（推荐）：
          fields={"process": {"eq": "sshd"}, "path": {"re": "/\\.ssh/"}}
          actor="pid:1234" 限定作用域；expires_in=86400 一天后自动失效；
          review_days=30 到期后进入复审清单。
        旧写法 contains="子串" 仍兼容，但会被标记 deprecated（过宽，容易误杀）。
        """
        rid = (rule_id or "").strip()
        cts = (contains or "").strip()
        flds = dict(fields or {})
        if not rid and not cts and not flds:
            return {"ok": False, "detail": "至少需要规则 ID、字段条件或匹配关键字"}
        if flds:
            for k in flds:
                if not isinstance(k, str) or not k.strip():
                    return {"ok": False, "detail": "字段名不能为空"}
        now = time.time()
        item: Dict[str, Any] = {
            "rule_id": rid, "actor": (actor or "").strip(),
            "fields": flds, "note": (note or "").strip(),
            "added": now, "hits": 0, "last_hit": 0,
            "review_days": float(review_days if review_days is not None else SUPPRESS_REVIEW_DAYS),
            "expires": float(now + float(expires_in)) if expires_in else 0.0,
        }
        if cts:
            item["contains"] = cts
            item["deprecated"] = "contains 子串匹配过宽，建议改用 fields"
        self.suppress.append(item)
        self.save_suppress()
        self.store.log_action("analyst", "suppress:add",
                              f"{rid} {actor} {json.dumps(flds, ensure_ascii=False) or cts}", note)
        return {"ok": True, "count": len(self.suppress), "item": item}

    def remove_suppress(self, index: int) -> Dict[str, Any]:
        if 0 <= index < len(self.suppress):
            item = self.suppress.pop(index)
            self.save_suppress()
            self.store.log_action("analyst", "suppress:remove",
                                  f"{item.get('rule_id')} {item.get('actor') or ''} "
                                  f"{json.dumps(item.get('fields') or {}, ensure_ascii=False)}",
                                  f"命中 {item.get('hits', 0)} 次")
            return {"ok": True, "count": len(self.suppress)}
        return {"ok": False, "detail": "索引不存在"}

    def suppress_review_due(self, now: Optional[float] = None) -> List[dict]:
        """到期复审清单：过期的、或超过 review_days 没复审的。"""
        now = now or time.time()
        out: List[dict] = []
        for i, s in enumerate(self.suppress):
            exp = float(s.get("expires") or 0)
            days = float(s.get("review_days") or SUPPRESS_REVIEW_DAYS)
            added = float(s.get("added") or 0)
            if exp and now > exp:
                out.append({"index": i, "reason": "已过期", "item": s})
            elif added and now - added > days * 86400:
                out.append({"index": i, "reason": f"超过 {int(days)} 天未复审", "item": s})
        return out

    def _is_suppressed(self, rule_id: str, ev: Event, detail: str = "",
                       actor: str = "") -> bool:
        if not self.suppress:
            return False
        now = time.time()
        for s in self.suppress:
            rid = (s.get("rule_id") or "").strip()
            if rid and rid != rule_id:
                continue
            exp = float(s.get("expires") or 0)
            if exp and now > exp:            # 过期即失效，不静默延长
                continue
            sactor = (s.get("actor") or "").strip()
            if sactor and sactor != actor:
                continue
            flds = s.get("fields") or {}
            if isinstance(flds, dict) and flds:
                ok = True
                for name, cond in flds.items():
                    if not _match_cond(_ev_field(ev, str(name), detail), cond):
                        ok = False
                        break
                if not ok:
                    continue
            elif s.get("contains"):
                # 兼容旧条目：子串匹配，作用域仍然是 rule_id
                hay = f"{detail}\n{ev.process or ''}\n{ev.path or ''}\n{ev.cmdline or ''}"
                if str(s["contains"]) not in hay:
                    continue
            s["hits"] = int(s.get("hits") or 0) + 1
            s["last_hit"] = now
            self.suppress_hits += 1
            self._suppress_dirty = True
            self._suppress_saved = self._suppress_saved or now
            return True
        # 命中计数别每条都落盘：30 秒攒一次
        if self._suppress_dirty and now - float(self._suppress_saved or 0) > 30:
            self.save_suppress()
            self._suppress_saved = now
        return False

    # ---------- 准入：抑制 + 稳定键去重（规则引擎与融合层共用） ----------
    def admit(self, f: Finding, ev: Event, cooldown: float) -> bool:
        """一条候选告警是否放行。

        返回 True = 新告警（已把 f 的 count/dedup_key/首末样本填好）；
        返回 False = 被抑制，或已并入同身份的既有告警（计数 +1，不新开）。
        """
        now = time.time()
        if self._is_suppressed(f.rule_id, ev, f.detail, f.actor):
            self.suppressed += 1
            return False
        key = dedup_key(f.rule_id, f.actor, ev)
        ent = self._dedup.get(key)
        if ent and (now - float(ent.get("last_emit") or 0)) < cooldown:
            ent["count"] = int(ent.get("count") or 1) + 1
            ent["last_ts"] = ev.ts or now
            ent["last_detail"] = f.detail
            self.merged_total += 1
            self._merges.append({
                "fid": ent.get("fid") or "", "count": ent["count"],
                "last_detail": f.detail, "last_ts": ent["last_ts"],
                "dedup_key": key,
            })
            self._dd_dirty = True
            return False

        f.count = 1
        f.dedup_key = key
        f.first_detail = f.detail
        f.last_detail = f.detail
        f.first_ts = ev.ts or now
        f.last_ts = ev.ts or now
        self._dedup[key] = {
            "fid": f.fid, "count": 1, "first_ts": ev.ts or now,
            "last_ts": ev.ts or now, "first_detail": f.detail,
            "last_detail": f.detail, "last_emit": now,
        }
        self._dd_dirty = True
        return True

    # ---------- 检测 ----------
    def observe(self, events: List[Event]) -> List[Finding]:
        out: List[Finding] = []
        now = time.time()
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

                detail = ""
                if callable(rule.detail):
                    try:
                        detail = rule.detail(ev, self.ctx) or ""
                    except Exception:
                        detail = ""
                else:
                    detail = str(rule.detail or "")

                f = Finding(
                    rule_id=rule.id, name=rule.name,
                    severity=sev_max(rule.severity, ev.severity),
                    event=ev, actor=actor, tags=list(rule.tags),
                    mitre=list(rule.mitre), detail=detail,
                    advice=rule.advice, ts=ev.ts,
                )
                if self.admit(f, ev, cooldown_for(rule)):
                    out.append(f)
        self.save_dedup()
        if self._suppress_dirty:
            self.save_suppress()
        return out

    def catalog(self) -> List[dict]:
        return [{
            "id": r.id, "name": r.name, "severity": r.severity,
            "tags": list(r.tags), "mitre": list(r.mitre),
            "advice": r.advice, "description": r.description,
            "cooldown": cooldown_for(r),
        } for r in self.rules]
