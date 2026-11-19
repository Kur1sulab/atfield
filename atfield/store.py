"""内存环形存储 + 可选落盘。线程安全，供采集线程 / 检测线程 / HTTP 线程共享。"""
from __future__ import annotations

import collections
import json
import os
import threading
import time
from typing import Any, Deque, Dict, List, Optional


class Store:
    def __init__(self, cfg: Dict[str, Any]):
        scfg = cfg.get("store", {})
        self._lock = threading.RLock()
        self.events: Deque[dict] = collections.deque(maxlen=int(scfg.get("max_events", 20000)))
        self.findings: Deque[dict] = collections.deque(maxlen=int(scfg.get("max_findings", 4000)))
        self.incidents: Deque[dict] = collections.deque(maxlen=int(scfg.get("max_incidents", 400)))
        self.state: Dict[str, Any] = {}
        self.tickets: Deque[dict] = collections.deque(maxlen=1000)
        self._ticket_seq = 0
        self.meta: Dict[str, Any] = {
            "started_at": time.time(),
            "events_total": 0,
            "findings_total": 0,
            "incidents_total": 0,
            "collectors": {},          # name -> {runs, errors, last_ts, last_ms, last_error}
            "actions": [],             # 响应动作审计
        }
        # 每类事件计数，用于态势
        self.counters: Dict[str, int] = {}
        self._fh = None
        self._path: Optional[str] = None
        self._findings_path: Optional[str] = None
        self._incidents_path: Optional[str] = None
        self._actions_path: Optional[str] = None
        self._tickets_path: Optional[str] = None
        self._max_bytes = int(scfg.get("persist_max_mb", 64)) * 1024 * 1024
        if scfg.get("persist", True):
            ddir = cfg.get("data_dir") or os.path.expanduser("~/.atfield")
            os.makedirs(ddir, exist_ok=True)
            self._path = os.path.join(ddir, "events.jsonl")
            try:
                self._fh = open(self._path, "a", encoding="utf-8")
            except Exception:
                self._fh = None
            # 告警/攻击链/处置动作/工单也落盘：否则 CLI 新进程（--monthly、
            # cron 月报）与重启后的常驻进程都只能看到空库，月报永远 0 条。
            self._findings_path = os.path.join(ddir, "findings.jsonl")
            self._incidents_path = os.path.join(ddir, "incidents.jsonl")
            self._actions_path = os.path.join(ddir, "actions.jsonl")
            self._tickets_path = os.path.join(ddir, "tickets.json")
            self._load_history()

    # ---------- 写 ----------
    def add_events(self, events: List[Any]) -> None:
        if not events:
            return
        with self._lock:
            for ev in events:
                d = ev.to_dict() if hasattr(ev, "to_dict") else dict(ev)
                self.events.append(d)
                self.meta["events_total"] += 1
                self.counters[d.get("kind", "?")] = self.counters.get(d.get("kind", "?"), 0) + 1
                if self._fh is not None:
                    try:
                        self._fh.write(json.dumps({
                            "ts": d.get("ts"), "kind": d.get("kind"),
                            "source": d.get("source"), "pid": d.get("pid"),
                            "process": d.get("process"), "path": d.get("path"),
                            "severity": d.get("severity"), "subject": d.get("subject"),
                        }, ensure_ascii=False) + "\n")
                    except Exception:
                        pass
            self._maybe_rotate()

    def add_findings(self, findings: List[Any]) -> None:
        if not findings:
            return
        with self._lock:
            rows: List[dict] = []
            for f in findings:
                d = f.to_dict() if hasattr(f, "to_dict") else dict(f)
                self.findings.appendleft(d)
                self.meta["findings_total"] += 1
                rows.append(d)
            self._append_jsonl(self._findings_path, rows)

    def add_incident(self, inc: Any) -> None:
        with self._lock:
            d = inc.to_dict() if hasattr(inc, "to_dict") else dict(inc)
            # 同一攻击链（iid）随批次演进：内存里去重保留最新，
            # 落盘用追加式，重启加载时按 iid 去重。
            iid = d.get("iid") or ""
            if iid:
                for old in list(self.incidents):
                    if old.get("iid") == iid:
                        self.incidents.remove(old)
                        break
            self.incidents.appendleft(d)
            self.meta["incidents_total"] += 1
            self._append_jsonl(self._incidents_path, [d])

    def set_state(self, key: str, value: Any) -> None:
        with self._lock:
            self.state[key] = value

    # ---------- 处置工单 ----------
    def create_ticket(self, title: str, severity: str = "medium", ref: str = "",
                      detail: str = "", source: str = "manual") -> Dict[str, Any]:
        with self._lock:
            self._ticket_seq += 1
            tk = {
                "tid": f"T{self._ticket_seq:04d}", "title": title[:240],
                "severity": severity, "ref": ref, "detail": (detail or "")[:2000],
                "source": source, "status": "open", "owner": "",
                "notes": [], "created": time.time(),
                "created_cn": time.strftime("%Y-%m-%d %H:%M:%S"),
                "updated": time.time(),
            }
            self.tickets.appendleft(tk)
            self.meta["tickets_total"] = self.meta.get("tickets_total", 0) + 1
            self.state["tickets"] = list(self.tickets)[:300]
            self._save_tickets()
        return tk

    def update_ticket(self, tid: str, status: str = "", note: str = "",
                      owner: str = "") -> Dict[str, Any]:
        with self._lock:
            for tk in self.tickets:
                if tk["tid"] != tid:
                    continue
                if status in ("open", "ack", "closed"):
                    tk["status"] = status
                if owner:
                    tk["owner"] = owner
                if note:
                    tk["notes"].append({"ts": time.time(),
                                        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                                        "text": note[:1000]})
                tk["updated"] = time.time()
                self.state["tickets"] = list(self.tickets)[:300]
                self._save_tickets()
                return {"ok": True, "ticket": tk}
        return {"ok": False, "detail": "工单不存在"}

    def snapshot_tickets(self, limit: int = 200) -> List[dict]:
        with self._lock:
            return list(self.tickets)[:limit]

    def timeline(self, limit: int = 400) -> List[dict]:
        """统一取证时间线：事件 / 告警 / 事件链 / 响应动作 / 工单 合并按时间排序。"""
        rows: List[dict] = []
        with self._lock:
            for e in list(self.events)[-1500:]:
                rows.append({"ts": e.get("ts") or 0, "type": "event",
                             "kind": e.get("kind"), "title": e.get("text") or e.get("kind"),
                             "severity": e.get("severity"), "source": e.get("source"),
                             "actor": e.get("process") or "", "ref": e.get("pid")})
            for f in list(self.findings):
                rows.append({"ts": (f.get("event") or {}).get("ts") or f.get("ts") or 0,
                             "type": "finding", "kind": f.get("rule_id"),
                             "title": f.get("name"), "severity": f.get("severity"),
                             "source": "rule", "actor": f.get("actor") or "",
                             "ref": f.get("rule_id")})
            for i in list(self.incidents):
                rows.append({"ts": i.get("start") or i.get("ts") or 0, "type": "incident",
                             "kind": i.get("template_id"), "title": i.get("title"),
                             "severity": i.get("severity"), "source": "correlate",
                             "actor": i.get("actor") or "", "ref": i.get("template_id")})
            for a in self.meta.get("actions", []):
                rows.append({"ts": a.get("ts") or 0, "type": "action",
                             "kind": a.get("action"), "title": f"{a.get('action')} · {a.get('target')}",
                             "severity": "info", "source": a.get("actor"),
                             "actor": a.get("target"), "ref": a.get("result")})
            for t in list(self.tickets):
                rows.append({"ts": t.get("created") or 0, "type": "ticket",
                             "kind": t.get("status"), "title": t.get("title"),
                             "severity": t.get("severity"), "source": t.get("source"),
                             "actor": t.get("tid"), "ref": t.get("tid")})
        rows.sort(key=lambda r: r.get("ts") or 0, reverse=True)
        return rows[:limit]

    def get_state(self, key: str, default: Any = None) -> Any:
        with self._lock:
            return self.state.get(key, default)

    def note_collector(self, name: str, ok: bool, ms: float, err: str = "") -> None:
        with self._lock:
            c = self.meta["collectors"].setdefault(name, {"runs": 0, "errors": 0})
            c["runs"] += 1
            c["last_ts"] = time.time()
            c["last_ms"] = round(ms, 1)
            if ok:
                c["last_error"] = ""
                c["ok_since"] = time.time()
            else:
                c["errors"] += 1
                c["last_error"] = (err or "")[:400]

    def log_action(self, actor: str, action: str, target: str, result: str) -> None:
        with self._lock:
            rec = {
                "ts": time.time(), "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "actor": actor, "action": action, "target": target, "result": result,
            }
            self.meta["actions"].append(rec)
            del self.meta["actions"][:-200]
            self._append_jsonl(self._actions_path, [rec])

    # ---------- 读 ----------
    def snapshot_events(self, limit: int = 300, kind: str = "", q: str = "",
                        min_sev: str = "") -> List[dict]:
        from .model import SEVERITY_ORDER
        with self._lock:
            items = list(self.events)[::-1]
        if kind:
            items = [e for e in items if e.get("kind") == kind]
        if min_sev:
            thr = SEVERITY_ORDER.get(min_sev, 0)
            items = [e for e in items if SEVERITY_ORDER.get(e.get("severity", "info"), 0) >= thr]
        if q:
            ql = q.lower()
            items = [e for e in items if ql in (e.get("text") or "").lower()]
        return items[:limit]

    def snapshot_findings(self, limit: int = 200) -> List[dict]:
        with self._lock:
            return list(self.findings)[:limit]

    def snapshot_incidents(self, limit: int = 50) -> List[dict]:
        with self._lock:
            return list(self.incidents)[:limit]

    def counters_snapshot(self) -> Dict[str, int]:
        with self._lock:
            return dict(self.counters)

    # ---------- 维护 ----------
    def _append_jsonl(self, path: Optional[str], rows: List[dict]) -> None:
        """追加式落盘（与 events.jsonl 同款），写失败不影响内存态。"""
        if not path or not rows:
            return
        try:
            with open(path, "a", encoding="utf-8") as fh:
                for d in rows:
                    fh.write(json.dumps(d, ensure_ascii=False) + "\n")
            if os.path.getsize(path) > self._max_bytes:
                os.replace(path, path + ".1")
        except Exception:
            pass

    def _save_tickets(self) -> None:
        """工单量小（≤1000），整体原子重写。"""
        if not self._tickets_path:
            return
        try:
            tmp = self._tickets_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(list(self.tickets), fh, ensure_ascii=False)
            os.replace(tmp, self._tickets_path)
        except Exception:
            pass

    def _load_history(self) -> None:
        """重启 / CLI 新进程：把落盘的告警、攻击链、处置动作、工单读回内存。
        坏行/坏文件只跳过不抛异常——历史数据不能挡住启动。"""
        def _read_jsonl(path: Optional[str]) -> List[dict]:
            rows: List[dict] = []
            if not path:
                return rows
            for p in (path + ".1", path):      # 先读轮转备份，再读当前文件
                try:
                    with open(p, "r", encoding="utf-8") as fh:
                        for line in fh:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                rows.append(json.loads(line))
                            except Exception:
                                pass
                except OSError:
                    pass
            return rows

        try:
            for d in _read_jsonl(self._findings_path):
                self.findings.appendleft(d)    # 文件旧→新，appendleft 后最新在前
            self.meta["findings_total"] = len(self.findings)
        except Exception:
            pass
        try:
            by_iid: "collections.OrderedDict[str, dict]" = collections.OrderedDict()
            for n, d in enumerate(_read_jsonl(self._incidents_path)):
                key = d.get("iid") or f"_n{n}"
                if key in by_iid:
                    by_iid.move_to_end(key)    # 同 iid 保留最后一次（最新状态）
                by_iid[key] = d
            for d in reversed(list(by_iid.values())):
                self.incidents.appendleft(d)
            self.meta["incidents_total"] = len(self.incidents)
        except Exception:
            pass
        try:
            self.meta["actions"] = _read_jsonl(self._actions_path)[-200:]
        except Exception:
            pass
        try:
            if self._tickets_path and os.path.isfile(self._tickets_path):
                with open(self._tickets_path, "r", encoding="utf-8") as fh:
                    tks = json.load(fh)
                if isinstance(tks, list):
                    for tk in tks[:1000]:      # 文件里就是最新在前
                        if isinstance(tk, dict):
                            self.tickets.append(tk)
                    # 恢复工单编号，避免重启后 T0001 撞号
                    seqs = [int(str(tk.get("tid"))[1:]) for tk in self.tickets
                            if str(tk.get("tid") or "").startswith("T")
                            and str(tk.get("tid"))[1:].isdigit()]
                    self._ticket_seq = max(seqs) if seqs else 0
                    self.state["tickets"] = list(self.tickets)[:300]
        except Exception:
            pass

    def _maybe_rotate(self) -> None:
        if self._fh is None or not self._path:
            return
        try:
            if self._fh.tell() > self._max_bytes:
                self._fh.close()
                os.replace(self._path, self._path + ".1")
                self._fh = open(self._path, "w", encoding="utf-8")
        except Exception:
            pass

    def close(self) -> None:
        with self._lock:
            if self._fh is not None:
                try:
                    self._fh.close()
                except Exception:
                    pass
                self._fh = None
