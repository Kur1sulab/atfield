"""文件完整性采集器：对安全关键文件做哈希基线，变动即告警（FIM）。"""
from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any, Dict, List

from ..model import Event
from .base import Collector


def sha256(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


class IntegrityCollector(Collector):
    name = "integrity"
    interval = 45.0

    def __init__(self, cfg, store):
        super().__init__(cfg, store)
        self._paths: List[str] = list(cfg.get("watch_paths") or [])
        self._state_path = os.path.join(cfg.get("data_dir") or os.path.expanduser("~/.atfield"),
                                        "integrity.json")
        self._known: Dict[str, Dict[str, Any]] = {}
        self._loaded = False

    def _load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        try:
            with open(self._state_path, "r", encoding="utf-8") as fh:
                self._known = json.load(fh) or {}
        except Exception:
            self._known = {}

    def _save(self) -> None:
        try:
            tmp = self._state_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self._known, fh, ensure_ascii=False, indent=1)
            os.replace(tmp, self._state_path)
        except Exception:
            pass

    def collect(self) -> List[Event]:
        self._load()
        now = time.time()
        events: List[Event] = []
        rows: List[dict] = []
        dirty = False

        for path in self._paths:
            exists = os.path.exists(path)
            rec = {"path": path, "exists": exists, "digest": "", "mtime": 0, "size": 0,
                   "readable": False}
            if exists:
                try:
                    st = os.stat(path)
                    rec["mtime"] = st.st_mtime
                    rec["size"] = st.st_size
                    rec["readable"] = os.access(path, os.R_OK)
                    if rec["readable"]:
                        rec["digest"] = sha256(path)
                except Exception:
                    pass

            prev = self._known.get(path)
            if prev is None:
                # 首次见到 → 建立基线，不告警
                self._known[path] = {"digest": rec["digest"], "mtime": rec["mtime"],
                                     "size": rec["size"], "exists": exists}
                dirty = True
            else:
                changed = False
                reason = ""
                if prev.get("exists") and not exists:
                    changed, reason = True, "文件被删除"
                elif not prev.get("exists") and exists:
                    changed, reason = True, "新增关键文件"
                elif exists and prev.get("digest") and rec["digest"] and prev["digest"] != rec["digest"]:
                    changed, reason = True, "内容哈希变化"
                if changed:
                    sev = "high" if any(k in path for k in (
                        "authorized_keys", "sshd_config", "sudoers", "pf.conf", "hosts")) else "medium"
                    events.append(Event(
                        kind="integrity.change", source=self.name, ts=now,
                        path=path, process=os.path.basename(path), severity=sev,
                        subject={"reason": reason, "old_digest": (prev.get("digest") or "")[:16],
                                 "new_digest": (rec["digest"] or "")[:16],
                                 "size": rec["size"]},
                    ))
                    self._known[path] = {"digest": rec["digest"], "mtime": rec["mtime"],
                                         "size": rec["size"], "exists": exists}
                    dirty = True
            rows.append({**rec, "digest": (rec["digest"] or "")[:16],
                         "watched": True})

        # 目录级监控：LaunchAgents 新增文件已由 persistence 采集器负责，这里只统计
        if dirty:
            self._save()

        self.store.set_state("integrity", {
            "files": rows, "ts": now,
            "changed": sum(1 for r in rows if r["exists"] and r["readable"]),
            "missing": [r["path"] for r in rows if not r["exists"]],
        })
        return events
