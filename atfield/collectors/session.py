"""会话采集器：登录会话盘点（who/last），识别远程登录与可疑来源。"""
from __future__ import annotations

import subprocess
import time
from typing import Dict, List

from ..model import Event
from .base import Collector


def _run(cmd: List[str], timeout: float = 6.0) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=timeout).stdout
    except Exception:
        return ""


class SessionCollector(Collector):
    name = "session"
    interval = 20.0

    def __init__(self, cfg, store):
        super().__init__(cfg, store)
        self._seen: Dict[str, dict] = {}
        self._seeded = False

    def collect(self) -> List[Event]:
        now = time.time()
        events: List[Event] = []
        sessions: List[dict] = []

        for line in _run(["/usr/bin/who"]).splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            user, tty = parts[0], parts[1]
            rest = line[len(user) + len(tty):].strip()
            # who 的时间格式不固定，取括号内的来源
            src = ""
            if "(" in rest and rest.endswith(")"):
                src = rest[rest.rfind("(") + 1:-1]
            when = rest[:rest.rfind("(")].strip() if src else rest
            key = f"{user}@{tty}"
            sessions.append({"user": user, "tty": tty, "from": src, "since": when,
                             "remote": bool(src and src not in ("console", "loginwindow"))})
            if key in self._seen:
                continue
            self._seen[key] = {"ts": now, "user": user}
            if not self._seeded:
                continue          # 首轮只记录现状，不把已有会话报成新登录
            remote = bool(src and src not in ("console", "loginwindow"))
            events.append(Event(
                kind="session.login", source=self.name, ts=now,
                user=user, process=tty, severity="medium" if remote else "low",
                subject={"tty": tty, "from": src, "remote": remote, "since": when},
            ))

        for key in list(self._seen):
            if not any(f"{s['user']}@{s['tty']}" == key for s in sessions):
                u = self._seen.pop(key)["user"]
                events.append(Event(
                    kind="session.logout", source=self.name, ts=now, user=u,
                    process=key.split("@")[-1], severity="info", subject={"key": key},
                ))

        # 历史登录（用于态势：谁在这台机器上活动过）
        hist: List[dict] = []
        for line in _run(["/usr/bin/last", "-20"]).splitlines():
            if not line.strip() or line.startswith("wtmp") or "reboot" in line[:20]:
                continue
            parts = line.split()
            if len(parts) < 5:
                continue
            hist.append({"user": parts[0], "tty": parts[1], "from": parts[-1] if len(parts) > 6 else "",
                         "raw": line.strip()})

        self.store.set_state("sessions", {
            "active": sessions, "history": hist[:20], "ts": now,
            "remote": sum(1 for s in sessions if s["remote"]),
        })
        self._seeded = True
        return events


class AuthLogCollector(Collector):
    """从 unified log 回捞近段认证失败（sudo 失败、SSH 失败）作为补充态势。"""

    name = "authlog"
    interval = 60.0

    def collect(self) -> List[Event]:
        now = time.time()
        events: List[Event] = []
        out = _run(["/usr/bin/log", "show", "--last", "5m", "--style", "compact",
                    "--predicate",
                    '(process == "sudo" AND eventMessage CONTAINS "incorrect") '
                    'OR (process == "sshd" AND eventMessage CONTAINS "Failed")'],
                   timeout=25)
        fails = [l for l in out.splitlines() if "incorrect" in l or "Failed" in l]
        if not fails:
            return []
        events.append(Event(
            kind="auth.fail", source=self.name, ts=now, severity="medium",
            process="sudo/sshd", subject={"count": len(fails), "window": "5m"},
            raw={"sample": "\n".join(fails[:5])[:1200]},
        ))
        return events
