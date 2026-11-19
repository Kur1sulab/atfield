"""持久化采集器：launchd / 登录项 / cron / 配置描述文件。攻击者最爱的地方。"""
from __future__ import annotations

import os
import plistlib
import subprocess
import time
from typing import Dict, List

from ..model import Event
from .base import Collector

HOME = os.path.expanduser("~")

LAUNCH_DIRS = [
    os.path.join(HOME, "Library/LaunchAgents"),
    "/Library/LaunchAgents",
    "/Library/LaunchDaemons",
    "/System/Library/LaunchAgents",       # 只读基线参考
    "/System/Library/LaunchDaemons",
]

INTERESTING_KEYS = ("Program", "ProgramArguments", "RunAtLoad", "KeepAlive",
                    "StartInterval", "StartCalendarInterval", "WatchPaths",
                    "QueueDirectories", "LimitLoadToSessionType")

SUSPICIOUS_BIN = ("/tmp/", "/var/tmp/", "/Users/Shared/", "/dev/shm/",
                  "/private/var/folders/", "curl", "wget", "base64", "python -c",
                  "osascript", "nc ", "ncat", "/bin/sh -c", "bash -c")


def _read_plist(path: str) -> Dict:
    try:
        with open(path, "rb") as fh:
            return plistlib.load(fh) or {}
    except Exception:
        return {}


def _suspicion(pl: Dict, path: str) -> List[str]:
    hits: List[str] = []
    blob = " ".join(str(x) for x in (pl.get("ProgramArguments") or []))
    prog = str(pl.get("Program") or "")
    joined = f"{prog} {blob}"
    for token in SUSPICIOUS_BIN:
        if token in joined:
            hits.append(f"命令含可疑片段「{token.strip()}」")
    if path.startswith("/tmp/") or path.startswith("/Users/Shared/"):
        hits.append("plist 位于临时/共享目录")
    if os.access(path, os.W_OK):
        try:
            st = os.stat(path)
            # 同组/其他可写 = 可被非属主篡改
            if st.st_mode & 0o022:
                hits.append("plist 权限过宽（组/其他可写）")
        except Exception:
            pass
    if pl.get("RunAtLoad") and pl.get("KeepAlive"):
        hits.append("RunAtLoad + KeepAlive（开机常驻）")
    return hits


class PersistenceCollector(Collector):
    name = "persistence"
    interval = 30.0

    def __init__(self, cfg, store):
        super().__init__(cfg, store)
        self._known: Dict[str, Dict] = {}
        self._seeded = False

    def collect(self) -> List[Event]:
        now = time.time()
        events: List[Event] = []
        items: List[dict] = []

        for d in LAUNCH_DIRS:
            if not os.path.isdir(d):
                continue
            try:
                names = sorted(os.listdir(d))
            except Exception:
                continue
            for name in names:
                if not name.endswith(".plist"):
                    continue
                full = os.path.join(d, name)
                pl = _read_plist(full)
                sus = _suspicion(pl, full)
                rec = {
                    "path": full, "label": pl.get("Label") or name,
                    "program": pl.get("Program") or " ".join(pl.get("ProgramArguments") or []),
                    "run_at_load": bool(pl.get("RunAtLoad")),
                    "keep_alive": bool(pl.get("KeepAlive")),
                    "interval": pl.get("StartInterval"),
                    "scope": "system" if full.startswith(("/Library", "/System")) else "user",
                    "writable": os.access(full, os.W_OK),
                    "suspicious": sus,
                    "mtime": os.path.getmtime(full),
                }
                items.append(rec)
                prev = self._known.get(full)
                if prev is None:
                    if not self._seeded:
                        continue      # 首轮建基线，不逐条报「新增」
                    sev = "high" if sus else "low"
                    events.append(Event(
                        kind="persistence.add", source=self.name, ts=now,
                        path=full, process=rec["label"], severity=sev,
                        cmdline=str(rec["program"])[:400], user=HOME.split("/")[-1],
                        subject={"label": rec["label"], "scope": rec["scope"],
                                 "run_at_load": rec["run_at_load"],
                                 "suspicious": sus},
                    ))
                elif prev.get("mtime") != rec["mtime"]:
                    events.append(Event(
                        kind="persistence.modify", source=self.name, ts=now,
                        path=full, process=rec["label"],
                        severity="high" if sus else "medium",
                        cmdline=str(rec["program"])[:400],
                        subject={"label": rec["label"], "suspicious": sus},
                    ))
        self._known = {r["path"]: r for r in items}
        self._seeded = True

        # cron：当前用户 crontab
        cron_rows: List[dict] = []
        try:
            out = subprocess.run(["/usr/bin/crontab", "-l"], capture_output=True,
                                 text=True, encoding="utf-8", errors="replace",
                                 timeout=5).stdout
            for line in out.splitlines():
                if line.strip() and not line.strip().startswith("#"):
                    cron_rows.append({"line": line.strip()})
        except Exception:
            pass
        # 系统级 cron 目录
        for d in ("/usr/lib/cron/tabs", "/etc/cron.d", "/var/at/tabs"):
            if not os.path.isdir(d):
                continue
            try:
                for name in os.listdir(d):
                    cron_rows.append({"line": f"{os.path.join(d, name)}"})
            except Exception:
                pass

        # 登录项 / 第三方安全产品
        login_items: List[dict] = []
        for d in (os.path.join(HOME, "Library/Application Support/com.apple.backgroundtaskmanagementagent"),
                  "/var/db/com.apple.xpc.launchd"):
            login_items.append({"path": d, "exists": os.path.isdir(d)})

        self.store.set_state("persistence", {
            "items": sorted(items, key=lambda r: (-len(r["suspicious"]), r["label"])),
            "suspicious": [r for r in items if r["suspicious"]],
            "cron": cron_rows,
            "ts": now,
            "count": len(items),
        })
        return events


class LoginItemCollector(Collector):
    """第三方安全软件 / 系统扩展盘点——被卸载或被篡改都是强信号。"""

    name = "securitysw"
    interval = 180.0

    KNOWN = {
        "/Applications/CrowdStrike Falcon.app": "CrowdStrike Falcon",
        "/Applications/SentinelOne.app": "SentinelOne",
        "/Library/Application Support/JAMF": "JAMF",
        "/Applications/Cisco Secure Client.app": "Cisco Secure Client",
        "/Library/Application Support/McAfee": "McAfee",
        "/Applications/Netskope Client.app": "Netskope",
        "/Library/Application Support/com.apple.TCC": "TCC 数据库",
    }

    def __init__(self, cfg, store):
        super().__init__(cfg, store)
        self._seen: Dict[str, bool] = {}

    def collect(self) -> List[Event]:
        now = time.time()
        events: List[Event] = []
        found: List[dict] = []
        for path, label in self.KNOWN.items():
            exists = os.path.exists(path)
            found.append({"path": path, "label": label, "present": exists})
            prev = self._seen.get(path)
            if prev is True and not exists:
                events.append(Event(
                    kind="defense.removed", source=self.name, ts=now,
                    path=path, process=label, severity="high",
                    subject={"label": label, "reason": "安全组件消失"},
                ))
            self._seen[path] = exists

        ext: List[str] = []
        try:
            out = subprocess.run(["/usr/bin/systemextensionsctl", "list"],
                                 capture_output=True, text=True,
                                 encoding="utf-8", errors="replace", timeout=8).stdout
            ext = [l.strip() for l in out.splitlines() if l.strip()][:40]
        except Exception:
            pass

        self.store.set_state("security_sw", {"items": found, "extensions": ext, "ts": now})
        return events
