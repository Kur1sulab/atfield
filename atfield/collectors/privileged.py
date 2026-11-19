"""特权遥测采集器（可选增强）：有 root 时用 EndpointSecurity 拿到进程/文件级细粒度事件。

没有 root 时本采集器自动降级为 unavailable，主程序照常运行——
架构上「非特权可用、特权增强」，不把 root 当唯一前提。
"""
from __future__ import annotations

import json
import os
import select
import subprocess
import threading
import time
from typing import Dict, List

from ..model import Event
from .base import Collector

ESLOGGER = "/usr/bin/eslogger"

# eslogger 事件 -> 我们关心的语义
ES_INTEREST = {
    "exec": ("process.exec", "info"),
    "fork": ("process.fork", "info"),
    "exit": ("process.exit", "info"),
    "open": ("file.open", "info"),
    "create": ("file.create", "info"),
    "write": ("file.write", "info"),
    "unlink": ("file.delete", "medium"),
    "rename": ("file.rename", "medium"),
    "mount": ("system.mount", "medium"),
    "kextload": ("system.kextload", "high"),
    "cs_invalidated": ("defense.cs_invalidated", "high"),
    "gatekeeper_user_override": ("defense.gatekeeper_override", "medium"),
    "xpc_connect": ("ipc.connect", "info"),
    "signal": ("process.signal", "low"),
    "setuid": ("cred.setuid", "medium"),
    "seteuid": ("cred.seteuid", "medium"),
    "iokit_open": ("device.open", "info"),
}

INTEREST_SUBS = ["exec", "create", "unlink", "rename", "cs_invalidated",
                 "gatekeeper_user_override", "setuid", "kextload", "mount"]

# 敏感路径：文件级监控的重点
SENSITIVE = ("/etc/", "/private/etc/", "/Library/LaunchDaemons/", "/Library/LaunchAgents/",
             "/System/Library/", "/usr/bin/", "/usr/sbin/", "/Users/Shared/", "/tmp/")
HOME = os.path.expanduser("~")
for _p in (".ssh", "Library/LaunchAgents", "Library/Keychains", "Library/Cookies",
           "Library/Application Support/com.apple.TCC"):
    SENSITIVE = SENSITIVE + (os.path.join(HOME, _p) + "/",)


class PrivilegedCollector(Collector):
    name = "privileged"
    interval = 0
    mode = "stream"

    def __init__(self, cfg, store):
        super().__init__(cfg, store)
        self._proc = None
        self._thread = None
        self._stop = threading.Event()
        self._buf: List[Event] = []
        self._lock = threading.Lock()
        self._reason = ""

    def probe(self) -> bool:
        if os.geteuid() != 0:
            self._reason = "需要 root（sudo 启动 atfieldd）才能订阅 EndpointSecurity"
            return False
        if not os.path.exists(ESLOGGER):
            self._reason = "系统无 /usr/bin/eslogger"
            return False
        # eslogger 需要 TCC/ES 授权，未授权会立刻非 0 退出
        try:
            p = subprocess.run([ESLOGGER, "exec"], capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=6)
            if p.returncode != 0 and "not" in (p.stderr or "").lower():
                self._reason = f"eslogger 授权失败: {(p.stderr or '').strip()[:160]}"
                return False
        except Exception as exc:
            self._reason = f"eslogger 探测异常: {type(exc).__name__}"
            return False
        return True

    @property
    def reason(self) -> str:
        return self._reason

    def start(self) -> None:
        if not self.enabled:
            return
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, name="atfield-eslogger", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        cmd = [ESLOGGER] + INTEREST_SUBS
        while not self._stop.is_set():
            try:
                self._proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                              stderr=subprocess.DEVNULL,
                                              text=True, errors="replace", bufsize=1)
                assert self._proc.stdout is not None
                deadline = time.time() + 3600
                while not self._stop.is_set() and time.time() < deadline:
                    r, _, _ = select.select([self._proc.stdout], [], [], 1.0)
                    if not r:
                        if self._proc.poll() is not None:
                            break
                        continue
                    line = self._proc.stdout.readline()
                    if not line:
                        break
                    self._handle(line)
            except Exception:
                pass
            finally:
                try:
                    if self._proc:
                        self._proc.terminate()
                        self._proc.wait(timeout=3)
                except Exception:
                    pass
                self._proc = None
            if not self._stop.is_set():
                time.sleep(5)

    def _handle(self, line: str) -> None:
        try:
            rec = json.loads(line)
        except Exception:
            return
        etype = str(rec.get("event", {}).get("event") or rec.get("event_type") or "").lower()
        kind, sev = ES_INTEREST.get(etype, ("", "info"))
        if not kind:
            return
        proc = rec.get("process") or {}
        exe = (proc.get("executable") or {}).get("path") or ""
        cmdline = " ".join((proc.get("executable") or {}).get("args") or [])
        target = ""
        f = rec.get("event", {})
        if isinstance(f.get("file"), dict):
            target = f["file"].get("path") or ""
        elif isinstance(f.get("target"), dict):
            target = f["target"].get("path") or ""

        # 文件类事件只留敏感路径，否则噪声会吃掉内存
        if kind.startswith("file.") and target and not target.startswith(SENSITIVE):
            return
        if kind.startswith("file.") and target.startswith(SENSITIVE):
            sev = "medium" if sev == "info" else sev

        ev = Event(
            kind=kind, source=self.name, ts=time.time(),
            pid=proc.get("audit_id") or None, ppid=(proc.get("ppid") or None),
            process=os.path.basename(exe) or (proc.get("name") or "?"),
            cmdline=cmdline[:400], path=target or exe, severity=sev,
            subject={"es_event": etype, "exe": exe,
                     "signing": (proc.get("signing_id") or "")},
        )
        with self._lock:
            self._buf.append(ev)

    def collect(self) -> List[Event]:
        with self._lock:
            buf, self._buf = self._buf, []
        self.store.set_state("privileged", {
            "connected": bool(self._proc and self._proc.poll() is None),
            "enabled": self.enabled, "reason": self._reason, "ts": time.time(),
        })
        return buf[-600:]

    def close(self) -> None:
        self._stop.set()
        try:
            if self._proc:
                self._proc.terminate()
        except Exception:
            pass
