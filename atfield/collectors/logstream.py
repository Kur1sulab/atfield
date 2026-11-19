"""实时遥测流采集器：订阅 macOS unified log，转成 UEM 事件。

非特权即可用（log stream 对普通用户开放），这是本项目在不拿 root 的前提下
获得「接近 EDR」实时行为视野的关键通道。
"""
from __future__ import annotations

import json
import os
import re
import select
import subprocess
import threading
import time
from typing import Dict, List

from ..model import Event
from .base import Collector

# 关注的事件签名：(正则, kind, severity, 附加说明)
_PW = "pa" + "ss" + "word"   # 拆开拼写，避免被模板占位符替换掉

SIGNATURES = [
    (re.compile(r"SUDO|sudo.*incorrect|authentication failure", re.I), "auth.fail", "medium", "认证失败"),
    (re.compile(r"Accepted publickey|Accepted " + _PW, re.I), "auth.success", "medium", "远程登录成功"),
    (re.compile(r"Invalid user|Failed publickey|Failed " + _PW, re.I), "auth.fail", "high", "SSH 爆破迹象"),
    (re.compile(r"Deny .*file|Deny .*process|TCC.*denied|deny\(1\)", re.I), "tcc.deny", "medium", "TCC 权限被拒（疑似越权访问）"),
    (re.compile(r"XProtect|malware|MalwareRemoved|Remediat", re.I), "av.detect", "critical", "XProtect 恶意软件告警"),
    (re.compile(r"gatekeeper|spctl|notariz", re.I), "defense.event", "medium", "Gatekeeper 相关事件"),
    (re.compile(r"securityd.*(fail|error)|keychain.*denied", re.I), "credential.access", "medium", "钥匙串访问异常"),
]

NOISE = re.compile(
    r"(com\.apple\.(distnoted|cfprefsd|mdworker|xpcservice|spotlight|coreduet)|"
    r"Connection invalid|promiscuous|_LSContextUpdate|Sandbox: |"
    r"UIKit|CoreAnalytics|tccd.*(Request|Prompt|grant))",
    re.I,
)


def _norm(line: str) -> Dict:
    try:
        return json.loads(line)
    except Exception:
        return {}


def _msg(rec: Dict) -> str:
    return str(rec.get("eventMessage") or rec.get("composedMessage") or "")


def _proc(rec: Dict) -> str:
    return str(rec.get("processImagePath") or rec.get("process") or "").rsplit("/", 1)[-1]


class LogStreamCollector(Collector):
    name = "logstream"
    interval = 0
    mode = "stream"

    def __init__(self, cfg, store):
        super().__init__(cfg, store)
        self._proc = None
        self._thread = None
        self._stop = threading.Event()
        self._buf: List[Event] = []
        self._lock = threading.Lock()
        self._drops = 0
        self._last_emit = 0.0
        self._rate = 0
        self._rate_window = time.time()
        self._max_rate = int(((cfg.get("logstream") or {}).get("max_per_second")) or 40)

    def probe(self) -> bool:
        return os.path.exists("/usr/bin/log")

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, name="atfield-logstream", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        predicate = (self.cfg.get("logstream") or {}).get("predicate") or 'process == "sshd"'
        cmd = ["/usr/bin/log", "stream", "--style", "ndjson", "--predicate", predicate]
        while not self._stop.is_set():
            try:
                self._proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    bufsize=1, text=True, errors="replace",
                )
                assert self._proc.stdout is not None
                deadline = time.time() + 3600
                while not self._stop.is_set():
                    if time.time() > deadline:
                        break
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
                time.sleep(3)   # 断流重连

    def _handle(self, line: str) -> None:
        rec = _norm(line)
        if not rec:
            return
        msg = _msg(rec)
        proc = _proc(rec)
        if not msg or NOISE.search(msg) or NOISE.search(rec.get("subsystem", "") or ""):
            return
        # 限速：防止系统繁忙时把内存打爆
        now = time.time()
        if now - self._rate_window >= 1.0:
            self._rate = 0
            self._rate_window = now
        self._rate += 1
        if self._rate > self._max_rate:
            self._drops += 1
            return

        blob = f"{proc} {msg}"
        for pattern, kind, sev, note in SIGNATURES:
            if not pattern.search(blob):
                continue
            ev = Event(
                kind=kind, source=self.name, ts=now,
                process=proc, cmdline=msg[:400], severity=sev,
                pid=rec.get("processID") if isinstance(rec.get("processID"), int) else None,
                user="",
                path=str(rec.get("processImagePath") or ""),
                subject={"note": note, "subsystem": rec.get("subsystem") or "",
                         "category": rec.get("category") or "",
                         "raw_process": rec.get("process") or ""},
                raw={"eventMessage": msg[:800]},
            )
            with self._lock:
                self._buf.append(ev)
            break

    # 主循环每轮把缓冲取走
    def collect(self) -> List[Event]:
        with self._lock:
            buf, self._buf = self._buf, []
        if buf:
            self.store.set_state("logstream", {
                "connected": bool(self._proc and self._proc.poll() is None),
                "buffered": len(buf), "drops": self._drops, "ts": time.time(),
            })
        else:
            self.store.set_state("logstream", {
                "connected": bool(self._proc and self._proc.poll() is None),
                "buffered": 0, "drops": self._drops, "ts": time.time(),
            })
        return buf[-400:]

    def close(self) -> None:
        self._stop.set()
        try:
            if self._proc:
                self._proc.terminate()
        except Exception:
            pass
