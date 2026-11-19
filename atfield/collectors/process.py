"""进程采集器：快照差分 = 进程创建/退出事件，同时维护进程树与「隐藏进程」交叉校验。"""
from __future__ import annotations

import os
import subprocess
import time
from typing import Dict, List, Optional

import psutil

from ..model import Event
from .base import Collector

SYSTEM_PREFIXES = ("/usr/", "/System/", "/bin/", "/sbin/", "/Library/Apple/")


class ProcessCollector(Collector):
    name = "process"
    interval = 3.0

    def __init__(self, cfg, store):
        super().__init__(cfg, store)
        self._prev: Dict[int, dict] = {}
        self._susp_dirs = tuple(cfg.get("suspicious_dir_prefixes") or ())
        self._sys_names = set(cfg.get("system_process_names") or ())
        self._hidden_checked = 0.0

    # ---------- 采集 ----------
    def _snap(self) -> Dict[int, dict]:
        out: Dict[int, dict] = {}
        attrs = ["pid", "ppid", "name", "username", "exe", "cmdline", "create_time"]
        for p in psutil.process_iter(attrs, ad_value=None):
            info = p.info
            pid = info.get("pid")
            if not pid:
                continue
            cmd = info.get("cmdline") or []
            if isinstance(cmd, (list, tuple)):
                cmdline = " ".join(str(c) for c in cmd)
            else:
                cmdline = str(cmd)
            out[pid] = {
                "pid": pid,
                "ppid": info.get("ppid") or 0,
                "name": info.get("name") or "?",
                "user": info.get("username") or "?",
                "exe": info.get("exe") or "",
                "cmdline": cmdline[:600],
                "ctime": info.get("create_time") or 0.0,
            }
        return out

    def collect(self) -> List[Event]:
        cur = self._snap()
        events: List[Event] = []
        now = time.time()

        # 首轮只建基线：既不误报 1000+ 条「新进程」，也让后续差分有意义
        first_run = not self._prev

        for pid, info in cur.items():
            if pid in self._prev:
                continue
            if first_run:
                continue
            exe = info["exe"]
            suspicious = bool(exe) and exe.startswith(self._susp_dirs)
            # 进程名仿冒：名称像系统进程，但可执行文件不在系统目录
            masquerade = (
                info["name"] in self._sys_names
                and exe
                and not exe.startswith(SYSTEM_PREFIXES)
            )
            sev = "info"
            if suspicious or masquerade:
                sev = "medium"
            events.append(Event(
                kind="process.start", source=self.name, ts=now,
                pid=pid, ppid=info["ppid"], user=info["user"],
                process=info["name"], cmdline=info["cmdline"], path=exe,
                severity=sev,
                subject={
                    "suspicious_path": suspicious,
                    "masquerade": masquerade,
                    "created": info["ctime"],
                },
                raw={"cmdline": info["cmdline"], "exe": exe},
            ))

        # 退出事件（保持较低噪声：只记录曾经出现过、现在消失的进程）
        for pid, info in self._prev.items():
            if pid in cur:
                continue
            events.append(Event(
                kind="process.exit", source=self.name, ts=now,
                pid=pid, ppid=info.get("ppid"), user=info.get("user", ""),
                process=info.get("name", "?"), cmdline=info.get("cmdline", ""),
                path=info.get("exe", ""),
                severity="info", subject={"lifetime": round(now - (info.get("ctime") or now), 1)},
            ))

        self._prev = cur

        # 隐藏进程交叉校验（psutil vs ps）——抗 rootkit 的基础手段，节流到 15s
        hidden: List[dict] = []
        if not first_run and now - self._hidden_checked > 15:
            self._hidden_checked = now
            hidden = self._cross_check_hidden()
            for h in hidden:
                events.append(Event(
                    kind="process.hidden", source=self.name, ts=now,
                    pid=h.get("pid"), process=h.get("name", "?"),
                    cmdline=h.get("cmdline", ""), severity="high",
                    subject={"reason": "仅 ps 可见 / 仅 psutil 可见"},
                ))

        self._publish_tree(cur, hidden)
        return events

    def _cross_check_hidden(self) -> List[dict]:
        try:
            out = subprocess.run(["/bin/ps", "-axo", "pid=,ppid=,user=,comm="],
                                 capture_output=True, text=True,
                                 encoding="utf-8", errors="replace", timeout=8).stdout
        except Exception:
            return []
        ps_map: Dict[int, dict] = {}
        for line in out.splitlines():
            parts = line.split(None, 3)
            if len(parts) < 4 or not parts[0].isdigit():
                continue
            ps_map[int(parts[0])] = {"ppid": parts[1], "user": parts[2], "name": parts[3]}

        # 只看「本用户」的进程：非 root 的 psutil 读不到别人进程属于权限限制，不是隐蔽
        try:
            me = psutil.Process().username()
        except Exception:
            me = ""
        hidden: List[dict] = []
        for pid, info in ps_map.items():
            if pid in self._prev or pid <= 200:
                continue
            if me and info.get("user") not in (me, "root"):
                continue
            # 二次确认：psutil 读得到 → 不是隐藏，只是两次快照之间的时间差
            try:
                p = psutil.Process(pid)
                p.name()
                continue
            except Exception:
                pass
            # ps 有、psutil 读不到、且信号探测证明进程确实存活 → 才算视图不一致
            try:
                os.kill(pid, 0)
            except Exception:
                continue
            hidden.append({"pid": pid, "name": info["name"], "cmdline": "",
                           "why": "ps 可见但 psutil 无法读取"})
        return hidden[:20]

    def _publish_tree(self, cur: Dict[int, dict], hidden: List[dict]) -> None:
        rows = []
        total_cpu = 0.0
        for pid, info in cur.items():
            cpu = 0.0
            mem = 0.0
            try:
                p = psutil.Process(pid)
                with p.oneshot():
                    cpu = p.cpu_percent(interval=None)
                    mem = p.memory_info().rss
            except Exception:
                pass
            total_cpu += cpu
            rows.append({
                "pid": pid, "ppid": info["ppid"], "name": info["name"],
                "user": info["user"], "exe": info["exe"],
                "cmdline": info["cmdline"], "cpu": round(cpu, 1),
                "rss": mem, "ctime": info["ctime"],
                "age": int(time.time() - (info["ctime"] or time.time())),
            })
        rows.sort(key=lambda r: (-r["cpu"], -r["rss"]))
        self.store.set_state("processes", {
            "count": len(rows),
            "rows": rows[:400],
            "cpu_total": round(total_cpu, 1),
            "hidden": hidden,
            "ts": time.time(),
            "users": len({r["user"] for r in rows}),
        })


class FilelessWatcher(Collector):
    """轻量补充：监控当前用户 shell 历史文件被写入（常用于落地痕迹/文件less 攻击）。"""

    name = "shellhist"
    interval = 20.0
    _targets = [".zsh_history", ".bash_history"]

    def __init__(self, cfg, store):
        super().__init__(cfg, store)
        self._sizes: Dict[str, int] = {}

    def collect(self) -> List[Event]:
        events: List[Event] = []
        home = os.path.expanduser("~")
        for name in self._targets:
            p = os.path.join(home, name)
            try:
                st = os.stat(p)
            except Exception:
                continue
            prev = self._sizes.get(p)
            self._sizes[p] = st.st_size
            if prev is not None and st.st_size > prev:
                events.append(Event(
                    kind="file.write", source=self.name, path=p, severity="info",
                    subject={"delta_bytes": st.st_size - prev, "size": st.st_size},
                ))
        return events
