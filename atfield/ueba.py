"""UEBA：主机行为基线画像，偏离即告警。

与签名规则互补——签名抓「已知坏」，基线抓「从没见过」。
画像持久化到 ~/.atfield/ueba.json，重启不丢；学习期内的观测只入画像不告警。
"""
from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List, Optional, Set

from .model import Event

LEARN_SECONDS = 2400          # 学习期：40 分钟内只学习不判定
LEARN_MIN_OBS = 400           # 或者累计 400 次观测后提前出学习期
# 系统路径上的新进程属于正常更新噪声，不作为「基线偏离」告警
SYSTEM_PREFIX = ("/usr/", "/System/", "/bin/", "/sbin/", "/Library/Apple/",
                 "/Applications/", "/private/var/db/", "/opt/homebrew/")


class UEBA:
    def __init__(self, cfg: Dict[str, Any], store):
        self.cfg = cfg
        self.store = store
        self.path = os.path.join(cfg.get("data_dir") or os.path.expanduser("~/.atfield"),
                                 "ueba.json")
        self.t0 = time.time()
        self.obs = 0
        self.profile: Dict[str, Any] = {
            "process_names": [], "exe_paths": [], "remote_ips": [],
            "remote_ports": [], "persistence_labels": [], "users": [],
            "hourly": {}, "learned_at": 0, "samples": 0,
        }
        self._proc: Set[str] = set()
        self._exe: Set[str] = set()
        self._rip: Set[str] = set()
        self._rport: Set[str] = set()
        self._plabel: Set[str] = set()
        self._users: Set[str] = set()
        self._hourly: Dict[str, int] = {}
        self._load()

    # ---------- 画像持久化 ----------
    def _load(self) -> None:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                d = json.load(fh) or {}
            self.profile.update({k: d.get(k, self.profile[k]) for k in self.profile})
            self._proc = set(self.profile["process_names"])
            self._exe = set(self.profile["exe_paths"])
            self._rip = set(self.profile["remote_ips"])
            self._rport = set(self.profile["remote_ports"])
            self._plabel = set(self.profile["persistence_labels"])
            self._users = set(self.profile["users"])
            self._hourly = dict(self.profile.get("hourly") or {})
        except Exception:
            pass

    def _save(self) -> None:
        self.profile.update({
            "process_names": sorted(self._proc)[-4000:],
            "exe_paths": sorted(self._exe)[-4000:],
            "remote_ips": sorted(self._rip)[-4000:],
            "remote_ports": sorted(self._rport)[-500:],
            "persistence_labels": sorted(self._plabel)[-2000:],
            "users": sorted(self._users)[-200:],
            "hourly": self._hourly,
            "learned_at": self.profile.get("learned_at") or time.time(),
            "samples": self.obs,
        })
        try:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.profile, fh, ensure_ascii=False)
            os.replace(tmp, self.path)
        except Exception:
            pass

    # ---------- 状态 ----------
    @property
    def learning(self) -> bool:
        return self.obs < LEARN_MIN_OBS and (time.time() - self.t0) < LEARN_SECONDS

    def status(self) -> Dict[str, Any]:
        return {
            "learning": self.learning,
            "learn_elapsed": int(time.time() - self.t0),
            "samples": self.obs,
            "known_processes": len(self._proc),
            "known_exe": len(self._exe),
            "known_remote": len(self._rip),
            "known_labels": len(self._plabel),
            "profile_age_h": round((time.time() - (self.profile.get("learned_at") or time.time())) / 3600, 1),
            "path": self.path,
        }

    # ---------- 观测 ----------
    def observe(self, events: List[Event]) -> List[Event]:
        """喂事件进来：学习期只建画像，出学习期后产出偏离事件。"""
        out: List[Event] = []
        hour_key = time.strftime("%H")
        for ev in events:
            self.obs += 1
            self._hourly[hour_key] = self._hourly.get(hour_key, 0) + 1

            if ev.user:
                self._users.add(ev.user)

            if ev.kind == "process.start":
                name = (ev.process or "").strip()
                exe = (ev.path or "").strip()
                first_name = bool(name) and name not in self._proc
                first_exe = bool(exe) and exe not in self._exe
                if name:
                    self._proc.add(name)
                if exe:
                    self._exe.add(exe)
                if not self.learning and (first_name or first_exe):
                    # 系统/应用目录里的新进程多为更新或用户正常安装，不单独告警
                    if exe and exe.startswith(SYSTEM_PREFIX):
                        continue
                    sev = "low"
                    why = []
                    if first_name:
                        why.append(f"首次出现的进程名「{name}」")
                    if first_exe:
                        why.append(f"首次出现的可执行路径「{exe}」")
                    # 夜间（0-6 点）首次出现 + 非系统路径 → 提高一级
                    if int(hour_key) < 6 and exe and not exe.startswith(("/usr/", "/System/")):
                        sev = "medium"
                        why.append("发生在 00:00-06:00 低活跃时段")
                    out.append(Event(
                        kind="ueba.new_process", source="ueba", ts=ev.ts, pid=ev.pid,
                        process=name, cmdline=ev.cmdline, path=exe, user=ev.user,
                        severity=sev, subject={"reasons": why}, raw={"exe": exe},
                    ))

            elif ev.kind == "net.connect":
                rip = str((ev.subject or {}).get("rip") or "")
                rport = str((ev.subject or {}).get("rport") or "")
                if rip and not self._is_local(rip):
                    first_rip = rip not in self._rip
                    if rip:
                        self._rip.add(rip)
                    if rport:
                        self._rport.add(rport)
                    if not self.learning and first_rip:
                        out.append(Event(
                            kind="ueba.new_destination", source="ueba", ts=ev.ts,
                            pid=ev.pid, process=ev.process, user=ev.user,
                            path=rip, severity="low",
                            subject={"ip": rip, "port": rport,
                                     "reasons": [f"首次外联目的地 {rip}:{rport}"]},
                        ))

            elif ev.kind in ("persistence.add", "persistence.modify"):
                label = str((ev.subject or {}).get("label") or ev.path or "")
                first = bool(label) and label not in self._plabel
                if label:
                    self._plabel.add(label)
                if not self.learning and first and ev.severity in ("high", "critical"):
                    out.append(Event(
                        kind="ueba.new_persistence", source="ueba", ts=ev.ts,
                        process=label, path=ev.path, severity="high",
                        subject={"label": label,
                                 "reasons": [f"首次出现的常驻项「{label}」"]},
                    ))

        if self.obs % 50 == 0:
            self._save()
        self.store.set_state("ueba", self.status())
        return out

    @staticmethod
    def _is_local(ip: str) -> bool:
        try:
            import ipaddress
            a = ipaddress.ip_address(ip)
            return a.is_private or a.is_loopback or a.is_link_local
        except Exception:
            return False

    # ---------- 行为画像视图 ----------
    def view(self) -> Dict[str, Any]:
        hourly = [{"hour": f"{h:02d}", "count": self._hourly.get(f"{h:02d}", 0)}
                  for h in range(24)]
        return {
            "status": self.status(),
            "hourly": hourly,
            "top_processes": sorted(self._proc)[:200],
            "users": sorted(self._users),
            "recent_destinations": sorted(self._rip)[-80:],
        }

    def reset(self) -> Dict[str, Any]:
        self._proc.clear(); self._exe.clear(); self._rip.clear()
        self._rport.clear(); self._plabel.clear(); self._users.clear()
        self._hourly.clear()
        self.obs = 0
        self.t0 = time.time()
        self.profile["learned_at"] = 0
        self._save()
        self.store.set_state("ueba", self.status())
        self.store.log_action("analyst", "ueba:reset", "profile", "已重置行为基线")
        return {"ok": True, "detail": "行为基线已重置，重新进入学习期"}
