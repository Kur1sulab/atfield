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
# ---- 频率异常（NoDoze 式，替代会饱和的 binary novelty）----
HOUR_WEIGHT = 0.5             # 「该时段历史频率」稀有度权重
COMBO_WEIGHT = 0.5            # 本机历史组合频率稀有度权重
RARE_THRESHOLD = 0.75         # 综合稀有度分达到即报（即使该进程以前见过）
RARE_COOLDOWN = 900.0         # 同一 (进程,小时) 组合的重复提示间隔
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
            "hourly": {}, "proc_hours": {}, "learned_at": 0, "samples": 0,
        }
        self._proc: Set[str] = set()
        self._exe: Set[str] = set()
        self._rip: Set[str] = set()
        self._rport: Set[str] = set()
        self._plabel: Set[str] = set()
        self._users: Set[str] = set()
        self._hourly: Dict[str, int] = {}
        self._proc_hours: Dict[str, int] = {}     # "进程|HH" -> 次数（组合频率）
        self._rare_last: Dict[str, float] = {}    # 频率异常提示冷却
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
            self._proc_hours = dict(self.profile.get("proc_hours") or {})
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
            "proc_hours": dict(sorted(self._proc_hours.items(),
                                      key=lambda kv: -kv[1])[:4000]),
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

    # ---------- 频率稀有度（hourly 直方图 + 本机组合频率）----------
    @staticmethod
    def _hour_of(ts: Optional[float]) -> str:
        return time.strftime("%H", time.localtime(ts or time.time()))

    @staticmethod
    def _rarity(count: int, total: int) -> float:
        """频率稀有度 0..1：count 相对 total 越少见越接近 1。

        用 log 压缩而不是二元「见过/没见过」：一个进程即使以前出现过，
        只要它在该时段的组合频率依旧极低，分仍然高——这就是抗饱和。
        """
        if total <= 0:
            return 1.0
        c = max(0, int(count))
        try:
            import math
            r = 1.0 - (math.log1p(c) / math.log1p(total))
        except Exception:
            r = 1.0 if c == 0 else 0.0
        return max(0.0, min(1.0, r))

    def _hour_rarity(self, hour_key: str) -> float:
        """「该时段历史频率」稀有度：把 hourly 直方图真正接进判定。"""
        total = sum(self._hourly.values())
        if total <= 0:
            return 1.0
        return self._rarity(int(self._hourly.get(hour_key, 0)), total)

    def _combo_rarity(self, proc: str, hour_key: str) -> float:
        """本机历史组合频率稀有度：(进程, 时段) 这个组合有多罕见。"""
        total = sum(self._proc_hours.values())
        if total <= 0:
            return 1.0
        return self._rarity(int(self._proc_hours.get(f"{proc}|{hour_key}", 0)), total)

    def frequency_score(self, proc: str, hour_key: str,
                        prior_hour: Optional[int] = None,
                        prior_total: Optional[int] = None) -> Dict[str, float]:
        """综合频率异常分：hourly 稀有度 + 组合频率稀有度。

        prior_* 传入「本条事件计入之前」的直方图值，避免本次自己把稀有度拉低。
        """
        if prior_total is not None:
            h = self._rarity(int(prior_hour or 0), int(prior_total))
        else:
            h = self._hour_rarity(hour_key)
        c = self._combo_rarity(proc, hour_key)
        return {"hour_rarity": round(h, 3), "combo_rarity": round(c, 3),
                "score": round(HOUR_WEIGHT * h + COMBO_WEIGHT * c, 3)}

    # ---------- 观测 ----------
    def observe(self, events: List[Event]) -> List[Event]:
        """喂事件进来：学习期只建画像，出学习期后产出偏离事件。"""
        out: List[Event] = []
        for ev in events:
            hour_key = self._hour_of(ev.ts)
            # 先取「本次之前」的直方图状态，稀有度不能自己拉低自己
            prior_hour = int(self._hourly.get(hour_key, 0))
            prior_total = sum(self._hourly.values())
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
                # 组合频率必须在「本次计入」之前算，否则本次会把分数自己拉低
                freq = self.frequency_score(name, hour_key, prior_hour, prior_total)
                combo_key = f"{name}|{hour_key}"
                self._proc_hours[combo_key] = self._proc_hours.get(combo_key, 0) + 1

                # ---- 频率异常（与首次出现解耦，独立成告警）----
                if (not self.learning and freq["score"] >= RARE_THRESHOLD
                        and not (exe and exe.startswith(SYSTEM_PREFIX))):
                    last = self._rare_last.get(combo_key, 0.0)
                    if time.time() - last >= RARE_COOLDOWN:
                        self._rare_last[combo_key] = time.time()
                        sev = "high" if freq["score"] >= 0.9 else "medium"
                        out.append(Event(
                            kind="ueba.rare_activity", source="ueba", ts=ev.ts,
                            pid=ev.pid, process=name, cmdline=ev.cmdline,
                            path=exe, user=ev.user, severity=sev,
                            subject={
                                "reasons": [
                                    f"「{name}」在该时段的历史频率极低"
                                    f"（时段稀有度 {freq['hour_rarity']}，"
                                    f"组合稀有度 {freq['combo_rarity']}）",
                                    f"频率异常分 {freq['score']} ≥ {RARE_THRESHOLD}",
                                ],
                                "hour": hour_key,
                                **freq,
                            },
                            raw={"exe": exe, "freq": freq},
                        ))

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
                    # 该时段历史频率极低（数据驱动，替代写死的 0-6 点）→ 提高一级
                    if freq["hour_rarity"] >= 0.6 and exe and not exe.startswith(("/usr/", "/System/")):
                        sev = "medium"
                        why.append(f"该时段历史频率极低（时段稀有度 {freq['hour_rarity']}）")
                    elif int(hour_key) < 6 and exe and not exe.startswith(("/usr/", "/System/")):
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
        self._hourly.clear(); self._proc_hours.clear(); self._rare_last.clear()
        self.obs = 0
        self.t0 = time.time()
        self.profile["learned_at"] = 0
        self._save()
        self.store.set_state("ueba", self.status())
        self.store.log_action("analyst", "ueba:reset", "profile", "已重置行为基线")
        return {"ok": True, "detail": "行为基线已重置，重新进入学习期"}
