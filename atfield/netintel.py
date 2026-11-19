"""NDR（主机侧网络检测）：目的地画像 + 心跳/信标检测 + 隧道特征。

非特权也可得的事实：五元组、进程归属、连接时间。基于这些做三件事：
1) 目的地画像：直连 IP（无域名）、高风险端口、动态 DNS 域、非常用端口出网；
2) 信标（beaconing）：同一 (进程, 目的地) 反复连接且间隔极规律 → C2 心跳特征；
3) 端口/协议异常：非浏览器进程连 80/443，或非常见端口组合。
"""
from __future__ import annotations

import math
import queue
import threading
import time
from typing import Any, Dict, List, Tuple

from .model import Event

BEACON_MIN_SAMPLES = 5
BEACON_CV_THRESHOLD = 0.18     # 变异系数低于此值 = 间隔过于规律
BROWSER_HINTS = ("safari", "chrome", "firefox", "edge", "arc", "brave", "opera",
                 "com.apple.webkit", "webcontent")
STANDARD_WEB_PORTS = {80, 443, 8080, 8443}


def _hostname_of(ip: str) -> str:
    try:
        import socket
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


class NetIntel:
    def __init__(self, cfg: Dict[str, Any], store, intel=None):
        self.cfg = cfg
        self.store = store
        self.intel = intel
        self.hist: Dict[Tuple[str, str], List[float]] = {}
        self.dest: Dict[str, dict] = {}          # ip -> 画像
        self.beacons: Dict[str, dict] = {}
        self.flags: List[dict] = []
        self._resolved: Dict[str, str] = {}
        self._last_run = 0.0
        self._flag_seen: Dict[str, float] = {}
        self.flag_cooldown = 900.0     # 同一 (类型, 进程, 目的地) 15 分钟内只报一次
        self._rq: "queue.Queue[str]" = queue.Queue()
        self._resolver_started = False

    def _start_resolver(self) -> None:
        """反向解析放到后台线程：gethostbyaddr 可能卡 5 秒，绝不能阻塞采集链路。"""
        if self._resolver_started:
            return
        self._resolver_started = True

        def loop() -> None:
            while True:
                ip = self._rq.get()
                host = ""
                try:
                    host = _hostname_of(ip)
                except Exception:
                    host = ""
                self._resolved[ip] = host
                d = self.dest.get(ip)
                if d is not None and not d.get("hostname"):
                    d["hostname"] = host

        threading.Thread(target=loop, daemon=True, name="atfield-rdns").start()

    # ---------- 观测 ----------
    def observe(self, events: List[Event]) -> List[Event]:
        out: List[Event] = []
        now = time.time()
        for ev in events:
            if ev.kind != "net.connect":
                continue
            sub = ev.subject or {}
            rip = str(sub.get("rip") or "")
            rport = int(sub.get("rport") or 0)
            if not rip:
                continue
            proc = (ev.process or "").lower()
            key = (proc, rip)
            self.hist.setdefault(key, []).append(ev.ts or now)
            self.hist[key] = self.hist[key][-120:]

            # ---- 目的地画像 ----
            prof = self.dest.setdefault(rip, {
                "ip": rip, "first": ev.ts or now, "count": 0,
                "ports": {}, "processes": {}, "hostname": None, "flags": [],
            })
            prof["count"] += 1
            prof["ports"][str(rport)] = prof["ports"].get(str(rport), 0) + 1
            prof["processes"][ev.process or "?"] = prof["processes"].get(ev.process or "?", 0) + 1

            if prof["hostname"] is None:
                if rip in self._resolved:
                    prof["hostname"] = self._resolved[rip]
                else:
                    self._start_resolver()
                    try:
                        self._rq.put_nowait(rip)
                    except Exception:
                        pass
                    prof["hostname"] = ""       # 解析中：先不判定「无域名」

            is_public = bool(sub.get("public"))
            browser = any(h in proc for h in BROWSER_HINTS)
            resolved_no_name = (rip in self._resolved and self._resolved[rip] == "")

            # 直连 IP 且反查确认无域名，且不是浏览器
            if is_public and not browser and resolved_no_name:
                self._flag(out, ev, "direct_ip",
                           f"非浏览器进程 {ev.process} 直连未解析域名的公网 IP {rip}",
                           "medium", {"ip": rip, "port": rport})

            # 高风险端口
            if is_public and sub.get("risky_port"):
                self._flag(out, ev, "risky_port",
                           f"{ev.process} 连接高风险端口 {rip}:{rport}（常见 C2/远控端口）",
                           "high", {"ip": rip, "port": rport})

            # 动态 DNS / 隧道域
            host = prof["hostname"] or ""
            if host and self.intel:
                hit = self.intel.match_domain(host)
                if hit:
                    self._flag(out, ev, "risky_domain",
                               f"{ev.process} 连接 {host}（{hit.get('note')}）",
                               "medium" if hit.get("rule") == "exact" else "low",
                               {"ip": rip, "domain": host, "rule": hit.get("rule")})
                hh = self.intel.match_ip(rip)
                if hh:
                    self._flag(out, ev, "ioc_ip",
                               f"{ev.process} 连接情报库命中 IP {rip}（来源 {hh.get('source')}）",
                               "high", {"ip": rip, "source": hh.get("source")})

            # ---- 信标检测（只针对公网对端：回环/内网轮询是本地代理与 IDE 的正常行为）----
            stamps = self.hist[key]
            if is_public and len(stamps) >= BEACON_MIN_SAMPLES:
                gaps = [b - a for a, b in zip(stamps, stamps[1:]) if b > a]
                if len(gaps) >= BEACON_MIN_SAMPLES - 1:
                    mean = sum(gaps) / len(gaps)
                    if mean > 3:
                        var = sum((g - mean) ** 2 for g in gaps) / len(gaps)
                        cv = math.sqrt(var) / mean if mean else 9
                        if cv < BEACON_CV_THRESHOLD:
                            bid = f"{proc}->{rip}"
                            prev = self.beacons.get(bid) or {}
                            self.beacons[bid] = {
                                "id": bid, "process": ev.process, "ip": rip,
                                "port": rport, "interval_s": round(mean, 1),
                                "cv": round(cv, 3), "samples": len(stamps),
                                "first": stamps[0], "last": stamps[-1],
                                "hits": int(prev.get("hits") or 0) + 1,
                                "hostname": prof["hostname"],
                            }
                            if self.beacons[bid]["hits"] % 3 == 1:   # 节流告警
                                self._flag(out, ev, "beaconing",
                                           f"{ev.process} 到 {rip}:{rport} 呈规律心跳"
                                           f"（间隔 {round(mean,1)}s，波动 {round(cv*100,1)}%）",
                                           "high", {"ip": rip, "port": rport,
                                                    "interval": round(mean, 1)})
        self._last_run = now
        self.store.set_state("netintel", self.status())
        return out

    def _flag(self, out: List[Event], ev: Event, kind: str, text: str,
              severity: str, subject: dict) -> None:
        key = f"{kind}|{ev.process}|{subject.get('ip') or subject.get('domain') or ''}"
        now = time.time()
        if now - self._flag_seen.get(key, 0) < self.flag_cooldown:
            return
        self._flag_seen[key] = now
        out.append(Event(kind=f"ndr.{kind}", source="ndr",
                         ts=ev.ts or time.time(), pid=ev.pid, process=ev.process,
                         path=str(subject.get("ip") or ""), user=ev.user,
                         severity=severity, subject=dict(subject, reason=text)))
        self.flags.append({"ts": time.time(), "kind": kind, "text": text,
                           "severity": severity, "process": ev.process})
        del self.flags[:-500]

    # ---------- 视图 ----------
    def status(self) -> Dict[str, Any]:
        top = sorted(self.dest.values(), key=lambda d: -d["count"])[:40]
        return {
            "destinations": len(self.dest),
            "public_destinations": sum(1 for d in self.dest.values()
                                       if d["ip"] and not _is_private(d["ip"])),
            "unresolved": sum(1 for d in self.dest.values() if not d["hostname"]),
            "beacons": sorted(self.beacons.values(), key=lambda b: -b["hits"])[:20],
            "beacon_count": len(self.beacons),
            "flags": self.flags[-60:][::-1],
            "top_destinations": top,
            "ts": self._last_run,
        }


def _is_private(ip: str) -> bool:
    try:
        import ipaddress
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_multicast
    except Exception:
        return True
