"""网络采集器：连接/监听差分，带进程归属与内外网判定。"""
from __future__ import annotations

import ipaddress
import socket
import time
from typing import Dict, List, Tuple

import psutil

from ..model import Event
from .base import Collector

# 常见 C2 / 后门端口（只作为加分项，不单独定级）
C2_PORTS = {4444, 4445, 1337, 31337, 6666, 6667, 6697, 9001, 12345, 54321}
# 高风险暴露端口：一旦监听即代表攻击面
RISKY_LISTEN = {
    22: ("SSH", "low"), 23: ("Telnet", "critical"), 445: ("SMB", "high"),
    548: ("AFP", "high"), 5900: ("VNC", "high"), 3389: ("RDP", "high"),
    2375: ("Docker API", "critical"), 2376: ("Docker TLS", "medium"),
    6379: ("Redis", "critical"), 3306: ("MySQL", "high"), 27017: ("MongoDB", "critical"),
    9200: ("Elasticsearch", "high"), 11211: ("Memcached", "high"),
    8888: ("Jupyter", "high"), 8080: ("HTTP-Alt", "info"), 8000: ("HTTP-Dev", "info"),
}


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast
    except Exception:
        return True


class NetworkCollector(Collector):
    name = "network"
    interval = 5.0

    def __init__(self, cfg, store):
        super().__init__(cfg, store)
        self._conns: Dict[Tuple, dict] = {}
        self._listens: Dict[Tuple, dict] = {}
        self._perm_error = ""

    def _gather(self):
        """返回 (connections, listeners)。

        macOS 非 root 下 psutil.net_connections 会抛 AccessDenied（拿不到别人的 socket 归属），
        这时退回 netstat 全量连接 + lsof 本用户进程归属：拿到完整连接面，只是部分行没有 pid。
        """
        conns, listens = {}, {}
        try:
            raw = psutil.net_connections(kind="inet")
            if raw:
                return self._from_psutil(raw)
        except Exception as exc:
            self._perm_error = f"{type(exc).__name__}（已回退 lsof）"
        return self._from_lsof()

    def _from_psutil(self, raw) -> Tuple[Dict, Dict]:
        conns, listens = {}, {}
        self._perm_error = ""
        for c in raw:
            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
            raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
            pname, puser = "?", "?"
            if c.pid:
                try:
                    p = psutil.Process(c.pid)
                    pname, puser = p.name(), p.username()
                except Exception:
                    pass
            row = {
                "pid": c.pid, "process": pname, "user": puser,
                "laddr": laddr, "raddr": raddr, "lport": c.laddr.port if c.laddr else 0,
                "rport": c.raddr.port if c.raddr else 0,
                "rip": c.raddr.ip if c.raddr else "",
                "status": c.status, "family": "IPv4" if c.family == socket.AF_INET else "IPv6",
                "type": "TCP" if c.type == socket.SOCK_STREAM else "UDP",
            }
            if c.status == psutil.CONN_LISTEN:
                listens[(row["laddr"], c.pid)] = row
            elif row["raddr"]:
                conns[(row["laddr"], row["raddr"], c.pid)] = row
        return conns, listens

    # ---------- 非特权兜底：lsof ----------
    def _from_lsof(self) -> Tuple[Dict, Dict]:
        """macOS 26+ 的 netstat 已不再列出常规 TCP/UDP 表（只剩 MPTCP 与 UNIX 套接字），
        因此兜底改用 lsof：无 root 时只列本用户进程，但足以覆盖用户态恶意程序的连接面。"""
        conns, listens = {}, {}
        try:
            import subprocess
            p = subprocess.run(["/usr/sbin/lsof", "-nP", "-i", "-w"],
                               capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=20)
            lines = (p.stdout or "").splitlines()
        except Exception as exc:
            self._perm_error += f" | lsof: {type(exc).__name__}: {exc}"
            return conns, listens

        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 9:
                continue
            proto_idx = -1
            for idx in range(4, len(parts)):
                if parts[idx] in ("TCP", "UDP"):
                    proto_idx = idx
                    break
            if proto_idx < 0 or proto_idx + 1 >= len(parts):
                continue
            cmd, pid_s, user = parts[0], parts[1], parts[2]
            proto = parts[proto_idx]
            name = parts[proto_idx + 1]
            state_raw = parts[proto_idx + 2] if len(parts) > proto_idx + 2 else ""
            state = state_raw.strip("()") or ("STATELESS" if proto == "UDP" else "")
            pid = int(pid_s) if pid_s.isdigit() else 0
            if name in ("*:*", "*"):
                continue
            left, _, right = name.partition("->")
            lip, _, lport_s = left.rpartition(":")
            if not lport_s.isdigit():
                continue
            lport = int(lport_s)
            row = {
                "pid": pid, "process": cmd, "user": user,
                "laddr": f"{lip or '*'}:{lport}", "lport": lport,
                "raddr": "", "rip": "", "rport": 0,
                "status": state, "proto": proto, "type": proto,
                "family": "IPv6" if ":" in lip else "IPv4",
            }
            remote_empty = (not right) or right in ("*:*", "*") or right.endswith(":*")
            if ("LISTEN" in state) or (proto == "UDP" and remote_empty):
                listens[(row["laddr"], pid)] = row
                continue
            if remote_empty:
                continue
            rip, _, rport_s = right.rpartition(":")
            if not rport_s.isdigit():
                continue
            row.update({"raddr": f"{rip}:{rport_s}", "rip": rip, "rport": int(rport_s)})
            conns[(row["laddr"], row["raddr"], pid)] = row
        return conns, listens

    def collect(self) -> List[Event]:
        conns, listens = self._gather()
        now = time.time()
        events: List[Event] = []

        for key, row in conns.items():
            if key in self._conns:
                continue
            public = row["rip"] and not _is_private(row["rip"])
            risky = row["rport"] in C2_PORTS or row["rport"] in (4444, 1337, 31337, 6667, 9001)
            sev = "info"
            if public and risky:
                sev = "high"
            elif public:
                sev = "low"
            events.append(Event(
                kind="net.connect", source=self.name, ts=now,
                pid=row["pid"], process=row["process"], user=row["user"],
                path=f"{row['rip']}:{row['rport']}",
                severity=sev,
                subject={
                    "raddr": row["raddr"], "rport": row["rport"], "rip": row["rip"],
                    "laddr": row["laddr"], "proto": row["type"],
                    "public": bool(public), "risky_port": bool(risky),
                },
            ))

        for key, row in listens.items():
            if key in self._listens:
                continue
            name, sev = RISKY_LISTEN.get(row["lport"], ("未知服务", "info"))
            # 只监听回环的暴露面小，降一级
            loopback_only = row["laddr"].startswith("127.") or row["laddr"].startswith("[::1]")
            if loopback_only and sev in ("high", "critical"):
                sev = "medium"
            events.append(Event(
                kind="net.listen", source=self.name, ts=now,
                pid=row["pid"], process=row["process"], user=row["user"],
                path=row["laddr"], severity=sev,
                subject={
                    "addr": row["laddr"], "port": row["lport"], "service": name,
                    "loopback_only": loopback_only, "proto": row["type"],
                },
            ))

        self._conns = conns
        self._listens = listens
        self._publish(conns, listens)
        return events

    def _publish(self, conns: Dict, listens: Dict) -> None:
        rows = sorted(conns.values(), key=lambda r: (not _is_private(r["rip"]), r["rport"]))
        for r in rows:
            r["public"] = bool(r["rip"]) and not _is_private(r["rip"])
        self.store.set_state("connections", {
            "active": len(rows),
            "public": sum(1 for r in rows if r["public"]),
            "rows": rows[:300],
            "listeners": sorted(listens.values(), key=lambda r: r["lport"])[:120],
            "ts": time.time(),
            "perm_error": self._perm_error,
        })
