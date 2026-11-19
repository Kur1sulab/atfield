"""诱饵端口 —— 在本机开若干 TCP 监听，记录「谁在敲这些不该有人用的端口」。

定位：低成本的早期预警，不是蜜罐平台。
  · 心之壁是单机 EDR，真蜜罐要独立资产与独立网段；这里只做「本机端口层诱饵」：
    正常人不会去连 127.0.0.1:2222，连了就是本机上有个东西在做端口扫描/横向探测。
  · 只记录连接元数据与对端发的头几百字节，不做反制、不回连、不投喂。

安全边界（写在代码里，不是写在文档里）
  1. 默认关闭：`decoy.enabled=false` 时 start_if_enabled() 直接跳过，一个端口都不开。
  2. 只绑回环：bind 必须能解析成 127.0.0.0/8 或 ::1；要绑非回环地址必须
     同时满足 allow_non_loopback=true 且地址不是 0.0.0.0/::/* 这类通配——
     把诱饵开到 0.0.0.0 等于给内网开了个新攻击面，代价远大于收益。
  3. 不残留：listen socket 与线程都在本进程内，stop() 关 socket、join 线程、
     释放端口；不起子进程，所以不存在「进程还在但控制台说停了」。
  4. 日志可审计：连接事件追加到 data_dir/decoy/decoy.jsonl（0600），
     启停动作另外进 AEGIS 审计链（append-only + 链式哈希）。
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import threading
import time
from typing import Any, Dict, List, Optional

PREVIEW_MAX = 120
MAX_EVENTS = 2000


def validate_bind(addr: str, allow_non_loopback: bool = False) -> Dict[str, Any]:
    """校验监听地址。回环放行；通配与外部地址默认拒绝。"""
    raw = str(addr or "").strip()
    if raw in ("", "*", "0.0.0.0", "::", "[::]"):
        return {"ok": False,
                "error": f"拒绝绑定通配地址 {raw or '(空)'}：诱饵端口只应绑回环，"
                         f"绑通配等于对内网新开攻击面"}
    try:
        ip = ipaddress.ip_address(raw.strip("[]"))
    except ValueError:
        # 主机名必须显式解析成本机回环，避免 DNS 被改后绑到别处
        return {"ok": False, "error": f"bind 必须是 IP 字面量（收到 {raw!r}）："
                                      f"不解析主机名，避免 DNS 变化把诱饵绑到非预期地址"}
    if ip.is_loopback:
        return {"ok": True, "bind": str(ip), "family": socket.AF_INET6 if ip.version == 6 else socket.AF_INET,
                "scope": "loopback"}
    if not allow_non_loopback:
        return {"ok": False,
                "error": f"{ip} 不是回环地址；确需对外诱捕请显式设 decoy.allow_non_loopback=true"}
    if ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return {"ok": False, "error": f"{ip} 是保留/组播地址，不作为诱饵监听地址"}
    return {"ok": True, "bind": str(ip), "family": socket.AF_INET6 if ip.version == 6 else socket.AF_INET,
            "scope": "non-loopback"}


def sanitize_preview(raw: bytes, limit: int = PREVIEW_MAX) -> str:
    """对端发来的内容只保留可打印 ASCII，截断，防止把二进制/终端控制符写进日志。"""
    if not raw:
        return ""
    out = []
    for b in raw[:limit]:
        out.append(chr(b) if 32 <= b < 127 else ".")
    return "".join(out)


class Decoy:
    def __init__(self, cfg: Optional[Dict[str, Any]] = None, audit: Any = None):
        c = (cfg or {}).get("decoy") or {}
        self.cfg = cfg or {}
        self.data_dir = os.path.abspath(
            (cfg or {}).get("data_dir") or os.path.expanduser("~/.atfield"))
        self.enabled_by_config = bool(c.get("enabled", False))
        self.bind = str(c.get("bind") or "127.0.0.1")
        self.allow_non_loopback = bool(c.get("allow_non_loopback", False))
        self.ports: List[int] = []
        for p in (c.get("ports") or []):
            try:
                self.ports.append(int(p))
            except (TypeError, ValueError):
                continue
        self.banner = str(c.get("banner", "SSH-2.0-OpenSSH_9.6\r\n"))
        self.max_conns = max(1, int(c.get("max_conns", 200) or 200))
        self.read_bytes = max(16, int(c.get("read_bytes", 512) or 512))
        self.log_keep = max(100, int(c.get("log_keep", MAX_EVENTS) or MAX_EVENTS))
        self.log_path = os.path.join(self.data_dir, "decoy", "decoy.jsonl")
        self.audit = audit

        self._lock = threading.Lock()
        self._socks: Dict[int, socket.socket] = {}
        self._threads: Dict[int, threading.Thread] = {}
        self._stop = threading.Event()
        self._events: List[Dict[str, Any]] = []
        self._log_fh: Optional[Any] = None
        self._conn_total = 0
        self._started_at: Optional[float] = None
        self._errors: Dict[int, str] = {}

    # ---------- 审计 ----------
    def set_audit(self, audit: Any) -> None:
        self.audit = audit

    def _audit(self, action: str, detail: Dict[str, Any]) -> None:
        if not self.audit:
            return
        try:
            self.audit.append(action, actor="decoy", role="system",
                              target=f"decoy:{self.bind}", result="ok", detail=detail)
        except Exception:
            pass        # 审计失败不能把监听带崩

    # ---------- 日志 ----------
    def _open_log(self) -> None:
        if self._log_fh is not None:
            return
        os.makedirs(os.path.dirname(self.log_path), mode=0o700, exist_ok=True)
        self._log_fh = open(self.log_path, "a", encoding="utf-8")
        try:
            os.chmod(self.log_path, 0o600)
        except OSError:
            pass

    def _write_log(self, rec: Dict[str, Any]) -> None:
        with self._lock:
            self._events.append(rec)
            if len(self._events) > self.log_keep:
                self._events = self._events[-self.log_keep:]
            fh = self._log_fh
            if fh is None:
                return
            try:
                fh.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
                fh.flush()
            except Exception:
                pass

    # ---------- 连接处理 ----------
    def _serve(self, sock: socket.socket, port: int) -> None:
        while not self._stop.is_set():
            try:
                conn, peer = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break            # socket 被 stop() 关掉
            t0 = time.time()
            data = b""
            try:
                conn.settimeout(0.5)
                if self.banner:
                    try:
                        conn.sendall(self.banner.encode("utf-8", "replace")[:256])
                    except OSError:
                        pass
                try:
                    data = conn.recv(self.read_bytes)
                except (socket.timeout, OSError):
                    data = b""
            finally:
                try:
                    conn.close()
                except OSError:
                    pass
            with self._lock:
                self._conn_total += 1
                total = self._conn_total
            if total > self.max_conns:
                continue
            try:
                ip = str(peer[0])
                pport = int(peer[1]) if len(peer) > 1 else 0
            except Exception:
                ip, pport = "", 0
            self._write_log({
                "ts": t0,
                "iso": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(t0)),
                "listen_port": port,
                "peer_ip": ip,
                "peer_port": pport,
                "bytes": len(data),
                "preview": sanitize_preview(data),
                "dur_ms": int((time.time() - t0) * 1000),
                "bind": self.bind,
            })

    # ---------- 启停 ----------
    def start(self, ports: Optional[List[int]] = None) -> Dict[str, Any]:
        """显式启动。已启动则幂等返回。"""
        v = validate_bind(self.bind, self.allow_non_loopback)
        if not v["ok"]:
            return {"ok": False, "error": v["error"], "bind": self.bind}
        with self._lock:
            if self._socks:
                return {"ok": True, "already": True, "bind": self.bind,
                        "ports": sorted(self._socks.keys())}

        want = [int(p) for p in (ports if ports is not None else self.ports)] or [0]
        self._stop.clear()
        self._errors = {}
        opened: Dict[int, socket.socket] = {}
        for port in want:
            s = socket.socket(v["family"], socket.SOCK_STREAM)
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((v["bind"], port))
                s.listen(16)
                s.settimeout(0.3)
            except OSError as exc:
                self._errors[port] = f"{type(exc).__name__}: {exc}"
                try:
                    s.close()
                except OSError:
                    pass
                continue
            actual = s.getsockname()[1]
            opened[actual] = s

        if not opened:
            return {"ok": False, "bind": self.bind,
                    "error": "所有诱饵端口都绑定失败（端口被占用？）",
                    "ports": self._errors}

        try:
            self._open_log()
        except OSError as exc:
            for s in opened.values():
                try:
                    s.close()
                except OSError:
                    pass
            return {"ok": False, "error": f"日志无法落盘，拒绝在不可审计状态下开监听：{exc}"}

        with self._lock:
            self._socks = dict(opened)
            for port, s in opened.items():
                th = threading.Thread(target=self._serve, args=(s, port),
                                      name=f"atfield-decoy-{port}", daemon=True)
                self._threads[port] = th
                th.start()
            self._started_at = time.time()
        self._audit("decoy.start", {"bind": self.bind, "ports": sorted(opened.keys()),
                                    "config_enabled": self.enabled_by_config})
        return self.status()

    def start_if_enabled(self, ports: Optional[List[int]] = None) -> Dict[str, Any]:
        """供 Core 启动时调用：配置没开就一个端口都不碰。"""
        if not self.enabled_by_config:
            return {"ok": True, "skipped": True, "running": False,
                    "detail": "诱饵端口未启用（decoy.enabled=false），未监听任何端口"}
        return self.start(ports)

    def stop(self) -> Dict[str, Any]:
        with self._lock:
            socks = list(self._socks.items())
            threads = list(self._threads.items())
            was_running = bool(socks)
        self._stop.set()
        for port, s in socks:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass
        current = threading.current_thread()
        for port, th in threads:
            if th is not current and th.is_alive():
                th.join(timeout=3.0)
        with self._lock:
            self._socks = {}
            self._threads = {}
            n = self._conn_total
            fh, self._log_fh = self._log_fh, None
            self._started_at = None
        if fh is not None:
            try:
                fh.close()
            except Exception:
                pass
        if was_running:
            self._audit("decoy.stop", {"bind": self.bind, "ports": [p for p, _ in socks],
                                       "connections": n})
        return {"ok": True, "was_running": was_running, "running": False,
                "connections": n, "ports": [p for p, _ in socks]}

    # ---------- 状态 ----------
    def running(self) -> bool:
        with self._lock:
            return bool(self._socks)

    def recent(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self._lock:
            evs = list(self._events)[-max(1, int(limit)):]
        return evs

    def event_count(self) -> int:
        with self._lock:
            return len(self._events)

    def events_since(self, idx: int, limit: int = 500) -> List[Dict[str, Any]]:
        """取第 idx 条之后的事件（前台展示用；环形缓冲裁剪后 idx 会失效）。"""
        with self._lock:
            evs = list(self._events)
        return evs[max(0, int(idx)):][:max(1, int(limit))]

    def status(self) -> Dict[str, Any]:
        with self._lock:
            ports = sorted(self._socks.keys())
            threads_alive = sum(1 for t in self._threads.values() if t.is_alive())
            conns = self._conn_total
            started = self._started_at
        log_lines = 0
        try:
            if os.path.isfile(self.log_path):
                with open(self.log_path, "rb") as fh:
                    log_lines = sum(1 for _ in fh)
        except OSError:
            log_lines = -1
        return {
            "ok": True,
            "enabled": self.enabled_by_config,
            "running": bool(ports),
            "bind": self.bind,
            "scope": validate_bind(self.bind, self.allow_non_loopback).get("scope", "invalid"),
            "ports": ports,
            "threads_alive": threads_alive,
            "errors": dict(self._errors),
            "connections": conns,
            "started_at": started,
            "uptime_s": int(time.time() - started) if started else 0,
            "log_path": self.log_path,
            "log_lines": log_lines,
            "log_mode": self._log_mode(),
            "recent": self.recent(20),
            "config_ports": list(self.ports),
        }

    def _log_mode(self) -> str:
        try:
            return format(os.stat(self.log_path).st_mode & 0o777, "04o")
        except OSError:
            return ""
