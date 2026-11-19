"""响应动作层：所有动作都有权限边界与审计留痕，不做「一键核弹」。

安全设计：
- 不允许操作 pid<=1 与自身进程；
- 非 root 时只能操作同用户进程（跨用户操作必须显式提权运行）；
- 隔离/封禁只生成命令、不静默执行（避免把运维自己的网断掉）；
- 每个动作写审计日志，供事后复盘。
"""
from __future__ import annotations

import os
import shutil
import time
import zipfile
from typing import Any, Dict, List

import psutil


class Responder:
    def __init__(self, cfg: Dict[str, Any], store):
        self.cfg = cfg
        self.store = store
        rcfg = cfg.get("response") or {}
        self.allow_kill = bool(rcfg.get("allow_kill", True))
        self.data_dir = cfg.get("data_dir") or os.path.expanduser("~/.atfield")

    # ---------- 进程控制 ----------
    def _guard_target(self, pid: int) -> Dict[str, Any]:
        if not isinstance(pid, int) or pid <= 1:
            return {"ok": False, "detail": "拒绝：非法 PID（pid<=1 为内核/launchd）"}
        if pid == os.getpid():
            return {"ok": False, "detail": "拒绝：不能操作 心之壁 自身"}
        try:
            p = psutil.Process(pid)
        except psutil.NoSuchProcess:
            return {"ok": False, "detail": "进程已不存在"}
        except Exception as exc:
            return {"ok": False, "detail": f"无法访问进程: {type(exc).__name__}"}
        if os.geteuid() != 0:
            try:
                if p.uids().real != os.getuid():
                    return {"ok": False,
                            "detail": "拒绝：目标属于其他用户，需 root 运行 心之壁 才能操作"}
            except Exception:
                pass
        try:
            return {"ok": True, "process": p, "name": p.name(), "exe": (p.exe() or "")}
        except Exception:
            return {"ok": True, "process": p, "name": "?", "exe": ""}

    def terminate(self, pid: int, force: bool = False) -> Dict[str, Any]:
        if not self.allow_kill:
            return {"ok": False, "detail": "配置中已禁用进程终止（response.allow_kill=false）"}
        g = self._guard_target(pid)
        if not g.get("ok"):
            return g
        p = g["process"]
        # 二次确认：可执行文件在系统目录且为关键守护进程时拒绝
        exe = g.get("exe") or ""
        if exe.startswith(("/System/", "/usr/libexec/")) and g.get("name") in (
                "launchd", "kernel_task", "WindowServer", "loginwindow"):
            return {"ok": False, "detail": f"拒绝：{g.get('name')} 是关键系统进程"}

        detail = ""
        try:
            if p.status() == psutil.STATUS_ZOMBIE:
                detail = "进程已是僵尸态（已终止，等待父进程回收），无需操作"
                self.store.log_action("analyst", "terminate", f"pid={pid} {g.get('name')}", detail)
                return {"ok": True, "detail": detail, "pid": pid, "name": g.get("name")}
            p.terminate()
            try:
                p.wait(timeout=4)
                detail = "已发送 SIGTERM 并确认退出"
            except psutil.TimeoutExpired:
                # 僵尸态意味着目标已经死了，只是父进程还没回收；这不是「没杀掉」
                try:
                    st = p.status()
                except Exception:
                    st = ""
                if st == psutil.STATUS_ZOMBIE:
                    detail = "已发送 SIGTERM，进程已终止（僵尸态，等待父进程回收）"
                elif force:
                    p.kill()
                    try:
                        p.wait(timeout=3)
                        detail = "SIGTERM 无效，已强制 SIGKILL"
                    except psutil.TimeoutExpired:
                        detail = "已发送 SIGKILL，进程仍处僵尸态（等待父进程回收）"
                else:
                    detail = "已发送 SIGTERM（进程未在 4s 内退出，可再次操作强制结束）"
        except Exception as exc:
            detail = f"操作失败: {type(exc).__name__}: {exc}"
        self.store.log_action("analyst", "terminate", f"pid={pid} {g.get('name')}", detail)
        return {"ok": detail.startswith("已"), "detail": detail, "pid": pid, "name": g.get("name")}

    def suspend(self, pid: int) -> Dict[str, Any]:
        g = self._guard_target(pid)
        if not g.get("ok"):
            return g
        try:
            g["process"].suspend()
            detail = "已挂起（保留现场，可恢复）"
        except Exception as exc:
            detail = f"失败: {type(exc).__name__}"
        self.store.log_action("analyst", "suspend", f"pid={pid} {g.get('name')}", detail)
        return {"ok": detail.startswith("已"), "detail": detail, "pid": pid}

    def resume(self, pid: int) -> Dict[str, Any]:
        g = self._guard_target(pid)
        if not g.get("ok"):
            return g
        try:
            g["process"].resume()
            detail = "已恢复运行"
        except Exception as exc:
            detail = f"失败: {type(exc).__name__}"
        self.store.log_action("analyst", "resume", f"pid={pid} {g.get('name')}", detail)
        return {"ok": detail.startswith("已"), "detail": detail, "pid": pid}

    # ---------- 边界封禁（只生成命令，不静默执行） ----------
    def block_commands(self, ip: str) -> Dict[str, Any]:
        try:
            import ipaddress
            ipaddress.ip_address(ip)
        except Exception:
            return {"ok": False, "detail": "非法 IP 地址"}
        cmds = [
            f"sudo pfctl -t atfield_block -T add {ip}",
            f"sudo pfctl -t atfield_block -T show",
            "# 需在 /etc/pf.conf 中预先定义: table <atfield_block> persist { } 并在 anchor 中 block drop from <atfield_block>",
        ]
        self.store.log_action("analyst", "block:generate", ip, "已生成封禁命令（未执行）")
        return {"ok": True, "detail": "已生成封禁命令", "commands": cmds}

    # ---------- 证据导出 ----------
    def export_evidence(self, store) -> Dict[str, Any]:
        ts = time.strftime("%Y%m%d-%H%M%S")
        outdir = os.path.join(self.data_dir, "exports")
        os.makedirs(outdir, exist_ok=True)
        path = os.path.join(outdir, f"atfield-evidence-{ts}.zip")
        try:
            with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
                # 1) 原始事件流
                raw = os.path.join(self.data_dir, "events.jsonl")
                if os.path.exists(raw):
                    zf.write(raw, "events.jsonl")
                # 2) 当前全量快照
                import json
                snap = {
                    "generated_at": ts,
                    "processes": store.get_state("processes"),
                    "connections": store.get_state("connections"),
                    "sessions": store.get_state("sessions"),
                    "persistence": store.get_state("persistence"),
                    "baseline": store.get_state("baseline"),
                    "integrity": store.get_state("integrity"),
                    "findings": store.snapshot_findings(2000),
                    "incidents": store.snapshot_incidents(200),
                    "actions": store.meta.get("actions", []),
                }
                zf.writestr("snapshot.json", json.dumps(snap, ensure_ascii=False, indent=1))
                # 3) 系统事实（供第三方复核）
                import subprocess
                for name, argv in (
                    ("ps.txt", ["/bin/ps", "-axo", "pid,ppid,user,etime,comm"]),
                    ("netstat.txt", ["/usr/sbin/lsof", "-nP", "-i", "TCP"]),
                    ("launchctl.txt", ["/bin/launchctl", "list"]),
                    ("sw_vers.txt", ["/usr/bin/sw_vers"]),
                ):
                    try:
                        p = subprocess.run(argv, capture_output=True, text=True,
                                           encoding="utf-8", errors="replace", timeout=25)
                        zf.writestr(name, (p.stdout or "")[:4_000_000])
                    except Exception:
                        zf.writestr(name, f"采集失败: {argv}")
            size = os.path.getsize(path)
        except Exception as exc:
            return {"ok": False, "detail": f"导出失败: {type(exc).__name__}: {exc}"}
        self.store.log_action("analyst", "export", path, f"{size} bytes")
        return {"ok": True, "detail": "证据包已生成", "path": path, "size": size}
