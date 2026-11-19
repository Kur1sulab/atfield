"""主机防火墙客户端：主程序这边唯一的入口。

主程序不碰 pfctl（普通用户连 /dev/pf 都读不了），全部动作发往
pfhelper 的 unix socket；helper 不在时状态里明确写 `available=false`，
绝不把「读不到」伪装成「没有阻断规则」——静默失效比报错难查一百倍。

配置（config.yaml）::

    firewall:
      enabled: false          # 总开关，默认关
      dry_run: true           # 只校验不加载，默认更保守
      socket: /var/run/atfield-pf.sock
      allow_attach: false     # 是否允许动 /etc/pf.conf
"""
from __future__ import annotations

import json
import os
import socket
import time
from typing import Any, Dict, List, Optional

PROTO = 1


class Firewall:
    def __init__(self, cfg: Dict[str, Any], store=None):
        fcfg = (cfg.get("firewall") or {}) if isinstance(cfg, dict) else {}
        self.cfg = cfg
        self.store = store
        self.enabled = bool(fcfg.get("enabled", False))
        self.dry_run = bool(fcfg.get("dry_run", True))
        self.socket_path = str(fcfg.get("socket") or "/var/run/atfield-pf.sock")
        self.allow_attach = bool(fcfg.get("allow_attach", False))
        self.timeout = float(fcfg.get("timeout", 6) or 6)
        self.last_error = ""

    # ---------- 通道 ----------
    def available(self) -> bool:
        return os.path.exists(self.socket_path)

    def _call(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if not self.enabled:
            return {"ok": False, "skipped": True,
                    "detail": "防火墙层未启用（firewall.enabled=false）"}
        payload = dict(payload)
        payload["v"] = PROTO
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect(self.socket_path)
            s.sendall((json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8"))
            buf = b""
            while b"\n" not in buf and len(buf) < 65536:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
            s.close()
            line = buf.split(b"\n", 1)[0].decode("utf-8", "replace")
            if not line:
                self.last_error = "helper 没有返回内容"
                return {"ok": False, "detail": self.last_error}
            out = json.loads(line)
            return out if isinstance(out, dict) else {"ok": False, "detail": "响应格式错误"}
        except FileNotFoundError:
            self.last_error = f"找不到 helper socket: {self.socket_path}"
            return {"ok": False, "unavailable": True, "detail": self.last_error}
        except socket.timeout:
            self.last_error = "helper 响应超时"
            return {"ok": False, "detail": self.last_error}
        except PermissionError:
            self.last_error = "没有权限连接 helper socket"
            return {"ok": False, "detail": self.last_error}
        except ConnectionRefusedError:
            self.last_error = "helper socket 存在但没有进程在听"
            return {"ok": False, "unavailable": True, "detail": self.last_error}
        except Exception as exc:                                # noqa: BLE001
            self.last_error = f"{type(exc).__name__}: {exc}"
            return {"ok": False, "detail": self.last_error}

    # ---------- 查询 ----------
    def status(self) -> Dict[str, Any]:
        base: Dict[str, Any] = {
            "enabled": self.enabled,
            "dry_run": self.dry_run,
            "allow_attach": self.allow_attach,
            "socket": self.socket_path,
            "socket_present": os.path.exists(self.socket_path),
            "available": False,
            "pf_enabled": None,
            "attached": None,
            "count": 0,
            "blocked": [],
            "detail": "",
        }
        if not self.enabled:
            base["detail"] = "防火墙层未启用（firewall.enabled=false）"
            return base
        if not base["socket_present"]:
            base["detail"] = ("特权 helper 未启动。装上并启动它之后这里才会变成可执行状态：\n"
                              "  sudo python3 -m atfield.pfhelper --allow-uid $(id -u)")
            return base
        res = self._call({"op": "status"})
        base["available"] = bool(res.get("ok"))
        if not res.get("ok"):
            base["detail"] = str(res.get("detail") or "helper 无响应")
            return base
        for k in ("pf_enabled", "anchor", "anchor_present", "rule_lines",
                  "rules_sample", "attached"):
            if k in res:
                base[k] = res[k]
        base["count"] = int(res.get("count") or 0)
        base["blocked"] = list(res.get("blocked") or [])[:500]
        if base.get("attached") is False:
            base["detail"] = ("anchor 已存在但没挂进主规则集（/etc/pf.conf 里没有 "
                              "anchor \"atfield\"），规则写进去也不会生效")
        return base

    def blocked(self) -> List[str]:
        st = self.status()
        return list(st.get("blocked") or [])

    # ---------- 动作 ----------
    def block(self, target: str, reason: str = "") -> Dict[str, Any]:
        res = self._call({"op": "block", "ip": str(target or ""),
                          "reason": str(reason or "")[:180], "dry_run": self.dry_run})
        res["dry_run"] = self.dry_run
        return res

    def unblock(self, target: str) -> Dict[str, Any]:
        res = self._call({"op": "unblock", "ip": str(target or ""), "dry_run": self.dry_run})
        res["dry_run"] = self.dry_run
        return res

    def flush(self) -> Dict[str, Any]:
        return self._call({"op": "flush"})

    def attach(self) -> Dict[str, Any]:
        """把 anchor 挂进主规则集。默认关闭，只有 allow_attach 才允许。"""
        if not self.allow_attach:
            return {"ok": False,
                    "detail": "未允许修改 /etc/pf.conf（firewall.allow_attach=false）"}
        return self._call({"op": "attach", "dry_run": self.dry_run})

    def detach(self) -> Dict[str, Any]:
        if not self.allow_attach:
            return {"ok": False,
                    "detail": "未允许修改 /etc/pf.conf（firewall.allow_attach=false）"}
        return self._call({"op": "detach"})

    # ---------- 给界面的一段人话 ----------
    def summary(self) -> Dict[str, Any]:
        st = self.status()
        if not st.get("enabled"):
            who, tone = "未启用", "off"
        elif not st.get("available"):
            who, tone = "helper 未就位", "off"
        elif not st.get("pf_enabled"):
            who, tone = "pf 未开启", "warn"
        elif st.get("attached") is False:
            who, tone = "规则未挂载", "warn"
        elif st.get("count"):
            who, tone = f"已阻断 {st['count']} 个目标", "on"
        else:
            who, tone = "在位 · 无阻断", "on"
        out = {"ok": True}
        out.update(st)                       # 状态摊平，前端不用再挖一层
        out.update({"label": who, "tone": tone})
        return out
