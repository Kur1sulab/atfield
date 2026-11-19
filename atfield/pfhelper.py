"""pf 特权 helper：心之壁 唯一碰得到防火墙的东西。

为什么要单独一个进程：
- 主程序以普通用户运行，`pfctl` 连状态都读不了（/dev/pf 要 root）；
- 把 root 收在一个只有几百行、只认 5 个动词的 daemon 里，
  比让整个控制台以 root 跑安全得多——控制台有 HTTP、有插件、有 AI 通道。

安全边界（逐条都是硬约束）：
1. 只监听 unix socket，不监听任何 TCP 端口；
2. 每个连接都用 getpeereid() 校验对端 uid，不在白名单直接断；
3. 只接受 status / block / unblock / flush / attach / detach 五个动词，
   参数经严格校验后才拼进 pf 规则——不做任何 shell 拼接；
4. 拒绝把本机地址、默认网关、回环、超大网段写进阻断表，防自锁；
5. 每条规则先 `pfctl -n` 解析校验，再真加载；加载失败自动回退到上一版；
6. 所有动作追加写审计行，落盘 root 可读。

用法（需要 root）：
    sudo python3 -m atfield.pfhelper --socket /var/run/atfield-pf.sock \
         --anchor atfield --allow-uid 501
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import struct
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

PROTO = 1
MAX_REQ = 4096
PFCTL = "/sbin/pfctl"
MARK_BEGIN = "# >>> atfield managed >>>"
MARK_END = "# <<< atfield managed <<<"
OPS = ("status", "block", "unblock", "flush", "attach", "detach")


# ---------------------------------------------------------------- 工具
def _run(cmd: List[str], stdin_text: Optional[str] = None, timeout: float = 8.0) -> Dict[str, Any]:
    try:
        p = subprocess.run(cmd, input=stdin_text, text=True,
                           capture_output=True, timeout=timeout)
        return {"ok": p.returncode == 0, "code": p.returncode,
                "out": (p.stdout or "").strip(), "err": (p.stderr or "").strip()}
    except FileNotFoundError:
        return {"ok": False, "code": -1, "out": "", "err": "找不到可执行文件"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "code": -2, "out": "", "err": "命令超时"}
    except Exception as exc:                                   # noqa: BLE001
        return {"ok": False, "code": -3, "out": "", "err": f"{type(exc).__name__}: {exc}"}


def local_addrs() -> Tuple[set, Optional[str]]:
    """本机地址 + 默认网关。用来防自锁——这两个东西永远不许进阻断表。"""
    addrs, gw = set(), None
    r = _run(["ifconfig", "-a"])
    if r["ok"]:
        for line in r["out"].splitlines():
            parts = line.split()
            if "inet" in parts:
                i = parts.index("inet")
                if i + 1 < len(parts):
                    addrs.add(parts[i + 1])
            elif "inet6" in parts:
                i = parts.index("inet6")
                if i + 1 < len(parts):
                    addrs.add(parts[i + 1].split("%")[0])
    r = _run(["route", "-n", "get", "default"])
    if r["ok"]:
        for line in r["out"].splitlines():
            if line.strip().startswith("gateway:"):
                gw = line.split(":", 1)[1].strip()
    return addrs, gw


def parse_target(raw: str) -> Tuple[Optional[Any], str]:
    """把用户输入变成一个网络对象。返回 (net, 错误)。"""
    s = (raw or "").strip()
    if not s or len(s) > 64:
        return None, "地址为空或过长"
    try:
        if "/" in s:
            net = ipaddress.ip_network(s, strict=False)
        else:
            net = ipaddress.ip_network(s + ("/32" if "." in s else "/128"), strict=False)
    except ValueError:
        return None, f"不是合法的 IP 或网段: {s[:40]}"
    if net.is_loopback:
        return None, "拒绝：回环地址（封了会断本机服务）"
    if net.is_unspecified:
        return None, "拒绝：0.0.0.0/:: 这类全零地址"
    if net.is_multicast:
        return None, "拒绝：组播地址"
    if net.prefixlen < (8 if net.version == 4 else 16):
        return None, f"拒绝：网段过大（/{net.prefixlen}），一封就是一片"
    return net, ""


def self_lock(net) -> str:
    """会不会把自己锁死。"""
    addrs, gw = local_addrs()
    if gw:
        try:
            if ipaddress.ip_address(gw) in net:
                return f"拒绝：{net} 覆盖本机默认网关 {gw}，封了整台机器就断网"
        except ValueError:
            pass
    for a in addrs:
        try:
            if ipaddress.ip_address(a) in net:
                if net.prefixlen in (32, 128):
                    return f"拒绝：{net} 是本机自己的地址"
                return (f"拒绝：{net} 包含本机地址 {a}，"
                        f"这个网段封下去会把自己锁在外面")
        except ValueError:
            continue
    return ""


def peer_creds(conn) -> Tuple[int, str]:
    """取对端 uid。三级兜底，取不到返回 (-1, 原因) —— 取不到就拒绝，绝不放行。"""
    try:
        getter = getattr(conn, "getpeereid", None)
        if getter is not None:
            uid, _gid = getter()
            return int(uid), ""
    except OSError as exc:
        err = f"getpeereid 失败: {exc}"
    else:
        err = ""
    # macOS: SOL_LOCAL / LOCAL_PEERCRED，struct xucred 头 8 字节是 version + uid
    try:
        raw = conn.getsockopt(0, 0x001, 76)
        if len(raw) >= 8:
            _ver, uid = struct.unpack_from("<II", raw, 0)
            return int(uid), ""
    except OSError:
        pass
    # Linux: SOL_SOCKET / SO_PEERCRED，struct ucred = pid + uid + gid
    try:
        raw = conn.getsockopt(socket.SOL_SOCKET, 17, 12)
        if len(raw) >= 12:
            _pid, uid, _gid = struct.unpack_from("<3i", raw, 0)
            return int(uid), ""
    except OSError:
        pass
    return -1, err or "取不到对端凭据"


def clean_reason(s: str) -> str:
    out = "".join(ch for ch in str(s or "") if 32 <= ord(ch) < 127 or ord(ch) > 127)
    return out.replace("#", "＃").strip()[:180]


# ---------------------------------------------------------------- helper
class PfHelper:
    def __init__(self, anchor: str, allow_uids: List[int], socket_path: str,
                 state_path: str, audit_path: str, allow_attach: bool = False,
                 group: str = ""):
        self.anchor = anchor
        self.allow_uids = set(allow_uids)
        self.group = group or ""
        self.socket_path = socket_path
        self.state_path = state_path
        self.audit_path = audit_path
        self.allow_attach = allow_attach
        self.pfconf = "/etc/pf.conf"
        self.state = self._load_state()

    # ---------- 状态 ----------
    def _load_state(self) -> Dict[str, Any]:
        try:
            with open(self.state_path, "r", encoding="utf-8") as f:
                d = json.load(f)
            if isinstance(d, dict) and isinstance(d.get("ips"), dict):
                return d
        except Exception:                                      # noqa: BLE001
            pass
        return {"ips": {}, "lkg": ""}

    def _save_state(self) -> None:
        tmp = self.state_path + ".tmp"
        os.makedirs(os.path.dirname(self.state_path) or ".", exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.state, f, ensure_ascii=False, indent=1)
        os.replace(tmp, self.state_path)
        self._chown_shared(self.state_path)

    def _chown_shared(self, path: str) -> None:
        """让控制台用户读得到审计/状态文件——审计本来就是要给人看的。"""
        try:
            os.chmod(path, 0o640)
        except OSError:
            pass
        if not self.group:
            return
        try:
            import grp
            os.chown(path, 0, grp.getgrnam(self.group).gr_gid)
        except Exception:                                      # noqa: BLE001
            pass

    def _audit(self, op: str, target: str, res: Dict[str, Any], uid: int) -> None:
        try:
            os.makedirs(os.path.dirname(self.audit_path) or ".", exist_ok=True)
            rec = {"ts": int(time.time()), "op": op, "target": target[:200],
                   "uid": uid, "ok": bool(res.get("ok")),
                   "detail": str(res.get("detail") or res.get("err") or "")[:300]}
            with open(self.audit_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            self._chown_shared(self.audit_path)
        except Exception:                                      # noqa: BLE001
            pass

    # ---------- pf 交互 ----------
    def _pf(self, args: List[str], stdin_text: Optional[str] = None) -> Dict[str, Any]:
        return _run([PFCTL] + args, stdin_text=stdin_text)

    def pf_status(self) -> Dict[str, Any]:
        info = self._pf(["-s", "info"])
        anchors = self._pf(["-s", "Anchors"])
        rules = self._pf(["-a", self.anchor, "-s", "rules"])
        return {
            "ok": True,
            "pf_enabled": bool(info["ok"] and "Status: Enabled" in info.get("out", "")),
            "pf_error": "" if info["ok"] else info.get("err", "")[:200],
            "anchor_present": bool(anchors["ok"] and self.anchor in anchors.get("out", "")),
            "rule_lines": len([l for l in (rules.get("out") or "").splitlines() if l.strip()]),
            "rules_sample": [l for l in (rules.get("out") or "").splitlines() if l.strip()][:8],
            "attached": self._is_attached(),
        }

    def _is_attached(self) -> bool:
        try:
            with open(self.pfconf, "r", encoding="utf-8") as f:
                body = f.read()
        except Exception:                                      # noqa: BLE001
            return False
        return f'anchor "{self.anchor}"' in body

    def render(self) -> str:
        """当前阻断表 → anchor 规则文本。纯函数，可单测。"""
        lines = [MARK_BEGIN, f"# generated {time.strftime('%Y-%m-%dT%H:%M:%S%z')}",
                 f"# rules {len(self.state['ips'])}"]
        for ip, meta in sorted(self.state["ips"].items()):
            why = clean_reason((meta or {}).get("reason", ""))
            lines.append(f"# {ip} {why}".rstrip())
            # 双向各一条，排除回环——不挡本机自己跟自己说话
            lines.append(f"block drop quick on ! lo0 from {ip} to any")
            lines.append(f"block drop quick on ! lo0 from any to {ip}")
        lines.append(MARK_END)
        return "\n".join(lines) + "\n"

    def _load_anchor(self, text: str) -> Dict[str, Any]:
        """先解析校验，再真加载。失败回退上一版。"""
        chk = self._pf(["-a", self.anchor, "-n", "-f", "-"], stdin_text=text)
        if not chk["ok"]:
            return {"ok": False, "stage": "parse",
                    "detail": (chk.get("err") or chk.get("out") or "规则解析失败")[:300]}
        res = self._pf(["-a", self.anchor, "-f", "-"], stdin_text=text)
        if not res["ok"]:
            lkg = self.state.get("lkg") or ""
            if lkg:
                rb = self._pf(["-a", self.anchor, "-f", "-"], stdin_text=lkg)
                return {"ok": False, "stage": "load", "rolled_back": bool(rb["ok"]),
                        "detail": (res.get("err") or res.get("out") or "加载失败")[:300]}
            return {"ok": False, "stage": "load",
                    "detail": (res.get("err") or res.get("out") or "加载失败")[:300]}
        self.state["lkg"] = text
        return {"ok": True, "loaded": True}

    # ---------- 五个动词 ----------
    def op_status(self) -> Dict[str, Any]:
        st = self.pf_status()
        st.update({"anchor": self.anchor, "count": len(self.state["ips"]),
                   "blocked": sorted(self.state["ips"].keys())[:500],
                   "helper": "ok"})
        return st

    def op_block(self, raw_ip: str, reason: str = "", dry_run: bool = False,
                 uid: int = 0) -> Dict[str, Any]:
        net, err = parse_target(raw_ip)
        if err:
            return {"ok": False, "detail": err}
        lock = self_lock(net)
        if lock:
            return {"ok": False, "detail": lock}
        ip = str(net)
        if len(self.state["ips"]) >= 500 and ip not in self.state["ips"]:
            return {"ok": False, "detail": "阻断表已满（上限 500 条），请先清理"}
        old = self.state["ips"].get(ip)
        self.state["ips"][ip] = {"reason": clean_reason(reason), "ts": int(time.time()), "uid": uid}
        text = self.render()
        if dry_run:
            chk = self._pf(["-a", self.anchor, "-n", "-f", "-"], stdin_text=text)
            if old is None:
                self.state["ips"].pop(ip, None)
            else:
                self.state["ips"][ip] = old
            return {"ok": bool(chk["ok"]), "dry_run": True, "ip": ip,
                    "validated": bool(chk["ok"]),
                    "detail": "语法校验通过，未加载" if chk["ok"]
                              else (chk.get("err") or "校验失败")[:300]}
        self._save_state()
        res = self._load_anchor(text)
        res.update({"ip": ip, "dry_run": False})
        if not res.get("ok"):
            self.state["ips"].pop(ip, None)
            self._save_state()
        return res

    def op_unblock(self, raw_ip: str, dry_run: bool = False, uid: int = 0) -> Dict[str, Any]:
        s = (raw_ip or "").strip()
        ip = s
        try:
            n = ipaddress.ip_network(s if "/" in s else s + ("/32" if "." in s else "/128"),
                                     strict=False)
            ip = str(n)
        except ValueError:
            pass
        if ip not in self.state["ips"]:
            return {"ok": True, "ip": ip, "removed": False, "detail": "本来就不在阻断表里"}
        self.state["ips"].pop(ip, None)
        text = self.render()
        if dry_run:
            return {"ok": True, "ip": ip, "dry_run": True, "removed": True}
        self._save_state()
        res = self._load_anchor(text)
        res.update({"ip": ip, "removed": bool(res.get("ok"))})
        return res

    def op_flush(self, uid: int = 0) -> Dict[str, Any]:
        n = len(self.state["ips"])
        self.state["ips"] = {}
        self._save_state()
        res = self._load_anchor(self.render())
        res.update({"flushed": n})
        return res

    def op_attach(self, dry_run: bool = False, uid: int = 0) -> Dict[str, Any]:
        """把 anchor 挂进主规则集——只有这一步会动系统文件。"""
        if not self.allow_attach:
            return {"ok": False, "detail": "helper 启动时未允许 attach（--allow-attach）"}
        if self._is_attached():
            return {"ok": True, "attached": True, "detail": "已经是挂载状态"}
        try:
            with open(self.pfconf, "r", encoding="utf-8") as f:
                body = f.read()
        except Exception as exc:                               # noqa: BLE001
            return {"ok": False, "detail": f"读不到 {self.pfconf}: {exc}"}
        new_body = body.rstrip() + f"\n\nanchor \"{self.anchor}\"\n"
        chk_path = self.state_path + ".pfconf.try"
        with open(chk_path, "w", encoding="utf-8") as f:
            f.write(new_body)
        chk = self._pf(["-n", "-f", chk_path])
        if not chk["ok"]:
            os.unlink(chk_path)
            return {"ok": False, "stage": "parse",
                    "detail": (chk.get("err") or "新规则集解析失败")[:300]}
        if dry_run:
            os.unlink(chk_path)
            return {"ok": True, "dry_run": True, "attached": False,
                    "detail": "主规则集加上 anchor 后语法通过，未写入"}
        bak = self.pfconf + f".atfield-bak-{int(time.time())}"
        with open(bak, "w", encoding="utf-8") as f:
            f.write(body)
        try:
            with open(self.pfconf, "w", encoding="utf-8") as f:
                f.write(new_body)
            os.unlink(chk_path)
            rel = self._pf(["-f", self.pfconf])
            if not rel["ok"]:
                with open(self.pfconf, "w", encoding="utf-8") as f:
                    f.write(body)
                self._pf(["-f", self.pfconf])
                return {"ok": False, "stage": "reload", "rolled_back": True,
                        "backup": bak, "detail": (rel.get("err") or "重载失败")[:300]}
        except Exception as exc:                               # noqa: BLE001
            return {"ok": False, "detail": f"写 {self.pfconf} 失败: {exc}"}
        return {"ok": True, "attached": True, "backup": bak}

    def op_detach(self, uid: int = 0) -> Dict[str, Any]:
        if not self.allow_attach:
            return {"ok": False, "detail": "helper 启动时未允许 attach（--allow-attach）"}
        try:
            with open(self.pfconf, "r", encoding="utf-8") as f:
                body = f.read()
        except Exception as exc:                               # noqa: BLE001
            return {"ok": False, "detail": f"读不到 {self.pfconf}: {exc}"}
        line = f'anchor "{self.anchor}"'
        kept = [l for l in body.splitlines() if l.strip() != line]
        if len(kept) == len(body.splitlines()):
            return {"ok": True, "attached": False, "detail": "本来就没挂"}
        bak = self.pfconf + f".atfield-bak-{int(time.time())}"
        with open(bak, "w", encoding="utf-8") as f:
            f.write(body)
        with open(self.pfconf, "w", encoding="utf-8") as f:
            f.write("\n".join(kept).rstrip() + "\n")
        rel = self._pf(["-f", self.pfconf])
        if not rel["ok"]:
            with open(self.pfconf, "w", encoding="utf-8") as f:
                f.write(body)
            self._pf(["-f", self.pfconf])
            return {"ok": False, "rolled_back": True, "backup": bak,
                    "detail": (rel.get("err") or "重载失败")[:300]}
        return {"ok": True, "attached": False, "backup": bak}

    # ---------- 分发 ----------
    def handle(self, req: Dict[str, Any], uid: int) -> Dict[str, Any]:
        op = str(req.get("op") or "")
        if op not in OPS:
            return {"ok": False, "detail": f"未知动作: {op[:20]}"}
        dry = bool(req.get("dry_run"))
        if op == "status":
            return self.op_status()
        if op == "block":
            return self.op_block(str(req.get("ip") or ""), str(req.get("reason") or ""),
                                 dry, uid)
        if op == "unblock":
            return self.op_unblock(str(req.get("ip") or ""), dry, uid)
        if op == "flush":
            return self.op_flush(uid)
        if op == "attach":
            return self.op_attach(dry, uid)
        return self.op_detach(uid)


# ---------------------------------------------------------------- 服务
def serve(args) -> int:
    try:
        os.unlink(args.socket)
    except FileNotFoundError:
        pass
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old = os.umask(0o177)
    try:
        srv.bind(args.socket)
        os.chmod(args.socket, 0o660)
        if args.group:
            try:
                import grp
                os.chown(args.socket, 0, grp.getgrnam(args.group).gr_gid)
            except Exception:                                  # noqa: BLE001
                pass
    finally:
        os.umask(old)
    srv.listen(8)
    helper = PfHelper(args.anchor, args.allow_uid, args.socket, args.state,
                      args.audit, allow_attach=args.allow_attach, group=args.group)
    sys.stderr.write(f"[pfhelper] listening {args.socket} anchor={args.anchor} "
                     f"uid={args.allow_uid} attach={args.allow_attach}\n")
    sys.stderr.flush()
    while True:
        try:
            conn, _ = srv.accept()
        except KeyboardInterrupt:
            break
        except Exception:                                      # noqa: BLE001
            continue
        with conn:
            try:
                conn.settimeout(5.0)
                peer_uid, peer_err = peer_creds(conn)
                buf = b""
                while len(buf) < MAX_REQ:
                    chunk = conn.recv(1024)
                    if not chunk:
                        break
                    buf += chunk
                    if b"\n" in buf:
                        break
                line = buf.split(b"\n", 1)[0].decode("utf-8", "replace")
                if peer_uid not in helper.allow_uids:
                    resp = {"ok": False,
                            "detail": (f"拒绝：对端 uid={peer_uid} 不在白名单"
                                       + (f"（{peer_err}）" if peer_err else ""))}
                else:
                    try:
                        req = json.loads(line or "{}")
                        if not isinstance(req, dict):
                            raise ValueError("请求必须是对象")
                        if int(req.get("v") or 0) != PROTO:
                            raise ValueError(f"协议版本不匹配（需要 {PROTO}）")
                        resp = helper.handle(req, peer_uid)
                    except Exception as exc:                   # noqa: BLE001
                        resp = {"ok": False, "detail": f"请求解析失败: {exc}"}
                    helper._audit(str((req or {}).get("op") or "?"),
                                  str((req or {}).get("ip") or ""), resp, peer_uid)
                conn.sendall((json.dumps(resp, ensure_ascii=False) + "\n").encode("utf-8"))
            except Exception:                                  # noqa: BLE001
                pass
    try:
        os.unlink(args.socket)
    except FileNotFoundError:
        pass
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="心之壁 pf 特权 helper")
    ap.add_argument("--socket", default="/var/run/atfield-pf.sock")
    ap.add_argument("--anchor", default="atfield")
    ap.add_argument("--allow-uid", type=int, action="append", default=None)
    ap.add_argument("--group", default="", help="socket 所属组（可选）")
    ap.add_argument("--state", default="/var/db/atfield-pf/state.json")
    ap.add_argument("--audit", default="/var/db/atfield-pf/audit.jsonl")
    ap.add_argument("--allow-attach", action="store_true",
                    help="允许修改 /etc/pf.conf 把 anchor 挂进主规则集")
    a = ap.parse_args()
    if a.allow_uid is None:
        a.allow_uid = [os.getuid()]
    if os.geteuid() != 0:
        sys.stderr.write("必须用 root 运行（pfctl 需要 /dev/pf）\n")
        return 2
    return serve(a)


if __name__ == "__main__":
    raise SystemExit(main())
