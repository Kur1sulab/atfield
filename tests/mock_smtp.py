#!/usr/bin/env python3
"""只接收、不转发的 mock SMTP 服务（纯标准库，Python 3.12 无 smtpd/aiosmtpd 也能跑）。

用途：实测月报 --send 投递链路。收到的每封信原样落盘（.eml + 信封 .json），
绝不向外转发，绝不碰真实邮件系统。

两种用法：
    # 1) 命令行起服务（手工验证 / 留证据）
    python3 tests/mock_smtp.py --port 8917 --out /tmp/inbox
    python3 tests/mock_smtp.py --port 8917 --out /tmp/inbox --starttls --cert c.pem --key k.pem
    python3 tests/mock_smtp.py --port 8917 --out /tmp/inbox --require-auth --user u --password ***

    # 2) 测试里内嵌（端口 0 自动分配）
    from tests.mock_smtp import MockSMTPServer
    srv = MockSMTPServer(out_dir); srv.start()
    ...  # srv.port / srv.wait_messages(1) / srv.messages
    srv.stop()

实现的 ESMTP 子集：EHLO/HELO、AUTH PLAIN/LOGIN、可选 STARTTLS、
MAIL FROM / RCPT TO / DATA / RSET / NOOP / QUIT。够 smtplib 走完整投递。
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import socketserver
import ssl
import sys
import threading
import time
from typing import Any, Dict, List, Optional


class _Handler(socketserver.BaseRequestHandler):
    """一个连接一个会话；信封与正文落盘到 server.out_dir。"""

    def setup(self) -> None:
        self.sock = self.request
        self.sock.settimeout(60)
        self.rfile = self.sock.makefile("rb")
        self.tls_active = False

    def send_line(self, line: str) -> None:
        self.sock.sendall((line + "\r\n").encode("utf-8"))

    def _read_line(self) -> Optional[str]:
        raw = self.rfile.readline()
        if not raw:
            return None
        return raw.decode("utf-8", "replace").rstrip("\r\n")

    def handle(self) -> None:
        srv: "MockSMTPServer" = self.server  # type: ignore[assignment]
        env: Dict[str, Any] = {
            "mail_from": None, "rcpt_tos": [], "auth_user": None,
            "auth_ok": False, "tls": False, "commands": [],
            "peer": list(self.client_address), "ts": time.time(),
        }
        self.send_line("220 mock.atfield.local ESMTP atfield-test-sink")
        while True:
            try:
                line = self._read_line()
            except (OSError, ssl.SSLError):
                return
            if line is None:
                return
            parts = line.split(" ", 1)
            cmd = parts[0].upper() if parts else ""
            arg = parts[1] if len(parts) > 1 else ""
            # AUTH 参数含口令，日志里打码
            env["commands"].append(
                (cmd + " <redacted>") if cmd == "AUTH" else line)
            if srv.verbose:
                shown = (cmd + " <redacted>") if cmd == "AUTH" else line
                print(f"[mock-smtp] C: {shown}", flush=True)

            if cmd in ("EHLO", "HELO"):
                if cmd == "EHLO":
                    feats = ["mock.atfield.local"]
                    if srv.users is not None or srv.require_auth:
                        feats.append("AUTH " + " ".join(srv.auth_mechs))
                    if srv.tls_context is not None and not self.tls_active:
                        feats.append("STARTTLS")
                    feats.append("HELP")
                    for i, f in enumerate(feats):
                        sep = "-" if i < len(feats) - 1 else " "
                        self.send_line(f"250{sep}{f}")
                else:
                    self.send_line("250 mock.atfield.local")
            elif cmd == "STARTTLS":
                if srv.tls_context is None or self.tls_active:
                    self.send_line("502 5.5.1 STARTTLS not available")
                    continue
                self.send_line("220 2.0.0 Ready to start TLS")
                try:
                    self.sock = srv.tls_context.wrap_socket(
                        self.sock, server_side=True)
                    self.rfile.close()
                    self.rfile = self.sock.makefile("rb")
                    self.tls_active = True
                    env["tls"] = True
                except (OSError, ssl.SSLError) as exc:
                    if srv.verbose:
                        print(f"[mock-smtp] TLS handshake failed: {exc}", flush=True)
                    return
            elif cmd == "AUTH":
                self._do_auth(arg, env, srv)
            elif cmd == "MAIL":
                if srv.require_auth and not env["auth_ok"]:
                    self.send_line("530 5.7.0 Authentication required")
                    continue
                env["mail_from"] = _extract_addr(arg)
                env["rcpt_tos"] = []
                self.send_line("250 2.1.0 Ok")
            elif cmd == "RCPT":
                if srv.require_auth and not env["auth_ok"]:
                    self.send_line("530 5.7.0 Authentication required")
                    continue
                addr = _extract_addr(arg)
                if not addr:
                    self.send_line("501 5.1.3 Bad recipient address")
                    continue
                env["rcpt_tos"].append(addr)
                self.send_line("250 2.1.5 Ok")
            elif cmd == "DATA":
                if not env["mail_from"] or not env["rcpt_tos"]:
                    self.send_line("503 5.5.1 Need MAIL/RCPT first")
                    continue
                self.send_line("354 End data with <CR><LF>.<CR><LF>")
                body = self._read_data()
                if body is None:
                    return
                n = srv.save_message(env, body)
                env = {**env, "mail_from": None, "rcpt_tos": []}
                self.send_line(f"250 2.0.0 Ok: queued as {n:06d}")
            elif cmd == "RSET":
                env["mail_from"] = None
                env["rcpt_tos"] = []
                self.send_line("250 2.0.0 Ok")
            elif cmd == "NOOP":
                self.send_line("250 2.0.0 Ok")
            elif cmd == "QUIT":
                self.send_line("221 2.0.0 Bye")
                return
            else:
                self.send_line("502 5.5.2 Command not implemented")

    def _do_auth(self, arg: str, env: Dict[str, Any], srv: "MockSMTPServer") -> None:
        mech, _, rest = arg.partition(" ")
        mech = mech.upper()
        user = pw = None
        try:
            if mech == "PLAIN":
                blob = rest.strip()
                if not blob:
                    self.send_line("334 ")
                    blob = (self._read_line() or "").strip()
                decoded = base64.b64decode(blob).decode("utf-8", "replace")
                _, user, pw = decoded.split("\x00", 2)
            elif mech == "LOGIN":
                # RFC 4954：AUTH LOGIN 可带初始响应（就是用户名），
                # smtplib 默认 initial_response_ok=True 会直接带上。
                if rest.strip():
                    user = base64.b64decode(rest.strip()).decode("utf-8", "replace")
                else:
                    self.send_line("334 " + base64.b64encode(b"Username:").decode())
                    user = base64.b64decode((self._read_line() or "").strip()).decode("utf-8", "replace")
                self.send_line("334 " + base64.b64encode(b"Password:").decode())
                pw = base64.b64decode((self._read_line() or "").strip()).decode("utf-8", "replace")
            else:
                self.send_line("504 5.5.4 Unrecognized authentication type")
                return
        except Exception:
            self.send_line("501 5.5.2 Malformed AUTH payload")
            return
        env["auth_user"] = user
        if srv.users is None:
            ok = True                      # 不校验模式：记录但放行
        else:
            ok = srv.users.get(str(user)) == str(pw)
        env["auth_ok"] = ok
        env["auth_mech"] = mech
        if ok:
            self.send_line("235 2.7.0 Authentication successful")
        else:
            self.send_line("535 5.7.8 Authentication credentials invalid")

    def _read_data(self) -> Optional[bytes]:
        chunks: List[bytes] = []
        while True:
            raw = self.rfile.readline()
            if not raw:
                return None
            if raw == b".\r\n" or raw == b".\n":
                break
            if raw.startswith(b".."):
                raw = raw[1:]              # dot-unstuffing（RFC 5321 §4.5.2）
            chunks.append(raw)
        return b"".join(chunks)

    def finish(self) -> None:
        try:
            self.rfile.close()
        except Exception:
            pass


def _extract_addr(arg: str) -> str:
    """从 'FROM:<a@b>' / 'TO:<a@b>' 里取地址。"""
    if "<" in arg and ">" in arg:
        return arg.split("<", 1)[1].split(">", 1)[0].strip()
    return arg.split(":", 1)[-1].strip()


class MockSMTPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, out_dir: str, host: str = "127.0.0.1", port: int = 0,
                 tls_context: Optional[ssl.SSLContext] = None,
                 require_auth: bool = False,
                 users: Optional[Dict[str, str]] = None,
                 auth_mechs: Optional[List[str]] = None,
                 verbose: bool = True):
        self.out_dir = out_dir
        self.tls_context = tls_context
        self.require_auth = require_auth
        self.users = users
        self.auth_mechs = auth_mechs or ["PLAIN", "LOGIN"]
        self.verbose = verbose
        self.messages: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        os.makedirs(out_dir, exist_ok=True)
        super().__init__((host, port), _Handler)

    @property
    def port(self) -> int:
        return int(self.server_address[1])

    def save_message(self, env: Dict[str, Any], body: bytes) -> int:
        with self._lock:
            n = len(self.messages) + 1
            stem = os.path.join(self.out_dir, f"msg-{n:03d}")
            with open(stem + ".eml", "wb") as fh:
                fh.write(body)
            rec = {**env, "n": n, "size": len(body),
                   "eml": stem + ".eml"}
            with open(stem + ".json", "w", encoding="utf-8") as fh:
                json.dump(rec, fh, ensure_ascii=False, indent=2)
            self.messages.append(rec)
        if self.verbose:
            print(f"[mock-smtp] RECEIVED #{n} from={env['mail_from']} "
                  f"rcpts={env['rcpt_tos']} bytes={len(body)} "
                  f"tls={env['tls']} auth_user={env['auth_user']} "
                  f"-> {stem}.eml", flush=True)
        return n

    # ---- 测试用生命周期 ----
    def start(self) -> "MockSMTPServer":
        t = threading.Thread(target=self.serve_forever,
                             name="mock-smtp", daemon=True)
        t.start()
        self._thread = t
        return self

    def stop(self) -> None:
        try:
            self.shutdown()
            self.server_close()
        except Exception:
            pass

    def wait_messages(self, n: int, timeout: float = 15.0) -> List[Dict[str, Any]]:
        t0 = time.time()
        while time.time() - t0 < timeout:
            with self._lock:
                if len(self.messages) >= n:
                    return list(self.messages)
            time.sleep(0.05)
        with self._lock:
            return list(self.messages)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="mock_smtp", description="只接收不转发的测试 SMTP 服务")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8917)
    ap.add_argument("--out", required=True, help="收信落盘目录")
    ap.add_argument("--starttls", action="store_true", help="广告并支持 STARTTLS（需 --cert/--key）")
    ap.add_argument("--cert", default="")
    ap.add_argument("--key", default="")
    ap.add_argument("--require-auth", action="store_true", help="未 AUTH 拒绝 MAIL FROM")
    ap.add_argument("--user", default="", help="合法账号（配合 --require-auth）")
    ap.add_argument("--password", default="")
    ap.add_argument("--auth-mechs", default="PLAIN,LOGIN")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    tls_ctx = None
    if args.starttls:
        if not (args.cert and args.key):
            print("--starttls 需要 --cert 与 --key", file=sys.stderr)
            return 2
        tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_ctx.load_cert_chain(args.cert, args.key)
    users = {args.user: args.password} if args.user else None
    srv = MockSMTPServer(args.out, host=args.host, port=args.port,
                         tls_context=tls_ctx, require_auth=args.require_auth,
                         users=users,
                         auth_mechs=[m.strip().upper() for m in args.auth_mechs.split(",") if m.strip()],
                         verbose=not args.quiet)
    print(f"[mock-smtp] listening on {args.host}:{srv.port} out={args.out} "
          f"starttls={bool(tls_ctx)} require_auth={args.require_auth}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
