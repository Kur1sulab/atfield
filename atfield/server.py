"""HTTP 服务：REST API + SSE 实时推送 + 静态控制台。

只绑回环地址，默认不对外监听——单机 EDR 控制台不应被局域网访问。
"""
from __future__ import annotations

import json
import mimetypes
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, quote, urlparse

from . import __product__, __version__, barrier as barrier_mod, compliance, depth as depth_mod, docker_inv as docker_inv_mod, monthly, report as report_mod

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")

# 写操作所需能力。未列出的路径按 triage 处理（研判级），只读路径一律 read。
POST_CAP: Dict[str, str] = {
    "/api/respond": "respond",
    "/api/playbook/confirm": "respond",
    "/api/playbook/reject": "respond",
    "/api/updates/apply": "admin",
    "/api/updates/rollback": "admin",
    "/api/updates/reset": "admin",
    "/api/updates/export": "admin",
    "/api/users/add": "admin",
    "/api/users/passwd": "admin",
    "/api/users/role": "admin",
    "/api/users/delete": "admin",
    "/api/selftest": "admin",
    # AI 层：改配置要 admin（能改端点=能决定数据发往哪），研判只要 triage
    "/api/ai/config": "admin",
    "/api/ai/test": "admin",
    "/api/ai/judge": "triage",
    # 防火墙：阻断是执行级动作，要 respond；动 /etc/pf.conf 只有 admin
    "/api/firewall/block": "respond",
    "/api/firewall/unblock": "respond",
    "/api/firewall/flush": "admin",
    "/api/firewall/attach": "admin",
    "/api/firewall/detach": "admin",
}


class AtFieldServer:
    def __init__(self, core, bind: str = "127.0.0.1", port: int = 8866):
        self.core = core
        self.bind = bind
        self.port = port
        self.httpd: Optional[ThreadingHTTPServer] = None

    def serve_forever(self) -> None:
        handler = _make_handler(self.core)
        self.httpd = ThreadingHTTPServer((self.bind, self.port), handler)
        self.httpd.daemon_threads = True
        self.httpd.serve_forever()

    def shutdown(self) -> None:
        if self.httpd:
            try:
                self.httpd.shutdown()
            except Exception:
                pass


def _make_handler(core):
    class Handler(BaseHTTPRequestHandler):
        # HTTP 头只能是 latin-1：Server 头用包名（ASCII 标识），不用产品显示名。
        # 产品名走页面正文和 /api/version，不塞进协议头。
        server_version = f"atfield/{__version__}"
        protocol_version = "HTTP/1.1"

        # 静默访问日志（避免污染终端输出）
        def log_message(self, fmt, *args):  # noqa: D401
            return

        # ---------- 工具 ----------
        def _send(self, code: int, body: bytes, ctype: str, extra: Optional[Dict] = None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
            self.send_header("X-Content-Type-Options", "nosniff")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            try:
                self.wfile.write(body)
            except Exception:
                pass

        def _json(self, obj: Any, code: int = 200, extra: Optional[Dict] = None):
            self._send(code, json.dumps(obj, ensure_ascii=False, default=str).encode(),
                       "application/json; charset=utf-8", extra)

        def _err(self, msg: str, code: int = 400):
            self._json({"ok": False, "error": msg}, code)

        def _q(self, q: Dict, key: str, default: str = "") -> str:
            v = q.get(key)
            return v[0] if v else default

        # ---------- 鉴权 ----------
        def _token(self) -> str:
            auth = self.headers.get("Authorization") or ""
            if auth.lower().startswith("bearer "):
                tok = auth[7:].strip()
                if tok:
                    return tok
            cookie = self.headers.get("Cookie") or ""
            for part in cookie.split(";"):
                k, _, v = part.strip().partition("=")
                if k == "atfield_session":
                    return v.strip()
            return ""

        def _session(self) -> Optional[Dict[str, Any]]:
            try:
                return core.auth.session(self._token())
            except Exception:
                return None

        def _guard(self, cap: str = "read", target: str = "") -> Optional[Dict[str, Any]]:
            """校验会话与能力；不通过时已写好响应，调用方只需 return。"""
            sess = self._session()
            if not sess:
                self._json({"ok": False, "error": "未登录", "login_required": True}, 401)
                return None
            role = str(sess.get("role") or "viewer")
            if cap and not core.auth.can(role, cap):
                try:
                    core.audit.append("auth.deny", actor=str(sess.get("user")),
                                      role=role, target=target or self.path,
                                      result="deny", detail={"need": cap})
                except Exception:
                    pass
                self._json({"ok": False, "error": "权限不足", "need": cap, "role": role}, 403)
                return None
            return sess

        def _audit(self, action: str, target: str, res: Any, sess: Optional[Dict] = None,
                   detail: Optional[Dict] = None) -> None:
            """把一次写操作记进审计链。失败绝不影响业务返回。"""
            try:
                ok = True
                if isinstance(res, dict):
                    ok = bool(res.get("ok", True))
                core.audit.append(action, actor=str((sess or {}).get("user") or "system"),
                                  role=str((sess or {}).get("role") or "system"),
                                  target=str(target)[:300], result="ok" if ok else "error",
                                  detail=detail or (res if isinstance(res, dict) else {}))
            except Exception:
                pass

        def _client_ip(self) -> str:
            return str(self.client_address[0]) if self.client_address else ""

        # ---------- GET ----------
        def do_GET(self):
            parsed = urlparse(self.path)
            path = parsed.path
            q = parse_qs(parsed.query)
            try:
                if path == "/api/ping":
                    return self._json({"ok": True, "version": __version__, "ts": time.time()})

                if path == "/api/version":
                    import platform as _pf
                    import sys as _sys
                    return self._json({
                        "name": __product__,
                        "version": __version__,
                        "python": _pf.python_version(),
                        "executable": _sys.executable,
                        "platform": _pf.platform(),
                        "themes": ["dark", "light"],
                        "ts": time.time(),
                    })
                if path == "/api/auth/me":
                    sess = self._session()
                    if not sess:
                        return self._json({
                            "ok": False, "login_required": True,
                            "auth_enabled": bool(getattr(core.auth, "enabled", True)),
                            "hint": (core.auth.status().get("bootstrap_file") or ""),
                        }, 401)
                    return self._json({"ok": True, "user": sess.get("user"),
                                       "role": sess.get("role"),
                                       "expires_at": sess.get("expires_at"),
                                       "must_change": bool(sess.get("must_change")),
                                       "caps": sorted(core.auth.caps(str(sess.get("role"))))})
                if path == "/api/governance":
                    if not self._guard("read"):
                        return
                    return self._json(core.governance())
                if path == "/api/audit":
                    if not self._guard("read"):
                        return
                    return self._json({
                        "records": core.audit.tail(int(self._q(q, "limit", "100")),
                                                   action=self._q(q, "action"),
                                                   actor=self._q(q, "actor")),
                        "stats": core.audit.stats(),
                        "anchor": core.audit.anchor(),
                    })
                if path == "/api/audit/verify":
                    if not self._guard("triage"):
                        return
                    return self._json(core.audit.verify())
                if path == "/api/ai/status":
                    if not self._guard("read"):
                        return
                    try:
                        st = core.ai.status()
                        st["stats"] = core.ai.stats()
                        return self._json({"ok": True, **st})
                    except Exception as exc:
                        return self._err(f"{type(exc).__name__}: {exc}", 500)
                if path == "/api/ai/suggestions":
                    if not self._guard("read"):
                        return
                    return self._json({
                        "ok": True,
                        "suggestions": core.ai.recent(int(self._q(q, "limit", "50"))),
                        "stats": core.ai.stats(),
                    })
                if path == "/api/updates":
                    if not self._guard("read"):
                        return
                    return self._json(core.updates.status())
                if path == "/api/users":
                    if not self._guard("admin"):
                        return
                    return self._json({"users": core.auth.list_users(),
                                       "roles": [{"role": r, "caps": sorted(core.auth.caps(r))}
                                                 for r in ("admin", "responder", "analyst", "viewer")]})
                if path == "/api/monthly":
                    if not self._guard("read"):
                        return
                    try:
                        data = monthly.collect(core, self._q(q, "month"))
                        return self._json({"ok": True, "data": data,
                                           "markdown": monthly.render_md(data)})
                    except Exception as exc:
                        return self._err(f"{type(exc).__name__}: {exc}", 500)
                if path == "/api/diag":
                    import sys
                    try:
                        import yaml as _y
                        yv = getattr(_y, "__version__", "?")
                    except Exception as exc:
                        yv = f"import-failed: {type(exc).__name__}: {exc}"
                    pbdir = core.playbooks.dir
                    return self._json({
                        "python": sys.executable, "yaml": yv,
                        "cwd": os.getcwd(), "sys_path0": (sys.path or [""])[0],
                        "playbook_dir": pbdir,
                        "playbook_files": sorted(os.listdir(pbdir)) if os.path.isdir(pbdir) else [],
                        "playbook_count": len(core.playbooks.items),
                        "data_dir": core.cfg.get("data_dir"),
                    })
                if path.startswith("/api/"):
                    if not self._guard("read"):
                        return
                if path == "/api/overview":
                    return self._json(core.overview())
                if path == "/api/events":
                    return self._json({"events": core.store.snapshot_events(
                        limit=int(self._q(q, "limit", "200")),
                        kind=self._q(q, "kind"),
                        q=self._q(q, "q"),
                        min_sev=self._q(q, "min_sev"))})
                if path == "/api/barrier":
                    # 心之壁：把已有检测按「守的是哪条边界」重新组织，不是新增检测
                    if not self._guard("read"):
                        return
                    try:
                        cov = barrier_mod.coverage_from_rules(core.engine.catalog())
                        res = barrier_mod.assess(
                            core.store.snapshot_findings(
                                limit=int(self._q(q, "limit", "500"))), cov)
                        return self._json({"ok": True, **res})
                    except Exception as exc:
                        return self._err(f"{type(exc).__name__}: {exc}", 500)
                if path == "/api/depth":
                    # 纵深剖面：把已有 findings/incidents 只读投影到 L0→L3 深度轴。
                    # 不新增检测、不改业务逻辑，只读 store 快照（同 /api/barrier 模式）。
                    if not self._guard("read"):
                        return
                    try:
                        res = depth_mod.build(core, hours=self._q(q, "hours", "6"))
                        return self._json(res)
                    except Exception as exc:
                        return self._err(f"{type(exc).__name__}: {exc}", 500)
                if path == "/api/docker":
                    # 容器态势（云原生调研 Layer 1）：纯标准库只读直连 docker.sock，
                    # 不依赖 docker CLI。与 /api/firewall 同口径：读不到时
                    # available=false＋原因，绝不伪装成「没有容器」。
                    # collect 内部已全量降级，这里再兜一层。
                    if not self._guard("read"):
                        return
                    try:
                        return self._json(docker_inv_mod.collect())
                    except Exception as exc:
                        return self._err(f"{type(exc).__name__}: {exc}", 500)
                if path == "/api/findings":
                    return self._json({"findings": core.store.snapshot_findings(
                        limit=int(self._q(q, "limit", "200")))})
                if path == "/api/incidents":
                    return self._json({"incidents": core.store.snapshot_incidents(
                        limit=int(self._q(q, "limit", "50")))})
                if path == "/api/assets":
                    st = core.store
                    return self._json({
                        "processes": st.get_state("processes") or {},
                        "connections": st.get_state("connections") or {},
                        "sessions": st.get_state("sessions") or {},
                        "persistence": st.get_state("persistence") or {},
                        "integrity": st.get_state("integrity") or {},
                        "security_sw": st.get_state("security_sw") or {},
                        "baseline": st.get_state("baseline") or {},
                    })
                if path == "/api/rules":
                    return self._json({"rules": core.engine.catalog(),
                                       "chains": core.correlator.catalog()})
                if path == "/api/actions":
                    return self._json({"actions": core.store.meta.get("actions") or []})
                # ---------- 检测与响应 ----------
                if path == "/api/intel":
                    return self._json({"stats": core.intel.stats(),
                                       "items": core.intel.listing(
                                           int(self._q(q, "limit", "200")))})
                if path == "/api/ueba":
                    return self._json(core.ueba.view())
                if path == "/api/firewall":
                    # 主机防火墙：读状态。helper 不在时 available=false，
                    # 绝不把「读不到」伪装成「没有阻断规则」
                    return self._json(core.firewall.summary())
                if path == "/api/canary":
                    return self._json(core.canary.status())
                if path == "/api/ndr":
                    return self._json(core.netintel.status())
                if path == "/api/playbooks":
                    return self._json(core.playbooks.status())
                if path == "/api/inventory":
                    full = self._q(q, "full") == "1"
                    data = core.inventory.last
                    if not data:
                        core.inventory.scan_async()
                        return self._json({"apps": 0, "scanning": True,
                                           "note": "首次扫描已在后台开始，稍后刷新"},
                                          )
                    if not full:
                        data = {k: v for k, v in data.items() if k != "items"}
                    return self._json(data)
                if path == "/api/compliance":
                    if not core.compliance_state:
                        base = core.store.get_state("baseline") or {}
                        core.compliance_state = compliance.build(base, core.store)
                    return self._json(core.compliance_state)
                if path == "/api/tickets":
                    return self._json({"tickets": core.store.snapshot_tickets(
                        int(self._q(q, "limit", "200")))})
                if path == "/api/timeline":
                    return self._json({"timeline": core.store.timeline(
                        int(self._q(q, "limit", "300")))})
                if path == "/api/suppress":
                    _due = core.engine.suppress_review_due()
                    return self._json({"items": core.engine.suppress,
                                       "count": len(core.engine.suppress),
                                       "suppressed_total": core.engine.suppressed,
                                       "suppress_hits": core.engine.suppress_hits,
                                       "review_due": [{"index": d["index"], "reason": d["reason"]}
                                                      for d in _due],
                                       "path": core.engine._suppress_path})
                if path == "/api/monthly/file":
                    try:
                        data = monthly.collect(core, self._q(q, "month"))
                        fmt = (self._q(q, "fmt", "html") or "html").lower()
                        if fmt == "md":
                            body = monthly.render_md(data).encode()
                            ctype = "text/markdown; charset=utf-8"
                            ext = "md"
                        else:
                            body = monthly.render_html(data).encode()
                            ctype = "text/html; charset=utf-8"
                            ext = "html"
                        # HTTP 头只能是 latin-1：中文名走 RFC 5987 的 filename*，
                        # 同时留一个 ASCII 文件名叫老客户端也能存下来
                        mon = data.get("month") or time.strftime("%Y-%m")
                        disp = (f'attachment; filename="atfield-monthly-{mon}.{ext}"; '
                                f"filename*=UTF-8''{quote(f'心之壁-月报-{mon}.{ext}')}")
                        return self._send(200, body, ctype,
                                          {"Content-Disposition": disp})
                    except Exception as exc:
                        return self._err(f"{type(exc).__name__}: {exc}", 500)
                if path == "/api/report.md":
                    md = report_mod.build(core)
                    return self._send(200, md.encode(), "text/markdown; charset=utf-8",
                                      {"Content-Disposition":
                                       f'attachment; filename="atfield-report-{time.strftime("%Y%m%d-%H%M%S")}.md"'})
                if path == "/api/stream":
                    return self._sse()
                # ---------- 静态 ----------
                return self._static(path)
            except BrokenPipeError:
                return
            except Exception as exc:
                return self._err(f"{type(exc).__name__}: {exc}", 500)

        def _static(self, path: str):
            rel = "index.html" if path in ("/", "") else path.lstrip("/")
            if rel.startswith("api/"):
                return self._err("unknown api", 404)
            full = os.path.normpath(os.path.join(WEB_DIR, rel))
            if not full.startswith(WEB_DIR) or not os.path.isfile(full):
                return self._err("not found", 404)
            ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype in ("application/javascript", "application/json"):
                ctype += "; charset=utf-8"
            with open(full, "rb") as fh:
                body = fh.read()
            return self._send(200, body, ctype)

        # ---------- SSE ----------
        def _sse(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "keep-alive")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            deadline = time.time() + 300
            while time.time() < deadline:
                try:
                    payload = json.dumps(core.overview(), ensure_ascii=False, default=str)
                except Exception:
                    payload = json.dumps({"error": "overview failed"})
                try:
                    self.wfile.write(f"data: {payload}\n\n".encode())
                    self.wfile.flush()
                except Exception:
                    return
                time.sleep(2)

        # ---------- POST ----------
        def do_POST(self):
            parsed = urlparse(self.path)
            path = parsed.path
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b"{}"
                if length > 1_048_576:
                    return self._err("body too large", 413)
                try:
                    body = json.loads(raw.decode("utf-8") or "{}")
                except Exception:
                    body = {}
                # ---------- 认证（公开） ----------
                if path == "/api/auth/login":
                    user = str(body.get("user") or "").strip()
                    pw = str(body.get("password") or "")
                    res = core.auth.login(user, pw, ip=self._client_ip(),
                                          ua=str(self.headers.get("User-Agent") or ""))
                    if res.get("ok"):
                        return self._login_reply(res)
                    return self._json(res, 401)
                if path == "/api/auth/logout":
                    tok = self._token()
                    res = core.auth.logout(tok, ip=self._client_ip())
                    return self._json(res, 200, extra={"Set-Cookie":
                        "atfield_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"})
                if path == "/api/auth/passwd":
                    sess = self._guard("read")
                    if not sess:
                        return
                    res = core.auth.set_password(
                        str(body.get("user") or sess.get("user")), str(body.get("password") or ""),
                        actor=str(sess.get("user")), actor_role=str(sess.get("role")))
                    return self._json(res, 200 if res.get("ok") else 400)
                # ---------- 写操作鉴权 ----------
                cap = POST_CAP.get(path, "triage")
                sess = self._guard(cap, path)
                if not sess:
                    return
                if (self.headers.get("X-Requested-With") or "") != "atfield":
                    return self._err("缺少 X-Requested-With 头（CSRF 防护）", 403)
                if path == "/api/respond":
                    return self._respond(body, sess)
                if path.startswith("/api/firewall/"):
                    return self._firewall(path, body, sess)
                if path == "/api/selftest":
                    return self._json(core.self_test())
                # ---------- AI 研判层 ----------
                if path == "/api/ai/config":
                    _res = core.ai.update_config(body or {})
                    # 审计只记「改了哪些键」，绝不记值（值里可能是 key）
                    self._audit("ai.config", "ai", {"ok": _res.get("ok")}, sess,
                                detail={"keys": sorted(
                                    {k for k in (body or {}) if k != "api_key"}),
                                    "api_key_rotated": bool((body or {}).get("api_key"))})
                    return self._json(_res, 200 if _res.get("ok") else 400)
                if path == "/api/ai/test":
                    _res = core.ai.ping()
                    self._audit("ai.test", "ai", {"ok": _res.get("ok")}, sess,
                                detail={"kind": _res.get("kind", ""),
                                        "latency_ms": _res.get("latency_ms", 0)})
                    return self._json(_res, 200 if _res.get("ok") else 502)
                if path == "/api/ai/judge":
                    _fid = str(body.get("fid") or "").strip()
                    _finds = core.store.snapshot_findings(limit=500) or []
                    if _fid:
                        _one = next((f for f in _finds
                                     if str(f.get("fid")) == _fid), None)
                        if _one is None:
                            return self._err(f"未找到 fid={_fid}", 404)
                        _res = core.ai.judge(_one, force=bool(body.get("force")))
                    else:
                        _res = core.ai.judge_many(
                            _finds, limit=int(body.get("limit") or 3))
                    self._audit("ai.judge", _fid or "batch",
                                {"ok": _res.get("ok")}, sess,
                                detail={"fid": _fid,
                                        "judged": _res.get("judged", 1 if _fid else 0)})
                    return self._json(_res)
                if path == "/api/export":
                    _res = core.responder.export_evidence(core.store)
                    self._audit("evidence.export", "evidence", _res, sess)
                    return self._json(_res)
                # ---------- 检测与响应操作 ----------
                if path == "/api/intel/add":
                    _kind = str(body.get("kind") or "")
                    _val = str(body.get("value") or "")
                    _res = core.intel.add(
                        _kind, _val, source=str(body.get("source") or "manual"),
                        note=str(body.get("note") or ""),
                        confidence=str(body.get("confidence") or "medium"))
                    self._audit("intel.add", f"{_kind}:{_val}", _res, sess)
                    return self._json(_res)
                if path == "/api/intel/import":
                    _res = core.intel.import_text(
                        str(body.get("text") or ""), source=str(body.get("source") or "import"))
                    self._audit("intel.import", str(body.get("source") or "import"), _res, sess,
                                detail={k: _res.get(k) for k in ("added", "skipped") if isinstance(_res, dict)})
                    return self._json(_res)
                if path == "/api/intel/remove":
                    _kind = str(body.get("kind") or "")
                    _val = str(body.get("value") or "")
                    _res = core.intel.remove(_kind, _val)
                    self._audit("intel.remove", f"{_kind}:{_val}", _res, sess)
                    return self._json(_res)
                if path == "/api/ueba/reset":
                    _res = core.ueba.reset()
                    self._audit("ueba.reset", "baseline", _res, sess)
                    return self._json(_res)
                if path == "/api/canary/deploy":
                    _res = core.canary.deploy(int(body.get("count") or 0))
                    self._audit("canary.deploy", str(body.get("count") or 0), _res, sess)
                    return self._json(_res)
                if path == "/api/canary/undeploy":
                    _res = core.canary.undeploy()
                    self._audit("canary.undeploy", "canary", _res, sess)
                    return self._json(_res)
                if path == "/api/playbooks/reload":
                    _res = core.playbooks.reload()
                    self._audit("playbooks.reload", "playbooks", _res, sess)
                    return self._json(_res)
                if path == "/api/playbook/confirm":
                    _rid = str(body.get("run_id") or "")
                    _res = core.playbooks.confirm(_rid)
                    self._audit("playbook.confirm", _rid, _res, sess)
                    return self._json(_res)
                if path == "/api/playbook/reject":
                    _rid = str(body.get("run_id") or "")
                    _res = core.playbooks.reject(_rid)
                    self._audit("playbook.reject", _rid, _res, sess)
                    return self._json(_res)
                if path == "/api/inventory/scan":
                    _res = core.inventory.scan_async()
                    self._audit("inventory.scan", "assets", _res, sess)
                    return self._json(_res)
                if path == "/api/inventory/cve":
                    _res = core.inventory.import_cve(str(body.get("text") or ""))
                    self._audit("inventory.cve_import", "cve", _res, sess)
                    return self._json(_res)
                if path == "/api/compliance/rebuild":
                    base = core.store.get_state("baseline") or {}
                    core.compliance_state = compliance.build(base, core.store)
                    self._audit("compliance.rebuild", "matrix", {"ok": True}, sess)
                    return self._json(core.compliance_state)
                if path == "/api/ticket/new":
                    _res = core.store.create_ticket(
                        title=str(body.get("title") or "手工工单"),
                        severity=str(body.get("severity") or "medium"),
                        ref=str(body.get("ref") or ""),
                        detail=str(body.get("detail") or ""),
                        source="manual")
                    self._audit("ticket.new", str(body.get("title") or "手工工单"), _res, sess)
                    return self._json(_res)
                if path == "/api/ticket/update":
                    _res = core.store.update_ticket(
                        str(body.get("tid") or ""), status=str(body.get("status") or ""),
                        note=str(body.get("note") or ""), owner=str(body.get("owner") or ""))
                    self._audit("ticket.update", str(body.get("tid") or ""), _res, sess,
                                detail={"status": body.get("status"), "owner": body.get("owner")})
                    return self._json(_res)
                if path == "/api/suppress/add":
                    _flds = body.get("fields")
                    _res = core.engine.add_suppress(
                        str(body.get("rule_id") or ""), str(body.get("contains") or ""),
                        str(body.get("note") or ""),
                        fields=_flds if isinstance(_flds, dict) else None,
                        actor=str(body.get("actor") or ""),
                        expires_in=(float(body.get("expires_in")) if body.get("expires_in") else None),
                        review_days=(float(body.get("review_days")) if body.get("review_days") else None))
                    self._audit("suppress.add", str(body.get("rule_id") or ""), _res, sess,
                                detail={"contains": body.get("contains")})
                    return self._json(_res)
                if path == "/api/suppress/remove":
                    try:
                        _idx = int(body.get("index"))
                    except Exception:
                        _idx = -1
                    _res = core.engine.remove_suppress(_idx)
                    self._audit("suppress.remove", str(_idx), _res, sess)
                    return self._json(_res)
                if path == "/api/rules/reload":
                    _res = core.reload_rules(actor=str(sess.get("user")), role=str(sess.get("role")))
                    return self._json(_res, 200 if _res.get("ok") else 400)
                if path == "/api/audit/verify":
                    _res = core.audit.verify()
                    self._audit("audit.verify", "audit-chain", _res, sess,
                                detail={"issues": _res.get("issue_count", 0),
                                        "head": _res.get("head", "")})
                    return self._json(_res)
                # ---------- 更新通道 ----------
                if path == "/api/updates/apply":
                    _dir = str(body.get("dir") or "")
                    _res = core.updates.apply(_dir, actor=str(sess.get("user")),
                                              role=str(sess.get("role")),
                                              force=bool(body.get("force")))
                    return self._json(_res, 200 if _res.get("ok") else 400)
                if path == "/api/updates/rollback":
                    _res = core.updates.rollback(actor=str(sess.get("user")),
                                                 role=str(sess.get("role")),
                                                 reason=str(body.get("reason") or "手工回滚"))
                    return self._json(_res, 200 if _res.get("ok") else 400)
                if path == "/api/updates/reset":
                    _res = core.updates.reset_breaker(actor=str(sess.get("user")),
                                                      role=str(sess.get("role")))
                    return self._json(_res)
                if path == "/api/updates/export":
                    _res = core.updates.export_baseline(str(body.get("dest") or ""),
                                                        version=str(body.get("version") or "") or None)
                    return self._json(_res, 200 if _res.get("ok") else 400)
                # ---------- 账号与报告 ----------
                if path == "/api/users/add":
                    _res = core.auth.add_user(str(body.get("user") or ""),
                                              str(body.get("password") or ""),
                                              role=str(body.get("role") or "viewer"),
                                              actor=str(sess.get("user")),
                                              actor_role=str(sess.get("role")))
                    return self._json(_res, 200 if _res.get("ok") else 400)
                if path == "/api/users/passwd":
                    _res = core.auth.set_password(str(body.get("user") or ""),
                                                  str(body.get("password") or ""),
                                                  actor=str(sess.get("user")),
                                                  actor_role=str(sess.get("role")))
                    return self._json(_res, 200 if _res.get("ok") else 400)
                if path == "/api/users/role":
                    _res = core.auth.set_role(str(body.get("user") or ""),
                                              str(body.get("role") or ""),
                                              actor=str(sess.get("user")),
                                              actor_role=str(sess.get("role")))
                    return self._json(_res, 200 if _res.get("ok") else 400)
                if path == "/api/users/delete":
                    _res = core.auth.delete_user(str(body.get("user") or ""),
                                                 actor=str(sess.get("user")),
                                                 actor_role=str(sess.get("role")))
                    return self._json(_res, 200 if _res.get("ok") else 400)
                if path == "/api/monthly":
                    _send = bool(body.get("send"))
                    if _send and not core.auth.can(str(sess.get("role")), "admin"):
                        return self._json({"ok": False, "error": "仅管理员可触发邮件投递"}, 403)
                    _res = core.monthly(str(body.get("month") or ""), send=_send,
                                        actor=str(sess.get("user")), role=str(sess.get("role")))
                    return self._json(_res, 200 if _res.get("ok") else 400)
                return self._err("unknown api", 404)
            except BrokenPipeError:
                return
            except Exception as exc:
                return self._err(f"{type(exc).__name__}: {exc}", 500)

        def _login_reply(self, res: Dict[str, Any]):
            tok = str(res.get("token") or "")
            ttl = int(getattr(core.auth, "session_ttl", 28800) or 28800)
            cookie = (f"atfield_session={tok}; Path=/; HttpOnly; SameSite=Strict; Max-Age={ttl}")
            role = str(res.get("role") or "viewer")
            self._json({"ok": True, "user": res.get("user"), "role": role,
                        "role_cn": res.get("role_cn", ""),
                        "caps": sorted(core.auth.caps(role)),
                        "must_change": bool(res.get("must_change")),
                        "expires_at": round(time.time() + ttl, 0),
                        "token": tok}, 200, extra={"Set-Cookie": cookie})

        def _respond(self, body: Dict[str, Any], sess: Optional[Dict] = None):
            action = str(body.get("action") or "")
            try:
                pid = int(body.get("pid") or 0)
            except Exception:
                pid = 0
            resp = core.responder
            res: Dict[str, Any]
            if action == "terminate":
                res = resp.terminate(pid, force=bool(body.get("force")))
                self._audit("respond.terminate", str(pid), res, sess)
            elif action == "suspend":
                res = resp.suspend(pid)
                self._audit("respond.suspend", str(pid), res, sess)
            elif action == "resume":
                res = resp.resume(pid)
                self._audit("respond.resume", str(pid), res, sess)
            elif action == "block":
                ip = str(body.get("ip") or "")
                res = resp.block_commands(ip)
                self._audit("respond.block", ip, res, sess)
            elif action == "export":
                res = resp.export_evidence(core.store)
                self._audit("respond.export", "evidence", res, sess)
            else:
                return self._err(f"未知动作: {action}")

        def _firewall(self, path: str, body: Dict[str, Any],
                      sess: Optional[Dict] = None):
            """防火墙动作。每个动作都进审计链——拦截是能影响业务的动作。"""
            fw = core.firewall
            act = path.rsplit("/", 1)[-1]
            res: Dict[str, Any]
            if act == "block":
                ip = str(body.get("ip") or "").strip()
                res = fw.block(ip, str(body.get("reason") or ""))
                self._audit("firewall.block", ip, res, sess)
            elif act == "unblock":
                ip = str(body.get("ip") or "").strip()
                res = fw.unblock(ip)
                self._audit("firewall.unblock", ip, res, sess)
            elif act == "flush":
                res = fw.flush()
                self._audit("firewall.flush", "all", res, sess)
            elif act == "attach":
                res = fw.attach()
                self._audit("firewall.attach", "pf.conf", res, sess)
            elif act == "detach":
                res = fw.detach()
                self._audit("firewall.detach", "pf.conf", res, sess)
            else:
                return self._err(f"未知防火墙动作: {act}", 404)
            code = 200 if (not isinstance(res, dict) or res.get("ok", True)) else 400
            if isinstance(res, dict) and res.get("skipped"):
                code = 409          # 未启用不是错误，是状态不对
            return self._json(res, code)

    return Handler
