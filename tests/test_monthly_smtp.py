#!/usr/bin/env python3
"""月报 SMTP 投递链路回归测试（真实 SMTP 会话，不是 mock 掉 smtplib）。

用 tests/mock_smtp.py 起只收不转发的本地假 SMTP（端口 0 自动分配，绝不碰
运行中的实例与真实邮件系统），让 monthly.deliver() 走完整 ESMTP 会话：
EHLO → (STARTTLS) → (AUTH) → MAIL FROM → RCPT TO → DATA → QUIT，
再对收到的 .eml 做 MIME 级断言（主题/发件人/收件人/正文/HTML 附件）。

覆盖的坑（2026-11 实测修复）：
  1. 旧版 starttls 缺省 True，对不支持 STARTTLS 的明文中继必然失败
     （SMTPNotSupportedError）→ 现改为缺省按服务器能力机会性升级。
  2. 显式 starttls: true 时失败必须报错，不允许静默降级明文。
  3. README 写的 from/to 键旧代码不认（只认 sender/recipients）。

运行：python3 tests/test_monthly_smtp.py
依赖：纯标准库 + 项目自身依赖；STARTTLS 用例需要系统有 openssl（没有则跳过）。
"""
from __future__ import annotations

import email
import email.policy
import email.utils
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from atfield import config as config_mod          # noqa: E402
from atfield import monthly                       # noqa: E402
from atfield.core import Core                     # noqa: E402
import mock_smtp                                  # noqa: E402

MONTH = time.strftime("%Y-%m")
PASS = 0
FAIL = 0
SKIP = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}  {detail}")


def skip(name: str, why: str) -> None:
    global SKIP
    SKIP += 1
    print(f"  skip {name}  ({why})")


def new_core(tmp: str, smtp_cfg=None) -> Core:
    # 显式指向不存在的配置文件 → 纯默认值，避免读到真实 ~/.atfield 配置
    cfg = config_mod.load(os.path.join(tmp, "no-such-config.yaml"))
    cfg["data_dir"] = os.path.join(tmp, "data")
    cfg["host_label"] = "smtp-test"
    cfg["monthly"] = {"smtp": smtp_cfg} if smtp_cfg is not None else {}
    return Core(cfg)


def smtp_cfg_for(srv: mock_smtp.MockSMTPServer, **extra) -> dict:
    base = {"host": "127.0.0.1", "port": srv.port,
            "sender": "atfield-report@example.com",
            "recipients": ["soc@example.com", "boss@example.com"]}
    base.update(extra)
    return base


def parse_eml(path: str):
    with open(path, "rb") as fh:
        return email.message_from_bytes(fh.read(), policy=email.policy.default)


def assert_message(test_name: str, core: Core, res: dict,
                   srv: mock_smtp.MockSMTPServer,
                   expect_sender: str, expect_rcpts: list) -> None:
    """对真实收到的信做 MIME 级断言。"""
    msgs = srv.wait_messages(1, timeout=15)
    check(f"{test_name}: 服务器收到 1 封信", len(msgs) == 1, f"got {len(msgs)}")
    if not msgs:
        return
    env = msgs[0]
    check(f"{test_name}: MAIL FROM 正确", env["mail_from"] == expect_sender,
          str(env["mail_from"]))
    check(f"{test_name}: RCPT TO 完整", env["rcpt_tos"] == expect_rcpts,
          str(env["rcpt_tos"]))
    msg = parse_eml(env["eml"])
    want_subj = f"心之壁 终端安全月报 · {MONTH} · smtp-test"
    check(f"{test_name}: Subject 正确", str(msg["Subject"]) == want_subj,
          str(msg["Subject"]))
    check(f"{test_name}: From 地址正确",
          email.utils.parseaddr(str(msg["From"]))[1] == expect_sender,
          str(msg["From"]))
    check(f"{test_name}: To 头完整",
          [a for _, a in email.utils.getaddresses([str(msg["To"])])] == expect_rcpts,
          str(msg["To"]))
    check(f"{test_name}: 顶层 multipart/mixed",
          msg.get_content_type() == "multipart/mixed", msg.get_content_type())
    plain = msg.get_body(preferencelist=("plain",))
    html = msg.get_body(preferencelist=("html",))
    check(f"{test_name}: 纯文本正文存在且含月报标题",
          plain is not None and "# 终端安全月度报告" in plain.get_content()
          and MONTH in plain.get_content())
    check(f"{test_name}: HTML 备选正文存在",
          html is not None and "<!doctype html" in html.get_content().lower()
          and MONTH in html.get_content())
    atts = [p for p in msg.walk()
            if p.get_content_disposition() == "attachment"]
    check(f"{test_name}: 恰好 1 个附件", len(atts) == 1, f"got {len(atts)}")
    if atts:
        att = atts[0]
        want_fn = f"心之壁-月报-{MONTH}.html"
        check(f"{test_name}: 附件文件名（中文）正确", att.get_filename() == want_fn,
              str(att.get_filename()))
        disk_html = res["paths"]["html"]
        with open(disk_html, "rb") as fh:
            want_bytes = fh.read()
        check(f"{test_name}: 附件内容 == 落盘 HTML（逐字节）",
              att.get_payload(decode=True) == want_bytes)
    for key in ("md", "html", "json"):
        check(f"{test_name}: {key} 已落盘", os.path.isfile(res["paths"][key]))


def make_cert(tmp: str):
    cert = os.path.join(tmp, "cert.pem")
    key = os.path.join(tmp, "key.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048",
         "-keyout", key, "-out", cert, "-days", "2", "-nodes",
         "-subj", "/CN=localhost",
         "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
        check=True, capture_output=True)
    return cert, key


def tls_server_ctx(cert: str, key: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    return ctx


# ---------------------------------------------------------------- 用例

def t01_plain_relay_default_starttls():
    """头条回归：不支持 STARTTLS 的明文中继 + 缺省配置 → 必须投递成功。"""
    tmp = tempfile.mkdtemp(prefix="atfield-smtp-t01-")
    srv = mock_smtp.MockSMTPServer(os.path.join(tmp, "inbox"), verbose=False).start()
    core = new_core(tmp, smtp_cfg_for(srv))
    try:
        seeded = core.self_test()          # 灌合成事件，让月报有真实内容
        check("t01: 自检产生了告警", len(seeded["findings"]) >= 1,
              str(seeded.get("findings")))
        res = monthly.build(core, month=MONTH, send=True)
        check("t01: sent=True", res["delivery"].get("sent") is True,
              str(res["delivery"]))
        check("t01: 月报统计到告警", res["counts"]["findings"] >= 1,
              str(res["counts"]))
        assert_message("t01", core, res, srv, "atfield-report@example.com",
                       ["soc@example.com", "boss@example.com"])
        check("t01: 会话未升级 TLS（服务器没广告）",
              srv.messages and srv.messages[0]["tls"] is False)
    finally:
        core.stop()
        srv.stop()
        shutil.rmtree(tmp, ignore_errors=True)


def t02_starttls_explicit_false():
    tmp = tempfile.mkdtemp(prefix="atfield-smtp-t02-")
    srv = mock_smtp.MockSMTPServer(os.path.join(tmp, "inbox"), verbose=False).start()
    core = new_core(tmp, smtp_cfg_for(srv, starttls=False))
    try:
        res = monthly.build(core, month=MONTH, send=True)
        check("t02: 显式 starttls=false 投递成功", res["delivery"].get("sent") is True,
              str(res["delivery"]))
        check("t02: 明文会话", srv.messages and srv.messages[0]["tls"] is False)
    finally:
        core.stop(); srv.stop(); shutil.rmtree(tmp, ignore_errors=True)


def t03_starttls_required_but_unsupported():
    """显式 true 而服务器不支持 → 必须失败，绝不静默降级明文。"""
    tmp = tempfile.mkdtemp(prefix="atfield-smtp-t03-")
    srv = mock_smtp.MockSMTPServer(os.path.join(tmp, "inbox"), verbose=False).start()
    core = new_core(tmp, smtp_cfg_for(srv, starttls=True))
    try:
        res = monthly.build(core, month=MONTH, send=True)
        d = res["delivery"]
        check("t03: sent=False", d.get("sent") is False, str(d))
        check("t03: 原因点名 STARTTLS", "STARTTLS" in str(d.get("reason")),
              str(d.get("reason")))
        check("t03: 原因含服务器地址", "127.0.0.1:" in str(d.get("reason")),
              str(d.get("reason")))
        check("t03: 服务器没收到信", len(srv.messages) == 0)
        check("t03: 报告仍落盘", os.path.isfile(res["paths"]["html"]))
    finally:
        core.stop(); srv.stop(); shutil.rmtree(tmp, ignore_errors=True)


def t04_starttls_upgrade():
    """服务器支持 STARTTLS：缺省自动升级 + 显式 true 强制升级，都要成功。"""
    if not shutil.which("openssl"):
        skip("t04", "无 openssl，无法生成测试证书")
        return
    tmp = tempfile.mkdtemp(prefix="atfield-smtp-t04-")
    cert, key = make_cert(tmp)
    old_env = os.environ.get("SSL_CERT_FILE")
    os.environ["SSL_CERT_FILE"] = cert     # 客户端 create_default_context 会读它
    try:
        for label, extra in (("缺省机会性升级", {}), ("显式 true", {"starttls": True})):
            srv = mock_smtp.MockSMTPServer(
                os.path.join(tmp, f"inbox-{label}"),
                tls_context=tls_server_ctx(cert, key), verbose=False).start()
            cfg = smtp_cfg_for(srv, **extra)
            cfg["host"] = "localhost"      # 证书 SAN 是 localhost
            core = new_core(tmp, cfg)
            try:
                res = monthly.build(core, month=MONTH, send=True)
                check(f"t04[{label}]: sent=True", res["delivery"].get("sent") is True,
                      str(res["delivery"]))
                msgs = srv.wait_messages(1, timeout=15)
                check(f"t04[{label}]: 会话确实走了 TLS",
                      bool(msgs) and msgs[0]["tls"] is True, str(msgs))
            finally:
                core.stop(); srv.stop()
    finally:
        if old_env is None:
            os.environ.pop("SSL_CERT_FILE", None)
        else:
            os.environ["SSL_CERT_FILE"] = old_env
        shutil.rmtree(tmp, ignore_errors=True)


def t05_auth_plain():
    tmp = tempfile.mkdtemp(prefix="atfield-smtp-t05-")
    srv = mock_smtp.MockSMTPServer(os.path.join(tmp, "inbox"),
                                   require_auth=True,
                                   users={"reporter": "s3cret-pw"},
                                   verbose=False).start()
    core = new_core(tmp, smtp_cfg_for(srv, user="reporter", password="s3cret-pw"))
    try:
        res = monthly.build(core, month=MONTH, send=True)
        check("t05: AUTH PLAIN 投递成功", res["delivery"].get("sent") is True,
              str(res["delivery"]))
        msgs = srv.wait_messages(1, timeout=15)
        check("t05: 服务器记录了正确账号", bool(msgs)
              and msgs[0]["auth_user"] == "reporter" and msgs[0]["auth_ok"] is True,
              str(msgs))
        check("t05: 机制为 PLAIN", bool(msgs) and msgs[0].get("auth_mech") == "PLAIN",
              str(msgs))
    finally:
        core.stop(); srv.stop(); shutil.rmtree(tmp, ignore_errors=True)


def t06_auth_login_only():
    tmp = tempfile.mkdtemp(prefix="atfield-smtp-t06-")
    srv = mock_smtp.MockSMTPServer(os.path.join(tmp, "inbox"),
                                   require_auth=True,
                                   users={"reporter": "s3cret-pw"},
                                   auth_mechs=["LOGIN"], verbose=False).start()
    core = new_core(tmp, smtp_cfg_for(srv, user="reporter", password="s3cret-pw"))
    try:
        res = monthly.build(core, month=MONTH, send=True)
        check("t06: 仅 AUTH LOGIN 的服务器也能投递", res["delivery"].get("sent") is True,
              str(res["delivery"]))
        msgs = srv.wait_messages(1, timeout=15)
        check("t06: 机制为 LOGIN", bool(msgs) and msgs[0].get("auth_mech") == "LOGIN",
              str(msgs))
    finally:
        core.stop(); srv.stop(); shutil.rmtree(tmp, ignore_errors=True)


def t07_auth_bad_password():
    tmp = tempfile.mkdtemp(prefix="atfield-smtp-t07-")
    srv = mock_smtp.MockSMTPServer(os.path.join(tmp, "inbox"),
                                   require_auth=True,
                                   users={"reporter": "right-pw"},
                                   verbose=False).start()
    core = new_core(tmp, smtp_cfg_for(srv, user="reporter", password="wrong-pw"))
    try:
        res = monthly.build(core, month=MONTH, send=True)
        d = res["delivery"]
        check("t07: 口令错误 → sent=False", d.get("sent") is False, str(d))
        check("t07: 原因含认证失败信息",
              "535" in str(d.get("reason")) or "Authentication" in str(d.get("reason")),
              str(d.get("reason")))
        check("t07: 服务器没收到信", len(srv.messages) == 0)
    finally:
        core.stop(); srv.stop(); shutil.rmtree(tmp, ignore_errors=True)


def t08_no_smtp_config():
    tmp = tempfile.mkdtemp(prefix="atfield-smtp-t08-")
    core = new_core(tmp, smtp_cfg=None)
    try:
        res = monthly.build(core, month=MONTH, send=True)
        d = res["delivery"]
        check("t08: 未配置 → sent=False", d.get("sent") is False, str(d))
        check("t08: 原因说明未配置", "未配置" in str(d.get("reason")), str(d.get("reason")))
        check("t08: 报告仍落盘", os.path.isfile(res["paths"]["html"]))
    finally:
        core.stop(); shutil.rmtree(tmp, ignore_errors=True)


def t09_send_false():
    tmp = tempfile.mkdtemp(prefix="atfield-smtp-t09-")
    core = new_core(tmp, smtp_cfg=None)
    try:
        res = monthly.build(core, month=MONTH, send=False)
        d = res["delivery"]
        check("t09: send=False → 仅落盘", d.get("sent") is False
              and "未要求投递" in str(d.get("reason")), str(d))
        check("t09: 三件产物齐全", all(os.path.isfile(res["paths"][k])
                                      for k in ("md", "html", "json")))
    finally:
        core.stop(); shutil.rmtree(tmp, ignore_errors=True)


def t10_server_down():
    tmp = tempfile.mkdtemp(prefix="atfield-smtp-t10-")
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    dead_port = s.getsockname()[1]
    s.close()                              # 这个端口现在没人监听
    core = new_core(tmp, {"host": "127.0.0.1", "port": dead_port,
                          "sender": "a@example.com", "recipients": ["b@example.com"],
                          "starttls": False})
    try:
        res = monthly.build(core, month=MONTH, send=True)
        d = res["delivery"]
        check("t10: 服务器不在 → sent=False 且不抛异常", d.get("sent") is False, str(d))
        check("t10: 原因含发送失败与地址", "发送失败" in str(d.get("reason"))
              and str(dead_port) in str(d.get("reason")), str(d.get("reason")))
        check("t10: 报告仍落盘", os.path.isfile(res["paths"]["html"]))
    finally:
        core.stop(); shutil.rmtree(tmp, ignore_errors=True)


def t11_readme_from_to_keys():
    """README 风格配置：from + 逗号分隔的 to 字符串。"""
    tmp = tempfile.mkdtemp(prefix="atfield-smtp-t11-")
    srv = mock_smtp.MockSMTPServer(os.path.join(tmp, "inbox"), verbose=False).start()
    core = new_core(tmp, {"host": "127.0.0.1", "port": srv.port,
                          "from": "README-style@example.com",
                          "to": "soc@example.com, boss@example.com"})
    try:
        res = monthly.build(core, month=MONTH, send=True)
        check("t11: from/to 键投递成功", res["delivery"].get("sent") is True,
              str(res["delivery"]))
        check("t11: recipients 拆成两个", res["delivery"].get("recipients")
              == ["soc@example.com", "boss@example.com"],
              str(res["delivery"].get("recipients")))
        assert_message("t11", core, res, srv, "README-style@example.com",
                       ["soc@example.com", "boss@example.com"])
    finally:
        core.stop(); srv.stop(); shutil.rmtree(tmp, ignore_errors=True)


def t12_audit_chain_records_delivery():
    tmp = tempfile.mkdtemp(prefix="atfield-smtp-t12-")
    srv = mock_smtp.MockSMTPServer(os.path.join(tmp, "inbox"), verbose=False).start()
    core = new_core(tmp, smtp_cfg_for(srv))
    try:
        res = core.monthly(MONTH, send=True, actor="tester", role="admin")
        check("t12: core.monthly ok", res.get("ok") is True
              and res["delivery"].get("sent") is True, str(res.get("delivery")))
        v = core.audit.verify()
        check("t12: 审计链校验通过", v.get("ok") is True, str(v))
        recs = core.audit.tail(limit=50, action="monthly.report")
        check("t12: 有 monthly.report 审计记录", len(recs) >= 1, str(len(recs)))
        check("t12: 审计记录了投递成功",
              any((r.get("detail") or {}).get("投递") is True for r in recs),
              str(recs))
    finally:
        core.stop(); srv.stop(); shutil.rmtree(tmp, ignore_errors=True)


def t13_cross_process_monthly():
    """cron/CLI 场景：进程 A 产生告警后退出，进程 B 的月报必须看得到并投递。"""
    tmp = tempfile.mkdtemp(prefix="atfield-smtp-t13-")
    data_dir = os.path.join(tmp, "data")
    cfg_a = config_mod.load(os.path.join(tmp, "no-such-config.yaml"))
    cfg_a["data_dir"] = data_dir
    core_a = Core(cfg_a)
    try:
        seeded = core_a.self_test()
        check("t13: 进程A产生告警与攻击链",
              len(seeded["findings"]) >= 1 and len(seeded["incidents"]) >= 1,
              f"f={len(seeded['findings'])} i={len(seeded['incidents'])}")
    finally:
        core_a.stop()
    srv = mock_smtp.MockSMTPServer(os.path.join(tmp, "inbox"), verbose=False).start()
    core_b = new_core(tmp, smtp_cfg_for(srv))   # 同一 data_dir 的全新进程态
    try:
        res = monthly.build(core_b, month=MONTH, send=True)
        check("t13: 进程B月报统计到历史告警", res["counts"]["findings"] >= 1,
              str(res["counts"]))
        check("t13: 进程B月报统计到历史攻击链", res["counts"]["incidents"] >= 1,
              str(res["counts"]))
        check("t13: sent=True", res["delivery"].get("sent") is True,
              str(res["delivery"]))
        msgs = srv.wait_messages(1, timeout=15)
        if msgs:
            body = parse_eml(msgs[0]["eml"]).get_body(
                preferencelist=("plain",)).get_content()
            check("t13: 收到的邮件正文含告警统计（非空壳）",
                  f"| 告警（规则命中） | {res['counts']['findings']} |" in body,
                  body[:200])
    finally:
        core_b.stop(); srv.stop(); shutil.rmtree(tmp, ignore_errors=True)


def t14_tickets_actions_persistence():
    tmp = tempfile.mkdtemp(prefix="atfield-smtp-t14-")
    cfg_a = config_mod.load(os.path.join(tmp, "no-such-config.yaml"))
    cfg_a["data_dir"] = os.path.join(tmp, "data")
    core_a = Core(cfg_a)
    try:
        tk = core_a.store.create_ticket("测试工单", severity="high")
        core_a.store.update_ticket(tk["tid"], status="closed", note="已处置")
        core_a.store.log_action("tester", "kill_process", "pid:123", "ok")
    finally:
        core_a.stop()
    core_b = new_core(tmp, smtp_cfg=None)
    try:
        tks = core_b.store.snapshot_tickets()
        check("t14: 工单跨进程存活", len(tks) == 1 and tks[0]["tid"] == tk["tid"],
              str(tks))
        check("t14: 工单状态保留 closed", bool(tks) and tks[0]["status"] == "closed",
              str(tks))
        check("t14: 处置动作跨进程存活",
              len(core_b.store.meta.get("actions") or []) == 1,
              str(core_b.store.meta.get("actions")))
        tk2 = core_b.store.create_ticket("重启后的新工单")
        check("t14: 工单编号不撞号", tk2["tid"] != tk["tid"],
              f"{tk['tid']} vs {tk2['tid']}")
        res = monthly.build(core_b, month=MONTH, send=False)
        check("t14: 月报统计到工单与处置", res["counts"]["tickets"] >= 1
              and res["counts"]["actions"] >= 1, str(res["counts"]))
    finally:
        core_b.stop(); shutil.rmtree(tmp, ignore_errors=True)


def t15_incident_dedupe_and_reload():
    tmp = tempfile.mkdtemp(prefix="atfield-smtp-t15-")
    cfg_a = config_mod.load(os.path.join(tmp, "no-such-config.yaml"))
    cfg_a["data_dir"] = os.path.join(tmp, "data")
    core_a = Core(cfg_a)
    try:
        core_a.store.add_incident({"iid": "abc123", "title": "链v1", "score": 1.0,
                                   "last_seen": time.time()})
        core_a.store.add_incident({"iid": "abc123", "title": "链v2", "score": 9.0,
                                   "last_seen": time.time()})
        snap = core_a.store.snapshot_incidents()
        check("t15: 同 iid 内存去重", len(snap) == 1 and snap[0]["title"] == "链v2",
              str(snap))
    finally:
        core_a.stop()
    core_b = new_core(tmp, smtp_cfg=None)
    try:
        snap = core_b.store.snapshot_incidents()
        check("t15: 重启加载按 iid 去重且保留最新",
              len(snap) == 1 and snap[0]["title"] == "链v2"
              and snap[0]["score"] == 9.0, str(snap))
    finally:
        core_b.stop(); shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("t") and callable(v)
             and k[1:3].isdigit()]
    print(f"月报 SMTP 投递回归 · {MONTH} · python {sys.version.split()[0]}")
    for fn in tests:
        print(f"\n[{fn.__name__}] {fn.__doc__.splitlines()[0] if fn.__doc__ else ''}")
        fn()
    print(f"\n结果：{PASS} 通过 / {FAIL} 失败 / {SKIP} 跳过")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
