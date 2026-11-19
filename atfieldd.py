#!/usr/bin/env python3
"""心之壁 CLI / 守护进程入口。

用法：
  python3 atfieldd.py                     启动控制台（默认 127.0.0.1:8866）
  python3 atfieldd.py --once              跑一轮采集并打印态势摘要
  python3 atfieldd.py --report a.md       导出 Markdown 态势报告
  python3 atfieldd.py --selftest          用合成事件验证检测与关联链路
  sudo python3 atfieldd.py                以 root 运行，启用 EndpointSecurity 增强遥测
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import signal
import sys
import time
import webbrowser

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from atfield import __product__, __version__, config  # noqa: E402
from atfield.core import Core  # noqa: E402
from atfield import report as report_mod  # noqa: E402
from atfield.server import AtFieldServer  # noqa: E402


def _print_banner(core: Core, url: str) -> None:
    ov = core.overview()
    root = "（root，EndpointSecurity 增强已启用）" if os.geteuid() == 0 else "（普通用户，非特权采集）"
    print("")
    print(f"  {__product__}  v{__version__}   终端作战态势感知平台")
    print(f"  主机 {ov['host']} / 用户 {ov['user']} / {ov['platform']}  {root}")
    print(f"  控制台  {url}")
    print(f"  健康度  {ov['health']['health']}（{ov['health']['grade']}）   风险指数 {ov['threat']['risk']}（{ov['threat']['level']}）")
    active = [c["name"] for c in ov["collectors"] if c["enabled"]]
    idle = [c["name"] for c in ov["collectors"] if not c["enabled"]]
    print(f"  采集器  {len(active)} 个运行: {', '.join(active)}")
    if idle:
        print(f"          未启用: {', '.join(idle)}")
    print("  按 Ctrl+C 退出")
    print("")


def _ask_pw(twice: bool = True) -> str:
    pw = getpass.getpass("新口令: ")
    if twice:
        again = getpass.getpass("再输一次: ")
        if pw != again:
            print("两次输入不一致，已取消")
            return ""
    return pw


def cmd_build_bundle(core: Core, dest: str, version: str) -> int:
    """把 data_dir 下的 rules/ 与 playbooks/ 打成带签名的更新包。"""
    upd = core.updates
    base = upd.data_dir          # 受管目录在 data_dir 下（rules/ 与 playbooks/）
    dest = os.path.abspath(dest)
    os.makedirs(dest, exist_ok=True)
    files = []
    for sub in ("rules", "playbooks"):
        src_dir = os.path.join(base, sub)
        if not os.path.isdir(src_dir):
            continue
        for name in sorted(os.listdir(src_dir)):
            if not name.endswith((".yaml", ".yml")):
                continue
            src = os.path.join(src_dir, name)
            if not os.path.isfile(src):
                continue
            rel = f"{sub}/{name}"
            out = os.path.join(dest, rel)
            os.makedirs(os.path.dirname(out), exist_ok=True)
            with open(src, "rb") as fr, open(out, "wb") as fw:
                data = fr.read()
                fw.write(data)
            files.append({"path": rel, "size": len(data),
                          "sha256": hashlib.sha256(data).hexdigest()})
    if not files:
        print(f"没有可打包的文件（{base}/rules 与 {base}/playbooks 都是空的）")
        return 1
    manifest = {
        "schema": 1,
        "version": version or (__version__ + "-bundle." + time.strftime("%Y%m%d%H%M%S")),
        "channel": upd.channel,
        "min_version": __version__,
        "released_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "notes": "规则与剧本基线",
        "files": files,
    }
    manifest["sig"] = upd.sign(manifest)
    with open(os.path.join(dest, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=2)
    print(f"更新包已生成: {dest}")
    print(f"  版本 {manifest['version']} / 通道 {manifest['channel']} / 文件 {len(files)} 个")
    print(f"  签名 {manifest['sig'][:16]}…（密钥指纹 {upd.key_fingerprint()}）")
    return 0


def cmd_once(core: Core, out: str | None) -> int:
    print("[心之壁] 单轮采集开始…")
    # 流式采集器需要时间建立连接，给它几秒
    for c in core.collectors:
        if c.enabled and getattr(c, "mode", "poll") == "stream":
            try:
                c.start()
            except Exception:
                pass
    time.sleep(4)
    total = 0
    for c in core.collectors:
        if not c.enabled:
            continue
        evs = c.run_once()
        total += len(evs)
        if evs:
            core.process(evs)            # 走与常驻模式完全相同的检测/关联链路
        print(f"  - {c.name:<12} 事件 {len(evs):>4}    " +
              (f"错误: {(core.store.meta['collectors'].get(c.name) or {}).get('last_error','')[:80]}"
               if (core.store.meta['collectors'].get(c.name) or {}).get('errors') else "ok"))
    ov = core.overview()
    print("")
    print(f"  采集事件 {total} 条 / 累计 {ov['totals']['events']}")
    print(f"  健康度 {ov['health']['health']}  风险指数 {ov['threat']['risk']}  告警 {ov['totals']['findings']}  攻击链 {ov['totals']['incidents']}")
    print(f"  结论: {ov['verdict']}")
    md = report_mod.build(core)
    path = out or os.path.join(os.path.expanduser("~/.atfield"), "report-once.md")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(md)
    print(f"  报告已写入: {path}")
    core.stop()
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="atfieldd", description="心之壁 终端作战态势感知平台")
    ap.add_argument("--bind", default="", help="监听地址（默认 127.0.0.1）")
    ap.add_argument("--port", type=int, default=0, help="监听端口（默认 8866）")
    ap.add_argument("--host-label", default="", help="主机标签（覆盖系统 hostname）")
    ap.add_argument("--config", default="", help="配置文件路径（默认 ~/.atfield/config.yaml）")
    ap.add_argument("--once", action="store_true", help="只跑一轮采集并输出报告")
    ap.add_argument("--report", default="", help="导出 Markdown 报告到指定路径后退出")
    ap.add_argument("--selftest", action="store_true", help="用合成事件验证检测/关联链路")
    ap.add_argument("--no-browser", action="store_true", help="启动时不自动打开浏览器")
    ap.add_argument("--version", action="store_true")
    # ---- 治理与运维子命令 ----
    ap.add_argument("--governance", action="store_true", help="打印治理状态（账号/审计/更新/规则）")
    ap.add_argument("--users", action="store_true", help="列出账号与角色")
    ap.add_argument("--passwd", default="", metavar="USER", help="修改账号口令（交互输入）")
    ap.add_argument("--user-add", default="", metavar="USER", help="新增账号（交互输入口令）")
    ap.add_argument("--user-del", default="", metavar="USER", help="删除账号")
    ap.add_argument("--role", default="viewer",
                    choices=["admin", "responder", "analyst", "viewer"], help="配合 --user-add 的角色")
    ap.add_argument("--audit-verify", action="store_true", help="校验审计哈希链")
    ap.add_argument("--audit-tail", type=int, default=0, metavar="N", help="打印最近 N 条审计记录")
    ap.add_argument("--monthly", action="store_true", help="生成月度报告")
    ap.add_argument("--month", default="", help="月份 YYYY-MM（默认本月）")
    ap.add_argument("--send", action="store_true", help="月度报告生成后尝试邮件投递")
    ap.add_argument("--rules-reload", action="store_true", help="重载内置与外部规则包")
    ap.add_argument("--update-status", action="store_true", help="查看更新通道状态")
    ap.add_argument("--update-apply", default="", metavar="DIR", help="应用更新包目录")
    ap.add_argument("--update-rollback", action="store_true", help="回滚到最近可用版本")
    ap.add_argument("--update-export", default="", metavar="DIR", help="导出当前规则/剧本基线")
    ap.add_argument("--update-build", default="", metavar="DIR",
                    help="把本地 rules/ 与 playbooks/ 打成签名更新包")
    ap.add_argument("--bundle-version", default="", help="配合 --update-build 的版本号")
    args = ap.parse_args(argv)

    if args.version:
        print(f"{__product__} {__version__}")
        return 0

    cfg = config.load(args.config or None)
    # 排障用：确认这次进程究竟读了哪份配置、ai 段是什么。默认不打印。
    if os.environ.get("ATFIELD_DEBUG_CFG"):
        print("DEBUG config_path =", cfg.get("_config_path"), flush=True)
        print("DEBUG data_dir    =", cfg.get("data_dir"), flush=True)
        print("DEBUG yaml_mod    =", bool(getattr(config, "yaml", None)),
              "|", getattr(config, "_YAML_ERR", ""), flush=True)
        if not getattr(config, "yaml", None):
            import sys as _sys
            print("DEBUG exe         =", _sys.executable, flush=True)
            print("DEBUG sys.path    =", [x for x in _sys.path if x], flush=True)
        print("DEBUG load_error  =", cfg.get("_load_error", ""), flush=True)
        print("DEBUG ai          =", json.dumps(cfg.get("ai") or {}, ensure_ascii=False), flush=True)
    if args.bind:
        cfg["server"]["bind"] = args.bind
    if args.port:
        cfg["server"]["port"] = args.port
    if args.host_label:
        cfg["host_label"] = args.host_label

    core = Core(cfg)
    actor = os.environ.get("USER") or "cli"

    # ---------- 治理与运维子命令（无需启动采集引擎） ----------
    if args.governance:
        print(json.dumps(core.governance(), ensure_ascii=False, indent=2))
        core.stop()
        return 0

    if args.users:
        st = core.auth.status()
        print(f"账号 {st.get('users')} 个 / 管理员 {st.get('admins')} 个 / 在线会话 {st.get('sessions')} 个")
        for u in core.auth.list_users():
            flag = "（初始口令未改）" if u.get("must_change") else ""
            print(f"  - {u['user']:<16} {u.get('role_cn') or u['role']:<8} 最近登录 {u.get('last_login_cn') or '—'}{flag}")
        core.stop()
        return 0

    if args.user_add:
        pw = _ask_pw()
        if not pw:
            core.stop()
            return 1
        res = core.auth.add_user(args.user_add, pw, role=args.role, actor=actor, actor_role="admin")
        print(json.dumps(res, ensure_ascii=False))
        core.stop()
        return 0 if res.get("ok") else 1

    if args.passwd:
        pw = _ask_pw()
        if not pw:
            core.stop()
            return 1
        res = core.auth.set_password(args.passwd, pw, actor=actor, actor_role="admin")
        print(json.dumps(res, ensure_ascii=False))
        core.stop()
        return 0 if res.get("ok") else 1

    if args.user_del:
        res = core.auth.delete_user(args.user_del, actor=actor, actor_role="admin")
        print(json.dumps(res, ensure_ascii=False))
        core.stop()
        return 0 if res.get("ok") else 1

    if args.audit_verify:
        res = core.audit.verify()
        print(json.dumps(res, ensure_ascii=False, indent=2))
        core.stop()
        return 0 if res.get("ok") else 2

    if args.audit_tail:
        recs = core.audit.tail(int(args.audit_tail))
        for r in recs:
            ts = r.get("ts_cn") or time.strftime("%Y-%m-%d %H:%M:%S",
                                                 time.localtime(float(r.get("ts") or 0)))
            print(f"{ts}  {r.get('action'):<20} {r.get('actor'):<10} "
                  f"{r.get('result'):<6} {str(r.get('target') or '')[:50]}  {str(r.get('hash'))[:10]}")
        print(f"共 {len(recs)} 条 / 累计 {core.audit.stats().get('records')} 条")
        core.stop()
        return 0

    if args.rules_reload:
        res = core.reload_rules(actor=actor, role="admin")
        print(json.dumps(res, ensure_ascii=False, indent=2))
        core.stop()
        return 0 if res.get("ok") else 2

    if args.monthly:
        res = core.monthly(args.month, send=bool(args.send), actor=actor, role="admin")
        print(json.dumps(res, ensure_ascii=False, indent=2))
        core.stop()
        return 0 if res.get("ok") else 2

    if args.update_status:
        print(json.dumps(core.updates.status(), ensure_ascii=False, indent=2))
        core.stop()
        return 0

    if args.update_build:
        rc = cmd_build_bundle(core, args.update_build, args.bundle_version)
        core.stop()
        return rc

    if args.update_apply:
        res = core.updates.apply(args.update_apply, actor=actor, role="admin")
        print(json.dumps(res, ensure_ascii=False, indent=2))
        core.stop()
        return 0 if res.get("ok") else 2

    if args.update_rollback:
        res = core.updates.rollback(actor=actor, role="admin", reason="CLI 回滚")
        print(json.dumps(res, ensure_ascii=False, indent=2))
        core.stop()
        return 0 if res.get("ok") else 2

    if args.update_export:
        res = core.updates.export_baseline(args.update_export)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        core.stop()
        return 0 if res.get("ok", True) else 2

    if args.selftest:
        res = core.self_test()
        print(json.dumps(res, ensure_ascii=False, indent=2))
        core.stop()
        return 0

    if args.report:
        core.start()
        time.sleep(3)
        md = report_mod.build(core)
        with open(args.report, "w", encoding="utf-8") as fh:
            fh.write(md)
        print(f"报告已写入 {args.report}（{len(md)} 字节）")
        core.stop()
        return 0

    if args.once:
        return cmd_once(core, args.report or None)

    # 常驻模式
    bind = cfg["server"]["bind"]
    port = int(cfg["server"]["port"])
    core.start()
    srv = AtFieldServer(core, bind, port)
    url = f"http://{'127.0.0.1' if bind in ('0.0.0.0', '') else bind}:{port}/"
    _print_banner(core, url)

    stop = {"flag": False}

    def _on_sig(signum, frame):
        stop["flag"] = True
        print("\n  正在停止…")
        try:
            srv.shutdown()
        except Exception:
            pass
        core.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _on_sig)
    signal.signal(signal.SIGTERM, _on_sig)

    if cfg["server"].get("open_browser") and not args.no_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        core.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
