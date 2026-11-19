#!/usr/bin/env python3
"""治理层回归测试：审计链 / RBAC / 更新通道 / SSRF 无关的 HTTP 闸门。

不依赖 pytest，也不需要联网：
    python3 tests/test_governance.py            # 全部
    python3 tests/test_governance.py audit      # 只跑审计链
    python3 tests/test_governance.py auth       # 只跑账号与 RBAC
    python3 tests/test_governance.py update     # 只跑更新通道
    python3 tests/test_governance.py http       # 只跑 HTTP 鉴权闸门

每个用例都在临时目录里建独立的 data_dir，跑完自动清理，不碰 ~/.atfield。
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from atfield import config  # noqa: E402
from atfield.audit import AuditLog  # noqa: E402
from atfield.auth import Auth  # noqa: E402
from atfield.core import Core  # noqa: E402
from atfield.server import AtFieldServer  # noqa: E402
from atfield.updates import Updates  # noqa: E402

PASS = 0
FAIL = 0


def check(name: str, cond: bool, extra: str = "") -> bool:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} {extra}")
    return bool(cond)


def tmp_cfg(tmp: str) -> dict:
    cfg = config.load()
    cfg["data_dir"] = tmp
    os.makedirs(tmp, exist_ok=True)
    return cfg


# ---------------------------------------------------------------- 审计链
def test_audit() -> None:
    print("\n== 审计链：append-only + 篡改检测 ==")
    tmp = tempfile.mkdtemp(prefix="atfield-audit-")
    try:
        al = AuditLog(tmp_cfg(tmp))
        for i in range(6):
            al.append("test.action", actor="tester", role="admin",
                      target=f"t{i}", detail={"i": i})
        st = al.stats()
        check("记录数正确", st["records"] == 6, str(st["records"]))
        check("链头是 64 位哈希", len(st["head"]) == 64, st["head"][:12])
        v = al.verify()
        check("完好的链校验通过", v["ok"] and v["issue_count"] == 0,
              json.dumps(v.get("issues"), ensure_ascii=False)[:160])

        # 1) 改写一条记录的内容 → hash 不匹配
        path = al.path
        lines = open(path, encoding="utf-8").read().splitlines()
        rec = json.loads(lines[2])
        rec["target"] = "HACKED"
        lines[2] = json.dumps(rec, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
        v = al.verify()
        check("改写内容被发现", (not v["ok"]) and v["issue_count"] >= 1,
              json.dumps(v.get("issues"), ensure_ascii=False)[:200])

        # 2) 删除中间一条 → seq 跳号
        al2 = AuditLog(tmp_cfg(os.path.join(tmp, "b")))
        for i in range(5):
            al2.append("t", actor="x", target=str(i))
        lines = open(al2.path, encoding="utf-8").read().splitlines()
        open(al2.path, "w", encoding="utf-8").write("\n".join(lines[:1] + lines[3:]) + "\n")
        v2 = al2.verify()
        check("删除记录被发现", (not v2["ok"]) and v2["issue_count"] >= 1,
              json.dumps(v2.get("issues"), ensure_ascii=False)[:200])

        # 3) 截断尾部：锚点记录到第 6 条，砍到 5 条 → 锚点能发现少了一条
        al3 = AuditLog(tmp_cfg(os.path.join(tmp, "c")))
        al3.anchor_every = 3
        for i in range(8):
            al3.append("t", actor="x", target=str(i))
        anc = al3.anchor()
        check("锚点已写入", bool(anc.get("head")) and int(anc.get("seq") or 0) >= 6,
              json.dumps(anc, ensure_ascii=False)[:120])
        lines = open(al3.path, encoding="utf-8").read().splitlines()
        # 砍到锚点序号之前：锚点写的是第 6 条，文件只剩 4 条 → 少了两条
        open(al3.path, "w", encoding="utf-8").write("\n".join(lines[:4]) + "\n")
        v3 = al3.verify()
        check("尾部截断被发现", not v3["ok"],
              json.dumps(v3.get("issues"), ensure_ascii=False)[:220])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------- RBAC
def test_auth() -> None:
    print("\n== 账号与 RBAC ==")
    tmp = tempfile.mkdtemp(prefix="atfield-auth-")
    try:
        au = Auth(tmp_cfg(tmp))
        st = au.status()
        check("首启有管理员", st["users"] >= 1 and st["admins"] == 1, json.dumps(st)[:120])
        check("首启口令文件已生成",
              os.path.isfile(os.path.join(tmp, "INITIAL-ADMIN.txt")))
        mode = oct(os.stat(os.path.join(tmp, "users.json")).st_mode)[-3:]
        check("users.json 权限 600", mode == "600", mode)

        pw = au.bootstrap_pw
        r = au.login("admin", pw, ip="127.0.0.1")
        check("初始口令能登录", r.get("ok") is True, json.dumps(r)[:160])
        tok = r.get("token", "")
        sess = au.session(tok)
        check("会话可解析出角色", (sess or {}).get("role") == "admin", str(sess)[:120])

        check("admin 有 admin 能力", au.can("admin", "admin"))
        check("viewer 无 respond 能力", not au.can("viewer", "respond"))
        check("analyst 有 triage 无 respond",
              au.can("analyst", "triage") and not au.can("analyst", "respond"))

        ok = au.add_user("watch", "{{SECRET_khbjcyaa}}", role="viewer",
                         actor="admin", actor_role="admin")
        check("可新增 viewer", ok.get("ok") is True, json.dumps(ok)[:120])
        bad = au.add_user("weak", "123456", role="viewer", actor="admin", actor_role="admin")
        check("弱口令被拒", bad.get("ok") is False, json.dumps(bad)[:120])
        dupe = au.add_user("watch", "{{SECRET_khbjcyaa}}", role="viewer",
                           actor="admin", actor_role="admin")
        check("重复账号被拒", dupe.get("ok") is False, json.dumps(dupe)[:120])

        last = au.delete_user("admin", actor="admin", actor_role="admin")
        check("不允许删掉最后一个管理员", last.get("ok") is False, json.dumps(last)[:120])

        # 爆破锁定：5 次失败后 locked
        locked = False
        for _ in range(5):
            rr = au.login("watch", "wrong-password-here", ip="127.0.0.1")
            locked = locked or bool(rr.get("locked"))
        check("连续失败触发锁定", locked, "")
        r2 = au.login("watch", "{{SECRET_khbjcyaa}}", ip="127.0.0.1")
        check("锁定期间正确口令也进不去", r2.get("ok") is False
              and "锁定" in str(r2.get("error")), json.dumps(r2, ensure_ascii=False)[:120])

        au.logout(tok)
        check("注销后令牌失效", au.session(tok) is None)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------- 更新通道
def test_update() -> None:
    print("\n== 更新通道：签名 / 完整性 / 熔断 / 回滚 ==")
    tmp = tempfile.mkdtemp(prefix="atfield-update-")
    bundle = os.path.join(tmp, "bundle")
    try:
        cfg = tmp_cfg(tmp)
        os.makedirs(os.path.join(tmp, "rules"), exist_ok=True)
        os.makedirs(os.path.join(tmp, "playbooks"), exist_ok=True)
        rule = (
            "pack: demo\nversion: \"1\"\nrules:\n"
            "  - id: DEMO-RULE\n    name: 演示规则\n    kind: [process]\n"
            "    where:\n      process:\n        contains: demo\n"
            "    severity: low\n    text: \"demo {{process}}\"\n"
        )
        open(os.path.join(tmp, "rules", "demo.yaml"), "w", encoding="utf-8").write(rule)
        open(os.path.join(tmp, "playbooks", "default.yaml"), "w", encoding="utf-8").write(
            "name: demo\non: [CANARY-TRIP]\nactions:\n  - notify\n")

        up = Updates(cfg)
        built = _build_bundle(up, os.path.join(tmp, "rules"),
                             os.path.join(tmp, "playbooks"), bundle, "9.9.1")
        check("能打出签名包", built, "")
        manifest = json.load(open(os.path.join(bundle, "manifest.json"), encoding="utf-8"))
        check("manifest 带签名", bool(manifest.get("sig")), "")

        probes = {"n": 0}

        def probe():
            probes["n"] += 1
            return {"name": "demo-probe", "ok": True, "detail": "ok"}

        up.register_probe(probe)
        res = up.apply(bundle, actor="tester", role="admin")
        check("正常包能应用", res.get("ok") is True, json.dumps(res, ensure_ascii=False)[:200])
        check("健康探针被执行", probes["n"] >= 1, str(probes))
        check("应用后产出 LKG 备份",
              bool((res.get("backup") or "")) or os.path.isdir(os.path.join(tmp, "update", "lkg")))

        # 内容被改 → 拒绝（大小/哈希不符）
        with open(os.path.join(bundle, "rules", "demo.yaml"), "a", encoding="utf-8") as fh:
            fh.write("\n# tampered\n")
        res2 = up.apply(bundle, actor="tester", role="admin")
        check("被篡改的包被拒", res2.get("ok") is False, json.dumps(res2, ensure_ascii=False)[:200])

        res3 = up.apply(bundle, actor="tester", role="admin")
        br = up.breaker()
        check("连续失败触发熔断", br["open"] is True, json.dumps(br)[:160])
        res4 = up.apply(bundle, actor="tester", role="admin")
        check("熔断期内拒绝应用", res4.get("ok") is False
              and "熔断" in str(res4.get("error")), json.dumps(res4, ensure_ascii=False)[:160])

        reset = up.reset_breaker(actor="tester", role="admin")
        check("可手工解除熔断", reset.get("ok") is True and up.breaker()["open"] is False, "")

        # 路径逃逸必须被拒绝
        evil = dict(manifest)
        evil["version"] = "9.9.9"
        evil["files"] = [{"path": "../evil.yaml", "size": 1, "sha256": "0" * 64}]
        evil["sig"] = up.sign(evil)
        os.makedirs(os.path.join(tmp, "evilb"), exist_ok=True)
        json.dump(evil, open(os.path.join(tmp, "evilb", "manifest.json"), "w"), ensure_ascii=False)
        res5 = up.apply(os.path.join(tmp, "evilb"), actor="tester", role="admin", force=True)
        check("路径逃逸被拒", res5.get("ok") is False
              and "非法路径" in str(res5.get("error")), json.dumps(res5, ensure_ascii=False)[:160])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _build_bundle(up, rules_dir: str, pb_dir: str, dest: str, version: str) -> bool:
    import hashlib
    os.makedirs(dest, exist_ok=True)
    files = []
    for sub, src_dir in (("rules", rules_dir), ("playbooks", pb_dir)):
        for name in sorted(os.listdir(src_dir)):
            if not name.endswith((".yaml", ".yml")):
                continue
            data = open(os.path.join(src_dir, name), "rb").read()
            out = os.path.join(dest, sub, name)
            os.makedirs(os.path.dirname(out), exist_ok=True)
            open(out, "wb").write(data)
            files.append({"path": f"{sub}/{name}", "size": len(data),
                          "sha256": hashlib.sha256(data).hexdigest()})
    if not files:
        return False
    manifest = {"schema": 1, "version": version, "channel": up.channel,
                "min_version": "0.0.1", "files": files}
    manifest["sig"] = up.sign(manifest)
    json.dump(manifest, open(os.path.join(dest, "manifest.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=2)
    return True


# ---------------------------------------------------------------- HTTP 闸门
PWV = "{{SECRET_wgkfyvbz}}"          # 测试用口令（策略要求 ≥12 位）


def _free_port() -> int:
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_http() -> None:
    print("\n== HTTP 鉴权闸门与能力位 ==")
    tmp = tempfile.mkdtemp(prefix="atfield-http-")
    srv = None
    try:
        core = Core(tmp_cfg(tmp))
        srv = AtFieldServer(core, port=_free_port())
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        time.sleep(0.5)
        pw = core.auth.bootstrap_pw

        def call(path, method="GET", body=None, token=None, csrf=True, expect=200):
            req = urllib.request.Request(f"http://127.0.0.1:{srv.port}" + path, method=method,
                                         data=json.dumps(body).encode() if body is not None else None)
            if body is not None:
                req.add_header("Content-Type", "application/json")
            if csrf:
                req.add_header("X-Requested-With", "atfield")
            if token:
                req.add_header("Authorization", "Bearer " + token)
            try:
                with urllib.request.urlopen(req, timeout=10) as r:
                    code, payload = r.status, r.read().decode("utf-8", "replace")
            except urllib.error.HTTPError as e:
                code, payload = e.code, e.read().decode("utf-8", "replace")
            ok = code == expect
            check(f"{method} {path} → {code}", ok, f"(expect {expect}) {payload[:110]}")
            try:
                return json.loads(payload)
            except Exception:
                return {}

        call("/api/overview", expect=401)
        call("/api/audit", expect=401)
        call("/api/stream", expect=401)
        r = call("/api/auth/login", "POST", {"user": "admin", "password": pw})
        tok = r.get("token", "")
        check("登录返回令牌", bool(tok), "")
        call("/api/auth/me", token=tok)
        call("/api/governance", token=tok)
        call("/api/audit/verify", token=tok)
        call("/api/monthly", token=tok)
        call("/api/rules/reload", "POST", {}, token=tok, csrf=False, expect=403)
        call("/api/rules/reload", "POST", {}, token=tok)

        call("/api/users/add", "POST",
             {"user": "v1", "password": PWV, "role": "viewer"}, token=tok)
        vt = call("/api/auth/login", "POST", {"user": "v1", "password": PWV}).get("token", "")
        call("/api/overview", token=vt)
        call("/api/respond", "POST", {"action": "suspend", "pid": 1}, token=vt, expect=403)
        call("/api/intel/add", "POST", {"kind": "ip", "value": "203.0.113.5"},
             token=vt, expect=403)
        call("/api/users/add", "POST", {"user": "x", "password": PWV}, token=vt, expect=403)

        v = call("/api/audit/verify", token=tok)
        check("审计链在跑过这些操作后依然完整", v.get("ok") is True,
              json.dumps(v, ensure_ascii=False)[:160])
        audit = call("/api/audit?limit=20", token=tok)
        actions = [x.get("action") for x in (audit.get("records") or [])]
        check("越权被记进审计", "auth.deny" in actions, str(actions[:8]))
        call("/api/auth/logout", "POST", {}, token=tok)
        call("/api/overview", token=tok, expect=401)
    finally:
        if srv:
            srv.shutdown()
        shutil.rmtree(tmp, ignore_errors=True)


SUITES = {"audit": test_audit, "auth": test_auth, "update": test_update, "http": test_http}


def main(argv) -> int:
    names = [a for a in argv[1:] if not a.startswith("-")] or list(SUITES)
    unknown = [n for n in names if n not in SUITES]
    if unknown:
        print(f"未知套件：{', '.join(unknown)}；可选：{', '.join(SUITES)}")
        return 2
    t0 = time.time()
    for n in names:
        SUITES[n]()
    print(f"\n合计 PASS={PASS} FAIL={FAIL}　耗时 {time.time() - t0:.1f}s")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
