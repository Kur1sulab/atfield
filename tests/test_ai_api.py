#!/usr/bin/env python3
"""心之壁 AI 层 REST 端到端验证：真起服务 → 真登录 → 真打 5 个 AI 接口 → 查审计。

覆盖：路由可达、能力位（admin/triage/read）、CSRF、密钥不外泄、审计只记键名。
"""
import json
import os
import pwd
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = "/Users/xu./aegis"


def _pick_python() -> str:
    """优先用带 PyYAML 的解释器跑服务。

    写配置（patch_section）要求真 PyYAML；若拿一个没有 yaml 的解释器跑，
    「改配置」相关用例会假失败。而读配置本身已有 yamlite 回退，不受影响。
    """
    cands = [sys.executable, "/Users/xu./.hermes/venvs/skills/bin/python3"]
    for c in cands:
        try:
            r = subprocess.run([c, "-c", "import yaml"], capture_output=True, timeout=20)
            if r.returncode == 0:
                return c
        except Exception:
            continue
    return sys.executable
WORK = "/tmp/atfield-api"
HOME_DIR = f"{WORK}/home"          # 假 HOME：连 ~ 都指到这里
DATA = f"{HOME_DIR}/.atfield"
def _free_port() -> int:
    """每次跑用一个空闲端口：固定端口会撞上上一轮残留的实例，
    然后请求全打到那个用默认配置的旧进程上（踩过，症状极难认）。"""
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])
    finally:
        s.close()


PORT = _free_port()
BASE = f"http://127.0.0.1:{PORT}"
# 运行时拼接的假 key：源码里不留 key 形态字面量
ROTATED_KEY = "sk-" + "testROTATED" + "0" * 12

OK, FAIL = 0, 0


def check(label, cond, extra=""):
    global OK, FAIL
    if cond:
        OK += 1
        print(f"  \033[32m✓\033[0m {label}" + (f"  {extra}" if extra else ""))
    else:
        FAIL += 1
        print(f"  \033[31m✗\033[0m {label}" + (f"  {extra}" if extra else ""))


def http(method, path, body=None, token=None, csrf=False, timeout=120):
    url = BASE + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Cookie", f"atfield_session={token}")
    if csrf:
        req.add_header("X-Requested-With", "atfield")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw.strip() else {}), dict(r.headers)
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, (json.loads(raw) if raw.strip() else {}), dict(e.headers)
        except Exception:
            return e.code, {"_raw": raw[:300]}, dict(e.headers)
    except Exception as e:
        return 0, {"_err": f"{type(e).__name__}: {e}"}, {}


# ---------------- 准备隔离环境 ----------------
print("=" * 74)
print("0) 隔离实例（绝不碰 ~/.atfield 正式目录）")
print("=" * 74)
shutil.rmtree(WORK, ignore_errors=True)
os.makedirs(DATA, exist_ok=True)

# 真实目录基线：整轮跑完必须一字未动
REAL_HOME = pwd.getpwuid(os.getuid()).pw_dir
_real_users = os.path.join(REAL_HOME, ".atfield", "users.json")
_real_cfg = os.path.join(REAL_HOME, ".atfield", "config.yaml")
_real_audit = os.path.join(REAL_HOME, ".atfield", "audit", "audit.log")


def _mt(p):
    return os.stat(p).st_mtime if os.path.isfile(p) else None


_baseline = {p: _mt(p) for p in (_real_users, _real_cfg, _real_audit)}
print(f"  真 HOME = {REAL_HOME}")
print(f"  假 HOME = {HOME_DIR}")

PY = _pick_python()
print(f"  解释器 = {PY}")
cfg_path = f"{WORK}/config.yaml"
with open(cfg_path, "w", encoding="utf-8") as fh:
    fh.write(f"""host_label: atfield-ai-api-test
data_dir: {DATA}
server:
  bind: 127.0.0.1
  port: {PORT}
  open_browser: false
ai:
  enabled: true
  provider: openai
  base_url: http://127.0.0.1:3425/v1
  model: group/daily
  api_key: magpie
  timeout: 90
  max_tokens: 700
  redact: true
  budget_per_hour: 60
  budget_per_day: 400
""")
print(f"  配置 {cfg_path}")

# 自检：这份配置在本进程能否被读到（和服务子进程的结果做对照）
sys.path.insert(0, ROOT)
try:
    from atfield import config as _cm
    _c = _cm.load(cfg_path)
    print(f"  自检 load -> ai.enabled={_c['ai'].get('enabled')} "
          f"max_tokens={_c['ai'].get('max_tokens')} data_dir={_c['data_dir']}")
except Exception as _e:
    print(f"  自检 load 失败: {type(_e).__name__}: {_e}")

svc_log = f"{WORK}/service.log"
print("  继承变量:", {k: os.environ.get(k) for k in
                   ("HOME", "PYTHONPATH", "PYTHONHOME", "ATFIELD_DATA_DIR",
                    "ATFIELD_AI_KEY", "ATFIELD_CONFIG")})
env = dict(os.environ, PYTHONPATH=ROOT, HOME=HOME_DIR,
           ATFIELD_DATA_DIR=DATA, USER="atfield-test",
           ATFIELD_DEBUG_CFG="1")

# 先跑 selftest 造几条合成 finding，让 judge 有数据可打
print("  跑 --selftest 生成合成事件 ...")
st = subprocess.run([PY, "atfieldd.py", "--config", cfg_path, "--selftest"],
                    cwd=ROOT, env=env, capture_output=True, text=True, timeout=180)
print("  selftest rc:", st.returncode, "|", (st.stdout or "").strip().splitlines()[-1][:120]
      if st.stdout.strip() else "(no output)")

_probe = socket.socket()
try:
    _probe.bind(("127.0.0.1", PORT))
except OSError as e:
    print(f"  ✗ 端口 {PORT} 已被占用: {e}")
    sys.exit(1)
finally:
    _probe.close()

_logfh = open(svc_log, "w", encoding="utf-8")
proc = subprocess.Popen([PY, "atfieldd.py", "--config", cfg_path,
                         "--no-browser", "--port", str(PORT)],
                        cwd=ROOT, env=env,
                        stdout=_logfh, stderr=subprocess.STDOUT, text=True)

try:
    # 等就绪
    ready = False
    for _ in range(90):
        if proc.poll() is not None:
            break
        try:
            with urllib.request.urlopen(BASE + "/api/ping", timeout=2) as r:
                if r.status == 200:
                    ready = True
                    break
        except Exception:
            time.sleep(0.5)
    check("服务就绪", ready, f"{BASE}")
    if not ready:
        print("  --- 服务输出 ---")
        try:
            proc.kill()
            print((proc.stdout.read() or "")[:2500])
        except Exception:
            pass
        sys.exit(1)

    # ---------------- 登录 ----------------
    print()
    print("=" * 74)
    print("1) 登录（拿 admin 会话）")
    print("=" * 74)
    # 只读隔离实例自己的初始化文件：正式的 ~/.atfield 口令不同（会 401），而且本来就该隔离
    # 不能用 glob('**')：Python 的 glob 默认跳过点开头的隐藏目录，
    # 而隔离目录叫 ~/.atfield —— 会静默返回空列表。用 os.walk 才可靠。
    cands = [os.path.join(r, f) for r, _, fs in os.walk(WORK) for f in fs
             if f == "INITIAL-ADMIN.txt"]
    admin_user, admin_pw = "admin", ""
    for c in cands:
        try:
            txt = open(c, encoding="utf-8").read()
        except Exception:
            continue
        print(f"  发现 {c}")
        for line in txt.splitlines():
            if ":" in line and not line.strip().startswith("#"):
                k, v = line.split(":", 1)
                k, v = k.strip().lower(), v.strip()
                if "user" in k and v:
                    admin_user = v
                elif ("pass" in k or "口令" in k) and v:
                    admin_pw = v
    if not admin_pw:
        print("  未能从 INITIAL-ADMIN.txt 解析口令，略过后续鉴权测试")
    st_code, body, hdrs = http("POST", "/api/auth/login",
                               {"user": admin_user, "password": admin_pw})
    check("登录成功", st_code == 200 and body.get("ok") is True,
          f"HTTP {st_code} role={body.get('role')}")
    token = ""
    if body.get("ok"):
        sc = hdrs.get("Set-Cookie") or ""
        for part in sc.split(";"):
            if part.strip().startswith("atfield_session="):
                token = part.strip().split("=", 1)[1]
        token = token or str(body.get("token") or "")
    check("拿到会话 token", bool(token), f"(len={len(token)})")

    # ---------------- 未登录必须 401 ----------------
    print()
    print("=" * 74)
    print("2) 未登录 / 错误 CSRF 必须被拒")
    print("=" * 74)
    c, b, _ = http("GET", "/api/ai/status")
    check("未登录读 status → 401", c == 401 and b.get("login_required") is True, f"HTTP {c}")
    c, b, _ = http("POST", "/api/ai/config", {"min_severity": "low"}, token=token, csrf=False)
    check("缺 CSRF 头写 config → 403", c == 403, f"HTTP {c} {str(b.get('error'))[:40]}")

    # ---------------- GET status ----------------
    print()
    print("=" * 74)
    print("3) GET /api/ai/status")
    print("=" * 74)
    # 先造数据，否则 judge 无 finding 可打
    print()
    print("=" * 74)
    print("3a) POST /api/selftest（本进程内生成合成 finding）")
    print("=" * 74)
    c, b, _ = http("POST", "/api/selftest", {}, token=token, csrf=True, timeout=180)
    print("  " + json.dumps(b, ensure_ascii=False)[:240])
    check("selftest 成功", c == 200 and b.get("ok") is not False, f"HTTP {c}")
    c, b, _ = http("GET", "/api/findings?limit=30", token=token)
    fl = b.get("findings") or []
    print(f"  findings={len(fl)}")
    check("store 里有 finding", len(fl) > 0, f"{len(fl)} 条")

    print()
    print("=" * 74)
    print("3b) GET /api/ai/status")
    print("=" * 74)
    _logfh.flush()
    print("  --- 服务进程自报 ---")
    try:
        for _ln in open(svc_log, encoding="utf-8", errors="replace").read().splitlines()[:5]:
            print("   ", _ln[:190])
    except Exception as _e:
        print("    (读日志失败)", _e)
    print("  --- 接口返回 ---")

    c, b, _ = http("GET", "/api/ai/status", token=token)
    cf = b.get("config") or {}
    print("  顶层: " + json.dumps({k: b.get(k) for k in
                                   ("ok", "mode", "egress", "redact", "preset",
                                    "config_path", "can_execute", "recent_ok_rate")},
                                  ensure_ascii=False))
    print("  config: " + json.dumps({k: cf.get(k) for k in
                                     ("ready", "provider", "model", "endpoint",
                                      "key_present", "key_source", "key_fingerprint",
                                      "max_tokens")}, ensure_ascii=False))
    check("200 且 ok", c == 200 and b.get("ok") is True, f"HTTP {c}")
    check("mode=gateway（回环网关≠本地推理）", b.get("mode") == "gateway", str(b.get("mode")))
    check("egress 明说会出网", "出网" in str(b.get("egress")), str(b.get("egress")))
    check("provider 自检就绪", cf.get("ready") is True, str(cf.get("problems")))
    check("端点正确", str(cf.get("endpoint")).endswith("/chat/completions"),
          str(cf.get("endpoint")))
    check("key 只出指纹", str(cf.get("key_fingerprint")).startswith("sha256:"))
    check("key_present=True", cf.get("key_present") is True)
    check("can_execute 恒 False", b.get("can_execute") is False)
    check("带 stats", isinstance(b.get("stats"), dict))

    # ---------------- POST test ----------------
    print()
    print("=" * 74)
    print("4) POST /api/ai/test（真打 magpie）")
    print("=" * 74)
    t0 = time.time()
    c, b, _ = http("POST", "/api/ai/test", {}, token=token, csrf=True)
    el = int((time.time() - t0) * 1000)
    print(f"  HTTP {c} {int(el)}ms :: " +
          json.dumps({k: b.get(k) for k in ("ok", "latency_ms", "model", "reply")},
                     ensure_ascii=False)[:220])
    check("连通成功", c == 200 and b.get("ok") is True, f"kind={b.get('kind')}")

    # ---------------- POST judge ----------------
    print()
    print("=" * 74)
    print("5) POST /api/ai/judge（批量研判）")
    print("=" * 74)
    c, b, _ = http("POST", "/api/ai/judge", {"limit": 2}, token=token, csrf=True, timeout=180)
    print("  " + json.dumps({k: b.get(k) for k in
                             ("ok", "judged", "skipped", "errors", "budget")},
                            ensure_ascii=False)[:300])
    check("接口返回 200", c == 200, f"HTTP {c}")
    check("有研判结构", isinstance(b, dict) and ("judged" in b or b.get("ok") is not None))

    # ---------------- GET suggestions ----------------
    print()
    print("=" * 74)
    print("6) GET /api/ai/suggestions")
    print("=" * 74)
    c, b, _ = http("GET", "/api/ai/suggestions?limit=20", token=token)
    all_sug = b.get("suggestions") or []
    sug = [s for s in all_sug if s.get("kind") != "ping"]
    print(f"  HTTP {c}  总记录={len(all_sug)}  研判记录={len(sug)}")
    if sug:
        s0 = sug[0]
        print("  首条:", json.dumps({k: s0.get(k) for k in
                                     ("fid", "verdict", "confidence", "executed")},
                                    ensure_ascii=False))
        check("建议含 executed=False", s0.get("executed") is False)
        check("verdict 合法", s0.get("verdict") in
              ("benign", "suspicious", "malicious", "uncertain"), str(s0.get("verdict")))
    check("200", c == 200, f"HTTP {c}")

    # ---------------- POST config ----------------
    print()
    print("=" * 74)
    print("7) POST /api/ai/config（改配置 + 轮换 key）")
    print("=" * 74)
    c, b, _ = http("POST", "/api/ai/config",
                   {"min_severity": "low", "max_tokens": 800,
                    "api_key": ROTATED_KEY},
                   token=token, csrf=True)
    print("  " + json.dumps({k: b.get(k) for k in ("ok", "changed", "warnings", "key_saved")},
                            ensure_ascii=False)[:400])
    check("改配置成功", c == 200 and b.get("ok") is True, f"HTTP {c}")
    blob = json.dumps(b, ensure_ascii=False)
    check("响应不回显 key 值", ROTATED_KEY not in blob)
    sec = f"{DATA}/secrets/ai.json"
    check("key 落到 secrets 文件（600）",
          os.path.isfile(sec) and (os.stat(sec).st_mode & 0o777) == 0o600, sec)
    check("没有污染正式目录 ~/.atfield/secrets",
          not os.path.isfile(os.path.expanduser("~/.atfield/secrets/ai.json")))
    # 配置生效了没
    c2, b2, _ = http("GET", "/api/ai/status", token=token)
    _cf2 = b2.get("config") or {}
    check("配置热生效（max_tokens=800）", _cf2.get("max_tokens") == 800,
          str(_cf2.get("max_tokens")))
    check("key 指纹已变（轮换生效）",
          _cf2.get("key_fingerprint") != cf.get("key_fingerprint"),
          f"{cf.get('key_fingerprint')} -> {_cf2.get('key_fingerprint')}")

    # ---------------- 审计只记键名 ----------------
    print()
    print("=" * 74)
    print("8) 审计：只记键名，绝不记值")
    print("=" * 74)
    c, b, _ = http("GET", "/api/audit?limit=60", token=token)
    rows = b.get("records") or []
    ai_rows = [r for r in rows if str(r.get("action", "")).startswith("ai.")]
    print(f"  审计总数={len(rows)}  ai.*={len(ai_rows)}")
    for r in ai_rows[:4]:
        print("   ", json.dumps({k: r.get(k) for k in ("action", "target", "result")},
                                ensure_ascii=False),
              str(r.get("detail"))[:150])
    check("有 ai.* 审计", len(ai_rows) >= 2, str([r.get("action") for r in ai_rows]))
    audit_blob = json.dumps(ai_rows, ensure_ascii=False)
    check("审计里没有 key 明文", ROTATED_KEY not in audit_blob)
    check("审计里有 api_key_rotated 布尔", "api_key_rotated" in audit_blob)

finally:
    print()
    print("=" * 74)
    print("收尾：停服务")
    print("=" * 74)
    try:
        _logfh.close()
    except Exception:
        pass
    try:
        proc.send_signal(signal.SIGINT)
        proc.wait(timeout=8)
        print("  已优雅停止")
    except Exception:
        proc.kill()
        print("  已强制结束")

print()
print("=" * 74)
print("9) 隔离硬验证：正式 ~/.atfield 全程一字未动")
print("=" * 74)
for _p, _was in _baseline.items():
    _now = _mt(_p)
    check(f"未触碰 {os.path.relpath(_p, REAL_HOME)}", _now == _was,
          f"{_was} -> {_now}")

print()
print("=" * 74)
print(f"结果：{OK} 通过 / {FAIL} 失败")
print("=" * 74)


def load_tests(loader, tests, pattern):
    """unittest discover 入口：脚本体已在导入时跑完，这里把计数变成正式断言。

    此前模块级 sys.exit() 被 unittest 记为导入错误（_FailedTest），
    discover 永远 FAILED(errors=3)、退出码 1，回归门禁形同虚设。
    """
    import unittest

    class _ScriptChecks(unittest.TestCase):
        def test_all_checks_passed(self):
            self.assertEqual(FAIL, 0, f"脚本内 {FAIL} 项检查失败（见上方输出）")

    tests.addTests(loader.loadTestsFromTestCase(_ScriptChecks))
    return tests


if __name__ == "__main__":
    sys.exit(0 if FAIL == 0 else 1)
