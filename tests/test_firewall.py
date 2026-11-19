#!/usr/bin/env python3
"""主机防火墙层验证：地址校验 → 规则渲染 → helper 真加载 → 自锁防护 → 越权拒绝。

所有阻断目标一律用 TEST-NET 保留段（198.51.100.0/24、203.0.113.0/24），
不含任何真实业务地址；用独立 anchor `atfield-test`，不碰主规则集与现有网络。

需要 root 起 helper（pfctl 要 /dev/pf）。跑不了 root 的那几节会明确标 SKIP，
不会假装通过。
"""
import json
import os
import shutil
import socket as sock_mod
import subprocess
import sys
import time

sys.path.insert(0, "/Users/xu./aegis")

from atfield import firewall as fw_mod      # noqa: E402
from atfield import pfhelper as ph          # noqa: E402

OK, FAIL, SKIP = 0, 0, 0
BASE = "/tmp/atfield-pf-test"
SOCK = os.path.join(BASE, "pf.sock")
ANCHOR = "atfield-test"
UID = os.getuid()


def check(label, cond, extra=""):
    global OK, FAIL
    if cond:
        OK += 1
        print(f"  \033[32m✓\033[0m {label}" + (f"  {extra}" if extra else ""))
    else:
        FAIL += 1
        print(f"  \033[31m✗\033[0m {label}" + (f"  {extra}" if extra else ""))


def skip(label, why):
    global SKIP
    SKIP += 1
    print(f"  \033[33m⊘\033[0m {label}  （SKIP: {why}）")


def sudo_ok():
    r = subprocess.run(["sudo", "-n", "true"], capture_output=True)
    return r.returncode == 0


# ==================================================================
print("=" * 74)
print("1) 地址校验：什么能封、什么绝对不许封")
print("=" * 74)

good = [("203.0.113.9", "203.0.113.9/32"),
        ("198.51.100.0/24", "198.51.100.0/24"),
        ("2001:db8::1", "2001:db8::1/128")]
for raw, want in good:
    net, err = ph.parse_target(raw)
    check(f"接受 {raw}", net is not None and str(net) == want and not err, err or str(net))

bad = [("", "空"),
       ("evil.example.com", "域名不是 IP"),
       ("127.0.0.1", "回环"),
       ("::1", "IPv6 回环"),
       ("0.0.0.0", "全零"),
       ("0.0.0.0/0", "默认路由全封"),
       ("10.0.0.0/4", "超大网段"),
       ("224.0.0.1", "组播"),
       ("999.1.1.1", "不存在")]
for raw, why in bad:
    net, err = ph.parse_target(raw)
    check(f"拒绝 {why}  {raw or '(空)'}", net is None and bool(err), err)

addrs, gw = ph.local_addrs()
print(f"  本机地址 {len(addrs)} 个，默认网关 {gw or '无'}")
for a in sorted(addrs)[:3]:
    if ":" in a:
        continue
    net, _ = ph.parse_target(a)
    if net is not None:
        lock = ph.self_lock(net)
        check(f"拒绝封本机地址 {a}", bool(lock), lock[:60])
if gw:
    net, _ = ph.parse_target(gw)
    if net is not None:
        check(f"拒绝封默认网关 {gw}", bool(ph.self_lock(net)), ph.self_lock(net)[:60])

check("注释注入被中和（# → 全角）", "#" not in ph.clean_reason("x # block all"))
check("超长理由被截断", len(ph.clean_reason("A" * 500)) <= 180)

# ==================================================================
print()
print("=" * 74)
print("2) 规则渲染：文本形状对不对")
print("=" * 74)

h = ph.PfHelper(ANCHOR, [UID], SOCK, os.path.join(BASE, "state.json"),
                os.path.join(BASE, "audit.jsonl"))
h.state["ips"] = {"203.0.113.9": {"reason": "反弹 shell", "ts": 1},
                  "198.51.100.0/24": {"reason": "扫描源段", "ts": 2}}
text = h.render()
check("带开始标记", ph.MARK_BEGIN in text)
check("带结束标记", ph.MARK_END in text)
check("每条目标两个方向各一条", text.count("block drop quick") == 4)
check("排除回环 on ! lo0", text.count("on ! lo0") == 4)
check("理由以注释形式出现", "# 203.0.113.9 反弹 shell" in text)
check("网段按 CIDR 原样写入", "from 198.51.100.0/24 to any" in text)
h.state["ips"] = {}

# ==================================================================
print()
print("=" * 74)
print("3) 客户端：读不到就说读不到，不伪装成安全")
print("=" * 74)

off = fw_mod.Firewall({"firewall": {"enabled": False}})
r = off.block("203.0.113.9")
check("未启用时 block 被挡", r.get("ok") is False and r.get("skipped"), r.get("detail", "")[:50])
check("未启用时状态 reasons 说得清", "未启用" in off.status()["detail"])

miss = fw_mod.Firewall({"firewall": {"enabled": True, "socket": "/tmp/definitely-not-here.sock"}})
st = miss.status()
check("socket 缺失 → available=False", st["available"] is False)
check("socket 缺失 → 不谎报 count=0", "helper 未启动" in st["detail"])
check("socket 缺失 → summary 标 off", miss.summary()["tone"] == "off")

# ==================================================================
print()
print("=" * 74)
print("4) 端到端：真 helper + 真 pf 加载")
print("=" * 74)

EXT = os.environ.get("ATFIELD_PF_SOCK", "")
proc = None
reachable = False

if EXT:
    print(f"  使用外部已启动的 helper: {EXT}")
    SOCK = EXT
    reachable = os.path.exists(SOCK)
elif not sudo_ok():
    skip("helper 端到端", "子进程里没有免密 sudo；先 sudo 起 helper 再设 ATFIELD_PF_SOCK 即可真跑")
else:
    shutil.rmtree(BASE, ignore_errors=True)
    os.makedirs(BASE, exist_ok=True)
    grp_name = ""
    try:
        import grp
        grp_name = grp.getgrgid(os.getgid()).gr_name
    except Exception:
        pass
    cmd = ["sudo", "-n", "env", "PYTHONPATH=/Users/xu./aegis",
           sys.executable, "-m", "atfield.pfhelper",
           "--socket", SOCK, "--anchor", ANCHOR, "--allow-uid", str(UID),
           "--state", os.path.join(BASE, "state.json"),
           "--audit", os.path.join(BASE, "audit.jsonl")]
    if grp_name:
        cmd += ["--group", grp_name]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for _ in range(60):
        if os.path.exists(SOCK):
            reachable = True
            break
        time.sleep(0.1)
    check("helper 起来并创建 socket", reachable, SOCK)

if reachable:
    fw = fw_mod.Firewall({"firewall": {"enabled": True, "dry_run": False, "socket": SOCK}})
    st = fw.status()
    check("status 可达", st["available"] is True, str(st.get("detail"))[:60])
    check("报出 pf 已开启", st.get("pf_enabled") is True)
    check("初始阻断表为空", st.get("count") == 0, f"count={st.get('count')}")
    check("主规则集未挂载（如实上报）", st.get("attached") is False)

    r = fw.block("203.0.113.9", "测试：反弹 shell 外联")
    check("block 成功", r.get("ok") is True, str(r.get("detail"))[:80])
    st = fw.status()
    check("阻断表里有了", st.get("count") == 1 and "203.0.113.9/32" in st["blocked"],
          str(st.get("blocked")))

    st = fw.status()
    sample = " ".join(st.get("rules_sample") or [])
    check("pf 里真的有这条规则", "203.0.113.9" in sample,
          (st.get("rules_sample") or [""])[0][:70])

    r = fw.block("203.0.113.9", "重复封同一个")
    check("重复 block 幂等", r.get("ok") is True and fw.status()["count"] == 1)

    r = fw.block("127.0.0.1")
    check("封回环被拒", r.get("ok") is False and "回环" in str(r.get("detail")),
          str(r.get("detail"))[:40])
    r = fw.block("evil.example.com")
    check("封域名被拒", r.get("ok") is False, str(r.get("detail"))[:40])
    if gw:
        r = fw.block(gw)
        check("封默认网关被拒", r.get("ok") is False and "网关" in str(r.get("detail")),
              str(r.get("detail"))[:50])

    r = fw.unblock("203.0.113.9")
    check("unblock 成功", r.get("ok") is True and r.get("removed") is True,
          str(r.get("detail"))[:60])
    check("阻断表清空", fw.status()["count"] == 0)
    st = fw.status()
    check("pf 里规则已移除", "203.0.113.9" not in " ".join(st.get("rules_sample") or []),
          f"remaining={st.get('rule_lines')}")

    r = fw.attach()
    check("未授权 attach 被拒", r.get("ok") is False and "allow_attach" in str(r.get("detail")),
          str(r.get("detail"))[:50])

    ap = os.path.join(os.path.dirname(SOCK), "audit.jsonl")
    lines = []
    if os.path.exists(ap):
        lines = [json.loads(l) for l in open(ap, encoding="utf-8") if l.strip()]
    ops = [l.get("op") for l in lines]
    check("helper 自己写了审计", len(lines) >= 4, f"{len(lines)} 条")
    check("审计里有 block/unblock", "block" in ops and "unblock" in ops,
          str(sorted(set(ops))[:6]))
    check("审计带 uid", bool(lines) and all("uid" in l for l in lines))

    fw.flush()
    check("flush 后阻断表归零", fw.status()["count"] == 0)

if proc is not None:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()

print()
print("=" * 74)
print(f"结果：{OK} 通过 / {FAIL} 失败 / {SKIP} 跳过")
print("=" * 74)
sys.exit(0 if FAIL == 0 else 1)
