"""安全基线采集器：把「终端现在到底安不安全」变成可量化的检查项。

每个检查项输出 pass / warn / fail / unknown，并给出证据与整改建议——
这部分就是「态势」里的资产与配置维度，和 EDR 的行为事件互补。
"""
from __future__ import annotations

import os
import plistlib
import re
import subprocess
import time
from typing import Any, Dict, List, Tuple

import psutil

from ..model import Event
from .base import Collector

HOME = os.path.expanduser("~")


def _cmd(argv: List[str], timeout: float = 8.0) -> Tuple[int, str]:
    try:
        p = subprocess.run(argv, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as exc:
        return 127, f"{type(exc).__name__}: {exc}"


def _defaults(domain: str, key: str) -> Tuple[int, str]:
    return _cmd(["/usr/bin/defaults", "read", domain, key], timeout=5)


def _listening_ports() -> set:
    ports = set()
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.status == psutil.CONN_LISTEN and c.laddr:
                ports.add(c.laddr.port)
    except Exception:
        pass
    return ports


class BaselineCollector(Collector):
    name = "baseline"
    interval = 120.0

    def __init__(self, cfg, store):
        super().__init__(cfg, store)
        self._prev: Dict[str, str] = {}
        self._results: List[dict] = []

    # ---------- 单项检查 ----------
    def _check(self, cid: str, name: str, category: str, weight: int) -> Dict[str, Any]:
        return {"id": cid, "name": name, "category": category, "weight": weight,
                "status": "unknown", "severity": "info", "evidence": "", "advice": "", "ts": time.time()}

    def checks(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        ports = _listening_ports()

        # 1. SIP
        c = self._check("SIP", "系统完整性保护 SIP", "系统安全", 12)
        rc, txt = _cmd(["/usr/bin/csrutil", "status"])
        if "enabled" in txt and "disabled" not in txt:
            c.update(status="pass", evidence="csrutil: enabled")
        elif "disabled" in txt:
            c.update(status="fail", severity="high", evidence=txt.strip(),
                     advice="csrutil enable（需恢复模式）——攻击者可任意改写系统文件与内核扩展")
        out.append(c)

        # 2. Gatekeeper
        c = self._check("GATEKEEPER", "Gatekeeper 应用公证校验", "系统安全", 10)
        rc, txt = _cmd(["/usr/sbin/spctl", "--status"])
        if "assessments enabled" in txt:
            c.update(status="pass", evidence=txt.strip())
        else:
            c.update(status="fail", severity="medium", evidence=txt.strip(),
                     advice="spctl --global-enable —— 当前可运行未公证/未签名应用")
        out.append(c)

        # 3. FileVault
        c = self._check("FILEVAULT", "磁盘加密 FileVault", "数据保护", 12)
        rc, txt = _cmd(["/usr/bin/fdesetup", "status"])
        if "FileVault is On" in txt:
            c.update(status="pass", evidence="FileVault is On")
        elif "Off" in txt:
            c.update(status="fail", severity="high", evidence=txt.strip(),
                     advice="启用 FileVault —— 设备丢失即等于数据泄露")
        else:
            c.update(status="unknown", evidence=txt.strip()[:200])
        out.append(c)

        # 4. 应用防火墙
        fw = "/usr/libexec/applicationfirewall/socketfilterfw"
        c = self._check("FIREWALL", "应用层防火墙", "网络防线", 10)
        rc, txt = _cmd([fw, "--getglobalstate"])
        if "enabled" in txt.lower() and "disabled" not in txt.lower():
            c.update(status="pass", evidence=txt.strip())
        else:
            c.update(status="fail", severity="medium", evidence=txt.strip() or "未启用",
                     advice="系统设置 → 网络 → 防火墙 → 打开")
        out.append(c)

        # 5. 隐身模式
        c = self._check("FW_STEALTH", "防火墙隐身模式", "网络防线", 4)
        rc, txt = _cmd([fw, "--getstealthmode"])
        if "enabled" in txt.lower() and "disabled" not in txt.lower():
            c.update(status="pass", evidence=txt.strip())
        else:
            c.update(status="warn", severity="low", evidence=txt.strip() or "未开启",
                     advice=f"{fw} --setstealthmode on —— 减少被局域网扫描发现")
        out.append(c)

        # 6. 远程登录暴露面
        c = self._check("SSH_EXPOSED", "SSH 远程登录", "暴露面", 8)
        if 22 in ports:
            c.update(status="warn", severity="medium", evidence="22/tcp 正在监听",
                     advice="确认确有远程运维需求；否则关闭「远程登录」，并限制来源 IP")
        else:
            c.update(status="pass", evidence="未监听 22/tcp")
        out.append(c)

        # 7. 高危共享服务
        c = self._check("SHARING", "文件共享 / 屏幕共享 / RDP", "暴露面", 10)
        risky = {445: "SMB", 548: "AFP", 5900: "屏幕共享(VNC)", 3389: "RDP", 139: "NetBIOS"}
        live = [f"{p}/{v}" for p, v in risky.items() if p in ports]
        if live:
            c.update(status="fail", severity="high", evidence="正在监听: " + ", ".join(live),
                     advice="关闭不用的共享服务；确需使用则绑定内网并加白名单")
        else:
            c.update(status="pass", evidence="未发现 SMB/AFP/VNC/RDP 监听")
        out.append(c)

        # 8. 自动更新
        c = self._check("AUTOUPDATE", "自动检查更新", "补丁管理", 8)
        rc, txt = _defaults("/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled")
        if txt.strip() in ("1", "true", "TRUE"):
            c.update(status="pass", evidence="AutomaticCheckEnabled=1")
        elif rc != 0:
            c.update(status="unknown", evidence="无法读取 SoftwareUpdate 偏好")
        else:
            c.update(status="warn", severity="medium", evidence=f"AutomaticCheckEnabled={txt.strip()}",
                     advice="启用自动更新，降低「补丁滞后 N 个月」类风险")
        out.append(c)

        # 9. 自动登录
        c = self._check("AUTOLOGIN", "自动登录（免密进桌面）", "身份与会话", 10)
        rc, txt = _defaults("/Library/Preferences/com.apple.loginwindow", "autoLoginUser")
        if rc == 0 and txt.strip():
            c.update(status="fail", severity="high", evidence=f"autoLoginUser={txt.strip()}",
                     advice="关闭自动登录 —— 物理接触即等于登录成功")
        else:
            c.update(status="pass", evidence="未配置自动登录")
        out.append(c)

        # 10. 访客账户
        c = self._check("GUEST", "访客账户", "身份与会话", 5)
        rc, txt = _defaults("/Library/Preferences/com.apple.loginwindow", "GuestEnabled")
        if rc == 0 and txt.strip() in ("1", "true", "TRUE"):
            c.update(status="warn", severity="medium", evidence="GuestEnabled=1",
                     advice="关闭访客账户，避免无凭据本地访问")
        else:
            c.update(status="pass", evidence="访客账户未启用")
        out.append(c)

        # 11. 锁屏密码
        c = self._check("SCREENLOCK", "唤醒需密码", "身份与会话", 8)
        rc1, t1 = _cmd(["/usr/bin/defaults", "-currentHost", "read",
                        "com.apple.screensaver", "askForPassword"])
        rc2, t2 = _cmd(["/usr/bin/defaults", "-currentHost", "read",
                        "com.apple.screensaver", "askForPasswordDelay"])
        if t1.strip() == "1":
            delay = t2.strip() or "0"
            try:
                d = float(delay)
            except Exception:
                d = 0.0
            if d <= 60:
                c.update(status="pass", evidence=f"askForPassword=1 delay={delay}s")
            else:
                c.update(status="warn", severity="medium", evidence=f"锁屏 {delay}s 后才要求密码",
                         advice="把「需要密码」设为立即")
        elif rc1 != 0:
            c.update(status="unknown", evidence="该 macOS 版本改由 MDM/新 API 管理锁屏策略")
        else:
            c.update(status="fail", severity="high", evidence=f"askForPassword={t1.strip()}",
                     advice="开启「进入睡眠或屏幕保护后立即要求密码」")
        out.append(c)

        # 12. XProtect 版本
        c = self._check("XPROTECT", "XProtect 恶意软件特征库", "恶意代码防护", 6)
        rc, txt = _cmd(["/usr/sbin/pkgutil", "--pkg-info", "com.apple.pkg.XProtectPlistConfigData"])
        m = re.search(r"version:\s*(\S+)", txt)
        if m:
            ver = m.group(1)
            num = int(re.sub(r"\D", "", ver)[:6] or 0)
            if num >= 5270:
                c.update(status="pass", evidence=f"XProtect 特征库 {ver}")
            else:
                c.update(status="warn", severity="medium", evidence=f"XProtect 特征库偏旧: {ver}",
                         advice="保持系统更新以刷新特征库")
        else:
            c.update(status="unknown", evidence=txt.strip()[:200])
        out.append(c)

        # 13. 第三方安全组件
        c = self._check("EDR_AGENT", "第三方 EDR / 安全代理", "恶意代码防护", 6)
        known = ["/Applications/CrowdStrike Falcon.app", "/Applications/SentinelOne.app",
                 "/Library/Application Support/JAMF", "/Applications/Cisco Secure Client.app",
                 "/Applications/Netskope Client.app"]
        present = [p for p in known if os.path.exists(p)]
        if present:
            c.update(status="pass", evidence="已装: " + ", ".join(os.path.basename(p) for p in present))
        else:
            c.update(status="warn", severity="low", evidence="未发现常见商用 EDR 代理",
                     advice="本机安全依赖 心之壁 自身检测能力，建议叠加一层商业 EDR 做纵深")
        out.append(c)

        # 14. 远程管理 (ARD)
        c = self._check("ARD", "Apple 远程管理 ARD", "暴露面", 8)
        ard = "/Library/Preferences/com.apple.RemoteManagement.plist"
        if os.path.exists(ard):
            try:
                with open(ard, "rb") as fh:
                    pl = plistlib.load(fh) or {}
            except Exception:
                pl = {}
            if pl.get("ARD_AllLocalUsers") or pl.get("AllowAllUsers"):
                c.update(status="fail", severity="high", evidence="ARD 允许任意本地用户被远程控制",
                         advice="关闭「远程管理」中的 All Local Users 授权")
            else:
                c.update(status="warn", severity="medium", evidence="ARD 已部署",
                         advice="确认远程管理需求与授权用户清单")
        else:
            c.update(status="pass", evidence="未部署 ARD")
        out.append(c)

        # 15. 时间同步
        c = self._check("TIMESYNC", "时间同步", "系统安全", 3)
        timed = any("timed" in (p.info.get("name") or "") for p in psutil.process_iter(["name"]))
        if timed:
            c.update(status="pass", evidence="timed 时间同步服务在运行")
        else:
            c.update(status="warn", severity="low", evidence="未检测到 timed",
                     advice="时间漂移会导致日志时间线失真与证书校验失败")
        out.append(c)

        # 16. sudo 失败堆积（来自事件流的弱信号，作为基线项展示）
        c = self._check("PRIVMON", "提权与认证失败监控", "身份与会话", 5)
        fails = self.store.counters.get("auth.fail", 0)
        if fails == 0:
            c.update(status="pass", evidence="本会话未捕获认证失败事件")
        elif fails < 5:
            c.update(status="warn", severity="low", evidence=f"捕获 {fails} 次认证失败",
                     advice="核对是否人为输错；持续失败即口令喷洒迹象")
        else:
            c.update(status="fail", severity="high", evidence=f"捕获 {fails} 次认证失败",
                     advice="立即排查来源 IP，必要时封禁")
        out.append(c)

        # 17. TCC 敏感授权（需要完全磁盘访问权限才能读，读不到就置 unknown）
        c = self._check("TCC", "敏感权限授权（TCC）", "数据保护", 6)
        tcc = os.path.join(HOME, "Library/Application Support/com.apple.TCC/TCC.db")
        if os.path.exists(tcc):
            rc, txt = _cmd(["/usr/bin/sqlite3", tcc,
                            "select service,client,auth_value from access where auth_value!=0 limit 40;"],
                           timeout=10)
            if rc == 0 and txt.strip():
                rows = [l for l in txt.splitlines() if l.strip()]
                c.update(status="warn", severity="low",
                         evidence=f"已授权 {len(rows)} 条 TCC 记录（示例: {rows[0][:80]}）",
                         advice="定期清理不再需要的「屏幕录制/辅助功能/完全磁盘访问」授权")
            else:
                c.update(status="unknown", evidence="无完全磁盘访问权限，TCC 库不可读")
        else:
            c.update(status="unknown", evidence="未找到用户 TCC 数据库")
        out.append(c)

        return out

    def collect(self) -> List[Event]:
        results = self.checks()
        self._results = results
        now = time.time()
        events: List[Event] = []

        # 状态迁移才产生事件，避免每轮刷屏
        for r in results:
            prev = self._prev.get(r["id"])
            self._prev[r["id"]] = r["status"]
            if prev is None:
                continue
            if prev == r["status"]:
                continue
            worse = {"pass": 0, "unknown": 1, "warn": 2, "fail": 3}
            if worse.get(r["status"], 0) <= worse.get(prev, 0):
                continue
            events.append(Event(
                kind="baseline.drift", source=self.name, ts=now, severity=r["severity"],
                process=r["name"], path=r["id"],
                subject={"check": r["id"], "name": r["name"], "from": prev,
                         "to": r["status"], "evidence": r["evidence"]},
            ))

        self.store.set_state("baseline", {
            "results": results,
            "ts": now,
            "counts": {
                "pass": sum(1 for r in results if r["status"] == "pass"),
                "warn": sum(1 for r in results if r["status"] == "warn"),
                "fail": sum(1 for r in results if r["status"] == "fail"),
                "unknown": sum(1 for r in results if r["status"] == "unknown"),
            },
        })
        return events
