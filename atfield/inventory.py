"""资产与软件清单：装了什么、什么版本、多久没更新、有没有落在非预期位置。

非特权即可读 /Applications 与 /Library 的 Info.plist。
版本老化不是「漏洞」——只是「该查一下有没有已知问题」的线索，措辞上严格区分。
"""
from __future__ import annotations

import json
import os
import plistlib
import threading
import time
from typing import Any, Dict, List

APP_DIRS = ["/Applications", "/System/Applications", os.path.expanduser("~/Applications")]
# 浏览器/办公/开发/远程控制——远程控制类软件是横向移动的高频入口，单列
SENSITIVE_CATEGORIES = {
    "remote": ("teamviewer", "anydesk", "screenconnect", "rustdesk", "splashtop",
               "logmein", "gotoassist", "vnc", "parsec", "sunlogin", "todesk", "aweray"),
    "browser": ("safari", "chrome", "firefox", "edge", "arc", "brave", "opera"),
    "dev": ("xcode", "visual studio code", "pycharm", "intellij", "docker", "postman"),
    "security": ("1password", "bitwarden", "keepass", "little snitch", "blockblock",
                 "knockknock", "objective-see", "malwarebytes", "crowdstrike",
                 "sentinelone", "carbon black", "falcon"),
    "vpn": ("tailscale", "wireguard", "openvpn", "forticlient", "cisco", "globalprotect",
            "clash", "surge", "quantumult", "shadowsocks", "v2ray"),
}

STALE_DAYS = 540   # 超过 18 个月未更新 → 值得复核（不是漏洞结论）
SIGN_CACHE_DAYS = 7
SIGN_MAX_CHECKS = 60   # codesign 是子进程，限制单轮检查量，避免首扫卡死


def _app_record(path: str) -> Dict[str, Any] | None:
    info = os.path.join(path, "Contents", "Info.plist")
    rec: Dict[str, Any] = {"path": path, "name": os.path.basename(path)[:-4],
                           "bundle_id": "", "version": "", "min_os": "",
                           "executable": "", "signed": "unknown"}
    try:
        with open(info, "rb") as fh:
            d = plistlib.load(fh)
        rec["bundle_id"] = str(d.get("CFBundleIdentifier") or "")
        rec["version"] = str(d.get("CFBundleShortVersionString")
                             or d.get("CFBundleVersion") or "")
        rec["min_os"] = str(d.get("LSMinimumSystemVersion") or "")
        rec["executable"] = str(d.get("CFBundleExecutable") or "")
    except Exception:
        return None
    try:
        st = os.stat(path)
        rec["mtime"] = st.st_mtime
        rec["modified_cn"] = time.strftime("%Y-%m-%d", time.localtime(st.st_mtime))
        rec["age_days"] = int((time.time() - st.st_mtime) / 86400)
    except Exception:
        rec["age_days"] = -1
    low = (rec["name"] + " " + rec["bundle_id"]).lower()
    for cat, keys in SENSITIVE_CATEGORIES.items():
        if any(k in low for k in keys):
            rec["category"] = cat
            break
    else:
        rec["category"] = "other"
    return rec


def _codesign(exe: str) -> str:
    try:
        import subprocess
        p = subprocess.run(["/usr/bin/codesign", "-v", "--strict", exe],
                           capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=8)
        if p.returncode == 0:
            return "valid"
        err = (p.stderr or "").strip()
        if "not signed" in err:
            return "unsigned"
        if "code object is not signed at all" in err:
            return "unsigned"
        return "invalid"
    except Exception:
        return "unknown"


class Inventory:
    def __init__(self, cfg: Dict[str, Any], store):
        self.cfg = cfg
        self.store = store
        self.dir = cfg.get("data_dir") or os.path.expanduser("~/.atfield")
        self.cve_path = os.path.join(self.dir, "cve_map.json")
        self.sign_path = os.path.join(self.dir, "codesign.json")
        self.cve: Dict[str, List[dict]] = {}
        self.sign_cache: Dict[str, dict] = {}
        self._load_cve()
        self._load_sign()
        self.last: Dict[str, Any] = {}
        self.ts = 0.0
        self.scanning = False
        store.set_state("inventory", {"apps": 0, "ts": 0})

    def _load_sign(self) -> None:
        try:
            with open(self.sign_path, "r", encoding="utf-8") as fh:
                self.sign_cache = json.load(fh) or {}
        except Exception:
            self.sign_cache = {}

    def _save_sign(self) -> None:
        try:
            tmp = self.sign_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.sign_cache, fh)
            os.replace(tmp, self.sign_path)
        except Exception:
            pass

    def _sign(self, exe: str) -> str:
        rec = self.sign_cache.get(exe)
        if rec and time.time() - float(rec.get("ts") or 0) < SIGN_CACHE_DAYS * 86400:
            return str(rec.get("v") or "unknown")
        val = _codesign(exe)
        self.sign_cache[exe] = {"v": val, "ts": time.time()}
        return val

    def scan_async(self) -> Dict[str, Any]:
        """后台扫描：第一次调用可能要几秒，不能让 HTTP 请求等。"""
        if self.scanning:
            return {"ok": True, "running": True, "detail": "扫描进行中"}
        self.scanning = True

        def _run():
            try:
                self.scan()
            finally:
                self.scanning = False

        threading.Thread(target=_run, daemon=True, name="atfield-inventory").start()
        return {"ok": True, "running": True, "detail": "已在后台开始扫描"}

    def _load_cve(self) -> None:
        try:
            with open(self.cve_path, "r", encoding="utf-8") as fh:
                self.cve = json.load(fh) or {}
        except Exception:
            self.cve = {}

    def import_cve(self, text: str) -> Dict[str, Any]:
        """导入形式：JSON {"产品关键字": [{"cve":..., "fixed_in":..., "note":...}]}"""
        try:
            data = json.loads(text)
            if not isinstance(data, dict):
                return {"ok": False, "detail": "需要 JSON 对象：{产品关键字: [{cve, fixed_in, note}]}"}
            self.cve.update({k.lower(): v for k, v in data.items()})
            tmp = self.cve_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.cve, fh, ensure_ascii=False, indent=1)
            os.replace(tmp, self.cve_path)
            self.store.log_action("analyst", "cve:import", str(len(data)), "已导入 CVE 映射表")
            return {"ok": True, "detail": f"已导入 {len(data)} 个产品的 CVE 映射"}
        except Exception as exc:
            return {"ok": False, "detail": f"解析失败：{type(exc).__name__}: {exc}"}

    def scan(self) -> Dict[str, Any]:
        apps: List[dict] = []
        for root in APP_DIRS:
            if not os.path.isdir(root):
                continue
            try:
                for name in sorted(os.listdir(root)):
                    if not name.endswith(".app"):
                        continue
                    rec = _app_record(os.path.join(root, name))
                    if rec:
                        apps.append(rec)
            except Exception:
                continue

        # 签名校验：只查「值得查」的（用户装/远程控制/安全/开发），并限流+缓存
        budget = SIGN_MAX_CHECKS
        for a in apps:
            if budget <= 0:
                break
            worth = (a.get("category") in ("remote", "security", "dev")
                     or a["path"].startswith((os.path.expanduser("~/Applications"),
                                              "/Applications")))
            if not worth or not a.get("executable"):
                continue
            exe = os.path.join(a["path"], "Contents", "MacOS", a["executable"])
            if os.path.exists(exe):
                a["signed"] = self._sign(exe)
                budget -= 1
        self._save_sign()

        # CVE 对照：只在版本号字面比较不了的情况下做「疑似」标注，不给结论式定罪
        for a in apps:
            hits: List[dict] = []
            low = (a["name"] + " " + a["bundle_id"]).lower()
            for key, entries in self.cve.items():
                if key in low:
                    for e in entries:
                        if e.get("fixed_in") and a.get("version") and \
                                _ver_lt(a["version"], str(e["fixed_in"])):
                            hits.append(dict(e, vendor_key=key))
            a["cve_candidates"] = hits

        stale = [a for a in apps if a.get("age_days", -1) > STALE_DAYS]
        unsigned = [a for a in apps if a.get("signed") == "invalid"]
        remote = [a for a in apps if a.get("category") == "remote"]
        security = [a for a in apps if a.get("category") == "security"]
        cve_hit = [a for a in apps if a.get("cve_candidates")]

        self.last = {
            "ts": time.time(),
            "apps": len(apps),
            "stale": stale[:60],
            "stale_count": len(stale),
            "unsigned": unsigned[:60],
            "unsigned_count": len(unsigned),
            "remote": remote,
            "security_tools": security,
            "cve_hits": cve_hit,
            "cve_map_size": len(self.cve),
            "by_category": {c: sum(1 for a in apps if a.get("category") == c)
                            for c in list(SENSITIVE_CATEGORIES) + ["other"]},
            "items": apps,
        }
        self.store.set_state("inventory", self.last)
        return self.last

    def status(self) -> Dict[str, Any]:
        if not self.last:
            return {"apps": 0, "ts": 0, "note": "尚未扫描"}
        return {k: v for k, v in self.last.items() if k != "items"}


def _ver_lt(a: str, b: str) -> bool:
    def parts(v: str):
        out = []
        for seg in v.replace("-", ".").replace("_", ".").split("."):
            num = "".join(ch for ch in seg if ch.isdigit())
            out.append(int(num) if num else 0)
        return out
    pa, pb = parts(a), parts(b)
    n = max(len(pa), len(pb))
    pa += [0] * (n - len(pa))
    pb += [0] * (n - len(pb))
    return pa < pb
