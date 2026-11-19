"""威胁情报（TI）：本地 IOC 库 + 导入 + 匹配。

不内置任何伪造的「真实情报」——只内置**类别规则**（动态 DNS 域、匿名代理域、
一次性托管域），这些是可辩护的高风险类别，而不是编造具体 IOC。
真实 IOC 由使用方通过 CSV / JSON 导入（可对接 MISP、STIX、EDR 导出）。
"""
from __future__ import annotations

import csv
import io
import json
import os
import time
from typing import Any, Dict, List, Optional

# 高风险「类别」而非具体情报：动态 DNS / 隧道 / 匿名托管——攻击者常用其规避封禁
RISKY_DOMAIN_SUFFIX = (
    ".duckdns.org", ".ngrok.io", ".ngrok-free.app", ".trycloudflare.com",
    ".serveo.net", ".localtunnel.me", ".hopto.org", ".zapto.org", ".sytes.net",
    ".ddns.net", ".no-ip.org", ".dyndns.org", ".3utilities.com", ".bounceme.net",
    ".loca.lt", ".pagekite.me", ".telebit.io", ".portmap.io",
)

# 一次性/隐私托管 TLD
RISKY_TLD = (".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".click", ".pw")


class Intel:
    def __init__(self, cfg: Dict[str, Any], store):
        self.cfg = cfg
        self.store = store
        self.path = os.path.join(cfg.get("data_dir") or os.path.expanduser("~/.atfield"),
                                 "intel.json")
        self.data: Dict[str, Dict[str, dict]] = {"ip": {}, "domain": {}, "hash": {}}
        self._load()
        store.set_state("intel", self.stats())

    # ---------- 持久化 ----------
    def _load(self) -> None:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                raw = json.load(fh) or {}
            for kind in self.data:
                self.data[kind] = raw.get(kind) or {}
        except Exception:
            pass

    def _save(self) -> None:
        try:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.data, fh, ensure_ascii=False, indent=1)
            os.replace(tmp, self.path)
        except Exception:
            pass

    # ---------- 增删 ----------
    def add(self, kind: str, value: str, source: str = "manual", note: str = "",
            confidence: str = "medium") -> Dict[str, Any]:
        kind = (kind or "").lower().strip()
        value = (value or "").strip()
        if kind not in self.data:
            return {"ok": False, "detail": f"未知类型 {kind}（支持 ip/domain/hash）"}
        if not value:
            return {"ok": False, "detail": "值为空"}
        self.data[kind][value.lower()] = {
            "value": value, "source": source, "note": note,
            "confidence": confidence, "added": time.time(),
        }
        self._save()
        self.store.set_state("intel", self.stats())
        self.store.log_action("analyst", "intel:add", f"{kind}:{value}", source)
        return {"ok": True, "detail": f"已加入情报库 {kind}:{value}"}

    def remove(self, kind: str, value: str) -> Dict[str, Any]:
        kind, value = (kind or "").lower(), (value or "").strip().lower()
        if kind in self.data and value in self.data[kind]:
            self.data[kind].pop(value, None)
            self._save()
            self.store.set_state("intel", self.stats())
            return {"ok": True, "detail": "已移除"}
        return {"ok": False, "detail": "库中不存在"}

    def import_text(self, text: str, kind: str = "auto", source: str = "import") -> Dict[str, Any]:
        """支持 CSV（type,value[,note]）与逐行纯值（自动判类型）。"""
        rows = 0
        added = 0
        reader = csv.reader(io.StringIO(text))
        for row in reader:
            if not row:
                continue
            rows += 1
            if len(row) >= 2 and row[0].strip().lower() in ("ip", "domain", "hash"):
                k, v = row[0].strip().lower(), row[1].strip()
                note = row[2].strip() if len(row) > 2 else ""
            else:
                v = row[0].strip()
                k = self._guess_kind(v)
                note = row[1].strip() if len(row) > 1 else ""
            if not v or v.startswith("#"):
                continue
            if self.add(k, v, source=source, note=note).get("ok"):
                added += 1
        return {"ok": True, "rows": rows, "added": added}

    def _guess_kind(self, v: str) -> str:
        try:
            import ipaddress
            ipaddress.ip_address(v)
            return "ip"
        except Exception:
            pass
        if len(v) in (32, 40, 64) and all(c in "0123456789abcdef" for c in v.lower()):
            return "hash"
        return "domain"

    # ---------- 匹配 ----------
    def match_ip(self, ip: str) -> Optional[dict]:
        if not ip:
            return None
        hit = self.data["ip"].get(str(ip).lower())
        return dict(hit, matched_kind="ip") if hit else None

    def match_domain(self, host: str) -> Optional[dict]:
        if not host:
            return None
        h = str(host).lower().strip(".")
        exact = self.data["domain"].get(h)
        if exact:
            return dict(exact, matched_kind="domain", rule="exact")
        for suffix in RISKY_DOMAIN_SUFFIX:
            if h.endswith(suffix):
                return {"value": h, "matched_kind": "domain", "rule": "risky_category",
                        "note": f"动态 DNS / 隧道服务（{suffix}）——常用于规避封禁",
                        "confidence": "medium", "source": "builtin-category"}
        for tld in RISKY_TLD:
            if h.endswith(tld):
                return {"value": h, "matched_kind": "domain", "rule": "risky_tld",
                        "note": f"高滥用率 TLD（{tld}）", "confidence": "low",
                        "source": "builtin-category"}
        return None

    def match_hash(self, h: str) -> Optional[dict]:
        if not h:
            return None
        hit = self.data["hash"].get(str(h).lower())
        return dict(hit, matched_kind="hash") if hit else None

    def stats(self) -> Dict[str, Any]:
        return {
            "ip": len(self.data["ip"]),
            "domain": len(self.data["domain"]),
            "hash": len(self.data["hash"]),
            "builtin_categories": len(RISKY_DOMAIN_SUFFIX) + len(RISKY_TLD),
            "path": self.path,
            "ts": time.time(),
        }

    def listing(self, limit: int = 200) -> List[dict]:
        out: List[dict] = []
        for kind in ("ip", "domain", "hash"):
            for v in list(self.data[kind].values())[-limit:]:
                out.append(dict(v, kind=kind))
        return out
