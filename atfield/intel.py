"""威胁情报（本地优先）：IOC 库 + 内置恶意域名类别 + CIDR 匹配 + 防误封闸门。

数据源策略（与全项目一致：默认零联网）：
- 本地 IOC 库：data_dir/intel.json，分析师手工录入或从本地文件导入
  （MISP 导出 CSV / 纯文本均可，逐行 type,value[,note[,confidence]]）。
- Spamhaus DROP / FireHOL 那种**网段条目**（1.2.3.0/24）直接可导入可命中。
- 内置类别规则：动态 DNS / 免费域名 / 隧道服务常见后缀，离线可用，
  只作「可疑」信号（medium/low），不作封禁依据，也不参与评分升级。
- 可选：用户自行配置在线情报源 URL（默认全空，绝不自动外联）。

防误封四层（依据 defense-landscape/11-threat-intel.md §5.2/5.3/5.5）：
① CIDR 匹配：ipaddress.ip_network 包含判断，单 IP 与网段条目同库共存；
② warninglist 前置：任何 IP 命中先过 intel_warnings 的 allowlist
   （RFC1918/回环/云与 CDN 共享段/sinkhole 保留段 + 本地 MISP 风格文件），
   命中 allowlist 直接返回 None——「封 IP」前默认排除共享基础设施；
③ 生命周期闸门：条目带 first_seen/last_seen/ttl_days/decay_score，
   score = CONF_MAP[confidence] × MISP 衰减(now-last_seen, tau[kind], delta[kind])，
   score ≥ 0.7 → critical，≥ 0.4 → high，其余 medium（AEG-043 定级闸门）。
   过期降级不删除：block → alert → archive。本地匹配**不**自动重置 last_seen
   （连着旧 IOC 不等于它仍恶意）；重置走显式 sight() 或重新导入。
④ 向后兼容：老格式 intel.json（只有 value/source/note/confidence/added）
   惰性补默认值平滑加载，旧字段一律保留；match 返回只增字段不改旧字段。

注意：match 返回里的 severity 是闸门定级结果。AEG-043（rules_builtin，读
cfg.ioc）与 netintel._flag 目前仍写死 critical/high，接线消费 hit["severity"]
属于规则层改动，不在本模块文件范围内（见交付说明「未完成」）。
"""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import os
import re
import time
from typing import Any, Dict, List, Optional

from .intel_warnings import WarningLists, build_warninglists

RISKY_TLDS = {".xyz", ".top", ".gq", ".tk", ".ml", ".cf", ".buzz", ".icu",
              ".cyou", ".monster", ".quest", ".rest"}
DYNAMIC_DNS = ("duckdns.org", "no-ip.com", "no-ip.org", "ddns.net", "hopto.org",
               "zapto.org", "sytes.net", "servebeer.com", "myftp.org",
               "dynu.com", "freeddns.org", "changeip.com", "3322.org",
               "f3322.net", "vicp.net", "oray.com", "gnway.net")
TUNNEL_HINTS = ("ngrok.io", "ngrok-free.app", "trycloudflare.com",
                "localtunnel.me", "serveo.net", "pagekite.me")

KINDS = ("ip", "domain", "hash")

# STIX 2.1 Appendix A 置信度词表 → 数值（Low 15 / Medium 50 / High 85）
CONF_MAP = {"low": 0.15, "medium": 0.50, "high": 0.85}
# MISP decay_score = base × (1 − (t/τ)^(1/δ))，按类型分档（锚点见 11-threat-intel §5.3）
DECAY_PARAMS = {"ip": (7.0, 0.55), "domain": (60.0, 0.5), "hash": (180.0, 0.3)}
DEFAULT_TTL_DAYS = {"ip": 7, "domain": 90, "hash": 180}
CRITICAL_AT = 0.7
HIGH_AT = 0.4
DAY_S = 86400.0


def decay_factor(age_days: float, tau: float, delta: float) -> float:
    """MISP 衰减模型：t=0 → 1，t≥τ → 0；δ 越小尾部衰减越快。"""
    if age_days <= 0:
        return 1.0
    if tau <= 0 or delta <= 0:
        return 0.0
    return max(0.0, 1.0 - (age_days / tau) ** (1.0 / delta))


def score_to_severity(score: float) -> str:
    """AEG-043 评分闸门：≥0.7 critical / ≥0.4 high / 其余 medium。"""
    if score >= CRITICAL_AT:
        return "critical"
    if score >= HIGH_AT:
        return "high"
    return "medium"


# 2026-11-19 接线：三处调用点（AEG-043 / NetIntel._flag / FUSION_MAP）统一用下面的
# 函数折算定级，禁止任何一处再写死 critical/high。闸门语义：
#   ① 命中必须是闸门算出来的（CIDR 最长前缀 + allowlist 前置 + 置信度衰减）；
#   ② 衰减到期（score=0，即 t ≥ τ）视为「不再计分」，不得再作为定级依据；
#   ③ fail-safe：拿不到闸门结果时只能给到最低档，绝不回落到写死的 critical/high。
SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def hit_counts(hit: Optional[dict]) -> bool:
    """这次命中还算不算分：无命中 / 衰减归零 → False。"""
    if not hit:
        return False
    try:
        return float(hit.get("score") or 0.0) > 0.0
    except (TypeError, ValueError):
        return False


def hit_severity(hit: Optional[dict], default: str = "low") -> str:
    """命中 → 定级。只认闸门的 severity；score 归零或字段缺失时退回 default（不猜高档）。"""
    if not hit_counts(hit):
        return default
    sev = str(hit.get("severity") or "")
    return sev if sev in SEV_RANK else score_to_severity(float(hit.get("score") or 0.0))


def grade_event_severity(ev, intel, fallback: str = "low") -> str:
    """给一条 NDR 事件按情报闸门定级（core.FUSION_MAP 用）。

    取事件主体里的 ip/domain 回查 intel：
      命中且未衰减 → 闸门分档；
      落在 retain/allowlist（私网、保留段、Cloudflare 等）→ 直接压到 low，永不高危；
      无命中 → 交回 fallback（事件自带等级，netintel 侧已过闸门）。
    """
    if intel is None:
        return fallback
    sub = getattr(ev, "subject", None) or {}
    ip = str(sub.get("ip") or sub.get("rip") or "")
    dom = str(sub.get("domain") or "")
    try:
        hit = intel.match_ip(ip) if ip else None
        if hit is None and dom:
            hit = intel.match_domain(dom)
        if hit is not None:
            # 闸门命中即为权威：衰减归零 → 不再计分（low），不回落到事件自带等级
            return hit_severity(hit, "low")
        # 闸门无命中：保留/共享基础设施不得凭事件自带等级抬到 critical/high
        if ip and intel.warnings.check_ip(ip) is not None:
            return "low"
        if dom and intel.warnings.check_domain(dom) is not None:
            return "low"
    except Exception:
        return fallback
    return fallback


def lifecycle_state(age_days: float, ttl_days: float, score: float) -> str:
    """过期降级不删除：block（可作阻断依据）→ alert（只告警）→ archive（归档）。"""
    if age_days <= ttl_days and score >= HIGH_AT:
        return "block"
    if age_days <= 2 * ttl_days:
        return "alert"
    return "archive"


class Intel:
    def __init__(self, cfg: dict, store):
        self.cfg = cfg
        self.store = store
        self.path = os.path.join(cfg["data_dir"], "intel.json")
        self.data: Dict[str, Dict[str, dict]] = {"ip": {}, "domain": {}, "hash": {}}
        self._nets_cache: Optional[List[tuple]] = None
        self._load()
        icfg = cfg.get("intel") if isinstance(cfg.get("intel"), dict) else {}
        files = icfg.get("warninglist_files") or cfg.get("warninglist_files") or []
        wdir = icfg.get("warninglist_dir") or os.path.join(cfg["data_dir"], "warninglists")
        self.warnings: WarningLists = build_warninglists(files=files, directory=wdir)
        self._seed_config()
        self._migrate_save()
        self.store.set_state("intel", self.stats())

    # ---------- 持久化 ----------
    def _load(self) -> None:
        try:
            with open(self.path, encoding="utf-8") as fh:
                raw = json.loads(fh.read())
            for k in KINDS:
                v = raw.get(k)
                if isinstance(v, dict):
                    self.data[k] = v
        except Exception:
            pass
        self._nets_cache = None

    def _normalize(self, kind: str, key: str, entry: Any, now: float) -> dict:
        """惰性补默认值（④向后兼容）：老条目只有 added 也能平滑加载。"""
        if not isinstance(entry, dict):
            entry = {"value": key}
            self.data[kind][key] = entry
        changed = False
        defaults = (
            ("value", key),
            ("source", "unknown"),
            ("note", ""),
            ("confidence", "medium"),
            ("added", now),
        )
        for f, dv in defaults:
            if f not in entry:
                entry[f] = dv
                changed = True
        if entry.get("confidence") not in CONF_MAP:
            entry["confidence"] = "medium"
        if "first_seen" not in entry:
            entry["first_seen"] = entry.get("added") or now
            changed = True
        if "last_seen" not in entry:
            entry["last_seen"] = entry.get("first_seen") or now
            changed = True
        if "ttl_days" not in entry:
            entry["ttl_days"] = DEFAULT_TTL_DAYS[kind]
            changed = True
        return entry

    def _seed_config(self) -> None:
        """把 config.yaml 的 ioc.ips/domains 一次性迁入闸门（接线，2026-11-19）。

        以前 AEG-043 直接拿 cfg["ioc"] 明文比字符串、写死 critical；现在名单必须
        作为 intel 条目进闸门，才有（a）CIDR 最长前缀、（b）allowlist 前置、
        （c）衰减时钟。明文名单没有来源与首次观测时间 → 按 low 置信入闸门
        （0.15 → medium），要 high/critical 必须走 Intel.add/情报导入并给置信度。
        只补缺失键：已存在的条目不覆盖，避免每次重启把衰减时钟重置为 0。
        """
        icfg = self.cfg.get("ioc") if isinstance(self.cfg.get("ioc"), dict) else {}
        now = time.time()
        seeded = 0
        for kind, field in (("ip", "ips"), ("domain", "domains")):
            for raw in (icfg.get(field) or []):
                value = str(raw or "").strip().lower()
                if not value:
                    continue
                key = self._ip_key(value) if kind == "ip" else value
                if not key or key in self.data[kind]:
                    continue
                # 保留/私网段写进 IOC 多半是配置笔误，不进闸门（进了也会被 allowlist 挡，但别污染统计）
                if kind == "ip" and self.warnings.check_ip(key) is not None:
                    continue
                if kind == "domain" and self.warnings.check_domain(key) is not None:
                    continue
                self.data[kind][key] = {
                    "value": key, "source": "config:ioc",
                    "note": "config.yaml ioc 名单迁入（无来源元数据，按低置信计分）",
                    "confidence": "low", "added": now,
                    "first_seen": now, "last_seen": now,
                    "ttl_days": DEFAULT_TTL_DAYS[kind],
                }
                seeded += 1
        if seeded:
            self._save()
            try:
                self.store.log_action("system", "intel:seed-config",
                                      f"{seeded} 条 config ioc 迁入闸门", "ok")
            except Exception:
                pass

    def _migrate_save(self) -> None:
        """老格式升级：补字段后落盘一次（旧字段全保留，失败静默）。"""
        now = time.time()
        changed = False
        for kind in KINDS:
            for key, entry in list(self.data[kind].items()):
                before = json.dumps(entry, sort_keys=True, default=str)
                self._normalize(kind, key, entry, now)
                if json.dumps(entry, sort_keys=True, default=str) != before:
                    changed = True
        if changed:
            self._save()

    def _save(self) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.data, fh, ensure_ascii=False, indent=1)
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except Exception:
            pass
        self.store.set_state("intel", self.stats())

    # ---------- 生命周期评分（③） ----------
    def _gate(self, kind: str, entry: dict, now: float) -> Dict[str, Any]:
        tau, delta = DECAY_PARAMS[kind]
        last = float(entry.get("last_seen") or entry.get("first_seen") or now)
        age_days = max(0.0, (now - last) / DAY_S)
        conf = CONF_MAP.get(entry.get("confidence"), CONF_MAP["medium"])
        d = decay_factor(age_days, tau, delta)
        score = round(conf * d, 4)
        entry["decay_score"] = score
        ttl = float(entry.get("ttl_days") or DEFAULT_TTL_DAYS[kind])
        return {
            "first_seen": entry.get("first_seen"),
            "last_seen": last,
            "ttl_days": ttl,
            "age_days": round(age_days, 3),
            "decay": round(d, 4),
            "score": score,
            "severity": score_to_severity(score),
            "lifecycle": lifecycle_state(age_days, ttl, score),
        }

    # ---------- 录入 ----------
    @staticmethod
    def _ip_key(value: str) -> Optional[str]:
        """单 IP → 规范化地址；网段 → 规范化网络（主机位清零）。非法返回 None。"""
        v = str(value).strip().lower()
        try:
            if "/" in v:
                return str(ipaddress.ip_network(v, strict=False))
            return str(ipaddress.ip_address(v))
        except Exception:
            return None

    def add(self, kind: str, value: str, source: str = "manual",
            note: str = "", confidence: str = "medium",
            first_seen: Optional[float] = None, last_seen: Optional[float] = None,
            ttl_days: Optional[float] = None) -> Dict[str, Any]:
        kind = kind.lower()
        value = (value or "").strip().lower()
        if kind not in KINDS or not value:
            return {"ok": False, "detail": "类型须为 ip/domain/hash 且值非空"}
        if kind == "ip":
            key = self._ip_key(value)
            if key is None:
                return {"ok": False, "detail": f"非法 IP/网段：{value}"}
        else:
            key = value
        now = time.time()
        old = self.data[kind].get(key) or {}
        entry = {
            "value": key, "source": source, "note": note,
            "confidence": confidence if confidence in CONF_MAP else "medium",
            "added": old.get("added") or now,
            # 重新录入/导入 = 一次 sighting：last_seen 重置，first_seen 保留
            "first_seen": first_seen or old.get("first_seen") or now,
            "last_seen": last_seen or now,
            "ttl_days": ttl_days or old.get("ttl_days") or DEFAULT_TTL_DAYS[kind],
        }
        if old.get("suppressed"):
            entry["suppressed"] = True
        self.data[kind][key] = entry
        self._gate(kind, entry, now)
        self._nets_cache = None
        self._save()
        self.store.log_action("analyst", "intel:add", f"{kind}:{key}", "ok")
        return {"ok": True, "detail": f"已录入 {kind} IOC：{key}"}

    def remove(self, kind: str, value: str) -> Dict[str, Any]:
        key = (value or "").strip().lower()
        if kind == "ip":
            key = self._ip_key(key) or key
        if self.data.get(kind, {}).pop(key, None) is None:
            return {"ok": False, "detail": "未找到该 IOC"}
        self._nets_cache = None
        self._save()
        self.store.log_action("analyst", "intel:remove", f"{kind}:{key}", "ok")
        return {"ok": True, "detail": "已删除"}

    def sight(self, kind: str, value: str) -> Dict[str, Any]:
        """显式 sighting：新观测重置衰减时钟（last_seen=now），不删条目。"""
        key = (value or "").strip().lower()
        if kind == "ip":
            key = self._ip_key(key) or key
        entry = self.data.get(kind, {}).get(key)
        if entry is None:
            return {"ok": False, "detail": "未找到该 IOC"}
        now = time.time()
        self._normalize(kind, key, entry, now)
        entry["last_seen"] = now
        self._gate(kind, entry, now)
        self._save()
        self.store.log_action("analyst", "intel:sight", f"{kind}:{key}", "ok")
        return {"ok": True, "detail": f"已重置衰减时钟：{key}"}

    def suppress(self, kind: str, value: str, reason: str = "") -> Dict[str, Any]:
        """IOC 级误报抑制：条目保留（可审计），match 一律返回 None。"""
        key = (value or "").strip().lower()
        if kind == "ip":
            key = self._ip_key(key) or key
        entry = self.data.get(kind, {}).get(key)
        if entry is None:
            return {"ok": False, "detail": "未找到该 IOC"}
        entry["suppressed"] = True
        if reason:
            entry["suppress_reason"] = reason
        self._save()
        self.store.log_action("analyst", "intel:suppress", f"{kind}:{key}", "ok")
        return {"ok": True, "detail": f"已抑制误报：{key}"}

    def import_text(self, text: str, source: str = "import") -> Dict[str, Any]:
        """CSV: type,value[,note[,confidence]]；也接受每行一个域名/IP/网段（自动判类）。

        兼容 Spamhaus DROP / FireHOL 形态：行内 `; 注释` 与整行 #/; 注释会被剥掉。
        """
        ok = bad = 0
        cleaned = []
        for line in (text or "").splitlines():
            line = re.sub(r"\s+;.*$", "", line)      # DROP 行内注释：1.2.3.0/24 ; SBL…
            s = line.strip()
            if s and not s.startswith("#") and not s.startswith(";"):
                cleaned.append(line)
        reader = csv.reader(io.StringIO("\n".join(cleaned)))
        for row in reader:
            if not row:
                continue
            row = [c.strip() for c in row]
            if len(row) >= 2 and row[0].lower() in KINDS:
                kind, value = row[0].lower(), row[1]
                note = row[2] if len(row) > 2 else ""
                conf = row[3].lower() if len(row) > 3 else "medium"
            else:
                value = row[0]
                kind = self._guess_kind(value)
                note, conf = "", "medium"
            if not value or value.startswith("#"):
                continue
            r = self.add(kind, value, source=source, note=note, confidence=conf)
            ok, bad = ok + int(r["ok"]), bad + int(not r["ok"])
        return {"ok": True, "detail": f"导入成功 {ok} 条，跳过 {bad} 条"}

    @staticmethod
    def _guess_kind(v: str) -> str:
        try:
            ipaddress.ip_address(v)
            return "ip"
        except Exception:
            pass
        if "/" in v:
            try:
                ipaddress.ip_network(v, strict=False)
                return "ip"
            except Exception:
                pass
        if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", v):
            return "hash"
        return "domain"

    # ---------- 匹配 ----------
    def _cidr_entries(self) -> List[tuple]:
        if self._nets_cache is None:
            nets = []
            for key in self.data["ip"]:
                if "/" in key:
                    try:
                        nets.append((ipaddress.ip_network(key, strict=False), key))
                    except Exception:
                        continue
            self._nets_cache = nets
        return self._nets_cache

    def match_ip(self, ip: str) -> Optional[dict]:
        """② allowlist 前置 → ① 单 IP 精确 + CIDR 包含（最长前缀优先）→ ③ 评分闸门。"""
        if not ip:
            return None
        raw = str(ip).strip().lower().split("%")[0]
        try:
            addr = ipaddress.ip_address(raw)
        except Exception:
            return None
        if self.warnings.check_ip(addr) is not None:
            return None                       # 共享/保留基础设施：永不命中
        now = time.time()
        key = raw if raw in self.data["ip"] else str(addr)
        entry = self.data["ip"].get(key)
        if entry is None:
            best = None
            for net, nkey in self._cidr_entries():
                if addr.version == net.version and addr in net:
                    if best is None or net.prefixlen > best[0].prefixlen:
                        best = (net, nkey)
            if best is not None:
                key = best[1]
                entry = self.data["ip"].get(key)
        if entry is None:
            return None
        entry = self._normalize("ip", key, entry, now)
        if entry.get("suppressed"):
            return None
        gate = self._gate("ip", entry, now)
        return dict(entry, matched_kind="ip", matched_value=key, **gate)

    def match_domain(self, domain: str) -> Optional[dict]:
        d = (domain or "").lower().strip(".")
        if not d:
            return None
        if self.warnings.check_domain(d) is not None:
            return None
        now = time.time()
        hit = self.data["domain"].get(d)
        if hit is not None:
            hit = self._normalize("domain", d, hit, now)
            if hit.get("suppressed"):
                return None
            gate = self._gate("domain", hit, now)
            return dict(hit, matched_kind="domain", rule="exact", **gate)
        labels = d.split(".")
        for i in range(1, len(labels)):
            parent = ".".join(labels[i:])
            if parent in DYNAMIC_DNS:
                return {"value": parent, "matched_kind": "domain",
                        "rule": "dynamic_dns", "confidence": "medium",
                        "note": "动态 DNS 服务（常被 C2 滥用）", "source": "builtin"}
            if parent in TUNNEL_HINTS:
                return {"value": parent, "matched_kind": "domain",
                        "rule": "tunnel_service", "confidence": "medium",
                        "note": "内网穿透/隧道服务", "source": "builtin"}
        tld = "." + labels[-1]
        if tld in RISKY_TLDS and len(labels) <= 3:
            return {"value": d, "matched_kind": "domain", "rule": "risky_tld",
                    "confidence": "low", "note": f"高风险廉价 TLD {tld}",
                    "source": "builtin"}
        return None

    def match_hash(self, h: str) -> Optional[dict]:
        key = (h or "").lower()
        hit = self.data["hash"].get(key)
        if hit is None:
            return None
        now = time.time()
        hit = self._normalize("hash", key, hit, now)
        if hit.get("suppressed"):
            return None
        gate = self._gate("hash", hit, now)
        return dict(hit, matched_kind="hash", **gate)

    # ---------- 视图 ----------
    def listing(self, kind: str = "", q: str = "", limit: int = 300) -> List[dict]:
        out: List[dict] = []
        now = time.time()
        kinds = (kind,) if kind in KINDS else KINDS
        for k in kinds:
            for key, v in self.data[k].items():
                if q and q.lower() not in json.dumps(v, ensure_ascii=False).lower():
                    continue
                v = self._normalize(k, key, v, now)
                gate = self._gate(k, v, now)
                out.append(dict(v, kind=k, **gate))
        out.sort(key=lambda x: -(x.get("last_seen") or x.get("added") or 0))
        return out[:limit]

    def stats(self) -> Dict[str, Any]:
        now = time.time()
        life = {"block": 0, "alert": 0, "archive": 0}
        for k in KINDS:
            for key, v in self.data[k].items():
                v = self._normalize(k, key, v, now)
                life[self._gate(k, v, now)["lifecycle"]] += 1
        return {
            "ip": len(self.data["ip"]), "domain": len(self.data["domain"]),
            "hash": len(self.data["hash"]),
            "builtin_categories": len(DYNAMIC_DNS) + len(TUNNEL_HINTS) + len(RISKY_TLDS),
            "warninglists": self.warnings.stats(),
            "gate": {"critical_at": CRITICAL_AT, "high_at": HIGH_AT,
                     "conf_map": dict(CONF_MAP),
                     "decay_params": {k: {"tau_days": t, "delta": d}
                                      for k, (t, d) in DECAY_PARAMS.items()}},
            "lifecycle": life,
            "path": self.path, "ts": time.time(),
        }
