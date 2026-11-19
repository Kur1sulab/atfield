"""防误封层 · warninglist 前置过滤（离线，纯标准库）。

任何 IOC 命中先过这一层：命中 allowlist 直接放行（match 返回 None），
避免把 RFC1918 / 回环 / 云与 CDN 共享段 / sinkhole 保留段当成恶意基础设施。
实案锚点：Cloudflare 奥地利事件——封 11 个 Cloudflare IP 导致数千站点连带断 2 天。

内置清单是**最小可用快照**（不联网、不声称实时）：
- RFC1918 三段 + 回环 + 链路本地 + CGNAT（RFC6598）
- Cloudflare 公布 IPv4 段（cloudflare.com/ips-v4 的常见快照）+ Fastly 常见段
- 公共 DNS 解析器（Google / Cloudflare）
- 文档/测试保留段（RFC5737 TEST-NET、RFC2544 基准段、2001:db8::/32）与已知 sinkhole

更全的名单（MISP warninglists，CC0 1.0，git 离线分发）通过本地文件加载：
- MISP JSON：{"name": ..., "type": "cidr"|"string", "list": [...]}
- 纯文本：每行一个 CIDR / IP / 域名，支持 # 与 ; 注释
默认还会扫 <data_dir>/warninglists/ 目录（存在才读）。全部离线，失败静默计数。
"""
from __future__ import annotations

import ipaddress
import json
import os
from typing import Any, Dict, List, Optional, Tuple, Union

# (网段, 标签) —— 内置最小可用 allowlist
BUILTIN_ALLOWLIST: Tuple[Tuple[str, str], ...] = (
    # RFC1918 私网三段
    ("10.0.0.0/8", "RFC1918 私网"),
    ("172.16.0.0/12", "RFC1918 私网"),
    ("192.168.0.0/16", "RFC1918 私网"),
    # 回环 / 链路本地 / CGNAT
    ("127.0.0.0/8", "回环"),
    ("::1/128", "回环 IPv6"),
    ("169.254.0.0/16", "链路本地"),
    ("fe80::/10", "链路本地 IPv6"),
    ("100.64.0.0/10", "CGNAT 共享地址（RFC6598）"),
    # Cloudflare 公布 IPv4 段（快照，非实时同步）
    ("173.245.48.0/20", "Cloudflare CDN"),
    ("103.21.244.0/22", "Cloudflare CDN"),
    ("103.22.200.0/22", "Cloudflare CDN"),
    ("103.31.4.0/22", "Cloudflare CDN"),
    ("141.101.64.0/18", "Cloudflare CDN"),
    ("108.162.192.0/18", "Cloudflare CDN"),
    ("190.93.240.0/20", "Cloudflare CDN"),
    ("188.114.96.0/20", "Cloudflare CDN"),
    ("197.234.240.0/22", "Cloudflare CDN"),
    ("198.41.128.0/17", "Cloudflare CDN"),
    ("162.158.0.0/15", "Cloudflare CDN"),
    ("104.16.0.0/13", "Cloudflare CDN"),
    ("104.24.0.0/14", "Cloudflare CDN"),
    ("172.64.0.0/13", "Cloudflare CDN"),
    ("131.0.72.0/22", "Cloudflare CDN"),
    # 其他云/CDN 常见段与公共 DNS
    ("151.101.0.0/16", "Fastly CDN"),
    ("8.8.8.8/32", "Google 公共 DNS"),
    ("8.8.4.4/32", "Google 公共 DNS"),
    ("1.1.1.1/32", "Cloudflare 公共 DNS"),
    ("1.0.0.1/32", "Cloudflare 公共 DNS"),
    # 文档/测试保留段（常被 sinkhole / 实验占用，永不该当真实 IOC 封禁）
    ("192.0.2.0/24", "TEST-NET-1 保留段（RFC5737）"),
    ("198.51.100.0/24", "TEST-NET-2 保留段（RFC5737）"),
    ("203.0.113.0/24", "TEST-NET-3 保留段（RFC5737）"),
    ("198.18.0.0/15", "基准测试保留段（RFC2544）"),
    ("2001:db8::/32", "文档保留段 IPv6（RFC3849）"),
    ("87.106.124.183/32", "Shadowserver sinkhole（历史已知快照）"),
)


class WarningLists:
    """网段 + 域名双通道 allowlist。check_* 返回命中标签，未命中返回 None。"""

    def __init__(self) -> None:
        self._nets: List[Tuple[Any, str]] = []
        self._net_keys: set = set()
        self._domains: Dict[str, str] = {}
        self.sources: List[str] = ["builtin"]
        self.errors: List[str] = []

    # ---------- 构建 ----------
    def add_cidr(self, cidr: str, label: str = "warninglist") -> bool:
        try:
            net = ipaddress.ip_network(str(cidr).strip(), strict=False)
        except Exception:
            return False
        key = str(net)
        if key in self._net_keys:
            return True
        self._net_keys.add(key)
        self._nets.append((net, label))
        return True

    def add_domain(self, domain: str, label: str = "warninglist") -> bool:
        d = str(domain).strip().lower().strip(".")
        if not d or "/" in d:
            return False
        self._domains.setdefault(d, label)
        return True

    def _add_auto(self, item: str, label: str) -> None:
        v = str(item).strip()
        if not v:
            return
        if self.add_cidr(v, label):
            return
        self.add_domain(v, label)

    def load_file(self, path: str) -> Dict[str, Any]:
        """离线加载单个本地文件：MISP warninglist JSON 或纯文本 CIDR/域名列表。"""
        name = os.path.basename(path)
        before = len(self._nets) + len(self._domains)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                text = fh.read()
        except Exception as exc:
            self.errors.append(f"{name}: {exc}")
            return {"ok": False, "file": name, "added": 0}
        label = name
        items: List[str] = []
        kind = ""
        stripped = text.lstrip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                obj = json.loads(text)
                if isinstance(obj, dict):
                    label = str(obj.get("name") or name)
                    kind = str(obj.get("type") or "").lower()
                    items = [str(x) for x in (obj.get("list") or [])]
                elif isinstance(obj, list):
                    items = [str(x) for x in obj]
            except Exception as exc:
                self.errors.append(f"{name}: JSON 解析失败 {exc}")
                return {"ok": False, "file": name, "added": 0}
        else:
            for line in text.splitlines():
                line = line.split("#", 1)[0].split(";", 1)[0].strip()
                if line:
                    items.append(line)
        for it in items:
            if kind == "cidr":
                if not self.add_cidr(it, label):
                    self.errors.append(f"{name}: 非法网段 {it}")
            elif kind in ("string", "domain", "hostname"):
                self.add_domain(it, label)
            else:
                self._add_auto(it, label)
        added = len(self._nets) + len(self._domains) - before
        self.sources.append(name)
        return {"ok": True, "file": name, "added": added}

    def load_dir(self, directory: str) -> int:
        if not directory or not os.path.isdir(directory):
            return 0
        n = 0
        for fn in sorted(os.listdir(directory)):
            if fn.lower().endswith((".json", ".txt", ".list")):
                if self.load_file(os.path.join(directory, fn)).get("ok"):
                    n += 1
        return n

    # ---------- 查询 ----------
    def check_ip(self, ip: Union[str, Any]) -> Optional[str]:
        try:
            addr = ip if not isinstance(ip, str) else ipaddress.ip_address(ip.strip())
        except Exception:
            return None
        for net, label in self._nets:
            if addr.version == net.version and addr in net:
                return label
        return None

    def check_domain(self, host: str) -> Optional[str]:
        h = str(host or "").lower().strip(".")
        if not h:
            return None
        for d, label in self._domains.items():
            if h == d or h.endswith("." + d):
                return label
        return None

    def stats(self) -> Dict[str, Any]:
        return {
            "networks": len(self._nets),
            "domains": len(self._domains),
            "sources": list(self.sources),
            "errors": list(self.errors),
        }


def build_warninglists(files: Optional[List[str]] = None,
                       directory: Optional[str] = None) -> WarningLists:
    """内置快照 + 显式文件列表 + 目录扫描（全部离线）。"""
    wl = WarningLists()
    for cidr, label in BUILTIN_ALLOWLIST:
        wl.add_cidr(cidr, label)
    for f in files or []:
        if f:
            wl.load_file(str(f))
    wl.load_dir(directory or "")
    return wl
