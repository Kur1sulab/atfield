"""NDR（主机侧网络检测）：目的地画像 + 心跳/信标检测 + 隧道特征。

非特权也可得的事实：五元组、进程归属、连接时间。基于这些做三件事：
1) 目的地画像：直连 IP（无域名）、高风险端口、动态 DNS 域、非常用端口出网；
2) 信标（beaconing）：同一 (进程, 目的地) 反复连接且间隔极规律 → C2 心跳特征。
   2026-11 重写（research/02-network.md §9 P0）：单一 CV 判据升级为
   抖动 + 持续性 + 周期性多信号打分（退避趋势降分），冷启动基线静默观察，
   告警按置信度×持续性聚合排序、顶层只推少数高置信（学 Darktrace / Vectra 教训）；
3) 端口/协议异常：非浏览器进程连 80/443，或非常见端口组合。
4) DNS 形态判定（dnsintel.py）：域名撞不上 IOC 名单时，再看它「长得像不像人起的」
   ——DGA 随机域 / DNS 隧道编码载荷。命中 watch/suspicious 出 ndr.dga /
   ndr.dns_tunnel 事件，走 _flag 冷却；前 N 个观察暖机只记录不报（cfg.dns）。
"""
from __future__ import annotations

import math
import queue
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from .dnsintel import DnsIntel
from .intel import hit_counts, hit_severity
from .model import Event

# ---------------- 信标检测阈值（多信号打分，全部集中在此便于调参） ----------------
# 取值理由：用合成序列标定（真心跳 / ±10% 轮询 / 宽松轮询 / 退避重连 / 短促突发），
# 回归见 tests/test_beacon.py。旧判据「CV<0.18 即 high」会把 IDE 自动保存、
# 代理轮询、浏览器心跳全部报成 C2，故改为多信号综合分过线才报。
BEACON_MIN_SAMPLES = 8          # 原为 5：5 个样本的 CV 估计噪声太大，≥8 才有统计意义
BEACON_MIN_SPAN_S = 300.0       # 观测跨度(last-first)≥5 分钟：短促突发（编译/同步风暴）不是驻留型 C2
BEACON_MIN_MEAN_GAP_S = 3.0     # 平均间隔下限：亚 3 秒的连接是批量传输不是心跳（沿用旧 mean>3）
BEACON_CV_THRESHOLD = 0.18      # 保留旧 CV 判据作为抖动信号之一：cv=0 满分，cv=0.18 得半分，2 倍(0.36)归零
BEACON_DELTA_REF = 0.25         # 「间隔的间隔」稳定度参考：std(相邻间隔差额)/平均间隔 ≥0.25 记 0 分；
                                # 真心跳不仅间隔稳，连误差（差额）都稳；随机轮询的差额会来回跳
BEACON_PERIODIC_BAND = 0.10     # 周期性带宽：落在均值 ±10% 内的间隔比例，比例越高越像心跳
BEACON_PERSIST_FULL_S = 1800.0  # 持续性满分跨度：连续观测 30 分钟记满分（占持续性一半权重）
BEACON_PERSIST_FULL_N = 30      # 持续性满分样本数：≥30 个样本记满分（占持续性一半权重）
BEACON_TREND_FREE = 0.10        # 趋势免罚区：相对漂移 ≤10% 不扣分（容忍时钟/调度微漂）
BEACON_TREND_FULL = 0.50        # 趋势满罚点：相对漂移 ≥50%（典型重连退避）扣满
BEACON_TREND_PENALTY = 0.35     # 趋势最大扣分：间隔递增/递减 = 重连退避，不是心跳，直接从综合分里扣
BEACON_W_CV = 0.28              # 权重：CV 抖动（旧判据降级为信号之一，不再单独触发）
BEACON_W_DELTA = 0.12           # 权重：间隔差额稳定性
BEACON_W_PERIODIC = 0.38        # 权重：周期性（均值 ±10% 带内比例）
BEACON_W_PERSIST = 0.22         # 权重：持续性（跨度 + 样本数）；四项权重和为 1.0
BEACON_SCORE_THRESHOLD = 0.60   # 综合分触发线：要求多数信号同时强；±10% 规律轮询仍会过线（时序上
                                # 与心跳不可分，交给冷启动基线与排序漏斗收敛噪声），宽松轮询/退避被拦下
BEACON_BASELINE_N = 12          # 冷启动：每个 (进程,目的地) 前 12 次连接只建基线不告警，第 13 次起才判
                                # （Darktrace 教训：冷启动期静默观察，不把陌生行为当异常）
BEACON_TOP_N = 5                # Vectra 漏斗：顶层只推置信度×持续性最高的前 5 条
NDR_FLAG_COOLDOWN_S = 900.0     # 同一 (类型,进程,目的地) 告警冷却 15 分钟（沿用旧 _flag 机制）

BROWSER_HINTS = ("safari", "chrome", "firefox", "edge", "arc", "brave", "opera",
                 "com.apple.webkit", "webcontent")
STANDARD_WEB_PORTS = {80, 443, 8080, 8443}


def _hostname_of(ip: str) -> str:
    try:
        import socket
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


class NetIntel:
    def __init__(self, cfg: Dict[str, Any], store, intel=None):
        self.cfg = cfg
        self.store = store
        self.intel = intel
        self.hist: Dict[Tuple[str, str], List[float]] = {}
        self.dest: Dict[str, dict] = {}          # ip -> 画像
        self.beacons: Dict[str, dict] = {}
        self.flags: List[dict] = []
        self._resolved: Dict[str, str] = {}
        self._last_run = 0.0
        self._flag_seen: Dict[str, float] = {}
        self.flag_cooldown = NDR_FLAG_COOLDOWN_S  # 同一 (类型, 进程, 目的地) 15 分钟内只报一次
        self._rq: "queue.Queue[str]" = queue.Queue()
        self._resolver_started = False
        # 冷启动基线学习：前 N 次连接只观察不告警
        self._seen: Dict[Tuple[str, str], int] = {}       # (进程,目的地) -> 累计连接数
        self._baseline: Dict[Tuple[str, str], dict] = {}  # (进程,目的地) -> 基线期学到的间隔画像
        # DNS 形态判定（DGA / 隧道启发式）：不看域名坏不坏，看长得像不像人起的。
        # 冷启动纪律：前 N 个观察只记录不报（cfg.dns.warmup_observations，默认 50）。
        dns_cfg = cfg.get("dns", {}) or {}
        self.dns = DnsIntel(warmup_observations=int(dns_cfg.get("warmup_observations", 50)))

    def _start_resolver(self) -> None:
        """反向解析放到后台线程：gethostbyaddr 可能卡 5 秒，绝不能阻塞采集链路。"""
        if self._resolver_started:
            return
        self._resolver_started = True

        def loop() -> None:
            while True:
                ip = self._rq.get()
                host = ""
                try:
                    host = _hostname_of(ip)
                except Exception:
                    host = ""
                self._resolved[ip] = host
                d = self.dest.get(ip)
                if d is not None and not d.get("hostname"):
                    d["hostname"] = host

        threading.Thread(target=loop, daemon=True, name="atfield-rdns").start()

    # ---------- 观测 ----------
    def observe(self, events: List[Event]) -> List[Event]:
        out: List[Event] = []
        now = time.time()
        for ev in events:
            if ev.kind != "net.connect":
                continue
            sub = ev.subject or {}
            rip = str(sub.get("rip") or "")
            rport = int(sub.get("rport") or 0)
            if not rip:
                continue
            proc = (ev.process or "").lower()
            key = (proc, rip)
            self.hist.setdefault(key, []).append(ev.ts or now)
            self.hist[key] = self.hist[key][-120:]

            # ---- 目的地画像 ----
            prof = self.dest.setdefault(rip, {
                "ip": rip, "first": ev.ts or now, "count": 0,
                "ports": {}, "processes": {}, "hostname": None, "flags": [],
            })
            prof["count"] += 1
            prof["ports"][str(rport)] = prof["ports"].get(str(rport), 0) + 1
            prof["processes"][ev.process or "?"] = prof["processes"].get(ev.process or "?", 0) + 1

            if prof["hostname"] is None:
                if rip in self._resolved:
                    prof["hostname"] = self._resolved[rip]
                else:
                    self._start_resolver()
                    try:
                        self._rq.put_nowait(rip)
                    except Exception:
                        pass
                    prof["hostname"] = ""       # 解析中：先不判定「无域名」

            is_public = bool(sub.get("public"))
            browser = any(h in proc for h in BROWSER_HINTS)
            resolved_no_name = (rip in self._resolved and self._resolved[rip] == "")

            # 直连 IP 且反查确认无域名，且不是浏览器
            if is_public and not browser and resolved_no_name:
                self._flag(out, ev, "direct_ip",
                           f"非浏览器进程 {ev.process} 直连未解析域名的公网 IP {rip}",
                           "medium", {"ip": rip, "port": rport})

            # 高风险端口
            if is_public and sub.get("risky_port"):
                self._flag(out, ev, "risky_port",
                           f"{ev.process} 连接高风险端口 {rip}:{rport}（常见 C2/远控端口）",
                           "high", {"ip": rip, "port": rport})

            # 动态 DNS / 隧道域
            host = prof["hostname"] or ""
            if host and self.intel:
                hit = self.intel.match_domain(host)
                if hit:
                    self._flag(out, ev, "risky_domain",
                               f"{ev.process} 连接 {host}（{hit.get('note')}）",
                               "medium" if hit.get("rule") == "exact" else "low",
                               {"ip": rip, "domain": host, "rule": hit.get("rule")})

            # 情报闸门：IP 命中不依赖反查到的域名 —— 直连 IP（反查无果）恰恰最该查 IOC。
            # 等级由 intel（CIDR 最长前缀 + allowlist + 置信度衰减）算，_flag 内再兜一次。
            if self.intel:
                hh = self.intel.match_ip(rip)
                if hit_counts(hh):
                    self._flag(out, ev, "ioc_ip",
                               f"{ev.process} 连接情报库命中 IP {rip}"
                               f"（来源 {hh.get('source')}，分数 {hh.get('score')}，"
                               f"{hh.get('lifecycle') or ''}）",
                               hit_severity(hh, "low"),
                               {"ip": rip, "source": hh.get("source"),
                                "score": hh.get("score"),
                                "gate_severity": hh.get("severity")})

            # ---- DNS 形态判定：与 IOC 名单无关，名单里没有的域名也要过一遍 ----
            # 暖机期 dns.observe 对外一律返回 ok，这里天然不会出事件（冷启动纪律）。
            if host:
                drec = self.dns.observe(host, ev.process or "")
                if drec["verdict"] in ("watch", "suspicious"):
                    kind = "dns_tunnel" if drec["kind"] == "tunnel" else "dga"
                    sev = "medium" if drec["verdict"] == "suspicious" else "low"
                    label = "DNS 隧道" if kind == "dns_tunnel" else "疑似 DGA"
                    sig = "、".join(drec["signals"][:4]) or "形态异常"
                    self._flag(out, ev, kind,
                               f"{ev.process} 外联形态异常域名 {host}"
                               f"（{label} {drec['score']:.2f}：{sig}）",
                               sev, {"ip": rip, "domain": host,
                                     "score": drec["score"], "verdict": drec["verdict"],
                                     "signals": drec["signals"]})

            # ---- 冷启动基线：每个 (进程,目的地) 前 N 次连接只学习不告警 ----
            cnt = self._seen.get(key, 0) + 1
            self._seen[key] = cnt
            if cnt == BEACON_BASELINE_N:
                self._learn_baseline(key, ev.ts or now)

            # ---- 信标检测（多信号打分；只针对公网对端：回环/内网轮询是本地代理与 IDE 的正常行为）----
            stamps = sorted(self.hist[key])
            if is_public and cnt > BEACON_BASELINE_N:
                sig = self._beacon_signals(stamps)
                if sig and sig["score"] >= BEACON_SCORE_THRESHOLD:
                    bid = f"{proc}->{rip}"
                    prev = self.beacons.get(bid) or {}
                    self.beacons[bid] = {
                        "id": bid, "process": ev.process, "ip": rip,
                        "port": rport, "interval_s": sig["mean"],
                        "cv": sig["cv"], "samples": len(stamps),
                        "first": stamps[0], "last": stamps[-1],
                        "hits": int(prev.get("hits") or 0) + 1,
                        "hostname": prof["hostname"],
                        # 新增打分细节（旧字段全部保留，UI/报告兼容）
                        "score": sig["score"], "persist": sig["persist"],
                        "span_s": sig["span"], "periodic": sig["periodic"],
                        "delta_ratio": sig["delta_ratio"],
                        "trend_ratio": sig["trend_ratio"],
                        "signals": sig["signals"],
                    }
                    if self.beacons[bid]["hits"] % 3 == 1:   # 节流告警
                        self._flag(out, ev, "beaconing",
                                   f"{ev.process} 到 {rip}:{rport} 呈规律心跳"
                                   f"（间隔 {sig['mean']}s，波动 {round(sig['cv']*100,1)}%，"
                                   f"持续 {round(sig['span']/60)} 分钟，置信 {sig['score']}）",
                                   "high", {"ip": rip, "port": rport,
                                            "interval": sig["mean"],
                                            "score": sig["score"]})
        self._last_run = now
        self.store.set_state("netintel", self.status())
        return out

    # ---------- 信标：冷启动基线 + 多信号打分 ----------
    def _learn_baseline(self, key: Tuple[str, str], ts: float) -> None:
        """冷启动期结束：把前 N 次连接的间隔画像固化为基线（只观察，不告警）。"""
        stamps = sorted(self.hist.get(key) or [])
        if len(stamps) < 2:
            return
        gaps = [b - a for a, b in zip(stamps, stamps[1:]) if b > a]
        if not gaps:
            return
        mean = sum(gaps) / len(gaps)
        cv = math.sqrt(sum((g - mean) ** 2 for g in gaps) / len(gaps)) / mean if mean else 0.0
        self._baseline[key] = {"n": len(stamps), "mean_gap_s": round(mean, 1),
                               "cv": round(cv, 3), "ts": ts}

    def _beacon_signals(self, stamps: List[float]) -> Optional[dict]:
        """对间隔序列做多信号打分；硬门槛（样本数/跨度/平均间隔）不满足返回 None。

        信号：① CV 抖动（旧判据保留）② 间隔差额稳定性（真心跳连误差都不变）
              ③ 周期性（落在均值 ±10% 带内的比例）④ 持续性（跨度 + 样本数）
        降分：间隔呈递增/递减趋势 = 重连退避，不是心跳。
        """
        n = len(stamps)
        if n < BEACON_MIN_SAMPLES:
            return None
        span = stamps[-1] - stamps[0]
        if span < BEACON_MIN_SPAN_S:
            return None
        gaps = [b - a for a, b in zip(stamps, stamps[1:]) if b > a]
        if len(gaps) < BEACON_MIN_SAMPLES - 1:
            return None
        mean = sum(gaps) / len(gaps)
        if mean < BEACON_MIN_MEAN_GAP_S:
            return None
        cv = math.sqrt(sum((g - mean) ** 2 for g in gaps) / len(gaps)) / mean
        # 周期性：落在均值 ±10% 带内的间隔比例
        band = BEACON_PERIODIC_BAND * mean
        periodic = sum(1 for g in gaps if abs(g - mean) <= band) / len(gaps)
        # 抖动的抖动：相邻间隔差额的标准差 / 平均间隔
        diffs = [b - a for a, b in zip(gaps, gaps[1:])]
        dmean = sum(diffs) / len(diffs)
        delta_ratio = math.sqrt(sum((d - dmean) ** 2 for d in diffs) / len(diffs)) / mean
        # 趋势：最小二乘斜率 → 相对漂移 = |斜率| × 序列长度 / 均值
        m = len(gaps)
        sx = m * (m - 1) / 2.0
        sxx = (m - 1) * m * (2 * m - 1) / 6.0
        sxy = sum(i * g for i, g in enumerate(gaps))
        denom = m * sxx - sx * sx
        slope = (m * sxy - sx * sum(gaps)) / denom if denom else 0.0
        trend_ratio = abs(slope) * (m - 1) / mean
        # 各信号归一到 0..1，加权和后扣趋势分
        s_cv = max(0.0, 1.0 - cv / (2 * BEACON_CV_THRESHOLD))
        s_delta = max(0.0, 1.0 - delta_ratio / BEACON_DELTA_REF)
        persist = (0.5 * min(1.0, span / BEACON_PERSIST_FULL_S)
                   + 0.5 * min(1.0, n / BEACON_PERSIST_FULL_N))
        penalty = BEACON_TREND_PENALTY * min(1.0, max(
            0.0, (trend_ratio - BEACON_TREND_FREE) / (BEACON_TREND_FULL - BEACON_TREND_FREE)))
        score = (BEACON_W_CV * s_cv + BEACON_W_DELTA * s_delta
                 + BEACON_W_PERIODIC * periodic + BEACON_W_PERSIST * persist - penalty)
        return {
            "score": round(max(0.0, min(1.0, score)), 3),
            "mean": round(mean, 1), "cv": round(cv, 3),
            "span": round(span, 1), "periodic": round(periodic, 3),
            "delta_ratio": round(delta_ratio, 3), "trend_ratio": round(trend_ratio, 3),
            "persist": round(persist, 3),
            "signals": {"cv": round(s_cv, 3), "delta": round(s_delta, 3),
                        "periodic": round(periodic, 3), "persist": round(persist, 3),
                        "trend_penalty": round(penalty, 3)},
        }

    def _grade(self, kind: str, severity: str, subject: dict) -> Optional[str]:
        """情报类信号的定级闸门（2026-11-19 接线）。

        ioc_ip 只认 intel 算出来的分档：即使调用方传了 "high"，落在保留/共享网段
        （allowlist 前置）或衰减到期的命中也不会变成高危；无闸门时只给最低档。
        返回值 None = 不再计分，调用方直接丢弃该事件。
        其余信号（beaconing / direct_ip / risky_port / dga …）是行为形态判据，
        保持自身等级不动。
        """
        if kind != "ioc_ip":
            return severity
        if self.intel is None:
            return "low"
        ip = str(subject.get("ip") or "")
        dom = str(subject.get("domain") or "")
        try:
            hit = self.intel.match_ip(ip) if ip else None
            if hit is None and dom:
                hit = self.intel.match_domain(dom)
        except Exception:
            hit = None
        if not hit_counts(hit):
            return None
        return hit_severity(hit, "low")

    def _flag(self, out: List[Event], ev: Event, kind: str, text: str,
              severity: str, subject: dict) -> None:
        subject = subject or {}
        graded = self._grade(kind, severity, subject)
        if graded is None:
            return
        severity = graded
        key = f"{kind}|{ev.process}|{subject.get('ip') or subject.get('domain') or ''}"
        now = time.time()
        if now - self._flag_seen.get(key, 0) < self.flag_cooldown:
            return
        self._flag_seen[key] = now
        out.append(Event(kind=f"ndr.{kind}", source="ndr",
                         ts=ev.ts or time.time(), pid=ev.pid, process=ev.process,
                         path=str(subject.get("ip") or ""), user=ev.user,
                         severity=severity, subject=dict(subject, reason=text)))
        self.flags.append({"ts": time.time(), "kind": kind, "text": text,
                           "severity": severity, "process": ev.process})
        del self.flags[:-500]

    # ---------- 视图 ----------
    def status(self) -> Dict[str, Any]:
        top = sorted(self.dest.values(), key=lambda d: -d["count"])[:40]
        # 告警聚合 + 排序（Vectra 漏斗）：按 置信度 × 持续性 降序，顶层只推前 N
        ranked_all = []
        for b in self.beacons.values():
            item = dict(b)
            item["rank_score"] = round(float(b.get("score") or 0)
                                       * float(b.get("persist") or 0), 4)
            ranked_all.append(item)
        ranked_all.sort(key=lambda b: (-b["rank_score"], -b["hits"], b["id"]))
        beacon_ranked = [dict(b, rank=i + 1)
                         for i, b in enumerate(ranked_all[:BEACON_TOP_N])]
        return {
            "destinations": len(self.dest),
            "public_destinations": sum(1 for d in self.dest.values()
                                       if d["ip"] and not _is_private(d["ip"])),
            "unresolved": sum(1 for d in self.dest.values() if not d["hostname"]),
            "beacons": ranked_all[:20],
            "beacon_ranked": beacon_ranked,
            "beacon_count": len(self.beacons),
            "baseline_learning": sum(1 for c in self._seen.values()
                                     if c <= BEACON_BASELINE_N),
            "baselines_learned": len(self._baseline),
            "flags": self.flags[-60:][::-1],
            "top_destinations": top,
            "dns": self.dns.status(),
            "ts": self._last_run,
        }


def _is_private(ip: str) -> bool:
    try:
        import ipaddress
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_multicast
    except Exception:
        return True
