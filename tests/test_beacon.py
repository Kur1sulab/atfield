#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""信标（beaconing）多信号判据回归。

背景（research/02-network.md §9 P0）：
  旧判据「同一 (进程,目的地) 连接间隔 CV < 0.18 即报 high」会把 IDE 自动保存、
  代理轮询、浏览器心跳全部报成 C2。新判据 = 抖动(CV+间隔差额稳定性) + 持续性
  (跨度/样本数) + 周期性(均值±10%带内比例) 加权打分，递增/递减趋势(重连退避)
  降分；每个 (进程,目的地) 前 12 次连接冷启动只建基线不告警；告警按
  置信度×持续性排序，顶层只推前 5（Vectra 漏斗）。

本文件只测 NetIntel（内存态 + store 桩，不起服务、不占端口、不做真实 DNS：
目的地用 TEST-NET-3 文档保留网段 203.0.113.0/24，反查结果预置）。
运行：python3 -m unittest tests.test_beacon -v
"""
import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from atfield.model import Event                     # noqa: E402
from atfield.netintel import (                      # noqa: E402
    NetIntel, BEACON_MIN_SAMPLES, BEACON_MIN_SPAN_S, BEACON_BASELINE_N,
    BEACON_SCORE_THRESHOLD, BEACON_CV_THRESHOLD, BEACON_TOP_N,
    BEACON_TREND_FREE,
)

IP = "203.0.113.7"          # TEST-NET-3 保留网段：纯合成，绝不指向真实目标
T0 = 1_700_000_000.0        # 固定事件时间轴，与墙钟无关（冷却测试另行处理）


class _StateStore:
    """NetIntel 只用到 set_state；桩足够，避免单测落盘。"""

    def __init__(self):
        self.state = {}

    def set_state(self, key, value):
        self.state[key] = value


def _ni():
    return NetIntel({}, _StateStore(), None)


def _feed(ni, gaps, ip=IP, port=443, pid=4242, process="beacon-unit",
          public=True):
    """按间隔序列灌 net.connect；首个事件在 T0，之后逐个累加 gap。"""
    ni._resolved.setdefault(ip, "unit.test.invalid")  # 预置反查：不起真实 DNS 线程
    ts = T0
    evs = []
    for g in [0.0] + list(gaps):
        ts += g
        evs.append(Event(
            kind="net.connect", source="unittest", ts=ts, host="unit-host",
            pid=pid, process=process, path=f"{ip}:{port}",
            subject={"raddr": f"{ip}:{port}", "rport": port,
                     "rip": ip, "public": public}))
    return ni.observe(evs)


def _beacon_flags(evs):
    return [e for e in evs if e.kind == "ndr.beaconing"]


def _stamps(gaps):
    ts = T0
    out = [ts]
    for g in gaps:
        ts += g
        out.append(ts)
    return out


def _cv(gaps):
    mean = sum(gaps) / len(gaps)
    return (sum((g - mean) ** 2 for g in gaps) / len(gaps)) ** 0.5 / mean


class BeaconCriteria(unittest.TestCase):
    # ---------------- 命中类 ----------------
    def test_fixed_heartbeat_hits(self):
        """真心跳（固定 60s、20 样本、跨度 1140s）必须命中，且为 high。"""
        ni = _ni()
        out = _feed(ni, [60.0] * 19)
        flags = _beacon_flags(out)
        self.assertEqual(len(flags), 1)
        self.assertEqual(flags[0].severity, "high")
        self.assertEqual(flags[0].subject["ip"], IP)
        b = ni.beacons[f"beacon-unit->{IP}"]
        self.assertGreaterEqual(b["score"], BEACON_SCORE_THRESHOLD)
        self.assertAlmostEqual(b["cv"], 0.0, places=3)
        self.assertAlmostEqual(b["periodic"], 1.0, places=3)

    def test_regular_polling_30pm3_hits(self):
        """验收要求：30±3s 规律轮询仍判 hit——±10% 带内轮询在时序上与心跳
        不可分，判据保留命中，噪声交给冷启动基线与排序漏斗收敛。"""
        rng = random.Random(42)
        gaps = [rng.uniform(27, 33) for _ in range(29)]
        ni = _ni()
        out = _feed(ni, gaps)
        self.assertEqual(len(_beacon_flags(out)), 1)
        self.assertLess(_cv(gaps), BEACON_CV_THRESHOLD)  # 旧判据同样会命中

    def test_jittered_heartbeat_hits(self):
        """带 ±5s 抖动的 60s 心跳（40 样本）不能漏：抖动略增仍过线。"""
        rng = random.Random(7)
        gaps = [rng.uniform(55, 65) for _ in range(39)]
        ni = _ni()
        out = _feed(ni, gaps)
        self.assertEqual(len(_beacon_flags(out)), 1)

    # ---------------- 拦截类 ----------------
    def test_backoff_linear_drift_not_hit(self):
        """退避重连（间隔线性递增 60+2i）不 hit：旧判据 CV≈0.14 会误报，
        新判据靠趋势降分拦下。"""
        gaps = [60.0 + 2 * i for i in range(19)]
        self.assertLess(_cv(gaps), BEACON_CV_THRESHOLD)  # 证明旧判据会误报
        ni = _ni()
        out = _feed(ni, gaps)
        self.assertEqual(_beacon_flags(out), [])
        self.assertEqual(ni.beacons, {})
        sig = ni._beacon_signals(_stamps(gaps))
        self.assertIsNotNone(sig)                    # 硬门槛都过了，是打分拦下的
        self.assertGreater(sig["trend_ratio"], BEACON_TREND_FREE)
        self.assertGreater(sig["signals"]["trend_penalty"], 0)
        self.assertLess(sig["score"], BEACON_SCORE_THRESHOLD)

    def test_backoff_exponential_not_hit(self):
        """指数退避（30s×2^i，15 样本）不 hit。"""
        gaps = [30.0 * 2 ** i for i in range(14)]
        ni = _ni()
        out = _feed(ni, gaps)
        self.assertEqual(_beacon_flags(out), [])
        self.assertEqual(ni.beacons, {})

    def test_loose_polling_not_hit(self):
        """宽松轮询 30±8s：CV≈0.15 旧判据误报，新判据周期性不足拦下。"""
        rng = random.Random(11)
        gaps = [rng.uniform(22, 38) for _ in range(29)]
        self.assertLess(_cv(gaps), BEACON_CV_THRESHOLD)  # 证明旧判据会误报
        ni = _ni()
        out = _feed(ni, gaps)
        self.assertEqual(_beacon_flags(out), [])
        self.assertEqual(ni.beacons, {})

    def test_insufficient_samples_not_hit(self):
        """样本不足（7 < 8）不 hit；打分函数硬门槛直接返回 None。"""
        ni = _ni()
        out = _feed(ni, [60.0] * 6)
        self.assertEqual(_beacon_flags(out), [])
        self.assertEqual(ni.beacons, {})
        self.assertIsNone(ni._beacon_signals(_stamps([60.0] * 6)))
        self.assertEqual(BEACON_MIN_SAMPLES, 8)

    def test_short_span_not_hit(self):
        """跨度过短（5s×19 = 95s < 300s）不 hit：旧判据 mean>3 且 CV=0 会误报。"""
        gaps = [5.0] * 19
        self.assertGreater(sum(gaps) / len(gaps), 3)   # 旧判据两个条件都满足
        self.assertEqual(_cv(gaps), 0.0)
        ni = _ni()
        out = _feed(ni, gaps)
        self.assertEqual(_beacon_flags(out), [])
        self.assertIsNone(ni._beacon_signals(_stamps(gaps)))
        self.assertEqual(BEACON_MIN_SPAN_S, 300.0)

    def test_private_dest_never_beacon(self):
        """内网/回环对端再规律也不报（本地代理与 IDE 的正常行为）。"""
        ni = _ni()
        out = _feed(ni, [60.0] * 19, ip="192.168.1.10", public=False)
        self.assertEqual(_beacon_flags(out), [])
        self.assertEqual(ni.beacons, {})

    # ---------------- 冷启动 ----------------
    def test_cold_start_silent_then_active(self):
        """前 12 次连接只建基线不告警（哪怕是完美心跳）；第 13 次起才开始判。"""
        ni = _ni()
        out = _feed(ni, [60.0] * 11)          # 恰好 12 个样本 = 基线期
        self.assertEqual(_beacon_flags(out), [])
        self.assertEqual(ni.beacons, {})
        key = ("beacon-unit", IP)
        self.assertIn(key, ni._baseline)
        self.assertEqual(ni._baseline[key]["n"], BEACON_BASELINE_N)
        st = ni.status()
        self.assertEqual(st["baseline_learning"], 1)
        self.assertEqual(st["baselines_learned"], 1)
        out2 = _feed(ni, [60.0])              # 第 13 次：基线期结束，开始判
        self.assertEqual(len(_beacon_flags(out2)), 1)
        self.assertEqual(ni.status()["baseline_learning"], 0)

    # ---------------- 冷却 ----------------
    def test_cooldown_no_repeat(self):
        """冷却期不重复报：同一批 20 事件触发 hits=1/4/7 三次告警尝试，
        只有第一次出事件；冷却键清除后下一轮尝试才再报。"""
        ni = _ni()
        out = _feed(ni, [60.0] * 19)
        self.assertEqual(len(_beacon_flags(out)), 1)
        self.assertEqual(ni.beacons[f"beacon-unit->{IP}"]["hits"], 8)
        ni._flag_seen.clear()                 # 模拟 15 分钟冷却到期
        out2 = _feed(ni, [60.0, 60.0, 60.0])  # hits 9/10/11 → 第 10 次尝试放行
        self.assertEqual(len(_beacon_flags(out2)), 1)

    def test_flag_cooldown_direct(self):
        """_flag 机制本身：同 (类型,进程,目的地) 连续两次只出一条。"""
        ni = _ni()
        ev = Event(kind="net.connect", source="unittest", ts=T0, host="unit-host",
                   pid=1, process="x", subject={"rip": IP, "rport": 443})
        out = []
        ni._flag(out, ev, "beaconing", "t1", "high", {"ip": IP})
        ni._flag(out, ev, "beaconing", "t2", "high", {"ip": IP})
        self.assertEqual(len(out), 1)

    # ---------------- 聚合排序（Vectra 漏斗） ----------------
    def test_ranking_and_top_n(self):
        """7 条信标按 置信度×持续性 排序，beacon_ranked 只推前 5。"""
        ni = _ni()
        sizes = [40, 36, 30, 24, 20, 16, 14]   # 固定 60s，样本越多持续性越高
        for i, n in enumerate(sizes):
            _feed(ni, [60.0] * (n - 1), pid=2000 + i, process=f"rank-p{i}")
        st = ni.status()
        self.assertEqual(st["beacon_count"], 7)
        ranked = st["beacon_ranked"]
        self.assertEqual(len(ranked), BEACON_TOP_N)
        self.assertEqual([b["rank"] for b in ranked], [1, 2, 3, 4, 5])
        self.assertEqual([b["process"] for b in ranked],
                         [f"rank-p{i}" for i in range(5)])
        scores = [b["rank_score"] for b in st["beacons"]]
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertEqual(len(st["beacons"]), 7)
        self.assertAlmostEqual(ranked[0]["rank_score"],
                               ranked[0]["score"] * ranked[0]["persist"], places=3)

    # ---------------- 兼容约束 ----------------
    def test_event_shape_and_legacy_fields(self):
        """Event 结构不改、kind 仍叫 ndr.beaconing；beacon 旧字段全保留。"""
        ni = _ni()
        out = _feed(ni, [60.0] * 19)
        ev = _beacon_flags(out)[0]
        self.assertEqual(ev.kind, "ndr.beaconing")
        self.assertEqual(ev.source, "ndr")
        for attr in ("eid", "ts", "pid", "process", "path", "user",
                     "severity", "subject"):
            self.assertTrue(hasattr(ev, attr))
        b = ni.beacons[f"beacon-unit->{IP}"]
        for field in ("id", "process", "ip", "port", "interval_s", "cv",
                      "samples", "first", "last", "hits", "hostname"):
            self.assertIn(field, b)


if __name__ == "__main__":
    unittest.main(verbosity=2)
