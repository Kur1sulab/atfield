#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""情报闸门接线回归（2026-11-19）。

背景：atfield/intel.py 的闸门（CIDR 最长前缀 → allowlist 前置 → score = 置信度 × 衰减）
此前没有真正进入判定路径，三处仍然写死等级：
  1) detect/rules_builtin.py  AEG-043  severity="critical"
  2) netintel.py              _flag("ioc_ip", ..., "high")
  3) core.py                  FUSION_MAP["ndr.ioc_ip"] → "high"
本文件逐条守住接线后的行为，任何一处退回写死值都会红：

  ① 保留/私网网段即使被录进情报库，也被闸门拦下，定级不被抬到 critical/high
  ② 真实高危情报（高置信 + 新鲜）仍能定到 critical
  ③ 衰减到期（t ≥ τ）后不再计分：不产告警、不进融合层

运行：python3 -m unittest discover -s tests -t tests
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from atfield.detect.engine import Engine                       # noqa: E402
from atfield.detect import rules_builtin                       # noqa: E402
from atfield.intel import Intel, grade_event_severity, hit_counts, hit_severity  # noqa: E402
from atfield.model import Event                                # noqa: E402
from atfield.netintel import NetIntel                          # noqa: E402
from atfield.store import Store                                # noqa: E402

# 测试地址全部为合成值：
#   私网 / 文档保留段 → 必须被 allowlist 拦下
#   PUB_* → 普通公网地址（不含任何特殊用途），用来验证「真高危仍能到 critical」
def _ip(a, b, c, d):
    """拼地址：避免在源码里出现整串字面量（会被证据脱敏层替换成占位符）。"""
    return "%d.%d.%d.%d" % (a, b, c, d)


PRIV_IP = _ip(10, 11, 12, 13)
PRIV_IP2 = _ip(192, 168, 77, 88)
RESERVED_IP = _ip(203, 0, 113, 9)     # TEST-NET-3 文档保留段
PUB_CRIT = _ip(45, 33, 32, 156)       # 普通公网：高置信 + 新鲜 → 应到 critical
PUB_STALE = _ip(5, 9, 100, 20)        # 普通公网：高置信但 30 天未再观测 → 衰减归零
PUB_MED = _ip(23, 94, 55, 12)         # 普通公网：低置信 → 只能到 medium
CIDR24 = _ip(45, 33, 32, 0) + "/24"
DAY = 86400.0


def _cfg(tmp, ioc_ips=()):
    return {
        "data_dir": tmp,
        "store": {"persist": False},
        "detect": {},
        "ioc": {"ips": list(ioc_ips), "domains": []},
    }


def _net_ev(ip, port=443, severity="", process="wired-unit"):
    """最小 net.connect 事件（字段与 collectors/network.py 对齐）。"""
    return Event(
        kind="net.connect", source="unittest", ts=time.time(), host="unit-host",
        pid=4242, process=process, path=f"{ip}:{port}", severity=severity,
        subject={"raddr": f"{ip}:{port}", "rport": port, "rip": ip, "public": True},
    )


def _ioc_findings(findings):
    return [f for f in findings if f.rule_id == "AEG-043"]


class _WiringBase(unittest.TestCase):
    ioc_ips: tuple = ()

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="atf-wiring-")
        self.cfg = _cfg(self.tmp, self.ioc_ips)
        self.store = Store(self.cfg)
        self.intel = Intel(self.cfg, self.store)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ---- 三处调用点的最小装配 ----
    def engine(self):
        eng = Engine(self.cfg, self.store, rules_builtin.RULES)
        eng.attach_intel(self.intel)          # core.py 里同样是这一句
        return eng

    def netintel(self):
        ni = NetIntel(self.cfg, self.store, self.intel)
        for ip in (PRIV_IP, PUB_CRIT, PUB_STALE, PUB_MED):
            ni._resolved.setdefault(ip, "unit.test.invalid")   # 不起真实 DNS
        return ni

    def aeg043_severity(self, ip, event_severity=""):
        got = _ioc_findings(self.engine().observe([_net_ev(ip, severity=event_severity)]))
        return got[0].severity if got else None


class GateBlocksReservedTest(_WiringBase):
    """① 保留/私网网段命中情报 → 闸门拦下，绝不定到 critical/high。"""

    def test_private_ip_in_intel_is_allowlisted(self):
        self.intel.add("ip", PRIV_IP, source="unit", confidence="high")
        self.assertIsNone(self.intel.match_ip(PRIV_IP),
                          "RFC1918 必须在 allowlist 前置阶段被拦下，不进匹配")

    def test_reserved_doc_range_is_allowlisted(self):
        self.intel.add("ip", RESERVED_IP, source="unit", confidence="high")
        self.assertIsNone(self.intel.match_ip(RESERVED_IP))

    def test_aeg043_does_not_fire_on_private_ip(self):
        self.intel.add("ip", PRIV_IP, source="unit", confidence="high")
        # 事件自带 critical 也不能把保留网段抬起来（旧实现 sev_max 会抬到 critical）
        self.assertIsNone(self.aeg043_severity(PRIV_IP, event_severity="critical"))

    def test_netintel_does_not_flag_private_ip(self):
        self.intel.add("ip", PRIV_IP, source="unit", confidence="high")
        out = self.netintel().observe([_net_ev(PRIV_IP)])
        self.assertEqual([e for e in out if e.kind == "ndr.ioc_ip"], [])

    def test_fusion_grade_drops_to_low_for_private_ip(self):
        self.intel.add("ip", PRIV_IP, source="unit", confidence="high")
        ev = Event(kind="ndr.ioc_ip", source="ndr", pid=4242, process="wired-unit",
                   severity="critical", subject={"ip": PRIV_IP, "reason": "unit"})
        self.assertEqual(grade_event_severity(ev, self.intel, fallback="high"), "low")

    def test_cidr_entry_matches_member_host_and_still_gated(self):
        """闸门按网段匹配（最长前缀），且网段命中同样受 allowlist/衰减管。"""
        self.intel.add("ip", CIDR24, source="unit", confidence="high")
        hit = self.intel.match_ip(PUB_CRIT)          # /24 内的主机地址
        self.assertIsNotNone(hit, "/24 条目必须能命中网段内的主机地址")
        self.assertEqual(hit["severity"], "critical")
        self.assertIsNone(self.intel.match_ip(_ip(45, 33, 33, 156)), "网段外地址不得命中")


class GateKeepsRealThreatTest(_WiringBase):
    """② 真实高危情报（高置信 + 新鲜）仍能到 critical。"""

    def test_high_confidence_public_ioc_reaches_critical_via_aeg043(self):
        self.assertIsNone(self.intel.warnings.check_ip(PUB_CRIT),
                          "测试地址必须不是保留/共享网段，否则本条断言无意义")
        self.intel.add("ip", PUB_CRIT, source="unit-high", confidence="high")
        self.assertEqual(self.aeg043_severity(PUB_CRIT), "critical")

    def test_netintel_ioc_flag_carries_gated_severity(self):
        self.intel.add("ip", PUB_CRIT, source="unit-high", confidence="high")
        out = [e for e in self.netintel().observe([_net_ev(PUB_CRIT)])
               if e.kind == "ndr.ioc_ip"]
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, "critical")
        self.assertEqual(out[0].subject.get("gate_severity"), "critical")

    def test_low_confidence_ioc_is_medium_not_critical(self):
        self.intel.add("ip", PUB_MED, source="unit-low", confidence="low")
        # 事件自带 critical 也不抬级：定级只认闸门（0.15 → medium）
        self.assertEqual(self.aeg043_severity(PUB_MED, event_severity="critical"), "medium")

    def test_fusion_map_no_longer_hardcodes_severity(self):
        from atfield.core import FUSION_MAP, GATED_FUSION_KINDS
        self.assertIn("ndr.ioc_ip", GATED_FUSION_KINDS)
        self.assertNotIn(FUSION_MAP["ndr.ioc_ip"][2], ("high", "critical"))

    def test_fusion_findings_uses_gate_severity(self):
        """core._fusion_findings 真跑一遍：表里只有 low 兜底，真实等级来自闸门。"""
        from atfield.core import Core
        self.intel.add("ip", PUB_CRIT, source="unit-high", confidence="high")

        class _Stub:
            def __init__(self, intel, engine):
                self.intel = intel
                self.engine = engine

        stub = _Stub(self.intel, Engine(self.cfg, self.store, []))
        ev = Event(kind="ndr.ioc_ip", source="ndr", pid=4242, process="wired-unit",
                   severity="high", subject={"ip": PUB_CRIT, "reason": "unit"})
        out = Core._fusion_findings(stub, [ev])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].rule_id, "TI-IOC-IP")
        self.assertEqual(out[0].severity, "critical")


class GateDecayTest(_WiringBase):
    """③ 衰减到期后不再计分。"""

    def _stale(self, ip):
        now = time.time()
        self.intel.add("ip", ip, source="unit-stale", confidence="high",
                       first_seen=now - 30 * DAY, last_seen=now - 30 * DAY)

    def test_score_is_zero_after_decay_window(self):
        self._stale(PUB_STALE)
        hit = self.intel.match_ip(PUB_STALE)
        self.assertIsNotNone(hit, "过期条目仍在库里，只是不再计分")
        self.assertEqual(hit["score"], 0.0)
        self.assertFalse(hit_counts(hit))
        self.assertEqual(hit_severity(hit, "low"), "low")

    def test_aeg043_silent_after_decay(self):
        self._stale(PUB_STALE)
        self.assertIsNone(self.aeg043_severity(PUB_STALE, event_severity="critical"))

    def test_netintel_silent_after_decay(self):
        self._stale(PUB_STALE)
        out = self.netintel().observe([_net_ev(PUB_STALE)])
        self.assertEqual([e for e in out if e.kind == "ndr.ioc_ip"], [])

    def test_fusion_not_counted_after_decay(self):
        self._stale(PUB_STALE)
        ev = Event(kind="ndr.ioc_ip", source="ndr", pid=4242, process="wired-unit",
                   severity="high", subject={"ip": PUB_STALE, "reason": "unit"})
        self.assertEqual(grade_event_severity(ev, self.intel, fallback="low"), "low")


class ConfigIocSeedTest(_WiringBase):
    """config.yaml 明文名单一次性迁入闸门：不再直接比字符串、不再写死 critical。"""

    ioc_ips = (PRIV_IP2,)

    def test_config_ioc_seeded_into_gate(self):
        key = str(PRIV_IP2)
        self.assertIsNone(self.intel.match_ip(key))       # 私网 → 不迁入
        # 公网条目迁入后受闸门管理：低置信（0.15）→ medium，不是 critical
        self.cfg["ioc"]["ips"] = [PUB_MED]
        seeded = Intel(self.cfg, self.store)
        self.assertIsNotNone(seeded.match_ip(PUB_MED))
        eng = Engine(self.cfg, self.store, rules_builtin.RULES)
        eng.attach_intel(seeded)
        got = _ioc_findings(eng.observe([_net_ev(PUB_MED, severity="critical")]))
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].severity, "medium")

    def test_seed_does_not_reset_decay_clock(self):
        self.cfg["ioc"]["ips"] = [PUB_STALE]
        first = Intel(self.cfg, self.store)
        first.add("ip", PUB_STALE, source="unit", confidence="high",
                  first_seen=time.time() - 30 * DAY, last_seen=time.time() - 30 * DAY)
        again = Intel(self.cfg, self.store)      # 模拟重启：不得把 last_seen 重置
        self.assertLess(again.data["ip"][PUB_STALE]["last_seen"], time.time() - 20 * DAY)


if __name__ == "__main__":
    unittest.main(verbosity=2)
