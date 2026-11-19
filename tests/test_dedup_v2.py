#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""降噪三项回归：去重键重构 / 冷却分级 / 抑制字段化 / 时段频率异常。

依据：research/defense-landscape/09-soc-soar.md §6.4 P0（1/2/3）。
运行：python3 -m unittest tests.test_dedup_v2 -v
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from atfield.detect.engine import (                     # noqa: E402
    Engine, Rule, cooldown_for, COOLDOWN_ONESHOT, COOLDOWN_PERIODIC,
)
from atfield.model import Event                          # noqa: E402
from atfield.store import Store                          # noqa: E402
from atfield.ueba import UEBA, RARE_THRESHOLD            # noqa: E402


class _StateStore:
    """UEBA 只用到 set_state / log_action；桩足够，避免落盘。"""

    def __init__(self):
        self.state = {}

    def set_state(self, key, value):
        self.state[key] = value

    def log_action(self, *a, **kw):
        pass


def _mk(tmp, rules):
    cfg = {"data_dir": tmp, "store": {"persist": False}, "detect": {}}
    return Engine(cfg, Store(cfg), rules)


def _ev(process="evil", path="/tmp/evil", detail_seed="", ts=None, **kw):
    return Event(kind="process.start", source="test", ts=ts or time.time(),
                 pid=4242, process=process, path=path, user="tester", **kw)


def _rule(rid="TEST-001", tags=("persistence",), sev="medium", text="命中 A"):
    return Rule(id=rid, name=rid, severity=sev, when=lambda ev, ctx: True,
                detail=text, tags=tags, cooldown=None)


class DedupKeyTest(unittest.TestCase):
    """场景 1：detail 变化不新开告警，而是并入 + 计数。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="atf-dedup-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_detail_drift_merges_instead_of_new_alert(self):
        eng = _mk(self.tmp, [_rule(text="路径 /tmp/evil 被写入")])
        det = eng.rules[0].detail
        f1 = eng.observe([_ev()])
        self.assertEqual(len(f1), 1)
        first = f1[0].to_dict()
        self.assertEqual(first["count"], 1)

        # 同一行为，detail 少一个字（可变文本），键里不再含 detail → 应并入
        eng.rules[0].detail = "路径 /tmp/evi 被写入"
        f2 = eng.observe([_ev()])
        self.assertEqual(f2, [], "detail 抖动不得新开告警")

        merges = eng.take_merges()
        self.assertEqual(len(merges), 1)
        self.assertEqual(merges[0]["fid"], first["fid"])
        self.assertEqual(merges[0]["count"], 2)
        self.assertIn("evi", merges[0]["last_detail"])

        st = Store({"data_dir": self.tmp, "store": {"persist": False}})
        st.add_findings(f1)
        self.assertEqual(st.bump_findings(merges), 1)
        row = st.snapshot_findings()[0]
        self.assertEqual(row["count"], 2, "计数应写回同一条告警")
        self.assertTrue(row["dedup_key"].startswith("TEST-001|"))
        self.assertEqual(row["detail"], "路径 /tmp/evil 被写入", "首条样本保留")
        self.assertTrue(row["last_detail"].endswith("evi 被写入"), "末条样本保留")
        self.assertEqual(det, "路径 /tmp/evil 被写入")

    def test_key_is_stable_identity(self):
        eng = _mk(self.tmp, [_rule()])
        eng.observe([_ev()])
        key = list(eng._dedup)[0]
        self.assertEqual(key, "TEST-001|pid:4242|evil|/tmp/evil")
        self.assertNotIn("命中", key)


class CooldownTierTest(unittest.TestCase):
    """场景 2：周期行为类长冷却、一次性行为类短冷却。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="atf-cd-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_tier_values(self):
        self.assertEqual(cooldown_for(_rule(tags=("persistence",))), COOLDOWN_PERIODIC)
        self.assertEqual(cooldown_for(_rule(tags=("discovery",))), 600.0)
        self.assertEqual(cooldown_for(_rule(tags=())), COOLDOWN_ONESHOT)
        self.assertEqual(cooldown_for(_rule(tags=("persistence",))), 900.0)
        r = _rule()
        r.cooldown = 45.0
        self.assertEqual(cooldown_for(r), 45.0, "显式 cooldown 优先")

    def test_tiered_cooldown_effective(self):
        tmp2 = tempfile.mkdtemp(prefix="atf-cd-oneshot-")
        try:
            per = _mk(self.tmp, [_rule(rid="P-1", tags=("persistence",))])
            one = _mk(tmp2, [_rule(rid="O-1", tags=())])
            for eng in (per, one):
                self.assertEqual(len(eng.observe([_ev()])), 1)
                # 模拟已过 30 秒（大于一次性冷却 20s，小于周期冷却 900s）
                for v in eng._dedup.values():
                    v["last_emit"] = time.time() - 30
            self.assertEqual(per.observe([_ev()]), [], "周期规则 900s 内应继续并入")
            self.assertEqual(len(one.observe([_ev()])), 1, "一次性规则 20s 后应允许新告警")
            self.assertEqual(per._dedup["P-1|pid:4242|evil|/tmp/evil"]["count"], 2)
        finally:
            shutil.rmtree(tmp2, ignore_errors=True)


class SuppressFieldTest(unittest.TestCase):
    """场景 3：抑制按字段（equality/regex）+ 作用域，而不是子串。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="atf-sup-")
        self.eng = _mk(self.tmp, [_rule(rid="SUP-1", tags=())])

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_field_equality_not_substring(self):
        # 旧写法：detail 里出现 "curl" 就抑制 → 过宽
        self.eng.add_suppress("SUP-1", contains="curl", note="legacy")
        self.eng.suppress.clear()          # 只测字段化路径
        res = self.eng.add_suppress("SUP-1", fields={"process": {"eq": "sshd"}}, note="sshd 正常行为")
        self.assertTrue(res["ok"])
        # detail 里含 sshd 但 process 不是 sshd → 不该被抑制（子串写法会误杀）
        self.assertEqual(len(self.eng.observe([_ev(process="python3", detail_seed="sshd")])), 1)
        # 字段等值命中 → 抑制，且命中计数 +1
        self.assertEqual(self.eng.observe([_ev(process="sshd", path="/usr/sbin/sshd")]), [])
        self.assertEqual(self.eng.suppress[0]["hits"], 1)
        self.assertEqual(self.eng.suppress_hits, 1)
        self.assertEqual(self.eng.suppressed, 1)

    def test_regex_scope_expiry_review(self):
        self.eng.add_suppress("SUP-1", fields={"path": {"re": r"/tmp/.+evil"}},
                              actor="pid:4242", note="re")
        self.assertEqual(self.eng.observe([_ev(path="/tmp/very-evil")]), [])
        # 作用域不匹配 → 不抑制
        other = _ev(path="/tmp/very-evil")
        other.pid = 9999
        self.assertEqual(len(self.eng.observe([other])), 1)

        # 过期即失效
        self.eng.suppress[0]["expires"] = time.time() - 1
        self.assertEqual(len(self.eng.observe([_ev(path="/tmp/very-evil")])), 1)

        # 复审提示
        self.eng.suppress[0]["expires"] = 0
        self.eng.suppress[0]["review_days"] = 1
        self.eng.suppress[0]["added"] = time.time() - 2 * 86400
        due = self.eng.suppress_review_due()
        self.assertEqual(len(due), 1)
        self.assertIn("复审", due[0]["reason"])

    def test_suppress_persisted_with_fields(self):
        self.eng.add_suppress("SUP-1", fields={"process": {"in": ["sshd", "launchd"]}})
        with open(os.path.join(self.tmp, "suppress.json"), "r", encoding="utf-8") as fh:
            items = json.load(fh)
        self.assertEqual(items[0]["fields"]["process"]["in"], ["sshd", "launchd"])
        self.assertEqual(items[0]["rule_id"], "SUP-1")


class HourlyRarityTest(unittest.TestCase):
    """场景 4：每小时频率异常能独立捕获（即使进程早就见过）。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="atf-hour-")
        self.u = UEBA({"data_dir": self.tmp}, _StateStore())
        # 退出学习期
        self.u.obs = 10 ** 6
        self.u.t0 = time.time() - 10 ** 6

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    @staticmethod
    def _ts_at(hour, n=0):
        lt = time.localtime()
        base = time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, hour, 0, 0, 0, 0, -1))
        return base + n

    def test_busy_hour_baseline_then_rare_hour_alerts(self):
        busy = self._ts_at(14)
        # 14 点把 python3 打成高频组合（进程早就"见过"，binary novelty 会饱和）
        exe = "/Users/tester/bin/python3"      # 非系统路径：系统目录上的新进程本就不报
        for i in range(600):
            self.u.observe([Event(kind="process.start", source="t", ts=busy + i,
                                  pid=100, process="python3", path=exe)])
        self.assertLess(self.u.frequency_score("python3", "14")["score"], RARE_THRESHOLD)

        # 同一进程出现在 03 点（历史几乎无活动）→ 频率异常应独立捕获
        rare = self._ts_at(3)
        out = self.u.observe([Event(kind="process.start", source="t", ts=rare,
                                    pid=101, process="python3", path=exe)])
        kinds = [e.kind for e in out]
        self.assertIn("ueba.rare_activity", kinds, f"应产出频率异常事件，实际 {kinds}")
        ev = [e for e in out if e.kind == "ueba.rare_activity"][0]
        self.assertGreaterEqual(ev.subject["score"], RARE_THRESHOLD)
        self.assertGreaterEqual(ev.subject["hour_rarity"], 0.9, "03 点历史频率几乎为 0")
        self.assertIn("频率", " ".join(ev.subject["reasons"]))

    def test_new_process_still_reported_and_hourly_used(self):
        busy = self._ts_at(10)
        for i in range(300):
            self.u.observe([Event(kind="process.start", source="t", ts=busy + i,
                                  pid=200, process="zsh", path="/Users/tester/bin/zsh")])
        out = self.u.observe([Event(kind="process.start", source="t",
                                    ts=self._ts_at(4), pid=201,
                                    process="curl", path="/Users/tester/bin/curl")])
        self.assertTrue(any(e.kind == "ueba.new_process" for e in out))
        h = self.u._hourly
        self.assertIn("04", h, "hourly 直方图按事件时间桶而不是墙钟")


if __name__ == "__main__":
    unittest.main(verbosity=2)
