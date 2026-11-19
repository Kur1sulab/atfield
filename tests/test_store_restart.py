#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Store 重启加载回归：攻击链顺序必须与在线语义一致。

背景（2026-11-19 落盘修复引入的回归）：
  在线 add_incident（store.py:89-102）对同一 iid 是「移除旧条目 + appendleft」，
  即最近更新的攻击链排最前。而 _load_history 读回 incidents.jsonl 时用了
  reversed()（store.py:300），重启后变成「最后一次更新最旧的链」排最前——
  顺序恰好相反。

用户怎么被坑：
  - 控制台总览「攻击链叙事」(core.overview -> recent_incidents) 与
    /api/incidents?limit=50 重启后展示的是最不活跃的 50 条链；
  - 威胁指数 scoring.threat 取 snapshot_incidents(50)，重启后算在错误子集上；
  - 唯一 iid 数超过 max_incidents 时，deque 溢出从右端淘汰——重启加载后
    右端恰好是最新链，最近活跃的攻击链被整条丢出内存。

本文件只测 Store（临时目录，不起服务、不占端口）。
运行：python3 -m unittest tests.test_store_restart -v
"""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from atfield.model import Incident            # noqa: E402
from atfield.store import Store               # noqa: E402


def _inc(iid, title, last_seen, score=1.0):
    return Incident(title=title, template_id="T-TEST", severity="high",
                    iid=iid, first_seen=last_seen - 60, last_seen=last_seen,
                    score=score, stages=[])


class StoreRestartOrder(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="atfield-store-restart-")
        self.cfg = {"data_dir": self.tmp, "store": {"max_incidents": 400}}

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _reopen(self, cfg=None):
        return Store(cfg or self.cfg)

    def test_restart_preserves_live_order(self):
        """多 iid + 中途更新：重启后顺序必须与在线完全一致。"""
        st = Store(self.cfg)
        st.add_incident(_inc("A", "链A-v1", 1000.0, 1.0))
        st.add_incident(_inc("B", "链B-v1", 2000.0, 2.0))
        st.add_incident(_inc("A", "链A-v2", 3000.0, 9.0))  # A 更新 → 应前移
        st.add_incident(_inc("C", "链C-v1", 2500.0, 3.0))
        live = [(i["iid"], i["title"], i["score"]) for i in st.snapshot_incidents()]
        st.close()
        self.assertEqual([x[0] for x in live], ["C", "A", "B"],
                         "在线语义本身变了？本测试的前提是在线=最近更新在前")
        st2 = self._reopen()
        try:
            back = [(i["iid"], i["title"], i["score"])
                    for i in st2.snapshot_incidents()]
            self.assertEqual(back, live,
                             "重启后攻击链顺序/状态与在线不一致")
        finally:
            st2.close()

    def test_restart_overflow_keeps_most_recent(self):
        """超过 max_incidents：重启后保留的必须是最近活跃的链，不是最旧的。"""
        cfg = {"data_dir": self.tmp, "store": {"max_incidents": 3}}
        st = Store(cfg)
        for k in range(5):
            st.add_incident(_inc(f"I{k}", f"链{k}", 1000.0 + k * 100, float(k)))
        live = [i["iid"] for i in st.snapshot_incidents()]
        st.close()
        self.assertEqual(live, ["I4", "I3", "I2"])
        st2 = self._reopen(cfg)
        try:
            back = [i["iid"] for i in st2.snapshot_incidents()]
            self.assertEqual(back, live,
                             "重启后溢出淘汰方向反了：最新的链被丢出内存")
        finally:
            st2.close()

    def test_readded_after_eviction_survives_restart(self):
        """已被淘汰的 iid 再次更新（重新入列）：重启后仍须在最前。"""
        cfg = {"data_dir": self.tmp, "store": {"max_incidents": 3}}
        st = Store(cfg)
        for k in range(5):
            st.add_incident(_inc(f"I{k}", f"链{k}", 1000.0 + k * 100, float(k)))
        # I0 已被挤出内存；再次更新时在线语义按新链重新入列到最前
        st.add_incident(_inc("I0", "链0-复活", 9000.0, 99.0))
        live = [i["iid"] for i in st.snapshot_incidents()]
        st.close()
        self.assertEqual(live, ["I0", "I4", "I3"])
        st2 = self._reopen(cfg)
        try:
            snap = st2.snapshot_incidents()
            self.assertEqual([i["iid"] for i in snap], live)
            self.assertEqual(snap[0]["title"], "链0-复活")
            self.assertEqual(snap[0]["score"], 99.0)
        finally:
            st2.close()

    def test_dedupe_keeps_latest_state(self):
        """同 iid 多次更新：重启后只留一条，且是最新状态（t15 的 Store 级守卫）。"""
        st = Store(self.cfg)
        st.add_incident(_inc("X", "链v1", 1000.0, 1.0))
        st.add_incident(_inc("X", "链v2", 2000.0, 9.0))
        st.close()
        st2 = self._reopen()
        try:
            snap = st2.snapshot_incidents()
            self.assertEqual(len(snap), 1)
            self.assertEqual(snap[0]["title"], "链v2")
            self.assertEqual(snap[0]["score"], 9.0)
        finally:
            st2.close()

    def test_findings_restart_newest_first(self):
        """相邻路径守卫：findings 重启后仍须最新在前（与在线一致）。"""
        st = Store(self.cfg)
        st.add_findings([{"rule_id": "R1", "name": "早", "ts": 1000.0},
                         {"rule_id": "R2", "name": "晚", "ts": 2000.0}])
        live = [f["rule_id"] for f in st.snapshot_findings()]
        st.close()
        st2 = self._reopen()
        try:
            self.assertEqual([f["rule_id"] for f in st2.snapshot_findings()], live)
            self.assertEqual(live[0], "R2")
        finally:
            st2.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
