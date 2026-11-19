"""防误封层回归：CIDR 匹配 + warninglist 前置 + IOC 生命周期闸门 + 老格式兼容。

六个必测场景（任务验收）：
1 CIDR 匹配支持单 IP 条目        2 网段条目命中单 IP
3 allowlist 优先于匹配           4 高频但老旧 IOC 降为 medium
5 新且高置信升为 critical        6 老格式 intel.json 平滑加载
另附：DROP 形态导入、MISP 风格本地 warninglist、sighting 重置、最长前缀、
IPv6 网段、误报抑制、类别规则不升级、旧字段保留。

纯标准库 + 临时目录，不起服务、不占端口、不联网。
运行：python3 -m unittest tests.test_intel_gate -v
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

from atfield.intel import Intel, CONF_MAP, score_to_severity, decay_factor  # noqa: E402

DAY = 86400.0


class _Store:
    """Intel 只用到 set_state / log_action，桩足够，避免单测落盘到真实库。"""

    def __init__(self):
        self.states = {}
        self.actions = []

    def set_state(self, key, value):
        self.states[key] = value

    def log_action(self, actor, action, target, result, detail=""):
        self.actions.append((actor, action, target, result))


class IntelGateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="atfield-intelgate-")
        self.cfg = {"data_dir": self.tmp}
        self.store = _Store()
        self.now = time.time()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def intel(self, cfg=None):
        return Intel(cfg or self.cfg, self.store)

    # ---- 场景 1：CIDR 匹配支持单 IP 条目 ----
    def test_single_ip_entry_matches(self):
        it = self.intel()
        r = it.add("ip", "5.6.7.8", source="test", confidence="high")
        self.assertTrue(r["ok"])
        hit = it.match_ip("5.6.7.8")
        self.assertIsNotNone(hit)
        self.assertEqual(hit["matched_kind"], "ip")
        self.assertEqual(hit["matched_value"], "5.6.7.8")
        self.assertIsNone(it.match_ip("5.6.7.9"))

    # ---- 场景 2：网段条目命中单 IP ----
    def test_cidr_entry_matches_ip_inside(self):
        it = self.intel()
        self.assertTrue(it.add("ip", "1.2.3.0/24", source="drop", confidence="high")["ok"])
        hit = it.match_ip("1.2.3.4")
        self.assertIsNotNone(hit, "落在网段内的 IP 必须命中")
        self.assertEqual(hit["matched_value"], "1.2.3.0/24")
        self.assertEqual(hit["value"], "1.2.3.0/24")
        self.assertIsNone(it.match_ip("1.2.4.4"), "网段外的 IP 不得命中")
        self.assertIsNone(it.match_ip("9.9.9.9"))

    # ---- 场景 3：allowlist 优先于匹配 ----
    def test_allowlist_precedes_match(self):
        it = self.intel()
        # 故意把私网/回环/Cloudflare 段录成 IOC，allowlist 仍须拦下
        for v in ("10.0.0.1", "10.0.0.0/8", "127.0.0.1", "104.16.5.5", "192.168.1.1"):
            self.assertTrue(it.add("ip", v, confidence="high")["ok"])
        for v in ("10.0.0.1", "10.9.9.9", "127.0.0.1", "104.16.5.5", "192.168.1.1"):
            self.assertIsNone(it.match_ip(v), f"allowlist 未拦住 {v}")
        # 对照：不在 allowlist 的同库条目照常命中
        self.assertTrue(it.add("ip", "1.2.3.0/24", confidence="high")["ok"])
        self.assertIsNotNone(it.match_ip("1.2.3.4"))

    # ---- 场景 4：高频但老旧 IOC 降为 medium ----
    def test_old_high_confidence_decays_to_medium(self):
        it = self.intel()
        it.add("ip", "5.6.7.8", source="feed", confidence="high",
               first_seen=self.now - 60 * DAY, last_seen=self.now - 30 * DAY)
        hit = it.match_ip("5.6.7.8")
        self.assertIsNotNone(hit, "过期降级不删除：仍要能命中")
        self.assertLess(hit["score"], 0.4)
        self.assertEqual(hit["severity"], "medium")
        self.assertEqual(hit["lifecycle"], "archive")
        self.assertEqual(hit["confidence"], "high", "置信度字段本身不改，只降评分")

    # ---- 场景 5：新且高置信升为 critical ----
    def test_fresh_high_confidence_is_critical(self):
        it = self.intel()
        it.add("ip", "5.6.7.9", source="feed", confidence="high",
               last_seen=self.now)
        hit = it.match_ip("5.6.7.9")
        self.assertIsNotNone(hit)
        self.assertGreaterEqual(hit["score"], 0.7)
        self.assertEqual(hit["severity"], "critical")
        self.assertEqual(hit["lifecycle"], "block")
        self.assertAlmostEqual(hit["score"], CONF_MAP["high"], places=3)

    # ---- 场景 6：老格式 intel.json 平滑加载 ----
    def test_legacy_json_loads(self):
        legacy = {
            "ip": {"5.6.7.8": {"value": "5.6.7.8", "source": "old-feed",
                                "note": "旧条目", "confidence": "high",
                                "added": self.now - 2 * DAY}},
            "domain": {"evil.example.com": {"value": "evil.example.com",
                                             "source": "manual", "note": "",
                                             "confidence": "medium",
                                             "added": self.now}},
            "hash": {},
        }
        with open(os.path.join(self.tmp, "intel.json"), "w", encoding="utf-8") as fh:
            json.dump(legacy, fh)
        it = self.intel()                      # 不得抛错
        hit = it.match_ip("5.6.7.8")
        self.assertIsNotNone(hit)
        for f in ("first_seen", "last_seen", "ttl_days", "decay_score"):
            self.assertIn(f, hit, f"惰性补默认值缺 {f}")
        self.assertEqual(hit["first_seen"], legacy["ip"]["5.6.7.8"]["added"])
        self.assertEqual(hit["source"], "old-feed")   # 旧字段保留
        self.assertEqual(hit["note"], "旧条目")
        self.assertIn("added", hit)
        # 迁移落盘后旧字段仍在、新字段已补
        with open(it.path, encoding="utf-8") as fh:
            disk = json.loads(fh.read())
        e = disk["ip"]["5.6.7.8"]
        self.assertEqual(e["source"], "old-feed")
        self.assertIn("ttl_days", e)
        self.assertIsNotNone(it.match_domain("evil.example.com"))

    # ---- 附加：Spamhaus DROP 形态导入（; 注释 + 裸网段自动判类） ----
    def test_import_drop_format(self):
        it = self.intel()
        text = ("; Spamhaus DROP 手造样本（离线）\n"
                "1.2.3.0/24 ; SBL999999\n"
                "5.6.7.0/24 ; SBL888888\n"
                "# 注释行\n"
                "ip,9.8.7.6,CSV 带置信度,high\n")
        r = it.import_text(text, source="drop-sample")
        self.assertTrue(r["ok"])
        self.assertIn("3 条", r["detail"])
        self.assertIsNotNone(it.match_ip("1.2.3.4"))
        self.assertIsNotNone(it.match_ip("5.6.7.200"))
        h = it.match_ip("9.8.7.6")
        self.assertIsNotNone(h)
        self.assertEqual(h["confidence"], "high")
        self.assertEqual(h["severity"], "critical")

    # ---- 附加：本地 MISP 风格 warninglist（JSON + 纯文本，离线） ----
    def test_local_warninglist_files(self):
        wdir = os.path.join(self.tmp, "warninglists")
        os.makedirs(wdir)
        with open(os.path.join(wdir, "google.json"), "w", encoding="utf-8") as fh:
            json.dump({"name": "google-allow", "type": "cidr",
                       "list": ["172.217.0.0/16"]}, fh)
        with open(os.path.join(wdir, "custom.txt"), "w", encoding="utf-8") as fh:
            fh.write("# 本地自定义\n13.107.0.0/16 ; 微软示例\n")
        it = self.intel()
        self.assertTrue(it.add("ip", "172.217.1.1", confidence="high")["ok"])
        self.assertTrue(it.add("ip", "13.107.5.5", confidence="high")["ok"])
        self.assertIsNone(it.match_ip("172.217.1.1"), "文件加载的网段未生效")
        self.assertIsNone(it.match_ip("13.107.5.5"))
        st = it.stats()["warninglists"]
        self.assertIn("google.json", st["sources"])
        self.assertIn("custom.txt", st["sources"])
        self.assertEqual(st["errors"], [])

    # ---- 附加：sighting 重置衰减时钟；误报抑制 ----
    def test_sight_reset_and_suppress(self):
        it = self.intel()
        it.add("ip", "5.6.7.8", confidence="high", last_seen=self.now - 30 * DAY)
        self.assertEqual(it.match_ip("5.6.7.8")["severity"], "medium")
        self.assertTrue(it.sight("ip", "5.6.7.8")["ok"])
        self.assertEqual(it.match_ip("5.6.7.8")["severity"], "critical")
        self.assertTrue(it.suppress("ip", "5.6.7.8", reason="业务误报")["ok"])
        self.assertIsNone(it.match_ip("5.6.7.8"))
        self.assertIn("5.6.7.8", it.data["ip"], "抑制不删除条目")

    # ---- 附加：最长前缀优先 + IPv6 网段 + 主机位规范化 ----
    def test_specificity_ipv6_and_normalization(self):
        it = self.intel()
        it.add("ip", "1.2.0.0/16", confidence="low")
        it.add("ip", "1.2.3.0/24", confidence="high")
        hit = it.match_ip("1.2.3.4")
        self.assertEqual(hit["matched_value"], "1.2.3.0/24")
        self.assertEqual(it.match_ip("1.2.9.9")["matched_value"], "1.2.0.0/16")
        it.add("ip", "2600:1f00::/32", confidence="high")   # 非 allowlist 的 v6 段
        self.assertIsNotNone(it.match_ip("2600:1f00:1::1"))
        self.assertIsNone(it.match_ip("2600:1f01::1"))
        it.add("ip", "7.7.7.7/24")                          # 主机位清零
        self.assertIn("7.7.7.0/24", it.data["ip"])
        self.assertIsNotNone(it.match_ip("7.7.7.200"))

    # ---- 附加：类别规则保持 low/medium 不升级；域名精确条目走闸门 ----
    def test_domain_gate_and_builtin_no_upgrade(self):
        it = self.intel()
        it.add("domain", "c2.evil.com", confidence="high")
        h = it.match_domain("c2.evil.com")
        self.assertEqual(h["severity"], "critical")
        self.assertEqual(h["rule"], "exact")
        low = it.match_domain("random123.xyz")
        self.assertEqual(low["rule"], "risky_tld")
        self.assertEqual(low["confidence"], "low", "类别规则不得被闸门升级")
        self.assertNotIn("severity", low)

    # ---- 附加：闸门边界与旧返回字段兼容 ----
    def test_gate_boundaries_and_compat_fields(self):
        self.assertEqual(score_to_severity(0.7), "critical")
        self.assertEqual(score_to_severity(0.69), "high")
        self.assertEqual(score_to_severity(0.4), "high")
        self.assertEqual(score_to_severity(0.39), "medium")
        self.assertEqual(decay_factor(0, 7, 0.55), 1.0)
        self.assertEqual(decay_factor(7, 7, 0.55), 0.0)
        it = self.intel()
        it.add("ip", "5.6.7.8", source="s", note="n", confidence="medium")
        hit = it.match_ip("5.6.7.8")
        for f in ("value", "source", "note", "confidence", "added", "matched_kind"):
            self.assertIn(f, hit, f"旧返回字段 {f} 丢失")
        st = it.stats()
        for f in ("ip", "domain", "hash", "builtin_categories", "path", "ts"):
            self.assertIn(f, st, f"stats 旧字段 {f} 丢失")
        self.assertEqual(st["lifecycle"]["block"], 1)
        self.assertEqual(len(it.listing()), 1)
        self.assertIn("severity", it.listing()[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
