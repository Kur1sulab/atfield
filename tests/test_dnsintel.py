#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DNS 异常判定（dnsintel）回归：DGA / 隧道启发式 + NetIntel 接线。

背景（2026-11-19 接手修复的三个真 bug，防止复发）：
  1) _labels() 原来整串 lower() → base64「必须含大写」判据永远不成立，
     aGVsbG8gd29ybGQgdGhpcyBpcyBh.evil.example.com 被判 ok(0.0)。
     现在字符集判定吃原始大小写，只有白名单/punycode 比较用小写；
     DnsIntel.observe 入口也不再 lower（去重键才用小写）。
  2) 纯辅音串 qwrtypsdfgh.net 原来只有 0.52(watch)。「一个元音都没有」
     现在是独立强信号（+0.25），不再靠辅音连缀权重叠加。
  3) 单段 54 字符的隧道域名原来 0.58 差一点到 0.60。重标定：
     ≥40 权重 0.32→0.40、中段门槛 30→24、大小写混杂 base64url 0.14→0.30
     （仅含连字符不再算 base64 证据，避免蹭到正常 hyphen 子域）。
另覆盖：暖机前 N 个观察只记录不报、暖机不得永久消音（不改动存储的 verdict）、
punycode 跳过、CDN 哈希主机名不误报、熵函数边界、NetIntel 事件产出/冷却/status.dns。

纪律：纯计算 + 临时目录 Store。不起服务、不占端口、不做任何网络请求——
集成测试把 hostname 预注入 NetIntel._resolved，绝不触发 gethostbyaddr。
运行：python3 -m unittest tests.test_dnsintel -v
"""
import os
import shutil
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from atfield.dnsintel import (DGA_MIN_LABEL, SUSPICIOUS, WATCH, DnsIntel,  # noqa: E402
                              analyze, dga_score, shannon_entropy, selftest,
                              tunnel_score)
from atfield.model import Event                       # noqa: E402
from atfield.netintel import NetIntel                 # noqa: E402
from atfield.store import Store                       # noqa: E402

# ---- 固定样本（正例形状来自真实 DGA / iodine / dnscat2 流量特征）----
DGA_POS = "xkjvqpzmrt.biz"
DGA_ZERO_VOWEL = "qwrtypsdfgh.net"
DGA_MIXED_CASE = "Xk7Qm9Zp2Rt4.com"
TUNNEL_B64 = "aGVsbG8gd29ybGQgdGhpcyBpcyBh.evil.example.com"
TUNNEL_LONG = ("dGhpcy1pcy1hLXZlcnktbG9uZy1zdWJkb21haW4tZm9yLXR1bm5lbA"
               ".exfil.click")
TUNNEL_B32 = "K7X3M2Q4Z2W5R6T3JBSWY3DPEHPK3PXPAB2CDE4F.tunnel.evil.net"
TUNNEL_MANY = ("Abcdefghij1234567890XyZw.Abcdefghij1234567890XyZw."
               "Abcdefghij1234567890XyZw.Abcdefghij1234567890XyZw."
               "Abcdefghij1234567890XyZw.evil.com")
DGA_WATCH = "bcdfg1a1e1i1o1u1bcdfg.net"          # 0.46：辅音连缀+数字比例
TUNNEL_WATCH = "abcdefghijklmnopqrstuvwx.example.net"  # 0.46：偏长+高熵
BENIGN = ["example.com", "www.google.com", "github.com", "mail.google.com",
          "news.ycombinator.com", "stackoverflow.com", "wikipedia.org",
          "serverfault.com", "kubernetes.io", "sourceforge.net",
          "slashdot.org", "arstechnica.com", "d111111abcdef8.cloudfront.net",
          "a1b2c3d4e5f6a7b8c9d0.cloudfront.net"]


class TestEntropy(unittest.TestCase):
    """熵函数边界：空串 / 单字符 / 重复字符不得抛错或出 NaN。"""

    def test_empty(self):
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_single_char(self):
        self.assertEqual(shannon_entropy("a"), 0.0)

    def test_repeated_chars(self):
        self.assertEqual(shannon_entropy("aaaaaaaaaaaa"), 0.0)

    def test_two_symbols(self):
        self.assertAlmostEqual(shannon_entropy("ab"), 1.0, places=9)

    def test_uniform_16(self):
        self.assertAlmostEqual(shannon_entropy("0123456789abcdef"), 4.0, places=9)

    def test_case_is_distinct(self):
        # 熵按原始字符统计：'A' 与 'a' 是两个符号（大小写证据的一部分）
        self.assertAlmostEqual(shannon_entropy("Aa"), 1.0, places=9)


class TestDga(unittest.TestCase):
    def test_positive_random_consonants(self):
        r = analyze(DGA_POS)
        self.assertGreaterEqual(r["score"], WATCH)
        self.assertEqual(r["kind"], "dga")

    def test_positive_zero_vowel_is_independent_signal(self):
        """bug#2 回归：零元音必须独立成信号，且直接把判定顶到 suspicious。"""
        r = analyze(DGA_ZERO_VOWEL)
        self.assertEqual(r["verdict"], "suspicious")
        self.assertIn("完全无元音", r["signals"])
        self.assertGreaterEqual(r["score"], SUSPICIOUS)

    def test_positive_mixed_case_not_swallowed(self):
        """bug#1 回归：DGA 路径的大小写混杂信号必须能吃到原始大写。"""
        r = dga_score(DGA_MIXED_CASE)
        self.assertIn("大小写混杂", r["signals"])
        self.assertEqual(r["verdict"], "suspicious")

    def test_positive_digit_heavy(self):
        r = analyze("jx8k2mq9zvp.net")
        self.assertEqual(r["verdict"], "suspicious")

    def test_negative_common_domains(self):
        for host in BENIGN:
            with self.subTest(host=host):
                r = analyze(host)
                self.assertEqual(r["verdict"], "ok",
                                 f"{host} 被误判：{r['signals']}")

    def test_negative_benign_suffix_with_random_subdomain(self):
        # 白名单后缀下的随机子域是云厂商自动命名，不按 DGA 算
        self.assertEqual(analyze("xk7q9m2z.random123.googleapis.com")["verdict"], "ok")

    def test_punycode_skipped(self):
        for host in ("xn--fiqs8s.com", "xn--fiqs8s.xn--55qx5d.cn"):
            with self.subTest(host=host):
                self.assertEqual(analyze(host)["verdict"], "ok")

    def test_hex_label_skipped(self):
        # 未知域下的纯 hex 注册域主体也不按 DGA 算（哈希形态）
        r = dga_score("a1b2c3d4e5f6a7b8c9d0.org")
        self.assertEqual(r["verdict"], "ok")
        self.assertIn("hex-label(cdn)", r["signals"])

    def test_short_label_not_judged(self):
        # 4~7 位随机串人类也在用，门槛以下不判
        self.assertEqual(analyze("xk7q.biz")["verdict"], "ok")
        self.assertLess(len("xk7q"), DGA_MIN_LABEL)

    def test_watch_band(self):
        r = analyze(DGA_WATCH)
        self.assertEqual(r["verdict"], "watch")
        self.assertEqual(r["kind"], "dga")
        self.assertTrue(WATCH <= r["score"] < SUSPICIOUS)


class TestTunnel(unittest.TestCase):
    def test_positive_base64_mixed_case(self):
        """bug#1 回归：原来 lower() 吞掉大写 → ok(0.0)，现在必须 suspicious。"""
        r = analyze(TUNNEL_B64)
        self.assertEqual(r["verdict"], "suspicious")
        self.assertEqual(r["kind"], "tunnel")
        self.assertTrue(any("base64url" in s for s in r["signals"]))

    def test_positive_very_long_single_label(self):
        """bug#3 回归：54 字符单段 + 3 段域名，原来 0.58 差一点，现在必须过线。"""
        r = analyze(TUNNEL_LONG)
        self.assertEqual(r["verdict"], "suspicious")
        self.assertGreaterEqual(r["score"], SUSPICIOUS)

    def test_positive_base32(self):
        r = analyze(TUNNEL_B32)
        self.assertEqual(r["verdict"], "suspicious")
        self.assertIn("base32 字符集", r["signals"])

    def test_positive_many_labels(self):
        r = analyze(TUNNEL_MANY)
        self.assertEqual(r["verdict"], "suspicious")
        self.assertTrue(any("段数" in s for s in r["signals"]))

    def test_negative_normal_domains(self):
        for host in ("www.example.com", "mail.google.com", "github.com"):
            with self.subTest(host=host):
                self.assertEqual(analyze(host)["verdict"], "ok")

    def test_negative_hyphen_subdomain(self):
        # 正常连字符子域：hyphen  alone 不再是 base64 证据
        r = analyze("my-long-service-name.example.com")
        self.assertEqual(r["verdict"], "ok")
        self.assertFalse(any("base64" in s for s in r["signals"]))

    def test_negative_cdn_hash_hostname(self):
        for host in ("d111111abcdef8.cloudfront.net",
                     "a1b2c3d4e5f6a7b8c9d0.cloudfront.net"):
            with self.subTest(host=host):
                self.assertEqual(analyze(host)["verdict"], "ok")

    def test_negative_hex_under_unknown_domain(self):
        # 未知域下的 32 位 hex：长度/熵可给弱分，但不得按 base32/base64 加权
        r = tunnel_score("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6.hash.example.org")
        self.assertEqual(r["verdict"], "ok")
        self.assertFalse(any("base" in s for s in r["signals"]))

    def test_punycode_label_skipped(self):
        host = "xn--" + "a" * 30 + ".example.com"
        r = tunnel_score(host)
        self.assertEqual(r["verdict"], "ok")
        self.assertIn("punycode", r["signals"])
        self.assertEqual(analyze(host)["verdict"], "ok")

    def test_watch_band(self):
        r = analyze(TUNNEL_WATCH)
        self.assertEqual(r["verdict"], "watch")
        self.assertEqual(r["kind"], "tunnel")


class TestCaseAndDedup(unittest.TestCase):
    """observe 入口的大小写保真与 DNS 大小写不敏感去重。"""

    def test_observe_keeps_case_evidence(self):
        d = DnsIntel(warmup_observations=0)
        rec = d.observe(TUNNEL_B64, "curl")
        self.assertEqual(rec["verdict"], "suspicious",
                         "入口 lower() 又把大写证据吞了？")

    def test_dedup_case_insensitive(self):
        d = DnsIntel(warmup_observations=0)
        d.observe("WWW.Example.COM", "curl")
        rec = d.observe("www.example.com", "curl")
        self.assertEqual(len(d.seen), 1)
        self.assertEqual(rec["hits"], 2)

    def test_strip_whitespace_and_trailing_dot(self):
        d = DnsIntel(warmup_observations=0)
        rec = d.observe("  example.com.  ")
        self.assertEqual(rec["host"], "example.com")
        self.assertIn("example.com", d.seen)

    def test_empty_observe(self):
        d = DnsIntel(warmup_observations=0)
        rec = d.observe("")
        self.assertEqual(rec["verdict"], "ok")
        self.assertEqual(len(d.seen), 0)

    def test_process_hits(self):
        d = DnsIntel(warmup_observations=0)
        d.observe("x.example.org", "curl")
        d.observe("x.example.org", "curl")
        rec = d.observe("x.example.org", "wget")
        self.assertEqual(rec["processes"], {"curl": 2, "wget": 1})


class TestWarmup(unittest.TestCase):
    """冷启动纪律（Darktrace 教训）：前 N 个观察只记录不报，之后必须能报。"""

    def test_first_n_observations_silent(self):
        d = DnsIntel(warmup_observations=3)
        for i in range(3):
            rec = d.observe(DGA_POS, "curl")
            self.assertEqual(rec["verdict"], "ok", f"第 {i+1} 个观察不该喊")
            self.assertTrue(rec["suppressed"])
        self.assertEqual(d.flagged, [])
        rec = d.observe(DGA_POS, "curl")
        self.assertEqual(rec["verdict"], "suspicious", "第 4 个观察必须给真实判定")
        self.assertEqual(len(d.flagged), 1)

    def test_warmup_does_not_permanently_silence(self):
        """暖机不得改写存储的 verdict，否则观察期结束后再观测也永远不报。"""
        d = DnsIntel(warmup_observations=1)
        rec = d.observe(DGA_POS)
        self.assertEqual(rec["verdict"], "ok")
        self.assertEqual(d.seen[DGA_POS]["verdict"], "suspicious",
                         "存储判定被暖机改写了？")
        d.observe("filler.example.com")          # 凑满暖机
        rec = d.observe(DGA_POS)
        self.assertEqual(rec["verdict"], "suspicious")
        self.assertGreaterEqual(len(d.flagged), 1)

    def test_zero_warmup_reports_immediately(self):
        d = DnsIntel(warmup_observations=0)
        self.assertEqual(d.observe(DGA_POS)["verdict"], "suspicious")

    def test_default_warmup_is_50(self):
        self.assertEqual(DnsIntel().warmup_observations, 50)

    def test_status_fields(self):
        d = DnsIntel(warmup_observations=2)
        d.observe(DGA_POS)
        st = d.status()
        for key in ("domains", "observations", "warming_up", "warmup_remaining",
                    "suspicious", "watch", "top", "flagged"):
            self.assertIn(key, st)
        self.assertTrue(st["warming_up"])
        self.assertEqual(st["warmup_remaining"], 1)
        d.observe("filler.example.com")
        self.assertFalse(d.status()["warming_up"])


class TestAnalyze(unittest.TestCase):
    def test_empty_and_none(self):
        self.assertEqual(analyze("")["verdict"], "ok")
        self.assertEqual(analyze(None)["verdict"], "ok")

    def test_kind_is_max_of_two(self):
        self.assertEqual(analyze(TUNNEL_B64)["kind"], "tunnel")
        self.assertEqual(analyze(DGA_POS)["kind"], "dga")

    def test_subject_shape(self):
        r = analyze(DGA_POS)
        for key in ("host", "score", "verdict", "kind", "signals", "dga", "tunnel"):
            self.assertIn(key, r)

    def test_module_selftest(self):
        ok, msg = selftest()
        self.assertTrue(ok, msg)


class TestNetIntelIntegration(unittest.TestCase):
    """NetIntel 接线：hostname → dnsintel → ndr.dga / ndr.dns_tunnel（走 _flag 冷却）。

    hostname 预注入 _resolved，绕开反向解析线程——测试不做任何网络请求。
    intel=None：形态判定必须独立于 IOC 名单工作（这正是 P1 建议的缺口）。
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="atfield-dnsintel-")
        self.cfg = {"data_dir": self.tmp, "dns": {"warmup_observations": 0}}
        self.store = Store(self.cfg)
        self.ni = NetIntel(self.cfg, self.store, intel=None)

    def tearDown(self):
        self.store.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _ev(self, ip, host=None, proc="curl", port=443, public=True):
        if host is not None:
            self.ni._resolved[ip] = host
        return Event(kind="net.connect", source="network", ts=time.time(),
                     pid=4242, process=proc,
                     subject={"rip": ip, "rport": port, "public": public,
                              "proto": "TCP"})

    def _ndr(self, out):
        return [e for e in out if e.kind.startswith("ndr.")]

    def test_dga_event_emitted(self):
        out = self.ni.observe([self._ev("203.0.113.7", DGA_POS)])
        evs = [e for e in self._ndr(out) if e.kind == "ndr.dga"]
        self.assertEqual(len(evs), 1)
        ev = evs[0]
        self.assertEqual(ev.source, "ndr")
        self.assertEqual(ev.severity, "medium")     # suspicious → medium
        self.assertEqual(ev.subject["domain"], DGA_POS)
        self.assertEqual(ev.subject["verdict"], "suspicious")
        self.assertGreaterEqual(ev.subject["score"], SUSPICIOUS)
        self.assertTrue(ev.subject["signals"])

    def test_tunnel_event_emitted(self):
        out = self.ni.observe([self._ev("203.0.113.8", TUNNEL_LONG)])
        evs = [e for e in self._ndr(out) if e.kind == "ndr.dns_tunnel"]
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0].severity, "medium")

    def test_watch_event_is_low(self):
        out = self.ni.observe([self._ev("203.0.113.9", TUNNEL_WATCH)])
        evs = self._ndr(out)
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0].kind, "ndr.dns_tunnel")
        self.assertEqual(evs[0].severity, "low")    # watch → low，冷启动不喊破喉咙

    def test_benign_host_no_event(self):
        out = self.ni.observe([self._ev("203.0.113.10", "www.google.com")])
        self.assertEqual(self._ndr(out), [])

    def test_cooldown_via_flag(self):
        ev = self._ev("203.0.113.7", DGA_POS)
        self.assertEqual(len(self.ni.observe([ev])), 1)
        self.assertEqual(self._ndr(self.ni.observe([ev])), [],
                         "900s 冷却内重复观测不得重复出事件")
        self.ni._flag_seen.clear()                  # 冷却到期等价操作
        self.assertEqual(len(self._ndr(self.ni.observe([ev]))), 1)

    def test_no_hostname_no_dns_event(self):
        # 私网 IP、无 hostname：没有域名就没有形态判定（也不触发反向解析）
        out = self.ni.observe([self._ev("10.0.0.5", public=False)])
        self.assertEqual(self._ndr(out), [])
        self.assertEqual(self.ni.dns.total, 0)

    def test_warmup_via_cfg(self):
        cfg = {"data_dir": self.tmp, "dns": {"warmup_observations": 2}}
        ni = NetIntel(cfg, self.store, intel=None)
        ni._resolved["203.0.113.7"] = DGA_POS
        ev = self._ev("203.0.113.7", DGA_POS)
        self.assertEqual(self._ndr(ni.observe([ev])), [], "暖机第 1 个观察不得报")
        self.assertEqual(self._ndr(ni.observe([ev])), [], "暖机第 2 个观察不得报")
        self.assertEqual(len(self._ndr(ni.observe([ev]))), 1, "暖机结束后必须报")
        self.assertEqual(ni.dns.warmup_observations, 2)

    def test_status_has_dns_field(self):
        self.ni.observe([self._ev("203.0.113.7", DGA_POS)])
        st = self.ni.status()
        self.assertIn("dns", st)
        self.assertEqual(st["dns"]["domains"], 1)
        self.assertEqual(st["dns"]["suspicious"], 1)
        self.assertFalse(st["dns"]["warming_up"])
        # observe 会把 status 落 store state，/api/ndr 与重启视图同样吃得到
        self.assertIn("dns", self.store.get_state("netintel"))

    def test_default_warmup_50_in_netintel(self):
        ni = NetIntel({"data_dir": self.tmp}, self.store, intel=None)
        self.assertEqual(ni.dns.warmup_observations, 50)
        self.assertTrue(ni.status()["dns"]["warming_up"])


class TestFusionMap(unittest.TestCase):
    """新事件 kind 必须登记进 core.FUSION_MAP，否则只流到事件流、升不成告警。"""

    def test_kinds_registered(self):
        from atfield.core import FUSION_MAP
        for kind, rid in (("ndr.dga", "NDR-DGA"),
                          ("ndr.dns_tunnel", "NDR-DNS-TUNNEL")):
            self.assertIn(kind, FUSION_MAP)
            spec = FUSION_MAP[kind]
            self.assertEqual(spec[0], rid)
            self.assertEqual(spec[2], "medium")
            self.assertIn("command_control", spec[3])
            self.assertTrue(spec[4])                # MITRE  technique 非空


if __name__ == "__main__":
    unittest.main(verbosity=2)