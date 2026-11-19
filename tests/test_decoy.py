#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""诱饵端口回归：默认不开 / 只绑回环 / 真连接记录 / 停得干净 / 日志可审计。

用真 socket 在本机回环上跑（端口 0 让内核分配），不依赖外网、不占固定端口。
核心断言：
  · decoy.enabled=false 时一个端口都不开；
  · 0.0.0.0/:: 与外部地址默认拒绝，必须 allow_non_loopback 显式放行；
  · 连上来能记到来源 IP/端口/字节数/首行，且控制字节被清洗；
  · stop() 之后线程归零、端口可被重新 bind（不残留）；
  · 日志文件 0600、每行合法 JSON。

运行：python3 -m unittest discover -s tests -t tests
"""
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from atfield import config                        # noqa: E402
from atfield import decoy as dc                   # noqa: E402


def mk_cfg(tmp, **decoy_over):
    c = {"data_dir": tmp,
         "decoy": {"enabled": False, "bind": "127.0.0.1", "allow_non_loopback": False,
                   "ports": [0], "banner": "SSH-2.0-OpenSSH_9.6\r\n", "max_conns": 50,
                   "read_bytes": 512, "log_keep": 200}}
    c["decoy"].update(decoy_over)
    return c


def wait_for(fn, timeout=4.0, step=0.05):
    end = time.time() + timeout
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(step)
    return None


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="atfield-decoy-")
        self.d = None

    def tearDown(self):
        if self.d is not None:
            try:
                self.d.stop()
            except Exception:
                pass
        for root, dirs, files in os.walk(self.tmp, topdown=False):
            for f in files:
                try:
                    os.chmod(os.path.join(root, f), 0o600)
                except OSError:
                    pass
                try:
                    os.unlink(os.path.join(root, f))
                except OSError:
                    pass
            for dd in dirs:
                try:
                    os.rmdir(os.path.join(root, dd))
                except OSError:
                    pass
        try:
            os.rmdir(self.tmp)
        except OSError:
            pass


class BindPolicy(unittest.TestCase):
    def test_loopback_ok(self):
        for addr in ("127.0.0.1", "127.0.0.5", "::1"):
            v = dc.validate_bind(addr)
            self.assertTrue(v["ok"], addr)
            self.assertEqual(v["scope"], "loopback")

    def test_wildcard_rejected(self):
        for addr in ("0.0.0.0", "::", "*", ""):
            v = dc.validate_bind(addr)
            self.assertFalse(v["ok"], addr)
            self.assertIn("通配", v["error"])

    def test_external_needs_explicit_flag(self):
        # 192.0.2.0/24 是 TEST-NET-1 文档保留网段：只做地址分类断言，绝不监听
        self.assertFalse(dc.validate_bind("192.0.2.10")["ok"])
        v = dc.validate_bind("192.0.2.10", allow_non_loopback=True)
        self.assertTrue(v["ok"], v)
        self.assertEqual(v["scope"], "non-loopback")

    def test_hostname_rejected(self):
        v = dc.validate_bind("localhost")
        self.assertFalse(v["ok"])
        self.assertIn("IP 字面量", v["error"])


class Defaults(Base):
    def test_disabled_by_config_opens_nothing(self):
        self.d = dc.Decoy(mk_cfg(self.tmp))
        res = self.d.start_if_enabled()
        self.assertTrue(res.get("ok"))
        self.assertTrue(res.get("skipped"))
        self.assertFalse(self.d.running())
        self.assertEqual(self.d.status()["ports"], [])
        self.assertFalse(os.path.exists(self.d.log_path))

    def test_stop_when_not_running_is_safe(self):
        self.d = dc.Decoy(mk_cfg(self.tmp))
        res = self.d.stop()
        self.assertTrue(res["ok"])
        self.assertFalse(res["was_running"])

    def test_real_config_default_is_off(self):
        cfg = config.DEFAULTS["decoy"]
        self.assertFalse(cfg["enabled"])
        self.assertEqual(cfg["bind"], "127.0.0.1")
        self.assertFalse(cfg["allow_non_loopback"])


class ListenAndRecord(Base):
    def _start(self, **over):
        self.d = dc.Decoy(mk_cfg(self.tmp, **over))
        res = self.d.start()
        self.assertTrue(res.get("ok"), json.dumps(res, ensure_ascii=False))
        ports = res["ports"]
        self.assertEqual(len(ports), 1)
        return ports[0]

    def test_connection_recorded_with_peer_and_payload(self):
        port = self._start()
        s = socket.create_connection(("127.0.0.1", port), timeout=3)
        try:
            s.sendall(b"GET /admin HTTP/1.1\r\nHost: decoy\r\n\r\n")
            banner = s.recv(64)
        finally:
            s.close()
        self.assertIn(b"SSH-2.0", banner)

        ev = wait_for(lambda: self.d.event_count() and self.d.recent(1)[0])
        self.assertIsNotNone(ev, "没有记录到连接事件")
        self.assertEqual(ev["peer_ip"], "127.0.0.1")
        self.assertEqual(ev["listen_port"], port)
        self.assertGreater(ev["peer_port"], 0)
        self.assertGreaterEqual(ev["bytes"], len(b"GET /admin HTTP/1.1"))
        self.assertIn("GET /admin HTTP/1.1", ev["preview"])

    def test_control_bytes_sanitized(self):
        port = self._start()
        s = socket.create_connection(("127.0.0.1", port), timeout=3)
        try:
            s.sendall(b"\x00\x01\x02hello\x07\r\n")
        finally:
            s.close()
        ev = wait_for(lambda: self.d.event_count() and self.d.recent(1)[0])
        self.assertIsNotNone(ev)
        self.assertIn("hello", ev["preview"])
        for ch in ("\x00", "\x01", "\x07"):
            self.assertNotIn(ch, ev["preview"])
        self.assertLessEqual(len(ev["preview"]), dc.PREVIEW_MAX)

    def test_status_and_idempotent_start(self):
        port = self._start()
        st = self.d.status()
        self.assertTrue(st["running"])
        self.assertIn(port, st["ports"])
        self.assertEqual(st["threads_alive"], 1)
        self.assertEqual(st["scope"], "loopback")
        again = self.d.start()
        self.assertTrue(again["ok"])
        self.assertTrue(again["already"])
        self.assertEqual(again["ports"], [port])

    def test_stop_frees_port_and_threads(self):
        port = self._start()
        before = threading.active_count()
        res = self.d.stop()
        self.assertTrue(res["ok"])
        self.assertEqual(res["ports"], [port])
        self.assertFalse(self.d.running())
        self.assertEqual(self.d.status()["threads_alive"], 0)
        self.assertLessEqual(threading.active_count(), before)
        # 端口必须能立刻重新 bind（证明 socket 真的关了，不是只把标志位改了）
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("127.0.0.1", port))
            probe.listen(1)
        finally:
            probe.close()

    def test_log_file_jsonl_and_mode_600(self):
        port = self._start()
        for _ in range(2):
            s = socket.create_connection(("127.0.0.1", port), timeout=3)
            try:
                s.sendall(b"ping\n")
            finally:
                s.close()
        wait_for(lambda: self.d.event_count() >= 2)
        self.d.stop()
        self.assertTrue(os.path.isfile(self.d.log_path))
        mode = os.stat(self.d.log_path).st_mode & 0o777
        self.assertEqual(format(mode, "04o"), "0600")
        with open(self.d.log_path, encoding="utf-8") as fh:
            recs = [json.loads(ln) for ln in fh if ln.strip()]
        self.assertGreaterEqual(len(recs), 2)
        for r in recs:
            self.assertEqual(r["listen_port"], port)
            self.assertEqual(r["peer_ip"], "127.0.0.1")
            self.assertIn("iso", r)
            self.assertLessEqual(len(r["preview"]), dc.PREVIEW_MAX)

    def test_enabled_config_autostarts(self):
        self.d = dc.Decoy(mk_cfg(self.tmp, enabled=True))
        res = self.d.start_if_enabled()
        self.assertTrue(res.get("ok"))
        self.assertFalse(res.get("skipped"))
        self.assertTrue(self.d.running())
        self.d.stop()
        self.assertFalse(self.d.running())

    def test_bind_error_reported_not_raised(self):
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        busy = blocker.getsockname()[1]
        try:
            self.d = dc.Decoy(mk_cfg(self.tmp, ports=[busy]))
            res = self.d.start()
            self.assertFalse(res.get("ok"))
            self.assertIn("error", res)
            self.assertFalse(self.d.running())
        finally:
            blocker.close()


class AuditIntegration(Base):
    def test_audit_chain_gets_start_and_stop(self):
        calls = []

        class FakeAudit:
            def append(self, action, **kw):
                calls.append((action, kw))

        self.d = dc.Decoy(mk_cfg(self.tmp, port=0), audit=FakeAudit())
        self.d.start()
        self.d.stop()
        actions = [c[0] for c in calls]
        self.assertIn("decoy.start", actions)
        self.assertIn("decoy.stop", actions)
        start_detail = [c[1]["detail"] for c in calls if c[0] == "decoy.start"][0]
        self.assertEqual(start_detail["bind"], "127.0.0.1")
        self.assertEqual(len(start_detail["ports"]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
