#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""凭据静态暴露盘点回归：命中判定 / 强制脱敏 / 白名单 / 只读保证。

铁律（任一红了就说明这一层已经不能上生产）：
  · 完整密钥绝不出现在返回体里——只给前 6 位 + 长度 + 不可逆指纹；
  · 权限过宽的私钥、没进 .gitignore 的 .env 必须带「为什么算风险」；
  · 扫自身仓库时 tests/ 里的假 key 不能被当成命中；
  · 扫描前后文件内容/权限/大小不变（只读）。

所有样本都是编造的固定串（不是真凭据），且拼装写入，避免本文件自己
被别的扫描器当成泄漏源。

运行：python3 -m unittest discover -s tests -t tests
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from atfield import config                        # noqa: E402
from atfield import credscan as cs                # noqa: E402

# 合成样本：全部为编造字符串（AKIA + 16 位大写字母数字），不是任何真实凭据
AWS_KEY = "AKIA" + "Z7XK9LMN2PQRSTUV"
GENERIC_PW = "S3cr3t-" + "Passw0rd-Test-01"
DB_PW = "pg-" + "Pa55w0rd-Test"
# jwt.io 公开示例 token（全球文档里的演示值，不是凭据）
JWT_LIKE = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
PRIV_BODY = ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
             + ("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo" * 2) + "\n")


def mk_cfg(tmp, **credscan_over):
    c = {
        "data_dir": os.path.join(tmp, "data"),
        "credscan": {
            "enabled": True, "roots": [], "max_files": 500,
            "max_bytes": 262144, "max_seconds": 10.0, "mask_keep": 6,
            "whitelist_enabled": True, "whitelist": [], "exclude": [],
        },
    }
    c["credscan"].update(credscan_over)
    return c


def write(path, text, mode=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    if mode is not None:
        os.chmod(path, mode)
    return path


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="atfield-credscan-")

    def tearDown(self):
        for root, dirs, files in os.walk(self.tmp, topdown=False):
            for f in files:
                try:
                    os.chmod(os.path.join(root, f), 0o600)
                except OSError:
                    pass
            for d in dirs:
                try:
                    os.rmdir(os.path.join(root, d))
                except OSError:
                    pass
        try:
            os.rmdir(self.tmp)
        except OSError:
            pass

    def scan(self, roots=None, **cfg_over):
        sc = cs.Scanner(mk_cfg(self.tmp, **cfg_over))
        return sc.scan(roots=roots or [self.tmp])


class Redaction(Base):
    """硬红线：输出里不许出现完整凭据。"""

    def test_aws_key_masked_but_detected(self):
        write(os.path.join(self.tmp, "proj", "settings.py"),
              f'AWS_ACCESS_KEY_ID = "{AWS_KEY}"\n')
        res = self.scan()
        self.assertTrue(res["ok"])
        hits = [h for h in res["hits"] if h["kind"] == "aws_access_key"]
        self.assertEqual(len(hits), 1, json.dumps(res, ensure_ascii=False))
        h = hits[0]
        self.assertEqual(h["prefix"], AWS_KEY[:6])
        self.assertEqual(h["length"], 20)
        self.assertEqual(h["line"], 1)
        self.assertEqual(h["masked"], AWS_KEY[:6] + "\u2026（20 位）")
        blob = json.dumps(res, ensure_ascii=False)
        self.assertNotIn(AWS_KEY, blob)                 # ← 红线
        self.assertNotIn(AWS_KEY[6:], blob)             # 连后半段也不许有
        self.assertEqual(len(h["fingerprint"]), cs.FINGERPRINT_LEN)
        self.assertNotEqual(h["fingerprint"], AWS_KEY)
        self.assertEqual(res["redaction"]["keep"], 6)
        self.assertTrue(res["readonly"])

    def test_generic_password_redacted(self):
        write(os.path.join(self.tmp, "app.ini"), f"password = {GENERIC_PW}\n")
        res = self.scan()
        hits = [h for h in res["hits"] if h["kind"] == "generic_secret"]
        self.assertEqual(len(hits), 1, json.dumps(res, ensure_ascii=False))
        self.assertEqual(hits[0]["length"], len(GENERIC_PW))
        self.assertNotIn(GENERIC_PW, json.dumps(res, ensure_ascii=False))
        self.assertTrue(any("明文" in r for r in hits[0]["risks"]))

    def test_db_url_password_redacted(self):
        write(os.path.join(self.tmp, "docker-compose.yml"),
              f'db: "postgres://svc:{DB_PW}@db.internal:5432/app"\n')
        res = self.scan()
        hits = [h for h in res["hits"] if h["kind"] == "db_url_password"]
        self.assertEqual(len(hits), 1, json.dumps(res, ensure_ascii=False))
        self.assertNotIn(DB_PW, json.dumps(res, ensure_ascii=False))
        self.assertEqual(hits[0]["prefix"], DB_PW[:6])

    def test_jwt_detected_and_redacted(self):
        write(os.path.join(self.tmp, "notes.txt"), f"token: {JWT_LIKE}\n")
        res = self.scan()
        self.assertGreaterEqual(len([h for h in res["hits"] if h["kind"] == "jwt"]), 1,
                                json.dumps(res, ensure_ascii=False))
        self.assertNotIn(JWT_LIKE, json.dumps(res, ensure_ascii=False))

    def test_mask_short_values_never_leak(self):
        # 6 位及以下：连前缀都不给（前 6 位就是全文）
        for v in ("a", "abc123"):
            m = cs.mask(v)
            self.assertEqual(m["prefix"], "", v)
            self.assertNotIn(v, m["masked"], v)
            self.assertEqual(m["length"], len(v))
        # 7 位：只给 6 位，第 7 位必须被吞掉
        m = cs.mask("abcdefg")
        self.assertEqual(m["prefix"], "abcdef")
        self.assertNotIn("abcdefg", m["masked"])

    def test_mask_keep_cannot_exceed_six(self):
        self.assertEqual(cs.mask("X" * 40, keep=99)["prefix"], "X" * 6)
        sc = cs.Scanner(mk_cfg(self.tmp, mask_keep=64))
        self.assertEqual(sc.keep, 6)


class Detection(Base):
    def test_private_key_mode_risk(self):
        p = write(os.path.join(self.tmp, ".ssh", "id_rsa"), PRIV_BODY, 0o644)
        res = self.scan()
        hits = [h for h in res["hits"] if h["kind"] == "private_key"]
        self.assertEqual(len(hits), 1, json.dumps(res, ensure_ascii=False))
        h = hits[0]
        self.assertEqual(h["path"], p)
        self.assertEqual(h["severity"], "critical")
        self.assertEqual(h["masked"], "私钥块（内容不取样）")
        self.assertTrue(any("0644" in r for r in h["risks"]), h["risks"])
        self.assertNotIn("QUJDREVGR0hJSktM", json.dumps(res, ensure_ascii=False))

        os.chmod(p, 0o600)
        res2 = self.scan()
        h2 = [h for h in res2["hits"] if h["kind"] == "private_key"][0]
        self.assertFalse(any("权限" in r for r in h2["risks"]), h2["risks"])

    def test_env_not_in_gitignore_is_flagged(self):
        repo = os.path.join(self.tmp, "repo")
        os.makedirs(os.path.join(repo, ".git"))
        write(os.path.join(repo, ".env"), f"DB_PASSWORD={DB_PW}\n")
        res = self.scan()
        hit = [h for h in res["hits"] if h["path"].endswith(".env")]
        self.assertEqual(len(hit), 1, json.dumps(res, ensure_ascii=False))
        self.assertTrue(any(".gitignore" in r for r in hit[0]["risks"]), hit[0]["risks"])

        write(os.path.join(repo, ".gitignore"), ".env\n")
        res2 = self.scan()
        hit2 = [h for h in res2["hits"] if h["path"].endswith(".env")]
        self.assertEqual(len(hit2), 1)
        self.assertFalse(any(".gitignore" in r for r in hit2[0]["risks"]), hit2[0]["risks"])

    def test_duplicate_secret_across_files_flagged(self):
        write(os.path.join(self.tmp, "a", "one.env"), f"API_TOKEN={GENERIC_PW}\n")
        write(os.path.join(self.tmp, "b", "two.env"), f"API_TOKEN={GENERIC_PW}\n")
        res = self.scan()
        multi = [h for h in res["hits"] if any("整体轮换" in r for r in h["risks"])]
        self.assertEqual(len(multi), 2, json.dumps(res, ensure_ascii=False))
        self.assertEqual(res["totals"]["unique_secrets"], 1)

    def test_placeholder_values_not_reported(self):
        write(os.path.join(self.tmp, "conf", "sample.env"),
              'password = "changeme"\n'
              'api_key = "${API_KEY}"\n'
              'token = "your_token_here"\n'
              'secret = "xxxxxxxx"\n')
        res = self.scan()
        self.assertEqual(res["totals"]["hits"], 0, json.dumps(res["hits"], ensure_ascii=False))

    def test_no_false_positive_on_binary(self):
        with open(os.path.join(self.tmp, "blob.bin"), "wb") as fh:
            fh.write(b"\x00\x01" + AWS_KEY.encode())
        res = self.scan()
        self.assertEqual(res["totals"]["hits"], 0)


class WhitelistAndExclusions(Base):
    def test_tests_dir_is_whitelisted(self):
        # 与真实测试同样的内容，放在 tests/ 下就不该命中
        write(os.path.join(self.tmp, "repo", "tests", "test_auth.py"),
              f'KEY = "{AWS_KEY}"\npassword = "{GENERIC_PW}"\n')
        res = self.scan()
        self.assertEqual(res["totals"]["hits"], 0, json.dumps(res["hits"], ensure_ascii=False))
        self.assertGreaterEqual(res["skipped"]["whitelisted"], 1)

    def test_sample_files_whitelisted(self):
        write(os.path.join(self.tmp, "conf", "credentials.sample"),
              f'AWS_ACCESS_KEY_ID="{AWS_KEY}"\n')
        self.assertEqual(self.scan()["totals"]["hits"], 0)

    def test_inline_allow_marker(self):
        write(os.path.join(self.tmp, "proj", "cfg.py"),
              f'A = "{AWS_KEY}"   # atfield:allow-cred 文档示例\n')
        self.assertEqual(self.scan()["totals"]["hits"], 0)

    def test_extra_whitelist_from_config(self):
        write(os.path.join(self.tmp, "libs", "x.py"), f'A = "{AWS_KEY}"\n')
        self.assertEqual(len(self.scan()["hits"]), 1)
        res = self.scan(whitelist=[os.path.join(self.tmp, "libs", "*")])
        self.assertEqual(res["totals"]["hits"], 0)

    def test_whitelist_can_be_disabled(self):
        write(os.path.join(self.tmp, "repo", "tests", "x.py"), f'A = "{AWS_KEY}"\n')
        self.assertEqual(self.scan()["totals"]["hits"], 0)
        res = self.scan(whitelist_enabled=False)
        self.assertEqual(res["totals"]["hits"], 1)

    def test_own_data_dir_excluded(self):
        write(os.path.join(self.tmp, "data", "leak.env"), f"PASSWORD={GENERIC_PW}\n")
        write(os.path.join(self.tmp, "proj", "ok.env"), f"PASSWORD={DB_PW}\n")
        res = self.scan()
        paths = [h["path"] for h in res["hits"]]
        self.assertTrue(all(os.sep + "data" + os.sep not in p for p in paths), paths)
        self.assertTrue(any("ok.env" in p for p in paths))

    def test_self_repo_scan_has_no_sample_hits(self):
        """扫自身仓库的 tests/：本文件里就写着假 key，结果必须是 0 命中。"""
        repo_tests = os.path.dirname(os.path.abspath(__file__))
        sc = cs.Scanner(mk_cfg(self.tmp))
        res = sc.scan(roots=[repo_tests])
        self.assertTrue(res["ok"])
        self.assertEqual(res["totals"]["hits"], 0,
                         json.dumps(res["hits"], ensure_ascii=False)[:800])


class RegressionOverlap(Base):
    """真机扫家目录时暴露的两个噪声源，必须有回归。"""

    def test_overlapping_roots_report_each_hit_once(self):
        sub = os.path.join(self.tmp, "proj")
        write(os.path.join(sub, "a.env"), f"API_TOKEN={GENERIC_PW}\n")
        res = self.scan(roots=[self.tmp, sub])       # 故意给父子重叠的根
        self.assertEqual(res["totals"]["hits"], 1, json.dumps(res["hits"], ensure_ascii=False))
        self.assertEqual(len(res["hits"]), 1)

    def test_private_key_has_no_fingerprint_and_no_rotation_noise(self):
        write(os.path.join(self.tmp, "a", "id_rsa"), PRIV_BODY, 0o600)
        write(os.path.join(self.tmp, "b", "id_ed25519"), PRIV_BODY, 0o600)
        res = self.scan()
        keys = [h for h in res["hits"] if h["kind"] == "private_key"]
        self.assertEqual(len(keys), 2)
        for h in keys:
            self.assertEqual(h["fingerprint"], "")
            self.assertFalse(any("整体轮换" in r for r in h["risks"]), h["risks"])
        self.assertEqual(res["totals"]["unique_secrets"], 0)


class ReadOnlyGuarantee(Base):
    def test_files_unchanged_after_scan(self):
        p1 = write(os.path.join(self.tmp, "proj", "a.env"), f"PASSWORD={GENERIC_PW}\n", 0o640)
        p2 = write(os.path.join(self.tmp, ".ssh", "id_rsa"), PRIV_BODY, 0o644)
        before = {}
        for p in (p1, p2):
            st = os.stat(p)
            with open(p, "rb") as fh:
                before[p] = (fh.read(), st.st_mode, st.st_size, st.st_mtime_ns)
        self.scan()
        for p, (body, mode, size, mtime) in before.items():
            st = os.stat(p)
            with open(p, "rb") as fh:
                self.assertEqual(fh.read(), body)
            self.assertEqual(st.st_mode, mode)
            self.assertEqual(st.st_size, size)
            self.assertEqual(st.st_mtime_ns, mtime)

    def test_source_has_no_write_or_upload_verbs(self):
        with open(os.path.abspath(cs.__file__), encoding="utf-8") as fh:
            src = fh.read()
        for bad in ('"w")', "'w'", "os.remove", "os.unlink", "os.rename", "shutil.",
                    "subprocess", "requests.", "urllib", "socket.", "http.client"):
            self.assertNotIn(bad, src, f"credscan.py 出现写/外连动作：{bad}")


class ConfigDefaults(unittest.TestCase):
    def test_defaults_present_and_safe(self):
        cfg = config.DEFAULTS
        self.assertIn("credscan", cfg)
        self.assertIn("decoy", cfg)
        self.assertTrue(cfg["credscan"]["enabled"])
        self.assertEqual(cfg["credscan"]["mask_keep"], 6)
        self.assertFalse(cfg["decoy"]["enabled"])          # 默认不开
        self.assertEqual(cfg["decoy"]["bind"], "127.0.0.1")

    def test_scan_over_real_config_defaults(self):
        tmp = tempfile.mkdtemp(prefix="atfield-credscan-cfg-")
        try:
            cfg = config.load()
            cfg["data_dir"] = tmp
            sc = cs.Scanner(cfg)
            self.assertEqual(sc.keep, 6)
            self.assertTrue(sc.whitelist.enabled)
            self.assertIn("tests", " ".join(sc.whitelist.patterns))
        finally:
            for root, dirs, files in os.walk(tmp, topdown=False):
                for f in files:
                    os.unlink(os.path.join(root, f))
                for d in dirs:
                    os.rmdir(os.path.join(root, d))
            os.rmdir(tmp)


if __name__ == "__main__":
    unittest.main(verbosity=2)
