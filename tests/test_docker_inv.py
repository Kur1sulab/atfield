#!/usr/bin/env python3
"""Docker 容器态势验证：优雅降级 / 真实形状解析 / 安全标记逐条 / 镜像关联 / 只读。

运行：python3 -m unittest tests.test_docker_inv -v
fixture 全部自造（形状照抄真实 Docker Engine API 返回），不依赖真实守护进程；
最后一节真机冒烟只在 /var/run/docker.sock 存在时跑（仍只发 GET），否则 SKIP。
"""
import inspect as py_inspect
import os
import socket
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from atfield import docker_inv as di      # noqa: E402


# ---------------------------------------------------------------- fixture
def mk_container(name, image, state="running", net="bridge", mounts=None,
                 health="none", image_id=None, ports=None, created=1795012468,
                 cid=None):
    """形状照抄 /containers/json?all=1 的真实条目（含 Health/Mounts/Ports）。"""
    return {
        "Id": cid or ("ab" * 32),
        "Names": ["/" + name],
        "Image": image,
        "ImageID": image_id or ("sha256:" + "cd" * 32),
        "Command": "entrypoint",
        "Created": created,
        "Ports": ports or [],
        "Labels": {},
        "State": state,
        "Status": "Up 17 hours" if state == "running" else "Exited (0) 2 hours ago",
        "HostConfig": {"NetworkMode": net},
        "Health": {"Status": health, "FailingStreak": 0},
        "NetworkSettings": {"Networks": {}},
        "Mounts": mounts or [],
    }


def mk_inspect(cid, privileged=False, user="", net="bridge"):
    """形状照抄 /containers/{id}/json 的关键段。"""
    return {
        "Id": cid,
        "Config": {"User": user, "Image": "whatever"},
        "HostConfig": {"Privileged": privileged, "NetworkMode": net},
        "State": {"Running": True},
    }


def mk_image(iid, tags, size=100 * 1024 * 1024, created=1794000000):
    return {"Id": iid, "RepoTags": tags, "Size": size, "Created": created,
            "Labels": {}, "Containers": -1}


INFO = {"Name": "docker-desktop", "ServerVersion": "29.9.2",
        "OperatingSystem": "Docker Desktop", "OSType": "linux",
        "Architecture": "aarch64", "NCPU": 12, "MemTotal": 8319172608,
        "Containers": 2, "ContainersRunning": 1, "Images": 2,
        "DockerRootDir": "/var/lib/docker"}


class FakeDocker:
    """可注入的 fetch：记录每次调用，路径白名单之外直接断言失败。"""

    def __init__(self, containers, images, info=None, inspects=None,
                 raise_on=None):
        self.containers = containers
        self.images = images
        self.info = INFO if info is None else info
        self.inspects = inspects or {}
        self.raise_on = raise_on or {}
        self.calls = []

    def __call__(self, path):
        self.calls.append(("GET", path))
        if path in self.raise_on:
            raise self.raise_on[path]
        if path == "/info":
            return self.info
        if path == "/containers/json?all=1":
            return self.containers
        if path == "/images/json":
            return self.images
        if path.startswith("/containers/") and path.endswith("/json"):
            cid = path.split("/")[2]
            if cid in self.inspects:
                return self.inspects[cid]
            raise di.DockerError("no such container")
        raise AssertionError(f"意外路径（只读白名单之外）: {path}")


def by_name(inv, name):
    return next(c for c in inv["containers"] if c["name"] == name)


# ---------------------------------------------------------------- 降级
class GracefulDegradation(unittest.TestCase):
    def test_socket_missing(self):
        out = di.collect(sock_path="/nonexistent/atfield-test/docker.sock")
        self.assertIs(out["available"], False)
        self.assertIn("不存在", out["reason"])

    def test_permission_denied(self):
        def fetch(path):
            raise PermissionError(13, "Permission denied")
        out = di.collect(fetch=fetch)
        self.assertIs(out["available"], False)
        self.assertIn("权限", out["reason"])

    def test_daemon_not_running(self):
        def fetch(path):
            raise ConnectionRefusedError(61, "Connection refused")
        out = di.collect(fetch=fetch)
        self.assertIs(out["available"], False)
        self.assertIn("守护进程", out["reason"])

    def test_timeout(self):
        def fetch(path):
            raise socket.timeout("timed out")
        out = di.collect(fetch=fetch)
        self.assertIs(out["available"], False)
        self.assertIn("超时", out["reason"])

    def test_http_error(self):
        def fetch(path):
            raise di.DockerError("Docker API 返回 HTTP 500（/info）")
        out = di.collect(fetch=fetch)
        self.assertIs(out["available"], False)
        self.assertIn("500", out["reason"])

    def test_bad_shape(self):
        fake = FakeDocker({"not": "a list"}, [])
        out = di.collect(fetch=fake)
        self.assertIs(out["available"], False)
        self.assertIn("形状异常", out["reason"])

    def test_never_raises_on_garbage(self):
        def fetch(path):
            raise RuntimeError("boom")
        out = di.collect(fetch=fetch)          # 不抛异常即合格
        self.assertIs(out["available"], False)
        self.assertTrue(out["reason"])


# ---------------------------------------------------------------- 解析
class ParseRealShape(unittest.TestCase):
    def setUp(self):
        self.c1 = mk_container(
            "lab-php", "php:7.4-apache", cid="11" * 32,
            image_id="sha256:" + "aa" * 32,
            ports=[{"IP": "0.0.0.0", "PrivatePort": 80, "PublicPort": 18094,
                    "Type": "tcp"},
                   {"IP": "::", "PrivatePort": 80, "PublicPort": 18094,
                    "Type": "tcp"}])
        self.c2 = mk_container(
            "deser-mysql", "mysql:8.0", state="exited", cid="22" * 32,
            image_id="sha256:" + "bb" * 32, created=1794000000,
            mounts=[{"Type": "volume", "Source": "/var/lib/docker/volumes/x/_data",
                     "Destination": "/var/lib/mysql"}])
        self.i1 = mk_image("sha256:" + "aa" * 32, ["php:7.4-apache"],
                           size=420 * 1024 * 1024)
        self.i2 = mk_image("sha256:" + "bb" * 32, ["mysql:8.0"],
                           size=780 * 1024 * 1024)
        self.fake = FakeDocker(
            [self.c1, self.c2], [self.i1, self.i2],
            inspects={"11" * 32: mk_inspect("11" * 32, user=""),
                      "22" * 32: mk_inspect("22" * 32, user="999")})
        self.out = di.collect(fetch=self.fake)

    def test_available_and_schema(self):
        self.assertIs(self.out["available"], True)
        c = by_name(self.out, "lab-php")
        for key in ("id", "name", "image", "state", "state_cn", "running",
                    "ports", "created", "created_cn", "user", "flags"):
            self.assertIn(key, c)
        self.assertEqual(c["name"], "lab-php")        # 去掉前导 /
        self.assertEqual(c["state_cn"], "运行中")
        self.assertIs(c["running"], True)
        self.assertEqual(c["created"], 1795012468)
        self.assertEqual(c["ports"], ["0.0.0.0:18094→80/tcp"])  # IPv6 双胞胎去重

    def test_stopped_container(self):
        c = by_name(self.out, "deser-mysql")
        self.assertIs(c["running"], False)
        self.assertEqual(c["state_cn"], "已退出")
        self.assertEqual(c["ports"], [])

    def test_running_first(self):
        self.assertEqual(self.out["containers"][0]["name"], "lab-php")

    def test_totals_and_daemon(self):
        t = self.out["totals"]
        self.assertEqual(t["containers"], 2)
        self.assertEqual(t["running"], 1)
        self.assertEqual(t["stopped"], 1)
        self.assertEqual(t["images"], 2)
        self.assertEqual(self.out["daemon"]["version"], "29.9.2")
        self.assertEqual(self.out["daemon"]["arch"], "aarch64")

    def test_image_schema(self):
        img = self.out["images"][0]
        for key in ("id", "tags", "size", "size_cn", "used_by", "dangling"):
            self.assertIn(key, img)
        self.assertIn("MB", img["size_cn"])


# ---------------------------------------------------------------- 标记
class SecurityFlags(unittest.TestCase):
    def assess(self, raw, insp):
        hits, _ = di.assess_container(raw, insp)
        return hits

    def test_privileged(self):
        raw = mk_container("p", "img:1", cid="01" * 32)
        self.assertIn("privileged",
                      self.assess(raw, mk_inspect(raw["Id"], privileged=True)))
        self.assertNotIn("privileged",
                         self.assess(raw, mk_inspect(raw["Id"], privileged=False)))

    def test_docker_sock_mount(self):
        for src, dst in (("/var/run/docker.sock", "/var/run/docker.sock"),
                         ("/host_mnt/var/run/docker.sock", "/var/run/docker.sock"),
                         ("/Users/xu./.docker/run/docker.sock", "/run/docker.sock")):
            raw = mk_container("s", "img:1", cid="02" * 32,
                               mounts=[{"Type": "bind", "Source": src,
                                        "Destination": dst}])
            self.assertIn("docker_sock", self.assess(raw, mk_inspect(raw["Id"])),
                          f"{src} 应命中")
        raw = mk_container("s", "img:1", cid="03" * 32,
                           mounts=[{"Type": "bind", "Source": "/Users/xu./code",
                                    "Destination": "/app"}])
        self.assertNotIn("docker_sock", self.assess(raw, mk_inspect(raw["Id"])))

    def test_host_network(self):
        raw = mk_container("h", "img:1", cid="04" * 32, net="host")
        self.assertIn("host_network", self.assess(raw, mk_inspect(raw["Id"])))
        raw = mk_container("b", "img:1", cid="05" * 32, net="bridge")
        self.assertNotIn("host_network", self.assess(raw, mk_inspect(raw["Id"])))

    def test_root_user(self):
        raw = mk_container("r", "img:1", cid="06" * 32)
        for user in ("", "root", "0", "0:0"):
            self.assertIn("root_user",
                          self.assess(raw, mk_inspect(raw["Id"], user=user)),
                          f"user={user!r} 应命中")
        for user in ("1000", "appuser", "999:999"):
            self.assertNotIn("root_user",
                             self.assess(raw, mk_inspect(raw["Id"], user=user)),
                             f"user={user!r} 不应命中")

    def test_root_unknown_when_inspect_fails(self):
        raw = mk_container("r", "img:1", cid="07" * 32)
        hits, facts = di.assess_container(raw, None)
        self.assertNotIn("root_user", hits)      # 未知 ≠ root，不许猜
        self.assertEqual(facts["user"], "未知")
        self.assertIsNone(facts["privileged"])

    def test_no_healthcheck(self):
        raw = mk_container("n", "img:1", cid="08" * 32, health="none")
        self.assertIn("no_healthcheck", self.assess(raw, mk_inspect(raw["Id"])))
        for h in ("healthy", "unhealthy", "starting"):
            raw = mk_container("n", "img:1", cid="09" * 32, health=h)
            self.assertNotIn("no_healthcheck",
                             self.assess(raw, mk_inspect(raw["Id"])))

    def test_bad_tag(self):
        bad = ["adminer:latest", "deser-docker-web", "<none>:<none>",
               "sha256:" + "ab" * 32, ""]
        good = ["redis:7-alpine", "php:7.4-apache", "ukiyo:1.1.0",
                "registry:5000/app:v1", "app@sha256:" + "cd" * 32]
        for img in bad:
            raw = mk_container("t", img, cid="0a" * 32)
            self.assertIn("bad_tag", self.assess(raw, mk_inspect(raw["Id"])),
                          f"{img!r} 应命中")
        for img in good:
            raw = mk_container("t", img, cid="0b" * 32)
            self.assertNotIn("bad_tag", self.assess(raw, mk_inspect(raw["Id"])),
                             f"{img!r} 不应命中")

    def test_severity_order(self):
        raw = mk_container("all", "x:latest", cid="0c" * 32, net="host",
                           health="none",
                           mounts=[{"Type": "bind", "Source": "/var/run/docker.sock",
                                    "Destination": "/var/run/docker.sock"}])
        hits, _ = di.assess_container(raw, mk_inspect(raw["Id"], privileged=True))
        self.assertEqual(hits[:2], ["privileged", "docker_sock"])
        self.assertEqual(hits, sorted(hits, key=lambda k: di._SEV_ORDER[
            di.FLAG_DEFS[k]["severity"]]))

    def test_flag_counts_in_totals(self):
        c1 = mk_container("priv", "img:latest", cid="10" * 32, net="host")
        c2 = mk_container("calm", "img:1", cid="20" * 32, health="healthy")
        fake = FakeDocker([c1, c2], [], inspects={
            "10" * 32: mk_inspect("10" * 32, privileged=True, user=""),
            "20" * 32: mk_inspect("20" * 32, user="1000")})
        out = di.collect(fetch=fake)
        t = out["totals"]
        self.assertEqual(t["flagged_containers"], 1)
        self.assertEqual(t["flags"]["privileged"], 1)
        self.assertEqual(t["flags"]["host_network"], 1)
        self.assertEqual(t["flags"]["root_user"], 1)
        self.assertEqual(t["flags"]["bad_tag"], 1)
        self.assertEqual(t["flags"]["docker_sock"], 0)
        self.assertEqual(by_name(out, "calm")["flags"], [])

    def test_inspect_failure_keeps_container(self):
        c1 = mk_container("x", "img:1", cid="30" * 32)
        fake = FakeDocker([c1], [], inspects={})     # inspect 全部失败
        out = di.collect(fetch=fake)
        self.assertIs(out["available"], True)
        c = by_name(out, "x")
        self.assertEqual(c["user"], "未知")
        self.assertNotIn("root_user", c["flag_keys"])


# ---------------------------------------------------------------- 关联
class ImageContainerLink(unittest.TestCase):
    def test_link_by_image_id(self):
        iid = "sha256:" + "ee" * 32
        c = mk_container("ukiyo", "ukiyo:1.1.0", cid="40" * 32, image_id=iid)
        img = mk_image(iid, ["ukiyo:1.1.0"])
        out = di.collect(fetch=FakeDocker([c], [img],
                                          inspects={"40" * 32: mk_inspect("40" * 32)}))
        self.assertEqual(out["images"][0]["used_by"], ["ukiyo"])

    def test_link_by_tag_when_id_differs(self):
        c = mk_container("adminer", "adminer:latest", cid="50" * 32,
                         image_id="sha256:" + "ff" * 32)
        img = mk_image("sha256:" + "99" * 32, ["adminer:latest"])
        out = di.collect(fetch=FakeDocker([c], [img],
                                          inspects={"50" * 32: mk_inspect("50" * 32)}))
        self.assertEqual(out["images"][0]["used_by"], ["adminer"])

    def test_unused_and_dangling(self):
        img = mk_image("sha256:" + "88" * 32, ["<none>:<none>"])
        out = di.collect(fetch=FakeDocker([], [img]))
        self.assertEqual(out["images"][0]["used_by"], [])
        self.assertIs(out["images"][0]["dangling"], True)
        self.assertEqual(out["totals"]["dangling_images"], 1)

    def test_two_containers_one_image(self):
        iid = "sha256:" + "77" * 32
        cs = [mk_container("a", "redis:7-alpine", cid="61" * 32, image_id=iid),
              mk_container("b", "redis:7-alpine", cid="62" * 32, image_id=iid,
                           state="exited")]
        img = mk_image(iid, ["redis:7-alpine"])
        out = di.collect(fetch=FakeDocker(cs, [img], inspects={
            "61" * 32: mk_inspect("61" * 32), "62" * 32: mk_inspect("62" * 32)}))
        self.assertEqual(out["images"][0]["used_by"], ["a", "b"])


# ---------------------------------------------------------------- 只读
class ReadOnlyGuarantee(unittest.TestCase):
    def test_only_get_whitelisted_paths(self):
        c = mk_container("x", "img:1", cid="70" * 32)
        fake = FakeDocker([c], [], inspects={"70" * 32: mk_inspect("70" * 32)})
        di.collect(fetch=fake)
        self.assertTrue(fake.calls)
        for method, path in fake.calls:
            self.assertEqual(method, "GET")
            ok = (path in ("/info", "/containers/json?all=1", "/images/json")
                  or (path.startswith("/containers/") and path.endswith("/json")))
            self.assertTrue(ok, f"白名单外路径: {path}")

    def test_source_has_no_write_verbs(self):
        src = py_inspect.getsource(di)
        for verb in ('"POST"', '"PUT"', '"DELETE"', '"PATCH"',
                     "subprocess", "docker exec", "os.system"):
            self.assertNotIn(verb, src, f"模块源码不应出现 {verb}")


# ---------------------------------------------------------------- 真机冒烟
@unittest.skipUnless(os.path.exists(di.DEFAULT_SOCK),
                     "本机没有 docker.sock，跳过真机冒烟")
class RealDaemonSmoke(unittest.TestCase):
    def test_real_collect_readonly(self):
        out = di.collect(timeout=10.0)
        self.assertIs(out["available"], True, out.get("reason"))
        self.assertIsInstance(out["containers"], list)
        self.assertEqual(out["totals"]["containers"], len(out["containers"]))
        self.assertEqual(out["totals"]["running"],
                         sum(1 for c in out["containers"] if c["running"]))
        for c in out["containers"]:
            self.assertTrue(c["name"])
            self.assertIn(c["state"], di.STATE_CN)


if __name__ == "__main__":
    unittest.main(verbosity=2)
