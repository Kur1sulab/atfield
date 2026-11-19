"""Docker 容器态势：docker.sock 只读枚举容器/镜像 + 安全标记。

调研报告 04-cloud-native.md §5 Layer 1 的落地：不封装 docker CLI（可能没装），
纯 Python 标准库 http.client + socket(AF_UNIX) 直连 Docker Engine API。
无云凭据、无内核工作、无第三方依赖。

铁律：
- 只发 GET（/info、/containers/json、/images/json、/containers/{id}/json），
  一条写操作都没有；不 exec、不 attach、不碰容器生命周期。
- 任何失败（socket 不存在 / 权限不足 / 守护进程没起 / 超时 / 坏 JSON）都降级为
  {"available": False, "reason": "..."}，绝不抛异常拖垮 8866 服务。
- 「读不到」与「没有容器」是两回事，前端必须分开说人话。
- 列表 API 的 HostConfig 只带 NetworkMode；privileged 与运行用户必须逐容器
  inspect 补齐（仍是 GET）。单个 inspect 失败只让该容器的 user/privileged
  记「未知」，不整体降级，也不猜。

安全标记是配置事实，不是入侵判定：攻防靶机带标记属预期，产品价值在于
「一眼看见哪台容器有逃逸面」，而不是把它们当告警。
"""
from __future__ import annotations

import http.client
import json
import os
import socket
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

DEFAULT_SOCK = "/var/run/docker.sock"

# 标记定义：key → 中文名 / 严重度 / 一句话解释。前端直接渲染这份字典，
# 保证「后端判定」与「前端展示」永远同一套口径。
FLAG_DEFS: Dict[str, Dict[str, str]] = {
    "privileged": {
        "label": "特权模式", "severity": "critical",
        "desc": "拥有几乎全部主机内核能力，容器逃逸即主机沦陷",
    },
    "docker_sock": {
        "label": "挂载 docker.sock", "severity": "critical",
        "desc": "容器内可指挥 Docker 守护进程，容器逃逸第一跳",
    },
    "host_network": {
        "label": "host 网络", "severity": "high",
        "desc": "共享主机网络命名空间，失去网络隔离",
    },
    "root_user": {
        "label": "root 运行", "severity": "medium",
        "desc": "未指定 user，容器内进程默认以 root 运行",
    },
    "no_healthcheck": {
        "label": "无健康检查", "severity": "low",
        "desc": "未配置 healthcheck，进程僵死不会被发现",
    },
    "bad_tag": {
        "label": "latest/无标签", "severity": "low",
        "desc": "镜像版本不可追溯，重建即漂移",
    },
}
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

STATE_CN = {
    "running": "运行中", "exited": "已退出", "created": "已创建",
    "paused": "已暂停", "restarting": "重启中", "dead": "已死亡",
    "removing": "移除中",
}
HEALTH_CN = {
    "none": "无健康检查", "starting": "启动中",
    "healthy": "健康", "unhealthy": "不健康",
}


class DockerError(Exception):
    """Docker API 读取失败（带可直接展示给用户的中文原因）。"""


def human_size(n: Any) -> str:
    """字节数 → 人话。只用于展示，不参与判定。"""
    try:
        v = float(n or 0)
    except (TypeError, ValueError):
        return "—"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if v < 1024 or unit == "TB":
            return f"{int(v)} {unit}" if unit == "B" else f"{v:.1f} {unit}"
        v /= 1024
    return "—"


def _bad_tag(image: str) -> bool:
    """latest / 隐式 latest / <none> / 裸 sha256 引用都算「版本不可追溯」。

    带 registry 端口（registry:5000/app:v1）与 digest 钉死（app@sha256:…）
    不算坏标签：前者有明确 tag，后者是不可变引用，反而是好实践。
    """
    if not image or image.startswith("sha256:"):
        return True
    last = image.rsplit("/", 1)[-1]
    if "@" in last:                      # digest 钉死
        return False
    if ":" not in last:                  # 没写 tag = 隐式 latest
        return True
    return last.rsplit(":", 1)[-1] in ("latest", "<none>")


def assess_container(raw: Dict[str, Any],
                     inspect: Optional[Dict[str, Any]] = None
                     ) -> Tuple[List[str], Dict[str, Any]]:
    """对单个容器做安全标记判定。返回 (命中的标记 key 列表, 事实字典)。

    raw 来自 /containers/json；inspect 来自 /containers/{id}/json（可为 None，
    表示 inspect 失败——此时 privileged/user 记未知，绝不猜成 root 或特权）。
    """
    hc = raw.get("HostConfig") or {}
    ihc = (inspect or {}).get("HostConfig") or {}
    cfg = (inspect or {}).get("Config") or {}

    net = str(hc.get("NetworkMode") or ihc.get("NetworkMode") or "")
    priv = ihc.get("Privileged") if inspect is not None else None
    user = cfg.get("User") if inspect is not None else None
    health = str((raw.get("Health") or {}).get("Status") or "none")
    image = str(raw.get("Image") or "")

    mounts = [m for m in (raw.get("Mounts") or []) if isinstance(m, dict)]
    sock_mounts = [
        m for m in mounts
        if str(m.get("Source") or "").endswith("docker.sock")
        or str(m.get("Destination") or "") in ("/var/run/docker.sock",
                                               "/run/docker.sock")
    ]

    hits: List[str] = []
    if priv is True:
        hits.append("privileged")
    if sock_mounts:
        hits.append("docker_sock")
    if net == "host":
        hits.append("host_network")
    # 只有 inspect 成功才判 root；空串/缺省 = Docker 默认 root
    if inspect is not None and str(user or "").strip() in ("", "root", "0", "0:0"):
        hits.append("root_user")
    if health == "none":
        hits.append("no_healthcheck")
    if _bad_tag(image):
        hits.append("bad_tag")
    hits.sort(key=lambda k: _SEV_ORDER.get(FLAG_DEFS[k]["severity"], 9))

    facts = {
        "network_mode": net or "bridge",
        "privileged": priv,                       # True/False/None(未知)
        "user": (str(user).strip() or "root") if inspect is not None else "未知",
        "health": health,
        "sock_mounts": [
            {"source": str(m.get("Source") or ""),
             "destination": str(m.get("Destination") or "")}
            for m in sock_mounts
        ],
    }
    return hits, facts


def _ports(raw: Dict[str, Any]) -> List[str]:
    """Ports 数组 → 展示串，如 0.0.0.0:18094→80/tcp。

    同一个发布端口 Docker 会列 IPv4/IPv6 两条（0.0.0.0 与 ::），
    按 (PublicPort, PrivatePort, Type) 去重保留首条——展示不重复，
    完整原始映射仍在 API 的 Ports 字段里，不算丢数据。
    """
    out: List[str] = []
    seen = set()
    for p in raw.get("Ports") or []:
        if not isinstance(p, dict):
            continue
        priv = p.get("PrivatePort")
        pub = p.get("PublicPort")
        typ = p.get("Type") or "tcp"
        key = (pub, priv, typ)
        if key in seen:
            continue
        seen.add(key)
        if pub:
            s = f"{p.get('IP') or '0.0.0.0'}:{pub}→{priv}/{typ}"
        else:
            s = f"{priv}/{typ}"
        if s not in out:
            out.append(s)
    return out


def _ts_cn(ts: Any) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(ts)))
    except (TypeError, ValueError, OSError, OverflowError):
        return "—"


def build_inventory(raw_containers: List[Dict[str, Any]],
                    raw_images: List[Dict[str, Any]],
                    info: Dict[str, Any],
                    inspect_map: Dict[str, Any]) -> Dict[str, Any]:
    """纯函数：原始 API JSON → 展示 schema。不碰网络，方便造 fixture 测试。"""
    containers: List[Dict[str, Any]] = []
    for raw in raw_containers:
        if not isinstance(raw, dict):
            continue
        cid = str(raw.get("Id") or "")
        hits, facts = assess_container(raw, inspect_map.get(cid))
        state = str(raw.get("State") or "").lower()
        names = raw.get("Names") or []
        name = str(names[0]).lstrip("/") if names else cid[:12]
        containers.append({
            "id": cid[:12],
            "name": name,
            "image": str(raw.get("Image") or ""),
            "image_id": str(raw.get("ImageID") or ""),
            "state": state,
            "state_cn": STATE_CN.get(state, state or "未知"),
            "running": state == "running",
            "status": str(raw.get("Status") or ""),
            "created": raw.get("Created") or 0,
            "created_cn": _ts_cn(raw.get("Created")),
            "ports": _ports(raw),
            "network_mode": facts["network_mode"],
            "privileged": facts["privileged"],
            "user": facts["user"],
            "health": facts["health"],
            "health_cn": HEALTH_CN.get(facts["health"], facts["health"]),
            "sock_mounts": facts["sock_mounts"],
            "flags": [{"key": k, "label": FLAG_DEFS[k]["label"],
                       "severity": FLAG_DEFS[k]["severity"]} for k in hits],
            "flag_keys": hits,
        })
    # 运行中在前，其余按创建时间倒序——一眼先看到活着的
    containers.sort(key=lambda c: (not c["running"], -(c["created"] or 0)))

    images: List[Dict[str, Any]] = []
    for raw in raw_images:
        if not isinstance(raw, dict):
            continue
        iid = str(raw.get("Id") or "")
        tags = [t for t in (raw.get("RepoTags") or []) if isinstance(t, str)]
        real_tags = [t for t in tags if t != "<none>:<none>"]
        used_by = sorted({
            c["name"] for c in containers
            if (c["image_id"] and c["image_id"] == iid)
            or (c["image"] and c["image"] in tags)
        })
        images.append({
            "id": iid.replace("sha256:", "")[:12],
            "tags": real_tags,
            "size": raw.get("Size") or 0,
            "size_cn": human_size(raw.get("Size")),
            "created": raw.get("Created") or 0,
            "created_cn": _ts_cn(raw.get("Created")),
            "dangling": not real_tags,
            "used_by": used_by,
        })

    flag_counts = {k: 0 for k in FLAG_DEFS}
    for c in containers:
        for k in c["flag_keys"]:
            flag_counts[k] += 1
    running = sum(1 for c in containers if c["running"])
    totals = {
        "containers": len(containers),
        "running": running,
        "stopped": len(containers) - running,
        "images": len(images),
        "dangling_images": sum(1 for i in images if i["dangling"]),
        "flagged_containers": sum(1 for c in containers if c["flag_keys"]),
        "flags": flag_counts,
    }
    daemon = {
        "name": str(info.get("Name") or ""),
        "version": str(info.get("ServerVersion") or ""),
        "os": str(info.get("OperatingSystem") or ""),
        "os_type": str(info.get("OSType") or ""),
        "arch": str(info.get("Architecture") or ""),
        "ncpu": info.get("NCPU") or 0,
        "mem_total": info.get("MemTotal") or 0,
        "mem_cn": human_size(info.get("MemTotal")),
        "root_dir": str(info.get("DockerRootDir") or ""),
    }
    return {"containers": containers, "images": images,
            "totals": totals, "daemon": daemon, "flag_defs": FLAG_DEFS}


class _UnixConn(http.client.HTTPConnection):
    """HTTP over AF_UNIX：Docker Engine API 的本机通道。"""

    def __init__(self, sock_path: str, timeout: float):
        super().__init__("localhost", timeout=timeout)
        self._sock_path = sock_path

    def connect(self) -> None:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._sock_path)
        self.sock = s


def fetch_json(sock_path: str, path: str, timeout: float = 5.0) -> Any:
    """只发 GET。失败抛 DockerError（中文原因），由 collect 统一降级。"""
    conn = _UnixConn(sock_path, timeout)
    try:
        conn.request("GET", path,
                     headers={"Host": "docker", "Accept": "application/json"})
        resp = conn.getresponse()
        body = resp.read()
        if resp.status != 200:
            raise DockerError(f"Docker API 返回 HTTP {resp.status}（{path}）")
        return json.loads(body.decode("utf-8"))
    except DockerError:
        raise
    except PermissionError as exc:
        raise DockerError(
            "权限不足：当前用户读不了 docker.sock（需加入 docker 组或以 root 运行）"
        ) from exc
    except (ConnectionRefusedError, FileNotFoundError) as exc:
        raise DockerError("Docker 守护进程没起（socket 在但没人监听）") from exc
    except socket.timeout as exc:
        raise DockerError("Docker API 读取超时") from exc
    except (OSError, http.client.HTTPException, ValueError) as exc:
        raise DockerError(
            f"Docker API 读取失败：{type(exc).__name__}: {exc}") from exc
    finally:
        conn.close()


def _unavailable(reason: str) -> Dict[str, Any]:
    return {"available": False, "reason": reason}


def collect(sock_path: str = DEFAULT_SOCK, timeout: float = 5.0,
            fetch: Optional[Callable[[str], Any]] = None,
            inspect: bool = True) -> Dict[str, Any]:
    """枚举本机 Docker 容器/镜像并打安全标记。永不抛异常。

    fetch 可注入（测试用）：签名 path → 解析后的 JSON；默认走真实 unix socket。
    """
    t0 = time.time()
    try:
        if fetch is None:
            if not os.path.exists(sock_path):
                return _unavailable(
                    f"Docker socket 不存在：{sock_path}（未安装 Docker 或未启动）")
            def fetch(p: str) -> Any:                    # noqa: E306
                return fetch_json(sock_path, p, timeout)
        info = fetch("/info")
        raw_containers = fetch("/containers/json?all=1")
        raw_images = fetch("/images/json")
        if not isinstance(raw_containers, list) or not isinstance(raw_images, list):
            return _unavailable("Docker API 返回形状异常（容器/镜像不是列表）")
        if not isinstance(info, dict):
            info = {}
        inspect_map: Dict[str, Any] = {}
        if inspect:
            for c in raw_containers:
                cid = str((c or {}).get("Id") or "")
                if not cid:
                    continue
                try:
                    inspect_map[cid] = fetch(f"/containers/{cid}/json")
                except Exception:                        # noqa: BLE001
                    inspect_map[cid] = None              # 单容器降级，不拖垮整体
        out = build_inventory(raw_containers, raw_images, info, inspect_map)
        out.update({"available": True, "ts": time.time(), "sock": sock_path,
                    "elapsed_ms": round((time.time() - t0) * 1000, 1)})
        return out
    except DockerError as exc:
        return _unavailable(str(exc))
    except PermissionError:
        return _unavailable(
            "权限不足：当前用户读不了 docker.sock（需加入 docker 组或以 root 运行）")
    except (ConnectionRefusedError, FileNotFoundError):
        return _unavailable("Docker 守护进程没起（socket 在但没人监听）")
    except socket.timeout:
        return _unavailable("Docker API 读取超时")
    except Exception as exc:                             # noqa: BLE001
        return _unavailable(
            f"Docker 态势读取失败：{type(exc).__name__}: {exc}")
