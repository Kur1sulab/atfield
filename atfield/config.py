"""配置：默认值 + ~/.atfield/config.yaml 覆盖。"""
from __future__ import annotations

import copy
import os
import shutil
from typing import Any, Dict

try:
    import yaml  # noqa: F401
    _YAML_ERR = ""
except Exception as _e:      # noqa: BLE001 —— 导入失败原因要留证，否则只会看到「配置文件没生效」
    yaml = None
    _YAML_ERR = f"{type(_e).__name__}: {_e}"

# PyYAML 是可选依赖：装不上也得能读配置。内置 yamlite 只负责「读」，
# 写配置仍然要求真 PyYAML（不拿手搓序列化器去赌用户的配置文件）。
try:
    from . import yamlite as _yamlite
except Exception:            # noqa: BLE001
    _yamlite = None

HOME = os.path.expanduser("~")
DATA_DIR = os.path.join(HOME, ".atfield")

# 数据目录迁移：改名前的版本用 ~/.aegis。新目录不存在而老目录有货时整份复制过来
# （复制而非移动 —— 老目录原样保留，出问题可直接回滚）；复制失败就继续用老目录，不中断启动。
_LEGACY_DATA_DIRS = [os.path.join(HOME, ".aegis")]


def migrate_legacy_data_dir() -> str:
    """把老名字下的数据目录迁到 ~/.atfield，返回实际可用目录。"""
    if os.path.isdir(DATA_DIR):
        return DATA_DIR
    for legacy in _LEGACY_DATA_DIRS:
        if os.path.isdir(legacy) and os.listdir(legacy):
            try:
                shutil.copytree(legacy, DATA_DIR, symlinks=True)
            except OSError:
                return legacy
            return DATA_DIR
    return DATA_DIR


migrate_legacy_data_dir()

DEFAULTS: Dict[str, Any] = {
    "host_label": "",              # 留空则用 gethostname()
    "data_dir": DATA_DIR,
    "server": {
        "bind": "127.0.0.1",
        "port": 8866,
        "open_browser": False,
    },
    # ---- AI 研判层（默认关闭：产品必须在没有模型的世界里完整可用）----
    "ai": {
        "enabled": False,
        # preset 只是配置模板的快捷方式；改 preset 会覆盖下面的 provider/base_url/model
        "preset": "",
        "provider": "openai",          # openai（兼容）| anthropic
        "base_url": "",
        "model": "",
        "api_key": "",                 # 不推荐写这里；优先环境变量或 secrets 文件
        "api_key_env": "ATFIELD_AI_KEY",
        "timeout": 30.0,
        "max_tokens": 900,
        "temperature": 0.2,
        # 出网脱敏。默认 True 且不建议关：端点是回环网关时它背后仍是云端模型
        "redact": True,
        # 只把达到这个级别的命中送审，避免低危噪声烧额度
        "min_severity": "high",
        "budget_per_hour": 60,
        "budget_per_day": 400,
        "auto_judge": False,           # 命中即自动送审（默认关，由分析员手动触发）
        # 声明「回环端点=本地推理」。默认 False：127.0.0.1 上的网关很可能
        # 在转发云端请求，宁可当成会出网（gateway）也不要误标成安全。
        "local_inference": False,
    },
    # ---- 主机防火墙执行层（默认关闭：拦截是最危险的动作，必须显式开）----
    "firewall": {
        "enabled": False,               # 总开关。关了就是纯观测，什么都不动
        "dry_run": True,                # 只做语法校验、不加载规则（默认更保守）
        "socket": "/var/run/atfield-pf.sock",
        "allow_attach": False,          # 是否允许把 anchor 挂进 /etc/pf.conf
        "timeout": 6.0,
    },
    "collectors": {
        "process": {"enabled": True, "interval": 3.0},
        "network": {"enabled": True, "interval": 5.0},
        "session": {"enabled": True, "interval": 20.0},
        "persistence": {"enabled": True, "interval": 30.0},
        "logstream": {"enabled": True, "interval": 0},
        "baseline": {"enabled": True, "interval": 120.0},
        "integrity": {"enabled": True, "interval": 45.0},
        "privileged": {"enabled": True, "interval": 0},
    },
    "logstream": {
        # 只订阅有安全语义的子系统/进程，避免被系统噪声淹没
        "predicate": (
            'process == "sudo" OR process == "sshd" OR process == "authd" '
            'OR process == "securityd" OR process == "tccd" '
            'OR subsystem == "com.apple.TCC" OR process == "XProtect" '
            'OR process == "XProtectRemediator" OR process == "coreduetd"'
        ),
        "max_per_second": 40,
    },
    "store": {
        "max_events": 20000,
        "max_findings": 4000,
        "max_incidents": 400,
        "persist": True,           # 落盘 jsonl
        "persist_max_mb": 64,
    },
    "detect": {
        "enabled": True,
        "correlate_window": 1200,  # 攻击链关联窗口（秒）
        "min_chain_stages": 2,
    },
    "response": {
        "allow_kill": True,        # 仅能杀同用户进程（无 root 时）
        "allow_isolate": False,    # 隔离需 root（pf），默认只生成命令不执行
        "require_confirm": True,
    },
    "watch_paths": [
        "/etc/hosts",
        "/etc/ssh/sshd_config",
        "/etc/pf.conf",
        "/etc/sudoers",
        os.path.join(HOME, ".ssh/authorized_keys"),
        os.path.join(HOME, ".ssh/config"),
        os.path.join(HOME, ".zshrc"),
        os.path.join(HOME, ".bash_profile"),
        os.path.join(HOME, "Library/Preferences/com.apple.SoftwareUpdate.plist"),
    ],
    "suspicious_dir_prefixes": [
        "/tmp/", "/private/tmp/", "/var/tmp/", "/Users/Shared/",
        "/private/var/folders/", "/dev/shm/",
    ],
    "system_process_names": [
        "sshd", "launchd", "kernel_task", "syslogd", "cron", "mdworker",
        "WindowServer", "loginwindow", "securityd", "tccd", "notifyd",
        "cfprefsd", "mds", "mds_stores", "coreaudiod", "powerd", "diskarbitrationd",
    ],
    "ioc": {
        "domains": [],
        "ips": [],
    },
}


def _deep_merge(base: Dict[str, Any], over: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load(path: str | None = None) -> Dict[str, Any]:
    """读取配置；任何异常都退回默认值（安全优先，不因配置错而停服）。"""
    cfg = copy.deepcopy(DEFAULTS)
    path = path or os.path.join(DATA_DIR, "config.yaml")
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                _text = fh.read()
            if yaml is not None:
                data = yaml.safe_load(_text) or {}
            elif _yamlite is not None:
                data = _yamlite.load(_text) or {}
                cfg["_yaml_backend"] = "yamlite"
            else:
                data = {}
                cfg["_load_error"] = "PyYAML 与内置 yamlite 均不可用，配置未被读取"
            if isinstance(data, dict):
                cfg = _deep_merge(cfg, data)
        except Exception as exc:
            # 读失败必须留痕：静默退回默认值会让用户以为配置生效了，
            # 而实际上 AI 之类的功能被悄悄关掉了（这类「静默失效」最难查）
            cfg["_load_error"] = f"{type(exc).__name__}: {exc}"
    os.makedirs(cfg["data_dir"], exist_ok=True)
    # 记住「这次到底读的是哪个文件」：自定义 --config 时，后续写回必须落在同一个
    # 文件上，否则多实例/演示环境改配置会写到默认路径去（真出过这个事故）。
    cfg["_config_path"] = path
    return cfg


def read_raw(path: str | None = None) -> Dict[str, Any]:
    """只读文件里真实写了的东西（不掺默认值）。写回时用它做底，避免把
    一整套默认值倒进用户的配置文件。"""
    path = path or os.path.join(DATA_DIR, "config.yaml")
    if not (yaml and os.path.isfile(path)):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def patch_section(section: str, values: Dict[str, Any],
                  path: str | None = None) -> Dict[str, Any]:
    """把 values 合并进配置文件的某个 section，其余段落原样保留。

    原子写（tmp + replace），失败不破坏原文件。没有 PyYAML 就拒绝写——
    宁可让调用方看到「改不了」，也不要拿手搓的序列化器去赌用户的配置。
    """
    path = path or os.path.join(DATA_DIR, "config.yaml")
    if not yaml:
        return {"ok": False, "error": "写配置需要 PyYAML"}
    raw = read_raw(path)
    sec = raw.get(section)
    if not isinstance(sec, dict):
        sec = {}
    for k, v in (values or {}).items():
        sec[k] = v
    raw[section] = sec
    tmp = path + ".tmp"
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as fh:
            yaml.safe_dump(raw, fh, allow_unicode=True, sort_keys=False,
                           default_flow_style=False)
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)     # 配置里可能有凭据，收权限
        except Exception:
            pass
        return {"ok": True, "path": path, "section": section,
                "keys": sorted((values or {}).keys())}
    except Exception as exc:
        try:
            os.unlink(tmp)
        except Exception:
            pass
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
