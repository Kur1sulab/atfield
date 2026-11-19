"""声明式规则包：让「规则更新」真的能改检测行为，而不是发个空包。

内置规则是 Python 闭包（能做任意判断，但改一行就要发版）。
产品化之后客户要自己做微调、要能灰度推规则，所以补一层可热加载的声明式规则：

    ~/.atfield/rules/*.yaml
    rules:
      - id: EXT-TMP-EXEC
        name: 临时目录里面启动可执行文件
        severity: high
        kind: process.start
        where:
          path: {contains: ["/tmp/", "/var/tmp/", "/Users/Shared/"]}
          user: {ne: root}
        text: "{process} 从临时目录启动（{path}），父进程 {ppid}"
        advice: 确认是不是人为投放的载荷
        tags: [execution]
        mitre: [T1059]
        cooldown: 30
      - id: EXT-SSH-BRUTE
        kind: log.event
        where: {process: {eq: sshd}}
        freq: {window: 60, threshold: 8}
        severity: medium

设计取舍：
- 只做「字段匹配 + 频率窗口」，不做脚本执行——规则包来自外部，
  绝不能让它变成远程代码执行（这是更新通道能被信任的前提）。
- 字段路径既支持事件顶层属性（process/path/cmdline/user/pid/kind/source），
  也支持 subject.xxx（各采集器塞进去的结构化细节）。
- 解析失败不影响内置规则：坏包被隔离记错，引擎照跑内置规则。
"""
from __future__ import annotations

import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None

from . import yamlite
from .detect.engine import Rule

SEVERITIES = ("critical", "high", "medium", "low", "info")
PACK_DIRNAME = "rules"


def _load_yaml(text: str) -> Any:
    if yaml is not None:
        try:
            return yaml.safe_load(text)
        except Exception:
            pass
    return yamlite.load(text)


def _resolve(ev: Any, path: str) -> Any:
    """按路径取事件字段：顶层属性优先，其次 subject 里的结构化字段。"""
    name = (path or "").strip()
    if not name:
        return None
    if name.startswith("subject."):
        subj = getattr(ev, "subject", None) or {}
        return subj.get(name.split(".", 1)[1]) if isinstance(subj, dict) else None
    if hasattr(ev, name):
        val = getattr(ev, name)
        if val is not None:
            return val
    subj = getattr(ev, "subject", None) or {}
    if isinstance(subj, dict) and name in subj:
        return subj.get(name)
    return None


def _as_num(v: Any) -> Optional[float]:
    try:
        return float(v)
    except Exception:
        return None


def _match_one(actual: Any, spec: Any) -> bool:
    """单字段匹配。spec 是标量 → 相等；是列表 → 命中任一；是字典 → 运算符。"""
    if isinstance(spec, list):
        return any(_match_one(actual, s) for s in spec)
    if not isinstance(spec, dict):
        if actual is None:
            return False
        if isinstance(actual, bool) or isinstance(spec, bool):
            return bool(actual) == bool(spec)
        a, b = str(actual), str(spec)
        return a == b or a.lower() == b.lower()
    for op, val in spec.items():
        key = str(op).lower()
        if key == "eq":
            if not _match_one(actual, val):
                return False
        elif key == "ne":
            if _match_one(actual, val):
                return False
        elif key == "in":
            pool = val if isinstance(val, list) else [val]
            if not any(_match_one(actual, p) for p in pool):
                return False
        elif key == "contains":
            pool = val if isinstance(val, list) else [val]
            text = str(actual or "").lower()
            if not any(str(p).lower() in text for p in pool):
                return False
        elif key == "startswith":
            pool = val if isinstance(val, list) else [val]
            text = str(actual or "")
            if not any(text.startswith(str(p)) for p in pool):
                return False
        elif key == "endswith":
            pool = val if isinstance(val, list) else [val]
            text = str(actual or "")
            if not any(text.endswith(str(p)) for p in pool):
                return False
        elif key == "re":
            try:
                if not re.search(str(val), str(actual or "")):
                    return False
            except re.error:
                return False
        elif key in ("gte", "gt", "lte", "lt"):
            a, b = _as_num(actual), _as_num(val)
            if a is None or b is None:
                return False
            if key == "gte" and not a >= b:
                return False
            if key == "gt" and not a > b:
                return False
            if key == "lte" and not a <= b:
                return False
            if key == "lt" and not a < b:
                return False
        elif key == "exists":
            want = bool(val)
            have = actual is not None and actual != ""
            if have != want:
                return False
        else:
            return False
    return True


def _match_all(ev: Any, where: Dict[str, Any]) -> bool:
    for path, spec in (where or {}).items():
        if not _match_one(_resolve(ev, path), spec):
            return False
    return True


def _render(template: str, ev: Any) -> str:
    """安全的 {字段} 渲染：拿不到就留 ——，绝不让规则包拿到宿主对象。"""
    if not template:
        return ""

    def repl(match: "re.Match[str]") -> str:
        name = match.group(1)
        val = _resolve(ev, name)
        if val is None:
            return "—"
        text = str(val)
        return text[:300]

    try:
        return re.sub(r"\{([a-zA-Z0-9_.]+)\}", repl, template)
    except Exception:
        return template


def _kind_list(spec: Any) -> Tuple[str, ...]:
    if isinstance(spec, list):
        return tuple(str(s) for s in spec if str(s))
    if isinstance(spec, str) and spec:
        return (spec,)
    return ()


def _build_rule(rd: Dict[str, Any], pack: str) -> Optional[Rule]:
    rid = str(rd.get("id") or "").strip()
    if not rid:
        return None
    where = rd.get("where") if isinstance(rd.get("where"), dict) else {}
    kinds = _kind_list(rd.get("kind"))
    freq = rd.get("freq") if isinstance(rd.get("freq"), dict) else {}
    window = float(freq.get("window") or 0)
    threshold = int(freq.get("threshold") or 0)
    severity = str(rd.get("severity") or "medium").lower()
    if severity not in SEVERITIES:
        severity = "medium"
    text_tpl = str(rd.get("text") or f"{rid} 命中")
    advice = str(rd.get("advice") or "")
    tags = tuple(str(t) for t in (rd.get("tags") or []))
    mitre = tuple(str(t) for t in (rd.get("mitre") or []))
    cooldown = float(rd.get("cooldown") or 30)
    enabled = bool(rd.get("enabled", True))
    desc = str(rd.get("description") or f"外部规则包 {pack}")

    def when(ev: Any, ctx: Any) -> bool:
        if kinds and getattr(ev, "kind", "") not in kinds:
            return False
        if where and not _match_all(ev, where):
            return False
        if window > 0 and threshold > 0:
            key = f"ext:{rid}"
            fkey = str(rd.get("freq_key") or "")
            if fkey:
                key += ":" + str(_resolve(ev, fkey))
            return ctx.reached(key, window, threshold)
        return True

    def detail(ev: Any, ctx: Any) -> str:
        return _render(text_tpl, ev)

    def actor(ev: Any, ctx: Any) -> str:
        return str(getattr(ev, "process", "") or getattr(ev, "path", "") or "")

    return Rule(id=rid, name=str(rd.get("name") or rid), severity=severity,
                when=when, detail=detail, advice=advice, tags=tags, mitre=mitre,
                cooldown=cooldown, actor=actor, enabled=enabled, description=desc)


def pack_files(cfg: Dict[str, Any]) -> List[str]:
    root = os.path.join(cfg.get("data_dir") or os.path.expanduser("~/.atfield"), PACK_DIRNAME)
    if not os.path.isdir(root):
        return []
    out = []
    for name in sorted(os.listdir(root)):
        if name.endswith((".yaml", ".yml")) and not name.startswith("."):
            out.append(os.path.join(root, name))
    return out


def load_packs(cfg: Dict[str, Any]) -> Tuple[List[Rule], List[Dict[str, Any]]]:
    """返回（规则列表, 包台账）。坏包不抛异常，只记进台账。"""
    rules: List[Rule] = []
    index: List[Dict[str, Any]] = []
    seen: Dict[str, str] = {}
    for path in pack_files(cfg):
        name = os.path.basename(path)
        entry: Dict[str, Any] = {"file": name, "pack": "", "version": "", "rules": 0,
                                 "skipped": 0, "error": ""}
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                data = _load_yaml(fh.read()) or {}
        except Exception as exc:
            entry["error"] = f"读取失败: {exc}"
            index.append(entry)
            continue
        if isinstance(data, list):
            data = {"rules": data}
        if not isinstance(data, dict):
            entry["error"] = "顶层不是映射"
            index.append(entry)
            continue
        pack = str(data.get("pack") or os.path.splitext(name)[0])
        entry["pack"] = pack
        entry["version"] = str(data.get("version") or "")
        entries = data.get("rules")
        if not isinstance(entries, list):
            entry["error"] = "缺少 rules 列表"
            index.append(entry)
            continue
        for rd in entries:
            if not isinstance(rd, dict):
                entry["skipped"] += 1
                continue
            rid = str(rd.get("id") or "").strip()
            if rid and rid in seen:
                # 同名规则先到先得，后来者跳过——避免推送包静默覆盖内置规则
                entry["skipped"] += 1
                continue
            rule = _build_rule(rd, pack)
            if rule is None:
                entry["skipped"] += 1
                continue
            seen[rule.id] = name
            rules.append(rule)
            entry["rules"] += 1
        index.append(entry)
    return rules, index


def bundled_ids(cfg: Dict[str, Any]) -> List[str]:
    """只取 id，给更新通道的健康探针用（不做完整构建）。"""
    ids: List[str] = []
    for path in pack_files(cfg):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                data = _load_yaml(fh.read()) or {}
        except Exception:
            continue
        entries = data.get("rules") if isinstance(data, dict) else data
        if isinstance(entries, list):
            for rd in entries:
                if isinstance(rd, dict) and rd.get("id"):
                    ids.append(str(rd["id"]))
    return ids
