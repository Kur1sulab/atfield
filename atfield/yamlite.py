"""极简 YAML 子集解析器（零依赖兜底）。

为什么要有它：心之壁的剧本只是「列表 + 映射 + 内联列表 + 标量」这四类结构。
真实环境里不一定装了 PyYAML（同一个 python 解释器换一个 venv 就可能没有），
产品不应该因为一个可选依赖就整个剧本引擎失效——装了就优先用 PyYAML，
没装就用这个解析器，行为一致。

支持：
  - 注释（# 到行尾，引号内不算）
  - 顶层列表 "- key: value" 与嵌套映射（按缩进）
  - 内联列表 [a, b, c]
  - 标量：字符串 / 整数 / 浮点 / true·false / null
不支持（也不需要）：锚点、多文档、块标量 | >、复杂嵌套流式写法。
"""
from __future__ import annotations

from typing import Any, List, Tuple


def _strip_comment(line: str) -> str:
    out = []
    quote = ""
    prev = ""
    for ch in line:
        if quote:
            out.append(ch)
            if ch == quote:
                quote = ""
            prev = ch
            continue
        if ch in ("'", '"'):
            quote = ch
            out.append(ch)
            prev = ch
            continue
        if ch == "#" and (prev == "" or prev in " \t"):
            break
        out.append(ch)
        prev = ch
    return "".join(out)


def _prepare(text: str) -> List[Tuple[int, str]]:
    rows: List[Tuple[int, str]] = []
    for raw in (text or "").splitlines():
        if not raw.strip():
            continue
        if raw.lstrip().startswith("#"):
            continue
        line = _strip_comment(raw).rstrip()
        if not line.strip():
            continue
        rows.append((len(line) - len(line.lstrip(" ")), line.strip()))
    return rows


def _scalar(s: str) -> Any:
    s = (s or "").strip()
    if not s:
        return ""
    if s.startswith("[") and s.endswith("]"):
        body = s[1:-1].strip()
        if not body:
            return []
        return [_scalar(x) for x in body.split(",")]
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        return s[1:-1]
    low = s.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("null", "~", "none"):
        return None
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return float(s)
    except ValueError:
        pass
    return s


def _parse_block(rows: List[Tuple[int, str]], i: int, indent: int) -> Tuple[Any, int]:
    if i >= len(rows):
        return {}, i
    if rows[i][1].startswith("-"):
        return _parse_list(rows, i, indent)
    return _parse_map(rows, i, indent)


def _parse_list(rows: List[Tuple[int, str]], i: int, indent: int) -> Tuple[list, int]:
    items: list = []
    while i < len(rows) and rows[i][0] == indent and rows[i][1].startswith("-"):
        content = rows[i][1][1:].strip()
        i += 1
        if not content:
            if i < len(rows) and rows[i][0] > indent:
                val, i = _parse_block(rows, i, rows[i][0])
                items.append(val)
            else:
                items.append(None)
            continue
        # "- key: value" → 该元素是映射，后续更深缩进行并入同一映射
        head = _strip_comment(content)
        is_map = ":" in head and not head.startswith(("[", "{", '"', "'"))
        if is_map:
            key, rest = head.split(":", 1)
            item: dict = {}
            rest = rest.strip()
            if rest:
                item[key.strip()] = _scalar(rest)
            elif i < len(rows) and rows[i][0] > indent:
                val, i = _parse_block(rows, i, rows[i][0])
                item[key.strip()] = val
            else:
                item[key.strip()] = None
            while i < len(rows) and rows[i][0] > indent:
                sub, i = _parse_block(rows, i, rows[i][0])
                if isinstance(sub, dict):
                    item.update(sub)
            items.append(item)
        else:
            items.append(_scalar(content))
    return items, i


def _parse_map(rows: List[Tuple[int, str]], i: int, indent: int) -> Tuple[dict, int]:
    out: dict = {}
    while i < len(rows) and rows[i][0] == indent and not rows[i][1].startswith("-"):
        line = rows[i][1]
        if ":" not in line:
            i += 1
            continue
        key, rest = line.split(":", 1)
        key, rest = key.strip(), rest.strip()
        i += 1
        if rest:
            out[key] = _scalar(rest)
        else:
            if i < len(rows) and rows[i][0] > indent:
                val, i = _parse_block(rows, i, rows[i][0])
                out[key] = val
            else:
                out[key] = None
    return out, i


def load(text: str) -> Any:
    rows = _prepare(text)
    if not rows:
        return None
    val, _ = _parse_block(rows, 0, rows[0][0])
    return val
