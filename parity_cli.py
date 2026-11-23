#!/usr/bin/env python3
"""心之壁 Python 版检测引擎的**只读对拍适配器**。

这个文件不属于业务代码：它不 import 服务、不启线程、不写业务数据，
只做一件事——把一份 JSONL 事件流喂给 `atfield.detect` 的引擎，把告警按
`Finding.to_dict()` 逐行吐出来，供 Go 版对拍工具（cmd/parity）比对。

    python3 parity_cli.py --events fixtures/events.jsonl \
        --proctable fixtures/proctable.json --out out/py_findings.jsonl

对拍口径（与 cmd/parity 严格一致，任何一条都不能单边改）：
  1. **逐条喂**：一次 observe([ev]) 只喂一条事件。engine.observe() 在函数
     入口取一次 now，按条喂才能让「每条事件一个时刻」的语义在两侧对齐。
  2. **时钟 = 事件 ts**：engine.py 里所有 time.time() 都被替换成「当前事件
     的时间戳」，这样冷却/频率窗口/去重首末时间都只由事件流决定，
     不受机器快慢与真实墙钟影响（重放两次结果必须一样）。
  3. **不加载外部规则包**：只用 rules_builtin.load()（32 条），因为 Go 版
     目前只有内置规则；rules_ext 的 YAML 包不在对拍范围内。
  4. **状态隔离**：data_dir 指到临时目录，不读 ~/.atfield 的 dedup/suppress，
     进程表由 --proctable 显式提供（两侧同一份）。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import types
from typing import Any, Dict, List


def _load_atfield(py_dir: str):
    py_dir = os.path.abspath(py_dir)
    if py_dir not in sys.path:
        sys.path.insert(0, py_dir)
    from atfield import model as model_mod
    from atfield import store as store_mod
    from atfield.detect import engine as engine_mod
    from atfield.detect import rules_builtin
    return model_mod, store_mod, engine_mod, rules_builtin


class _Clock:
    """engine.py 里的 time 替身：只提供 time()，返回当前事件的 ts。"""

    def __init__(self) -> None:
        self.now = 0.0

    def time(self) -> float:  # noqa: A003 - 故意与 time.time 同名
        return self.now

    def monotonic(self) -> float:
        return self.now

    def sleep(self, _s: float) -> None:  # 重放不睡
        return None


def _event_fields(model_mod) -> set:
    import dataclasses

    return {f.name for f in dataclasses.fields(model_mod.Event)}


def main() -> int:
    ap = argparse.ArgumentParser(description="心之壁 Python 检测引擎只读对拍适配器")
    ap.add_argument("--events", required=True, help="事件流 JSONL")
    ap.add_argument("--out", required=True, help="告警输出 JSONL")
    ap.add_argument("--data-dir", required=True, help="去重/抑制状态目录（建议临时目录）")
    ap.add_argument("--py-dir", default=os.path.expanduser("~/aegis"), help="Python 版仓库根目录")
    ap.add_argument("--proctable", default="", help="进程表 JSON（{\"rows\":[{pid,ppid,exe}]}）")
    ap.add_argument("--ioc", default="", help="明文 IOC 名单 JSON（{\"ips\":[],\"domains\":[]}）")
    args = ap.parse_args()

    model_mod, store_mod, engine_mod, rules_builtin = _load_atfield(args.py_dir)

    os.makedirs(args.data_dir, exist_ok=True)
    cfg: Dict[str, Any] = {
        "data_dir": os.path.abspath(args.data_dir),
        "store": {"persist": False},
        "detect": {},
    }
    if args.ioc:
        with open(args.ioc, "r", encoding="utf-8") as fh:
            ioc = json.load(fh) or {}
        cfg["ioc"] = {"ips": list(ioc.get("ips") or []), "domains": list(ioc.get("domains") or [])}

    store = store_mod.Store(cfg)
    if args.proctable:
        with open(args.proctable, "r", encoding="utf-8") as fh:
            table = json.load(fh) or {}
        store.state["processes"] = table

    engine = engine_mod.Engine(cfg, store, rules_builtin.load())

    # 时钟注入：只替换 engine 模块内的 time 绑定，不动全局 time，
    # 也不动 rules_builtin（它不依赖 time）。
    clock = _Clock()
    engine_mod.time = clock  # type: ignore[assignment]

    fields = _event_fields(model_mod)
    emitted = 0
    total = 0
    with open(args.events, "r", encoding="utf-8") as src, \
            open(args.out, "w", encoding="utf-8") as dst:
        for lineno, line in enumerate(src, 1):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except Exception as exc:
                raise SystemExit(f"parity_cli: {args.events}:{lineno} 解析失败: {exc}")
            kwargs = {k: v for k, v in raw.items() if k in fields}
            if not kwargs.get("kind"):
                raise SystemExit(f"parity_cli: {args.events}:{lineno} 缺 kind 字段")
            ev = model_mod.Event(**kwargs)
            total += 1
            clock.now = float(raw.get("ts") or 0.0)
            for f in engine.observe([ev]):
                dst.write(json.dumps(f.to_dict(), ensure_ascii=False, default=str) + "\n")
                emitted += 1

    print(f"parity_cli: {total} events -> {emitted} findings", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
