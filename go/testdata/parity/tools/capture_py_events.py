#!/usr/bin/env python3
"""跑一轮 Python 心之壁采集（与 `atfieldd.py --once` 完全相同的链路），
把该轮**采集器产出**的事件与**融合层衍生**事件分别落成 jsonl，供对拍使用。

不改 Python 仓库任何文件；只 import 它。

用法:
  python3 capture_py_events.py --out-dir DIR --py-dir ~/aegis
产物:
  DIR/py_collector_events.jsonl   采集器原始事件（对拍主输入）
  DIR/py_derived_events.jsonl     融合层衍生事件（ueba/ndr/canary…，Go 版尚无此层）
  DIR/py_findings.jsonl           该轮 Python 引擎告警（自检用，不参与对拍）
  DIR/py_proctable.json           该轮 process 采集器发布的进程表（{rows:[{pid,ppid,exe}]}）
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from typing import Any, Dict, List

EVENT_FIELDS = ("eid", "kind", "source", "ts", "host", "user", "pid", "ppid",
                "process", "cmdline", "path", "severity", "subject", "raw")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--py-dir", default=os.path.expanduser("~/aegis"))
    ap.add_argument("--rounds", type=int, default=1, help="连跑几轮（常驻进程语义，与 --once 相同链路）")
    args = ap.parse_args()

    sys.path.insert(0, os.path.abspath(args.py_dir))
    from atfield import config as config_mod
    from atfield.core import Core

    out_dir = os.path.abspath(args.out_dir)
    os.makedirs(out_dir, exist_ok=True)
    data_dir = tempfile.mkdtemp(prefix="atfield-capture-")

    cfg: Dict[str, Any] = config_mod.load(None)
    cfg["data_dir"] = data_dir
    cfg.setdefault("store", {})["persist"] = False
    cfg.setdefault("ai", {})["enabled"] = False
    cfg.setdefault("firewall", {})["enabled"] = False

    core = Core(cfg)
    t0 = time.time()

    # 与 cmd_once 一致：流式采集器先 start，给几秒建立连接
    for c in core.collectors:
        if getattr(c, "enabled", False) and getattr(c, "mode", "poll") == "stream":
            try:
                c.start()
            except Exception:
                pass
    time.sleep(4)

    collector_events: List[Any] = []
    derived: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    per_collector: List[Dict[str, Any]] = []
    seen_eids: set = set()

    for rnd in range(1, args.rounds + 1):
        for c in core.collectors:
            if not getattr(c, "enabled", False):
                continue
            try:
                evs = c.run_once()
            except Exception as exc:                      # 采集器异常不掩盖
                per_collector.append({"round": rnd, "collector": c.name, "events": 0,
                                      "error": repr(exc)[:200]})
                continue
            collector_events.extend(evs)
            seen_eids.update(e.eid for e in evs)
            if evs:
                res = core.process(evs)                    # 与常驻模式同一链路
                findings.extend(res.get("findings") or [])
                # core.process 内部产生的衍生事件：store 里出现但不在采集器产出里的 eid
                for d in list(core.store.events):
                    eid = d.get("eid")
                    if eid and eid not in seen_eids:
                        seen_eids.add(eid)
                        derived.append({k: d.get(k) for k in EVENT_FIELDS if k in d})
            err = (core.store.meta["collectors"].get(c.name) or {})
            per_collector.append({"round": rnd, "collector": c.name, "events": len(evs),
                                  "errors": err.get("errors", 0),
                                  "last_error": (err.get("last_error") or "")[:200]})
            print(f"  - r{rnd} {c.name:<12} events={len(evs):>4}", flush=True)

    elapsed = time.time() - t0

    def dump(objs, path, full=True):
        with open(path, "w", encoding="utf-8") as fh:
            for o in objs:
                src = o.to_dict() if full else o
                d = {k: src[k] for k in EVENT_FIELDS if k in src}
                fh.write(json.dumps(d, ensure_ascii=False, sort_keys=True) + "\n")

    dump(collector_events, os.path.join(out_dir, "py_collector_events.jsonl"))
    dump(derived, os.path.join(out_dir, "py_derived_events.jsonl"), full=False)
    with open(os.path.join(out_dir, "py_findings.jsonl"), "w", encoding="utf-8") as fh:
        for f in findings:
            fh.write(json.dumps(f, ensure_ascii=False, sort_keys=True) + "\n")

    procs = core.store.state.get("processes") or {}
    rows = procs.get("rows") or []
    table = {"rows": [{"pid": r.get("pid"), "ppid": r.get("ppid"), "exe": r.get("exe") or ""}
                      for r in rows if isinstance(r, dict)]}
    with open(os.path.join(out_dir, "py_proctable.json"), "w", encoding="utf-8") as fh:
        json.dump(table, fh, ensure_ascii=False, indent=1)

    summary = {
        "python_version": getattr(__import__("atfield"), "__version__", ""),
        "elapsed_s": round(elapsed, 3),
        "collector_events": len(collector_events),
        "derived_events": len(derived),
        "findings": len(findings),
        "proctable_rows": len(table["rows"]),
        "collectors": per_collector,
    }
    with open(os.path.join(out_dir, "py_capture_summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, ensure_ascii=False, indent=2)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"data_dir={data_dir}（临时，不落盘）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
