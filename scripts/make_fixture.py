#!/usr/bin/env python3
"""生成对拍用的**真实事件流**样本（脱敏后落盘）。

来源两路，都是本机真实数据，不合成事件：

  1. 现场采集：用 Python 版 atfield 的采集器跑一轮（collectors.build +
     run_once），拿到「此刻这台机器」的事件；
  2. 历史流：从 ~/.atfield/events.jsonl（Python 版服务真实落盘的 20 万条）
     里按 kind 分层抽样，补上现场采集撞不到的行为（canary 触发、隐藏进程、
     持久化变更、认证失败、UEBA/NDR 衍生事件……）。

脱敏只改「值」，不动「结构」：主机名/用户名/家目录/公网 IP 换成占位，
令牌型键值（token=…、password=…）打码。字段名、kind、severity、subject
的键集合、数组顺序全部保留——否则对拍就变成了对拍两个假东西。

    python3 scripts/make_fixture.py --out testdata/parity

产物：
    events.jsonl    事件流（每行一个 Event）
    proctable.json  进程表（pid/ppid/exe），两侧共用
    meta.json       来源、脱敏规则、条数、规则覆盖统计
"""
from __future__ import annotations

import argparse
import collections
import getpass
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, Iterable, List, Tuple

DEFAULT_PY_DIR = os.path.expanduser("~/aegis")
DEFAULT_HISTORY = os.path.expanduser("~/.atfield/events.jsonl")

# 每类事件最多抽多少条（稀有行为优先，保证规则覆盖而不是堆量）
PER_KIND_CAP = {
    "process.start": 700,
    "process.exit": 120,
    "net.connect": 500,
    "net.listen": 60,
    "auth.fail": 120,
    "tcc.deny": 60,
    "persistence.add": 80,
    "defense.event": 60,
    "av.detect": 60,
    "process.hidden": 60,
    "ndr.beaconing": 40,
    "ndr.direct_ip": 60,
    "ndr.risky_port": 20,
    "ueba.new_process": 60,
    "ueba.new_destination": 60,
    "ueba.rare_activity": 20,
    "ueba.new_persistence": 20,
    "canary.trip": 20,
    "integrity.change": 10,
    "baseline.drift": 10,
}
DEFAULT_CAP = 40
MAX_EVENTS = 3000

# 令牌型键值打码（只动 value，不动键名）
TOKEN_RE = re.compile(
    r"(?i)\b(token|password|passwd|secret|api[_-]?key|authorization|bearer)"
    r"(\s*[=:]\s*)(\S+)"
)
# 公网 IPv4 → TEST-NET-3（203.0.113.0/24），保留「是不是公网」这个语义
PUBLIC_IP_RE = re.compile(r"\b(?!10\.)(?!127\.)(?!192\.168\.)(?!172\.(?:1[6-9]|2\d|3[01])\.)"
                          r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


class Redactor:
    def __init__(self, host: str, user: str, home: str) -> None:
        self.host = host or ""
        self.user = user or ""
        self.home = home.rstrip("/")
        self._ip_map: Dict[str, str] = {}
        self._next_ip = 1

    def _map_ip(self, ip: str) -> str:
        if ip not in self._ip_map:
            self._ip_map[ip] = f"203.0.113.{self._next_ip}"
            self._next_ip += 1
            if self._next_ip > 254:
                self._next_ip = 1
        return self._ip_map[ip]

    def text(self, s: str) -> str:
        if not isinstance(s, str) or not s:
            return s
        out = s
        if self.home:
            out = out.replace(self.home, "/Users/USER-A")
            out = out.replace(self.home.lstrip("/"), "Users/USER-A")
        if self.user and len(self.user) >= 3:
            out = re.sub(rf"(?<![\w-]){re.escape(self.user)}(?![\w-])", "USER-A", out)
        if self.host and len(self.host) >= 3:
            out = out.replace(self.host, "HOST-A")
        out = TOKEN_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}<REDACTED>", out)
        out = PUBLIC_IP_RE.sub(lambda m: self._map_ip(m.group(1)), out)
        return out

    def value(self, v: Any) -> Any:
        if isinstance(v, str):
            return self.text(v)
        if isinstance(v, list):
            return [self.value(x) for x in v]
        if isinstance(v, dict):
            return {k: self.value(x) for k, x in v.items()}
        return v

    def event(self, ev: Dict[str, Any]) -> Dict[str, Any]:
        out = {k: self.value(v) for k, v in ev.items()}
        if out.get("host"):
            out["host"] = "HOST-A"
        if out.get("user"):
            out["user"] = "USER-A"
        return out


def live_capture(py_dir: str) -> List[Dict[str, Any]]:
    """用 Python 版采集器跑一轮（等价于 atfieldd --once 的采集阶段）。"""
    if py_dir not in sys.path:
        sys.path.insert(0, py_dir)
    from atfield import collectors as collectors_mod
    from atfield import config as config_mod
    from atfield import store as store_mod

    cfg = config_mod.load()
    tmp = tempfile.mkdtemp(prefix="aegis-fixture-")
    cfg["data_dir"] = tmp
    cfg["store"] = {"persist": False}
    cfg["host_label"] = socket.gethostname()
    store = store_mod.Store(cfg)

    out: List[Dict[str, Any]] = []
    built = collectors_mod.build(cfg, store)
    for c in built:
        if not getattr(c, "enabled", False):
            continue
        try:
            evs = c.run_once() or []
        except Exception as exc:  # 采集失败不影响整轮
            print(f"  ! {getattr(c, 'name', '?')}: {type(exc).__name__}: {exc}", file=sys.stderr)
            continue
        print(f"  · {getattr(c, 'name', '?')}: {len(evs)} 条", file=sys.stderr)
        for ev in evs:
            try:
                out.append(ev.to_dict())
            except Exception:
                pass
    return out


def load_history(path: str, caps: Dict[str, int]) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """按 kind 分层抽样。单遍扫描，每类保留前 N 条（时间上均匀取：见 stride）。"""
    if not os.path.isfile(path):
        return [], {}
    total: Dict[str, int] = collections.Counter()
    picked: Dict[str, List[Dict[str, Any]]] = collections.defaultdict(list)
    stride: Dict[str, int] = {}

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except Exception:
                continue
            kind = str(ev.get("kind") or "")
            if not kind:
                continue
            total[kind] += 1
            cap = caps.get(kind, DEFAULT_CAP)
            bucket = picked[kind]
            # 前 20% 全收（时间上最近的先保留），其余按 stride 抽样，
            # 避免只拿到「同一分钟的重复行为」。
            n = total[kind]
            if len(bucket) < cap:
                bucket.append(ev)
            else:
                stride[kind] = max(1, n // cap)
                if n % stride[kind] == 0:
                    bucket[n % cap] = ev

    out: List[Dict[str, Any]] = []
    for kind, rows in picked.items():
        rows.sort(key=lambda e: float(e.get("ts") or 0))
        out.extend(rows)
    return out, dict(total)


def proc_table(py_dir: str, events: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """进程表：ps 快照 ∪ 事件流里出现的 pid→ppid 关系。"""
    rows: Dict[int, Tuple[int, str]] = {}
    try:
        text = subprocess.run(["ps", "-axo", "pid=,ppid=,comm="],
                              capture_output=True, text=True, timeout=20).stdout
        for line in text.splitlines():
            parts = line.split(None, 2)
            if len(parts) < 3:
                continue
            try:
                pid, ppid = int(parts[0]), int(parts[1])
            except ValueError:
                continue
            rows[pid] = (ppid, parts[2].strip())
    except Exception as exc:
        print(f"  ! ps 快照失败: {exc}", file=sys.stderr)

    for ev in events:
        pid = ev.get("pid")
        ppid = ev.get("ppid")
        if isinstance(pid, int) and isinstance(ppid, int) and ppid:
            rows.setdefault(pid, (ppid, str(ev.get("path") or ev.get("process") or "")))

    # 只保留事件流里出现过的 pid 及其祖先链，控制体积
    wanted = set()
    for ev in events:
        pid = ev.get("pid")
        if isinstance(pid, int):
            wanted.add(pid)
    keep = set()
    for pid in wanted:
        cur = pid
        for _ in range(16):
            if cur in keep:
                break
            keep.add(cur)
            nxt = rows.get(cur, (0, ""))[0]
            if nxt in (0, 1) or nxt not in rows:
                break
            cur = nxt

    out = []
    for pid in sorted(keep):
        ppid, exe = rows.get(pid, (0, ""))
        out.append({"pid": pid, "ppid": ppid, "exe": exe})
    return {"rows": out}


def main() -> int:
    ap = argparse.ArgumentParser(description="生成真实事件流对拍样本")
    ap.add_argument("--out", default="testdata/parity", help="输出目录")
    ap.add_argument("--py-dir", default=DEFAULT_PY_DIR, help="Python 版仓库根目录")
    ap.add_argument("--history", default=DEFAULT_HISTORY, help="历史事件流 JSONL")
    ap.add_argument("--max-events", type=int, default=MAX_EVENTS)
    ap.add_argument("--no-live", action="store_true", help="跳过现场采集（只用历史流）")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    red = Redactor(host=socket.gethostname(), user=getpass.getuser(),
                   home=os.path.expanduser("~"))

    live: List[Dict[str, Any]] = []
    if not args.no_live:
        print("现场采集（Python 版采集器跑一轮）…", file=sys.stderr)
        live = live_capture(args.py_dir)

    print("历史流分层抽样…", file=sys.stderr)
    hist, totals = load_history(args.history, PER_KIND_CAP)

    merged = live + hist
    merged.sort(key=lambda e: float(e.get("ts") or 0))
    if len(merged) > args.max_events:
        # 保留最近的事件（时间上连续的尾部），并保证稀有 kind 不被裁掉
        rare = {"canary.trip", "integrity.change", "process.hidden", "ndr.beaconing",
                "ueba.rare_activity", "ueba.new_persistence", "baseline.drift"}
        keep = [e for e in merged if e.get("kind") in rare]
        rest = [e for e in merged if e.get("kind") not in rare]
        budget = max(0, args.max_events - len(keep))
        rest = rest[-budget:] if budget else []
        merged = sorted(keep + rest, key=lambda e: float(e.get("ts") or 0))

    clean = []
    for i, ev in enumerate(merged, 1):
        ev = red.event(ev)
        ev.setdefault("source", "fixture")
        ev["eid"] = f"fx{i:05d}"       # 确定性 eid：两侧同源，event_id 才可比
        if not ev.get("ts"):
            continue
        clean.append(ev)

    ev_path = os.path.join(args.out, "events.jsonl")
    with open(ev_path, "w", encoding="utf-8") as fh:
        for ev in clean:
            fh.write(json.dumps(ev, ensure_ascii=False, sort_keys=True) + "\n")

    table = proc_table(args.py_dir, clean)
    tbl_path = os.path.join(args.out, "proctable.json")
    with open(tbl_path, "w", encoding="utf-8") as fh:
        json.dump(table, fh, ensure_ascii=False, indent=1)

    kinds = collections.Counter(e.get("kind") for e in clean)
    meta = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "sources": {
            "live_capture": len(live),
            "history": len(hist),
            "history_file": args.history,
            "history_kind_totals": totals,
        },
        "events": len(clean),
        "size_bytes": os.path.getsize(ev_path),
        "proctable_rows": len(table["rows"]),
        "kinds": dict(kinds.most_common()),
        "redaction": [
            "hostname → HOST-A；user → USER-A；家目录 → /Users/USER-A",
            "公网 IPv4 → 203.0.113.0/24（保留「是否公网」语义，私有地址不动）",
            "token/password/secret/api_key/authorization 的 value → <REDACTED>",
            "eid 重编为 fxNNNNN（确定性，两侧同源）",
            "字段名/kind/severity/subject 键集合与数组顺序一律不动",
        ],
    }
    meta_path = os.path.join(args.out, "meta.json")
    with open(meta_path, "w", encoding="utf-8") as fh:
        json.dump(meta, fh, ensure_ascii=False, indent=2)

    print(f"写出 {ev_path}：{len(clean)} 条事件，"
          f"{os.path.getsize(ev_path)/1024:.0f} KB，{len(kinds)} 种 kind", file=sys.stderr)
    print(f"写出 {tbl_path}：{len(table['rows'])} 行进程表", file=sys.stderr)
    print(f"写出 {meta_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
