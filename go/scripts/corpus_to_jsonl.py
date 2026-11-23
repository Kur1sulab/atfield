#!/usr/bin/env python3
"""把 internal/detect/testdata 的手工语料转成对拍工具能吃的 JSONL。

真实事件流（testdata/parity）覆盖的是「本机真发生过的行为」——32 条规则里
只会压到十几条。这份手工语料是**合成**的，专门为「32 条规则各来一发」而写，
用来补规则覆盖：两个流都跑一遍，才算既真实又全。

    python3 scripts/corpus_to_jsonl.py
    out/bin/parity -events testdata/parity/corpus.jsonl \
        -proctable testdata/parity/corpus_proctable.json -out out/parity/corpus
"""
from __future__ import annotations

import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "internal", "detect", "testdata", "parity_corpus.json")
OUT_DIR = os.path.join(ROOT, "testdata", "parity")

# 与 internal/detect/parity_test.go 里的进程树一致：100 ← 200 ← 300，
# 400=后门，500=curl。同一份表喂两侧，root_pid 才有可比性。
PROCTABLE = {
    "rows": [
        {"pid": 100, "ppid": 1, "exe": "/sbin/launchd"},
        {"pid": 200, "ppid": 100, "exe": "/bin/zsh"},
        {"pid": 300, "ppid": 200, "exe": "/usr/bin/whoami"},
        {"pid": 400, "ppid": 200, "exe": "/tmp/backdoor"},
        {"pid": 500, "ppid": 200, "exe": "/usr/bin/curl"},
    ]
}


def main() -> int:
    with open(SRC, "r", encoding="utf-8") as fh:
        corpus = json.load(fh)
    os.makedirs(OUT_DIR, exist_ok=True)
    ev_path = os.path.join(OUT_DIR, "corpus.jsonl")
    with open(ev_path, "w", encoding="utf-8") as fh:
        for i, ev in enumerate(corpus, 1):
            row = dict(ev)
            row.setdefault("severity", "info")
            row["source"] = row.get("source") or "parity"
            row["ts"] = float(i)          # 语料本身没有时间，按顺序给确定性 ts
            row["eid"] = f"c{i:04d}"
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    tbl_path = os.path.join(OUT_DIR, "corpus_proctable.json")
    with open(tbl_path, "w", encoding="utf-8") as fh:
        json.dump(PROCTABLE, fh, ensure_ascii=False, indent=1)
    print(f"{ev_path}: {len(corpus)} 条事件")
    print(f"{tbl_path}: {len(PROCTABLE['rows'])} 行进程表")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
