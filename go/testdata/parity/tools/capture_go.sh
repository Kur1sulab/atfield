#!/bin/bash
# 采一份「Go 采集器真实事件流」：连跑 N 轮 `atfieldd --once --all`，把每轮
# 的 events_list 按轮次顺序拼成一份 JSONL；同时抓一份同一时刻的进程表。
#
# 为什么是「连跑 N 轮进程」而不是一个常驻进程：Go 版目前只有 --once，
# 每次运行 = 一次冷启动 + 一轮采集。对拍要的是事件流，不是常驻内存，
# 所以 N 次独立运行拼成的时间线正是一台机器上 N 次轮询会看到的东西。
#
# 用法：
#   testdata/parity/tools/capture_go.sh /tmp/gocap 3
# 产物：
#   $OUT/go_events.jsonl      每行一个 model.Event（按轮次顺序）
#   $OUT/go_proctable.json    {"rows":[{pid,ppid,exe}]}（ps 快照，两侧共用）
#   $OUT/round<N>.json        每轮原始输出（含每采集器耗时，便于性能取证）
set -uo pipefail

OUT="${1:?用法: capture_go.sh <输出目录> [轮数]}"
ROUNDS="${2:-3}"
BIN="${ATFIELDD_BIN:-}"

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"          # go/
if [ -z "$BIN" ]; then
  BIN="$OUT/atfieldd"
  ( cd "$ROOT" && go build -o "$BIN" ./cmd/atfieldd ) || exit 1
fi

mkdir -p "$OUT"
: > "$OUT/go_events.jsonl"
for i in $(seq 1 "$ROUNDS"); do
  "$BIN" --once --all > "$OUT/round$i.json" 2>"$OUT/round$i.err" || {
    echo "第 $i 轮失败（见 $OUT/round$i.err）" >&2; exit 1; }
  python3 - "$OUT/round$i.json" >> "$OUT/go_events.jsonl" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
for run in d.get("runs") or []:
    for ev in run.get("events_list") or []:
        print(json.dumps(ev, ensure_ascii=False, sort_keys=True))
PY
  echo "  轮 $i 完成：$(wc -l < "$OUT/go_events.jsonl") 条事件累计" >&2
done

ps -ww -axo pid=,ppid=,command= | python3 -c '
import sys, json
rows = []
for line in sys.stdin:
    parts = line.strip().split(None, 2)
    if len(parts) < 3:
        continue
    try:
        rows.append({"pid": int(parts[0]), "ppid": int(parts[1]), "exe": parts[2].split(" ")[0]})
    except ValueError:
        continue
json.dump({"rows": rows}, open(sys.argv[1], "w"), ensure_ascii=False)
' "$OUT/go_proctable.json"

echo "事件 $(wc -l < "$OUT/go_events.jsonl") 条 → $OUT/go_events.jsonl" >&2
echo "进程表 $(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1]))["rows"]))' "$OUT/go_proctable.json") 行 → $OUT/go_proctable.json" >&2
