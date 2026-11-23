#!/usr/bin/env bash
# 一键对拍：Go 版 vs Python 版告警集合。
#
#   scripts/parity.sh                 # 用现有样本跑一次
#   scripts/parity.sh --refresh       # 先重新生成真实事件流样本，再跑
#   scripts/parity.sh --events X --proctable Y   # 指定别的事件流
#
# 退出码：0 = 100% 一致；2 = 有迁移缺口；3 = 工具/环境问题。
# 报告落 out/parity/report.md（终端同时打印摘要）。
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

REFRESH=0
ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --refresh) REFRESH=1; shift ;;
    --help|-h)
      sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) ARGS+=("$1"); shift ;;
  esac
done

PY_DIR="${AEGIS_PY_DIR:-$HOME/aegis}"
if [[ ! -f "$PY_DIR/parity_cli.py" ]]; then
  echo "parity.sh: 找不到 Python 适配器 $PY_DIR/parity_cli.py" >&2
  echo "           （设 AEGIS_PY_DIR 指向 Python 版仓库根目录）" >&2
  exit 3
fi

mkdir -p out/bin
echo "== 构建 cmd/parity =="
go build -o out/bin/parity ./cmd/parity

if [[ $REFRESH -eq 1 ]]; then
  echo "== 重新生成真实事件流样本（本机采集 + 历史流抽样 + 脱敏）=="
  python3 scripts/make_fixture.py --out testdata/parity --py-dir "$PY_DIR"
fi

echo "== 对拍 =="
set +e
out/bin/parity \
  -events "${EVENTS:-testdata/parity/events.jsonl}" \
  -proctable "${PROCTABLE:-testdata/parity/proctable.json}" \
  -py-dir "$PY_DIR" \
  "${ARGS[@]+"${ARGS[@]}"}"
code=$?
set -e

echo
echo "报告：$ROOT/out/parity/report.md"
exit $code
