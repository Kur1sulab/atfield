#!/bin/bash
# 心之壁.app 启动器（由 packaging/build_app.sh 安装到 Contents/MacOS/atfield-launcher）。
#
# 职责：定位内嵌的 Python 运行时与 atfield 源码，然后 exec atfieldd.py。
# 注意：脚本内任何 python 调用（含依赖自检）都必须带 -B 或继承
# PYTHONDONTWRITEBYTECODE=1——往已签名的 .app 里写 .pyc 会让
# codesign --verify 报 "a sealed resource is missing or invalid"。
# 设计约束：
#   - 不依赖调用者 cwd（Finder 双击、/usr/local/bin/atfield 软链、直接路径调用都要能用）
#   - 不修改仓库任何文件，只读 Contents/Resources
#   - 出错时给出中文可执行建议，而不是抛 Python traceback
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

# ---------- 解析自身真实路径（穿过 /usr/local/bin/atfield 这类符号链接） ----------
_self="${BASH_SOURCE[0]}"
while [ -L "${_self}" ]; do
  _dir="$(cd -- "$(dirname -- "${_self}")" && pwd -P)"
  _link="$(readlink -- "${_self}")"
  case "${_link}" in
    /*) _self="${_link}" ;;
    *)  _self="${_dir}/${_link}" ;;
  esac
done
MACOS_DIR="$(cd -- "$(dirname -- "${_self}")" && pwd -P)"
CONTENTS_DIR="$(cd -- "${MACOS_DIR}/.." && pwd -P)"
RES_DIR="${CONTENTS_DIR}/Resources"
DAEMON_PY="${RES_DIR}/atfieldd.py"
RUNTIME_ENV="${RES_DIR}/runtime.env"

fail() {
  # $1 退出码，其余为提示行
  local code="$1"; shift || true
  {
    printf '\n[心之壁] 启动失败\n'
    local line
    for line in "$@"; do printf '  %s\n' "${line}"; done
    printf '\n'
  } >&2
  exit "${code}"
}

[[ -f "${DAEMON_PY}" ]] || fail 5 \
  "应用包内缺少 ${DAEMON_PY}" \
  "应用包可能不完整，请重新构建：bash packaging/build_app.sh --force"

# ---------- 选择解释器 ----------
PY=""
if [[ -n "${ATFIELD_PYTHON:-}" ]]; then
  [[ -x "${ATFIELD_PYTHON}" ]] || fail 5 "环境变量 ATFIELD_PYTHON 指向的解释器不可执行：${ATFIELD_PYTHON}" \
    "unset ATFIELD_PYTHON 使用内嵌/系统默认解释器。"
  PY="${ATFIELD_PYTHON}"
fi

# 1) 自包含运行时（build_app.sh --bundle-runtime 产物）
if [[ -z "${PY}" && -x "${RES_DIR}/runtime/bin/python3" ]]; then
  PY="${RES_DIR}/runtime/bin/python3"
fi

# 2) 构建时写入的解释器记录
if [[ -z "${PY}" && -f "${RUNTIME_ENV}" ]]; then
  # shellcheck disable=SC1090
  . "${RUNTIME_ENV}"
  if [[ -n "${ATFIELD_PYTHON:-}" && -x "${ATFIELD_PYTHON}" ]]; then
    PY="${ATFIELD_PYTHON}"
  fi
  ATFIELD_PYTHON=""
fi

# 3) 系统常见位置
if [[ -z "${PY}" ]]; then
  for candidate in \
    /opt/homebrew/bin/python3 \
    /usr/local/bin/python3 \
    /Library/Frameworks/Python.framework/Versions/Current/bin/python3 \
    /usr/bin/python3
  do
    if [[ -x "${candidate}" ]]; then PY="${candidate}"; break; fi
  done
fi
if [[ -z "${PY}" ]] && command -v python3 >/dev/null 2>&1; then
  PY="$(command -v python3)"
fi
[[ -n "${PY}" ]] || fail 5 \
  "找不到可用的 python3 解释器" \
  "请安装 Python 3.9+（brew install python@3.12），" \
  "或重建应用包把运行时打进去：bash packaging/build_app.sh --bundle-runtime --force"

# ---------- 依赖自检：psutil 是唯一硬依赖 ----------
if ! "${PY}" -B -c 'import psutil' >/dev/null 2>&1; then
  fail 6 \
    "当前解释器缺少 psutil：${PY}" \
    "方案 A（推荐）：重建为自包含包  bash packaging/build_app.sh --bundle-runtime --force" \
    "方案 B：为该系统 Python 安装依赖  \"${PY}\" -m pip install --user -r \"${RES_DIR}/requirements.txt\"" \
    "方案 C：指定已有虚拟环境        ATFIELD_PYTHON=/path/to/venv/bin/python3 atfield"
fi

# ---------- Finder/launchd 启动（stdout 指向 /dev/null）时把输出落到日志 ----------
# 判定依据：stdout 的真实目标确实是 /dev/null（launchd/Finder 的默认 stdio）。
# 管道（`atfield --version | grep`）、重定向到文件、TTY 都保留原始输出，不会被吞。
_stdout_target="$(readlink /dev/fd/1 2>/dev/null || true)"
if [[ ! -t 1 && "${_stdout_target}" == "/dev/null" ]]; then
  LOG_DIR="${HOME}/Library/Logs/心之壁"
  mkdir -p -- "${LOG_DIR}"
  LOG_FILE="${LOG_DIR}/launcher.log"
  printf '\n===== %s launch =====\n' "$(date '+%Y-%m-%d %H:%M:%S')" >>"${LOG_FILE}"
  exec >>"${LOG_FILE}" 2>&1
fi

export PYTHONPATH="${RES_DIR}${PYTHONPATH:+:${PYTHONPATH}}"
exec "${PY}" "${DAEMON_PY}" "$@"
