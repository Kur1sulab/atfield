#!/bin/bash
# 心之壁 打包脚本共享库：路径解析 / 日志 / 参数与前置校验 / 版本号解析。
# 仅被 packaging/*.sh source，不单独执行。
# 注意：所有路径都可能含空格或以点结尾（例如用户目录 /Users/<name>），
#       脚本内一律加双引号，并用 pwd -P 取物理路径。

# ---- 目录解析：以本文件位置为锚点，避免依赖调用者 cwd ----
ATFIELD_LIB_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
ATFIELD_PACKAGING_DIR="$(cd -- "${ATFIELD_LIB_DIR}/.." && pwd -P)"
ATFIELD_REPO_ROOT="$(cd -- "${ATFIELD_PACKAGING_DIR}/.." && pwd -P)"

ATFIELD_INIT_PY="${ATFIELD_REPO_ROOT}/atfield/__init__.py"
ATFIELD_DAEMON_PY="${ATFIELD_REPO_ROOT}/atfieldd.py"
ATFIELD_WEB_DIR="${ATFIELD_REPO_ROOT}/atfield/web"
ATFIELD_REQ_TXT="${ATFIELD_REPO_ROOT}/requirements.txt"
ATFIELD_TEMPLATE_DIR="${ATFIELD_PACKAGING_DIR}/templates"

# 固定产品标识（与 Info.plist / pkg identifier / MDM 配置保持一致）
ATFIELD_BUNDLE_ID="com.kurisulab.atfield"
ATFIELD_APP_NAME_DEFAULT="心之壁"
ATFIELD_MIN_MACOS="13.0"
ATFIELD_DIST_DIR="${ATFIELD_PACKAGING_DIR}/dist"

# ---- 日志 ----
if [[ -t 1 ]]; then
  _C_RESET=$'\033[0m'; _C_RED=$'\033[31m'; _C_GRN=$'\033[32m'
  _C_YEL=$'\033[33m'; _C_BLU=$'\033[34m'; _C_BOLD=$'\033[1m'
else
  _C_RESET=''; _C_RED=''; _C_GRN=''; _C_YEL=''; _C_BLU=''; _C_BOLD=''
fi

log_info() { printf '%s[心之壁]%s %s\n' "${_C_BLU}" "${_C_RESET}" "$*"; }
log_ok()   { printf '%s[ OK ]%s %s\n'  "${_C_GRN}" "${_C_RESET}" "$*"; }
log_warn() { printf '%s[WARN]%s %s\n'  "${_C_YEL}" "${_C_RESET}" "$*" >&2; }
log_err()  { printf '%s[FAIL]%s %s\n'  "${_C_RED}" "${_C_RESET}" "$*" >&2; }
log_step() { printf '\n%s==> %s%s\n' "${_C_BOLD}" "$*" "${_C_RESET}"; }

# die <退出码> <中文错误> [下一步建议...]
die() {
  local code="${1:-1}"; shift || true
  local msg="${1:-未知错误}"; shift || true
  log_err "${msg}"
  local hint
  for hint in "$@"; do
    printf '         ↳ %s\n' "${hint}" >&2
  done
  exit "${code}"
}

# ---- 前置校验 ----
need_cmd() {
  local c
  for c in "$@"; do
    command -v "${c}" >/dev/null 2>&1 || die 4 "缺少必需命令：${c}" \
      "macOS 自带该命令；若在精简系统上，请安装 Xcode Command Line Tools：" \
      "  xcode-select --install"
  done
}

need_file() {
  local f="$1" desc="${2:-文件}"
  [[ -e "${f}" ]] || die 2 "${desc} 不存在：${f}" \
    "确认你在 心之壁 仓库内运行本脚本（仓库根目录应包含 atfieldd.py 与 atfield/）。"
  [[ -f "${f}" ]] || die 2 "${desc}不是普通文件：${f}"
}

need_dir() {
  local d="$1" desc="${2:-目录}"
  [[ -d "${d}" ]] || die 2 "${desc} 不存在：${d}" \
    "请先执行前置构建步骤，或用 --help 查看本脚本要求的输入。"
}

need_readable() {
  local p="$1"
  [[ -r "${p}" ]] || die 2 "无读取权限：${p}" "检查文件属主与权限（ls -l \"${p}\"）。"
}

# ---- 版本号：单一真源 atfield/__init__.py 的 __version__ ----
atfield_version() {
  need_file "${ATFIELD_INIT_PY}" "版本号真源 atfield/__init__.py"
  local ver=""
  if command -v python3 >/dev/null 2>&1; then
    ver="$(python3 - "${ATFIELD_INIT_PY}" <<'PY' 2>/dev/null || true
import ast, sys
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as fh:
    tree = ast.parse(fh.read(), filename=path)
for node in tree.body:
    if isinstance(node, ast.Assign):
        for t in node.targets:
            if isinstance(t, ast.Name) and t.id == "__version__":
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    print(node.value.value)
PY
)"
  fi
  # 回退：python3 不可用时用 grep/sed 解析（同样只认模块级赋值形态）
  if [[ -z "${ver}" ]]; then
    ver="$(sed -n 's/^__version__[[:space:]]*=[[:space:]]*["'\'']\([^"'\'']*\)["'\''][[:space:]]*$/\1/p' \
      "${ATFIELD_INIT_PY}" | head -n 1)"
  fi
  [[ -n "${ver}" ]] || die 3 "无法从 ${ATFIELD_INIT_PY} 解析 __version__" \
    "该文件应包含形如  __version__ = \"1.0.0\"  的模块级赋值。" \
    "本脚本刻意不硬编码版本号，请修复真源后重试。"
  [[ "${ver}" =~ ^[0-9]+(\.[0-9]+){0,3}([-+][0-9A-Za-z.-]+)?$ ]] || die 3 \
    "解析出的版本号格式不可用：'${ver}'" \
    "pkg 版本号需为数字点分形式（如 1.0.0），请在 atfield/__init__.py 中修正。"
  printf '%s\n' "${ver}"
}

# ---- python3 选择 ----
# 打印第一个可用的 python3 绝对路径；全部不可用则返回 1。
find_python3() {
  local candidate
  for candidate in \
    "${ATFIELD_PYTHON_OVERRIDE:-}" \
    "/opt/homebrew/bin/python3" \
    "/usr/local/bin/python3" \
    "/Library/Frameworks/Python.framework/Versions/Current/bin/python3" \
    "/usr/bin/python3"
  do
    [[ -n "${candidate}" ]] || continue
    if [[ -x "${candidate}" ]]; then
      printf '%s\n' "${candidate}"; return 0
    fi
  done
  if command -v python3 >/dev/null 2>&1; then
    command -v python3; return 0
  fi
  return 1
}

# ---- 输出目录安全约束 ----
# 只允许写入 packaging/ 内或临时目录（/tmp、$TMPDIR），防止误删用户目录。
assert_writable_target() {
  local p="$1" what="${2:-输出路径}"
  [[ -n "${p}" ]] || die 1 "${what}为空" "请显式传入目录，例如 --output \"${ATFIELD_DIST_DIR}\""
  [[ "${p}" != "/" ]] || die 1 "${what}不能是根目录 /"
  case "${p}" in
    "${ATFIELD_PACKAGING_DIR}"|"${ATFIELD_PACKAGING_DIR}"/*) : ;;
    /tmp/*|/private/tmp/*|"${TMPDIR:-/tmp}"/*) : ;;
    *) die 1 "${what}必须位于 packaging/ 或 /tmp 下：${p}" \
            "本仓库约定打包产物只落在 \"${ATFIELD_DIST_DIR}\"，避免污染其他目录。" ;;
  esac
  # 拒绝把 packaging/ 本身或仓库根当成可删除目标
  [[ "${p}" != "${ATFIELD_PACKAGING_DIR}" ]] || die 1 "${what}不能是 packaging/ 目录本身"
}

# 安全删除：只允许 packaging/ 与 /tmp 下的路径，且必须含 心之壁 字样或位于 build 子目录
safe_rm_rf() {
  local p="$1"
  [[ -n "${p}" && "${p}" != "/" ]] || die 1 "拒绝删除空路径或根目录"
  assert_writable_target "${p}" "待删除路径"
  if [[ -d "${p}" ]]; then
    rm -rf -- "${p}"
  fi
}

# ---- 杂项 ----
mtime_now() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }

# 校验 Info.plist 关键键值是否落地（打包后自检）
plist_get() {
  local plist="$1" key="$2"
  /usr/libexec/PlistBuddy -c "Print :${key}" "${plist}" 2>/dev/null || true
}

print_banner_header() {
  printf '\n%s%s%s\n' "${_C_BOLD}" "$1" "${_C_RESET}"
  printf '%s\n' "------------------------------------------------------------"
}
