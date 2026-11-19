#!/bin/bash
# packaging/release.sh —— 一条命令跑完发布链：构建 .app → 签名 → 验签 → 出 .pkg → 汇总指纹
#
# 设计要点：
#   · 单一入口，失败即停在失败的那一步（不继续往下产出「看着像成功」的包）
#   · 同一时间只允许一条发布链（dist/.release.lock），并发会把 dist 写坏
#   · 验签用 sign_and_notarize.sh --verify-only（exit 0 通过 / 7 失败），不靠日志猜
#   · 结尾打印一行可粘贴的指纹结论：RELEASE_OK version=… pkg=… sha256=… bytes=… files=…
#   · 全过程日志落在 <dist>/release-<时间戳>/，不用回头翻终端
#
# 退出码：0 成功 / 1 参数错误 / 2 前置缺失 / 3 构建 .app 失败 / 4 签名失败
#         5 验签失败 / 6 出 .pkg 失败 / 7 已有发布链在跑 / 8 产物自检未通过
set -euo pipefail

SELF_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
. "${SELF_DIR}/lib/common.sh"

EXEC_NAME="atfield-launcher"

OUT_DIR="${ATFIELD_DIST_DIR}"
APP_NAME="${ATFIELD_APP_NAME_DEFAULT}"
PYTHON_OVERRIDE=""
BUNDLE_RUNTIME=1
SKIP_NOTARIZE=0
IDENTITY=""
INSTALLER_IDENTITY=""
PROXY_URL=""
NO_PROXY_MODE=0
DRY_RUN=0

usage() {
  cat <<'USAGE'
release.sh —— 心之壁 一键发布链（构建 .app → 签名 → 验签 → 出 .pkg → 打印指纹）

用法:
  bash packaging/release.sh [选项]

选项:
  --version                  打印版本号后退出（单一真源 atfield/__init__.py）
  --output DIR               输出目录（默认 packaging/dist；只允许 packaging/ 或 /tmp 下）
  --app-name NAME            应用名（默认 ATField）
  --python PATH              打包用的系统 python3
  --no-runtime               不内嵌 venv（开发自测用，产物不可脱离本机 Python）
  --identity NAME            Developer ID Application 证书名（默认自动挑；无证书则 ad-hoc）
  --installer-identity NAME  Developer ID Installer 证书名（给了就顺带签 .pkg）
  --skip-notarize            跳过公证（无凭据时用，签名仍做）
  --proxy URL                显式指定代理（默认自动探测 127.0.0.1:7897）
  --no-proxy                 关闭代理自动探测
  --dry-run, -n              只校验并打印将要执行的命令，不写文件
  -h, --help                 显示本帮助

产物（默认 packaging/dist/）:
  心之壁.app                     已签名应用包
  心之壁-<version>.pkg           分发用安装包
  release-<时间戳>/release.log    全过程日志 + release-report.txt

退出码: 0 成功 / 1 参数 / 2 前置缺失 / 3 构建 app 失败 / 4 签名失败
        5 验签失败 / 6 出 pkg 失败 / 7 已有发布链在跑 / 8 产物自检未通过
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) atfield_version; exit 0 ;;
    --output) OUT_DIR="${2:-}"; shift 2 ;;
    --app-name) APP_NAME="${2:-}"; shift 2 ;;
    --python) PYTHON_OVERRIDE="${2:-}"; shift 2 ;;
    --no-runtime) BUNDLE_RUNTIME=0; shift ;;
    --identity) IDENTITY="${2:-}"; shift 2 ;;
    --installer-identity) INSTALLER_IDENTITY="${2:-}"; shift 2 ;;
    --skip-notarize) SKIP_NOTARIZE=1; shift ;;
    --proxy) PROXY_URL="${2:-}"; shift 2 ;;
    --no-proxy) NO_PROXY_MODE=1; shift ;;
    --dry-run|-n) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) log_err "未知参数：$1"; usage; exit 1 ;;
  esac
done

# ---- 前置校验 ----------------------------------------------------------------
need_cmd bash codesign pkgutil shasum find
[[ $BUNDLE_RUNTIME -eq 1 ]] || log_warn "已指定 --no-runtime：产物依赖本机 Python，不可直接分发"
need_file "${ATFIELD_DAEMON_PY}" "入口 atfieldd.py"
need_file "${ATFIELD_INIT_PY}" "版本号真源 atfield/__init__.py"
need_dir "${ATFIELD_WEB_DIR}" "Web 静态资源目录"
assert_writable_target "${OUT_DIR}" "输出目录"
mkdir -p "${OUT_DIR}" || die 1 "无法创建输出目录：${OUT_DIR}" \
  "确认父目录存在且可写（ls -ld \"$(dirname "${OUT_DIR}")\"）。"

VERSION="$(atfield_version)"
APP_PATH="${OUT_DIR}/${APP_NAME}.app"
PKG_PATH="${OUT_DIR}/${APP_NAME}-${VERSION}.pkg"
STAMP="$(date '+%Y%m%d-%H%M%S')"
LOG_DIR="${OUT_DIR}/release-${STAMP}"
LOCK_DIR="${OUT_DIR}/.release.lock"

# ---- 代理：venv 里 pip 要联网，国内直连必挂 ----------------------------------
if [[ -z "${PROXY_URL}" && $NO_PROXY_MODE -eq 0 ]]; then
  if command -v nc >/dev/null 2>&1 && nc -z 127.0.0.1 7897 >/dev/null 2>&1; then
    PROXY_URL="http://127.0.0.1:7897"
  fi
fi
if [[ -n "${PROXY_URL}" ]]; then
  export HTTP_PROXY="${PROXY_URL}" HTTPS_PROXY="${PROXY_URL}" ALL_PROXY="${PROXY_URL}"
  export http_proxy="${PROXY_URL}" https_proxy="${PROXY_URL}" all_proxy="${PROXY_URL}"
  log_info "使用代理：${PROXY_URL}"
fi

log_step "心之壁 发布链 ${VERSION}（$( [[ $DRY_RUN -eq 1 ]] && echo 'DRY-RUN' || echo '实跑' )）"
log_info "输出目录：${OUT_DIR}"

if [[ $DRY_RUN -eq 1 ]]; then
  printf '\n将要执行：\n'
  printf '  1) bash build_app.sh --force --bundle-runtime --app-name "%s" --output "%s"\n' "${APP_NAME}" "${OUT_DIR}"
  printf '  2) bash sign_and_notarize.sh --target "%s"%s\n' "${APP_PATH}" "$( [[ $SKIP_NOTARIZE -eq 1 ]] && echo ' --skip-notarize' )"
  printf '  3) bash sign_and_notarize.sh --verify-only --target "%s"\n' "${APP_PATH}"
  printf '  4) bash build_pkg.sh --force --app "%s" --output "%s"%s\n' "${APP_PATH}" "${OUT_DIR}" \
    "$( [[ -n "${INSTALLER_IDENTITY}" ]] && echo " --installer-identity ${INSTALLER_IDENTITY}" )"
  printf '  5) shasum -a 256 "%s"；校验包内静态资源与源码一致\n\n' "${PKG_PATH}"
  exit 0
fi

# ---- 单链互斥锁 --------------------------------------------------------------
if ! mkdir "${LOCK_DIR}" 2>/dev/null; then
  holder="$(cat "${LOCK_DIR}/pid" 2>/dev/null || echo '?')"
  if [[ "${holder}" =~ ^[0-9]+$ ]] && kill -0 "${holder}" 2>/dev/null; then
    die 7 "已有发布链在跑（pid ${holder}）" "等它结束，或确认是残留后删除 ${LOCK_DIR}"
  fi
  log_warn "发现残留锁（pid ${holder} 已不存在），接管"
  rm -rf -- "${LOCK_DIR}"
  mkdir "${LOCK_DIR}" || die 7 "无法建立互斥锁：${LOCK_DIR}"
fi
printf '%s\n' "$$" > "${LOCK_DIR}/pid"

cleanup() {
  local rc=$?
  rm -rf -- "${LOCK_DIR}"
  if [[ $rc -ne 0 ]]; then
    log_err "发布链中断（退出码 ${rc}），日志：${LOG_DIR}"
    [[ -f "${LOG_DIR}/release.log" ]] && tail -n 20 "${LOG_DIR}/release.log" >&2 || true
  fi
}
trap cleanup EXIT

mkdir -p "${LOG_DIR}"
LOG="${LOG_DIR}/release.log"
: > "${LOG}"
exec > >(tee -a "${LOG}") 2>&1

# run_logged <步骤名> <日志文件名> <命令...>
run_logged() {
  local title="$1" logfile="$2"; shift 2
  local started ended
  started="$(date '+%H:%M:%S')"
  log_step "${title}"
  if "$@" 2>&1 | tee "${LOG_DIR}/${logfile}"; then
    ended="$(date '+%H:%M:%S')"
    log_ok "${title}（${started} → ${ended}）"
    return 0
  fi
  log_err "${title} 失败，完整输出见 ${LOG_DIR}/${logfile}"
  return 1
}

# ---- 1. 构建 .app ------------------------------------------------------------
APP_ARGS=(--force --output "${OUT_DIR}" --app-name "${APP_NAME}")
[[ $BUNDLE_RUNTIME -eq 1 ]] && APP_ARGS+=(--bundle-runtime)
[[ -n "${PYTHON_OVERRIDE}" ]] && APP_ARGS+=(--python "${PYTHON_OVERRIDE}")
run_logged "1/5 构建 ${APP_NAME}.app" build-app.log \
  bash "${SELF_DIR}/build_app.sh" "${APP_ARGS[@]}" || die 3 "构建 .app 失败"

need_dir "${APP_PATH}" "构建产物 ${APP_NAME}.app"
LAUNCHER="${APP_PATH}/Contents/MacOS/${EXEC_NAME}"
need_file "${LAUNCHER}" "启动器 ${EXEC_NAME}"

# ---- 2. 签名 ----------------------------------------------------------------
SIGN_ARGS=(--target "${APP_PATH}")
[[ -n "${IDENTITY}" ]] && SIGN_ARGS+=(--identity "${IDENTITY}")
[[ $SKIP_NOTARIZE -eq 1 ]] && SIGN_ARGS+=(--skip-notarize)
run_logged "2/5 签名（$( [[ -n "${IDENTITY}" ]] && echo "${IDENTITY}" || echo '自动挑证书，无则 ad-hoc' )）" sign.log \
  bash "${SELF_DIR}/sign_and_notarize.sh" "${SIGN_ARGS[@]}" || die 4 "签名失败"

# ---- 3. 验签 ----------------------------------------------------------------
VERIFY_ARGS=(--verify-only --target "${APP_PATH}")
run_logged "3/5 验签（codesign --verify --deep --strict）" verify.log \
  bash "${SELF_DIR}/sign_and_notarize.sh" "${VERIFY_ARGS[@]}" || die 5 "验签未通过"

# ---- 4. 出 .pkg -------------------------------------------------------------
PKG_ARGS=(--force --app "${APP_PATH}" --output "${OUT_DIR}")
[[ -n "${INSTALLER_IDENTITY}" ]] && PKG_ARGS+=(--installer-identity "${INSTALLER_IDENTITY}")
run_logged "4/5 生成 ${APP_NAME}-${VERSION}.pkg" pkg.log \
  bash "${SELF_DIR}/build_pkg.sh" "${PKG_ARGS[@]}" || die 6 "生成 .pkg 失败"

need_file "${PKG_PATH}" "安装包 ${PKG_PATH}"

if [[ -n "${INSTALLER_IDENTITY}" ]]; then
  run_logged "4b 校验 .pkg 签名（pkgutil --check-signature）" pkg-sign-check.log \
    pkgutil --check-signature "${PKG_PATH}" || die 6 ".pkg 签名校验失败"
fi

# ---- 5. 自检 + 指纹 ---------------------------------------------------------
log_step "5/5 产物自检"

# 5a. 启动器版本号必须是刚构建的这一版
VER_LINE="$("${LAUNCHER}" --version 2>&1 | tail -n 1 || true)"
if [[ "${VER_LINE}" != *"${VERSION}"* ]]; then
  die 8 "启动器版本与真源不一致：期望含 ${VERSION}，实际 '${VER_LINE}'" \
        "可能打包了旧产物，检查 ${APP_PATH}/Contents/Resources/atfield/__init__.py"
fi
log_ok "启动器版本：${VER_LINE}"

# 5b. 包内静态资源必须与源码逐字节一致（防止改了源码忘了重建）
ASSET_STATUS="SAME"
for rel in index.html style.css app.js; do
  src="${ATFIELD_WEB_DIR}/${rel}"
  dst="${APP_PATH}/Contents/Resources/atfield/web/${rel}"
  [[ -f "${src}" ]] || continue
  a="$(shasum -a 256 "${src}" | awk '{print $1}')"
  b="$(shasum -a 256 "${dst}" 2>/dev/null | awk '{print $1}')"
  if [[ "${a}" != "${b}" ]]; then
    ASSET_STATUS="DIFF(${rel})"
  fi
  printf '    %-11s %s %s\n' "${rel}" "${a:0:12}" "$( [[ "${a}" == "${b}" ]] && echo '== bundle' || echo '!= bundle' )"
done
[[ "${ASSET_STATUS}" == "SAME" ]] || die 8 "包内静态资源与源码不一致：${ASSET_STATUS}" \
  "重新跑本脚本（带 --force），不要手工只替换单文件"

# 5c. 指纹
PKG_BYTES="$(stat -f%z "${PKG_PATH}")"
# 注意：这里必须容错——pipefail + set -e 下「命令替换里的管道失败」会让整个赋值语句 exit
PKG_FILES="$(pkgutil --payload-files "${PKG_PATH}" 2>/dev/null | grep -cv '/$' || true)"
PKG_FILES="${PKG_FILES:-0}"
APP_BYTES="$(du -sh "${APP_PATH}" | awk '{print $1}')"
SHA="$(shasum -a 256 "${PKG_PATH}" | awk '{print $1}')"
SIGN_KIND="$(codesign -dv --verbose=2 "${APP_PATH}" 2>&1 | awk -F= '/^Authority/{print $2; exit}')"
SIGN_KIND="${SIGN_KIND:-ad-hoc（仅供本机测试，不可分发）}"

REPORT="${LOG_DIR}/release-report.txt"
mkdir -p "$(dirname "${REPORT}")"
cat > "${REPORT}" <<REPORT_EOF
心之壁 发布报告
==================
生成时间   ${STAMP}
版本       ${VERSION}
应用       ${APP_PATH}（${APP_BYTES}）
安装包     ${PKG_PATH}（${PKG_BYTES} 字节 / ${PKG_FILES} 文件）
SHA-256    ${SHA}
签名       ${SIGN_KIND}
静态资源   ${ASSET_STATUS}（index.html / style.css / app.js 与源码逐字节一致）
代理       ${PROXY_URL:-未使用}
日志目录   ${LOG_DIR}

复现命令
--------
bash packaging/release.sh$( [[ -n "${INSTALLER_IDENTITY}" ]] && echo " --installer-identity \"${INSTALLER_IDENTITY}\"" )

安装验证
--------
sudo installer -pkg "${PKG_PATH}" -target /
/usr/local/bin/atfield --version
REPORT_EOF

cp "${REPORT}" "${OUT_DIR}/release-report.txt"

log_ok "发布报告：${REPORT}"
printf '\n'
printf '%sRELEASE_OK%s version=%s pkg=%s sha256=%s bytes=%s files=%s sign=%s assets=%s\n' \
  "${_C_GRN}${_C_BOLD}" "${_C_RESET}" "${VERSION}" "${PKG_PATH##*/}" "${SHA}" "${PKG_BYTES}" "${PKG_FILES}" "${SIGN_KIND}" "${ASSET_STATUS}"
