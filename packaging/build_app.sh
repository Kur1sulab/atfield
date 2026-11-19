#!/bin/bash
# packaging/build_app.sh —— 把 心之壁 打包成 心之壁.app（macOS 应用包）
#
# 产物结构：
#   dist/心之壁.app/Contents/MacOS/atfield-launcher      # bash 启动器
#   dist/心之壁.app/Contents/Info.plist                # 由 templates/Info.plist.in 渲染
#   dist/心之壁.app/Contents/Resources/atfield/          # 完整源码包（含 web 静态资源）
#   dist/心之壁.app/Contents/Resources/atfieldd.py       # 入口
#   dist/心之壁.app/Contents/Resources/runtime.env     # 构建时选定的解释器（供启动器读取）
#   dist/心之壁.app/Contents/Resources/runtime/        # 仅 --bundle-runtime 时存在（venv + psutil）
#
# 退出码：0 成功 / 1 参数错误 / 2 前置文件缺失 / 3 版本解析或构建失败 / 4 缺少工具 / 5 自检未通过
set -euo pipefail

SELF_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
. "${SELF_DIR}/lib/common.sh"

EXEC_NAME="atfield-launcher"

APP_NAME="${ATFIELD_APP_NAME_DEFAULT}"
OUT_DIR="${ATFIELD_DIST_DIR}"
PYTHON_OVERRIDE=""
BUNDLE_RUNTIME=0
DRY_RUN=0
FORCE=0

usage() {
  cat <<'USAGE'
build_app.sh —— 把 心之壁 打包成 心之壁.app

用法:
  bash packaging/build_app.sh [选项]

选项:
  --version              打印从 atfield/__init__.py 解析出的版本号后退出
  --dry-run, -n          只做校验并打印将要执行的每一步，不写任何文件
  --output DIR           输出目录（默认 packaging/dist；仅允许 packaging/ 或 /tmp 下）
  --app-name NAME        应用名，决定 心之壁.app 的文件名（默认 心之壁）
  --python PATH          指定打包使用的系统 python3（默认自动探测）
  --bundle-runtime       把 venv + psutil + PyYAML 装进 Contents/Resources/runtime，
                         生成自包含包（首次构建需联网）
  --force, -f            覆盖输出目录中已存在的同名 .app
  -h, --help             显示本帮助

示例:
  bash packaging/build_app.sh --dry-run             # 先看它要干什么
  bash packaging/build_app.sh --force               # 快速打包，复用系统 python3
  bash packaging/build_app.sh --bundle-runtime      # 自包含包，拷到别的机器也能跑

退出码:
  0  成功（--dry-run 校验通过也返回 0）
  1  参数错误（未知参数、空值、输出目录越界等）
  2  前置文件缺失（atfieldd.py / atfield/__init__.py / atfield/web 不在仓库内）
  3  版本号解析失败，或构建/渲染失败（含 venv 创建、依赖安装失败）
  4  缺少必需工具（python3 / plutil / ditto / PlistBuddy）
  5  构建后自检未通过（Info.plist 不可解析、版本不一致、启动器不可执行等）
USAGE
}

# ---------------- 参数解析（逐个校验，不吞错） ----------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      printf '心之壁 %s\n' "$(atfield_version)"
      exit 0
      ;;
    --dry-run|-n)
      DRY_RUN=1
      ;;
    --bundle-runtime)
      BUNDLE_RUNTIME=1
      ;;
    --force|-f)
      FORCE=1
      ;;
    --output)
      [[ $# -ge 2 && -n "${2:-}" && "${2}" != --* ]] || die 1 "--output 需要一个目录参数" \
        "示例: --output \"${ATFIELD_DIST_DIR}\""
      OUT_DIR="$2"; shift
      ;;
    --output=*)
      OUT_DIR="${1#*=}"
      [[ -n "${OUT_DIR}" ]] || die 1 "--output= 后面不能为空"
      ;;
    --app-name)
      [[ $# -ge 2 && -n "${2:-}" && "${2}" != --* ]] || die 1 "--app-name 需要一个名称参数" \
        "示例: --app-name 心之壁"
      APP_NAME="$2"; shift
      ;;
    --app-name=*)
      APP_NAME="${1#*=}"
      [[ -n "${APP_NAME}" ]] || die 1 "--app-name= 后面不能为空"
      ;;
    --python)
      [[ $# -ge 2 && -n "${2:-}" && "${2}" != --* ]] || die 1 "--python 需要一个可执行文件路径"
      PYTHON_OVERRIDE="$2"; shift
      ;;
    --python=*)
      PYTHON_OVERRIDE="${1#*=}"
      [[ -n "${PYTHON_OVERRIDE}" ]] || die 1 "--python= 后面不能为空"
      ;;
    -h|--help)
      usage; exit 0
      ;;
    *)
      log_err "未知参数：$1"
      printf '\n' >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done

# 应用名不能带路径分隔符/空格，否则产物会写到 --output 之外或让 pkgbuild 行为不一致
case "${APP_NAME}" in
  */*|.|..) die 1 "--app-name 不能包含路径分隔符：${APP_NAME}" "用不含空格的纯名称，例如 ATField" ;;
esac
[[ "${APP_NAME}" != *" "* ]] || die 1 "--app-name 不能包含空格：${APP_NAME}" \
  "Info.plist 与 pkgbuild 对含空格路径处理不一致，请使用 ATField 这类不含空格的名称。"

if [[ "${DRY_RUN}" == "1" ]]; then
  print_banner_header "心之壁 应用包构建（dry-run，不写文件）"
else
  print_banner_header "心之壁 应用包构建"
fi

# ---------------- 1. 前置校验（全部先做完，再动手） ----------------
log_step "1/7 前置校验"
need_cmd python3
need_cmd plutil
need_cmd ditto
need_cmd /usr/libexec/PlistBuddy
need_file "${ATFIELD_INIT_PY}" "版本号真源"
need_file "${ATFIELD_DAEMON_PY}" "守护进程入口 atfieldd.py"
need_dir  "${ATFIELD_WEB_DIR}" "Web 静态资源目录 atfield/web"
need_file "${ATFIELD_WEB_DIR}/index.html" "控制台首页 atfield/web/index.html"
need_file "${ATFIELD_TEMPLATE_DIR}/Info.plist.in" "Info.plist 模板"
need_file "${ATFIELD_TEMPLATE_DIR}/atfield-launcher.sh" "启动器模板"
log_ok "仓库根目录：${ATFIELD_REPO_ROOT}"
log_ok "静态资源：index.html / app.js / style.css 就位"

VERSION="$(atfield_version)"
log_ok "版本号（真源 atfield/__init__.py）：${VERSION}"

if [[ -n "${PYTHON_OVERRIDE}" ]]; then
  [[ -x "${PYTHON_OVERRIDE}" ]] || die 2 "--python 指定的文件不存在或不可执行：${PYTHON_OVERRIDE}" \
    "用 command -v python3 查一个可用路径。"
  PYTHON_BIN="${PYTHON_OVERRIDE}"
else
  PYTHON_BIN="$(find_python3)" || die 4 "找不到 python3" \
    "安装 Python 3.9+：brew install python@3.12（或 xcode-select --install 获得 /usr/bin/python3）"
fi
PY_VER="$("${PYTHON_BIN}" -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null || echo "?")"
log_ok "打包解释器：${PYTHON_BIN} (Python ${PY_VER})"

assert_writable_target "${OUT_DIR}" "--output"
APP_PATH="${OUT_DIR}/${APP_NAME}.app"
CONTENTS="${APP_PATH}/Contents"
RES_DIR="${CONTENTS}/Resources"

printf '        输出目录：%s\n' "${OUT_DIR}"
if [[ -e "${APP_PATH}" && "${FORCE}" != "1" ]]; then
  if [[ "${DRY_RUN}" == "1" ]]; then
    log_warn "目标已存在：${APP_PATH}"
    log_warn "真实构建时会被整体替换 —— 需显式加 --force（dry-run 只提示，不算失败）"
  else
    die 1 "目标已存在：${APP_PATH}" \
      "加 --force 覆盖，或换个输出目录：--output /tmp/atfield-build"
  fi
fi


# ---------------- 2. dry-run 分支：只打印计划 ----------------
if [[ "${DRY_RUN}" == "1" ]]; then
  log_step "2/7 dry-run：以下动作不会真正执行"
  cat <<PLAN
  执行计划（目标 ${APP_PATH}）
   1) rm -rf "${APP_PATH}"
   2) mkdir -p "${CONTENTS}/MacOS" "${RES_DIR}"
   3) ditto "${ATFIELD_REPO_ROOT}/atfield" "${RES_DIR}/atfield"
      find "${RES_DIR}/atfield" -name __pycache__ -type d -prune -exec rm -rf {} +
      find "${RES_DIR}/atfield" -name '*.pyc' -type f -delete
   4) ditto "${ATFIELD_DAEMON_PY}" "${RES_DIR}/atfieldd.py"
      ditto "${ATFIELD_REQ_TXT}" "${RES_DIR}/requirements.txt"
   5) install -m 0755 "${ATFIELD_TEMPLATE_DIR}/atfield-launcher.sh" "${CONTENTS}/MacOS/${EXEC_NAME}"
   6) 渲染 Info.plist：@VERSION@=${VERSION} @MIN_MACOS@=${ATFIELD_MIN_MACOS} @BUNDLE_ID@=${ATFIELD_BUNDLE_ID}
      sed -e 's/@VERSION@/${VERSION}/g' ... "${ATFIELD_TEMPLATE_DIR}/Info.plist.in" > "${CONTENTS}/Info.plist"
      plutil -lint "${CONTENTS}/Info.plist"
   7) 写入 ${RES_DIR}/runtime.env（ATFIELD_PYTHON=${PYTHON_BIN}，版本 ${VERSION}）
   8) 自检：PlistBuddy 读回 CFBundleShortVersionString == ${VERSION}；启动器可执行；web 资源存在
      启动器设置 PYTHONDONTWRITEBYTECODE=1，避免运行期往包内写 __pycache__ 破坏代码签名
PLAN
  if [[ "${BUNDLE_RUNTIME}" == "1" ]]; then
    cat <<PLAN
   9) 内嵌运行时（--bundle-runtime）："${PYTHON_BIN}" -m venv "${RES_DIR}/runtime"
      "${RES_DIR}/runtime/bin/python3" -m pip install --disable-pip-version-check -r "${ATFIELD_REQ_TXT}"
      —— 该步骤需要联网（首次下载 psutil 轮子）
PLAN
  else
    cat <<PLAN
   9) 跳过内嵌运行时（未传 --bundle-runtime）：
      目标机器需自带 python3 并已安装 psutil，否则启动器会以退出码 6 明确提示。
PLAN
  fi
  cat <<PLAN
  后续命令（本脚本不执行）：
      bash packaging/sign_and_notarize.sh --target "${APP_PATH}"
      bash packaging/build_pkg.sh --app "${APP_PATH}"
PLAN
  log_step "dry-run 完成"
  printf '  校验全部通过，未写入任何文件。去掉 --dry-run 即可真正构建。\n\n'
  exit 0
fi

# ---------------- 3. 构建骨架 ----------------
log_step "2/7 准备 ${APP_NAME}.app 骨架"
mkdir -p -- "${OUT_DIR}"
safe_rm_rf "${APP_PATH}"
mkdir -p -- "${CONTENTS}/MacOS" "${RES_DIR}"
chmod 755 "${APP_PATH}" "${CONTENTS}" "${RES_DIR}"
log_ok "已创建 ${CONTENTS}/{MacOS,Resources}"

log_step "3/7 复制 Python 源码与 Web 静态资源"
ditto --norsrc "${ATFIELD_REPO_ROOT}/atfield" "${RES_DIR}/atfield" \
  || die 3 "复制 atfield/ 失败" "检查磁盘空间与文件权限：du -sh \"${ATFIELD_REPO_ROOT}/atfield\""
find "${RES_DIR}/atfield" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
find "${RES_DIR}/atfield" -name '*.pyc' -type f -delete 2>/dev/null || true
ditto --norsrc "${ATFIELD_DAEMON_PY}" "${RES_DIR}/atfieldd.py"
if [[ -f "${ATFIELD_REQ_TXT}" ]]; then
  ditto --norsrc "${ATFIELD_REQ_TXT}" "${RES_DIR}/requirements.txt"
fi
for asset in index.html app.js style.css; do
  [[ -f "${RES_DIR}/atfield/web/${asset}" ]] || die 3 "静态资源缺失：atfield/web/${asset}" \
    "源码不完整，先在仓库根目录确认 atfield/web/ 下三件套齐全。"
done
log_ok "源码 + 静态资源已就位：$(find "${RES_DIR}/atfield" -type f | wc -l | tr -d ' ') 个文件"

log_step "4/7 安装启动器"
install -m 0755 "${ATFIELD_TEMPLATE_DIR}/atfield-launcher.sh" "${CONTENTS}/MacOS/${EXEC_NAME}" \
  || die 3 "安装启动器失败：${CONTENTS}/MacOS/${EXEC_NAME}"
log_ok "${CONTENTS}/MacOS/${EXEC_NAME} (0755)"

# ---------------- 4. 渲染 Info.plist ----------------
log_step "5/7 渲染 Info.plist"
sed -e "s|@APP_NAME@|${APP_NAME}|g" \
    -e "s|@BUNDLE_ID@|${ATFIELD_BUNDLE_ID}|g" \
    -e "s|@EXECUTABLE@|${EXEC_NAME}|g" \
    -e "s|@VERSION@|${VERSION}|g" \
    -e "s|@MIN_MACOS@|${ATFIELD_MIN_MACOS}|g" \
    "${ATFIELD_TEMPLATE_DIR}/Info.plist.in" >"${CONTENTS}/Info.plist" \
  || die 3 "渲染 Info.plist 失败"
plutil -lint "${CONTENTS}/Info.plist" >/dev/null \
  || die 5 "Info.plist 语法不合法：${CONTENTS}/Info.plist" \
         "用 plutil -lint \"${CONTENTS}/Info.plist\" 查看具体行号。"
chmod 644 "${CONTENTS}/Info.plist"
log_ok "Info.plist：${ATFIELD_BUNDLE_ID} v${VERSION}，LSMinimumSystemVersion=${ATFIELD_MIN_MACOS}"

# ---------------- 5. runtime.env ----------------
log_step "6/7 写入运行时记录"
{
  printf '# 由 packaging/build_app.sh 生成于 %s\n' "$(mtime_now)"
  printf '# 启动器（Contents/MacOS/%s）按以下顺序找解释器：\n' "${EXEC_NAME}"
  printf '#   $ATFIELD_PYTHON > Resources/runtime/bin/python3 > 本文件 ATFIELD_PYTHON > 系统 python3\n'
  printf 'ATFIELD_VERSION=%s\n' "${VERSION}"
  printf 'ATFIELD_PYTHON=%s\n' "${PYTHON_BIN}"
  printf 'ATFIELD_BUILT_AT=%s\n' "$(mtime_now)"
  printf 'ATFIELD_HOST_ARCH=%s\n' "$(uname -m)"
} >"${RES_DIR}/runtime.env"
chmod 644 "${RES_DIR}/runtime.env"
log_ok "${RES_DIR}/runtime.env → ATFIELD_PYTHON=${PYTHON_BIN}"

if [[ "${BUNDLE_RUNTIME}" == "1" ]]; then
  log_info "创建内嵌运行时（venv）…"
  # --copies：venv 默认把 bin/python3 建成指向宿主解释器的符号链接，
  # 而 codesign 拒绝「符号链接指向包外」的 .app（invalid destination for symbolic link）。
  "${PYTHON_BIN}" -m venv --copies "${RES_DIR}/runtime" \
    || die 3 "创建 venv 失败：${RES_DIR}/runtime" \
           "确认 ${PYTHON_BIN} 带 venv 模块（系统 /usr/bin/python3 需先 xcode-select --install）。"
  "${RES_DIR}/runtime/bin/python3" -m pip install --disable-pip-version-check -q \
      --upgrade pip >/dev/null 2>&1 || log_warn "pip 自升级失败（不影响后续安装）"
  # psutil 是硬依赖；PyYAML 是「MDM 下发的 config.yaml 能被读取」的前提
  # （atfield/config.py 在 import yaml 失败时会静默忽略配置文件）。
  if ! "${RES_DIR}/runtime/bin/python3" -m pip install --disable-pip-version-check -q \
        -r "${ATFIELD_REQ_TXT}" pyyaml; then
    die 3 "内嵌依赖安装失败（psutil / pyyaml）" \
      "该步骤需要联网；检查网络/代理，或改用不加 --bundle-runtime 的构建。"
  fi
  # 兜底：把仍指向包外的符号链接就地解引用成真实文件，避免签名校验报
  # invalid destination for symbolic link in bundle。
  while IFS= read -r link; do
    target="$(readlink -f "${link}" 2>/dev/null || true)"
    if [[ -n "${target}" && -e "${target}" && "${target}" != "${RES_DIR}/runtime/"* ]]; then
      cp -Lf "${target}" "${link}.tmp" && mv -f "${link}.tmp" "${link}"
      chmod 755 "${link}" 2>/dev/null || true
      log_info "解引用包外符号链接：${link##*/runtime/}"
    fi
  done < <(find "${RES_DIR}/runtime" -type l)
  "${RES_DIR}/runtime/bin/python3" -c 'import psutil, yaml' \
    || die 3 "内嵌运行时自检失败：无法 import psutil / yaml"
  # 清掉 pip 装依赖时产生的字节码：包越小越好，也避免签名前就有冗余文件
  find "${RES_DIR}/runtime" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
  find "${RES_DIR}/runtime" -name '*.pyc' -type f -delete 2>/dev/null || true
  log_ok "内嵌运行时完成：$("${RES_DIR}/runtime/bin/python3" -c 'import sys;print(sys.version.split()[0])')"
fi

# ---------------- 6. 自检 ----------------
log_step "7/7 构建自检"
problems=0
plist_ver="$(plist_get "${CONTENTS}/Info.plist" "CFBundleShortVersionString")"
if [[ "${plist_ver}" == "${VERSION}" ]]; then
  log_ok "CFBundleShortVersionString = ${plist_ver}"
else
  log_err "版本号不一致：Info.plist=${plist_ver:-<空>} vs 真源=${VERSION}"
  problems=$((problems + 1))
fi
for key in CFBundleIdentifier CFBundleExecutable LSUIElement NSHighResolutionCapable; do
  val="$(plist_get "${CONTENTS}/Info.plist" "${key}")"
  [[ -n "${val}" ]] || { log_err "Info.plist 缺少键 ${key}"; problems=$((problems + 1)); }
done
[[ "$(plist_get "${CONTENTS}/Info.plist" "CFBundleIdentifier")" == "${ATFIELD_BUNDLE_ID}" ]] \
  || { log_err "CFBundleIdentifier 不是 ${ATFIELD_BUNDLE_ID}"; problems=$((problems + 1)); }
[[ -x "${CONTENTS}/MacOS/${EXEC_NAME}" ]] \
  || { log_err "启动器不可执行"; problems=$((problems + 1)); }
bash -n "${CONTENTS}/MacOS/${EXEC_NAME}" \
  || { log_err "启动器语法检查未通过"; problems=$((problems + 1)); }
[[ -f "${RES_DIR}/atfield/web/index.html" ]] \
  || { log_err "缺少 Resources/atfield/web/index.html"; problems=$((problems + 1)); }
[[ -f "${RES_DIR}/atfieldd.py" ]] \
  || { log_err "缺少 Resources/atfieldd.py"; problems=$((problems + 1)); }

if ! "${PYTHON_BIN}" -c 'import psutil' >/dev/null 2>&1; then
  log_warn "打包解释器 ${PYTHON_BIN} 当前缺少 psutil —— 本包在这台机器上启动会被拦下（退出码 6）。"
  log_warn "修复：\"${PYTHON_BIN}\" -m pip install --user psutil   或重建：--bundle-runtime"
fi

if [[ "${problems}" -ne 0 ]]; then
  die 5 "自检失败（${problems} 项）" "产物保留在 ${APP_PATH} 便于排查；修复后加 --force 重跑。"
fi

SIZE="$(du -sh "${APP_PATH}" | awk '{print $1}')"
log_step "构建完成"
printf '  应用包  %s  (%s)\n' "${APP_PATH}" "${SIZE}"
printf '  标识    %s\n' "${ATFIELD_BUNDLE_ID}"
printf '  版本    %s\n' "${VERSION}"
printf '  启动器  %s/Contents/MacOS/%s\n' "${APP_PATH}" "${EXEC_NAME}"
print_banner_header "下一步"
printf '  1) 直接试跑版本自检\n     "%s" --version\n' "${CONTENTS}/MacOS/${EXEC_NAME}"
printf '  2) 签名（无证书会自动降级为 ad-hoc）\n     bash "%s/sign_and_notarize.sh" --target "%s"\n' "${ATFIELD_PACKAGING_DIR}" "${APP_PATH}"
printf '  3) 打 pkg\n     bash "%s/build_pkg.sh" --app "%s"\n\n' "${ATFIELD_PACKAGING_DIR}" "${APP_PATH}"
