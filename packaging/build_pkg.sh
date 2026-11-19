#!/bin/bash
# packaging/build_pkg.sh —— 把 心之壁.app 打成可分发的 心之壁-<version>.pkg
#
# 流程：pkgbuild（组件包，payload = /Applications/心之壁.app）
#       → 渲染 distribution.xml（允许 currentUserDomain、min 13.0）
#       → productbuild（产品包，可带 Developer ID Installer 签名）
#
# 退出码：0 成功 / 1 参数错误 / 2 输入缺失（.app 不存在）/ 3 版本解析或打包失败
#         4 缺少工具（pkgbuild/productbuild/security）/ 5 产物自检未通过
set -euo pipefail

SELF_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
. "${SELF_DIR}/lib/common.sh"

EXEC_NAME="atfield-launcher"
CLI_NAME="atfield"

OUT_DIR="${ATFIELD_DIST_DIR}"
APP_PATH=""
INSTALLER_IDENTITY=""
DRY_RUN=0
FORCE=0

usage() {
  cat <<'USAGE'
build_pkg.sh —— 生成 心之壁-<version>.pkg（含 postinstall、distribution.xml）

用法:
  bash packaging/build_pkg.sh [选项]

选项:
  --app PATH                 待打包的 .app（默认 packaging/dist/心之壁.app）
  --output DIR               输出目录（默认 packaging/dist）
  --installer-identity NAME  Developer ID Installer 证书名，用于 productbuild --sign
                             （省略则生成未签名的 .pkg，可在分发前再签）
  --dry-run, -n              只校验并打印命令，不生成任何文件
  --force, -f                覆盖已存在的同名 .pkg
  --version                  打印版本号后退出（从 atfield/__init__.py 读取）
  -h, --help                 显示本帮助

安装后行为（postinstall）:
  · 建立 /usr/local/bin/atfield -> /Applications/心之壁.app/Contents/MacOS/atfield-launcher
  · 把每个用户已存在的 ~/.atfield 收权为 700（目录）/ 600（文件）并纠正属主
  · 全过程写 /var/log/atfield-install.log

示例:
  bash packaging/build_pkg.sh --dry-run
  bash packaging/build_pkg.sh --app packaging/dist/心之壁.app --force
  bash packaging/build_pkg.sh --installer-identity "Developer ID Installer: Kurisu Lab (TEAMID)"

退出码:
  0  成功
  1  参数错误（未知参数、证书名不存在、输出目录越界等）
  2  输入缺失（.app 或其 Info.plist 不存在）
  3  版本解析失败 / pkgbuild 或 productbuild 执行失败
  4  缺少必需工具（pkgbuild、productbuild、security、plutil、ditto）
  5  产物自检未通过（pkg 不可读、缺 postinstall、版本不一致）
USAGE
}

# ---------------- 参数解析 ----------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --app)
      [[ $# -ge 2 && -n "${2:-}" && "${2}" != --* ]] || die 1 "--app 需要一个 .app 路径" \
        "先构建：bash packaging/build_app.sh"
      APP_PATH="$2"; shift
      ;;
    --app=*)
      APP_PATH="${1#*=}"
      [[ -n "${APP_PATH}" ]] || die 1 "--app= 后面不能为空"
      ;;
    --output)
      [[ $# -ge 2 && -n "${2:-}" && "${2}" != --* ]] || die 1 "--output 需要一个目录参数"
      OUT_DIR="$2"; shift
      ;;
    --output=*)
      OUT_DIR="${1#*=}"
      [[ -n "${OUT_DIR}" ]] || die 1 "--output= 后面不能为空"
      ;;
    --installer-identity)
      [[ $# -ge 2 && -n "${2:-}" && "${2}" != --* ]] || die 1 "--installer-identity 需要一个证书名"
      INSTALLER_IDENTITY="$2"; shift
      ;;
    --installer-identity=*)
      INSTALLER_IDENTITY="${1#*=}"
      [[ -n "${INSTALLER_IDENTITY}" ]] || die 1 "--installer-identity= 后面不能为空"
      ;;
    --dry-run|-n) DRY_RUN=1 ;;
    --force|-f)   FORCE=1 ;;
    --version)
      printf '心之壁 %s\n' "$(atfield_version)"
      exit 0
      ;;
    -h|--help) usage; exit 0 ;;
    *)
      log_err "未知参数：$1"
      printf '\n' >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done

[[ -n "${APP_PATH}" ]] || APP_PATH="${ATFIELD_DIST_DIR}/心之壁.app"
case "${APP_PATH}" in
  /*) : ;;
  *)  APP_PATH="$(cd -- "$(dirname -- "${APP_PATH}")" 2>/dev/null && pwd -P)/$(basename -- "${APP_PATH}")" ;;
esac

if [[ "${DRY_RUN}" == "1" ]]; then
  print_banner_header "心之壁 pkg 构建（dry-run，不写文件）"
else
  print_banner_header "心之壁 pkg 构建"
fi

# ---------------- 1. 前置校验 ----------------
log_step "1/6 前置校验"
need_cmd pkgbuild
need_cmd productbuild
need_cmd security
need_cmd plutil
need_cmd ditto
log_ok "Xcode 工具链：$(xcode-select -p 2>/dev/null || echo '未找到，可能只有 Command Line Tools 包')"

need_dir "${APP_PATH}" "待打包的应用（${APP_PATH}）"
need_file "${APP_PATH}/Contents/Info.plist" "应用 Info.plist"
need_file "${APP_PATH}/Contents/MacOS/${EXEC_NAME}" "应用启动器"
need_file "${ATFIELD_TEMPLATE_DIR}/distribution.xml.in" "distribution.xml 模板"
need_file "${ATFIELD_TEMPLATE_DIR}/postinstall.sh" "postinstall 模板"

VERSION="$(atfield_version)"
log_ok "版本号（真源 atfield/__init__.py）：${VERSION}"

APP_NAME="$(basename -- "${APP_PATH}" .app)"
[[ -n "${APP_NAME}" ]] || die 2 "无法从路径推断应用名：${APP_PATH}"
APP_PLIST="${APP_PATH}/Contents/Info.plist"
plutil -lint "${APP_PLIST}" >/dev/null || die 2 "Info.plist 语法不合法：${APP_PLIST}" \
  "重新构建应用包：bash packaging/build_app.sh --force"

APP_VER="$(plist_get "${APP_PLIST}" "CFBundleShortVersionString")"
APP_BID="$(plist_get "${APP_PLIST}" "CFBundleIdentifier")"
if [[ "${APP_VER}" != "${VERSION}" ]]; then
  die 3 "版本不一致：.app 内 Info.plist=${APP_VER:-<空>} vs atfield/__init__.py=${VERSION}" \
    "应用包陈旧，请重建：bash packaging/build_app.sh --force"
fi
[[ -n "${APP_BID}" ]] || die 3 "Info.plist 缺少 CFBundleIdentifier" "重建应用包后重试。"
log_ok "应用：${APP_PATH}（${APP_BID} v${APP_VER}）"

assert_writable_target "${OUT_DIR}" "--output"
FINAL_PKG="${OUT_DIR}/${APP_NAME}-${VERSION}.pkg"
if [[ -e "${FINAL_PKG}" && "${FORCE}" != "1" ]]; then
  die 1 "目标已存在：${FINAL_PKG}" \
    "加 --force 覆盖，或 --output /tmp/atfield-pkg"
fi

# 安装证书校验（可选）
if [[ -n "${INSTALLER_IDENTITY}" ]]; then
  id_list="$(security find-identity -v -p basic 2>/dev/null || true)"
  if printf '%s\n' "${id_list}" | grep -Fq -- "${INSTALLER_IDENTITY}"; then
    log_ok "Installer 证书就绪：${INSTALLER_IDENTITY}"
  else
    log_err "未找到指定的 Installer 证书：${INSTALLER_IDENTITY}"
    printf '\n当前可用签名身份：\n' >&2
    printf '%s\n' "${id_list:-  （无）}" | sed 's/^/  /' >&2
    die 1 "证书校验失败" \
      "Installer 证书需为「Developer ID Installer」类型，可在 Xcode → Settings → Accounts → Manage Certificates 申请。" \
      "或用 ad-hoc 分发：省略 --installer-identity 生成未签名 pkg。"
  fi
else
  log_warn "未指定 --installer-identity：将生成未签名 pkg（可安装，但 Gatekeeper 会提示未经认证的开发者）"
  log_warn "分发前建议先签：bash packaging/sign_and_notarize.sh --pkg \"${FINAL_PKG}\""
fi

BUILD_DIR="${OUT_DIR}/build"
PKG_ROOT="${BUILD_DIR}/pkgroot"
SCRIPTS_DIR="${BUILD_DIR}/scripts"
COMP_PKG="${BUILD_DIR}/${APP_NAME}-${VERSION}-component.pkg"
DIST_XML="${BUILD_DIR}/distribution.xml"

# ---------------- 2. dry-run ----------------
if [[ "${DRY_RUN}" == "1" ]]; then
  log_step "2/6 dry-run：以下动作不会真正执行"
  cat <<PLAN
  执行计划（产物 ${FINAL_PKG}）
   1) rm -rf "${BUILD_DIR}"
      mkdir -p "${PKG_ROOT}/Applications" "${SCRIPTS_DIR}"
   2) ditto --norsrc "${APP_PATH}" "${PKG_ROOT}/Applications/${APP_NAME}.app"
      —— payload 安装路径即 /Applications/${APP_NAME}.app
   3) 渲染 postinstall（@APP_NAME@=${APP_NAME} @EXECUTABLE@=${EXEC_NAME} @CLI_NAME@=${CLI_NAME}）
      install -m 0755 "${ATFIELD_TEMPLATE_DIR}/postinstall.sh" "${SCRIPTS_DIR}/postinstall"
      bash -n "${SCRIPTS_DIR}/postinstall"
   4) pkgbuild --root "${PKG_ROOT}" --identifier ${APP_BID} --version ${VERSION} \\
            --scripts "${SCRIPTS_DIR}" --install-location / --ownership recommended \\
            "${COMP_PKG}"
   5) 渲染 distribution.xml（minOS ${ATFIELD_MIN_MACOS}、enable_currentUserHome=true）
      productbuild --distribution "${DIST_XML}" --package-path "${BUILD_DIR}" \\
            [--sign "${INSTALLER_IDENTITY:-<未签名>}"] "${FINAL_PKG}"
   6) 自检：pkgutil --payload-files 列出 payload；pkgutil --check-signature（若签名）；
      sha256 摘要 + 体积
PLAN
  log_step "dry-run 完成"
  printf '  校验全部通过，未写入任何文件。去掉 --dry-run 即可生成 pkg。\n\n'
  exit 0
fi

# ---------------- 3. 构建 ----------------
log_step "2/6 准备 payload"
mkdir -p -- "${OUT_DIR}"
safe_rm_rf "${BUILD_DIR}"
mkdir -p -- "${PKG_ROOT}/Applications" "${SCRIPTS_DIR}"
ditto --norsrc "${APP_PATH}" "${PKG_ROOT}/Applications/${APP_NAME}.app" \
  || die 3 "复制 .app 到 payload 失败" "检查 ${APP_PATH} 是否被占用/权限是否可读。"
# 去掉派生数据，避免 payload 里出现 __pycache__（会让包变大且影响签名一致性）
find "${PKG_ROOT}/Applications/${APP_NAME}.app" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
find "${PKG_ROOT}/Applications/${APP_NAME}.app" -name '*.pyc' -type f -delete 2>/dev/null || true
log_ok "payload: /Applications/${APP_NAME}.app ($(du -sh "${PKG_ROOT}/Applications/${APP_NAME}.app" | awk '{print $1}'))"

log_step "3/6 渲染 postinstall"
sed -e "s|@APP_NAME@|${APP_NAME}|g" \
    -e "s|@EXECUTABLE@|${EXEC_NAME}|g" \
    -e "s|@CLI_NAME@|${CLI_NAME}|g" \
    "${ATFIELD_TEMPLATE_DIR}/postinstall.sh" >"${SCRIPTS_DIR}/postinstall" \
  || die 3 "渲染 postinstall 失败"
chmod 755 "${SCRIPTS_DIR}/postinstall"
bash -n "${SCRIPTS_DIR}/postinstall" \
  || die 3 "postinstall 语法检查未通过：${SCRIPTS_DIR}/postinstall"
log_ok "postinstall 就绪（符号链接 /usr/local/bin/${CLI_NAME} + ~/.atfield 收权 700）"

log_step "4/6 pkgbuild（组件包）"
pkgbuild --root "${PKG_ROOT}" \
         --identifier "${APP_BID}" \
         --version "${VERSION}" \
         --scripts "${SCRIPTS_DIR}" \
         --install-location "/" \
         --ownership recommended \
         "${COMP_PKG}" \
  || die 3 "pkgbuild 失败" \
         "常见原因：payload 路径不可读、标识符非法、磁盘空间不足。" \
         "手工复现：pkgbuild --root \"${PKG_ROOT}\" --identifier \"${APP_BID}\" --version \"${VERSION}\" --install-location / /tmp/test.pkg"
log_ok "组件包：${COMP_PKG} ($(du -h "${COMP_PKG}" | awk '{print $1}'))"

log_step "5/6 productbuild（产品包 + distribution.xml）"
sed -e "s|@APP_NAME@|${APP_NAME}|g" \
    -e "s|@BUNDLE_ID@|${APP_BID}|g" \
    -e "s|@VERSION@|${VERSION}|g" \
    -e "s|@MIN_MACOS@|${ATFIELD_MIN_MACOS}|g" \
    -e "s|@COMPONENT_PKG@|$(basename -- "${COMP_PKG}")|g" \
    "${ATFIELD_TEMPLATE_DIR}/distribution.xml.in" >"${DIST_XML}" \
  || die 3 "渲染 distribution.xml 失败"
# 注意：distribution.xml 是 Installer Distribution XML（根节点 installer-gui-script），
# 不是 plist——拿 plutil -lint 去查必然报「unknown tag」，那是假警报。
# 这里只做两件真事：XML 结构是否完整、根节点对不对；schema 由 productbuild 自己把关。
if command -v xmllint >/dev/null 2>&1; then
  xmllint --noout "${DIST_XML}" 2>/dev/null \
    || log_warn "distribution.xml XML 结构有问题（继续，productbuild 会给出具体错误）"
  grep -q '<installer-gui-script' "${DIST_XML}" \
    || log_warn "distribution.xml 根节点不是 installer-gui-script，productbuild 可能拒绝"
else
  log_info "没有 xmllint，跳过 distribution.xml 预检（productbuild 会自己校验）"
fi

pb_args=(--distribution "${DIST_XML}" --package-path "${BUILD_DIR}")
if [[ -n "${INSTALLER_IDENTITY}" ]]; then
  pb_args+=(--sign "${INSTALLER_IDENTITY}")
fi
productbuild "${pb_args[@]}" "${FINAL_PKG}" \
  || die 3 "productbuild 失败" \
         "若报签名错误：确认证书是 Developer ID Installer 且在钥匙串中可用（security find-identity -v -p basic）。" \
         "若报 distribution 错误：检查 \"${DIST_XML}\" 里的 pkg-ref 文件名与 --package-path 是否一致。"
log_ok "产品包：${FINAL_PKG} ($(du -h "${FINAL_PKG}" | awk '{print $1}'))"

# ---------------- 4. 自检 ----------------
log_step "6/6 产物自检"
problems=0
[[ -s "${FINAL_PKG}" ]] || { log_err "产物为空：${FINAL_PKG}"; problems=$((problems + 1)); }

payload_list="$(pkgutil --payload-files "${FINAL_PKG}" 2>/dev/null || true)"
if printf '%s\n' "${payload_list}" | grep -Fq "Applications/${APP_NAME}.app/Contents/Info.plist"; then
  log_ok "payload 含 Applications/${APP_NAME}.app（$(printf '%s\n' "${payload_list}" | wc -l | tr -d ' ') 项）"
else
  log_err "payload 中找不到 ${APP_NAME}.app"
  problems=$((problems + 1))
fi

# postinstall 是否进了包：用 pkgutil --expand 检查脚本目录
EXTRACT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/atfield-pkgcheck.XXXXXX")"
if pkgutil --expand "${FINAL_PKG}" "${EXTRACT_DIR}/expanded" 2>/dev/null; then
  if find "${EXTRACT_DIR}/expanded" -name 'postinstall' -type f | grep -q .; then
    log_ok "包内含 postinstall 脚本"
  else
    log_err "包内未找到 postinstall 脚本"
    problems=$((problems + 1))
  fi
  if grep -q "<os-version min=\"${ATFIELD_MIN_MACOS}\"" "${EXTRACT_DIR}/expanded/Distribution" 2>/dev/null; then
    log_ok "distribution 最低系统版本 = ${ATFIELD_MIN_MACOS}"
  else
    log_warn "distribution 中未检出 minOS=${ATFIELD_MIN_MACOS}（继续，安装仍会按 pkgbuild 约束执行）"
  fi
else
  log_warn "pkgutil --expand 展开失败，跳过脚本内容自检"
fi
rm -rf -- "${EXTRACT_DIR}"

sig_report="$(pkgutil --check-signature "${FINAL_PKG}" 2>&1 || true)"
if printf '%s\n' "${sig_report}" | grep -q "Status: signed"; then
  log_ok "pkg 已签名：$(printf '%s\n' "${sig_report}" | grep -m1 'Developer ID Installer' || echo 'see pkgutil --check-signature')"
else
  log_warn "pkg 未签名 —— 分发到其他机器时 Gatekeeper 会提示，建议先执行 sign_and_notarize.sh --pkg"
fi

if [[ "${problems}" -ne 0 ]]; then
  die 5 "自检失败（${problems} 项）" "产物保留在 ${FINAL_PKG} 便于排查。"
fi

SHA="$(shasum -a 256 "${FINAL_PKG}" | awk '{print $1}')"
log_step "完成"
printf '  pkg     %s (%s)\n' "${FINAL_PKG}" "$(du -h "${FINAL_PKG}" | awk '{print $1}')"
printf '  标识    %s\n' "${APP_BID}"
printf '  版本    %s\n' "${VERSION}"
printf '  sha256  %s\n' "${SHA}"
print_banner_header "下一步"
printf '  1) 签名 + 公证（无证书会降级 ad-hoc）\n     bash "%s/sign_and_notarize.sh" --pkg "%s"\n' "${ATFIELD_PACKAGING_DIR}" "${FINAL_PKG}"
printf '  2) 本机试装（会真的写入 /Applications）\n     sudo installer -pkg "%s" -target /\n' "${FINAL_PKG}"
printf '  3) 静默分发\n     sudo installer -pkg "%s" -target / -verboseR\n\n' "${FINAL_PKG}"
