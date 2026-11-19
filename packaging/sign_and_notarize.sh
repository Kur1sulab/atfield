#!/bin/bash
# packaging/sign_and_notarize.sh —— 代码签名 + 公证（notarization）+ 装订（staple）
#
# 行为约定（重要）：
#   · 先用 security find-identity -v -p codesigning 探测 Developer ID Application 证书
#   · 有证书 → codesign --deep --options runtime --timestamp + notarytool submit --wait + stapler staple
#   · 无证书 → 打印「未找到 Developer ID Application 证书」，降级为 ad-hoc（codesign -s -）继续，
#              结果明确标注「仅供本机测试」，退出码仍为 0（附 WARNING）
#
# 退出码：0 成功（含 ad-hoc 降级）/ 1 参数错误或缺证书（显式指定时）/ 2 目标不存在
#         4 缺少工具 / 5 缺少公证凭据 / 6 公证未通过 / 7 签名或 staple 校验失败
set -euo pipefail

SELF_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
. "${SELF_DIR}/lib/common.sh"

TARGET_APP=""
TARGET_PKG=""
IDENTITY=""
INSTALLER_IDENTITY=""
APPLE_ID="${APPLE_ID:-}"
TEAM_ID="${TEAM_ID:-}"
APP_PASSWORD="${APPLE_APP_PASSWORD:-}"
DRY_RUN=0
SKIP_NOTARIZE=0
VERIFY_ONLY=0
ADHOC=0

usage() {
  cat <<'USAGE'
sign_and_notarize.sh —— 心之壁 应用/安装包签名、公证、装订

用法:
  bash packaging/sign_and_notarize.sh [选项]

目标（至少给一个；都不给时默认 dist/心之壁.app）:
  --target PATH            要签名的 .app（默认 packaging/dist/<应用名>.app）
  --pkg PATH               要签名/公证的 .pkg（需要 Developer ID Installer 证书）

签名身份:
  --identity NAME          Developer ID Application 证书名（默认自动从钥匙串挑第一个）
  --installer-identity NAME Developer ID Installer 证书名（给 --pkg 用）

公证凭据（也可用环境变量 APPLE_ID / TEAM_ID / APPLE_APP_PASSWORD）:
  --apple-id EMAIL         Apple ID
  --team-id TEAMID         团队 ID
  --password PASS          App 专用密码（app-specific password，不是账号密码）

其它:
  --skip-notarize          只签名，不提交公证（离线环境 / 临时构建）
  --verify-only            只做验签（codesign --verify --deep --strict），不签名、不需要证书
  --dry-run, -n            只做探测与打印命令，不签名不提交
  --version                打印版本号后退出
  -h, --help               显示本帮助

无证书时会发生什么:
  脚本打印「未找到 Developer ID Application 证书」，随后用 codesign -s - 做 ad-hoc 签名，
  产物仅供本机测试（Gatekeeper 在别的机器上仍会拦截，notarytool 也不会受理）。
  退出码依然是 0，但输出里带 WARNING —— 便于 CI 里区分「签名成功」与「仅本机可用」。

示例:
  bash packaging/sign_and_notarize.sh --dry-run
  bash packaging/sign_and_notarize.sh                       # 自动挑证书；没证书就 ad-hoc
  bash packaging/sign_and_notarize.sh --target packaging/dist/心之壁.app \
       --apple-id me@example.com --team-id TEAMID1234 --password "abcd-efgh-ijkl-mnop"
  bash packaging/sign_and_notarize.sh --pkg packaging/dist/心之壁-<version>.pkg \
       --installer-identity "Developer ID Installer: Kurisu Lab (TEAMID1234)"

退出码:
  0 成功（含 ad-hoc 降级；降级时带 WARNING）
  1 参数错误；或 --identity 指定的证书在钥匙串里不存在
  2 目标 .app/.pkg 不存在
  4 缺少必需工具（codesign / security / xcrun / ditto / spctl）
  5 需要公证但缺少凭据（APPLE_ID / TEAM_ID / APPLE_APP_PASSWORD）
  6 notarytool 提交后状态不是 Accepted
  7 codesign --verify 或 stapler validate 未通过
USAGE
}

# ---------------- 参数解析 ----------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      [[ $# -ge 2 && -n "${2:-}" && "${2}" != --* ]] || die 1 "--target 需要一个 .app 路径"
      TARGET_APP="$2"; shift ;;
    --target=*) TARGET_APP="${1#*=}"; [[ -n "${TARGET_APP}" ]] || die 1 "--target= 不能为空" ;;
    --pkg)
      [[ $# -ge 2 && -n "${2:-}" && "${2}" != --* ]] || die 1 "--pkg 需要一个 .pkg 路径"
      TARGET_PKG="$2"; shift ;;
    --pkg=*) TARGET_PKG="${1#*=}"; [[ -n "${TARGET_PKG}" ]] || die 1 "--pkg= 不能为空" ;;
    --identity)
      [[ $# -ge 2 && -n "${2:-}" && "${2}" != --* ]] || die 1 "--identity 需要一个证书名"
      IDENTITY="$2"; shift ;;
    --identity=*) IDENTITY="${1#*=}"; [[ -n "${IDENTITY}" ]] || die 1 "--identity= 不能为空" ;;
    --installer-identity)
      [[ $# -ge 2 && -n "${2:-}" && "${2}" != --* ]] || die 1 "--installer-identity 需要一个证书名"
      INSTALLER_IDENTITY="$2"; shift ;;
    --installer-identity=*) INSTALLER_IDENTITY="${1#*=}"; [[ -n "${INSTALLER_IDENTITY}" ]] || die 1 "--installer-identity= 不能为空" ;;
    --apple-id)
      [[ $# -ge 2 && -n "${2:-}" && "${2}" != --* ]] || die 1 "--apple-id 需要一个邮箱"
      APPLE_ID="$2"; shift ;;
    --apple-id=*) APPLE_ID="${1#*=}" ;;
    --team-id)
      [[ $# -ge 2 && -n "${2:-}" && "${2}" != --* ]] || die 1 "--team-id 需要一个团队 ID"
      TEAM_ID="$2"; shift ;;
    --team-id=*) TEAM_ID="${1#*=}" ;;
    --password)
      [[ $# -ge 2 && -n "${2:-}" ]] || die 1 "--password 需要一个 App 专用密码" \
        "可在 appleid.apple.com → 登录与安全 → App 专用密码 生成。"
      APP_PASSWORD="$2"; shift ;;
    --password=*) APP_PASSWORD="${1#*=}" ;;
    --skip-notarize) SKIP_NOTARIZE=1 ;;
    --verify-only) VERIFY_ONLY=1 ;;
    --dry-run|-n) DRY_RUN=1 ;;
    --version) printf '心之壁 %s\n' "$(atfield_version)"; exit 0 ;;
    -h|--help) usage; exit 0 ;;
    *)
      log_err "未知参数：$1"
      printf '\n' >&2
      usage >&2
      exit 1 ;;
  esac
  shift
done

# 默认目标
if [[ -z "${TARGET_APP}" && -z "${TARGET_PKG}" ]]; then
  TARGET_APP="${ATFIELD_DIST_DIR}/${ATFIELD_APP_NAME_DEFAULT}.app"
elif [[ -z "${TARGET_APP}" && -n "${TARGET_PKG}" ]]; then
  TARGET_APP=""
fi

# --verify-only：只验签，不碰证书、不写任何文件
if [[ "${VERIFY_ONLY}" == "1" ]]; then
  [[ -n "${TARGET_APP}" ]] || die 1 "--verify-only 需要 --target 指定一个 .app"
  [[ -e "${TARGET_APP}" ]] || die 2 "目标不存在：${TARGET_APP}"
  print_banner_header "心之壁 验签（只验证，不签名）"
  if codesign --verify --deep --strict --verbose=2 "${TARGET_APP}" 2>&1; then
    log_ok "签名有效性校验通过：${TARGET_APP}"
    printf '\n'
    codesign -dv "${TARGET_APP}" 2>&1 | sed -n '1,12p'
    exit 0
  fi
  log_err "签名校验失败：${TARGET_APP}"
  exit 7
fi

if [[ "${DRY_RUN}" == "1" ]]; then
  print_banner_header "心之壁 签名与公证（dry-run，不执行签名）"
else
  print_banner_header "心之壁 签名与公证"
fi

# ---------------- 1. 前置校验 ----------------
log_step "1/6 前置校验"
need_cmd codesign
need_cmd security
need_cmd spctl
need_cmd ditto
need_cmd xcrun

if [[ -n "${TARGET_APP}" ]]; then
  need_dir "${TARGET_APP}" "待签名 .app"
  need_file "${TARGET_APP}/Contents/Info.plist" "应用 Info.plist"
  log_ok "目标 .app：${TARGET_APP}"
fi
if [[ -n "${TARGET_PKG}" ]]; then
  need_file "${TARGET_PKG}" "待签名 .pkg"
  case "${TARGET_PKG}" in
    /*) : ;;
    *) TARGET_PKG="$(cd -- "$(dirname -- "${TARGET_PKG}")" && pwd -P)/$(basename -- "${TARGET_PKG}")" ;;
  esac
  log_ok "目标 .pkg：${TARGET_PKG}"
fi

VERSION="$(atfield_version)"
log_ok "版本号（真源 atfield/__init__.py）：${VERSION}"

# ---------------- 2. 探测签名身份 ----------------
log_step "2/6 探测签名身份"
id_output="$(security find-identity -v -p codesigning 2>&1 || true)"
printf '%s\n' "${id_output}" | sed 's/^/        /'

dev_id="$(printf '%s\n' "${id_output}" \
  | grep -o '"Developer ID Application: [^"]*"' | tr -d '"' | head -n 1 || true)"
installer_auto="$(security find-identity -v -p basic 2>/dev/null \
  | grep -o '"Developer ID Installer: [^"]*"' | tr -d '"' | head -n 1 || true)"

if [[ -n "${IDENTITY}" ]]; then
  if ! printf '%s\n' "${id_output}" | grep -Fq -- "${IDENTITY}"; then
    log_err "未找到 Developer ID Application 证书：${IDENTITY}"
    printf '\n当前可用 codesigning 身份：\n%s\n\n' "${id_output:-  （无）}" >&2
    die 1 "显式指定的证书不存在于钥匙串" \
      "用 security find-identity -v -p codesigning 确认证书名（含团队后缀）。" \
      "若确实没有证书，去掉 --identity 让脚本自动降级为 ad-hoc 签名。" \
      "申请证书：Xcode → Settings → Accounts → Manage Certificates → Developer ID Application。"
  fi
  signing_identity="${IDENTITY}"
elif [[ -n "${dev_id}" ]]; then
  signing_identity="${dev_id}"
else
  signing_identity=""
fi

if [[ -z "${signing_identity}" ]]; then
  ADHOC=1
  log_warn "未找到 Developer ID Application 证书"
  log_warn "降级为 ad-hoc 签名（codesign -s -）：产物仅供本机测试，不能分发给其他机器。"
  log_warn "如需正式分发：申请 Developer ID Application 证书后重跑本脚本。"
else
  log_ok "使用证书：${signing_identity}"
fi

if [[ -n "${TARGET_PKG}" ]]; then
  [[ -n "${INSTALLER_IDENTITY}" ]] || INSTALLER_IDENTITY="${installer_auto}"
  if [[ -z "${INSTALLER_IDENTITY}" ]]; then
    log_warn "未找到 Developer ID Installer 证书 —— .pkg 无法签名（ad-hoc 对 pkg 无意义）"
    log_warn "pkg 仍可安装，但 Gatekeeper 会提示「无法验证开发者」。"
  else
    log_ok "Installer 证书：${INSTALLER_IDENTITY}"
  fi
fi

# 公证能力判定
NEED_NOTARIZE=0
if [[ "${SKIP_NOTARIZE}" != "1" && -z "${signing_identity}" ]]; then
  log_warn "ad-hoc 签名无法公证，自动跳过 notarytool（可用 --skip-notarize 消除此提示）"
elif [[ "${SKIP_NOTARIZE}" != "1" ]]; then
  NEED_NOTARIZE=1
fi

if [[ "${NEED_NOTARIZE}" == "1" ]]; then
  missing=()
  [[ -n "${APPLE_ID}" ]]      || missing+=("APPLE_ID / --apple-id")
  [[ -n "${TEAM_ID}" ]]       || missing+=("TEAM_ID / --team-id")
  [[ -n "${APP_PASSWORD}" ]]  || missing+=("APPLE_APP_PASSWORD / --password")
  command -v xcrun >/dev/null 2>&1 || die 4 "缺少 xcrun" "xcode-select --install"
  if ! xcrun notarytool --version >/dev/null 2>&1; then
    die 4 "xcrun notarytool 不可用（需要 Xcode 13+ 的 notarytool）" \
      "安装完整 Xcode 或更新 Command Line Tools：xcode-select --install" \
      "只想签名不公证：加 --skip-notarize"
  fi
  if (( ${#missing[@]} > 0 )); then
    log_err "公证缺少凭据：${missing[*]}"
    die 5 "需要公证但缺少 Apple 凭据" \
      "用 App 专用密码（不是 Apple ID 登录密码），在 appleid.apple.com 生成。" \
      "示例：APPLE_ID=me@example.com TEAM_ID=TEAMID1234 APPLE_APP_PASSWORD=abcd-efgh-ijkl-mnop bash packaging/sign_and_notarize.sh" \
      "只想签名不公证：加 --skip-notarize"
  fi
fi

# ---------------- 3. dry-run ----------------
if [[ "${DRY_RUN}" == "1" ]]; then
  log_step "3/6 dry-run：以下命令不会执行"
  if [[ "${ADHOC}" == "1" ]]; then
    cat <<PLAN
  模式：ad-hoc（未找到 Developer ID Application 证书 —— 结果仅供本机测试）
    codesign --force --deep --options runtime --timestamp=none --sign - "${TARGET_APP}"
    codesign --verify --deep --strict --verbose=2 "${TARGET_APP}"
PLAN
  else
    cat <<PLAN
  模式：正式签名 + 公证
    codesign --force --deep --options runtime --timestamp --sign "${signing_identity}" "${TARGET_APP}"
    codesign --verify --deep --strict --verbose=2 "${TARGET_APP}"
    ditto -c -k --keepParent "${TARGET_APP}" "\${TMPDIR}/atfield-${VERSION}.zip"
    xcrun notarytool submit "<zip>" --apple-id "${APPLE_ID:-<APPLE_ID>}" --team-id "${TEAM_ID:-<TEAM_ID>}" \
          --password "****" --wait --output-format json
    xcrun stapler staple "${TARGET_APP}" && xcrun stapler validate "${TARGET_APP}"
    spctl --assess --type execute -vv "${TARGET_APP}"
PLAN
  fi
  if [[ -n "${TARGET_PKG}" ]]; then
    if [[ -n "${INSTALLER_IDENTITY}" ]]; then
      cat <<PLAN
  pkg：productsign --sign "${INSTALLER_IDENTITY}" "${TARGET_PKG}" "<signed.pkg>"
      xcrun notarytool submit "<signed.pkg>" … --wait   （若启用公证）
      xcrun stapler staple "<signed.pkg>"
PLAN
    else
      printf '  pkg：跳过签名（无 Developer ID Installer 证书）\n'
    fi
  fi
  log_step "dry-run 完成"
  printf '  探测完成，未签名、未提交。去掉 --dry-run 即可执行。\n\n'
  exit 0
fi

# ---------------- 4. 签名 .app ----------------
sign_app() {
  local app="$1"
  log_step "3/6 签名 .app"
  local args=(--force --deep --options runtime)
  if [[ "${ADHOC}" == "1" ]]; then
    args+=(--timestamp=none --sign -)
  else
    args+=(--timestamp --sign "${signing_identity}")
  fi
  log_info "codesign ${args[*]} \"${app}\""
  codesign "${args[@]}" "${app}" \
    || die 7 "codesign 失败" \
      "常见原因：扩展属性异常（xattr -cr \"${app}\"）、包内二进制架构不匹配、钥匙串被锁。" \
      "查看详情：codesign --force --deep --verbose=4 --sign - \"${app}\""

  log_step "4/6 校验签名"
  codesign --verify --deep --strict --verbose=2 "${app}" 2>&1 | sed 's/^/        /' \
    || die 7 "codesign --verify 未通过：${app}" "产物不可用，请重新构建后再签。"
  log_ok "签名有效性校验通过"
  printf '\n        签名详情：\n'
  codesign -dv --verbose=4 "${app}" 2>&1 | grep -E 'Identifier|Format|CodeDirectory|Authority|TeamIdentifier|Signature|flags' | sed 's/^/        /' || true
}

# ---------------- 5. 公证 .app ----------------
notarize_artifact() {
  local artifact="$1" kind="$2" zip_path=""
  log_step "5/6 提交公证（notarytool --wait）"
  if [[ "${kind}" == "app" ]]; then
    zip_path="${TMPDIR:-/tmp}/atfield-${VERSION}-notarize-$$.zip"
    log_info "ditto -c -k --keepParent 打包为 ${zip_path}"
    ditto -c -k --keepParent "${artifact}" "${zip_path}" \
      || die 6 "创建公证上传包失败：${zip_path}" "检查磁盘空间与 ${TMPDIR:-/tmp} 可写性。"
  else
    zip_path="${artifact}"
  fi

  local json
  json="$(xcrun notarytool submit "${zip_path}" \
            --apple-id "${APPLE_ID}" \
            --team-id "${TEAM_ID}" \
            --password "${APP_PASSWORD}" \
            --wait --output-format json 2>&1)" || {
    log_err "notarytool submit 调用失败"
    printf '%s\n' "${json}" | sed 's/^/        /' >&2
    die 6 "公证提交失败" \
      "凭据错误（App 专用密码/团队 ID）或网络不可达都会走到这里。" \
      "用 --skip-notarize 先出未公证产物，或检查凭据后重试。"
  }
  printf '%s\n' "${json}" | sed 's/^/        /'

  local status sub_id
  status="$(printf '%s' "${json}" | python3 -c 'import json,sys;print((json.load(sys.stdin) or {}).get("status",""))' 2>/dev/null || true)"
  sub_id="$(printf '%s' "${json}" | python3 -c 'import json,sys;print((json.load(sys.stdin) or {}).get("id",""))' 2>/dev/null || true)"

  if [[ "${status}" != "Accepted" ]]; then
    log_err "公证状态：${status:-未知}"
    [[ -n "${sub_id}" ]] && log_err "提交 ID：${sub_id}"
    die 6 "公证未通过（status=${status:-unknown}）" \
      "拉取详细日志：xcrun notarytool log ${sub_id:-<id>} --apple-id \"${APPLE_ID}\" --team-id \"${TEAM_ID}\" --password '****'" \
      "常见原因：未启用 hardened runtime、包含未签名嵌套二进制、缺少 --timestamp。"
  fi
  log_ok "公证通过（submission=${sub_id:-?}）"

  log_step "6/6 装订票据并评估"
  xcrun stapler staple "${artifact}" 2>&1 | sed 's/^/        /' \
    || die 7 "stapler staple 失败：${artifact}" "公证已通过但装订失败，可重试或改用 xcrun stapler staple -v 查看原因。"
  xcrun stapler validate "${artifact}" 2>&1 | sed 's/^/        /' \
    || die 7 "stapler validate 未通过：${artifact}"

  if [[ "${kind}" == "app" ]]; then
    spctl --assess --type execute -vv "${artifact}" 2>&1 | sed 's/^/        /' \
      || die 7 "Gatekeeper 评估未通过：${artifact}" \
        "检查签名证书是否为 Developer ID Application，以及 stapled ticket 是否生效。"
  else
    spctl --assess --type install -vv "${artifact}" 2>&1 | sed 's/^/        /' || true
  fi
  log_ok "装订完成，Gatekeeper 放行"
  if [[ -f "${zip_path}" && "${kind}" == "app" ]]; then
    rm -f -- "${zip_path}"
  fi
}

if [[ -n "${TARGET_APP}" ]]; then
  sign_app "${TARGET_APP}"
  if [[ "${NEED_NOTARIZE}" == "1" ]]; then
    notarize_artifact "${TARGET_APP}" "app"
  else
    # ad-hoc 或 --skip-notarize：给出诚实的本机评估结果
    if [[ "${SKIP_NOTARIZE}" == "1" ]]; then
      log_step "5/6 跳过公证（--skip-notarize）"
    else
      log_step "5/6 跳过公证（ad-hoc 签名无法公证）"
    fi
    log_warn "未公证产物在 Gatekeeper 下的表现（预期为 rejected）："
    spctl --assess --type execute -vv "${TARGET_APP}" 2>&1 | sed 's/^/        /' || true
    log_warn "本机可通过「系统设置 → 隐私与安全性 → 仍要打开」或 xattr -dr com.apple.quarantine 放行。"
  fi
fi

# ---------------- 6. 签名 .pkg ----------------
if [[ -n "${TARGET_PKG}" ]]; then
  log_step "附加步骤：处理 .pkg"
  if [[ -n "${INSTALLER_IDENTITY}" ]]; then
    need_cmd productsign
    signed_pkg="${TARGET_PKG%.pkg}-signed.pkg"
    productsign --sign "${INSTALLER_IDENTITY}" "${TARGET_PKG}" "${signed_pkg}" \
      || die 7 "productsign 失败：${TARGET_PKG}" \
        "确认证书类型为 Developer ID Installer，且目标路径可写。"
    log_ok "已签名 pkg：${signed_pkg}"
    pkgutil --check-signature "${signed_pkg}" 2>&1 | sed 's/^/        /' || true
    if [[ "${NEED_NOTARIZE}" == "1" ]]; then
      notarize_artifact "${signed_pkg}" "pkg"
    else
      log_warn "未公证的 pkg 无法在受管设备上静默安装（Gatekeeper 会拦截）——建议提供凭据后重跑。"
    fi
  else
    log_warn "跳过 pkg 签名：没有 Developer ID Installer 证书（ad-hoc 不适用于 pkg）"
    log_warn "该 pkg 仍可本机 sudo installer -pkg 安装，但对外分发会触发 Gatekeeper 提示。"
  fi
fi

# ---------------- 7. 结论 ----------------
log_step "结果"
if [[ "${ADHOC}" == "1" ]]; then
  printf '  %s模式    ad-hoc（codesign -s -）%s\n' "${_C_YEL}" "${_C_RESET}"
  printf '  结果    仅供本机测试；不可分发，notarytool 不会受理\n'
  printf '  警告    WARNING: 未找到 Developer ID Application 证书，产物未公证\n'
  [[ -n "${TARGET_APP}" ]] && printf '  产物    %s\n' "${TARGET_APP}"
  [[ -n "${TARGET_PKG}" ]] && printf '  产物    %s（未签名）\n' "${TARGET_PKG}"
  printf '\n  正式分发前请补齐：Developer ID Application 证书 + App 专用密码，然后重跑本脚本。\n\n'
else
  printf '  模式    正式签名：%s\n' "${signing_identity}"
  [[ "${NEED_NOTARIZE}" == "1" ]] && printf '  公证    Accepted + stapled\n' \
                                 || printf '  公证    已跳过（--skip-notarize）\n'
  [[ -n "${TARGET_APP}" ]] && printf '  产物    %s\n' "${TARGET_APP}"
  [[ -n "${TARGET_PKG}" ]] && printf '  产物    %s\n' "${TARGET_PKG}"
  printf '\n'
fi
exit 0
