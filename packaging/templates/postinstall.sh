#!/bin/bash
# 心之壁 pkg postinstall：由 packaging/build_pkg.sh 从 templates/postinstall.sh 渲染，
# 安装时以 root 身份在 pkg 脚本目录内执行（cwd=/，PATH 已由 Installer 设置）。
#
# 做两件事（失败不阻断安装，只记日志，避免半安装状态）：
#   1. 创建 /usr/local/bin/atfield -> /Applications/心之壁.app/Contents/MacOS/atfield-launcher
#   2. 把每个真实用户已存在的 ~/.atfield 收权到 700（目录）/ 600（文件）并纠正属主
set -uo pipefail
# 注意：这里刻意不用 set -e —— 收权失败不应让整个安装回滚。

APP_DIR="/Applications/@APP_NAME@.app"
LAUNCHER="${APP_DIR}/Contents/MacOS/@EXECUTABLE@"
LINK="/usr/local/bin/@CLI_NAME@"
LOG_DIR="/var/log"
LOG_FILE="${LOG_DIR}/atfield-install.log"
EXIT_CODE=0

_log() { printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }

{
  _log "== postinstall start (uid=$(id -u))"

  # ---------- 1. CLI 入口 ----------
  if [ ! -x "${LAUNCHER}" ]; then
    _log "ERROR 启动器不存在或不可执行：${LAUNCHER}"
    _log "       应用包可能损坏，请重新安装 心之壁-*.pkg"
    exit 1   # 这一条必须失败：没有启动器装了也没用
  fi
  mkdir -p /usr/local/bin || { _log "ERROR 无法创建 /usr/local/bin"; exit 1; }
  if ln -sfn "${LAUNCHER}" "${LINK}"; then
    _log "OK  已建立软链 ${LINK} -> ${LAUNCHER}"
  else
    _log "WARN 软链创建失败（可能 /usr/local 被企业策略保护）"
    _log "     手动修复：sudo ln -sfn \"${LAUNCHER}\" \"${LINK}\""
    EXIT_CODE=0
  fi

  # ---------- 2. ~/.atfield 权限收紧 ----------
  # pkg 里没有用户目录内容；这里处理安装前已存在的 ~/.atfield（含审计日志、锚点密钥），
  # 这些是敏感数据：必须 700/600，且属主必须是该用户（root 建目录会导致 daemon 写不进）。
  _tighten_home() {
    local home="$1" d owner group
    d="${home}/.atfield"
    [ -d "${d}" ] || return 0
    owner="$(/usr/bin/stat -f '%Su' "${home}" 2>/dev/null || echo root)"
    group="$(/usr/bin/stat -f '%Sg' "${home}" 2>/dev/null || echo wheel)"
    chown -R "${owner}:${group}" "${d}" 2>/dev/null || _log "WARN chown 失败：${d}"
    /usr/bin/find "${d}" -type d -exec chmod 700 {} + 2>/dev/null
    /usr/bin/find "${d}" -type f -exec chmod 600 {} + 2>/dev/null
    chmod 700 "${d}" 2>/dev/null
    _log "OK  收权 ${d} -> ${owner}:${group} (700/600)"
  }

  for _home in /Users/*; do
    [ -d "${_home}" ] || continue
    case "${_home}" in */Guest|*/Shared) continue ;; esac
    _tighten_home "${_home}"
  done
  [ -d /var/root ] && _tighten_home /var/root

  _log "== postinstall done (exit=${EXIT_CODE})"
  exit "${EXIT_CODE}"
} >>"${LOG_FILE}" 2>&1
