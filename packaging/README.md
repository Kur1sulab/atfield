# 心之壁 macOS 打包与分发

把 `atfieldd.py` + `atfield/` 打成一个可分发、可签名公证、可由 MDM 静默部署的 macOS 应用。
本目录之外的文件一律不做修改；**版本号只有一个真源**：`atfield/__init__.py` 的 `__version__`。

```
packaging/
├── build_app.sh                 # → dist/心之壁.app
├── build_pkg.sh                 # → dist/心之壁-<version>.pkg（pkgbuild + productbuild）
├── sign_and_notarize.sh         # codesign + notarytool + stapler（无证书自动降级 ad-hoc；--verify-only 只验签）
├── release.sh                   # 一键发布链：构建 → 签名 → 验签 → 出 pkg → 打印指纹（单链互斥）
├── lib/common.sh                # 三个脚本共用的路径/日志/校验/版本解析
├── templates/
│   ├── atfield-launcher.sh        # Contents/MacOS/atfield-launcher
│   ├── Info.plist.in            # LSUIElement=false / NSHighResolutionCapable / com.kurisulab.atfield
│   ├── distribution.xml.in      # currentUserDomain + minOS 13.0
│   └── postinstall.sh           # /usr/local/bin/atfield 符号链接 + ~/.atfield 收权 700
├── mdm/
│   ├── com.kurisulab.atfield.plist # 配置基线（按 config.yaml DEFAULTS 结构，逐项注释）
│   └── install.md               # Jamf / Intune / Mosyle 静默部署 + TCC(PPPC) 说明
└── dist/                        # 所有构建产物（唯一写入位置）
```

## 一条命令发布（推荐）

```bash
bash packaging/release.sh                 # 构建 → 签名 → 验签 → 出 pkg → 打印指纹
bash packaging/release.sh --dry-run       # 只看将要执行什么
bash packaging/release.sh --installer-identity "Developer ID Installer: xxx (TEAMID)"   # 顺带签 pkg
```

结尾会打印一行可直接粘贴、可对账的结论：

```
RELEASE_OK version=1.1.0 pkg=心之壁-1.1.0.pkg sha256=cd789e12… bytes=1963204 files=670 sign=ad-hoc（…） assets=SAME
```

它替你把下面这些容易漏的事做掉了：

| 环节 | 保证 |
|------|------|
| 构建 | 版本号只认 `atfield/__init__.py`；启动器 `--version` 必须与真源一致，否则 exit 8 |
| 签名 | 无 Developer ID 证书时自动 ad-hoc 并在结论里写明「仅供本机测试，不可分发」 |
| 验签 | 调 `sign_and_notarize.sh --verify-only`（exit 0/7），**不靠日志里有没有 VERIFY 字样猜** |
| 静态资源 | `index.html` / `style.css` / `app.js` 与源码逐字节比对，不一致直接 exit 8（防「改了源码没重建」） |
| 并发 | `dist/.release.lock` 互斥；残留锁（pid 已死）自动接管，活锁拒绝并 exit 7 |
| 留痕 | 全过程落 `dist/release-<时间戳>/{release.log, release-report.txt}`，各步单独日志 |

两个必须知道的口径：

- **sha256 每次构建都不同**：`pkgbuild` 会把打包时间写进 payload 的 cpio/mtime，同一份源码跑两次得到两个 sha。
  对账时以当次 `release-report.txt` 里的 sha 为准，别拿上一次的哈希去比对「是不是同一版」——要比就比
  `version` + 包内静态资源 sha（脚本已经逐字节比过）。
- **锁只防并发，不防手贱**：`dist/.release.lock` 里存的是发布链 pid；进程活着就拒绝（exit 7），
  pid 已死则打印 WARN 自动接管。要手工清理残留锁，先 `cat dist/.release.lock/pid` 确认那个 pid 真没了。

## 三条命令跑通

```bash
bash packaging/build_app.sh --bundle-runtime --force   # 1) 应用包（自包含 psutil + PyYAML）
bash packaging/sign_and_notarize.sh                    # 2) 签名；无证书 → ad-hoc 并 WARNING
bash packaging/sign_and_notarize.sh --verify-only --target packaging/dist/心之壁.app  # 只验签（exit 0 通过 / 7 失败）
bash packaging/build_pkg.sh --force                    # 3) 安装包 心之壁-<version>.pkg
```

只想先看看它们要干什么，全部支持干跑：

```bash
bash packaging/build_app.sh --dry-run
bash packaging/build_pkg.sh --dry-run
bash packaging/sign_and_notarize.sh --dry-run
bash packaging/*.sh --help        # 每个脚本的完整选项 + 退出码
```

**正式分发**（有 Developer ID 证书时）：

```bash
bash packaging/build_app.sh --bundle-runtime --force
bash packaging/sign_and_notarize.sh \
  --apple-id me@example.com --team-id TEAMID1234 --password "abcd-efgh-ijkl-mnop"
bash packaging/build_pkg.sh --installer-identity "Developer ID Installer: Kurisu Lab (TEAMID1234)" --force
bash packaging/sign_and_notarize.sh --pkg packaging/dist/心之壁-1.0.0.pkg \
  --installer-identity "Developer ID Installer: Kurisu Lab (TEAMID1234)" \
  --apple-id me@example.com --team-id TEAMID1234 --password "abcd-efgh-ijkl-mnop"
```

凭据也可以走环境变量：`APPLE_ID` / `TEAM_ID` / `APPLE_APP_PASSWORD`（必须是 App 专用密码）。

## 产物布局

```
dist/心之壁.app/Contents/
├── Info.plist                              # com.kurisulab.atfield / v<version> / LSMinimumSystemVersion 13.0
├── MacOS/atfield-launcher                    # bash 启动器：定位运行时 → exec atfieldd.py
└── Resources/
    ├── atfieldd.py                           # 入口
    ├── requirements.txt
    ├── runtime.env                         # 构建时选定的解释器（ATFIELD_PYTHON=...）
    ├── runtime/                            # 仅 --bundle-runtime：venv + psutil + PyYAML
    └── atfield/                              # 完整源码（含 web/ 静态资源）
```

启动器找解释器的顺序：`$ATFIELD_PYTHON` → `Resources/runtime/bin/python3` → `runtime.env` 里的
`ATFIELD_PYTHON` → `/opt/homebrew/bin/python3` → `/usr/local/bin/python3` → `/usr/bin/python3`。
它还会先检查 `import psutil`，失败时给出三条修复路径并以 **退出码 6** 结束，不会抛 Python traceback。

Finder 双击启动时 `stdout` 是 `/dev/null`，输出自动落到 `~/Library/Logs/心之壁/launcher.log`；
终端里执行（哪怕走管道或重定向）则保持原始输出。

## 退出码

### release.sh

| 码 | 含义 |
|----|------|
| 0 | 全链成功（含 ad-hoc 签名降级） |
| 1 | 参数错误 / 输出目录越界 |
| 2 | 前置缺失（`atfieldd.py`、`atfield/__init__.py`、`atfield/web/`、必需命令） |
| 3 | 构建 `.app` 失败（详见 `release-*/build-app.log`） |
| 4 | 签名失败（`release-*/sign.log`） |
| 5 | 验签未通过（`release-*/verify.log`） |
| 6 | 出 `.pkg` 失败或 pkg 签名校验不过 |
| 7 | 已有发布链在跑（互相踩 dist 会把产物写坏） |
| 8 | 产物自检未通过：启动器版本与真源不一致，或包内静态资源 ≠ 源码 |

### build_app.sh

| 码 | 含义 |
|----|------|
| 0 | 成功（`--dry-run` 校验通过也返回 0） |
| 1 | 参数错误：未知参数、空值、`--app-name` 含路径分隔符/空格、输出目录越界、目标已存在且未加 `--force` |
| 2 | 前置文件缺失：`atfieldd.py` / `atfield/__init__.py` / `atfield/web/index.html` / 模板不在仓库内 |
| 3 | 版本号解析失败；渲染 Info.plist、复制源码、创建 venv 或安装依赖失败 |
| 4 | 缺少工具（`python3` / `plutil` / `ditto` / `/usr/libexec/PlistBuddy`）或找不到 python3 |
| 5 | 构建后自检未通过（Info.plist 不可解析、版本不一致、启动器不可执行、静态资源缺失） |

### build_pkg.sh

| 码 | 含义 |
|----|------|
| 0 | 成功 |
| 1 | 参数错误；`--installer-identity` 指定的证书不在钥匙串；目标 pkg 已存在且未加 `--force` |
| 2 | 输入缺失：`.app` 或其 `Contents/Info.plist` 不存在 |
| 3 | 版本不一致（.app 陈旧）、版本解析失败、`pkgbuild` / `productbuild` 执行失败 |
| 4 | 缺少工具（`pkgbuild` / `productbuild` / `security` / `plutil` / `ditto`） |
| 5 | 产物自检未通过（payload 缺 `心之壁.app`、包内缺 postinstall） |

### sign_and_notarize.sh

| 码 | 含义 |
|----|------|
| 0 | 成功；**包含 ad-hoc 降级**（此时输出带 WARNING，便于 CI 区分） |
| 1 | 参数错误；`--identity` 指定的证书在钥匙串里不存在 |
| 2 | 目标 `.app` / `.pkg` 不存在 |
| 4 | 缺少工具（`codesign` / `security` / `spctl` / `ditto` / `xcrun` / `productsign`），或 `xcrun notarytool` 不可用 |
| 5 | 需要公证但缺少凭据（`APPLE_ID` / `TEAM_ID` / `APPLE_APP_PASSWORD`） |
| 6 | `notarytool submit` 失败，或返回状态不是 `Accepted` |
| 7 | `codesign --verify` / `stapler staple` / `stapler validate` / Gatekeeper 评估未通过 |

`pkgbuild`、`productbuild`、`codesign`、`xcrun notarytool`、`stapler` 都来自 Xcode Command Line Tools：

```bash
xcode-select --install          # 本机已安装：/Library/Developer/CommandLineTools
xcode-select -p                 # 确认路径
```

## 已知限制

1. **未公证时 Gatekeeper 会拦。** ad-hoc 签名（`codesign -s -`）只能让包在本机「结构完整」，
   `spctl --assess` 的结果是 `rejected`，`notarytool` 根本不会受理。拿到别的 Mac 上会被拦；
   本机放行方式：`系统设置 → 隐私与安全性 → 仍要打开`，或 `xattr -dr com.apple.quarantine /Applications/心之壁.app`。
   要真正分发，必须有 `Developer ID Application` 证书 + App 专用密码。
2. **完全磁盘访问必须手动授予。** `SystemPolicyAllFiles`（FDA）**无法**通过 PPPC 配置描述文件授予
   （Apple 只允许 `Deny`，`Allow` 会被 TCC 忽略；`tccutil` 也只能 `reset`）。没有 FDA 时
   `logstream` / `privileged` / `integrity` 采集器会降级（事件变少、状态面板标红），而不是崩溃。
   详见 `mdm/install.md` 第 5 节。
3. **arm64 / x86_64：这不是 universal 包。** `.app` 是「脚本 + Python 源码」，本身没有 Mach-O 主程序，
   架构取决于内嵌运行时：
   - 用 `--bundle-runtime` 在 Apple Silicon 上构建 → 内嵌的 `python3` 只有 arm64，**Intel Mac 上跑不起来**；
   - 不带 `--bundle-runtime` → 用的是目标机自己的 `python3`，两种架构都能跑，但目标机必须自备 `psutil`（和 PyYAML）；
   - 跨架构分发请分别在 arm64 / x86_64 机器上各构建一份，或用 universal2 的 Python 重做 `runtime/`。
   `distribution.xml` 的 `hostArchitectures="arm64,x86_64"` 只表示两种机型都允许安装，不代表二进制是双架构。
4. **`~/.atfield` 收权发生在 postinstall 时点。** 安装前该目录必须已存在才会被处理；安装后新建的目录沿用
   `atfield/audit.py` 自己创建的 `0700`。postinstall 以 root 运行，会对 `/Users/*` 与 `/var/root` 逐个处理，
   写 `/var/log/atfield-install.log`，失败只记日志不回滚安装。
5. **`--output` 只允许 `packaging/` 与 `/tmp` 内。** 这是硬约束，用来防止误删用户目录；
   脚本在 `rm -rf` 前会二次校验目标路径。
6. **`.pkg` 的 ad-hoc 签名不存在。** `codesign` 对 pkg 无效（`pkgutil --check-signature` 仍显示
   no signature），pkg 只能用 `productsign` + `Developer ID Installer`。因此没有该证书时，
   `sign_and_notarize.sh --pkg` 会明确跳过并给出警告，退出码仍为 0。
7. **签名之后不能往 .app 里写任何文件。** 最隐蔽的一条：Python 首次 import 会在
   `Resources/runtime/lib/python3.*/site-packages/**/__pycache__/` 生成 `.pyc`，
   于是 `codesign --verify` 报 `a sealed resource is missing or invalid`，而安装器本身完全正常。
   因此启动器在脚本顶部就 `export PYTHONDONTWRITEBYTECODE=1`，所有内嵌 python 调用（含 psutil 自检）
   都带 `-B`；`build_app.sh --bundle-runtime` 在签名前也会清一遍 `__pycache__`。
   验收顺序必须是「构建 → 签名 → 真跑一次 → 再 `codesign --verify`」，只验一次会漏掉这个坑。
8. **内嵌 venv 的符号链接必须解引用。** `python -m venv` 默认把 `bin/python3` 指向宿主解释器，
   codesign 会以 `invalid destination for symbolic link in bundle` 拒绝；构建脚本用 `--copies`
   并对残留的包外符号链接就地 `cp -L` 成真实文件。

## 本机实测记录（macOS 27.3 / arm64）

- `bash -n` 三个脚本 + 两个模板脚本全部通过（系统 bash 3.2.57）。
- `build_app.sh --dry-run` 不写任何文件；实体构建产出 `dist/心之壁.app`，同时自检读回
  `CFBundleShortVersionString=1.1.0`、`CFBundleIdentifier=com.kurisulab.atfield`。
- 打包后的应用真的能跑：`atfield-launcher --port 8899 --no-browser` 启动，
  `curl http://127.0.0.1:8899/` 返回 **HTTP 200 / 4389 bytes**（index.html），
  `/app.js` 返回 **HTTP 200 / 53415 bytes** —— 证明 `Contents/Resources/atfield/web` 静态资源随包可用。
- `build_app.sh --bundle-runtime` 产出 16M 自包含包，`.../atfield-launcher --version` 输出 `心之壁 1.1.0`。
- `build_pkg.sh` 产出 `dist/心之壁-1.1.0.pkg`，`pkgutil --payload-files` 列出 670 项，
  `pkgutil --expand` 检出 postinstall 与 `os-version min="13.0"`，
  `productbuild` 回显 `Supported OS versions: [Min: 13.0, Before: None]`。
- `sign_and_notarize.sh` 在无证书环境下：打印「未找到 Developer ID Application 证书」→ ad-hoc 签名
  → `codesign --verify` 通过 → `spctl` 报 rejected（预期）→ 退出码 0 且带 WARNING。
- `plutil -lint packaging/mdm/com.kurisulab.atfield.plist` OK；转 YAML 后经 `atfield.config.load()`
  合并验证：`server.bind=127.0.0.1`、`server.auth.enabled=true`、`audit.enabled=true`、8 个采集器全开、
  默认 `watch_paths` 完整保留。

## 静态资源（控制台界面）与重建纪律

- `atfield/web/` 的 `index.html` / `app.js` / `style.css` 会被整体复制到
  `心之壁.app/Contents/Resources/atfield/web/`，**包里没有独立版本号，也没有热更新通道**：
  改了界面就必须重跑 `build_app.sh` → 签名 → 真跑 → `--verify-only` → `build_pkg.sh`。
  只重建 `.app` 不重建 `.pkg`，交付出去的安装包仍是旧界面。
- 验收包里界面是否最新，不要看时间戳，直接比字节：
  `shasum -a 256 atfield/web/style.css packaging/dist/心之壁.app/Contents/Resources/atfield/web/style.css`
  两行哈希一致才算打进去了。
- 本轮（v1.1.0，改名 心之壁 + 白色界面）单链串行实测：`心之壁-1.1.0.pkg`
  **1,963,204 B / 670 文件 / sha256 `cd789e121764d17e5bf56a57600c9a1eaccd0de2d2d2344ef699bb36a2ac354c`**，
  随包 7.8 MB 的 `心之壁.app`（含 python runtime + psutil），`codesign --verify --deep --strict` 通过、
  `Signature=adhoc`、`TeamIdentifier=not set`（无 Developer ID 证书，只能本机测试，不能对外分发）；
  启动器 `--version` 输出 `心之壁 1.1.0`；包内 `atfield/web/{style.css,app.js,index.html}`
  与源码 sha256 三项全 SAME（`fa550f06e5` / `5b9c43eff4` / `94a210fa82`）。
  历史对照：改名前的 AEGIS v1.0.0 为 `AEGIS-1.0.0.pkg` 2,129,530 B / 719 文件，产物保存在
  `packaging/dist/archive-20261118/`。
- **禁止并发构建同一个 `packaging/dist`。** 多链并行会互相覆盖产物，导致同一版本两次构建
  sha256 不同（曾在 5 条链并行时出现 `b0f2907b…` 与 `8901fb78…` 两个哈希）。串行执行，做完记哈希。
