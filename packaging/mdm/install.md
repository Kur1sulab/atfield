# 心之壁的 MDM 静默部署（Jamf / Intune / Mosyle）

一页纸。目标：受管 Mac 上「静默装包 → 预置配置 → 说明完全磁盘访问怎么给」，全程不弹窗、不需要用户在终端里敲命令。

---

## 0. 先在本机构建好可分发的 pkg

```bash
bash packaging/build_app.sh --bundle-runtime --force          # 自包含 .app（含 psutil + PyYAML）
bash packaging/build_pkg.sh --force                            # → packaging/dist/心之壁-1.0.0.pkg
bash packaging/sign_and_notarize.sh --pkg packaging/dist/心之壁-1.0.0.pkg \
     --installer-identity "Developer ID Installer: Kurisu Lab (TEAMID1234)"
```

> MDM（尤其 Intune）只接受**已签名 + 已公证**的 pkg。没有证书时本机可以
> `sudo installer -pkg ... -target /` 装，但下发到终端会被 Gatekeeper 拦。
> 自包含包的同时也解决了「目标机没装 psutil / PyYAML」的问题 —— 后者是 **MDM 配置能否生效的前提**：
> `atfield/config.py` 在 `import yaml` 失败时会静默忽略 `config.yaml`，配置看起来"推下去了但没生效"就查这里。

安装后由 postinstall 自动完成：

- `/usr/local/bin/atfield` → `/Applications/心之壁.app/Contents/MacOS/atfield-launcher`
- 已存在的 `~/.atfield` 收权为 `700`（目录）/ `600`（文件）并纠正属主
- 日志：`/var/log/atfield-install.log`

---

## 1. 把配置基线（`mdm/com.kurisulab.atfield.plist`）变成 config.yaml

```bash
# 1) plist → JSON（系统自带 plutil，无需额外依赖）
plutil -convert json -o - packaging/mdm/com.kurisulab.atfield.plist > /tmp/atfield-config.json

# 2) JSON → YAML（纯标准库，不依赖 PyYAML）
python3 - <<'PY' > /tmp/atfield-config.yaml
import json
cfg = json.load(open("/tmp/atfield-config.json", encoding="utf-8"))

def emit(v, ind=0):
    pad = "  " * ind
    if isinstance(v, dict):
        for k, x in v.items():
            if isinstance(x, (dict, list)):
                print(f"{pad}{k}:"); emit(x, ind + 1)
            else:
                print(f"{pad}{k}: {scalar(x)}")
    elif isinstance(v, list):
        if not v:
            print(f"{pad}[]")
        for x in v:
            if isinstance(x, (dict, list)):
                print(f"{pad}-"); emit(x, ind + 1)
            else:
                print(f"{pad}- {scalar(x)}")

def scalar(x):
    if isinstance(x, bool):  return "true" if x else "false"
    if x is None:            return "null"
    if isinstance(x, (int, float)): return repr(x)
    s = str(x).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{s}"'

emit(cfg)
PY
```

结果 `/tmp/atfield-config.yaml` 就是 `~/.atfield/config.yaml` 的内容（结构与 `atfield/config.py` 的 `DEFAULTS` 一致）。

**下发到全局（所有用户共用一份基线）：**

```bash
sudo mkdir -p "/Library/Application Support/ATField"
sudo install -m 644 -o root -g wheel /tmp/atfield-config.yaml \
     "/Library/Application Support/ATField/config.yaml"
```

**每用户生效**：`atfield` 默认读 `~/.atfield/config.yaml`。用 LaunchDaemon 直接指向全局基线最省事（root 采集能力也最全）：

```xml
<!-- /Library/LaunchDaemons/com.kurisulab.atfield.agent.plist -->
<key>Label</key><string>com.kurisulab.atfield.agent</string>
<key>ProgramArguments</key>
<array>
  <string>/usr/local/bin/atfield</string>
  <string>--config</string>
  <string>/Library/Application Support/ATField/config.yaml</string>
  <string>--no-browser</string>
</array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
```

```bash
sudo launchctl bootstrap system /Library/LaunchDaemons/com.kurisulab.atfield.agent.plist
```

> 基线本身把 `server.bind` 钉在 `127.0.0.1` 并要求 `server.auth.enabled=true`：
> 控制台只在本机可达、且必须登录。以 root 跑守护进程时这个组合是必须的 —— 否则同机任意用户都能看全量态势数据。
> 需要远程看，用 `ssh -L 8866:127.0.0.1:8866 host`，不要把 bind 改成 `0.0.0.0`。

---

## 2. Jamf Pro

1. **Packages** → 上传 `心之壁-1.0.0.pkg`（REST：
   `curl -H "Authorization: Bearer $TOKEN" -X POST "https://jss/api/v1/packages"`）。
   上传后勾选 *Reboot required: No*。
2. **Policies → New**：Trigger 勾 `Recurring Check-in` / `Custom`（event `atfield-install`），
   Payloads 里加 **Packages → 心之壁-1.0.0.pkg**，Actions 里加
   `installer -pkg /Library/Application\ Support/JAMF/Waiting\ Room/心之壁-1.0.0.pkg -target /`（Jamf 会自动处理 Waiting Room，通常无需手写）。
3. **Scripts** → 新增一个 post-install 脚本，内容就是上面第 1 节的「下发全局配置」三步。
4. 验证 / 手动触发：

```bash
sudo jamf policy -event atfield-install
sudo jamf recon
ls -l /usr/local/bin/atfield "/Applications/心之壁.app/Contents/MacOS/atfield-launcher"
```

---

## 3. Microsoft Intune

1. **Apps → macOS → Add → macOS app (PKG)**：上传**已签名且公证**的 `心之壁-1.0.0.pkg`，
   Bundle ID 填 `com.kurisulab.atfield`。
2. **Detection rule** 用脚本（Intune 认为 exit 0 + 有 stdout 即已安装）：

```bash
#!/bin/sh
if [ -x "/Applications/心之壁.app/Contents/MacOS/atfield-launcher" ]; then
  echo "心之壁 installed"; exit 0
fi
echo "心之壁 not installed"; exit 1
```

3. **配置**用 **Devices → macOS → Shell scripts**（以 root 运行）：把第 1 节的 YAML 直接内联写盘：

```bash
#!/bin/bash
set -euo pipefail
mkdir -p "/Library/Application Support/ATField"
cat > "/Library/Application Support/ATField/config.yaml" <<'YAML'
# ここに /tmp/atfield-config.yaml の内容を貼る
YAML
chmod 644 "/Library/Application Support/ATField/config.yaml"
```

4. LaunchDaemon 同上（打包成第二个 shell script 或用 **Settings catalog → Custom profile** 推 plist）。

---

## 4. Mosyle

- **Management → Custom Commands**：`/usr/sbin/installer -pkg "/Library/Application Support/ATField/心之壁-1.0.0.pkg" -target / -verboseR`（先把 pkg 用 **Install PKG** 动作或文件分发放到该目录）。
- 更推荐 **Management → Install PKG**：直接上传 pkg，Mosyle 负责分发和重试。
- 配置下发用 **Custom Command** 跑第 1 节的 YAML 写盘命令；LaunchDaemon 用 **Custom Profile** 上传 plist。

---

## 5. 完全磁盘访问（TCC / PPPC）——能写什么、不能写什么

心之壁的 `logstream` / `privileged` / `integrity` 采集器要读到全量日志与受保护目录，
没有 **Full Disk Access** 时只会降级（不是崩溃）：采集器标红、事件量显著变少。

**事实先说清楚：`SystemPolicyAllFiles`（完全磁盘访问）无法通过 PPPC 配置描述文件授予。**
Apple 只允许 MDM 对个别服务下发 `Allow`，FDA 不在其中 —— 下发 `Allow` 会被 TCC 忽略；
能做的只有 `Deny`（合规封堵）。所以下面给出两种结构：**策略封堵（真能生效）** 与
**授权模板（结构正确但 Apple 不受理 Allow）**。

**（A）通用结构：PPPC 配置描述文件**

```json
{
  "PayloadType": "com.apple.TCC.configuration-profile-policy",
  "PayloadIdentifier": "com.kurisulab.atfield.pppc",
  "PayloadUUID": "6F1C2A10-0000-4000-8000-心之壁0000001",
  "PayloadVersion": 1,
  "PayloadDisplayName": "心之壁 TCC Policy",
  "PayloadContent": {
    "Services": {
      "SystemPolicyAllFiles": [
        {
          "Identifier": "com.kurisulab.atfield",
          "IdentifierType": "bundleID",
          "CodeRequirement": "identifier \"com.kurisulab.atfield\" and anchor apple generic and certificate leaf[subject.OU] = \"TEAMID1234\"",
          "Authorization": "Deny",
          "StaticCode": false,
          "Comment": "心之壁 — 若用于封堵则 Deny 生效；改成 Allow 对 FDA 无效"
        }
      ]
    }
  }
}
```

- `IdentifierType`：`bundleID`（推荐，跟签名绑定）/ `path`（路径变了就失效）。
- `CodeRequirement`：把 `TEAMID1234` 换成你的 Team ID；**没有它等于放行任意同名程序**，
  这是 PPPC 最常见的误配。
- `StaticCode: false` 表示按 CodeRequirement 动态校验，比钉死静态代码更耐升级。
- 旧格式（`PayloadContent` 直接是数组）部分老 MDM 仍在用，结构相同、只差一层包装。

**（B）实际授权只能由用户/管理员在本机完成**

```bash
# 直接把用户带到「完全磁盘访问」面板（避免让用户在设置里翻菜单）
open "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"
# 用户把 /Applications/心之壁.app 拖进去并勾选；或用 MDM 下发下面这段提示
```

受管场景下的现实做法：

1. **通知 + 引导**：Jamf Self Service / Intune Company Portal 放一条「开启 心之壁 完全磁盘访问」的图文说明，
   配上面的 `open` 命令做一键跳转。
2. **可验证**：`log show --predicate 'subsystem == "com.apple.TCC"' --last 1h | grep -i atfield`
   能看到 TCC 的拒绝/放行记录；心之壁 控制台的采集器状态面板也会显示 `logstream` 是否降级。
3. **重新授权**：`tccutil reset SystemPolicyAllFiles com.kurisulab.atfield`
   （`tccutil` 只能 reset，**不能 grant** —— 这条命令本身也说明"自动授予"不存在）。

**为什么不建议自动授予（即使技术上能绕）：**

- **Apple 明确禁止**：FDA 是用户知情同意的边界，PPPC 的 `Allow` 对该服务不生效；绕过它等于和系统完整性保护对着干，升级后随时失效。
- **最小权限**：FDA 意味着能读邮件、照片、浏览器库、其他应用容器。给一个 EDR 装上等于给它全机明文。
  只做进程/网络监控的场景不需要 FDA，先跑降级模式再逐台评估。
- **合规与审计**：等保/SOC2 要求「授权动作可追溯到人」。静默授予会让审计链断在"谁批准的"这一环，
  出事时无法举证。心之壁 自己的 audit 链也记录不到这种外部授权。
- **误配放大**：PPPC 里 `CodeRequirement` 写错（或干脆省略）等于给所有同名程序开 FDA，这比不授权危险得多。
- **可恢复性**：手动授权用户随时能撤销；静默授权被撤销时用户不知道发生了什么，排查成本更高。

---

## 6. 部署后验证清单

```bash
# 1) 安装到位
ls -l /Applications/心之壁.app/Contents/MacOS/atfield-launcher /usr/local/bin/atfield
# 2) 版本一致（应等于 atfield/__init__.py 的 __version__）
/usr/local/bin/atfield --version
# 3) 配置真的被读到（关键：确认 yaml 模块可用，否则配置被静默忽略）
/Applications/心之壁.app/Contents/Resources/runtime/bin/python3 -c 'import yaml;print("pyyaml ok")'
# 4) 权限收紧
ls -ld ~/.atfield && ls -l ~/.atfield
# 5) 控制台只绑回环
lsof -nP -iTCP:8866 -sTCP:LISTEN
# 6) 安装日志
tail -50 /var/log/atfield-install.log
```
