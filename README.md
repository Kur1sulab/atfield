# 心之壁 终端安全态势融合平台

把传统 EDR（进程 / 网络 / 持久化 / 文件完整性 / 行为检测 / 响应）与态势感知
（资产、会话、暴露面、安全基线、风险量化、攻击链叙事）合成一个平台，并继续融合进
**HIDS、UEBA、NDR、诱饵（Canary/Honeypot）、威胁情报、SOAR 剧本、处置工单、资产软件清单、
CIS/等保合规矩阵、统一取证时间线**——一套采集、一个状态存储、一条分析链路。

设计取向：**非特权优先、root 增强**。普通用户即可跑满主体能力；拿到 root 后自动叠加
EndpointSecurity（eslogger）实时事件，不把 root 当作能否运行的前提。

---

## 一、能力矩阵（融合了哪些"工具"）

| 能力域 | 相当于传统什么工具 | 本平台实现 | 权限 |
|---|---|---|---|
| 进程行为 | EDR / 进程审计 | psutil 快照差分 + 进程树 + `ps` 交叉校验 + 无文件执行观察 | 用户 |
| 网络连接 | EDR 网络模块 | psutil 连接差分；非 root 权限不足时回退 `lsof` 全量解析 | 用户 |
| 会话审计 | HIDS / 登录审计 | `who` / `last` + 统一日志里的 sudo/sshd 失败记录 | 用户 |
| 持久化 | HIDS / 启动项审计 | LaunchAgents/Daemons、登录项、cron、配置描述文件、系统扩展 | 用户 |
| 文件完整性 | HIDS / FIM | SHA-256 基线 + 关键文件变动告警 | 用户 |
| 实时遥测 | EDR 内核回调 | macOS 统一日志（`log stream`）订阅安全语义事件 | 用户 |
| 深度遥测 | EDR 内核扩展 | `/usr/bin/eslogger` EndpointSecurity（exec/open/rename/kextload…） | **root** |
| 安全基线 | 配置核查 / 加固工具 | 8 大类检查，pass/warn/fail/unknown + 证据 + 整改建议 | 用户 |
| 行为基线 | UEBA | 进程名/可执行路径/外联目的地画像，首次出现即偏离 | 用户 |
| 网络检测 | NDR（主机侧） | 目的地画像、直连 IP、风险端口、动态 DNS、**心跳信标检测** | 用户 |
| 诱饵 | 蜜罐 / Canary Token | 家目录诱饵文件，读取/改写/删除即告警（零误报信号源） | 用户 |
| 威胁情报 | TIP | 本地 IOC 库（IP/域名/哈希）+ 导入 + 内建高风险**类别**规则 | 用户 |
| 自动处置 | SOAR | YAML 剧本 + 审批门 + 动作审计 + 冷却 | 用户 |
| 工单 | ITSM / 处置闭环 | 工单生命周期（待处理/处理中/已关闭）与备注 | 用户 |
| 资产软件 | 资产盘点 / 漏洞管理 | 应用清单、版本、签名校验、老化、远程控制类单列、CVE 映射导入 | 用户 |
| 合规映射 | 合规检查表 | 实时基线 → CIS macOS 与等保 2.0 三级条款矩阵 + 得分 | 用户 |
| 攻击链 | SIEM 关联规则 | 时序关联模板（执行→持久化→外联、凭据→外联等） | 用户 |
| 取证 | DFIR | 统一时间线、一键证据包（含 ps/netstat/launchctl 等快照与审计） | 用户 |
| 误报治理 | SOC 白名单 | 抑制规则（规则 ID + 关键字），可查可撤，抑制计数可见 | 用户 |

---

## 二、心之壁（边界完整性）

这个产品的名字来自那个设定——**心之壁**：维持自我形态、隔绝他人的力场。

终端上也是一样：任何一次异常，本质都是某条边界被试探、或被穿透。
所以平台不新增一门检测，而是把已有的进程/文件/网络/凭据/信号观测
按五条边界重新归位，让「漏在哪一条」一眼看得到。

| 边界 | 守什么 | 由谁在守（已有能力） |
|---|---|---|
| 进程边界 | 内存读写 · 调试附着 · 代码注入 | 签名规则（进程行为）、UEBA 进程画像 |
| 文件边界 | 二进制 · 配置 · 凭证文件完整性 | FIM 哈希基线、持久化审计、诱饵触碰 |
| 网络边界 | 出站外联 · 入站连接 · 隧道 | NDR 画像、心跳信标、威胁情报 |
| 凭据边界 | 身份使用 · 权限边界 · 会话 | 会话审计、sudo/sshd 失败、提权行为 |
| 信号边界 | 控制信号 · 调试与注入的落地动作 | 信号/附着类规则 |

每条边界四种状态：

| 状态 | 含义 |
|---|---|
| **守住** | 有规则覆盖，这段时间没观测到异常 |
| **波动** | 被试探过，但挡住了 |
| **穿透** | 真实发生的越界（严重级命中，或高危且诱饵被实际踩中） |
| **静默** | 没观测到异常，**但也没有证据说它守得住**——需要人自己去确认 |

**守住和静默必须分开**。没观测到异常，不等于边界稳固；把两者混为一谈，
力场强度就会变成一个虚假的安心数字。

力场强度 = 五条边界得分的均值。它不是发生概率，也不是健康分，
而是「有几堵墙还立着」的摘要。

### 八角徽记

心之壁的图形是那个**平顶平底的八角**，八边形的**边就是墙本身**：

- 周长按边界数等分，**一条边界一段墙板**，板与板之间留一道窄缝
- 守住＝实弧 · 波动＝闪 · 静默＝细线（墙还在，但薄，没测过） · 穿透＝**这段墙真的断开一个口子**
- 外圈一圈极淡的点线会缓慢自转——力场是活的，不是一张静态图
- **点它**直接滚到最该看的那条边界（先找被穿透的，没有就找最弱的），
  徽记不是装饰，是这块页面的入口

整个徽记只画 `/api/barrier` 已经算好的状态，不产生任何新数据。

控制台：左侧「检测与响应 → 心之壁」，或 `GET /api/barrier`。

---

## 三、力场判读（可选 AI 层）

心之壁告诉你哪条边界在漏；**力场判读**负责给出定性——
这次越界是真的穿透、只是波动、还是自身抖动。

判读用和心之壁同一套语言，不需要在 verdict 和边界状态之间来回翻译：

| AI 判定 | 力场语言 | 含义 |
|---|---|---|
| `benign` | 力场未动 | 这个行为没有越过任何边界 |
| `suspicious` | 力场波动 | 边界被碰了一下，但还没破 |
| `malicious` | 力场穿透 | 边界已经被越过 |
| `uncertain` | 判读不明 | 模型给不出结论，需要人来定 |

### 五条不动摇的约束

1. **只判读，不动作**：AI 进程无 root、不执行 `pfctl`、不删文件、不改策略；
   唯一写入是 `~/.atfield/suggestions.jsonl`（建议流水）。
2. **只看结构化摘要**：只吃 Finding 的字段，不吃原始流量、不读文件内容。
3. **出网强制脱敏**：主机名/用户名/家目录/内外网 IP/域名/凭据形态在出网前替换为占位符，
   无 UI 绕过开关。回环端点也不例外——本机网关背后可能仍是云端模型。
4. **必须能关**：`ai.enabled: false`（默认值）时产品完整可用；判读层缺失不影响任何检测。
5. **凭据不进日志/审计/界面**：只出现 `mask_key()` 指纹。`api_key` 只落
   `~/.atfield/secrets/ai.json`（600），**永不写入 `config.yaml`**。

### 接入方式

任意 OpenAI 兼容端点（OpenAI / DeepSeek / Kimi / Qwen / vLLM / Ollama / 自建网关），
或 Anthropic 原生协议。内置预设：`magpie`、`deepseek`、`kimi`、`qwen`、`ollama`、`anthropic`。

```yaml
ai:
  enabled: true
  preset: magpie          # 或直接写 provider / base_url / model
  model: group/daily
  redact: true            # 出网脱敏，默认开，不建议关
  min_severity: high      # 只送审高危以上
  budget_per_hour: 60
  budget_per_day: 400
  auto_judge: false       # 命中即自动送审，默认关
```

凭据三种放法，优先级从低到高：
`config.yaml ai.api_key` → 环境变量 `ATFIELD_AI_KEY` → `~/.atfield/secrets/ai.json`（600，推荐）。
**通过控制台轮换 key 时会自动清空 `config.yaml` 里的旧值**——否则旧值优先级最高，轮换永远不生效。

> 配置读取不依赖 PyYAML：装不上时自动回退内置 `yamlite`（只读）。
> 两条路径都不可用才会退默认值，且会在 `status` 里带出 `_load_error` 而不是静默失效。

---

## 四、架构

```
  ┌─────────────── 采集层（11 个采集器，统一 Event 模型） ───────────────┐
  │ process  network  session  persistence  integrity  baseline          │
  │ logstream(统一日志)  privileged(eslogger/root)  authlog  loginitem    │
  │ fileless                                                             │
  └──────────────────────────────┬──────────────────────────────────────┘
                                 ▼
  ┌──────────── 分析层（三路并行，结果合并） ────────────┐
  │ 签名规则引擎（60+ 条 macOS 行为规则 / MITRE 映射）     │
  │ 检测与响应：UEBA 基线偏离 · NDR 画像与信标 · TI 匹配     │
  │ 诱饵触碰判定（atime/哈希/删除）                       │
  └──────────────────────────────┬──────────────────────┘
                                 ▼
      Finding（哪里不对） → Correlator（攻击链） → 评分（健康度 / 风险度）
                                 ▼
      SOAR 剧本（审批门）→ 工单 → 响应动作（挂起/终止/封禁命令/取证包）
                                 ▼
      REST + SSE 控制台（127.0.0.1，仅回环）· Markdown 报告 · 合规矩阵 · 时间线
```

统一事件模型（UEM）是扩展点：新增采集器或新增检测与响应，只要产出 `Event`，
检测、关联、评分、报告、控制台都会自动吃到，无需改上层。

---

## 五、快速开始

```bash
cd atfield
python3 atfieldd.py                 # 常驻：采集 + 检测 + 控制台 127.0.0.1:8866
python3 atfieldd.py --once          # 跑一轮采集与检测后退出（适合 cron / 巡检）
python3 atfieldd.py --once --report /tmp/atfield.md   # 附带态势报告
python3 atfieldd.py --selftest      # 合成事件验证检测与关联链路
sudo python3 atfieldd.py            # 有 root 时自动叠加 EndpointSecurity 深度遥测
```

首次启动会生成一个随机管理员口令，写在 `~/.atfield/INITIAL-ADMIN.txt`；打开控制台用它登录，
**登录后第一件事是改口令**：控制台「治理与审计链」页可直接改，命令行用
`python3 atfieldd.py --passwd <账号名>`（交互输入新口令）。改完把 `INITIAL-ADMIN.txt` 删掉。
控制台默认强制登录，接口未登录一律 401。

依赖只有 `psutil`（唯一硬依赖）。PyYAML 可选：装了就用它解析剧本，没装自动切到
内置解析器（`atfield/yamlite.py`），功能一致——因为换一个 venv 就可能没装 yaml，
产品不该因此失效。

```bash
pip3 install psutil        # 必须
pip3 install pyyaml        # 可选，仅影响剧本解析引擎选择
```

控制台只监听 `127.0.0.1`，不对外网开放；自带账号体系（scrypt 口令 + 内存会话 + 四角色 RBAC），
需要远程看就套 SSH 隧道（`ssh -L 8866:127.0.0.1:8866`），不要把端口直接暴露到公网。

---

## 六、数据文件（全部在 `~/.atfield/`）

| 路径 | 内容 |
|---|---|
| `config.yaml` | 配置覆盖（采集周期、端口、抑制等） |
| `ueba.json` | 行为基线画像（重启不丢） |
| `intel.json` | 本地 IOC 库 |
| `canary/index.json` | 诱饵清单与触碰计数 |
| `suppress.json` | 误报抑制规则 |
| `playbooks/*.yaml` | 处置剧本（默认三份，可自由改，界面热重载） |
| `integrity.json` | 文件完整性基线 |
| `codesign.json` | 签名校验缓存（7 天） |
| `cve_map.json` | 可选的 CVE 映射表（本地，不联网） |
| `exports/*.zip` | 证据包（含快照与审计） |
| `auth.json` | 账号、角色、scrypt 口令摘要、失败计数（`0600`） |
| `INITIAL-ADMIN.txt` | 首启随机管理员口令（改完请删） |
| `audit.log` / `audit-*.log` | append-only 哈希链审计（滚动封存） |
| `audit/anchor.json` | 链头 HMAC 锚点（防整链替换） |
| `update/` | 更新通道：`state.json`、`update.key`、`lkg/` 备份 |
| `rules/*.yaml` | 外部声明式规则包（热重载） |
| `exports/monthly/<YYYY-MM>/` | 月报 Markdown / HTML / JSON |

---

## 七、检测与关联

- **签名规则**：管道执行、解释器单行、Base64 解码、反弹 shell、凭据访问、关闭防护、
  持久化落地、异常监听、C2 端口、扫描行为、隐藏进程、基线劣化……每条带 MITRE 映射、
  处置建议与冷却时间。
- **融合信号**：`UEBA-NEW-{PROC,PERSIST,DEST}`、`NDR-{BEACON,DIRECT-IP,RISKY-PORT,RISKY-DOMAIN}`、
  `TI-IOC-IP`、`CANARY-TRIP`。
- **攻击链**：把离散命中按时间窗口串成叙事（如"执行 → 持久化 → 外联"），
  链上有阶段、主体、时间线，便于讲清"对手在干什么"，而不是丢一堆告警。
- **两个正交分数**：健康度（配置与防护能力）与风险度（行为与告警，带半衰期衰减）。
  一个分数会误导决策：配置满分也可能正在被打，风险为零也可能门没锁。

### 误报控制（工程上比"多报"更重要）

1. **学习期**：UEBA 前 40 分钟（或 400 次观测）只建画像不判定。
2. **系统路径过滤**：`/usr`、`/System`、`/Applications` 等系统/应用目录里的"新进程"
   属于更新噪声，不产生基线偏离告警。
3. **只统计公网**：信标检测与"单进程连接数异常"只看公网对端，避免把本地代理、IDE、
   数据库连接池误判成 C2 或扫描。
4. **隐藏进程三重确认**：`ps` 可见 + `psutil` 不可读 + 信号探测存活，且只比对当前用户
   的进程（非 root 读不到别人的进程属权限限制，不是隐蔽）。
5. **冷却与去重**：同规则同主体在冷却窗口内只报一次。
6. **抑制规则**：可指定规则 ID 与关键字，必须写依据，随时可撤，抑制次数单独计数。

---

## 八、响应安全边界（只读优先）

| 动作 | 行为 |
|---|---|
| 挂起 / 恢复 | 同用户进程可操作；PID ≤ 1、平台自身进程硬拒绝 |
| 终止 | 默认 SIGTERM；僵尸态识别为"已终止"；需 `force` 才 SIGKILL |
| 跨用户操作 | 非 root 拒绝，明确提示需 root 运行 |
| 边界封禁（生成） | 默认**只生成可复核命令**（pfctl table 操作），不静默改防火墙 |
| 主机防火墙（真执行） | 可选独立通道，见下节；默认关闭，且"规则就位 ≠ 生效" |
| 证据导出 | 打包事件/告警/攻击链/审计 + ps/netstat/launchctl 等快照 |
| 剧本执行 | 默认 `require_confirm: true`，先进待确认队列，人工点确认才动 |

所有动作写审计（时间、操作者、动作、对象、结果），控制台"响应与审计"可查。

### 主机防火墙执行层（pf）

默认**关闭**。这是整套系统里唯一能真正切断连接的东西，所以把权限收到最小：

- 主程序**不碰 pf**——普通用户连 `/dev/pf` 都读不了（实测 `Permission denied`），
  所有动作发给独立的 root helper（`python -m atfield.pfhelper`），走 unix socket；
- helper 只有 6 个动词（`status / block / unblock / flush / attach / detach`），
  参数逐个校验后才拼进规则，**不做任何 shell 拼接**；
- 每个连接都用 `LOCAL_PEERCRED`（macOS）或 `SO_PEERCRED`（Linux）取对端 uid，
  不在白名单直接断；**取不到 uid 就拒绝**，不放行；
- 拒绝把**本机地址、默认网关、回环、组播、超大的 /8 级网段**写进阻断表（防自锁）；
- 每条规则先 `pfctl -n` 解析校验，再真加载；加载失败自动回退到上一版（lkg）；
- 规则双向各一条且 `on ! lo0`，不挡本机自己跟自己说话；
- 阻断表落在 helper 侧（root 所有，0640 + 组可读），每个动作写审计。

**必须说清楚的一条**：规则写进 anchor **不等于生效**。主规则集 `/etc/pf.conf`
里要有 `anchor "atfield"` 这一行，anchor 才会被求值。所以状态里把
「anchor 已存在」和「已挂载」分成两个字段，界面显示「待挂载」并说明原因——
不把"规则就位"当成"已经挡住了"。挂载需要 `firewall.allow_attach: true`
且非 dry-run；写入前备份 `/etc/pf.conf`、新规则集先 `pfctl -n` 校验、
重载失败自动还原。

启动 helper（root，一次性）：

```bash
sudo python3 -m atfield.pfhelper --socket /var/run/atfield-pf.sock \
     --anchor atfield --allow-uid $(id -u) --group $(id -gn)
```

```yaml
firewall:
  enabled: false          # 总开关，默认关
  dry_run: true           # 只做语法校验，不加载
  socket: /var/run/atfield-pf.sock
  allow_attach: false     # 是否允许改 /etc/pf.conf
```

---

## 九、API（供二次开发）

```
GET  /api/ping /api/version /api/diag /api/overview /api/events /api/findings
GET  /api/incidents /api/assets /api/rules /api/chains /api/actions /api/timeline
GET  /api/report.md                  # 实时态势报告（Markdown）
GET  /api/stream                     # SSE，2s 推一次全量态势
GET  /api/ueba /api/ndr /api/canary /api/intel /api/playbooks /api/tickets
GET  /api/inventory /api/compliance /api/suppress
POST /api/selftest /api/respond {action,pid|ip} /api/export
POST /api/ueba/reset /api/canary/deploy /api/canary/undeploy
POST /api/intel/add /api/intel/import /api/intel/remove
POST /api/playbooks/reload /api/playbook/confirm /api/playbook/reject
POST /api/inventory/scan /api/inventory/cve /api/compliance/rebuild
POST /api/ticket/new /api/ticket/update
POST /api/suppress/add /api/suppress/remove
GET  /api/firewall                   # 主机防火墙状态（enabled/available/pf_enabled/attached/count）
POST /api/firewall/block {ip,reason} # 下阻断规则（需 respond 能力）
POST /api/firewall/unblock {ip}      # 解封（需 respond 能力）
POST /api/firewall/{flush,attach,detach}  # 需 admin；attach 还要 firewall.allow_attach

# 治理层（全部需要登录，写操作还要 X-Requested-With: atfield）
GET  /api/auth/me                    # 当前会话与能力位（未登录返回 401 + login_required）
POST /api/auth/login {user,password} # 成功返回 token 并下发 HttpOnly Cookie
POST /api/auth/logout                # 注销并清 Cookie
POST /api/auth/passwd {user,password}
GET  /api/governance                 # 账号 / 审计链 / 更新通道 / 规则包 总览
GET  /api/audit?limit=&action=&actor=  # 审计记录（含链头与锚点）
GET  /api/audit/verify   POST /api/audit/verify   # 全链校验
GET  /api/updates   POST /api/updates/{apply,rollback,reset,export}
GET  /api/users   POST /api/users/{add,passwd,role,delete}
GET  /api/monthly?month=YYYY-MM       # 月报预览（Markdown）
GET  /api/monthly/file?fmt=html|md    # 月报下载（附件）
POST /api/monthly {month,send}        # 生成落盘；send=true 需管理员且配好 SMTP
POST /api/rules/reload               # 重载内置 + 外部规则包
```

鉴权约定：

- 会话令牌放 `Authorization: Bearer <token>` 或 HttpOnly Cookie `atfield_session` 任一即可；
  SSE 只有 Cookie 一条路（`EventSource` 不能带自定义头）。
- 所有写请求必须带 `X-Requested-With: atfield`，跨源无法伪造该头，构成 CSRF 兜底。
- 能力位：`read` < `triage` < `respond` < `admin`，越权返回 403 并记 `auth.deny` 审计。

---

## 十、治理层（谁能改、改了什么、升级怎么退）

商用 EDR 被问得最多的不是"能检测什么"，而是这三个问题。对应三块实现：

### 8.1 账号与角色（`atfield/auth.py`）

| 角色 | 能力位 | 能做什么 |
|---|---|---|
| `viewer` 只读 | `read` | 看态势/告警/时间线 |
| `analyst` 研判分析 | +`triage` | 加情报、写抑制、建工单、重建合规矩阵 |
| `responder` 响应处置 | +`respond` | 终止/挂起进程、生成封禁命令、导出证据 |
| `admin` 管理员 | +`admin` | 账号增删改、更新/回滚、邮件投递、自检 |

- 口令用 `scrypt` + 每账号独立 salt 存储，文件权限 `0600`；连续 5 次失败锁定 300 秒。
- 会话只存内存，进程重启即失效；Cookie 为 `HttpOnly; SameSite=Strict`。
- 首次启动生成随机管理员口令，写入 `~/.atfield/INITIAL-ADMIN.txt`（改完口令请删该文件）。
- 用 `--users` 查账号、`--user-add/--passwd/--user-del` 管账号，或直接走控制台"治理与审计链"页。

### 8.2 不可篡改审计链（`atfield/audit.py`）

每条记录自带 `prev`（上一条哈希）与 `hash = sha256(prev + 规范化JSON)`，首条 `prev` 为 64 个 0；
链头每 200 条用本机密钥做 HMAC 锚点写入 `anchor.json`；单文件超阈值封存为 `audit-<时间>.log`，
链路跨文件延续；按 180 天 / 256 MB 双阈值裁剪。

能发现：内容改写（hash 不匹配）、记录删除（seq 跳号）、尾部截断（链头与锚点不符）、整链替换
（锚点签名失败）。`--audit-verify` 或 `POST /api/audit/verify` 一键校验，退出码非 0 即异常。

### 8.3 规则/剧本更新通道（`atfield/updates.py`）

四道闸：**签名**（manifest HMAC）→ **完整性**（逐文件 sha256 + size）→ **路径白名单**
（只收 `rules/` 与 `playbooks/` 下的 yaml）→ **健康探针**（应用后重载规则与剧本，检测能力归零
或剧本解析失败即判失败）。

失败连续 2 次触发熔断（默认冷却 6 小时），应用前自动备份 last-known-good，探针不过自动回滚。
规则包只做**声明式字段匹配与频率窗口，不支持脚本执行**——避免更新通道变成远程代码执行入口。

```bash
python3 atfieldd.py --update-build ./bundle --bundle-version 1.0.1   # 打签名包
python3 atfieldd.py --update-apply ./bundle                          # 应用（含探针 + 备份）
python3 atfieldd.py --update-status                                  # 看版本 / 熔断 / LKG
python3 atfieldd.py --update-rollback                                # 回滚到 LKG
python3 atfieldd.py --update-export ./baseline                       # 导出当前基线
```

### 8.4 外部规则包（`atfield/rules_ext.py`）

`~/.atfield/rules/*.yaml`，字段：`pack` / `version` / `rules[]`（`id`、`name`、`kind`、`where`、
`freq{window,threshold}`、`severity`、`text`（支持 `{{process}}` 占位）、`advice`、`tags`、
`mitre`、`cooldown`、`enabled`）。坏包只记进台账不抛异常，同名规则先到先得，**不能覆盖内置规则 ID**。

### 8.5 月度报告（`atfield/monthly.py`）

按自然月统计事件/告警/攻击链/处置/工单/合规得分，产出 Markdown + 内联样式 HTML
（HTML 可直接进邮件），落盘到 `~/.atfield/exports/monthly/<YYYY-MM>/`。
配置 `monthly.smtp`（host/port/user/password/sender 或 from/recipients 或 to/ssl/starttls）后
`--monthly --send` 会投递；`starttls` 缺省按服务器能力自动升级，显式 `true` 强制升级
（失败即报错，不静默降级），`false` 关闭。没配 SMTP 时只落盘并在结果里说明原因，**不会假装发送成功**。
投递链路可离线实测：`tests/mock_smtp.py` 起一个只收不转发的本地假 SMTP，
`tests/test_monthly_smtp.py` 覆盖明文/STARTTLS/AUTH/失败路径。

### 8.6 控制台

侧栏"运行 → 治理与审计链"：审计链完整性（链头/锚点/一键校验）、更新通道（版本/熔断/回滚/
基线导出）、账号与角色（增删改）、月报（预览/落盘/邮件/下载）。写操作按能力位灰掉，越权会
被服务端拒绝并留下 `auth.deny` 记录。

### 8.7 界面主题与可访问性

- **默认"纸白"浅色主题**（`--bg #f7f8fa` / 面板纯白 / 正文 `#101828`）。侧栏底部三个圆点切换
  纸白 · 石墨（深色）· 暖墨（暖色深底），选择写 `localStorage['atfield.theme']`；老版本留下的
  深色选择由 `atfield.theme.v2` 一次性迁移到浅色，之后尊重用户点选。
- 浅色下不做装饰性渐变（登录页的蓝色光斑只在深色两套出现，`--login-glow` 变量控制）。
- 浅色登录页是**纯平白底**：遮罩不透明度由 `--login-veil` 控制，浅色 100%（不透过底层卡片，
  也就没有半透明玻璃留下的灰色方块感），深色两套 88%（保留玻璃质感）。
- **所有文本颜色按 WCAG AA（≥ 4.5:1）实测**：打包版 `心之壁.app` 1.1.0 上逐视图跑
  `contrast-live.js`，16 个视图合计 **0 violation**（含表头、徽章、KPI 小字；复跑办法见
  `design-review` 技能的 `scripts/contrast-live.js`）。
- 主操作按钮统一 `.btn.primary`（登录、生成预览、保存、导出证据包等）。
- 侧栏在 900 / 800 / 720 三档窗口高度下都保证 16 个菜单项完整可见：矮屏先收起采集器明细、
  再收紧行距；采集器完整状态仍在「运行 → 采集通道」页，侧栏标题只留"采集通道 · N 路"。
- 截图见 `docs/shots/`（light-overview / light-findings / light-governance / light-login）。

---

## 十一、打包与分发（macOS）

`packaging/` 下是零第三方打包工具的原生方案：源码 + 静态资源 + 启动器塞进 `心之壁.app`，
`pkgbuild`/`productbuild` 出 `.pkg`。

```bash
bash packaging/build_app.sh --dry-run                  # 先看它要做什么
bash packaging/build_app.sh --force --bundle-runtime   # 自包含 .app（内嵌 venv + psutil）
bash packaging/build_app.sh --force                    # 轻量 .app（用机器自带 python3）
bash packaging/sign_and_notarize.sh --target packaging/dist/心之壁.app
bash packaging/sign_and_notarize.sh --verify-only --target packaging/dist/心之壁.app
bash packaging/build_pkg.sh --app packaging/dist/心之壁.app
```

- 有 Developer ID 证书 → 正式签名 + `notarytool` 公证 + `stapler` 装订。
- **没有证书时脚本明确降级为 ad-hoc 并打印"仅供本机测试、不可分发"**，不会假装签名成功；
  公证步骤整体跳过（ad-hoc 无法公证）。
- 内嵌运行时用 `venv --copies` 并把指向包外的符号链接就地解引用——否则 `codesign --verify`
  会以 `invalid destination for symbolic link in bundle` 拒绝。
- MDM 静默部署与免登录配置见 `packaging/README.md`、`packaging/mdm/`。

---

## 十二、已知限制（写清楚，不粉饰）

- macOS 26+ 的 `netstat` 已不再输出常规 TCP/UDP 表，非 root 连接面依赖 `lsof`，
  因此**只能看到当前用户进程**的连接归属；要全量进程归属需 root（eslogger/系统级 socket 查询）。
- 诱饵的"读取"判定基于 atime：Spotlight 索引、备份工具也会读，因此读取类触碰定为**中危**
  并提示结合进程判断；改写/删除/哈希变化才是**严重**。
- EndpointSecurity 需要 root + TCC 授权，未授权时该采集器显示不可用，其余能力不受影响。
- 威胁情报库默认**不含**具体 IOC（不编造情报），只有动态 DNS / 隧道服务 / 高滥用 TLD
  这类"类别规则"；具体 IOC 请从自有情报源导入。
- 合规矩阵是把实时基线映射到条款，未覆盖条款显式标 `gap`，不虚报通过；`unknown`
  表示权限不足未判定，不等于合格。
- 不提供攻击能力：这是防御平台，所有动作都属于观测、判定与受控处置。
- 主机防火墙的**挂载**（往 `/etc/pf.conf` 写 `anchor "atfield"`）没有在生产环境
  长期跑过：目前只验证到"生成的规则集能通过 `pfctl -n` 校验、备份与自动还原路径
  就绪"。要真正开始阻断，请先在测试机跑一段时间。
- 未挂载时 anchor 里的规则**不生效**——这是 pf 的机制，不是缺陷。界面会明确显示
  「待挂载」，不会把规则条数当成已拦截量。
