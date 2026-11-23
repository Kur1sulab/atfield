# 心之壁 Go 版迁移

> Python 版在 `~/aegis`（v1.1.3，14,340 行业务 + 4,692 行测试）。
> 本目录是 Go 重写版。**两个版本并行存在，直到对拍一致才切换**。

## 一、为什么换

不是为了「Go 更快」，主要是跨平台：

| 指标 | Python 版（实测） | Go 版（实测/预期） |
|---|---|---|
| 常驻内存 | 70.2 MB | 摘骨架待测，同机 Go 服务 3.0–4.3 MB |
| 安装包 | `.app` 8.2 MB，其中 **7.2 MB 是内嵌 Python runtime** | 单文件 2.1 MB（骨架），无 runtime |
| 依赖系统 Python | 是 | 否 |
| Windows / Linux | 要重做采集 + 重做打包（PyInstaller 产物 30–60MB，易被杀软误报） | `GOOS=... go build` 一条命令 |

**决定性理由是「要 Windows + Linux」**，不是性能。

## 二、验收标准（唯一标准）

```
同一份真实事件流 → Python 版告警集合 == Go 版告警集合
```

不是「测试通过」，不是「能编译」，是**对拍逐条一致**。字段名、判定顺序、
reasons 数组顺序都必须一致，否则对拍失去意义。

## 三、接口设计（先定接口再写实现）

```go
type Collector interface {
    Name() string
    Mode() string                    // poll | stream
    Interval() time.Duration
    Probe() error                    // nil=可用；错误=不可用原因（如「需要 root」）
    Collect(ctx) ([]model.Event, error)
    Close() error
}
```

`Probe()` 是跨平台的关键：Windows 没有 EndpointSecurity、Linux 没有 ETW，
这些是常态。**把不可用原因显式报给控制台，比静默少采一片数据安全得多**。

其余三层（Enforcer / Store / Detector）同理由接口先行，各平台分别实现。

## 四、目录

```
cmd/atfieldd/           服务入口（--selftest / --once / --once --all）
internal/model/         Event / Finding / Incident（字段与 Python 逐一对齐）
internal/collector/     Collector 接口 + Base + RunOnce
    process.go              判定逻辑（平台无关）
    process_darwin.go       ps -ww -axo ... command=
    process_windows.go      tasklist /fo csv
    process_linux.go        /proc/<pid>/{stat,cmdline}
    network.go              连接判定/差分/事件组装（平台无关）
    network_parse.go        lsof / /proc/net/* / netstat 的纯文本解析（**不带 build tag**）
    network_darwin.go       lsof -nP -i -w
    network_windows.go      netstat -ano（退化路径，完整方案 GetExtendedTcpTable 未做）
    network_linux.go        /proc/net/{tcp,tcp6} + /proc/<pid>/fd 归属
    registry_*.go           各平台采集器注册表（含迁移进度）
```

## 五、平台能力矩阵（诚实版）

| 能力 | macOS | Windows | Linux |
|---|---|---|---|
| 进程表 | `ps` | `tasklist`（**首版无 PPID/命令行**） | `/proc` |
| 连接表 | `lsof`（26+ netstat 失效） | **现状 `netstat -ano`**；应上 `GetExtendedTcpTable` | `/proc/net/*`（TCP） |
| 文件事件 | ES `eslogger`（root+TCC） | ETW（**minifilter 需 WHQL 签名，个人做不了**） | inotify/fanotify/auditd |
| 封禁 | `pfctl` | WFP / netsh | nftables |

**Windows 的检测强度天然低于 macOS**，产品界面必须显示差异，不许假装一样。

## 六、进度

| 模块 | darwin | windows | linux |
|---|---|---|---|
| process | ✅ | ✅（PPID/命令行缺失，已标注） | ✅ |
| network | ✅ lsof（非 root 只见本用户连接） | ✅ `netstat -ano`（**退化路径**，IP Helper 未做） | ✅ /proc/net（仅 TCP，UDP 待做） |
| persistence | ✅ launchd plist（含二进制 plist）/ crontab / /etc/periodic | ✅ 注册表 Run+RunOnce（含 Wow6432Node）/ 启动目录 / 计划任务（**.lnk 不解析目标，服务键未采**） | ✅ cron（/etc/cron*、spool、~/.crontab）+ systemd unit（/etc、~/.config） |
| privileged | ⬜ eslogger | ⬜ ETW（能力有限） | ⬜ auditd |
| session/logstream/integrity/baseline/fileless | ⬜ | — | — |
| detector（规则引擎） | ✅ `internal/detect`，32/32 条规则 + Python 对拍（见 MIGRATION-RULES.md） | | |
| store / api / web（embed 复用现有 app.js） | ⬜ | | |
| enforcer | ⬜ pf | ⬜ WFP | ⬜ nft |

## 七、实测发现（迁移期的高价值教训）

1. **`ps comm=` 会截断路径**：第一版用 `comm=`，把
   `/System/Library/.../com.apple.CloudDocs.iCloudDriveFileProvider` 截成
   `"/System/Library/"`，连进程名都丢了。改用 `-ww ... command=` 从命令行首段取 exe。
2. **系统路径信任必须排除解释器**：`/bin/bash` 在系统目录，若按路径整体信任，
   `bash -c "curl x | sh"` 会一路绿灯。这是**决定检测有效性**的一条，测试里钉住了。
3. **误报要靠白名单收敛，不是靠调阈值**：本机真跑 118 → 59 → 18 → **1** 条：
   - 118→59：修 ps 截断（exe 路径正确后 `exe-in-tmp` 等判定才准）
   - 59→18：隐藏目录白名单（`.hermes`/`.local`/`.cargo` 是正常工具链）
   - 18→1：base64 只在「解释器」或「伴随解码指令」时判（GUI 应用的 argv 天然带 base64）
4. **测试必须双向**：只测「该报的报」会奖励「全判可疑」的实现；每条规则都要有反例。
5. **持久化项的可疑判据必须区分「谁能改它」**：persistence 第一版无差别套规则，
   本机 944 条里报 **51** 条——其中 24 条是 Apple 自己的看门狗
   （`AirPlayUIAgent`/`bluetoothd`/`apsd` 天生 `RunAtLoad`+`KeepAlive`）、
   4 条是 `/System` 里按 CPU 架构缺失的 `cvmsCompAgent`（`prog-missing`）、
   1 条 `kdumpd`（命令行里带 `/tmp`、`/var/tmp`，它本来就写崩溃转储）。
   这些全在 SIP 保护下，攻击者改不了。改为「条目在不可变系统位置时只清点不判定」
   后：51 → **10**，收敛后的 10 条全部可指名（6 个本机自建 Agent + ToDesk/UURemote
   各 2 个带看门狗的远程控制守护进程），没有一条结构性误报。
   教训：**先问「这条记录谁能写」，再问「它长什么样」**。
6. **plist 解析不要自己写二进制解析器**：macOS 上 104/966 个 launchd plist 是
   `bplist00`。手写 offset table 是 150 行易错代码，而 `plutil -convert xml1 -o -`
   是系统自带的权威实现、只读、不改文件。配 path+mtime+size 缓存后，
   真机清点冷 514ms → 热 **8ms**（944 条）。

## 八、network 采集器（三平台已落地）

### 8.1 字段对齐

`kind` / `source` / `path` / `severity` / `subject` 全键同名同义：

| 事件 | path | subject 键 |
|---|---|---|
| `net.connect` | `ip:port`（远端） | `raddr` `rport` `rip` `laddr` `proto` `public` `risky_port` |
| `net.listen` | `addr:port` | `addr` `port` `service` `loopback_only` `proto` |

Python 侧的键集合在 `network_test.go` 里硬编码成契约（`pythonConnKeys` /
`pythonListenKeys`），任一侧加删字段测试先红。

### 8.2 判定（顺序与 Python 版一致，不能换）

```
public = 远端地址非私网
risky  = 远端端口 ∈ C2 集合
public && risky → high ；public → low ；其余 → info
监听：RISKY_LISTEN 命中 → 其档位；仅回环时 high/critical 降 medium；未收录 → info
```

私网判定对齐 `ipaddress.is_private`，并**额外**补了 `100.64.0.0/10`（CGNAT）：
Go 的 `net.IP.IsPrivate` 不含这一段，而 Tailscale 全在段内——本机不补这一条，
每条 tailnet 连接都会被判「公网」，直接多出几十条假 low。这是实测降噪。

### 8.3 平台实现与已知边界

| 平台 | 取数方式 | 边界（必须显示在控制台，不许假装完整） |
|---|---|---|
| darwin | `lsof -nP -i -w` | **非 root 只能看到当前用户的连接**（别人的 socket fd 不可读）；`COMMAND` 截断到 9 字符 |
| linux | `/proc/net/{tcp,tcp6}` + `/proc/<pid>/fd` 反查 inode | 非 root 反查别人的 socket 得到 pid=0；**只做 TCP**（UDP 见 8.6） |
| windows | `netstat -ano` + `tasklist` 取进程名 | **退化路径**：拿不到进程路径、10k 连接时 200–800ms、漏瞬态连接、本地化文本脆。完整方案 `GetExtendedTcpTable`（iphlpapi.dll）**本版未做**，理由见 `network_windows.go` 文件头 |

为什么 darwin 用 `-i` 而不是 `-iTCP -sTCP:ESTABLISHED`：`-sTCP:ESTABLISHED`
会把 LISTEN 行一起滤掉，而同一轮还要产出 `net.listen`；拆两次调用则取样时刻
不同，刚建立又断开的连接会对不上、diff 漏事件。详见 `network_darwin.go`。

Linux 的 `/proc/net/*` 地址是**小端十六进制**（IPv6 是 4 组小端 32 位字），
按大端直读会得到反序地址；`TestParseProcNet` 用 `::1` 钉住了这个坑。

### 8.4 实测（macOS 26 / darwin-arm64 / 非 root）

```
./out/atfieldd-darwin-arm64 --once --all
network: 25ms, 288 events = 235 net.connect + 53 net.listen
         info 265 / low 19 / high 2 / medium 2
```

连采 6 轮（2s 间隔，同一个采集器实例）看稳态：

| 轮次 | 事件数 | 告警档（low 及以上） |
|---|---|---|
| 1（冷启动，全量） | 257 | 22 |
| 2 | 0 | 0 |
| 3 | 0 | 0 |
| 4 | 3 | 0 |
| 5 | 1 | 0 |
| 6 | 2 | 0 |

结论：冷启动是「清单」（整张连接表），之后每轮只有真正新建的连接，稳态
**告警为 0**。剩下 2 条 high 里，`mysqld *:3306` 是真实暴露（该报），
`TencentMeeting → 公网:8080` 是 C2 端口表把 8080 也算进去导致的误报
（建议两版一起把 8080 移出 C2 集合，属于判定口径变更，本版未擅改）。

### 8.5 降噪（白名单收敛，不是调阈值）

过程：302 → 288 事件，low 40 → 19。

1. **多 worker 监听合并**：nginx 13 个 worker 各自 `LISTEN *:80` / `*:443`，
   82 条监听里 24 条是同端口纯重复。按 `(proto, laddr, port)` 合并成一条，
   `subject["workers"]` 记 worker 数。对「这台机器对外开了什么」零信息损失。
2. **代理出站降级**：`verge-mih`（lsof 截断的 verge-mihomo）单进程 59 条公网
   连接，占 low 的四分之一，全是代理节点。按**进程名前缀**白名单（截断导致
   精确匹配一个都命中不了），`public` + `low` 降为 `info` 并标
   `subject["proxy"]=true`——降级不丢弃，「本机通过代理出网」仍留在清单里。
   边界：改名的后门不在名单里，这条只压正常软件噪音，不构成检测能力。

两项都受 `Options["denoise"]` 控制（默认 `true`）。**对拍时置 `false`**，
事件流与 Python 版逐条一致（`TestListenDedupeAcrossWorkers` 与
`TestProxyEgressDowngrade` 都同时测了两条路径）。

### 8.6 与 Python 版的已知差异（对拍时按此解释）

1. **IPv6 方括号**：Python `_from_lsof` 保留 `[2606:...]`，`ipaddress` 解析
   抛异常 → 兜底判私有 → **IPv6 公网连接在 Python 版恒为 info**。Go 剥括号后
   正确判 `public`，方向是「Go 多报、不漏报」。修 Python 侧后差异消失。
2. 三个扩展键 `beacon_hits` / `proxy` / `workers`（前两个只在命中时出现）。
3. Windows 的 `user` 字段为空（Python 走 psutil 有值）。

### 8.7 未做（下一步）

- Linux UDP：`/proc/net/udp` 没有状态列，绑定端口与「监听」不可区分；
- Windows `GetExtendedTcpTable`（见 8.3）；
- macOS root 全覆盖：需以 root 运行，不是代码问题。

## 九、persistence 采集器（三平台已落地）

### 9.1 采集面

| 平台 | 采什么 | 边界（控制台要显示） |
|---|---|---|
| darwin | `~/Library/LaunchAgents`、`/Library/LaunchAgents`、`/Library/LaunchDaemons`、`/System/Library/Launch{Agents,Daemons}` 的 plist（解析 `Program`/`ProgramArguments`/`RunAtLoad`/`KeepAlive`）+ `crontab -l` + `/etc/crontab` + `/etc/cron.d/*` + `/etc/periodic/*` | `/System` 段只清点不判定（SIP 保护，见 9.2）；login items（`backgrounditems.btm`）未做——它的告警语义是「登录项消失」，必须有 state store 才有意义 |
| linux | `/etc/crontab`、`/etc/cron.d/*`、`/etc/cron.{hourly,daily,weekly,monthly}/*`、`/var/spool/cron{,/crontabs}/*`、`~/.crontab`、`crontab -l`、`/etc/systemd/{system,user}/*.service`、`~/.config/systemd/user/*.service` | 包自带的 `/lib/systemd/system/*.service` **刻意不采**（发行版内容、量大、不可写，采进来只会淹没手工投放）；`*.timer`/`.desktop` 未做 |
| windows | `HKLM`/`HKCU` × `Run`/`RunOnce` + `Wow6432Node` 32 位视图（`reg query` 子进程）、两份 `Start Menu\Programs\Startup` 启动目录、`schtasks /query /fo csv /v` | 启动目录的 `.lnk` **不解析目标**（要 COM `IShellLink`），只靠差分发现「多了一个」；服务键 `HKLM\SYSTEM\CurrentControlSet\Services` 未采；非 ASCII 路径在无控制台会话里可能拿不到正确编码，那类条目**不判路径**（否则乱码会全判 `prog-missing`） |

### 9.2 判定（顺序固定，对拍逐字比对 `reasons` 数组）

| # | reason | 判据 | Python 对应 |
|---|---|---|---|
| 1 | `cmd-token:<tok>` | 命令行命中 `SUSPICIOUS_BIN`（表与顺序完全相同） | 命令含可疑片段 |
| 2 | `item-in-temp` | 条目文件在 `/tmp`、`/var/tmp`、`/Users/Shared`、`/dev/shm`、`/var/folders` | plist 位于临时/共享目录 |
| 3 | `perm-too-wide` | 条目文件 group/other 可写（`mode & 022`） | 权限过宽 |
| 4 | `run-at-load-keep-alive` | launchd：`RunAtLoad` + `KeepAlive` | 同名判据 |
| 5 | `prog-in-temp` | 可执行文件在临时/共享目录 | 新增 |
| 6 | `prog-missing` | 可执行文件不存在（指向已删路径） | 新增 |
| 7 | `prog-hidden-dir` | 可执行文件在非白名单隐藏目录（复用 process 的白名单） | 新增 |
| 8 | `root-item-user-binary` | 系统级条目（LaunchDaemon/systemd/HKLM）却指向普通用户可写目录 | 新增（对应 Python 口头上的「来源不明」） |

前四条与 Python 的 `_suspicion()` 顺序/判据一致；后四条是增量，只追加不动前面。
Python 的中文理由串换成英文 slug（与 `process.go` 统一），映射即上表。

**「来源不明」为什么不用「不在 Program Files/系统目录」**：本机 13 个用户
LaunchAgent 里 5 个指向 `~/`、`~/Library/Application Support/`——那是正常软件的
正常装法。只保留「系统级条目 → 用户可写目录」这一条：跨了权限边界才是提权
持久化，同权限内的用户自启项不构成提权。

**`run-at-load-keep-alive` 为什么只对 launchd 生效**：systemd 的等价组合是
`enabled + Restart=always`，nginx/docker/ssh 全中，报它等于全量噪音。

### 9.3 与 Python 版的差异（对拍时按此解释）

1. **首轮对「已可疑」的条目出一枪**（`persistence.suspicious`，`baselined=false`）。
   Python 首轮只建基线、零输出；那在常驻服务里没问题，但 `--once` 跑一次就退出时
   等于什么都看不到。对拍只比 `add`/`modify`/`remove`。
2. **新增 `persistence.remove`**：开机项静默消失是攻击者关防护/清痕迹的动作之一，
   Python 版没有。
3. **token 匹配收紧了词边界**：路径类 token（`/tmp/` 等）仍是子串匹配，命令类
   （`curl`/`wget`/`base64`/`nc`/`osascript`）要求词边界。Python 的裸子串会把
   `curly`、`rsync` 里的 `nc` 也算命中。
4. 条目 ID 与 `subject` 键更多（`id`/`kind`/`scope`/`run_at_load`/`keep_alive`/
   `item_path`），只增不改。

### 9.4 实测（macOS 26 / darwin-arm64 / 非 root）

```
./out/atfieldd-darwin-arm64 --once --all
persistence: 944 items, 10 events, 831ms（冷）
reasons: run-at-load-keep-alive ×10, cmd-token:osascript ×1
```

两轮结果完全一致（944 / 10），无抖动。稳态成本靠 plist 缓存压到 **8ms**：
`TestDarwinPlistCacheWarms` 实测冷 514ms → 热 8ms（940 条 plist，其中 104 条
二进制 plist 走 `plutil`）。

收敛过程（51 → 10）：

| 版本 | 事件数 | 多出来的是什么 |
|---|---|---|
| 第一版（四条规则无差别套） | 51 | 24 条 Apple 看门狗（AirPlayUIAgent/bluetoothd/apsd…）、4 条 `/System` 里按架构缺失的 `cvmsCompAgent`、1 条 `kdumpd`（命令行天然带 `/tmp`） |
| 改为「`/System` 条目只清点不判定」 | **10** | 剩下 10 条可全部指名：6 个本机自建 Agent（hermes/hindsight/magpie/yak 等，`RunAtLoad+KeepAlive` 是它们的正常工作方式）+ ToDesk / UURemote 各 2 个带看门狗的远程控制守护进程 |

这 10 条不是「结构性误报」：它们是**真实存在的看门狗**，只是归属可解释。
要不要静音属于策略问题（白名单配置），不是判定逻辑问题——所以没有硬编码压制。

### 9.5 未做

- login items / `backgrounditems.btm`（依赖 store）；
- windows 服务键、`.lnk` 目标解析；
- linux `.timer` 与 `~/.config/autostart/*.desktop`；
- 签名校验（`codesign --verify` 逐条 fork 太贵，9.2 第 8 条用路径边界替代）。

## 十、下一步

1. 写对拍脚本：`aegis` 与 `aegis-go` 同时喂同一份事件流，diff 告警集
2. 对齐率 100% 后再接 HTTP + embed 前端，替换 8866
3. Python 版保留一版可回退
