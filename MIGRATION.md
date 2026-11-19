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
    registry_*.go           各平台采集器注册表（含迁移进度）
```

## 五、平台能力矩阵（诚实版）

| 能力 | macOS | Windows | Linux |
|---|---|---|---|
| 进程表 | `ps` | `tasklist`（**首版无 PPID/命令行**） | `/proc` |
| 连接表 | `lsof`（26+ netstat 失效） | `GetExtendedTcpTable` | `/proc/net/*` |
| 文件事件 | ES `eslogger`（root+TCC） | ETW（**minifilter 需 WHQL 签名，个人做不了**） | inotify/fanotify/auditd |
| 封禁 | `pfctl` | WFP / netsh | nftables |

**Windows 的检测强度天然低于 macOS**，产品界面必须显示差异，不许假装一样。

## 六、进度

| 模块 | darwin | windows | linux |
|---|---|---|---|
| process | ✅ | ✅（PPID/命令行缺失，已标注） | ✅ |
| network | ⬜ lsof | ⬜ IP Helper | ⬜ /proc/net |
| persistence | ⬜ LaunchAgents | ⬜ 注册表/计划任务 | ⬜ systemd/cron |
| privileged | ⬜ eslogger | ⬜ ETW（能力有限） | ⬜ auditd |
| session/logstream/integrity/baseline/fileless | ⬜ | — | — |
| detector（规则引擎） | ⬜ 移植 rules_builtin.py 436 行 | | |
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

## 八、下一步

1. 派并行子代理：network（三平台）+ persistence（三平台）+ detector 移植
2. 写对拍脚本：`aegis` 与 `aegis-go` 同时喂同一份事件流，diff 告警集
3. 对齐率 100% 后再接 HTTP + embed 前端，替换 8866
4. Python 版保留一版可回退
