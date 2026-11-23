# 心之壁 · Go 重写版

> 本目录是 **[心之壁 AT Field](https://github.com/Kur1sulab/atfield)** 的 Go 重写版，与 Python 版**同仓共存**：
> 仓库根是 Python 现行版本（v1.1.x），`go/` 是 Go 版。
> **两个版本并行存在，直到对拍逐条一致才切换**——不是「写完就换」。

心之壁是一套终端安全态势融合平台（EDR + HIDS + UEBA + NDR + 诱饵 + SOAR）。
本目录用 Go 重做采集层、检测引擎、存储与 HTTP 层，目标是**不依赖系统 Python**地跑在 macOS / Windows / Linux 上。

---

## 一、为什么换（不是性能）

| 指标 | Python 版（实测） | Go 版 |
|---|---|---|
| 常驻内存 | 70.2 MB | 同机 Go 服务 3.0–4.3 MB |
| 安装包 | `.app` 8.2 MB，其中 **7.2 MB 是内嵌 Python runtime** | 单文件，无 runtime |
| 依赖系统 Python | 是 | 否 |
| Windows / Linux | 要重做采集 + 重做打包（PyInstaller 产物易被杀软误报） | `GOOS=… go build` 一条命令 |

**决定性理由是「要出 Windows + Linux」**，不是跑得更快。完整论证见 [MIGRATION.md](MIGRATION.md)。

## 二、当前状态（实测）

| 项 | 结果 |
|---|---|
| `go build ./...` / `go vet ./...` | 干净 |
| `go test ./...` | 全绿（collector / detect / store / api / enforcer / parity / webui） |
| 检测规则移植 | **32 / 32** 条，引擎 12 个公共入口全部对齐 |
| 告警集合对拍 | **2432 事件 → 两侧各 256 条告警，对齐率 100.00%**（仅 Python 0 / 仅 Go 0 / 字段不一致 0） |
| 采集器**已实现** | 10 个：process · network · persistence · privileged · fileless · session · authlog · logstream · integrity · baseline |
| 采集器**已注册启用** | 5 个：process · network · persistence · privileged · fileless |
| store / api / webui / enforcer | 已落地（enforcer 按平台分 pf / WFP / nftables） |

> 已实现但未接入 `Registry` 的采集器不在采集链路上——**这一栏的差距必须显示在控制台，不许假装完整**。

## 三、验收标准（唯一标准）

```
同一份真实事件流  →  Python 版告警集合 == Go 版告警集合
```

不是「测试通过」，不是「能编译」。字段名、判定顺序、`reasons` 数组顺序都必须一致，
否则对拍失去意义。任何一条口径都不能单边改。

对拍命令把它变成可执行的检查：

```bash
# 默认用 testdata/parity/ 下的事件流与进程表，两侧跑同一份
go run ./cmd/parity

# 换事件流 / 加 IOC，或复用已有 Python 产物（不重跑 Python）
go run ./cmd/parity -events fixtures/events.jsonl -ioc fixtures/ioc.json
go run ./cmd/parity -py-from out/parity/py_findings.jsonl
```

对拍工具**只报告不修正**：任何不一致都是迁移缺口，由人决策。100% 一致退出码 0，否则 2。
Python 侧的只读适配器在同一仓库根目录：`../parity_cli.py`。

## 四、目录

```
cmd/atfieldd/            服务入口（--selftest / --once / --once --all）
cmd/parity/              Python ↔ Go 告警集合对拍工具
internal/model/          Event / Finding / Incident（字段与 Python 逐一对齐）
internal/collector/      Collector 接口 + Base + 各平台实现 + 注册表
internal/detect/         规则引擎（32 条内置规则）+ 情报闸门
internal/parity/         对拍判定与报告
internal/store/          状态存储
internal/api/            HTTP 层
internal/webui/          内嵌前端（复用现有 app.js）
internal/enforcer/       封禁执行层
testdata/parity/         对拍素材（事件流 + 进程表 + 黄金告警）
```

## 五、平台能力矩阵（诚实版）

| 能力 | macOS | Windows | Linux |
|---|---|---|---|
| 进程表 | `ps -ww -axo … command=` | `tasklist /fo csv`（首版无 PPID / 命令行） | `/proc/<pid>/{stat,cmdline}` |
| 连接表 | `lsof -nP -i -w`（macOS 26+ 的 `netstat` 已失效） | `netstat -ano`（**退化路径**，`GetExtendedTcpTable` 未做） | `/proc/net/{tcp,tcp6}` + `/proc/<pid>/fd` 反查 |
| 持久化 | launchd plist（含二进制 plist）/ crontab / `/etc/periodic` | 注册表 Run + RunOnce（含 Wow6432Node）/ 启动目录 / 计划任务（`.lnk` 不解析目标） | cron（`/etc/cron*`、spool）+ systemd unit |
| 实时文件事件 | ES `eslogger`（root + 完整磁盘访问） | ETW（minifilter 需 WHQL 签名，个人做不了） | inotify / fanotify / auditd |
| 封禁 | `pfctl` | WFP / netsh | nftables |

**Windows 的检测强度天然低于 macOS**，界面必须显示差异，不许假装一样。
各平台边界（非 root 只见本用户连接、UDP 未做、`COMMAND` 截断 9 字符等）都写在对应源文件的文件头。

## 六、Go 独有的能力

`fileless` 采集器在 Python 侧**没有对应实现**（那边的 `FilelessWatcher` 实际是 shell 历史监控）。
所以它是新增能力，不是迁移项：命令行可疑特征 + 已删除映像（`lsof +L1`）+ 匿名可执行内存段（`vmmap`）。

## 七、用法

```bash
go build -o out/atfieldd ./cmd/atfieldd

./out/atfieldd --selftest        # 只跑采集器可用性自检（不可用原因逐条说明）
./out/atfieldd --once            # 跑一轮采集，输出样本事件
./out/atfieldd --once --all      # 输出全部事件（对拍 / 统计用）
./out/atfieldd --version
```

`Probe()` 会把「需要 root / 需要完整磁盘访问 / 平台无此能力」的原因是显式报出来，
而不是静默少采一片数据。

## 八、文档

- [MIGRATION.md](MIGRATION.md) — 迁移设计、接口先行的理由、各平台边界、**第七节的实测教训**（误报 118→1 的收敛过程等方法论）
- [MIGRATION-RULES.md](MIGRATION-RULES.md) — 32 条规则逐条对照（Python 行号 / Go 行号 / 命中与反例用例）

## 九、许可

与 Python 版一致，见仓库根的 [LICENSE](../LICENSE)。
