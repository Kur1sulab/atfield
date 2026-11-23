# 更新日志

本仓有两个实现，版本线各自独立：

| 实现 | 当前位置 | 版本 |
|---|---|---|
| Python | 仓库根（`atfield/`） | `v1.1.x` |
| Go | `go/`（跨平台单二进制） | `0.2.0-go` |

切换的唯一验收标准写在 [`go/MIGRATION.md`](go/MIGRATION.md)：**同一份事件流喂进去，
两版告警集合逐条一致**（字段名、判定顺序、reasons 数组顺序全部一致）。

---

## Go `0.2.0-go` — 2026-11-23

### 新增 · `atfieldd --serve`：从 CLI 骨架变成可常驻服务

`--serve` / `--addr` 把 api + webui（embed）+ enforcer + store + 采集轮询 + detect 串成一条链路：
每个采集器一条 goroutine、错峰 200ms 启动，事件入库 → 引擎 Observe → 告警入库 → 合并回写。

- 默认只监听回环；非回环必须 `--allow-remote` **且** `--token` 两把锁同时打开。
- 封禁只做 dry-run（构造命令、语法校验、不加载），`POST` 需 CSRF 头。
- SIGINT/SIGTERM 优雅退出：停采集 → 落盘（事件与告警各写 `jsonl`）。

### 新增 · 采集器全接线

`Registry` 三平台补齐 `session` / `integrity` / `baseline` / `logstream` / `authlog`，
顺序与 Python `REGISTRY` 逐项对齐（顺序影响控制台展示与对拍输出，改顺序等于改行为）。
实测 10 个采集器、单轮 125 事件；`--selftest` 9 个可用，`privileged` 诚实报
「需要 root 与 Full Disk Access」而不是静默少采。

### 修复 · `totals` 恒为 0

`process` / `network` / `persistence` 原先只返回可疑事件，全量条数被丢弃。
补 `Snapshot()` 后 `totals` 才有真实值（进程 903 / 连接 95 / 持久化 944 条中 10 条可疑）。
`persistence` 的 `known` 加了互斥锁——HTTP 协程会读它，Go 的 map 并发读写是 fatal。

### 实测 · Python ↔ Go 对拍

| 流 | 事件 | Python 告警 | Go 告警 | 对齐率 |
|---|---:|---:|---:|---:|
| Go 自采（3 轮） | 519 | 10 | 10 | 100% |
| Python 自采（3 轮） | 215 | 4 | 4 | 100% |
| Python 守护真实历史 | 46,599 | 1,715 | 1,715 | 100% |

逐字段比较 `severity / name / detail / advice / tags / mitre / reasons(顺序) / subject /
dedup_key / count / ts / first_ts / last_ts`。引擎侧零判定差异。

### 新增 · 覆盖诊断（`internal/parity/coverage.go`）

把「有事件量但两侧 0 告警」的盲区顶到台面上。首轮就抓到一条：
**Go 的进程采集器只发 `process.suspicious`，而规则只认 `process.start`** ——
`AEG-001~006 / 030 / 073` 八条规则在 Go 侧结构上不可达。这是采集器契约不符，不是引擎判定错，
所以口径是「写进报告 + 加测试禁止在规则里加 kind 别名掩盖」，而不是改规则凑数。

### 性能

| 指标 | Python | Go |
|---|---|---|
| 常驻内存 | 76.4 MB | **20.8 MB**（约 1/3.7） |
| 引擎跑 46,599 事件 | 3.30 s | **1.47 s**（2.2×） |
| 交付形态 | `.app` 8.2 MB（内嵌 7.2 MB Python runtime） | 单文件，无运行时依赖 |

冷启动 Go 略慢（6.5–7.3s vs 5.3–5.6s）：采集器串行，logstream 3.0s + fileless 1.6s + authlog 0.8s。

### 已知缺口（诚实清单）

- **关联器未迁**：`incidents` 恒为 0，Go 没有 correlator，也没有 ueba/ndr 衍生事件与融合告警。
- **路由 Go 23 条 / Python 80 条**：缺的 59 条含 users/auth/RBAC/月报/更新/AI/情报/诱饵/playbook 等面板。
- **认证只有令牌模式**：Python 的 `users.json` + scrypt + RBAC + 失败锁定未迁；
  因此默认是「开放模式且只允许回环」，401/403 响应形状与 Python 一致但登录流程不存在。
- **数据目录刻意分离**（`~/.atfield-go` vs `~/.atfield`）：两边 `events.jsonl` / `findings.jsonl`
  字段集不同，交替追加会让双方重放都读到半截记录。合并前必须先统一落盘 schema。
- `loginitem`（securitysw）采集器未迁。

---

## Python `v1.1.3` — 2026-11-19

### 新增 · 情报闸门（总纲 2.1）

CIDR 最长前缀匹配 + 保留网段前置 + 时效衰减；三处写死的等级改由闸门计算。
配套降噪三项（总纲 2.3 / 2.4）：去重键重构、hourly 直方图接入判定、抑制条件字段化。

### 新增 · 凭据静态暴露盘点 + 诱饵端口（总纲 2.5 / 2.6）

### 新增 · 控制台视觉层

接入 AR TEX 共享视觉层，默认深色毛玻璃；告警表展示聚合条数与首末样本。

### 新增 · 只读对拍适配器

`parity_cli.py`：与 Go 侧 `cmd/parity` 同口径逐条喂事件，支撑上面的 100% 对拍。
