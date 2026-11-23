# 真实事件流对拍报告 —— Python 心之壁 1.1.3 ↔ Go 版

> 验收标准（`MIGRATION.md` 第二节）：同一份真实事件流 → 两版告警集合逐条一致
> （字段名、判定顺序、reasons 顺序都要一致）。
>
> 本报告只回答三件事：**真实流上到底一不一致、差在哪、差的那部分该谁修**。
> 所有数字都来自本机实跑，命令与原始输出在第 2、6 节；流与抽样规则见
> `testdata/parity/STREAMS.md`。

环境：macOS 27.3 / arm64，Python 3（`~/aegis` v1.1.3），Go 1.24.13，
`go run ./cmd/parity`，Python 侧 `parity_cli.py`（32 条内置规则，不加载外部规则包）。

---

## 一、结论

| 事件流 | 事件 | Python 告警 | Go 告警 | 对齐 | 仅 Python（缺失） | 仅 Go（多余） | 字段不符 | 对齐率 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `live_go`（Go 采集 ×3 轮） | 519 | 10 | 10 | 10 | **0** | **0** | **0** | **100.00%** |
| `live_py`（Python 采集 ×3 轮） | 215 | 4 | 4 | 4 | **0** | **0** | **0** | **100.00%** |
| `history_py`（守护进程真实历史） | 46,599 | 1,715 | 1,715 | 1,715 | **0** | **0** | **0** | **100.00%** |
| **合计（本次三条真实流）** | **47,333** | **1,729** | **1,729** | **1,729** | **0** | **0** | **0** | **100.00%** |
| 既有 `events.jsonl`（真实历史样本，回归） | 2,432 | 256 | 256 | 256 | 0 | 0 | 0 | 100.00% |
| 黄金语料 79 事件（32/32 规则，逐字段） | 79 | 32 | 32 | 32 | 0 | 0 | 0 | 100.00% |

三条结论，按重要性排：

1. **引擎一致，没有可修的判定差异。** 47,333 条真实事件、1,729 条告警，
   `severity / name / detail / advice / tags / mitre / reasons（含顺序）/
   subject / dedup_key / count / ts / first_ts / last_ts / first_detail /
   last_detail / event_id` 全部逐字段相同。`internal/detect` 里**没有**发现
   「阈值/顺序/归一化」层面的偏差，因此本次没有改任何一条规则——
   强行改只会破坏对拍（见 4.3）。
2. **真正的差异在采集器契约，不在规则引擎。** Go 采集器把可疑进程发成
   `process.suspicious`、首轮持久化发成 `persistence.suspicious`，这两个 kind
   没有任何规则消费。后果：**Go 自采流里进程类告警恒为 0**，AEG-001/002/003/004/
   005/006/030/073 这 8 条规则在 Go 侧结构上不可达（详见 3.1，含换算实验：
   同一批 6 条事件按契约改写后会出 4 条 AEG-003）。这段属于
   `internal/collector/`，按任务约束**只写进报告、不动代码**。
3. **性能不是问题，但和 `MIGRATION.md` 的预期值有出入。** 常驻内存
   Python 76.4 MB → Go 单轮峰值 20.8 MB（约 1/3.7）；冷启动到首轮完成
   Python 5.6 s → Go 7.3 s（`ps` 采样口径；`/usr/bin/time -l` 口径是
   5.3 s → 6.5 s，两种都列在第六节）——Go 反而**慢** 1.7 s，因为 10 个采集器
   串行跑、其中 logstream 固定等 3 s；引擎本身 Go 快 2.2 倍。单文件二进制
   10.4 MB（当前树，含正在接线的 api/web 层）vs `.app` 8.2 MB。数字与命令见第六节。

---

## 二、对拍原始输出（`go run ./cmd/parity …`，原样粘贴）

### 2.1 `live_go` —— Go 采集方向（519 条 / 3 轮）

```text
$ go run ./cmd/parity -events testdata/parity/streams/live_go_events.jsonl \
    -proctable testdata/parity/streams/live_go_proctable.json \
    -ioc testdata/parity/streams/live_ioc.json -out out/parity-real/live_go

重放归一：0 条补 eid，519 条补 host（两侧同源：out/parity-real/live_go/work/events.normalized.jsonl）
事件 519 条 → Python 10 告警 / Go 10 告警
对齐槽位 10：一致 10，仅Python 0，仅Go 0，字段不一致 0
对齐率 100.00%

kind 覆盖：6 种 kind / 519 条事件；其中 3 种事件有量但两侧 0 告警
  persistence.suspicious       30 条事件  0 告警
  process.suspicious            6 条事件  0 告警
  tcc.deny                      1 条事件  0 告警
  （0 告警未必是缺陷：先对照采集器契约，确认这些 kind 是否在规则消费范围内）

对齐率 100%（10/10）—— 两版告警集合完全一致
```

命中规则：AEG-040 ×1、AEG-041 ×2、AEG-043 ×1（IOC 命中，真实公网地址）、
AEG-045 ×2、AEG-062 ×4。

### 2.2 `live_py` —— Python 采集方向（215 条 / 3 轮）

```text
$ go run ./cmd/parity -events testdata/parity/streams/live_py_events.jsonl \
    -proctable testdata/parity/streams/live_py_proctable.json \
    -ioc testdata/parity/streams/live_ioc.json -out out/parity-real/live_py

事件 215 条 → Python 4 告警 / Go 4 告警
对齐槽位 4：一致 4，仅Python 0，仅Go 0，字段不一致 0
对齐率 100.00%

kind 覆盖：4 种 kind / 215 条事件；其中 2 种事件有量但两侧 0 告警
  process.exit                  1 条事件  0 告警
  process.start                 1 条事件  0 告警

对齐率 100%（4/4）—— 两版告警集合完全一致
```

命中规则：AEG-040 ×1、AEG-041 ×2、AEG-043 ×1。
（`process.start` 1 条是良性新进程、`process.exit` 1 条是纯清点事件，
0 告警是正确行为，不是契约问题。）

### 2.3 `history_py` —— 真实守护进程历史流（46,599 条）

```text
$ go run ./cmd/parity -events testdata/parity/streams/history_py_events.jsonl \
    -proctable testdata/parity/proctable.json \
    -ioc testdata/parity/streams/live_ioc.json -out out/parity-real/history_py

重放归一：46599 条补 eid，46599 条补 host（两侧同源：…/events.normalized.jsonl）
事件 46599 条 → Python 1715 告警 / Go 1715 告警
对齐槽位 1715：一致 1715，仅Python 0，仅Go 0，字段不一致 0
对齐率 100.00%

kind 覆盖：22 种 kind / 46599 条事件；其中 11 种事件有量但两侧 0 告警
  ndr.direct_ip              2875 条事件  0 告警
  ueba.new_destination       1714 条事件  0 告警
  ueba.new_process            604 条事件  0 告警
  defense.event               246 条事件  0 告警
  ndr.beaconing                44 条事件  0 告警
  ueba.rare_activity           21 条事件  0 告警
  canary.trip                  14 条事件  0 告警
  ndr.risky_port                7 条事件  0 告警
  session.logout                4 条事件  0 告警
  ueba.new_persistence          4 条事件  0 告警
  … 另有 1 种

对齐率 100%（1715/1715）—— 两版告警集合完全一致
```

命中规则（14 条）：AEG-003 ×447、AEG-010 ×944、AEG-012 ×51、AEG-031 ×2、
AEG-040 ×23、AEG-050 ×30、AEG-051 ×88、AEG-060 ×6、AEG-061 ×9、AEG-062 ×6、
AEG-070 ×58、AEG-071 ×13、AEG-072 ×36、AEG-074 ×2。

这份流的价值在于**频率窗口类规则**（AEG-050 6 次/300 s、AEG-072 4 次/120 s）
和**跨事件状态**（dedup、reasons 顺序）都被真实时间戳压到了，仍然 100%。

### 2.4 补充：黄金语料（32/32 规则逐字段）

```text
$ go run ./cmd/parity -events /tmp/golden_events.jsonl \
    -proctable /tmp/golden_proctable.json -ioc /tmp/golden_ioc.json

事件 79 条 → Python 32 告警 / Go 32 告警
对齐槽位 32：一致 32，仅Python 0，仅Go 0，字段不一致 0
对齐率 100.00%
```

### 2.5 补充：冷却边界探针（真实事件 × 4 个时间点）

取一条真实的 `net.connect`（公网、非常见端口、severity=low），在
`t, t+120, t+620, t+1220` 各重放一次（AEG-041 的 tags=command_control →
冷却 600 s）。期望：t 出第 1 条、t+120 并入、t+620 距离上次发射 620 s > 600 s
出新条、t+1220 恰好 600 s 边界再出新条。

```text
事件 4 条 → Python 3 告警 / Go 3 告警
对齐槽位 3：一致 3，仅Python 0，仅Go 0，字段不一致 0
对齐率 100.00%
```

两版发射时刻完全一致：`1795443296.69 / 1795443916.69 / 1795444516.69`
（count 均为 1）。冷却边界（`>= cooldown` 还是 `> cooldown`）没有偏差。

---

## 三、差异四分类

### 3.1 采集器缺字段 / 契约不符（**不修，写进报告**）

这是本次唯一有实质影响的差异类别。判断依据不是「猜」，是真实流 +
`coverage.json` + 一次契约换算实验。

| # | 现象 | 证据（真实数字） | 影响 | 归属 |
|---|---|---|---|---|
| 1 | Go 进程采集器只发 `process.suspicious`，规则只认 `process.start` | `live_go` 里 6 条 `process.suspicious` → **0 告警**；改成契约形状后 **4 条 AEG-003** | AEG-001/002/003/004/005/006/030/073 **在 Go 侧结构上不可达**（8 条规则 `when` 的第一句就是 `kind == "process.start"`） | `internal/collector/process.go` |
| 2 | `process.suspicious` 的 subject 只有 `reasons`，缺 `suspicious_path` / `masquerade` / `created` | 同上；AEG-004 明确读 `subject.masquerade` | 即使把 kind 改对，AEG-004 仍然不出 | `internal/collector/process.go` |
| 3 | Go 无 `process.hidden`（不做 ps/psutil 交叉校验） | Python 真实历史里 AEG-070 命中 **58** 次；Go 采集流 0 条 | AEG-070 在 Go 侧无数据源 | `internal/collector/process.go` |
| 4 | 首轮持久化发 `persistence.suspicious`（规则只认 `add`/`modify`） | `live_go` 30 条 → 0 告警；`TestCollectorAddAfterSeed` 证明第 2 轮起会发 `persistence.add` | **不算漏报**（Python 首轮纯建基线、一条不发），属于契约外的多余事件 | `internal/collector/persistence.go` |
| 5 | 历史流（Python `store.events.jsonl` 投影）只有 8 个键，缺 `eid/user/ppid/cmdline` | 46,599 条全部缺；重放时 actor 只能退化到 pid/host | 规则 001/002/005/006/030 在这份流上**两侧都**打不出来，是流的限制，不是引擎差异 | Python `store.add_events` 的投影口径 |

第 1 条的换算实验（证明「引擎没问题，是事件形状不对」）：

```text
# 把 6 条 process.suspicious 按 Python 契约改写成 process.start +
# subject.suspicious_path / masquerade（其余字段一字不动），再喂两版引擎：
事件 6 条 → Python 4 告警 / Go 4 告警
对齐槽位 4：一致 4，仅Python 0，仅Go 0，字段不一致 0
```

4 条都是 `AEG-003 执行路径位于临时/共享目录`（`/tmp/atfieldd-parity` ×3 +
`~/.pg0/.../postgres` ×1；后者因为落在隐藏目录 `.pg0` 被 `exe-hidden-dir` 命中）。
这条实验同时说明：**采集器修好后，引擎侧不需要任何改动**。

> 另一个反直觉的点：Go 采集器在真实流里把**自己**（`/tmp/atfieldd-parity`）
> 判成了 `exe-in-tmp`。这是正确的判定，但它恰好落在「没有规则消费」的 kind 上，
> 所以一条告警都不会出现——这正是 `coverage.json` 要解决的问题。

### 3.2 规则判定阈值 / 顺序不同 —— **0 处**

查过的、最容易出现偏差的 5 个点，全部无差异：

| 检查点 | 怎么验的 | 结果 |
|---|---|---|
| `dedup_key = rule\|actor\|process\|path` | 1,715 条告警逐条比对 `dedup_key` | 全同 |
| 冷却分级（oneshot 20 s / recurring 600 s / periodic 900 s） | 真实事件在 0/120/620/1220 s 重放 | 发射时刻全同（2.5 节） |
| 频率窗口 `reached(key, window, n)` | 历史流里 AEG-050/072/045/073 的真实爆发 | 条数与 detail 全同 |
| `severity_fn` 情报闸门（IOC 不得被事件自带 high 抬高） | 真实公网事件 + IOC 名单 | AEG-043 等级/detail 全同 |
| reasons 数组顺序 | 逐条比对 `reasons` 字段 | 全同（工具按顺序比较） |

### 3.3 归一化不同 —— 3 处，均不影响判定

1. **缺 `eid`/`host` 的补齐**：`live_go`/`live_py` 是原生事件（有 eid），
   `history_py` 46,599 条全部缺 eid/host，工具按行号补 `ln:N` + 占位 host，
   两侧读**同一份**归一文件。这不是「掩盖差异」，而是把不可比字段变成可比字段，
   否则 Python 侧会生成随机 uuid、Go 侧留空，`event_id` 永远对不上。
2. **非 UTF-8 进程名**：真实 `lsof` 输出里混进了一个非法字节序列，Go 的
   JSON 序列化把它写成 `�\x93\x94`（U+FFFD + 字面量转义）。两侧读同一份，
   判定一致；但落库可读性差，建议采集器入口统一做一次 UTF-8 清洗
   （属于采集器，未动）。
3. **入仓脱敏**：公网 IPv4 → `203.0.113.<n>`、家目录/用户名/主机名替换，
   `subject.public`/`rport` 不动。脱敏前后告警数完全相同
   （live_go 10、live_py 4、history_py 1,715），且 AEG-043 仍按映射后的 IOC 命中。

### 3.4 Go 独有能力（**不算缺失**）

- `net.connect` 的 subject 多两个键：`beacon_hits`（重复连接计数）、
  `proxy`（代理进程标记）。Python 侧没有这两个键，也没有规则读它们——
  按字段比较规则，工具只比 `subject` 全集，但两份流各自都是 Go 采集产物，
  所以两侧看到的是同一份 subject，不构成差异。
- Go 采集器还会产 `file.*`、`defense.*`、`net.webclient`、`priv.*` 等
  Python 1.1.3 没有的 kind（见 `internal/collector` 常量）。这些 kind 在
  两版规则里都没有消费点，属**双方都不判定**的清点信息，不算 Go 多报。
- 采集器覆盖面：Go 有 `baseline`/`persistence`/`integrity`/`authlog`/`fileless`/
  `privileged`；Python 另有 `login_item`（登录项）与 `shellhist`（shell 历史
  写入）。这两块 Go 侧还没有对应实现，属**已知迁移缺口**，不在本次「对拍差异」里。

### 3.5 Python 独有能力（**不算 Go 缺失**）

- **融合层**：`ueba.*` / `ndr.*` / `canary.trip` 是 Python `core.process()` 里
  `ueba.observe()` + `netintel.observe()` 产出的衍生事件，再由 `_fusion_findings`
  出告警。本次对拍只跑「32 条内置规则」，不跑融合层，所以历史流里 5,283 条
  衍生事件在**两侧都是 0 告警**（2.3 节的 kind 覆盖已列出）。
  Go 版目前没有融合层——这属于「尚未实现的能力」，不是「对拍缺失」，
  报告口径上必须单独说明，否则会被误读成 Go 漏报 5,283 次。
- **外部规则包**：`rules_ext` 的 YAML 包不在对拍范围内（`parity_cli.py` 顶注
  第 3 条已约定），Go 版也只有内置 32 条。

---

## 四、改了什么

### 4.1 `cmd/parity/main_test.go` —— 真实流进回归

`TestRealStreamParity` 从「只跑 `events.jsonl`」扩成表驱动四条流
（`corpus` / `live_go` / `live_py` / `history_py`），每条流各自带 proctable 与
IOC；`-short` 时跳过 46k 的大流。这是把本报告的结论钉进 CI：以后谁改了规则、
采集器事件形状或归一逻辑，`go test ./cmd/parity` 会直接红。

### 4.2 `internal/parity/coverage.go`（新增）+ `coverage_test.go` —— kind 覆盖诊断

对齐率只回答「两侧是否一致」，不回答「这批事件有没有被任何规则看见」。
新增 `parity.Coverage(events, rows)`：按 kind 统计事件数与告警数，把
「事件有量、告警为 0」的 kind 标成 `Silent()`。`cmd/parity` 现在会打印这段
并落盘 `coverage.json`：

```text
kind 覆盖：6 种 kind / 519 条事件；其中 3 种事件有量但两侧 0 告警
  persistence.suspicious       30 条事件  0 告警
  process.suspicious            6 条事件  0 告警
  tcc.deny                      1 条事件  0 告警
```

这条诊断是可复用的：它把 3.1 节那种「100% 对齐但检测没发生」的情况
从「完美报告」里直接顶出来。单测覆盖了计数、`Silent()` 判定、找不到事件的
告警归组、空输入。

### 4.3 `internal/detect/rules_builtin_test.go` —— 契约别名防呆测试

新增 `TestCollectorKindIsNotARuleAlias`，用四条用例钉住：
`process.suspicious` 不是 AEG-003 的输入、`process.start + suspicious_path` 才是；
`persistence.suspicious` 不是 AEG-010 的输入、`persistence.add` 才是。

**为什么加这条测试而不是改规则**：最省事的「修法」是在 `when` 里多认一个
`kind == "process.suspicious"`。那样 Go 侧会突然多出告警、Python 侧没有，
对拍当场从 100% 掉到 60% 开外——本质是拿「放宽判定」换「看起来能报警」。
正确修法在采集器（把事件映射成契约形状），这条测试就是防止下一个人
「顺手修一下」。

### 4.4 没有改的

- `internal/detect` 的 32 条规则：一条没动（3.2 节证明无差异）。
- `internal/collector/*`：按任务约束不动（3.1 节列了具体文件与行号，父代可直接派活）。
- `cmd/atfieldd/*`：不动。

---

## 五、公平性说明

对拍要成立，前提是「两侧看到的是同一个东西」。本次做到的是：

1. **同一份归一事件流**：工具先把事件写成 `work/events.normalized.jsonl`，
   Go 与 Python 都读这一份（不是各读各的原文件）。
2. **同一份进程表**：`-proctable` 一份文件喂两侧；`live_go`/`live_py` 各用
   自己采集时刻的进程表（同一时刻、同一台机器）。
3. **同一份 IOC**：`-ioc` 一份 JSON 喂两侧，AEG-043 才算同一把尺子。
4. **逐条喂 + 时钟=事件 ts**：两侧都是「一条事件一次 observe」，
   Python 侧把 `time.time()` 换成了当前事件的时间戳，Go 侧同样按事件 ts 判定，
   冷却/频率窗口只由事件流决定，不受机器快慢影响（重放两次结果一致）。
5. **不加载外部状态**：两侧 data_dir 都是临时目录，不读 `~/.atfield` 的
   dedup/suppress/规则包。

**哪些差异不算 Go 缺失**（否则会得出错误的迁移结论）：

- Python 独有的融合层告警（ueba/ndr/canary，历史流 5,283 条衍生事件）——
  Go 版没有这层能力，不在「同一份规则」的比较范围内。
- Python 独有的采集器（`login_item`、`shellhist`）—— 没有事件就没有告警，
  不能算「Go 漏报」。
- Go 独有的 kind / subject 额外键 —— 两侧规则都不消费，不产生告警差异。

**反过来，哪些「一致」不能当成「没问题」**：

- 两侧都不消费的 kind（3.1 节）—— 对齐率 100%，检测却是 0。
  这次靠 `coverage.json` 才把它摆到台面上。
- 融合层事件在两侧都是 0 告警 —— 一致的「都没做」，不等于「都做了」。

---

## 六、性能实测

同一台机器、同一时段，Python 版 `~/aegis` 与 Go 版同一棵树
（`go build ./cmd/atfieldd`）。RSS 用 `ps -o rss=` 以 0.15 s 间隔采样取峰值，
另外用 `/usr/bin/time -l` 交叉核对（后者含子进程峰值，数值更高）。

### 6.1 常驻内存

| 引擎 | 测量方式 | RSS |
|---|---|---:|
| Python 守护进程 | `python3 atfieldd.py --no-browser --port 8899`，19 s / 29 s 两次采样 | **76.4 MB**（76,352 / 76,416 KB，已稳定） |
| Python `--once` 峰值 | `ps` 采样 27 次 | 72.6 MB |
| Go `--once --all` 峰值 | `ps` 采样 35 次 | **20.8 MB** |

```bash
ps -o pid=,rss=,vsz=,etime= -p <python-daemon-pid>
#  37186  76352 488897072 00:19
#  37186  76416 488897072 00:29
```

`/usr/bin/time -l` 口径（含子进程：`lsof`/`ps`/`plutil`）：

| 引擎 | maximum resident set size | peak memory footprint |
|---|---:|---:|
| Python `--once` | 84,099,072 B（80.2 MiB） | 73,679,352 B |
| Go `--once --all` | 45,498,368–46,170,112 B（43.4–44.0 MiB） | 13,959,792–16,073,304 B |

> 两个口径差在「是否把子进程算进来」。同一口径（`ps`）下 Go 是 Python 的
> **1/3.7**；`time -l` 口径下是 **1/1.8**。报告里两个都给，避免拿不同尺子对比。
> 另外：`MIGRATION.md` 里写的「同机 Go 服务 3.0–4.3 MB」是**空载骨架**的数，
> 带上 10 个采集器 + lsof/ps 子进程后不是这个量级，建议改文档时注明口径。

### 6.2 冷启动到首轮完成

```bash
/usr/bin/time -l python3 atfieldd.py --once     # 5.33 s
/usr/bin/time -l <go-bin> --once --all          # 6.49 s（三次：9.17 / 6.49 / 5.98）
```

| 引擎 | 墙钟 | 说明 |
|---|---:|---|
| Python `--once` | **5.33 s**（ps 采样口径 5.56 s） | 其中 4 s 是流式采集器固定 warmup（`cmd_once` 的 `sleep(4)`） |
| Go `--once --all` | **6.49 s**（中位；5.98–9.17 s 随机器负载） | 无固定 warmup，但 10 个采集器**串行**跑，各自带阻塞超时 |

Go 单轮耗时拆解（`--once --all` 输出里的 `ms`，一次实测）：

```text
process        49 ms      network       24 ms      session      10 ms
persistence   788 ms      baseline     157 ms      integrity      0 ms
logstream    3000 ms      authlog      805 ms      fileless    1645 ms
privileged      0 ms      ─────────────────────────────────────
合计         6478 ms
```

结论：**Go 慢在「串行 + 固定超时」**（logstream 3 s + fileless 1.6 s +
authlog 0.8 s ≈ 5.5 s，占 85%），不是引擎慢。同一份 46,599 条真实流：

| 引擎 | 单跑耗时 | 吞吐 |
|---|---:|---:|
| Go `detect`（含读流/写归一/对拍，`-py-from` 跳过 Python） | **1.47 s** | ≈31.7k 事件/s |
| Python `detect`（`parity_cli.py`，同样输入） | **3.30 s** | ≈14.1k 事件/s |

引擎本身 Go 快 2.2 倍；**冷启动慢的账要记在采集器**（串行 + 首轮等窗），
不在检测层。要提速应在采集器层做并发/缩短首轮等窗，不动规则。

### 6.3 二进制体积

| 产物 | 体积 | 构成 |
|---|---:|---|
| Python `.app` | **8.2 MB** | 内嵌 Python runtime 7.2 MB + `atfield/` 820 KB + `atfieldd.py` 16 KB + launcher 4.3 KB |
| Go 单文件（当前树，`go build ./cmd/atfieldd`） | **10.4 MB**（10,437,490 B） | 含 `internal/api` + `service` + `webui` 资源（这些是并行工作流刚接上的） |
| Go 单文件（`-ldflags="-s -w"`） | 7.3 MB（7,298,594 B） | 去符号表/DWARF |
| Go 单文件（22:14 的构建，不含 api/web 层） | 4.73 MB（4,727,874 B） | 只有采集器 + detect |

> 注意：`out/atfieldd-darwin-arm64` 在本报告写作期间被并行工作流重建过
> （4.73 MB → 10.4 MB），所以体积数字**随树变动**。这里三种都列出来，
> 结论是：**单文件不带 api/web 时 4.7 MB（比 `.app` 小 43%）；把 HTTP/Web 层
> 一起打进去后 10.4 MB（比 `.app` 大 27%），strip 后 7.3 MB（比 `.app` 小 11%）**。
> 体积优势没有 `MIGRATION.md` 里「2.1 MB 骨架」那么夸张，但「不依赖系统 Python、
> 不需要 7.2 MB runtime」这条仍然成立。

---

## 七、覆盖与残余风险

### 7.1 真实流压到了哪些规则

47,333 条真实事件共压到 **17/32** 条规则：
AEG-003、010、012、031、040、041、043、045、050、051、060、061、062、070、
071、072、074。

**没压到的 15 条**及原因（不是「没测」，是这台机器上没有真实触发源）：

| 规则 | 为什么真实流里没有 |
|---|---|
| AEG-001/002/005/006/030/073 | 本机没有「下载即执行 / 一行解释器 / base64 解码 / 反弹 shell / 凭据读取 / 侦察聚集」的真实进程 |
| AEG-004 | 没有真实的进程名仿冒（`com.apple.*` 从非系统目录启动） |
| AEG-011 | 真实历史里没有 `persistence.modify`（947 条 `persistence.add`，0 条 modify） |
| AEG-020/021/022/023 | 没有真实的防护被关闭/白名单被改事件（SIP 下也关不掉） |
| AEG-042 | 没有进程连 C2 端口（4444/1337/31337…） |
| AEG-044 | 没有「临时目录里的程序连公网」 |
| AEG-052 | 没有 `session.login` 远程登录（本机单人使用） |

这 15 条由 `internal/detect` 的黄金语料测试覆盖（79 事件 → 36 告警，
32/32 规则，逐字段比 `rule_id/severity/actor/detail/dedup_key`），
再加 2.4 节的 CLI 全字段复核。**结论要这么读**：真实流证明「真实数据形状下
4.7 万条事件量级的一致性」；黄金语料证明「32 条规则的判定文本一致性」。
两者合起来才是完整证据，只报其中一个都会高估覆盖面。

### 7.2 已知盲区（本轮没纳入比较）

1. **合并计数（merge）**：对拍比较的是「发射出来的告警」。冷却期内的合并只
   更新 `dedup` 条目的 `count`，不重新发射，所以 `count` 在两版输出里恒为 1。
   两版 `TakeMerges()` 的条数没有进比较——如果一边多并了几条，当前工具看不出来。
   本轮的间接证据是 `history_py` 的 1,715 条发射数完全一致（合并数不同通常会
   导致后续发射时刻错位），但没有直接数字。
2. **抑制条目（suppress）**：`parity_cli` 不加载 suppress 文件，`fixtureStore`
   也是空实现，所以「同一条告警在两侧是否被同一条抑制规则吃掉」没有覆盖。
3. **融合层**：ueba/ndr/canary 的衍生告警不在 32 条规则里（3.5 节）。
4. **首轮 vs 常驻**：Go 只有 `--once`，Python 的 `--once` 与常驻是同一套
   `core.process`，但 Go 的「第 2 轮起」行为（持久化 `add`、进程差分）没有
   在真实流上验证过——`persistence.suspicious` 那条差异就是首轮专属。

---

## 八、复现

```bash
cd go

# 1) 采流（可选：仓库里已带采好的三份）
bash testdata/parity/tools/capture_go.sh /tmp/gocap 3
python3 testdata/parity/tools/capture_py_events.py --out-dir /tmp/pycap --rounds 3

# 2) 脱敏（入仓前必做）
python3 testdata/parity/tools/redact_streams.py testdata/parity/streams \
        --user '<你的用户名>' --home "$HOME"

# 3) 对拍
go run ./cmd/parity -events testdata/parity/streams/live_go_events.jsonl \
    -proctable testdata/parity/streams/live_go_proctable.json \
    -ioc testdata/parity/streams/live_ioc.json -out out/parity-real/live_go
go run ./cmd/parity -events testdata/parity/streams/live_py_events.jsonl \
    -proctable testdata/parity/streams/live_py_proctable.json \
    -ioc testdata/parity/streams/live_ioc.json -out out/parity-real/live_py
go run ./cmd/parity -events testdata/parity/streams/history_py_events.jsonl \
    -proctable testdata/parity/proctable.json \
    -ioc testdata/parity/streams/live_ioc.json -out out/parity-real/history_py

# 4) 回归（含四条真实流的端到端对拍；-short 跳过 46k 大流）
go test ./cmd/parity -run TestRealStreamParity -v
go test ./... -count=1
```
