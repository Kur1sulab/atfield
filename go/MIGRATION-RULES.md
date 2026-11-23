# 检测引擎移植对照表（Python → Go）

> 源：`~/aegis/atfield/detect/engine.py`（518 行）、`~/aegis/atfield/detect/rules_builtin.py`（436 行）
> 目标：`~/aegis-go/internal/detect/`
> Python 版本：atfield 1.1.3（v1.1.3，规则引擎 + 情报闸门接线后的版本）

## 结论

**32 条规则中 32 条已移植**（100%），引擎侧 12 个公共入口全部对齐；
`go test ./internal/detect/` 内含 Python 黄金文件对拍：**79 个事件 → 36 条告警，
rule_id / severity / actor / detail / dedup_key 五个字段零差异**。

## 一、规则对照（32/32）

| # | 规则 ID | Python 行 | Python 判定要点 | Go 实现 | Go 行 | 命中/反例用例 |
|---|---|---|---|---|---|---|
| 1 | AEG-001 | rules_builtin.py:63 | `process.start` + `PIPE_EXEC.search(cmdline + " " + path)` | `ruleAEG001` | rules_builtin.go:181 | `TestBuiltinRulesHitAndMiss/AEG-001` |
| 2 | AEG-002 | :72 | `process.start` + `INTERP_ONE_LINER` | `ruleAEG002` | :200 | `/AEG-002` |
| 3 | AEG-003 | :81 | `process.start` + (`subject.suspicious_path` 或 path 前缀 ∈ SUSP_DIRS) | `ruleAEG003` | :219 | `/AEG-003` |
| 4 | AEG-004 | :92 | `process.start` + `subject.masquerade` | `ruleAEG004` | :241 | `/AEG-004` |
| 5 | AEG-005 | :101 | `process.start` + `B64_DECODE` | `ruleAEG005` | :260 | `/AEG-005` |
| 6 | AEG-006 | :110 | `process.start` + `REVSHELL` | `ruleAEG006` | :279 | `/AEG-006` |
| 7 | AEG-010 | :120 | `kind == persistence.add` | `ruleAEG010` | :298 | `/AEG-010` |
| 8 | AEG-011 | :129 | `kind == persistence.modify` | `ruleAEG011` | :317 | `/AEG-011` |
| 9 | AEG-012 | :138 | `persistence.add/modify` + `subject.suspicious` | `ruleAEG012` | :336 | `/AEG-012` |
| 10 | AEG-020 | :149 | `process.start`/`defense.event` + `DISABLE_DEFENSE` | `ruleAEG020` | :358 | `/AEG-020` |
| 11 | AEG-021 | :159 | `kind == defense.cs_invalidated` | `ruleAEG021` | :380 | `/AEG-021` |
| 12 | AEG-022 | :168 | `kind == defense.gatekeeper_override` | `ruleAEG022` | :399 | `/AEG-022` |
| 13 | AEG-023 | :177 | `kind == defense.removed` | `ruleAEG023` | :418 | `/AEG-023` |
| 14 | AEG-030 | :187 | `process.start`+`CRED_ACCESS` 或 `file.open/file.create`+path 命中 | `ruleAEG030` | :437 | `/AEG-030` |
| 15 | AEG-031 | :197 | `kind == credential.access` | `ruleAEG031` | :462 | `/AEG-031` |
| 16 | AEG-040 | :207 | `net.listen` 且 `ev.severity ∈ {high, critical}` | `ruleAEG040` | :481 | `/AEG-040` |
| 17 | AEG-041 | :216 | `net.connect` + `public` + rport ∉ {80,443,53,123,22,993,587,5223,8080,8443} | `ruleAEG041` | :503 | `/AEG-041` |
| 18 | AEG-042 | :226 | `net.connect` + rport ∈ C2 端口集 | `ruleAEG042` | :533 | `/AEG-042` |
| 19 | AEG-043 | :296 | `net.connect` + `_ioc_hit != None`，**`severity_fn=_ioc_severity`** | `ruleAEG043` | :563 | `/AEG-043`、`TestIntelGatePrecedence` |
| 20 | AEG-044 | :308 | `net.connect` + `public` + `exe_of(pid)` 前缀 ∈ SUSP_DIRS | `ruleAEG044` | :584 | `/AEG-044` |
| 21 | AEG-045 | :318 | `net.connect` + `public` + `reached("scan:{pid}", 60, 25)` | `ruleAEG045` | :606 | `/AEG-045`（25 命中 / 24 不命中） |
| 22 | AEG-050 | :330 | `auth.fail` + `reached("authfail:{process}", 300, 6)` | `ruleAEG050` | :630 | `/AEG-050`（6 / 5） |
| 23 | AEG-051 | :339 | `kind == auth.fail` | `ruleAEG051` | :649 | `/AEG-051` |
| 24 | AEG-052 | :348 | `auth.success`/`session.login` 且 (`subject.remote` 或 kind=auth.success) | `ruleAEG052` | :668 | `/AEG-052` |
| 25 | AEG-060 | :359 | `integrity.change` + path 含 authorized_keys/sshd_config/sudoers/pf.conf/etc-hosts | `ruleAEG060` | :690 | `/AEG-060` |
| 26 | AEG-061 | :370 | `kind == integrity.change` | `ruleAEG061` | :714 | `/AEG-061` |
| 27 | AEG-062 | :379 | `kind == baseline.drift` | `ruleAEG062` | :733 | `/AEG-062` |
| 28 | AEG-070 | :389 | `kind == process.hidden` | `ruleAEG070` | :752 | `/AEG-070` |
| 29 | AEG-071 | :398 | `kind == av.detect` | `ruleAEG071` | :771 | `/AEG-071` |
| 30 | AEG-072 | :407 | `tcc.deny` + `reached("tccdeny:{process}", 120, 4)` | `ruleAEG072` | :790 | `/AEG-072`（4 / 3） |
| 31 | AEG-073 | :416 | `process.start` + `DISCOVERY` + `reached("discovery:{root_pid}", 120, 6)` | `ruleAEG073` | :809 | `/AEG-073`（6 / 5） |
| 32 | AEG-074 | :426 | `file.write` 且 path 含 `history` | `ruleAEG074` | :831 | `/AEG-074` |

规则顺序与 Python 注册顺序一致（`builtinRules` 字面量顺序 = 对拍契约，
`TestBuiltinRuleIDsExact` 钉死）。Python 的 `load()` 返回副本，Go 的 `BuiltinRules()`
同样返回副本，避免调用方改动全局规则表。

共享的常量/判定集合与 Python 逐字对齐：

| 对象 | Python | Go |
|---|---|---|
| `SUSP_DIRS` | rules_builtin.py:42 | rules_builtin.go `suspDirs` |
| `PORT_SCAN_THRESHOLD = 25` | :45 | `portScanThreshold` |
| `PIPE_EXEC` / `INTERP_ONE_LINER` / `B64_DECODE` / `REVSHELL` / `CRED_ACCESS` / `DISABLE_DEFENSE` / `DISCOVERY` | :23-40 | `rePipeExec` / `reInterpOneLiner` / `reB64Decode` / `reRevShell` / `reCredAccess` / `reDisableDefense` / `reDiscovery` |
| `_ev_cmd` | :49 | `cmdOf` |
| `_PW = "pa"+"ss"+"word"` | :20 | 同样拆写，避免模板占位符替换 |

## 二、引擎对照（engine.py 518 行）

| Python | 行 | Go | 位置 |
|---|---|---|---|
| `COOLDOWN_ONESHOT/RECURRING/PERIODIC`、`COOLDOWN_TAGS` | 23-34 | 同常量 + `CooldownTags` | rule.go:22-48 |
| `cooldown_for(rule)` | 39 | `CooldownFor` | rule.go:62 |
| `cooldown_for_tags(tags)` | 54 | `CooldownForTags` | rule.go:50 |
| `Ctx`（freq/reached/once/state/counters/intel） | 64-107 | `Ctx`（`Freq`/`Reached`/`Once`/`State`/`Counters`/`Intel`） | rule.go:110-220 |
| `@dataclass Rule` | 110-127 | `Rule`（`Disabled` = !enabled，见下） | rule.go:81-108 |
| `_proc_rows` | 130 | `procRows` | rule.go:235 |
| `root_pid` | 134 | `RootPID` | rule.go:276 |
| `exe_of` | 149 | `ExeOf` | rule.go:297 |
| `dedup_key` | 158 | `DedupKey` | rule.go:311 |
| `_ev_field` | 167 | `evField` | rule.go:321 |
| `_match_cond` | 183 | `matchCond` | rule.go:379 |
| `Engine.__init__` | 214 | `New` | engine.go:135 |
| `_load_dedup` | 238 | `loadDedup` | engine.go:578 |
| `save_dedup` | 249 | `saveDedup` | engine.go:601 |
| `take_merges` | 272 | `TakeMerges` | engine.go:475 |
| `reload_suppress` | 281 | `loadSuppress` | engine.go:192 |
| `save_suppress` | 291 | `SaveSuppress` | engine.go:260 |
| `add_suppress` | 301 | `AddSuppress` | engine.go:285 |
| `remove_suppress` | 339 | `RemoveSuppress` | engine.go:339 |
| `suppress_review_due` | 350 | `SuppressReviewDue` | engine.go:354 |
| `_is_suppressed` | 364 | `isSuppressed` | engine.go:374 |
| `admit` | 406 | `Admit` | engine.go:432 |
| `observe` | 446 | `Observe` | engine.go:485 |
| `_severity` | 490 | `severity` | engine.go:547 |
| `attach_intel` | 505 | `AttachIntel` | engine.go:183 |
| `catalog` | 511 | `Catalog` | engine.go:562 |

## 三、有意的实现差异（全部不改变判定结果）

1. **`enabled` → `Disabled`（取反）**
   Go 零值 bool 是 false；若沿用 `Enabled`，任何忘记赋值的规则会静默失效——
   这正是「漏一条规则」的最短路径。取反后零值 = 启用，`TestDisabledRuleSkipped` 覆盖。

2. **`severity_fn: Optional[Callable[..., Optional[str]]]` → `SeverityFn func(...) string`**
   `""` 表示 Python 的 `None`（闸门判定「不再计分」，整条丢弃）。
   **语义钉死**：有 `SeverityFn` 就以它为最终等级，不与 `ev.Severity` 取 max；
   返回值非法或 panic 同样按「不计分」处理（对应 Python 的 `except → None`）。
   覆盖：`TestSeverityFnIsFinal`（降级 / 升级 / 空 / 非法 / panic 五种）、
   `TestIntelGatePrecedence`（闸门压过明文名单与 allowlist）。

3. **时钟注入 `Ctx.Now` / `Engine.Now`**
   Python 直接调 `time.time()`；Go 抽成可替换函数，只为让频率窗口与冷却的测试
   可确定性推进。默认 `wallClock`，生产行为等价。

4. **情报闸门改为接口 `Intel`**
   Python 依赖 `atfield/intel.py`（547 行，尚未移植）。规则层只固定它用到的四个能力：
   `MatchIP` / `MatchDomain` / `AllowedIP` / `AllowedDomain`；
   `CONF_MAP`（0.15/0.50/0.85）、`score_to_severity`（≥0.7 critical、≥0.4 high、其余 medium）、
   `hit_counts`（score>0）、`hit_severity`（不计分退回 default）按 intel.py:53-103 复刻。
   **`score_to_severity` 没有 low 档**——这是第一版移植时踩过的坑（误以为 0.15 → low），
   对拍时被 AEG-043 的等级差异抓出来。

5. **`str(float)` 的整数值不带 `.0`**
   Python 侧 subject 里的 `128` 是 int，detail 渲染 `128`；Go 的 `encoding/json`
   一律给 float64，若不抹掉 `.0` 会渲染成 `128.0`。这一处差异由对拍发现并修正
   （见 `pyFloat` 注释与 `TestPythonParity` 第 36 条）。

6. **落盘格式**
   `dedup.json` 紧凑 JSON（Python `json.dump` 无 indent），`suppress.json` `indent=1`；
   均为 `*.tmp` + `os.Rename` 原子替换，失败静默（抑制表不是关键路径）。
   `save_dedup` 的 10 秒节流与「>20000 条时按 last_emit 裁 24 小时」逻辑一致。

7. **`Finding.event` 未内嵌**
   Python 的 `Finding.to_dict()` 会把整条 `Event` 序列化进告警；Go 版沿用骨架里的
   `Finding.EventID` + `Finding.TS` 做关联，避免同一份事件在每条告警里重复一份。
   告警集合与五个关键字段不受影响；API 层若需要内嵌事件，在 store 层按 event_id 回查即可。

8. **未移植（不在本层职责内）**
   - `store`（State/Counters/LogAction/ReapplyDedup 由 `Store` 接口 + `NopStore` 兜底）
   - `intel.py` 的匹配/衰减/持久化实现（接口已就位）
   - API/Web 层对 `catalog()` / `take_merges()` 的消费

## 四、验证

```bash
cd ~/aegis-go
go test ./...                 # 含 32 条规则双向用例 + 引擎用例 + Python 对拍
go vet ./...
for os in darwin linux windows freebsd; do GOOS=$os GOARCH=amd64 go build ./...; done
```

对拍方法（可复现）：
1. Python 侧用 `atfield.model.Event` 构造 79 个事件（32 条规则各一组命中样本 +
   10 条反例噪声，含进程表 pid 100←200←300 / 400=/tmp/backdoor / 500=/usr/bin/curl），
   跑 `Engine({"data_dir": ..., "ioc": {"ips": ["203.0.113.9"]}}, store, load())`；
2. 导出 `rule_id/severity/actor/detail/dedup_key` 作为黄金文件
   `internal/detect/testdata/parity_expected_py.json`；
3. Go 侧 `TestPythonParity` 读同一份语料（`testdata/parity_corpus.json`）跑
   `New(...).Observe(events)`，逐条逐字段比对。

当前结果：**79 事件 → 36 条告警，五个字段零差异**。

## 五、下一步

1. 接真实事件流对拍（store/enforcer 接线后，用同一份落盘事件流跑两版）
2. `intel.py` 移植到 `internal/intel`，实现 `detect.Intel` 接口
3. 规则热加载（`Rule.Disabled` 已预留，配置层尚未接）
