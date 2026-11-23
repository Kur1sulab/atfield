# testdata/parity/streams —— 真实事件流的来源与口径

这里放的是**真实采集**得到的事件流，不是合成样本。三份流覆盖两个采集方向，
对拍时两边（Go `internal/detect` / Python `atfield.detect`）读的是**同一份归一后
的文件 + 同一份进程表 + 同一份 IOC**，见 `REAL-STREAM-REPORT.md`。

| 文件 | 事件 | 体积 | 来源 | 轮次 |
|---|---|---|---|---|
| `live_go_events.jsonl` | 519 | 192 KB | Go `atfieldd --once --all` | 3 轮（3 次独立进程） |
| `live_py_events.jsonl` | 215 | 85 KB | Python `atfieldd.py --once` 链路 | 3 轮（同一进程，常驻语义） |
| `history_py_events.jsonl` | 46,599 | 13.7 MB | Python 守护进程落盘 `~/.atfield/events.jsonl.1` | 真实时间线切片 |

配套文件：

- `live_go_proctable.json` / `live_py_proctable.json`：各自采集时刻的进程表
  （`{"rows":[{pid,ppid,exe}]}`，两侧共用同一份）。
- `live_ioc.json`：从 `live_go` 流里出现次数最多的公网地址生成的 IOC 名单，
  用来在**真实事件**上打到 AEG-043（情报命中）这条规则。
- `live_py_round_findings.jsonl`：Python 采集那 3 轮里 Python 引擎自己给出的
  告警（3 条），只作旁证，不参与对拍。

## 1. live_go —— Go 采集方向

```bash
go build -o /tmp/atfieldd ./cmd/atfieldd
bash testdata/parity/tools/capture_go.sh /tmp/gocap 3
cp /tmp/gocap/go_events.jsonl testdata/parity/streams/live_go_events.jsonl
cp /tmp/gocap/go_proctable.json testdata/parity/streams/live_go_proctable.json
```

- `--once --all` 每次运行 = 一次冷启动 + 一轮全采集器；连跑 3 次拼成 3 轮时间线。
- kind 分布：`net.connect` 383、`net.listen` 87、`persistence.suspicious` 30、
  `baseline.drift` 12、`process.suspicious` 6、`tcc.deny` 1。
- 注意 `process.suspicious` / `persistence.suspicious` 这两个 kind **没有规则消费**，
  详见报告第三节第 1 类差异。

## 2. live_py —— Python 采集方向

```bash
python3 testdata/parity/tools/capture_py_events.py \
        --out-dir /tmp/pycap --rounds 3 --py-dir ~/aegis
cp /tmp/pycap/py_collector_events.jsonl testdata/parity/streams/live_py_events.jsonl
cp /tmp/pycap/py_proctable.json        testdata/parity/streams/live_py_proctable.json
```

- 脚本走的是 `atfieldd.py --once` 同一条链路：流式采集器先 `start()`、`sleep 4`、
  逐采集器 `run_once()` → `core.process()`（检测/关联/剧本全跑），只是把这一轮
  的事件原样落盘，不改 Python 仓库任何文件。
- kind 分布：`net.connect` 156、`net.listen` 57、`process.start` 1、`process.exit` 1。
- 首轮 process 采集器只建基线（Python 的语义），所以 3 轮只有 2 条进程事件 ——
  这是采集器设计，不是丢数据。

## 3. history_py —— 真实守护进程历史流

```bash
# 保留全部非 net.connect / process.exit 的事件（其余两类是高频噪声，占 78%）
python3 - <<'PY'
import json
src = open('/Users/<you>/.atfield/events.jsonl.1')
out = open('testdata/parity/streams/history_py_events.jsonl', 'w')
for line in src:
    if json.loads(line).get('kind') in ('net.connect', 'process.exit'):
        continue
    out.write(line)
PY
```

**抽样规则（唯一一处抽样，且是「按 kind 过滤」不是「随机抽样」）**：

- 源文件 222,050 条（`~/.atfield/events.jsonl.1`，67 MB），其中
  `net.connect` 145,469 + `process.exit` 29,982 = 175,451 条（79%）是纯噪声；
  全量保留会让单文件突破 20 MB 且几乎不增加告警。
- 保留**其余 24 个 kind 的全部 46,599 条**，顺序、时间戳、字段一律不动。
- 于是这份流覆盖了 14 条规则（含 AEG-010/012/050/051/070/072 这些靠频率窗口
  和跨事件状态才命中的规则），是本目录里最有对拍价值的一份。
- 网络类规则（AEG-041/043/045）由 `live_go` / `live_py` 两份流覆盖，不需要在这里重复。

## 4. 脱敏

`tools/redact_streams.py` 统一处理（口径与 `meta.json` 一致）：

- 公网 IPv4 → `203.0.113.<n>`（按首次出现顺序稳定分配，跨文件一致；
  IOC 文件同步改，所以 AEG-043 照样命中）
- 家目录 → `/Users/USER-A`，用户名 → `USER-A`，主机名 → `HOST-A`
- 私有地址、端口、kind、severity、subject 键集合与数组顺序**不动**

脱敏只改字符串值，不改规则读取的 `subject.public` / `subject.rport`，
所以脱敏前后告警集合完全一致（实测：live_go 10 条、live_py 4 条、
history_py 1715 条，脱敏前后同数同序）。

## 5. 怎么重跑对拍

```bash
cd go
go run ./cmd/parity -events testdata/parity/streams/live_go_events.jsonl \
    -proctable testdata/parity/streams/live_go_proctable.json \
    -ioc testdata/parity/streams/live_ioc.json -out out/parity-real/live_go

go run ./cmd/parity -events testdata/parity/streams/live_py_events.jsonl \
    -proctable testdata/parity/streams/live_py_proctable.json \
    -ioc testdata/parity/streams/live_ioc.json -out out/parity-real/live_py

go run ./cmd/parity -events testdata/parity/streams/history_py_events.jsonl \
    -proctable testdata/parity/proctable.json \
    -ioc testdata/parity/streams/live_ioc.json -out out/parity-real/history_py
```

`go test ./cmd/parity -run TestRealStreamParity` 会把这三份流连同既有
`events.jsonl` 一起跑（`-short` 时跳过 46k 的大流）。
