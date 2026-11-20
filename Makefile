# 心之壁 Go 版 —— 常用目标。
#
# 迁移验收的唯一标准是「同一份事件流喂两版，告警集合完全一致」，
# 所以 `make parity` 才是真正的验收动作；build/test 只是它的前置。

GO ?= go
PYTHON ?= python3
PY_DIR ?= $(HOME)/aegis
EVENTS ?= testdata/parity/events.jsonl
PROCTABLE ?= testdata/parity/proctable.json

.PHONY: all
all: build test

.PHONY: build
build:
	$(GO) build ./...

.PHONY: test
test:
	$(GO) test ./...

# 对拍：100% 一致退出 0，否则非 0（缺口清单见 out/parity/report.md）
.PHONY: parity
parity:
	./scripts/parity.sh

# 重新采集一份真实事件流样本（需要 Python 版仓库）
.PHONY: parity-refresh
parity-refresh:
	./scripts/parity.sh --refresh

# 规则覆盖补全：用手工语料把 32 条规则逐条压一遍（真实流只压得到十几条）
.PHONY: parity-corpus
parity-corpus:
	$(PYTHON) scripts/corpus_to_jsonl.py
	$(GO) build -o out/bin/parity ./cmd/parity
	out/bin/parity -events testdata/parity/corpus.jsonl \
		-proctable testdata/parity/corpus_proctable.json \
		-ioc testdata/parity/corpus_ioc.json \
		-py-dir $(PY_DIR) -out out/parity/corpus

# 两条流都跑：真实流（真实行为）+ 手工语料（规则覆盖）
.PHONY: parity-all
parity-all: parity parity-corpus
	@echo "真实流报告：out/parity/report.md；语料报告：out/parity/corpus/report.md"

# 只跑对拍相关的单测（比较逻辑 + 端到端真实流）
.PHONY: parity-test
parity-test:
	$(GO) test ./internal/parity ./cmd/parity -v

.PHONY: parity-report
parity-report:
	@test -f out/parity/report.md || { echo "先跑 make parity"; exit 1; }
	@cat out/parity/report.md

.PHONY: clean
clean:
	rm -rf out/bin out/parity
