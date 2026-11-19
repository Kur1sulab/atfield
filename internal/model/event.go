// Package model 定义心之壁的归一化数据模型。
//
// 这些结构与 Python 版 atfield/model.py 逐字段对齐——Go 版验收靠的是
// 「同一份真实事件流喂两版，告警集合完全一致」，字段名/语义一旦漂移，
// 对拍就失去意义。改这里必须同步改 Python 侧并重跑对拍。
package model

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// 严重度档位。顺序即强弱，比较用已排序切片的下标。
var SeverityOrder = []string{"info", "low", "medium", "high", "critical"}

// SeverityRank 返回档位序号，未识别按 info 处理（与 Python 侧一致：
// 宁可低估也不让未知字符串把事件抬成高危）。
func SeverityRank(s string) int {
	for i, v := range SeverityOrder {
		if v == s {
			return i
		}
	}
	return 0
}

// Event 一条归一化终端事件。
type Event struct {
	Kind     string         `json:"kind"`
	Source   string         `json:"source"`
	TS       float64        `json:"ts"`
	Host     string         `json:"host,omitempty"`
	User     string         `json:"user,omitempty"`
	PID      *int           `json:"pid,omitempty"`
	PPID     *int           `json:"ppid,omitempty"`
	Process  string         `json:"process,omitempty"`
	Cmdline  string         `json:"cmdline,omitempty"`
	Path     string         `json:"path,omitempty"`
	Severity string         `json:"severity"`
	Subject  map[string]any `json:"subject,omitempty"`
	Raw      map[string]any `json:"raw,omitempty"`
	EID      string         `json:"eid"`
}

// NewEvent 构造事件并补默认值（时间、严重度归一、事件 ID）。
func NewEvent(kind, source string) *Event {
	return &Event{
		Kind:     kind,
		Source:   source,
		TS:       float64(time.Now().UnixNano()) / 1e9,
		Severity: "info",
		EID:      shortID(),
	}
}

// Normalize 兜底：时间缺失补当前、非法严重度降为 info、ID 缺失补生成。
func (e *Event) Normalize() {
	if e.TS <= 0 {
		e.TS = float64(time.Now().UnixNano()) / 1e9
	}
	if SeverityRank(e.Severity) == 0 && e.Severity != "info" {
		e.Severity = "info"
	}
	if e.EID == "" {
		e.EID = shortID()
	}
}

// Finding 一条告警（同一去重键的多次事件聚合为一条，带 count 与首末样本）。
type Finding struct {
	ID          string         `json:"id"`
	RuleID      string         `json:"rule_id"`
	Name        string         `json:"name"`
	Severity    string         `json:"severity"`
	Status      string         `json:"status"`
	FirstTS     float64        `json:"first_ts"`
	LastTS      float64        `json:"last_ts"`
	Count       int            `json:"count"`
	DedupKey    string         `json:"dedup_key"`
	FirstDetail string         `json:"first_detail,omitempty"`
	LastDetail  string         `json:"last_detail,omitempty"`
	Subject     map[string]any `json:"subject,omitempty"`
	Tags        []string       `json:"tags,omitempty"`
	VerifyState string         `json:"verify_state,omitempty"`
}

// Incident 由多条 Finding 关联出来的事件（攻击链）。
type Incident struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Severity string   `json:"severity"`
	TS       float64  `json:"ts"`
	Findings []string `json:"findings,omitempty"`
	Summary  string   `json:"summary,omitempty"`
}

func shortID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return hex.EncodeToString([]byte(time.Now().Format("150405")))
	}
	return hex.EncodeToString(b[:])
}
