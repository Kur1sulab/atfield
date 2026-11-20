package parity

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/Kur1sulab/atfield/internal/model"
)

// RowsFromGo 把 Go 侧 Finding 规范化成 Row。
//
// path / process 不直接挂在 Finding 上，统一从 dedup_key 的第 3、4 段取
// （两侧 dedup_key 的构造口径一致：rule|actor|process|path）。
func RowsFromGo(findings []*model.Finding) []Row {
	out := make([]Row, 0, len(findings))
	for _, f := range findings {
		if f == nil {
			continue
		}
		_, _, process, path := SplitDedupKey(f.DedupKey)
		out = append(out, Row{
			RuleID:      f.RuleID,
			Actor:       f.Actor,
			Process:     process,
			Path:        path,
			Name:        f.Name,
			Severity:    f.Severity,
			Detail:      f.Detail,
			Advice:      f.Advice,
			DedupKey:    f.DedupKey,
			Count:       f.Count,
			FirstDetail: f.FirstDetail,
			LastDetail:  f.LastDetail,
			TS:          f.TS,
			FirstTS:     f.FirstTS,
			LastTS:      f.LastTS,
			EventID:     f.EventID,
			Tags:        f.Tags,
			MITRE:       f.MITRE,
			Reasons:     ReasonsOf(f.Subject),
			Subject:     f.Subject,
		})
	}
	return out
}

// RowsFromPyDicts 把 Python Finding.to_dict() 的列表规范化成 Row。
//
// Python 侧 Finding 不带 subject/path：subject 在 event 子对象里，
// path 从 dedup_key 取（与 Go 侧同一条口径）。
func RowsFromPyDicts(dicts []map[string]any) []Row {
	out := make([]Row, 0, len(dicts))
	for _, d := range dicts {
		dedup := str(d["dedup_key"])
		_, _, process, path := SplitDedupKey(dedup)
		ev, _ := d["event"].(map[string]any)
		if path == "" && ev != nil {
			path = str(ev["path"])
		}
		if process == "" && ev != nil {
			process = str(ev["process"])
		}
		subject, _ := ev["subject"].(map[string]any)
		eventID := ""
		if ev != nil {
			eventID = str(ev["eid"])
		}
		out = append(out, Row{
			RuleID:      str(d["rule_id"]),
			Actor:       str(d["actor"]),
			Process:     process,
			Path:        path,
			Name:        str(d["name"]),
			Severity:    str(d["severity"]),
			Detail:      str(d["detail"]),
			Advice:      str(d["advice"]),
			DedupKey:    dedup,
			Count:       intOf(d["count"]),
			FirstDetail: str(d["first_detail"]),
			LastDetail:  str(d["last_detail"]),
			TS:          floatOf(d["ts"]),
			FirstTS:     floatOf(d["first_ts"]),
			LastTS:      floatOf(d["last_ts"]),
			EventID:     eventID,
			Tags:        strList(d["tags"]),
			MITRE:       strList(d["mitre"]),
			Reasons:     ReasonsOf(subject),
			Subject:     subject,
		})
	}
	return out
}

// ReadFindingsJSONL 读一份告警 JSONL。py=true 时按 Python to_dict() 解析。
func ReadFindingsJSONL(path string, py bool) ([]Row, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()

	var out []Row
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		text := sc.Bytes()
		if len(trimSpace(text)) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(text, &m); err != nil {
			return nil, fmt.Errorf("%s:%d 解析失败: %w", path, line, err)
		}
		if py {
			out = append(out, RowsFromPyDicts([]map[string]any{m})...)
		} else {
			var f model.Finding
			if err := json.Unmarshal(text, &f); err != nil {
				return nil, fmt.Errorf("%s:%d 解析失败: %w", path, line, err)
			}
			out = append(out, RowsFromGo([]*model.Finding{&f})...)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	}
	return fmt.Sprint(v)
}

func intOf(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return int(i)
		}
	case string:
		if i, err := strconv.Atoi(t); err == nil {
			return i
		}
	}
	return 0
}

func floatOf(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case int:
		return float64(t)
	case json.Number:
		if f, err := t.Float64(); err == nil {
			return f
		}
	case string:
		if f, err := strconv.ParseFloat(t, 64); err == nil {
			return f
		}
	}
	return 0
}

func strList(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, it := range t {
			out = append(out, str(it))
		}
		return out
	}
	return nil
}

func trimSpace(b []byte) []byte {
	start := 0
	for start < len(b) && (b[start] == ' ' || b[start] == '\t' || b[start] == '\r' || b[start] == '\n') {
		start++
	}
	end := len(b)
	for end > start && (b[end-1] == ' ' || b[end-1] == '\t' || b[end-1] == '\r' || b[end-1] == '\n') {
		end--
	}
	return b[start:end]
}
