package collector

// integrity.go —— 文件完整性监控（FIM）：对安全关键文件做 sha256 基线，
// 变动即告警。
//
// 对标 Python 版 atfield/collectors/integrity.py（118 行）。对齐关系：
//
//	python 字段/判定                        go
//	kind="integrity.change"                 EventIntegrityChange
//	source="integrity"                      "integrity"
//	path=path                               ev.Path
//	process=os.path.basename(path)           ev.Process（baseName）
//	subject.reason ∈ {文件被删除,新增关键文件,内容哈希变化}
//	                                        **同**（逐字，中文原串）
//	                                        + subject.reason_slug（deleted/created/modified）
//	subject.old_digest / new_digest 前 16 位 同（[:16]）
//	subject.size                            subject.size
//	severity: 路径含 authorized_keys/sshd_config/sudoers/pf.conf/hosts → high
//	          否则 medium                   integritySeverity() 同一集合
//	首次见到 → 只建基线不告警               同
//	exists 状态翻转、digest 变化 → 告警      同（三条分支顺序也相同）
//	基线落盘 {path: {digest,mtime,size,exists}}
//	                                        **同一 JSON 形状**，两版可互读
//
// 为什么 reason 保留中文原文而不是换成 slug：subject.reason 是 Python 侧
// 已经存在的字段，改它的值等于改对拍口径。所以 reason 逐字保留中文原文，
// 另加 reason_slug 做机器可读键（规则/竞态判断用 slug，UI 用 reason）。
//
// 平台无关：三平台都用 os.Stat + sha256，没有一条平台分支。唯一的平台差异
// 是**默认监控清单**（macOS 有 pf.conf，Linux 有 /etc/passwd、/etc/shadow，
// Windows 有 hosts 与 RDP 配置），放在 integrity_<platform>.go 里。
//
// 已知边界（产品口径，不许假装完整）：
//   - 只做「内容变没变」，不做「谁改的」。要归因得配合 auditd/ETW，
//     那是 privileged 采集器的活。
//   - 只对**可读**文件算哈希。root 才能读的 /etc/sudoers 在普通用户下
//     digest 恒为空 → 不会误报「内容变化」（Python 同口径：
//     `prev.get("digest") and rec["digest"]` 双非空才比）。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Kur1sulab/atfield/go/internal/model"
)

// EventIntegrityChange 事件类型（与 Python 字面量一致）。
const EventIntegrityChange = "integrity.change"

// 判定理由 slug。
const (
	reasonDeleted  = "deleted"  // 文件被删除
	reasonCreated  = "created"  // 新增关键文件
	reasonModified = "modified" // 内容哈希变化
)

// reasonCN slug → Python 版原文字符串。对拍按这张表比。
var reasonCN = map[string]string{
	reasonDeleted:  "文件被删除",
	reasonCreated:  "新增关键文件",
	reasonModified: "内容哈希变化",
}

// highRiskPathTokens 与 Python 版
// `any(k in path for k in ("authorized_keys","sshd_config","sudoers","pf.conf","hosts"))`
// 同集同序。注意是**子串**匹配不是路径段匹配——/etc/hosts.deny 也算 hosts，
// 这是原版行为，照抄（宁高勿低）。
var highRiskPathTokens = []string{
	"authorized_keys", "sshd_config", "sudoers", "pf.conf", "hosts",
}

// integritySeverity 严重度判定——**唯一**一处，三平台共用。
func integritySeverity(path string) string {
	for _, k := range highRiskPathTokens {
		if strings.Contains(path, k) {
			return "high"
		}
	}
	return "medium"
}

// integrityRecord 基线里一条记录的落盘形状。
// 字段名与 Python 版 integrity.json 逐字相同（digest/mtime/size/exists），
// 这样一台机器从 Python 版切到 Go 版不需要重新建基线。
type integrityRecord struct {
	Digest string  `json:"digest"`
	MTime  float64 `json:"mtime"`
	Size   int64   `json:"size"`
	Exists bool    `json:"exists"`
}

// integrityRow 本轮观测到的一行（对应 Python 的 rec + rows 元素）。
type integrityRow struct {
	Path     string  `json:"path"`
	Exists   bool    `json:"exists"`
	Digest   string  `json:"digest"` // 已截断到 16 位（与 Python rows 一致）
	MTime    float64 `json:"mtime"`
	Size     int64   `json:"size"`
	Readable bool    `json:"readable"`
	Watched  bool    `json:"watched"`
}

// Integrity 文件完整性采集器。
type Integrity struct {
	Base

	mu      sync.Mutex
	paths   []string
	state   string // 基线文件绝对路径
	known   map[string]integrityRecord
	loaded  bool
	rows    []integrityRow
	changed int
	missing []string

	// hashFn 测试注入（生产用 sha256File）
	hashFn func(string) string
	// statFn 测试注入（生产用 os.Stat）
	statFn func(string) (os.FileInfo, error)
}

// NewIntegrity 构造并自检。
func NewIntegrity(cfg Config) Collector {
	ig := &Integrity{known: map[string]integrityRecord{}}
	interval := 45 * time.Second // Python interval = 45.0
	if cfg.Interval > 0 {
		interval = cfg.Interval
	}
	ig.paths = integrityWatchPaths(cfg)
	ig.state = filepath.Join(integrityDataDir(cfg), "integrity.json")
	ig.hashFn = sha256File
	ig.statFn = os.Stat
	ig.Init("integrity", ModePoll, interval, ig.probe)
	if !cfg.WantEnabled() {
		ig.Status.Enabled = false
	}
	return ig
}

// probe 可用性自检：监控清单非空 + 基线目录可写。
//
// 为什么检查「可写」而不是「存在」：首次运行时基线文件本来就不存在，
// 那是最正常的状态；但目录不可写意味着每轮都要重算全部哈希且永远建不起
// 基线，那时告警会变成「每轮都报一遍所有文件被改」——比不采更糟。
func (ig *Integrity) probe() error {
	if len(ig.paths) == 0 {
		return fmt.Errorf("监控清单为空（watch_paths 未配置）")
	}
	dir := filepath.Dir(ig.state)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("基线目录不可用: %v", err)
	}
	probe := filepath.Join(dir, ".integrity-probe")
	if err := os.WriteFile(probe, []byte("ok"), 0o600); err != nil {
		return fmt.Errorf("基线目录不可写: %v", err)
	}
	_ = os.Remove(probe)
	return nil
}

// Items 监控清单条数（清点用）。
func (ig *Integrity) Items() int {
	ig.mu.Lock()
	defer ig.mu.Unlock()
	return len(ig.paths)
}

// Snapshot 等价于 Python 的 store.set_state("integrity", ...)，键名相同。
func (ig *Integrity) Snapshot() map[string]any {
	ig.mu.Lock()
	defer ig.mu.Unlock()
	return map[string]any{
		"files":   ig.rows,
		"ts":      nowSeconds(),
		"changed": ig.changed,
		"missing": ig.missing,
	}
}

// load 读基线（只读一次；读不到按空基线处理，与 Python 的 except 分支同口径）。
func (ig *Integrity) load() {
	if ig.loaded {
		return
	}
	ig.loaded = true
	data, err := os.ReadFile(ig.state)
	if err != nil {
		return
	}
	var known map[string]integrityRecord
	if err := json.Unmarshal(data, &known); err != nil {
		return // 基线损坏 → 当空基线，重建（不因为一个坏文件就永远告警）
	}
	if known != nil {
		ig.known = known
	}
}

// save 原子写基线（tmp + rename）。写失败不报错：本轮告警已经产出了，
// 落盘失败只会让下一轮重报一次，比丢事件安全。
func (ig *Integrity) save() {
	data, err := json.MarshalIndent(ig.known, "", " ")
	if err != nil {
		return
	}
	tmp := ig.state + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, ig.state)
}

// Collect 采一轮。
func (ig *Integrity) Collect(ctx context.Context) ([]model.Event, error) {
	ig.mu.Lock()
	defer ig.mu.Unlock()
	ig.load()

	now := nowSeconds()
	var events []model.Event
	rows := make([]integrityRow, 0, len(ig.paths))
	dirty := false
	changed, missing := 0, []string(nil)

	for _, path := range ig.paths {
		select {
		case <-ctx.Done():
			return events, ctx.Err()
		default:
		}

		rec := integrityRecord{}
		readable := false
		fi, err := ig.statFn(path)
		exists := err == nil
		if exists {
			rec.MTime = float64(fi.ModTime().UnixNano()) / 1e9
			rec.Size = fi.Size()
			rec.Exists = true
			// os.access 的 Go 等价物：直接试着开。Python 用 os.access(path, R_OK)，
			// 那个在 root 下对 0644 也返回 True，与「真能读」一致。
			if fh, oerr := os.Open(path); oerr == nil {
				readable = true
				fh.Close()
			}
			if readable {
				rec.Digest = ig.hashFn(path)
			}
		}

		prev, known := ig.known[path]
		if !known {
			// 首次见到 → 建基线，不告警（Python: prev is None 分支）
			ig.known[path] = rec
			dirty = true
		} else {
			reason := ""
			switch {
			case prev.Exists && !exists:
				reason = reasonDeleted
			case !prev.Exists && exists:
				reason = reasonCreated
			case exists && prev.Digest != "" && rec.Digest != "" && prev.Digest != rec.Digest:
				reason = reasonModified
			}
			if reason != "" {
				events = append(events, *ig.changeEvent(path, prev, rec, reason, now))
				ig.known[path] = rec
				dirty = true
			}
		}

		if exists {
			if readable {
				changed++
			}
		} else {
			missing = append(missing, path)
		}
		rows = append(rows, integrityRow{
			Path: path, Exists: exists, Digest: clip(rec.Digest, 16),
			MTime: rec.MTime, Size: rec.Size, Readable: readable, Watched: true,
		})
	}

	if dirty {
		ig.save()
	}
	ig.rows = rows
	ig.changed = changed
	ig.missing = missing
	return events, nil
}

// changeEvent 组装一条 integrity.change。
func (ig *Integrity) changeEvent(path string, prev, cur integrityRecord, reason string, now float64) *model.Event {
	ev := model.NewEvent(EventIntegrityChange, "integrity")
	ev.TS = now
	ev.Path = path
	ev.Process = filepath.Base(path)
	ev.Severity = integritySeverity(path)
	// reason 直接放 Python 版的原文字符串（"文件被删除" 等），逐字对拍；
	// reason_slug 是机器可读键（deleted/created/modified），给规则与竞态判断用。
	// 为什么不让 reason 只放 slug：subject.reason 是 Python 侧已有的字段，
	// 改它的值等于改对拍口径；加一个键则不影响比对。
	ev.Subject = map[string]any{
		"reason":      reasonCN[reason],
		"reason_slug": reason,
		"old_digest":  clip(prev.Digest, 16),
		"new_digest":  clip(cur.Digest, 16),
		"size":        cur.Size,
	}
	return ev
}

// sha256File 流式计算 sha256（64KB 块，与 Python 的 iter(lambda: f.read(65536)) 同粒度）。
// 读失败返回空串（Python 同口径：except 返回 ""），空串不参与比较。
func sha256File(path string) string {
	fh, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer fh.Close()
	h := sha256.New()
	buf := make([]byte, 64*1024)
	for {
		n, err := fh.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return ""
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// integrityWatchPaths 监控清单：Options["watch_paths"] 覆盖，否则用平台默认。
//
// 配置形状与 Python 的 cfg["watch_paths"] 一致（顶层字符串数组）；
// Go 版 Config 只有 Options 一个自由字典，所以约定 Options["watch_paths"]。
func integrityWatchPaths(cfg Config) []string {
	if raw, ok := cfg.Options["watch_paths"]; ok {
		var list []string
		switch v := raw.(type) {
		case []string:
			list = v
		case []any:
			for _, e := range v {
				if s, ok := e.(string); ok && s != "" {
					list = append(list, s)
				}
			}
		case string:
			for _, s := range strings.Split(v, ",") {
				if s = strings.TrimSpace(s); s != "" {
					list = append(list, s)
				}
			}
		}
		if len(list) > 0 {
			return dedupeStrings(expandHome(list))
		}
	}
	return dedupeStrings(expandHome(platformDefaultWatchPaths()))
}

// integrityDataDir 基线目录：Options["data_dir"] 覆盖，否则 ~/.atfield
// （与 Python config.DATA_DIR 同一默认值，两版共用同一份基线文件）。
func integrityDataDir(cfg Config) string {
	if v, ok := cfg.Options["data_dir"].(string); ok && v != "" {
		return expandHomeOne(v)
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".atfield")
	}
	return ".atfield"
}

// expandHome 展开 ~ 前缀（Go 没有 os.path.expanduser，手写）。
func expandHome(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		out = append(out, expandHomeOne(p))
	}
	return out
}

func expandHomeOne(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return p
		}
		if p == "~" {
			return home
		}
		return filepath.Join(home, p[2:])
	}
	return p
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
