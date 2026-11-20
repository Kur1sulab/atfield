package store

// audit.go —— 不可篡改审计链：append-only 哈希链 + HMAC 锚点 + 分片留存。
//
// 逐项对标 Python 版 atfield/audit.py（368 行），语义与字段名保持一致，
// 这样同一份 audit.log 两版都能验。核心不变式：
//
//	记录 n 的 prev == 记录 n-1 的 hash
//	hash = sha256(prev + canonicalJSON(记录去掉 hash 字段))
//	第一条 prev = 64 个 '0'（创世）
//
// 为什么不是「写个日志文件就完事」：日志文件谁都能改。等保/司法取证场景要
// 证明的是「这条记录自写下后没被改过、没被删过、没被整链替换」——只有哈希链
// 能证明前两条，只有带密钥的锚点能证明第三条（攻击者重写整条自洽链时，
// 没有本机密钥就签不出新锚点）。
//
// 能查出来的问题：
//   - 内容被改写 → 重算 hash 不符
//   - 记录被删   → seq 不连续 / prev 断链
//   - 尾部截断   → 最后 seq < 锚点 seq
//   - 整链替换   → 创世 hash 不符 / 锚点 HMAC 不通过

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Genesis 创世前驱：64 个 '0'。
const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// Masked 敏感值脱敏占位符（与 Python 版 MASKED 同字面量）。
const Masked = "***"

// 审计链文件名（与 Python 版同名，可共用一个 data_dir 做交叉验证）。
const (
	FileAuditLog  = "audit.log"
	FileAnchorKey = "anchor.key"
	FileAnchor    = "anchor.json"
)

// AuditConfig 审计链配置（对应 Python cfg["audit"]）。
type AuditConfig struct {
	// Dir 为空时用 <DataDir>/audit。
	Dir string
	// Enabled 关掉后 Append 变成 no-op（返回 skipped），不落任何东西。
	Enabled bool
	// MaxMB 单分片大小上限，超过即封存。
	MaxMB int
	// RetainDays 分片留存天数。
	RetainDays int
	// RetainTotalMB 分片总容量上限。
	RetainTotalMB int
	// AnchorEvery 每多少条写一次锚点。
	AnchorEvery int
}

// DefaultAuditConfig 缺省值与 Python 一致。
func DefaultAuditConfig() AuditConfig {
	return AuditConfig{
		Enabled:       true,
		MaxMB:         8,
		RetainDays:    180,
		RetainTotalMB: 256,
		AnchorEvery:   200,
	}
}

func (c AuditConfig) withDefaults() AuditConfig {
	d := DefaultAuditConfig()
	if c.MaxMB <= 0 {
		c.MaxMB = d.MaxMB
	}
	if c.RetainDays <= 0 {
		c.RetainDays = d.RetainDays
	}
	if c.RetainTotalMB <= 0 {
		c.RetainTotalMB = d.RetainTotalMB
	}
	if c.AnchorEvery <= 0 {
		c.AnchorEvery = d.AnchorEvery
	}
	return c
}

// AuditRecord 一条审计记录。字段名与 Python 版逐字一致。
//
// Detail 用 map[string]any：审计链要能吃任意结构化上下文，
// 提前定死字段等于逼调用方把信息塞进 Result 字符串。
type AuditRecord struct {
	Seq    int            `json:"seq"`
	TS     float64        `json:"ts"`
	Time   string         `json:"time"`
	Action string         `json:"action"`
	Actor  string         `json:"actor"`
	Role   string         `json:"role"`
	Target string         `json:"target"`
	Result string         `json:"result"`
	Detail map[string]any `json:"detail"`
	Prev   string         `json:"prev"`
	Hash   string         `json:"hash"`
}

// AuditInput Append 的入参（对应 Python append 的关键字参数）。
type AuditInput struct {
	Action string
	Actor  string
	Role   string
	Target string
	Result string
	Detail map[string]any
}

// AuditResult Append 的返回（对应 Python 的 {"ok":...}）。
type AuditResult struct {
	OK      bool         `json:"ok"`
	Skipped string       `json:"skipped,omitempty"`
	Error   string       `json:"error,omitempty"`
	Record  *AuditRecord `json:"record,omitempty"`
}

// Anchor 锚点文件内容。
type Anchor struct {
	Seq      int      `json:"seq"`
	Head     string   `json:"head"`
	TS       float64  `json:"ts"`
	Time     string   `json:"time"`
	Segments []string `json:"segments"`
	Sig      string   `json:"sig"`
}

// VerifyResult 链校验结果。
type VerifyResult struct {
	OK       bool     `json:"ok"`
	Records  int      `json:"records"`
	LastSeq  int      `json:"last_seq"`
	Head     string   `json:"head"`
	Problems []string `json:"problems,omitempty"`
	// AnchorOK 锚点校验：false 表示「链自洽但锚点对不上」——
	// 这是整链被替换的典型特征，比单条被改严重得多。
	AnchorOK     bool   `json:"anchor_ok"`
	AnchorDetail string `json:"anchor_detail,omitempty"`
}

// AuditLog 线程安全的追加式审计链。
//
// Append 永不 panic、永不把错误抛给主流程（审计不该把处置流程带崩），
// 失败信息通过 AuditResult.OK=false 回传。
type AuditLog struct {
	mu sync.Mutex

	dir         string
	path        string
	keyPath     string
	anchorPath  string
	maxBytes    int64
	retainDays  int
	retainMB    int
	anchorEvery int
	enabled     bool

	key   []byte
	seq   int
	head  string
	since int
	fh    *os.File
}

// OpenAudit 打开（或新建）审计链，并从文件尾部恢复 seq/head。
func OpenAudit(cfg AuditConfig) (*AuditLog, error) {
	cfg = cfg.withDefaults()
	if cfg.Dir == "" {
		return nil, errors.New("store: 审计链缺少目录")
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("store: 创建审计目录 %s: %w", cfg.Dir, err)
	}
	a := &AuditLog{
		dir:         cfg.Dir,
		path:        filepath.Join(cfg.Dir, FileAuditLog),
		keyPath:     filepath.Join(cfg.Dir, FileAnchorKey),
		anchorPath:  filepath.Join(cfg.Dir, FileAnchor),
		maxBytes:    int64(cfg.MaxMB) * 1024 * 1024,
		retainDays:  cfg.RetainDays,
		retainMB:    cfg.RetainTotalMB,
		anchorEvery: cfg.AnchorEvery,
		enabled:     cfg.Enabled,
	}
	a.key = a.loadKey()
	a.seq, a.head = a.resume()
	return a, nil
}

// Dir 审计目录。
func (a *AuditLog) Dir() string { return a.dir }

// Enabled 是否启用。
func (a *AuditLog) Enabled() bool { return a.enabled }

// ---------------- 初始化 ----------------

// loadKey 读或生成本机锚点密钥（32 字节十六进制文本，0600）。
//
// 密钥丢了就签不出旧锚点——这是设计意图：把密钥和日志一起偷走的人
// 才能伪造锚点，而那意味着主机已经沦陷，链本身也保不住了。
func (a *AuditLog) loadKey() []byte {
	if raw, err := os.ReadFile(a.keyPath); err == nil {
		if v := strings.TrimSpace(string(raw)); len(v) >= 32 {
			return []byte(v)
		}
	}
	buf := make([]byte, 32)
	for i := range buf {
		buf[i] = byte(nowNano() >> (uint(i%8) * 8))
	}
	// 叠一层 sha256 抹掉时间戳的低熵结构
	sum := sha256.Sum256(append(buf, []byte(fmt.Sprint(nowNano(), os.Getpid()))...))
	key := []byte(hex.EncodeToString(sum[:]))
	_ = writeFileAtomic(a.keyPath, key)
	return key
}

// resume 从当前文件尾部恢复 seq/head。损坏时退回创世（不阻断启动）。
//
// 只读尾部 64KB：审计日志可能几十 MB，全量扫描会让启动变慢，
// 而最后一行必然在尾部。
func (a *AuditLog) resume() (int, string) {
	st, err := os.Stat(a.path)
	if err != nil || st.Size() == 0 {
		return 0, Genesis
	}
	fh, err := os.Open(a.path)
	if err != nil {
		return 0, Genesis
	}
	defer fh.Close()
	const tail = 65536
	off := st.Size() - tail
	if off < 0 {
		off = 0
	}
	if _, err := fh.Seek(off, 0); err != nil {
		return 0, Genesis
	}
	buf := make([]byte, st.Size()-off)
	if _, err := fh.Read(buf); err != nil && len(buf) == 0 {
		return 0, Genesis
	}
	lines := splitLines(buf)
	for i := len(lines) - 1; i >= 0; i-- {
		var rec AuditRecord
		if json.Unmarshal(lines[i], &rec) != nil {
			continue
		}
		if rec.Seq > 0 && rec.Hash != "" {
			return rec.Seq, rec.Hash
		}
	}
	return 0, Genesis
}

// ---------------- 写 ----------------

// Append 追加一条审计记录。永不 panic；失败经 AuditResult 回传。
func (a *AuditLog) Append(in AuditInput) AuditResult {
	if a == nil {
		return AuditResult{OK: false, Skipped: "audit disabled"}
	}
	if !a.enabled {
		return AuditResult{OK: false, Skipped: "audit disabled"}
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	seq := a.seq + 1
	now := time.Now()
	rec := AuditRecord{
		Seq:    seq,
		TS:     round3(tsOf(now)),
		Time:   now.Format("2006-01-02 15:04:05"),
		Action: truncate(in.Action, 120),
		Actor:  truncate(orDefault(strings.TrimSpace(in.Actor), "system"), 120),
		Role:   truncate(orDefault(strings.TrimSpace(in.Role), "system"), 40),
		Target: truncate(in.Target, 400),
		Result: truncate(orDefault(strings.TrimSpace(in.Result), "ok"), 120),
		Detail: scrub(in.Detail),
		Prev:   a.head,
	}
	rec.Hash = hashRecord(a.head, rec)

	// 行内容也走同一个规范化器：写出去的字面量必须与算 hash 时用的完全一致。
	// 用 encoding/json 会把 float64(3.0) 写成 "3"，而 hash 那侧按 Python 写成
	// "3.0"——校验时重算必然对不上。
	line, err := canonicalJSON(rec.toMap())
	if err != nil {
		return AuditResult{OK: false, Error: "marshal failed"}
	}
	line += "\n"

	if a.fh == nil {
		fh, err := os.OpenFile(a.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			return AuditResult{OK: false, Error: "open failed"}
		}
		a.fh = fh
	}
	if _, err := a.fh.Write([]byte(line)); err != nil {
		a.fh.Close()
		a.fh = nil
		return AuditResult{OK: false, Error: "write failed", Record: &rec}
	}
	// 审计记录必须真正落盘：不 fsync 的审计链在断电后可能整段消失，
	// 而「断电丢了审计」正是内部人最想要的结局。
	if err := a.fh.Sync(); err != nil {
		return AuditResult{OK: false, Error: "fsync failed", Record: &rec}
	}

	a.seq, a.head = seq, rec.Hash
	a.since++

	needAnchor := a.since >= a.anchorEvery
	if a.maxBytes > 0 {
		if st, err := a.fh.Stat(); err == nil && st.Size() >= a.maxBytes {
			a.seal()
			needAnchor = true
		}
	}
	if needAnchor {
		a.writeAnchor()
	}
	out := rec
	return AuditResult{OK: true, Record: &out}
}

// toMap 把记录摊成 map（审计链的规范形态）。
//
// 为什么不用结构体直接序列化：hash 必须**整个键都不在 body 里**，而不是置空。
// Python 侧写的是 {k: v for k, v in rec.items() if k != "hash"}——置空会多出
// 一个 "hash":""，算出来的 hash 与校验时（键被排除）不一致，写进去的链自己
// 就验不过。用 map 还能保证字段增删不改历史 hash。
func (r AuditRecord) toMap() map[string]any {
	detail := r.Detail
	if detail == nil {
		detail = map[string]any{}
	}
	return map[string]any{
		"seq":    r.Seq,
		"ts":     r.TS,
		"time":   r.Time,
		"action": r.Action,
		"actor":  r.Actor,
		"role":   r.Role,
		"target": r.Target,
		"result": r.Result,
		"detail": detail,
		"prev":   r.Prev,
		"hash":   r.Hash,
	}
}

// hashRecord 计算一条记录的 hash：sha256(prev + 规范化JSON)。
//
// 规范化 = 键排序、无空格、中文不转义、整数绝不写成浮点。哈希只对语义负责，
// 所以序列化方式必须确定——否则同一份内容在不同实现下算出不同 hash。
func hashRecord(prev string, rec AuditRecord) string {
	body := rec.toMap()
	delete(body, "hash")
	s, err := canonicalJSON(body)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256([]byte(prev + s))
	return hex.EncodeToString(sum[:])
}

// hashBody 校验时用：对「磁盘上读出来的原始键值」重算 hash。
//
// 与 hashRecord 的区别是输入是 map 而不是结构体——校验必须按文件里实际的
// 字段集算，多一个字段、少一个字段都该判为改动。hash 字段本身要排除。
func hashBody(prev string, rec map[string]any) string {
	body := make(map[string]any, len(rec))
	for k, v := range rec {
		if k == "hash" {
			continue
		}
		body[k] = v
	}
	s, err := canonicalJSON(body)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256([]byte(prev + s))
	return hex.EncodeToString(sum[:])
}

// intOf / strOf 从校验解码出的 map 里取标量。
func intOf(v any) int {
	switch x := v.(type) {
	case json.Number:
		n, _ := x.Int64()
		return int(n)
	case float64:
		return int(x)
	case int:
		return x
	}
	return 0
}

func strOf(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// ---------------- 锚点 ----------------

// anchorBody 锚点参与签名的字段集：**不含 sig**。
//
// 不能直接对 Anchor 结构体做规范化——那样会把 "sig":"" 也算进 payload，
// 与 Python 侧 {k: v for k, v in anchor.items() if k != "sig"} 差一个键，
// 签名对不上（实测踩过）。
func (a Anchor) anchorBody() map[string]any {
	segs := a.Segments
	if segs == nil {
		segs = []string{}
	}
	return map[string]any{
		"seq":      a.Seq,
		"head":     a.Head,
		"ts":       a.TS,
		"time":     a.Time,
		"segments": segs,
	}
}

func (a *AuditLog) sign(payload string) string {
	mac := hmac.New(sha256.New, a.key)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// writeAnchor 写锚点：当前序号 + 链头 + 累计条数 + 分片清单，用本机密钥签名。
func (a *AuditLog) writeAnchor() {
	now := time.Now()
	body := Anchor{
		Seq:  a.seq,
		Head: a.head,
		// Python 是 round(time.time(), 3)：锚点 ts 保留 3 位小数
		TS:       round3(tsOf(now)),
		Time:     now.Format("2006-01-02 15:04:05"),
		Segments: a.segmentNames(),
	}
	payload, err := canonicalJSON(body.anchorBody())
	if err != nil {
		return
	}
	body.Sig = a.sign(payload)
	raw, err := json.MarshalIndent(body, "", "  ")
	if err != nil {
		return
	}
	if err := writeFileAtomic(a.anchorPath, raw); err != nil {
		return
	}
	a.since = 0
}

// Anchor 读锚点文件（不存在返回零值）。
func (a *AuditLog) Anchor() Anchor {
	var out Anchor
	raw, err := os.ReadFile(a.anchorPath)
	if err != nil {
		return out
	}
	if json.Unmarshal(raw, &out) != nil {
		return Anchor{}
	}
	return out
}

// ---------------- 分片与留存 ----------------

// segmentNames 历史分片文件名（不含当前 audit.log），按「时间戳 → 序号」升序。
//
// 不能直接按文件名字典序排：两版的命名格式不同（Python 是 audit-<stamp>.log，
// Go 是 audit-<stamp>-<seq>.log），同一秒里 '-' 排在 '.' 前面，字典序会把
// Go 的新分片排到 Python 老分片之前——校验时立刻报「seq 不连续」。
// 这里按解析出的 (时间戳, 序号) 排，两种格式混放也能排对。
func (a *AuditLog) segmentNames() []string {
	entries, err := os.ReadDir(a.dir)
	if err != nil {
		return []string{}
	}
	names := make([]string, 0, 4)
	for _, e := range entries {
		n := e.Name()
		if strings.HasPrefix(n, "audit-") && strings.HasSuffix(n, ".log") {
			names = append(names, n)
		}
	}
	sort.Slice(names, func(i, j int) bool {
		ti, si := parseSegmentName(names[i])
		tj, sj := parseSegmentName(names[j])
		if ti != tj {
			return ti < tj
		}
		if si != sj {
			return si < sj
		}
		return names[i] < names[j]
	})
	return names
}

// parseSegmentName 从 audit-<stamp>[-<seq>].log 里取出 (stamp, seq)。
// 解析不出来时返回空串和 0，排序时自然落到最前（老格式/手工文件）。
func parseSegmentName(name string) (string, int) {
	base := strings.TrimSuffix(strings.TrimPrefix(name, "audit-"), ".log")
	stamp, seqStr := base, ""
	if i := strings.LastIndex(base, "-"); i >= 0 {
		// 形如 20261120T001530Z-000042：最后一段是纯数字才算序号
		cand := base[i+1:]
		if cand != "" && strings.Trim(cand, "0123456789") == "" {
			stamp, seqStr = base[:i], cand
		}
	}
	seq := 0
	if seqStr != "" {
		seq, _ = strconv.Atoi(seqStr)
	}
	return stamp, seq
}

// seal 封存当前分片为 audit-<UTC>-<seq>.log，链路跨文件延续（head 已在内存里带着）。
//
// 文件名必须带 seq：只用秒级时间戳时，同一秒内封存两次会得到同一个文件名，
// os.Rename 直接把上一份分片覆盖掉——丢的是整整一段链，而且 Verify 会报
// 「seq 不连续」，让人以为是有人删了日志。（Python 版就是纯时间戳，实测踩过。）
func (a *AuditLog) seal() {
	if a.fh != nil {
		_ = a.fh.Sync()
		_ = a.fh.Close()
		a.fh = nil
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	target := filepath.Join(a.dir, fmt.Sprintf("audit-%s-%06d.log", stamp, a.seq))
	if err := os.Rename(a.path, target); err != nil {
		// 改名失败就继续写原文件：数据通道比分片美观重要
		return
	}
	// 封存动作本身入链——「删了什么、封了什么」都要可证明
	a.appendSealNote(filepath.Base(target))
	a.prune()
}

func (a *AuditLog) appendSealNote(name string) {
	// 注意：这里故意不走 Append 的锁（seal 已在锁内调用）。
	seq := a.seq + 1
	now := time.Now()
	rec := AuditRecord{
		Seq: seq, TS: tsOf(now), Time: now.Format("2006-01-02 15:04:05"),
		Action: "audit:seal", Actor: "system", Role: "system",
		Target: name, Result: "ok",
		Detail: map[string]any{"segment": name}, Prev: a.head,
	}
	rec.Hash = hashRecord(a.head, rec)
	line, err := json.Marshal(rec)
	if err != nil {
		return
	}
	fh, err := os.OpenFile(a.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	_, _ = fh.Write(append(line, '\n'))
	_ = fh.Sync()
	fh.Close()
	a.seq, a.head = seq, rec.Hash
}

// prune 按天数与总量裁剪最老分片。
func (a *AuditLog) prune() {
	names := a.segmentNames()
	if len(names) == 0 {
		return
	}
	cutoff := time.Now().Add(-time.Duration(a.retainDays) * 24 * time.Hour)
	total := int64(0)
	sizes := make([]int64, len(names))
	for i, n := range names {
		if st, err := os.Stat(filepath.Join(a.dir, n)); err == nil {
			sizes[i] = st.Size()
			total += st.Size()
		}
	}
	limit := int64(a.retainMB) * 1024 * 1024
	for i, n := range names {
		path := filepath.Join(a.dir, n)
		st, err := os.Stat(path)
		if err != nil {
			continue
		}
		expired := st.ModTime().Before(cutoff)
		overQuota := total > limit
		if !expired && !overQuota {
			continue
		}
		if err := os.Remove(path); err != nil {
			continue
		}
		total -= sizes[i]
	}
}

// Close 关闭文件句柄（可重复调用）。
func (a *AuditLog) Close() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fh == nil {
		return nil
	}
	err := a.fh.Close()
	a.fh = nil
	return err
}

// Seq / Head 当前链位置（诊断/对拍用）。
func (a *AuditLog) Seq() int {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.seq
}

// Head 当前链头 hash。
func (a *AuditLog) Head() string {
	if a == nil {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.head
}

// ---------------- 读取 ----------------

// Tail 取最近的审计记录（按 seq 倒序），可按 action/actor 子串过滤。
//
// 读的是磁盘而不是内存：审计链的正本永远是文件，内存里只留 seq/head。
// 这样即使进程刚重启、内存还没攒任何记录，面板也能立刻显示历史。
func (a *AuditLog) Tail(limit int, action, actor string) []AuditRecord {
	if a == nil {
		return nil
	}
	var rows []AuditRecord
	for _, p := range a.recordPaths() {
		lines, err := readJSONL(p)
		if err != nil {
			continue
		}
		for _, line := range lines {
			var rec AuditRecord
			if json.Unmarshal(line, &rec) != nil {
				continue
			}
			if action != "" && !strings.Contains(rec.Action, action) {
				continue
			}
			if actor != "" && !strings.Contains(rec.Actor, actor) {
				continue
			}
			rows = append(rows, rec)
		}
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Seq > rows[j].Seq })
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	return rows
}

// Stats 审计链体检信息（面板 / 巡检脚本用）。
type AuditStats struct {
	Enabled       bool   `json:"enabled"`
	Records       int    `json:"records"`
	Head          string `json:"head"`
	Segments      int    `json:"segments"`
	Bytes         int64  `json:"bytes"`
	AnchorSeq     int    `json:"anchor_seq"`
	AnchorHead    string `json:"anchor_head"`
	AnchorTime    string `json:"anchor_time"`
	AnchorEvery   int    `json:"anchor_every"`
	RetainDays    int    `json:"retain_days"`
	RetainTotalMB int    `json:"retain_total_mb"`
}

// Stats 当前链状态快照。
func (a *AuditLog) Stats() AuditStats {
	if a == nil {
		return AuditStats{}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	segs := a.segmentNames()
	st := AuditStats{
		Enabled: a.enabled, Records: a.seq, Head: a.head,
		Segments: len(segs), AnchorEvery: a.anchorEvery,
		RetainDays: a.retainDays, RetainTotalMB: a.retainMB,
	}
	for _, n := range segs {
		if fi, err := os.Stat(filepath.Join(a.dir, n)); err == nil {
			st.Bytes += fi.Size()
		}
	}
	if fi, err := os.Stat(a.path); err == nil {
		st.Bytes += fi.Size()
		st.Segments++
	}
	anc := a.Anchor()
	st.AnchorSeq, st.AnchorHead, st.AnchorTime = anc.Seq, anc.Head, anc.Time
	return st
}

// recordPaths 分片 + 当前文件，按时间正序（校验与读取共用同一顺序）。
func (a *AuditLog) recordPaths() []string {
	paths := make([]string, 0, 4)
	for _, n := range a.segmentNames() {
		paths = append(paths, filepath.Join(a.dir, n))
	}
	return append(paths, a.path)
}

// ---------------- 校验 ----------------

// Verify 全量校验链：逐条重算 hash、检查 prev 链、检查 seq 连续，
// 最后比对锚点。返回的问题列表按发现顺序排列，一条不改链也不会漏报。
func (a *AuditLog) Verify() VerifyResult {
	res := VerifyResult{OK: true}
	if a == nil {
		res.OK = false
		res.Problems = append(res.Problems, "审计链未启用")
		return res
	}

	// 分片 + 当前文件按时间正序拼接校验
	paths := a.recordPaths()

	prev := Genesis
	wantSeq := 1
	first := true
	for _, p := range paths {
		lines, err := readJSONL(p)
		if err != nil {
			continue
		}
		for _, line := range lines {
			// 用 UseNumber 解码：detail 里的整数必须保住字面量。
			// 解到 map[string]any 会把 3 变成 float64(3)，重算 hash 时就成 "3.0"，
			// 于是自己写的链自己验不过——这是最容易踩的一个坑。
			var rec map[string]any
			dec := json.NewDecoder(bytes.NewReader(line))
			dec.UseNumber()
			if err := dec.Decode(&rec); err != nil {
				res.OK = false
				res.Problems = append(res.Problems,
					fmt.Sprintf("%s: 第 %d 条不是合法 JSON", filepath.Base(p), res.Records+1))
				continue
			}
			res.Records++

			seq := intOf(rec["seq"])
			prevRec := strOf(rec["prev"])
			hashRec := strOf(rec["hash"])

			if seq != wantSeq {
				res.OK = false
				res.Problems = append(res.Problems,
					fmt.Sprintf("seq 不连续：期望 %d，实得 %d（有记录被删）", wantSeq, seq))
			}
			if first {
				// 创世记录：prev 必须是 64 个 0，否则整链被替换
				if prevRec != Genesis {
					res.OK = false
					res.Problems = append(res.Problems,
						"创世记录 prev 不是全 0（链被替换）")
				}
				first = false
			}
			if prevRec != prev {
				res.OK = false
				res.Problems = append(res.Problems,
					fmt.Sprintf("seq %d: prev 断链（记录被删或被改写）", seq))
			}
			if want := hashBody(prevRec, rec); want != hashRec {
				res.OK = false
				res.Problems = append(res.Problems,
					fmt.Sprintf("seq %d: hash 不符（内容被改写）", seq))
			}
			prev = hashRec
			res.LastSeq = seq
			res.Head = hashRec
			wantSeq = seq + 1
		}
	}

	// 锚点校验：链自洽但锚点对不上 = 整链被重写
	anc := a.Anchor()
	if anc.Sig == "" {
		res.AnchorDetail = "无锚点"
		return res
	}
	payload, err := canonicalJSON(anc.anchorBody())
	if err != nil {
		res.AnchorDetail = "锚点序列化失败"
		return res
	}
	if a.sign(payload) != anc.Sig {
		res.AnchorOK = false
		res.AnchorDetail = "锚点 HMAC 不通过（密钥不符或锚点被改）"
		res.OK = false
		res.Problems = append(res.Problems, res.AnchorDetail)
		return res
	}
	res.AnchorOK = true
	if res.LastSeq < anc.Seq {
		res.OK = false
		res.AnchorDetail = fmt.Sprintf("尾部被截断：最后 seq %d < 锚点 seq %d", res.LastSeq, anc.Seq)
		res.Problems = append(res.Problems, res.AnchorDetail)
		return res
	}
	// 条数够、链自洽，但链头与锚点不一致 —— 整链被重写成另一条自洽的假链，
	// 或锚点之后的历史被替换。只有锚点能发现这一种。
	if res.LastSeq == anc.Seq && res.Head != anc.Head {
		res.OK = false
		res.AnchorOK = false
		res.AnchorDetail = fmt.Sprintf("链头与锚点不一致：锚点 %s…，实际 %s…",
			short(anc.Head), short(res.Head))
		res.Problems = append(res.Problems, res.AnchorDetail)
		return res
	}
	res.AnchorDetail = fmt.Sprintf("锚点 seq=%d 已覆盖", anc.Seq)
	return res
}

// short 截断 hash 便于展示。
func short(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}

// ---------------- 小工具 ----------------

// scrub 敏感字段脱敏：键名含 pass/token/secret/key/cookie 的字符串值打码。
//
// 审计链要证明「谁做了什么」，但不需要把凭据原样抄一遍——
// 审计日志本身被读走时，不能连带泄露被处置对象的凭据。
//
// 比 Python 版多走一步：**递归进嵌套 map/切片**。Python 的 _scrub 只看顶层，
// 于是 detail={"creds": {"password": "..."}} 会把口令原样写进审计链——
// 一个「看起来脱敏了」的洞。这里递归到底。
func scrub(d map[string]any) map[string]any {
	if d == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(d))
	for k, v := range d {
		if s, ok := v.(string); ok && isSensitive(k) && s != "" {
			out[k] = Masked
			continue
		}
		out[k] = scrubValue(v)
	}
	return out
}

// scrubValue 递归处理嵌套结构。
func scrubValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		return scrub(x)
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = scrubValue(item)
		}
		return out
	}
	return v
}

func isSensitive(key string) bool {
	k := lower(key)
	for _, frag := range []string{"pass", "token", "secret", "apikey", "api_key", "cookie", "credential"} {
		if strings.Contains(k, frag) {
			return true
		}
	}
	return false
}

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func splitLines(buf []byte) [][]byte {
	var out [][]byte
	start := 0
	for i := 0; i <= len(buf); i++ {
		if i < len(buf) && buf[i] != '\n' {
			continue
		}
		line := buf[start:i]
		start = i + 1
		for len(line) > 0 && (line[len(line)-1] == '\r' || line[len(line)-1] == ' ') {
			line = line[:len(line)-1]
		}
		if len(line) > 0 {
			out = append(out, line)
		}
	}
	return out
}
