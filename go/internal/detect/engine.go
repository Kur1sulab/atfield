package detect

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Kur1sulab/atfield/internal/model"
)

// 降噪三件套（engine.py 顶注，09-soc-soar §6.4 P0）：
//  1. 去重键 = rule.id|actor|process|path —— 稳定身份，不含 detail；
//     detail 抖动只并入已有告警并计数，不新开告警。
//  2. 冷却按规则类型分级：周期行为类 10–15 分钟，一次性行为类保持短冷却。
//  3. 抑制条件字段化：字段 equality/regex + 作用域(rule_id+actor) + 过期 + 复审提示，
//     保留审计与命中计数；旧 contains 子串条目仍兼容（标记 deprecated）。

// Store 引擎依赖的持久层最小面。Python 侧是 atfield/store.py 的 Store 实例；
// Go 版由 store 包实现，没接上时用 NopStore（单测/独立引擎）。
type Store interface {
	State(name string) any
	Counters() map[string]int
	LogAction(actor, action, detail, note string)
	ReapplyDedup(entries map[string]DedupEntry)
}

// NopStore 空实现：无状态、不落盘。
type NopStore struct{}

func (NopStore) State(string) any                   { return nil }
func (NopStore) Counters() map[string]int           { return map[string]int{} }
func (NopStore) LogAction(_, _, _, _ string)        {}
func (NopStore) ReapplyDedup(map[string]DedupEntry) {}

// DedupEntry 一条去重身份的状态（engine.py:240-247 的 JSON 结构）。
type DedupEntry struct {
	FID         string  `json:"fid"`
	Count       int     `json:"count"`
	FirstTS     float64 `json:"first_ts"`
	LastTS      float64 `json:"last_ts"`
	FirstDetail string  `json:"first_detail"`
	LastDetail  string  `json:"last_detail"`
	LastEmit    float64 `json:"last_emit"`
}

// Merge 一次并入（前端拿它更新既有告警卡片）。
type Merge struct {
	FID        string  `json:"fid"`
	Count      int     `json:"count"`
	LastDetail string  `json:"last_detail"`
	LastTS     float64 `json:"last_ts"`
	DedupKey   string  `json:"dedup_key"`
}

// SuppressItem 抑制条目（engine.py:301-333）。
type SuppressItem struct {
	RuleID     string         `json:"rule_id"`
	Actor      string         `json:"actor"`
	Fields     map[string]any `json:"fields,omitempty"`
	Note       string         `json:"note"`
	Added      float64        `json:"added"`
	Hits       int            `json:"hits"`
	LastHit    float64        `json:"last_hit"`
	ReviewDays float64        `json:"review_days"`
	Expires    float64        `json:"expires"`
	// Contains 旧写法：子串匹配，过宽，已 deprecated。
	Contains   string `json:"contains,omitempty"`
	Deprecated string `json:"deprecated,omitempty"`
}

// SuppressResult 与 Python 侧返回 dict 的键一一对应。
type SuppressResult struct {
	OK     bool          `json:"ok"`
	Detail string        `json:"detail,omitempty"`
	Count  int           `json:"count,omitempty"`
	Item   *SuppressItem `json:"item,omitempty"`
}

// ReviewDue 到期复审项。
type ReviewDue struct {
	Index  int           `json:"index"`
	Reason string        `json:"reason"`
	Item   *SuppressItem `json:"item"`
}

// CatalogEntry 规则目录项，键名与 engine.py:511-518 完全一致。
type CatalogEntry struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Severity        string   `json:"severity"`
	Tags            []string `json:"tags"`
	MITRE           []string `json:"mitre"`
	Advice          string   `json:"advice"`
	Description     string   `json:"description"`
	Cooldown        float64  `json:"cooldown"`
	DynamicSeverity bool     `json:"dynamic_severity"`
}

// Engine 规则引擎。
type Engine struct {
	cfg   Config
	store Store
	rules []Rule
	ctx   *Ctx

	dedup   map[string]*DedupEntry
	merges  []Merge
	ddPath  string
	ddDirty bool
	ddSaved float64

	// Suppress 抑制条目（持久化到 suppress.json）。
	Suppress     []SuppressItem
	Suppressed   int
	SuppressHits int
	supPath      string
	supSaved     float64
	supDirty     bool

	// MergedTotal 累计并入次数。
	MergedTotal int

	// Intel 情报闸门（engine.py:505-509）。
	Intel Intel

	// Now 时钟注入点（测试用），默认 wallClock。
	Now func() float64
}

// New 构造引擎。rules 传 BuiltinRules() 即为内建规则集。
func New(cfg Config, store Store, rules []Rule) *Engine {
	if store == nil {
		store = NopStore{}
	}
	e := &Engine{cfg: cfg, store: store, Now: wallClock, dedup: map[string]*DedupEntry{}}
	for _, r := range rules {
		if r.Disabled {
			continue
		}
		e.rules = append(e.rules, r)
	}
	e.ctx = &Ctx{
		store: store,
		cfg:   cfg,
		freq:  map[string][]float64{},
		fired: map[string]float64{},
		Now:   func() float64 { return e.Now() },
	}
	dir := cfg.DataDir
	if dir == "" {
		dir = defaultDataDir()
	}
	e.ddPath = filepath.Join(dir, "dedup.json")
	e.supPath = filepath.Join(dir, "suppress.json")
	e.loadDedup()
	e.loadSuppress()
	return e
}

func defaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ".atfield"
	}
	return filepath.Join(home, ".atfield")
}

// Rules 返回已装载规则的副本（顺序即求值/输出顺序）。
func (e *Engine) Rules() []Rule {
	out := make([]Rule, len(e.rules))
	copy(out, e.rules)
	return out
}

// Ctx 暴露规则上下文（融合层/take_merges 之外的调用方用）。
func (e *Engine) Ctx() *Ctx { return e.ctx }

// AttachIntel 把情报闸门注入规则上下文（engine.py:505-509）。
func (e *Engine) AttachIntel(intel Intel) {
	e.Intel = intel
	if e.ctx != nil {
		e.ctx.Intel = intel
	}
}

// ---------------- 抑制（engine.py:214-403） ----------------

func (e *Engine) loadSuppress() {
	raw, err := os.ReadFile(e.supPath)
	if err == nil {
		var items []SuppressItem
		if json.Unmarshal(raw, &items) == nil && items != nil {
			e.Suppress = items
			e.normalizeSuppress()
			return
		}
	}
	if len(e.cfg.Suppress) > 0 {
		e.Suppress = append([]SuppressItem(nil), e.cfg.Suppress...)
		e.normalizeSuppress()
	}
}

func (e *Engine) normalizeSuppress() {
	for i := range e.Suppress {
		if e.Suppress[i].ReviewDays == 0 {
			e.Suppress[i].ReviewDays = SuppressReviewDays
		}
		if e.Suppress[i].Fields == nil {
			e.Suppress[i].Fields = map[string]any{}
		}
	}
}

func suppressFromMap(m map[string]any) SuppressItem {
	it := SuppressItem{
		RuleID:   strOf(m["rule_id"]),
		Actor:    strOf(m["actor"]),
		Note:     strOf(m["note"]),
		Added:    floatOf(m["added"]),
		Hits:     intOf(m["hits"]),
		LastHit:  floatOf(m["last_hit"]),
		Contains: strOf(m["contains"]),
		Expires:  floatOf(m["expires"]),
	}
	if rd, ok := m["review_days"]; ok && rd != nil {
		it.ReviewDays = floatOf(rd)
	} else {
		it.ReviewDays = SuppressReviewDays
	}
	if f, ok := m["fields"].(map[string]any); ok {
		it.Fields = f
	}
	return it
}

func floatOf(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		if err != nil {
			return 0
		}
		return f
	}
	return 0
}

// SaveSuppress 落盘（原子替换，失败静默——与 Python 一致，抑制表不是关键路径）。
func (e *Engine) SaveSuppress() {
	dir := filepath.Dir(e.supPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	buf, err := json.MarshalIndent(e.Suppress, "", " ")
	if err != nil {
		return
	}
	tmp := e.supPath + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o644); err != nil {
		return
	}
	if err := os.Rename(tmp, e.supPath); err != nil {
		_ = os.Remove(tmp)
		return
	}
	e.supDirty = false
}

// AddSuppress 新增抑制条目（engine.py:301-337）。
//
// 字段化写法（推荐）：Fields{"process": {"eq": "sshd"}, "path": {"re": `/\\.ssh/`}}；
// actor 限定作用域；expiresIn 秒后自动失效；reviewDays 到期进复审清单。
// 旧写法 contains 仍兼容，但标记 deprecated（过宽，容易误杀）。
func (e *Engine) AddSuppress(ruleID, contains, note string, fields map[string]any, actor string, expiresIn, reviewDays *float64) SuppressResult {
	rid := strings.TrimSpace(ruleID)
	cts := strings.TrimSpace(contains)
	flds := map[string]any{}
	for k, v := range fields {
		flds[k] = v
	}
	if rid == "" && cts == "" && len(flds) == 0 {
		return SuppressResult{OK: false, Detail: "至少需要规则 ID、字段条件或匹配关键字"}
	}
	for k := range flds {
		if strings.TrimSpace(k) == "" {
			return SuppressResult{OK: false, Detail: "字段名不能为空"}
		}
	}
	now := e.Now()
	item := SuppressItem{
		RuleID:     rid,
		Actor:      strings.TrimSpace(actor),
		Fields:     flds,
		Note:       strings.TrimSpace(note),
		Added:      now,
		Hits:       0,
		ReviewDays: SuppressReviewDays,
	}
	if reviewDays != nil {
		item.ReviewDays = *reviewDays
	}
	if expiresIn != nil {
		item.Expires = now + *expiresIn
	}
	if cts != "" {
		item.Contains = cts
		item.Deprecated = "contains 子串匹配过宽，建议改用 fields"
	}
	e.Suppress = append(e.Suppress, item)
	e.SaveSuppress()
	e.store.LogAction("analyst", "suppress:add", strings.TrimSpace(rid+" "+actor+" "+jsonInline(flds)+cts), note)
	out := item
	return SuppressResult{OK: true, Count: len(e.Suppress), Item: &out}
}

func jsonInline(m map[string]any) string {
	if len(m) == 0 {
		return ""
	}
	b, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	return string(b)
}

// RemoveSuppress 按索引删除（engine.py:339-348）。
func (e *Engine) RemoveSuppress(index int) SuppressResult {
	if index < 0 || index >= len(e.Suppress) {
		return SuppressResult{OK: false, Detail: "索引不存在"}
	}
	item := e.Suppress[index]
	e.Suppress = append(e.Suppress[:index], e.Suppress[index+1:]...)
	e.SaveSuppress()
	e.store.LogAction("analyst", "suppress:remove",
		strings.TrimSpace(item.RuleID+" "+item.Actor+" "+jsonInline(item.Fields)),
		"命中 "+strconv.Itoa(item.Hits)+" 次")
	return SuppressResult{OK: true, Count: len(e.Suppress)}
}

// SuppressReviewDue 到期复审清单：过期的、或超过 reviewDays 没复审的
// （engine.py:350-362）。
func (e *Engine) SuppressReviewDue(now float64) []ReviewDue {
	if now == 0 {
		now = e.Now()
	}
	out := []ReviewDue{}
	for i := range e.Suppress {
		s := &e.Suppress[i]
		days := s.ReviewDays
		if days == 0 {
			days = SuppressReviewDays
		}
		if s.Expires != 0 && now > s.Expires {
			out = append(out, ReviewDue{Index: i, Reason: "已过期", Item: s})
		} else if s.Added != 0 && now-s.Added > days*86400 {
			out = append(out, ReviewDue{Index: i, Reason: "超过 " + strconv.Itoa(int(days)) + " 天未复审", Item: s})
		}
	}
	return out
}

func (e *Engine) isSuppressed(ruleID string, ev *model.Event, detail, actor string) bool {
	if len(e.Suppress) == 0 {
		return false
	}
	now := e.Now()
	for i := range e.Suppress {
		s := &e.Suppress[i]
		rid := strings.TrimSpace(s.RuleID)
		if rid != "" && rid != ruleID {
			continue
		}
		if s.Expires != 0 && now > s.Expires { // 过期即失效，不静默延长
			continue
		}
		if sa := strings.TrimSpace(s.Actor); sa != "" && sa != actor {
			continue
		}
		if len(s.Fields) > 0 {
			ok := true
			for name, cond := range s.Fields {
				if !matchCond(evField(ev, name, detail), cond) {
					ok = false
					break
				}
			}
			if !ok {
				continue
			}
		} else if s.Contains != "" {
			// 兼容旧条目：子串匹配，作用域仍然是 rule_id
			hay := detail + "\n" + ev.Process + "\n" + ev.Path + "\n" + ev.Cmdline
			if !strings.Contains(hay, s.Contains) {
				continue
			}
		}
		s.Hits++
		s.LastHit = now
		e.SuppressHits++
		e.supDirty = true
		if e.supSaved == 0 {
			e.supSaved = now
		}
		return true
	}
	// 命中计数别每条都落盘：30 秒攒一次
	if e.supDirty && now-e.supSaved > 30 {
		e.SaveSuppress()
		e.supSaved = now
	}
	return false
}

// ---------------- 准入（engine.py:405-443） ----------------

// Admit 一条候选告警是否放行。
//
// true = 新告警（已把 count/dedup_key/首末样本填好）；
// false = 被抑制，或已并入同身份的既有告警（计数 +1，不新开）。
func (e *Engine) Admit(f *model.Finding, ev *model.Event, cooldown float64) bool {
	now := e.Now()
	if e.isSuppressed(f.RuleID, ev, f.Detail, f.Actor) {
		e.Suppressed++
		return false
	}
	key := DedupKey(f.RuleID, f.Actor, ev)
	if ent := e.dedup[key]; ent != nil && now-ent.LastEmit < cooldown {
		ent.Count++
		ent.LastTS = evTime(ev, now)
		ent.LastDetail = f.Detail
		e.MergedTotal++
		e.merges = append(e.merges, Merge{
			FID: ent.FID, Count: ent.Count, LastDetail: f.Detail,
			LastTS: ent.LastTS, DedupKey: key,
		})
		e.ddDirty = true
		return false
	}

	ts := evTime(ev, now)
	f.Count = 1
	f.DedupKey = key
	f.FirstDetail = f.Detail
	f.LastDetail = f.Detail
	f.FirstTS = ts
	f.LastTS = ts
	e.dedup[key] = &DedupEntry{
		FID: f.ID, Count: 1, FirstTS: ts, LastTS: ts,
		FirstDetail: f.Detail, LastDetail: f.Detail, LastEmit: now,
	}
	e.ddDirty = true
	return true
}

func evTime(ev *model.Event, now float64) float64 {
	if ev != nil && ev.TS > 0 {
		return ev.TS
	}
	return now
}

// TakeMerges 取走累计的并入记录（engine.py:255-259）。
func (e *Engine) TakeMerges() []Merge {
	out := e.merges
	e.merges = nil
	e.saveDedup(false)
	return out
}

// ---------------- 检测（engine.py:445-488） ----------------

// Observe 跑一批事件，返回新开告警（已按规则顺序排列）。
func (e *Engine) Observe(events []*model.Event) []*model.Finding {
	out := []*model.Finding{}
	for _, ev := range events {
		if ev == nil {
			continue
		}
		for i := range e.rules {
			r := &e.rules[i]
			if !safeWhen(r, ev, e.ctx) {
				continue
			}
			actor := ""
			if r.Actor != nil {
				actor = safeActor(r, ev, e.ctx)
			}
			if actor == "" {
				if ev.PID != nil {
					actor = RootPID(ev.PID, e.ctx)
				} else {
					actor = "host"
				}
			}
			detail := r.DetailText
			if r.Detail != nil {
				detail = safeDetail(r, ev, e.ctx)
			}
			sev := e.severity(r, ev)
			if sev == "" {
				// severity_fn 判定「不再计分」：整条丢弃（engine.py:481-482）。
				continue
			}
			f := &model.Finding{
				ID:       newFID(),
				RuleID:   r.ID,
				Name:     r.Name,
				Severity: sev,
				EventID:  ev.EID,
				Actor:    actor,
				Tags:     append([]string(nil), r.Tags...),
				MITRE:    append([]string(nil), r.MITRE...),
				Detail:   detail,
				Advice:   r.Advice,
				TS:       ev.TS,
				Subject:  ev.Subject,
			}
			if e.Admit(f, ev, CooldownFor(r)) {
				out = append(out, f)
			}
		}
	}
	e.saveDedup(false)
	if e.supDirty {
		e.SaveSuppress()
	}
	return out
}

// severity 一条规则对一条事件的最终等级（engine.py:490-503）。
//
// 有 SeverityFn 就以闸门结果为准，**不与 ev.Severity 取 max**：事件自带的
// high（如公网直连）不能把保留网段的 IOC 抬成 high/critical。
// 返回 "" = 闸门判定「不再计分」，调用方跳过该条。
func (e *Engine) severity(r *Rule, ev *model.Event) string {
	if r.SeverityFn != nil {
		return validOrEmpty(safeSeverityFn(r, ev, e.ctx))
	}
	return sevMax(r.Severity, ev.Severity)
}

func validOrEmpty(s string) string {
	if validSeverity(s) {
		return s
	}
	return ""
}

// Catalog 规则目录（engine.py:511-518）。
func (e *Engine) Catalog() []CatalogEntry {
	out := make([]CatalogEntry, 0, len(e.rules))
	for i := range e.rules {
		r := &e.rules[i]
		out = append(out, CatalogEntry{
			ID: r.ID, Name: r.Name, Severity: r.Severity,
			Tags: append([]string{}, r.Tags...), MITRE: append([]string{}, r.MITRE...),
			Advice: r.Advice, Description: r.Description,
			Cooldown: CooldownFor(r), DynamicSeverity: r.SeverityFn != nil,
		})
	}
	return out
}

// ---------------- 去重表持久化（engine.py:240-289） ----------------

func (e *Engine) loadDedup() {
	raw, err := os.ReadFile(e.ddPath)
	if err == nil {
		var m map[string]*DedupEntry
		if json.Unmarshal(raw, &m) == nil {
			for k, v := range m {
				if v != nil {
					e.dedup[k] = v
				}
			}
		}
	}
	e.store.ReapplyDedup(e.snapshotDedup())
}

func (e *Engine) snapshotDedup() map[string]DedupEntry {
	out := make(map[string]DedupEntry, len(e.dedup))
	for k, v := range e.dedup {
		out[k] = *v
	}
	return out
}

func (e *Engine) saveDedup(force bool) {
	now := e.Now()
	if !e.ddDirty && !force {
		return
	}
	if !force && now-e.ddSaved < 10 {
		return
	}
	if len(e.dedup) > DedupMax {
		for k, v := range e.dedup {
			if now-v.LastEmit > 86400 {
				delete(e.dedup, k)
			}
		}
	}
	dir := filepath.Dir(e.ddPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	buf, err := json.Marshal(e.dedup)
	if err != nil {
		return
	}
	tmp := e.ddPath + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o644); err != nil {
		return
	}
	if err := os.Rename(tmp, e.ddPath); err != nil {
		_ = os.Remove(tmp)
		return
	}
	e.ddDirty = false
	e.ddSaved = now
}

// newFID 10 位十六进制告警 ID（Python uuid4().hex[:10]）。
func newFID() string {
	var b [5]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "0000000000"
	}
	return hex.EncodeToString(b[:])
}
