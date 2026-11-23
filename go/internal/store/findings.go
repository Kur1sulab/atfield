package store

// findings.go —— 告警 / 攻击链 / 工单 / 处置动作四类数据的读写。
//
// 四者的关系（对拍时按这个模型检查一致性）：
//
//	Event ──(规则命中+准入)──> Finding ──(关联)──> Incident
//	  一条原始事件                一条告警          一条攻击链，findings 里存告警 ID
//	                              │
//	                              ├──> Ticket   处置工单，ref 指回 fid
//	                              └──> Action   处置动作，target 指回 pid/ip/fid
//
// 方向是单向的：Finding 不知道 Ticket 存在，Ticket 用 ref 反向指。
// 这样删工单不会动告警，而告警被环形缓冲淘汰后工单仍留有 ref 快照（审计需要）。

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Kur1sulab/atfield/internal/model"
)

// 工单状态。Python 侧只接受这三个值，别的原样忽略。
const (
	TicketOpen   = "open"
	TicketAck    = "ack"
	TicketClosed = "closed"
)

// Bump 一次「并入已有告警」的增量（对应 Python bump_findings 的 rows 元素，
// 也就是 detect.Merge 的字段集）。
//
// 语义是**增量**：Count 是并入后的总数，LastDetail/LastTS 覆盖，First* 不动。
type Bump struct {
	FID        string  `json:"fid"`
	Count      int     `json:"count"`
	LastDetail string  `json:"last_detail"`
	LastTS     float64 `json:"last_ts"`
	DedupKey   string  `json:"dedup_key"`
}

// DedupState 一条去重身份的状态（字段与 detect.DedupEntry 一致，
// 这样同一个 dedup.json 两版都能读）。
type DedupState struct {
	FID         string  `json:"fid"`
	Count       int     `json:"count"`
	FirstTS     float64 `json:"first_ts"`
	LastTS      float64 `json:"last_ts"`
	FirstDetail string  `json:"first_detail"`
	LastDetail  string  `json:"last_detail"`
	LastEmit    float64 `json:"last_emit"`
}

// Ticket 处置工单。
type Ticket struct {
	TID       string       `json:"tid"`
	Title     string       `json:"title"`
	Severity  string       `json:"severity"`
	Ref       string       `json:"ref,omitempty"`
	Detail    string       `json:"detail,omitempty"`
	Source    string       `json:"source"`
	Status    string       `json:"status"`
	Owner     string       `json:"owner,omitempty"`
	Notes     []TicketNote `json:"notes"`
	Created   float64      `json:"created"`
	CreatedCN string       `json:"created_cn"`
	Updated   float64      `json:"updated"`
}

// TicketNote 工单上的一条处理备注。
type TicketNote struct {
	TS   float64 `json:"ts"`
	Time string  `json:"time"`
	Text string  `json:"text"`
}

// Action 一次处置动作的审计记录（落 actions.jsonl，并同步进哈希链）。
//
// 两个标记位对应两类「actor 不可信」：
//
//	ActorDefaulted  调用方没给 actor，存储层按 system 兜底；
//	ActorIsRole     调用方给的是一个**角色名**（analyst/admin/responder/viewer），
//	                不是具体身份。这几乎总是硬编码的痕迹。
//
// Python 版把这 15 处全写成 "analyst"，事后无法区分「研判员点了终止」
// 和「系统自动处置」，也无法回答「谁批的」。Go 版不改写调用方给的值
// （改写等于伪造证据），但把「这是角色不是人」显式记在记录上——
// 审计员 grep actor_is_role 就能把所有还没整改的调用点全找出来。
type Action struct {
	TS             float64 `json:"ts"`
	Time           string  `json:"time"`
	Actor          string  `json:"actor"`
	Action         string  `json:"action"`
	Target         string  `json:"target"`
	Result         string  `json:"result"`
	ActorDefaulted bool    `json:"actor_defaulted,omitempty"`
	ActorIsRole    bool    `json:"actor_is_role,omitempty"`
}

// Roles 合法角色名（与 auth.py 的 ROLES 一致）。
var Roles = []string{"admin", "responder", "analyst", "viewer"}

// IsRole 判断一个字符串是不是角色名（而不是具体身份）。
func IsRole(s string) bool {
	for _, r := range Roles {
		if s == r {
			return true
		}
	}
	return false
}

// TicketResult 工单操作结果（对应 Python 返回的 {"ok":..,"ticket"/"detail":..}）。
type TicketResult struct {
	OK     bool    `json:"ok"`
	Detail string  `json:"detail,omitempty"`
	Ticket *Ticket `json:"ticket,omitempty"`
}

// TimelineRow 统一取证时间线的一行。
type TimelineRow struct {
	TS       float64 `json:"ts"`
	Type     string  `json:"type"`
	Kind     string  `json:"kind,omitempty"`
	Title    string  `json:"title,omitempty"`
	Severity string  `json:"severity,omitempty"`
	Source   string  `json:"source,omitempty"`
	Actor    string  `json:"actor,omitempty"`
	Ref      any     `json:"ref,omitempty"`
}

// ---------------- 告警 ----------------

// AddFindings 写入一批新告警（首次出现的去重身份）。
//
// 已存在同一 DedupKey 时不新增行，转走 BumpFindings 的并入语义——
// 上层就算漏了准入判断，存储层也不会把同一条告警摊成两行。
func (s *Store) AddFindings(fs []*model.Finding) (added, merged int, err error) {
	if len(fs) == 0 {
		return 0, 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, 0, errClosed
	}
	var rows [][]byte
	for _, f := range fs {
		if f == nil {
			continue
		}
		// 存副本，不存调用方的指针：告警对象常被上层复用/改写（引擎会把同
		// 一个 *Finding 继续拿去渲染或再判断），共享指针就是一个隐藏的数据
		// 竞争——它在单线程测试里永远不显形，在 -race 下才炸。
		f = cloneFinding(f)
		if f.ID == "" {
			f.ID = shortID()
		}
		if f.DedupKey != "" {
			if exist := s.byDedupKey(f.DedupKey); exist != nil {
				// 已有同身份：按并入处理，绝不新开一行
				s.bumpLocked(exist, Bump{
					FID: exist.ID, Count: exist.Count + 1,
					LastDetail: f.Detail, LastTS: f.TS, DedupKey: f.DedupKey,
				})
				// 并入必须落盘。漏了这一行，重启后这次命中就白加了——
				// 内存里 count=5、磁盘上还是 4，且没有任何报错。
				rows = append(rows, mustJSON(bumpRecord{
					Op: "bump", FID: exist.ID, DedupKey: exist.DedupKey,
					Count: exist.Count, LastDetail: exist.LastDetail, LastTS: exist.LastTS,
				}))
				merged++
				continue
			}
		}
		if f.Count <= 0 {
			f.Count = 1
		}
		if f.FirstTS == 0 {
			f.FirstTS = f.TS
		}
		if f.LastTS == 0 {
			f.LastTS = f.TS
		}
		if f.FirstDetail == "" {
			f.FirstDetail = f.Detail
		}
		if f.LastDetail == "" {
			f.LastDetail = f.Detail
		}
		if f.Status == "" {
			f.Status = "open"
		}
		if gone, evicted := s.findings.append(f); evicted {
			// 淘汰即从索引摘除，否则 GetFinding 会查到缓冲里早没有的告警
			s.indexDropLocked(gone)
		}
		s.indexAddLocked(f)
		s.meta.FindingsTotal++
		added++
		rows = append(rows, mustJSON(f))
	}
	if s.fFindings != nil {
		if err := s.fFindings.appendRows(rows); err != nil {
			return added, merged, err
		}
	}
	return added, merged, nil
}

// BumpFindings 应用一批并入增量，返回实际更新条数。
//
// 与 Python 的关键差异：**每条并入都落盘**（写一条 {"op":"bump"} 记录）。
// Python 注释里说「计数由 dedup.json 回填」，但 CLI 单次进程根本没加载过
// dedup.json，于是重启后 count 全退回 1。存储层自己记住才算真的记住。
func (s *Store) BumpFindings(rows []Bump) (int, error) {
	if len(rows) == 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, errClosed
	}
	var recs [][]byte
	n := 0
	for _, r := range rows {
		target := s.findIdx[r.FID]
		if target == nil && r.DedupKey != "" {
			target = s.byDedupKey(r.DedupKey)
		}
		if target == nil {
			continue
		}
		s.bumpLocked(target, r)
		recs = append(recs, mustJSON(bumpRecord{
			Op: "bump", FID: target.ID, DedupKey: target.DedupKey,
			Count: target.Count, LastDetail: target.LastDetail, LastTS: target.LastTS,
		}))
		n++
	}
	if s.fFindings != nil && len(recs) > 0 {
		if err := s.fFindings.appendRows(recs); err != nil {
			return n, err
		}
	}
	return n, nil
}

// BumpByDedupKey 按去重键并入一次命中（供引擎准入路径直接调用）。
//
// 返回 (是否命中已有告警, 更新后的副本)。false 表示该身份还没出现过，
// 调用方应走 AddFindings 新开一条。
func (s *Store) BumpByDedupKey(key, detail string, ts float64) (bool, *model.Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.byDedupKey(key)
	if f == nil {
		return false, nil
	}
	s.bumpLocked(f, Bump{FID: f.ID, Count: f.Count + 1, LastDetail: detail, LastTS: ts, DedupKey: key})
	if s.fFindings != nil {
		_ = s.fFindings.appendRows([][]byte{mustJSON(bumpRecord{
			Op: "bump", FID: f.ID, DedupKey: key, Count: f.Count,
			LastDetail: f.LastDetail, LastTS: f.LastTS,
		})})
	}
	return true, cloneFinding(f)
}

// bumpLocked 就地更新一条告警：count 递增、last_* 覆盖、first_* 不动。
// 调用方必须持写锁。
func (s *Store) bumpLocked(f *model.Finding, r Bump) {
	if r.Count > 0 {
		f.Count = r.Count
	} else {
		f.Count++
	}
	if r.LastDetail != "" {
		f.LastDetail = r.LastDetail
	}
	if r.LastTS > 0 {
		f.LastTS = r.LastTS
	}
	if r.DedupKey != "" {
		f.DedupKey = r.DedupKey
	}
	// first_* 是取证锚点：无论并入多少次都不许动。
	if f.FirstTS == 0 {
		f.FirstTS = f.LastTS
	}
	if f.FirstDetail == "" {
		f.FirstDetail = f.LastDetail
	}
	s.meta.MergedTotal++
}

// byDedupKey 按去重键找告警（最新一条）。调用方必须持锁。
//
// 走 dedupIdx 而不是遍历整个环形缓冲：单条事件的准入要查一次，20k 事件/分钟
// 乘以 4000 条缓冲就是 8000 万次比较。索引在插入/淘汰时同步维护。
func (s *Store) byDedupKey(key string) *model.Finding {
	if key == "" {
		return nil
	}
	return s.dedupIdx[key]
}

// indexAddLocked 把一条告警挂进索引。调用方必须持锁。
func (s *Store) indexAddLocked(f *model.Finding) {
	s.findIdx[f.ID] = f
	if f.DedupKey != "" {
		s.dedupIdx[f.DedupKey] = f
	}
}

// indexDropLocked 从索引摘除一条被淘汰的告警。调用方必须持锁。
//
// 只删「指向被淘汰对象」的条目：同一个 dedup_key 在缓冲里只该有一条，
// 但万一调用方手工塞了重复行，删之前先确认指的就是这条，别把活条目误删。
func (s *Store) indexDropLocked(f *model.Finding) {
	if f == nil {
		return
	}
	if cur, ok := s.findIdx[f.ID]; ok && cur == f {
		delete(s.findIdx, f.ID)
	}
	if f.DedupKey != "" {
		if cur, ok := s.dedupIdx[f.DedupKey]; ok && cur == f {
			delete(s.dedupIdx, f.DedupKey)
		}
	}
}

// ReapplyDedup 重启后把 dedup.json 的计数回填到刚载入的告警行。
//
// 存储层自己的 bump 记录已经能自愈，这个入口是给「外部 dedup.json 更新、
// 但 bump 记录丢失」的兜底路径，以及两版共用 data_dir 时的兼容。
func (s *Store) ReapplyDedup(entries map[string]DedupState) (int, error) {
	if len(entries) == 0 {
		return 0, nil
	}
	rows := make([]Bump, 0, len(entries))
	for k, v := range entries {
		rows = append(rows, Bump{
			FID: v.FID, Count: v.Count, LastDetail: v.LastDetail,
			LastTS: v.LastTS, DedupKey: k,
		})
	}
	// 顺序稳定，便于对拍
	sort.Slice(rows, func(i, j int) bool { return rows[i].DedupKey < rows[j].DedupKey })
	return s.BumpFindings(rows)
}

// SnapshotFindings 取告警快照（最新在前）。minSev 为空不过滤。
func (s *Store) SnapshotFindings(limit int, minSev string) []*model.Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	limit = normLimit(limit, s.findings.max)
	thr := model.SeverityRank(minSev)
	out := make([]*model.Finding, 0, limit)
	for i := len(s.findings.buf) - 1; i >= 0 && len(out) < limit; i-- {
		f := s.findings.buf[i]
		if minSev != "" && model.SeverityRank(f.Severity) < thr {
			continue
		}
		out = append(out, cloneFinding(f))
	}
	return out
}

// GetFinding 按 ID 取一条告警的副本。
func (s *Store) GetFinding(id string) *model.Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if f := s.findIdx[id]; f != nil {
		return cloneFinding(f)
	}
	return nil
}

// GetFindingByDedup 按去重键取一条告警的副本。
func (s *Store) GetFindingByDedup(key string) *model.Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneFinding(s.byDedupKey(key))
}

// SetFindingStatus 改告警状态（open/triaged/closed），返回是否找到。
func (s *Store) SetFindingStatus(id, status string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.findIdx[id]
	if f == nil {
		return false
	}
	f.Status = status
	if s.fFindings != nil {
		_ = s.fFindings.appendRows([][]byte{mustJSON(bumpRecord{
			Op: "status", FID: f.ID, DedupKey: f.DedupKey, Status: status,
			Count: f.Count, LastDetail: f.LastDetail, LastTS: f.LastTS,
		})})
	}
	return true
}

// ---------------- 攻击链 ----------------

// AddIncident 写入/更新一条攻击链。同一 ID 视为演进：移除旧条目，最新在前。
// 落盘是追加式的，加载时按 ID 去重保留最后一份（与 Python 同口径）。
func (s *Store) AddIncident(inc model.Incident) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errClosed
	}
	if inc.ID == "" {
		return fmt.Errorf("store: 攻击链缺少 ID")
	}
	if inc.TS == 0 {
		inc.TS = nowTS()
	}
	for i := range s.incidents.buf {
		if s.incidents.buf[i].ID == inc.ID {
			s.incidents.removeAt(i)
			break
		}
	}
	s.incidents.append(inc)
	s.meta.IncidentsTotal++
	if s.fIncidents != nil {
		return s.fIncidents.appendRows([][]byte{mustJSON(inc)})
	}
	return nil
}

// SnapshotIncidents 取攻击链快照（最新在前）。
func (s *Store) SnapshotIncidents(limit int) []model.Incident {
	s.mu.RLock()
	defer s.mu.RUnlock()
	limit = normLimit(limit, s.incidents.max)
	out := make([]model.Incident, 0, limit)
	for i := len(s.incidents.buf) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, cloneIncident(s.incidents.buf[i]))
	}
	return out
}

// ---------------- 工单 ----------------

// CreateTicket 建工单。编号 T0001 起，重启后从磁盘上最大编号续号，不撞号。
func (s *Store) CreateTicket(title, severity, ref, detail, source string) (*Ticket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errClosed
	}
	if severity == "" {
		severity = "medium"
	}
	if source == "" {
		source = "manual"
	}
	s.ticketSeq++
	now := s.now()
	tk := Ticket{
		TID:       fmt.Sprintf("T%04d", s.ticketSeq),
		Title:     truncate(title, 240),
		Severity:  severity,
		Ref:       ref,
		Detail:    truncate(detail, 2000),
		Source:    source,
		Status:    TicketOpen,
		Notes:     []TicketNote{},
		Created:   tsOf(now),
		CreatedCN: now.Format("2006-01-02 15:04:05"),
		Updated:   tsOf(now),
	}
	s.tickets.append(tk)
	s.meta.TicketsTotal++
	s.state["tickets"] = s.ticketsTail(300)
	if err := s.saveTicketsLocked(); err != nil {
		return &tk, err
	}
	return &tk, nil
}

// UpdateTicket 改状态/责任人/加备注。tid 不存在返回 ok=false（不报错——
// 前端把它当业务态处理，不是异常）。
func (s *Store) UpdateTicket(tid, status, note, owner string) (TicketResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return TicketResult{}, errClosed
	}
	for i := range s.tickets.buf {
		tk := &s.tickets.buf[i]
		if tk.TID != tid {
			continue
		}
		if status == TicketOpen || status == TicketAck || status == TicketClosed {
			tk.Status = status
		}
		if owner != "" {
			tk.Owner = owner
		}
		if note != "" {
			now := s.now()
			tk.Notes = append(tk.Notes, TicketNote{
				TS: tsOf(now), Time: now.Format("2006-01-02 15:04:05"),
				Text: truncate(note, 1000),
			})
		}
		tk.Updated = tsOf(s.now())
		s.state["tickets"] = s.ticketsTail(300)
		cp := cloneTicket(*tk)
		if err := s.saveTicketsLocked(); err != nil {
			return TicketResult{OK: true, Ticket: &cp}, err
		}
		return TicketResult{OK: true, Ticket: &cp}, nil
	}
	return TicketResult{OK: false, Detail: "工单不存在"}, nil
}

// SnapshotTickets 取工单快照（最新在前）。
func (s *Store) SnapshotTickets(limit int) []Ticket {
	s.mu.RLock()
	defer s.mu.RUnlock()
	limit = normLimit(limit, s.tickets.max)
	out := make([]Ticket, 0, limit)
	for i := len(s.tickets.buf) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, cloneTicket(s.tickets.buf[i]))
	}
	return out
}

// ticketsTail 取最近 n 条工单（时间正序），写进 state["tickets"] 供前端直接读。
func (s *Store) ticketsTail(n int) []Ticket {
	buf := s.tickets.buf
	start := 0
	if len(buf) > n {
		start = len(buf) - n
	}
	out := make([]Ticket, 0, len(buf)-start)
	for i := start; i < len(buf); i++ {
		out = append(out, cloneTicket(buf[i]))
	}
	return out
}

// ---------------- 处置动作（审计） ----------------

// LogAction 记一次处置动作：进内存环形缓冲 + 落 actions.jsonl + 进哈希链。
//
// actor 为空时落 "system" 并置 ActorDefaulted。**不编造人名**——
// Python 版 15 处硬编码 "analyst" 让 responder/admin 的处置无法追责，
// 这是本包明确不重蹈的缺陷。
func (s *Store) LogAction(actor, action, target, result string) Action {
	rec, _ := s.LogActionE(actor, action, target, result)
	return rec
}

// LogActionE 同 LogAction，但把落盘错误也回传（审计写失败必须可感知）。
func (s *Store) LogActionE(actor, action, target, result string) (Action, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return Action{}, errClosed
	}
	now := s.now()
	rec := Action{
		TS:     tsOf(now),
		Time:   now.Format("2006-01-02 15:04:05"),
		Actor:  truncate(strings.TrimSpace(actor), 120),
		Action: truncate(action, 120),
		Target: truncate(target, 400),
		Result: truncate(result, 400),
	}
	if rec.Actor == "" {
		rec.Actor = "system"
		rec.ActorDefaulted = true
	} else if IsRole(rec.Actor) {
		// 角色名不是身份。不篡改调用方给的值（那是伪造证据），
		// 但把它标出来，让「还有哪些调用点在硬编码角色」可被查询。
		rec.ActorIsRole = true
	}
	s.actions.append(rec)
	s.meta.ActionsTotal++
	var err error
	if s.fActions != nil {
		err = s.fActions.appendRows([][]byte{mustJSON(rec)})
	}
	audit := s.audit
	s.mu.Unlock()

	// 审计链有自己的锁，放在 Store 锁外追加：链写盘 fsync 慢，
	// 攥着 Store 锁会卡住采集线程。
	if audit != nil {
		audit.Append(AuditInput{
			Action: rec.Action, Actor: rec.Actor, Role: "system",
			Target: rec.Target, Result: rec.Result,
			Detail: map[string]any{"ts": rec.TS, "actor_defaulted": rec.ActorDefaulted},
		})
	}
	return rec, err
}

// SnapshotActions 取处置动作快照（最新在前）。
func (s *Store) SnapshotActions(limit int) []Action {
	s.mu.RLock()
	defer s.mu.RUnlock()
	limit = normLimit(limit, s.actions.max)
	out := make([]Action, 0, limit)
	for i := len(s.actions.buf) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, s.actions.buf[i])
	}
	return out
}

// ---------------- 统一时间线 ----------------

// Timeline 把事件/告警/攻击链/动作/工单合成一条按时间倒序的取证时间线。
// 任何一类为空都不影响其余几类（取证现场经常只剩半份数据）。
func (s *Store) Timeline(limit int) []TimelineRow {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows := make([]TimelineRow, 0, 256)

	start := 0
	if n := len(s.events.buf); n > 1500 {
		start = n - 1500
	}
	for i := start; i < len(s.events.buf); i++ {
		e := s.events.buf[i]
		title := e.Process
		if title == "" {
			title = e.Kind
		}
		var ref any
		if e.PID != nil {
			ref = *e.PID
		}
		rows = append(rows, TimelineRow{
			TS: e.TS, Type: "event", Kind: e.Kind, Title: title,
			Severity: e.Severity, Source: e.Source, Actor: e.Process, Ref: ref,
		})
	}
	for _, f := range s.findings.buf {
		ts := f.TS
		if ts == 0 {
			ts = f.FirstTS
		}
		rows = append(rows, TimelineRow{
			TS: ts, Type: "finding", Kind: f.RuleID, Title: f.Name,
			Severity: f.Severity, Source: "rule", Actor: f.Actor, Ref: f.RuleID,
		})
	}
	for _, i := range s.incidents.buf {
		rows = append(rows, TimelineRow{
			TS: i.TS, Type: "incident", Kind: i.ID, Title: i.Title,
			Severity: i.Severity, Source: "correlate", Ref: i.ID,
		})
	}
	for _, a := range s.actions.buf {
		rows = append(rows, TimelineRow{
			TS: a.TS, Type: "action", Kind: a.Action,
			Title: a.Action + " · " + a.Target, Severity: "info",
			Source: a.Actor, Actor: a.Target, Ref: a.Result,
		})
	}
	for _, t := range s.tickets.buf {
		rows = append(rows, TimelineRow{
			TS: t.Created, Type: "ticket", Kind: t.Status, Title: t.Title,
			Severity: t.Severity, Source: t.Source, Actor: t.TID, Ref: t.TID,
		})
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].TS > rows[j].TS })
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	return rows
}

// ---------------- 内部：落盘 ----------------

// bumpRecord findings.jsonl 的增量记录。用 Op 区分三种行：
//
//	（无 op）  新告警全量行
//	bump      并入：count/last_* 覆盖
//	status    状态变更
type bumpRecord struct {
	Op         string  `json:"op"`
	FID        string  `json:"fid"`
	DedupKey   string  `json:"dedup_key,omitempty"`
	Count      int     `json:"count,omitempty"`
	LastDetail string  `json:"last_detail,omitempty"`
	LastTS     float64 `json:"last_ts,omitempty"`
	Status     string  `json:"status,omitempty"`
}

// saveTicketsLocked 工单量小（≤1000），整体原子重写。调用方必须持写锁。
func (s *Store) saveTicketsLocked() error {
	if s.ticketsPt == "" {
		return nil
	}
	return writeFileAtomic(s.ticketsPt, mustJSON(s.tickets.buf))
}

// ---------------- 拷贝 ----------------

// 读路径一律返回深拷贝：调用方改快照不能污染存储，
// 也不能在 -race 下与写入方抢同一块内存。

func cloneFinding(f *model.Finding) *model.Finding {
	if f == nil {
		return nil
	}
	c := *f
	if f.Subject != nil {
		c.Subject = make(map[string]any, len(f.Subject))
		for k, v := range f.Subject {
			c.Subject[k] = v
		}
	}
	if f.Tags != nil {
		c.Tags = append([]string(nil), f.Tags...)
	}
	if f.MITRE != nil {
		c.MITRE = append([]string(nil), f.MITRE...)
	}
	return &c
}

func cloneIncident(i model.Incident) model.Incident {
	c := i
	if i.Findings != nil {
		c.Findings = append([]string(nil), i.Findings...)
	}
	return c
}

func cloneTicket(t Ticket) Ticket {
	c := t
	if t.Notes != nil {
		c.Notes = append([]TicketNote(nil), t.Notes...)
	}
	return c
}

func tsOf(t time.Time) float64 { return float64(t.UnixNano()) / 1e9 }
