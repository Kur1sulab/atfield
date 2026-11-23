package store

// history.go —— 启动回填。这是 Python 版翻车的地方，Go 版重点保证。
//
// Python 的 `_load_history()` 只回填 findings/incidents/actions/tickets，
// events.jsonl 写了却从不读；而且它只写 8 个字段，读回来也还原不成 Event。
// 结果：进程重启后 `snapshot_events` 空、`events_total` 归零，
// 面板上「今天采了多少事件」永远是当前进程启动以来的数字。
//
// Go 版的做法：
//   - events.jsonl 写完整 Event，启动时全量回填环形缓冲（超容量只留尾部）；
//   - findings.jsonl 按「全量行 + op:bump/status 增量」重放，得到重启前的
//     count/last_detail/last_ts；
//   - 工单从 tickets.json 整体读回，编号从最大 TID 续号；
//   - meta 里的累计计数从数据本身重算，不信任何单独存的文件。

import (
	"encoding/json"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/Kur1sulab/atfield/go/internal/model"
)

// loadHistory 从磁盘回填全部历史。坏行跳过（历史坏行不能挡住启动）。
func (s *Store) loadHistory() {
	s.loadEvents()
	s.loadFindings()
	s.loadIncidents()
	s.loadActions()
	s.loadTickets()
}

// loadEvents 回填事件环形缓冲。
//
// 只保留最后 MaxEvents 条：容量由配置决定，超出部分本来就会被淘汰，
// 先把整份读进内存再截断会在大文件上白吃几百 MB。
func (s *Store) loadEvents() {
	if s.fEvents == nil {
		return
	}
	// 只回填最新 maxEvents 条：倒着读到够数就停，不把几百 MB 历史读进内存
	lines := tailLinesRotated(s.fEvents.path, s.events.max)
	for _, line := range lines {
		var ev model.Event
		if json.Unmarshal(line, &ev) != nil {
			continue
		}
		s.events.append(ev)
		s.meta.EventsTotal++
		if ev.Kind != "" {
			s.counters[ev.Kind]++
		}
	}
}

// loadFindings 重放 findings.jsonl：全量行建对象，增量行改计数/状态。
//
// 这是「重启后 count 还是 N」的实现核心。Python 靠 Engine 加载 dedup.json
// 来回填，但 CLI 单次进程根本不加载，于是月报永远 count=1。
func (s *Store) loadFindings() {
	if s.fFindings == nil {
		return
	}
	// 先按 fid 收齐所有行，最后再按出现顺序重建环形缓冲：
	// 增量行必须应用到对应的全量行上，而增量可能出现在全量行之后很久。
	//
	// 内存上界是「不同的 fid 个数」，不是文件行数：bump 行只改既有对象，
	// 不新建。文件再大也只跟告警条数有关。
	var order []string
	byID := make(map[string]*model.Finding, 1024)
	status := make(map[string]string, 64)

	handle := func(line []byte) bool {
		// 先探 op：增量行没有完整 Finding 字段
		var probe struct {
			Op         string  `json:"op"`
			FID        string  `json:"fid"`
			DedupKey   string  `json:"dedup_key"`
			Count      int     `json:"count"`
			LastDetail string  `json:"last_detail"`
			LastTS     float64 `json:"last_ts"`
			Status     string  `json:"status"`
		}
		if json.Unmarshal(line, &probe) != nil {
			return true
		}
		switch probe.Op {
		case "bump":
			f := byID[probe.FID]
			if f == nil {
				// 全量行被淘汰/损坏：从增量行尽量还原一个可用的对象，
				// 比丢掉整条告警强（取证现场宁可信息不全也别缺项）。
				f = &model.Finding{ID: probe.FID, DedupKey: probe.DedupKey, Status: "open"}
				byID[probe.FID] = f
				order = append(order, probe.FID)
			}
			if probe.Count > 0 {
				f.Count = probe.Count
			}
			if probe.LastDetail != "" {
				f.LastDetail = probe.LastDetail
			}
			if probe.LastTS > 0 {
				f.LastTS = probe.LastTS
			}
			if probe.DedupKey != "" && f.DedupKey == "" {
				f.DedupKey = probe.DedupKey
			}
		case "status":
			if probe.Status != "" {
				status[probe.FID] = probe.Status
				if f := byID[probe.FID]; f != nil {
					f.Status = probe.Status
				}
			}
		default:
			var f model.Finding
			if json.Unmarshal(line, &f) != nil || f.ID == "" {
				return true
			}
			if old := byID[f.ID]; old != nil {
				// 同一 ID 重复写（重启后重新载入再写）：以最新一份为准，
				// 就地覆盖保持指针不变，findIdx 不失效。
				*old = f
				return true
			}
			cp := f
			byID[cp.ID] = &cp
			order = append(order, cp.ID)
		}
		return true
	}
	scanJSONLRotated(s.fFindings.path, handle)

	// 按写入顺序重建环形缓冲（超容量丢最旧）
	start := 0
	if over := len(order) - s.findings.max; over > 0 {
		start = over
	}
	for _, id := range order[start:] {
		f := byID[id]
		if f == nil {
			continue
		}
		if st, ok := status[f.ID]; ok {
			f.Status = st
		}
		if f.Status == "" {
			f.Status = "open"
		}
		if f.Count <= 0 {
			f.Count = 1
		}
		if f.FirstTS == 0 {
			f.FirstTS = f.LastTS
		}
		if f.FirstDetail == "" {
			f.FirstDetail = f.LastDetail
		}
		if gone, evicted := s.findings.append(f); evicted {
			s.indexDropLocked(gone)
		}
		s.indexAddLocked(f)
		s.meta.FindingsTotal++
		s.meta.MergedTotal += int64(maxInt(f.Count-1, 0))
	}
}

// loadIncidents 回填攻击链。同一 ID 保留最后一份（演进式更新）。
func (s *Store) loadIncidents() {
	if s.fIncidents == nil {
		return
	}
	seen := map[string]int{}
	var all []model.Incident
	scanJSONLRotated(s.fIncidents.path, func(line []byte) bool {
		var inc model.Incident
		if json.Unmarshal(line, &inc) != nil || inc.ID == "" {
			return true
		}
		if idx, ok := seen[inc.ID]; ok {
			all[idx] = inc // 后写的覆盖先写的
			return true
		}
		seen[inc.ID] = len(all)
		all = append(all, inc)
		return true
	})
	start := 0
	if over := len(all) - s.incidents.max; over > 0 {
		start = over
	}
	for _, inc := range all[start:] {
		s.incidents.append(inc)
		s.meta.IncidentsTotal++
	}
}

// loadActions 回填处置动作环形缓冲。
func (s *Store) loadActions() {
	if s.fActions == nil {
		return
	}
	scanJSONLRotated(s.fActions.path, func(line []byte) bool {
		var a Action
		if json.Unmarshal(line, &a) != nil {
			return true
		}
		s.actions.append(a)
		s.meta.ActionsTotal++
		return true
	})
}

// loadTickets 回填工单并续号。
//
// 续号必须按磁盘上的**最大 TID**，不能用 len(buf)+1：工单被环形缓冲淘汰过、
// 或用户手工删过中间几条时，len+1 会撞上已有编号。
//
// 顺带按 TID 序号升序排一遍：两版对 tickets.json 的写入顺序不同（Python 写
// 最新在前，Go 写时间正序），靠文件名顺序读会得到不同的内存顺序。TID 单调
// 递增，按它排序两边结果一致。
func (s *Store) loadTickets() {
	if s.ticketsPt == "" {
		return
	}
	raw, err := os.ReadFile(s.ticketsPt)
	if err != nil {
		return
	}
	var list []Ticket
	if json.Unmarshal(raw, &list) != nil {
		return
	}
	sort.SliceStable(list, func(i, j int) bool {
		ni, oki := parseTicketSeq(list[i].TID)
		nj, okj := parseTicketSeq(list[j].TID)
		if !oki || !okj {
			return false // 解析不出来的保持原顺序
		}
		return ni < nj
	})
	start := 0
	if over := len(list) - s.tickets.max; over > 0 {
		start = over
	}
	maxSeq := 0
	for _, tk := range list[start:] {
		if tk.Notes == nil {
			tk.Notes = []TicketNote{}
		}
		s.tickets.append(tk)
		s.meta.TicketsTotal++
		if n, ok := parseTicketSeq(tk.TID); ok && n > maxSeq {
			maxSeq = n
		}
	}
	s.ticketSeq = maxSeq
	if len(s.tickets.buf) > 0 {
		s.state["tickets"] = s.ticketsTail(300)
	}
}

// parseTicketSeq 从 "T0007" 解析出 7。
func parseTicketSeq(tid string) (int, bool) {
	t := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(tid)), "T")
	if t == "" {
		return 0, false
	}
	n, err := strconv.Atoi(t)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
