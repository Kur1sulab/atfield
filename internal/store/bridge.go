package store

// bridge.go —— 与检测引擎/采集层的接线面。
//
// 本包**刻意不 import detect 或 collector**：
//   - detect 自己定义了 Store 接口（engine.go:24）并留了 NopStore 兜底，
//     就是为了不依赖具体持久层。持久层反过来 import 检测层，今天不成环，
//     明天 detect 想引用 store.DedupState 就成环了。存储层必须是叶子包。
//   - 所以接线面只放「形状相同的普通结构体」：detect.Merge 与 store.Bump
//     字段一一对应，调用方在 wiring 层一行 map 就接上，编译器在那一行做检查。
//
// 接线示例（在 main 或 wiring 层，不在本包）：
//
//	merges := eng.TakeMerges()
//	rows := make([]store.Bump, 0, len(merges))
//	for _, m := range merges {
//	    rows = append(rows, store.Bump{
//	        FID: m.FID, Count: m.Count, LastDetail: m.LastDetail,
//	        LastTS: m.LastTS, DedupKey: m.DedupKey,
//	    })
//	}
//	st.BumpFindings(rows)

// CollectorStatus 采集器状态的存储侧视图。
//
// 字段与 collector.Status 同名同义，但不 import collector——
// 采集层不该被存储层反向依赖，存储层也不该被采集层绑死。
type CollectorStatus struct {
	Name      string
	Runs      int64
	Errors    int64
	LastTS    float64
	LastMS    float64
	LastError string
	OkSince   float64
}

// SaveCollectorStatus 把采集层的累计状态写进 meta（面板/月报读它）。
//
// 用 Save 而不是复用 NoteCollector：采集层维护的是**全生命周期累计值**，
// NoteCollector 是按次累加。两者混用会让计数翻倍——这个错在单测里不明显，
// 但面板上会立刻显形。
func (s *Store) SaveCollectorStatus(rows []CollectorStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range rows {
		s.meta.Collectors[r.Name] = CollectorStat{
			Runs:      r.Runs,
			Errors:    r.Errors,
			LastTS:    r.LastTS,
			LastMS:    r.LastMS,
			LastError: r.LastError,
			OkSince:   r.OkSince,
		}
	}
}

// SaveMerges 批量并入（调用方把引擎的 Merge 映射成 Bump）。
//
// 顺序很重要：必须在「取走 merges」之后、下一批事件入库之前调，
// 否则并入会落到还没入库的告警上——那些行会被静默跳过，count 就永久丢了。
func (s *Store) SaveMerges(rows []Bump) (int, error) { return s.BumpFindings(rows) }
