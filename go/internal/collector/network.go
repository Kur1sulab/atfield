package collector

// network.go —— 连接采集的通用部分：判定、差分、事件组装都在这里；
// 取连接表按平台实现（network_darwin.go / network_linux.go / network_windows.go），
// 平台文件只负责「跑命令/读文件 → []netRow」。
//
// 为什么判定必须放共用文件：Python 版 network.py 的严重度分支只有三行，
// 但它是两版对拍的**唯一**判定来源。判定一旦被复制进平台文件，四平台就会
// 长出四套阈值，对拍失去意义。
//
// 字段与 atfield/collectors/network.py 逐一对齐（kind/source/path/severity/
// subject 的每个键都同名同义）：Go 版验收标准是「同一份事件流两版告警集合
// 一致」，键名一漂移对拍就作废。

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Kur1sulab/atfield/go/internal/model"
)

// c2Ports 常见 C2 / 后门 / 管理面端口，与 Python 版 network.py 的
// `C2_PORTS | {4444,1337,31337,6667,9001}` 完全同集（Python 里后四个写成了
// 冗余的 `or ... in (...)`，并集一样，这里只保留一个集合）。
//
// 注意 22 在里面：出站 SSH 到公网按 Python 版口径就是 high。这不是笔误——
// 内网机器主动外连 22 是横向/隧道的高价值信号，宁可让运维解释一次。
var c2Ports = map[int]bool{
	21: true, 22: true, 23: true, 53: true, 445: true,
	1433: true, 1521: true, 3306: true, 3389: true, 5900: true,
	6379: true, 8080: true, 8443: true,
	4444: true, 1337: true, 31337: true, 6667: true, 9001: true,
}

// listenHint 高危监听端口的静态画像。
type listenHint struct {
	Service string
	Sev     string
}

// riskyListen 与 Python 版 RISKY_LISTEN 同键同值（service 文本参与对拍，别改）。
var riskyListen = map[int]listenHint{
	21:    {"ftp", "medium"},
	22:    {"ssh", "low"},
	23:    {"telnet", "high"},
	445:   {"smb", "high"},
	1433:  {"mssql", "high"},
	3306:  {"mysql", "high"},
	3389:  {"rdp", "high"},
	5432:  {"postgres", "medium"},
	5900:  {"vnc", "high"},
	6379:  {"redis", "high"},
	27017: {"mongodb", "high"},
	9200:  {"elasticsearch", "high"},
	11211: {"memcached", "high"},
}

// netRow 各平台把原生字段映射到这里再判定。字段语义与 Python 版 `_from_lsof`
// 构造的 row 字典一一对应：
//
//	proto=L4, laddr/lport=本地, raddr/rport=对端, pid/process/user=归属
//
// Inode 只在 Linux 上使用（/proc/net/tcp 的第 10 列），用来把 socket 归属到
// 进程；其他平台留 0。
type netRow struct {
	Proto   string // TCP / UDP
	LAddr   string // 本地地址，通配绑定是 * / 0.0.0.0 / ::
	LPort   int
	RAddr   string // 对端地址；空 = 没有对端（LISTEN、未连接的 UDP）
	RPort   int
	State   string // LISTEN / ESTABLISHED / ...（空表示未知）
	PID     int
	User    string
	Process string
	Inode   int
}

// Network 连接采集器。
type Network struct {
	Base

	mu      sync.Mutex
	conns   map[string]netRow // 上一轮已上报的连接（差分用）
	listens map[string]netRow // 上一轮已上报的监听
	hits    map[string]int    // beacon 原料：同一 (pid, rip, rport) 第几次出现

	// denoise 降噪开关：默认开，`Options["denoise"]=false` 可关掉，
	// 关掉后事件流与 Python 版逐条一致（对拍用）。
	// 降噪只做两件事，都在下面标了原因：多 worker 监听去重、代理出站降级。
	denoise bool
}

// NewNetwork 构造并自检。
func NewNetwork(cfg Config) Collector {
	n := &Network{denoise: true}
	interval := 5 * time.Second
	if cfg.Interval > 0 {
		interval = cfg.Interval
	}
	if v, ok := cfg.Options["denoise"].(bool); ok {
		n.denoise = v
	}
	n.Init("network", ModePoll, interval, platformProbeNet)
	if !cfg.WantEnabled() {
		n.Status.Enabled = false
	}
	return n
}

// Collect 采一轮连接表，只输出「上一轮没见过」的连接/监听。
//
// 为什么只报新增：连接表每 5s 全量重采，若每轮全量出事件，一台正常机器
// 每分钟能刷出几千条同类事件，检测价值被自己的噪音淹没。Python 版同口径
// （`_diff` 用 (laddr, raddr, pid) 做键），对拍必须一致。
func (n *Network) Collect(ctx context.Context) ([]model.Event, error) {
	rows, err := platformConns(ctx)
	if err != nil {
		return nil, err
	}
	return n.diff(rows), nil
}

// diff 把本轮快照与上一轮做差，产出新事件。纯函数式（只依赖 n 的差分状态），
// 因此测试可以直接喂 []netRow 走完整判定链路，不需要真的开 socket。
func (n *Network) diff(rows []netRow) []model.Event {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.conns == nil {
		n.conns = map[string]netRow{}
		n.listens = map[string]netRow{}
		n.hits = map[string]int{}
	}

	conns := make(map[string]netRow, len(rows))
	listens := make(map[string]netRow)
	workers := map[string]int{}
	for _, r := range rows {
		switch {
		case r.RAddr != "" && r.RPort > 0:
			conns[connKey(r)] = r
		case r.LPort > 0 && r.State == "LISTEN":
			listens[n.listenKey(r)] = r
			if n.denoise {
				workers[listenAddrKey(r)]++
			}
		}
	}

	// 本轮内同键去重：lsof 对同一个 socket 不会给两行，但 /proc 与 netstat
	// 会（双栈监听、同一连接被父子进程共享），Python 版用 dict 天然去重，
	// 这里必须显式做，否则会出现「同一条连接两个事件」。
	emitted := map[string]bool{}

	var out []model.Event
	for _, r := range rows {
		if r.RAddr != "" && r.RPort > 0 {
			k := connKey(r)
			if _, seen := n.conns[k]; seen || emitted[k] {
				continue
			}
			emitted[k] = true
			ev := connEvent(r, n.beacon(r), n.denoise)
			out = append(out, *ev)
			continue
		}
		if r.LPort > 0 && r.State == "LISTEN" {
			k := n.listenKey(r)
			if _, seen := n.listens[k]; seen || emitted[k] {
				continue
			}
			emitted[k] = true
			ev := listenEvent(r)
			if n.denoise {
				if w := workers[listenAddrKey(r)]; w > 1 {
					ev.Subject["workers"] = w
				}
			}
			out = append(out, *ev)
		}
	}

	n.conns, n.listens = conns, listens
	return out
}

// Snapshot 供 store.set_state("connections", ...) 使用，键名照 Python 版
// （active / public / rows / listeners / ts）。
//
// 为什么从 n.conns / n.listens 取而不是重新跑一遍 lsof：那一轮刚采完的
// 快照就是这两个 map（diff 结尾刚整体替换过），再采一次等于每 5 秒多开
// 两个子进程，还会让「面板上的连接」与「事件里的连接」来自不同时刻。
//
// rows / listeners 都做稳定排序：map 迭代顺序随机，不排序会让同一份数据
// 两次请求顺序不同，前端列表跟着跳。
func (n *Network) Snapshot() map[string]any {
	n.mu.Lock()
	defer n.mu.Unlock()

	rows := make([]map[string]any, 0, len(n.conns))
	pub := 0
	for _, r := range n.conns {
		public := r.RAddr != "" && !isPrivateHost(r.RAddr)
		if public {
			pub++
		}
		rows = append(rows, map[string]any{
			"proto": r.Proto, "laddr": r.LAddr, "lport": r.LPort,
			"raddr": r.RAddr, "rport": r.RPort, "state": r.State,
			"pid": r.PID, "process": r.Process, "user": r.User,
			"public": public,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		// 公网连接排前面，再按对端端口——与 Python 的 sort 键一致。
		pi, pj := rows[i]["public"].(bool), rows[j]["public"].(bool)
		if pi != pj {
			return pi
		}
		return asIntAny(rows[i]["rport"]) < asIntAny(rows[j]["rport"])
	})

	listeners := make([]map[string]any, 0, len(n.listens))
	for _, r := range n.listens {
		listeners = append(listeners, map[string]any{
			"proto": r.Proto, "laddr": r.LAddr, "lport": r.LPort,
			"pid": r.PID, "process": r.Process, "user": r.User,
		})
	}
	sort.Slice(listeners, func(i, j int) bool {
		return asIntAny(listeners[i]["lport"]) < asIntAny(listeners[j]["lport"])
	})
	if len(rows) > 300 {
		rows = rows[:300]
	}
	if len(listeners) > 120 {
		listeners = listeners[:120]
	}
	return map[string]any{
		"active":    len(n.conns),
		"public":    pub,
		"rows":      rows,
		"listeners": listeners,
		"ts":        nowSeconds(),
	}
}

// asIntAny 读 map 里的端口值。写成小工具而不是断言 int：
// rows 是 map[string]any，排序闭包里断言失败会 panic，宁可退化成 0。
func asIntAny(v any) int {
	if n, ok := v.(int); ok {
		return n
	}
	return 0
}

// beacon 记录「同一进程 + 同一目的地」第几次被看到，只采不算：
// 单次连接说明不了什么，周期性重连同一 (pid, rip, rport) 才是 beaconing 的
// 形态。这里只给出原料（beacon_hits ≥ 2 时才写进 subject），**不参与严重度**
// ——Python 版没有这条，多算一步会让两版告警不等。
func (n *Network) beacon(r netRow) int {
	k := fmt.Sprintf("%d|%s|%d", r.PID, r.RAddr, r.RPort)
	n.hits[k]++
	// 键只增不减会随长时间运行膨胀；超过 2 万条直接清空重来，
	// 丢的是历史计数不是当前判定（beacon 原料本来就是短期特征）。
	if len(n.hits) > 20000 {
		n.hits = map[string]int{k: 1}
	}
	return n.hits[k]
}

func connKey(r netRow) string {
	return fmt.Sprintf("%s|%s|%d|%d", r.LAddr, r.RAddr, r.LPort, r.PID)
}

// listenKey 监听去重键。
//
// denoise 关掉时按 (laddr, port, pid)：一个进程一个事件，与 Python 版一致。
// denoise 打开时按 (proto, laddr, port)：nginx 的 13 个 worker 各自 LISTEN
// 同一个 *:443，对「这台机器对外开了什么」没有任何增量信息，合并成一条并把
// worker 数写进 subject["workers"]。实测本机 82 条监听里 24 条是纯重复。
func (n *Network) listenKey(r netRow) string {
	if n.denoise {
		return listenAddrKey(r)
	}
	return fmt.Sprintf("%s|%d|%d", r.LAddr, r.LPort, r.PID)
}

// listenAddrKey 只看「地址 + 端口」的聚合键（worker 计数用）。
func listenAddrKey(r netRow) string {
	return fmt.Sprintf("%s|%s|%d", r.Proto, r.LAddr, r.LPort)
}

// proxyEgressProcs 代理/隧道客户端的进程名白名单（小写）。
//
// 为什么用**前缀**匹配：lsof 的 COMMAND 列截断到 9 字符，实机看到的是
// "verge-mih"（verge-mihomo 的前 9 个字符），精确匹配一个都命中不了。
// 代价是名单必须足够长（≥5 字符）以免误伤，这里最短的也是 "xray"→不收录，
// 只留 ≥5 字符的名字。
//
// 边界要说清楚：改名的后门不在名单里，也就是说这条只能压正常软件的噪音，
// 不构成检测能力。它换掉的是「40 条 low 里 10 条来自代理客户端」这种噪音。
var proxyEgressProcs = []string{
	"clash", "clash-verge", "verge-mihomo", "mihomo", "v2ray", "sing-box",
	"xray-core", "trojan", "shadowsocks", "ss-local", "surge", "stash",
	"quantumult", "tailscaled", "tailscale", "wireguard-go", "openvpn",
	"warp-svc", "cloudflared", "frpc", "ngrok",
}

func isProxyProc(proc string) bool {
	p := strings.ToLower(strings.TrimSpace(proc))
	if len(p) < 5 {
		return false
	}
	for _, name := range proxyEgressProcs {
		if strings.HasPrefix(name, p) || strings.HasPrefix(p, name) {
			return true
		}
	}
	return false
}

// connVerdict 出站连接的判定，逐字对应 Python 版 `_from_lsof` 的严重度分支：
//
//	public && risky → high；public → low；其余 → info
//
// 顺序不能换：先判 public 再判端口，否则内网 3306 会被抬成 high，
// 而「内网连数据库」是本机每天都在发生的事。
func connVerdict(raddr string, rport int) (sev string, isPublic, risky bool) {
	isPublic = raddr != "" && !isPrivateHost(raddr)
	risky = c2Ports[rport]
	switch {
	case isPublic && risky:
		return "high", isPublic, risky
	case isPublic:
		return "low", isPublic, risky
	default:
		return "info", isPublic, risky
	}
}

// listenVerdict 监听端口的判定（Python 版同款）：
// 未收录的端口一律 info——「监听了高端口」本身不是信号，macOS 上
// rapportd/ControlCenter 每个会话都开一堆随机高端口。
//
// 只监听回环时把 high/critical 降为 medium：127.0.0.1 上的 mysql 只有本机
// 能连，暴露面确实低一档；但仍然不是 info，因为本机进程照样能读它。
func listenVerdict(lip string, lport int) (sev, service string, loopbackOnly bool) {
	h, ok := riskyListen[lport]
	sev, service = h.Sev, h.Service
	if !ok {
		sev, service = "info", "未知服务"
	}
	loopbackOnly = isLoopbackHost(lip)
	if loopbackOnly && (sev == "high" || sev == "critical") {
		sev = "medium"
	}
	return sev, service, loopbackOnly
}

// connEvent 组装 net.connect 事件，subject 键集合与 Python 版完全相同。
func connEvent(r netRow, beaconHits int, denoise bool) *model.Event {
	sev, isPublic, risky := connVerdict(r.RAddr, r.RPort)
	// 降噪（只作用于 low 档）：本机代理/隧道客户端连公网节点，每换一个出口
	// 就是一条「公网 + low」。实测 verge-mihomo 一个进程 10 条，占 low 总量
	// 的四分之一，而它连的每一条都是正常的。降为 info 而不是丢弃——「这台
	// 机器在通过代理出网」本身是有用的清点信息，只是不该占告警位。
	if denoise && sev == "low" && isProxyProc(r.Process) {
		sev = "info"
	}
	ev := model.NewEvent("net.connect", "network")
	pid := r.PID
	ev.PID = &pid
	ev.Process = r.Process
	ev.User = r.User
	ev.Path = fmt.Sprintf("%s:%d", r.RAddr, r.RPort)
	ev.Severity = sev
	ev.Subject = map[string]any{
		"raddr":      r.RAddr,
		"rport":      r.RPort,
		"rip":        r.RAddr,
		"laddr":      r.LAddr,
		"proto":      r.Proto,
		"public":     isPublic,
		"risky_port": risky,
	}
	if denoise && isProxyProc(r.Process) && isPublic {
		ev.Subject["proxy"] = true
	}
	if beaconHits >= 2 {
		// 额外键（Python 版没有）：只采不算的 beaconing 原料。
		// 只在重复出现时写入，正常流量的事件流与 Python 版逐字节一致。
		ev.Subject["beacon_hits"] = beaconHits
	}
	return ev
}

// listenEvent 组装 net.listen 事件。
func listenEvent(r netRow) *model.Event {
	sev, service, loopbackOnly := listenVerdict(r.LAddr, r.LPort)
	ev := model.NewEvent("net.listen", "network")
	pid := r.PID
	ev.PID = &pid
	ev.Process = r.Process
	ev.User = r.User
	ev.Path = fmt.Sprintf("%s:%d", r.LAddr, r.LPort)
	ev.Severity = sev
	ev.Subject = map[string]any{
		"addr":          r.LAddr,
		"port":          r.LPort,
		"service":       service,
		"loopback_only": loopbackOnly,
		"proto":         r.Proto,
	}
	return ev
}

// isLoopbackHost 判断监听地址是否只对本机可见。
// `*` / `0.0.0.0` / `::` 是通配绑定，外部可达，不能算回环。
func isLoopbackHost(host string) bool {
	h := unbracket(host)
	switch h {
	case "":
		return false
	case "localhost":
		return true
	}
	ip := net.ParseIP(h)
	if ip == nil {
		return strings.HasPrefix(h, "127.")
	}
	return ip.IsLoopback()
}

// isPrivateHost 判断一个地址是否「非公网」。
//
// 与 Python 版 `_is_private()` 的语义对齐：解析失败按私有处理（宁可漏报
// 一条低危，也不要把一堆畸形地址刷成 high）。差异点只有一处，见文件末尾。
//
// 为什么要逐条列 IANA 特殊段而不是只用 net.IP.IsPrivate：
// 100.64.0.0/10（CGNAT）在 Go 里不算 private，而 Tailscale / 运营商 NAT
// 全在这个段——本机实测有 Tailscale，不排除的话每条 tailnet 连接都会判成
// 「公网」，直接产出几十条 low 假阳性。这条是实测降噪，不是理论洁癖。
var privateCIDRs = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
	"192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
	"198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
	"255.255.255.255/32",
}

var privateNets = func() []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(privateCIDRs))
	for _, c := range privateCIDRs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}()

func isPrivateHost(host string) bool {
	h := unbracket(host)
	if h == "" || h == "*" || h == "localhost" {
		return true // 通配/未知一律按非公网
	}
	// IPv6 link-local 带 zone（fe80::1%en0），剥掉再解析
	if i := strings.IndexByte(h, '%'); i > 0 {
		h = h[:i]
	}
	// IPv4-mapped IPv6（::ffff:1.2.3.4）：按 v4 判，否则 IsPrivate 会漏
	ip := net.ParseIP(h)
	if ip == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		// IsPrivate 覆盖 RFC1918 与 IPv6 ULA（fc00::/7），
		// 但**不**覆盖 CGNAT/0.0.0.0 等段——下面那张表补的正是这些。
		return true
	}
	for _, n := range privateNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// unbracket 去掉 lsof / netstat 给 IPv6 加的方括号。
//
// 已知与 Python 版的唯一行为差异：Python 的 `_from_lsof` 把 `[2606:...]:443`
// 的 rip 原样保留方括号，`ipaddress.ip_address("[2606:...]")` 抛异常 → 兜底
// 判私有 → **IPv6 公网连接在 Python 版恒为 info**。Go 侧剥括号后能正确判成
// public，方向是「Go 多报、不漏报」。这条差异只影响 IPv6 远端，已写进
// MIGRATION.md，等 Python 侧同步修正后消失。
func unbracket(host string) string {
	if strings.HasPrefix(host, "[") {
		if i := strings.IndexByte(host, ']'); i > 0 {
			return host[1:i]
		}
	}
	return host
}

// platformProbeNet 由各平台实现（Probe 用）。
// platformConns 由各平台实现（取连接表）。
//
// 二者分开是因为「能不能用」和「这一轮取到什么」是两件事：Probe 只在启动时
// 跑一次，取数据每 5s 跑一次，失败语义不同（前者决定控制台显示可用性，
// 后者只记一次 errors 计数）。
