package collector

// network_test.go —— 连接采集的双向测试。
//
// 双向的含义（与 process_test.go 同一纪律）：每条判定都要有**反例**。
// 「公网:4444 报 high」是正例；「内网:4444 不报」「公网:443 不报 high」
// 「127.0.0.1:3306 不报 high」是反例。只测正例的实现，全判可疑也能全绿，
// 那正是要防的失败模式。
//
// 这些用例不依赖任何平台：解析器在 network_parse.go（无 build tag），
// 判定在 network.go（无 build tag）。所以 `go test ./...` 在 darwin /
// linux / windows 上跑的是同一批断言。

import (
	"sort"
	"strings"
	"testing"
)

// pythonConnKeys / pythonListenKeys 是 Python 版 network.py 产出的 subject
// 键集合，硬编码在这里当契约：任何一侧加减字段，这个测试先红。
var (
	pythonConnKeys   = []string{"raddr", "rport", "rip", "laddr", "proto", "public", "risky_port"}
	pythonListenKeys = []string{"addr", "port", "service", "loopback_only", "proto"}
)

// TestIsPrivateHost 公网/非公网判定，双向。
// 这条错了，所有严重度都会跟着错，所以用例密度最高。
func TestIsPrivateHost(t *testing.T) {
	cases := []struct {
		host string
		want bool // true = 非公网（不参与 public 判定）
		note string
	}{
		// —— 反例：这些都是公网，必须判 false ——
		{"8.8.8.8", false, "公网 DNS"},
		{"1.1.1.1", false, "公网 DNS"},
		{"203.0.115.5", false, "公网 IP，且落在 172.16/12 之外"},
		{"2606:4700::1", false, "公网 IPv6，不带方括号"},
		{"[2606:4700::1]", false, "公网 IPv6，带方括号（lsof 写法）"},
		{"2606:4700::1", false, "公网 IPv6，带 zone"},

		// —— 正例：非公网 ——
		{"127.0.0.1", true, "回环"},
		{"127.1.2.3", true, "回环整段"},
		{"10.1.2.3", true, "RFC1918"},
		{"172.16.5.5", true, "RFC1918 下沿"},
		{"172.31.255.1", true, "RFC1918 上沿"},
		{"192.168.1.10", true, "RFC1918"},
		{"100.64.1.2", true, "CGNAT：Tailscale 全在这个段，不排除会刷出几十条假 low"},
		{"100.100.100.100", true, "CGNAT 上沿"},
		{"169.254.1.1", true, "link-local"},
		{"0.0.0.0", true, "通配"},
		{"255.255.255.255", true, "广播"},
		{"::1", true, "IPv6 回环"},
		{"[::1]", true, "IPv6 回环（lsof 写法）"},
		{"fe80::1%en0", true, "IPv6 link-local 带 zone"},
		{"fd00::1", true, "IPv6 ULA"},
		{"224.0.0.1", true, "组播"},
		{"", true, "空地址按非公网处理"},
		{"*", true, "通配绑定"},
		{"not-an-ip", true, "解析失败兜底按非公网（宁漏不错报）"},
	}
	for _, tc := range cases {
		t.Run(tc.host+"_"+tc.note, func(t *testing.T) {
			if got := isPrivateHost(tc.host); got != tc.want {
				t.Fatalf("isPrivateHost(%q)=%v, want %v", tc.host, got, tc.want)
			}
		})
	}
}

// TestConnVerdict 出站连接的严重度，双向。
func TestConnVerdict(t *testing.T) {
	cases := []struct {
		name    string
		raddr   string
		rport   int
		wantSev string
		wantPub bool
		wantRis bool
	}{
		// —— 该报的 ——
		{"公网 + C2 端口", "8.8.8.8", 4444, "high", true, true},
		{"公网 + SSH（内网机器主动外连 22 是隧道信号）", "8.8.8.8", 22, "high", true, true},
		{"公网 + 6379", "1.1.1.1", 6379, "high", true, true},
		{"公网普通端口 → low（不是 high）", "8.8.8.8", 443, "low", true, false},
		{"公网高端口 → low", "1.1.1.1", 53421, "low", true, false},
		{"公网 IPv6 普通端口 → low", "2606:4700::1", 443, "low", true, false},

		// —— 不该报的（反例，缺了这些等于没测）——
		{"内网连 mysql 不报 high", "10.0.0.5", 3306, "info", false, true},
		{"回环连 4444 不报 high", "127.0.0.1", 4444, "info", false, true},
		{"Tailscale 段连 8080 不报 high", "100.64.1.2", 8080, "info", false, true},
		{"IPv6 回环连 22 不报", "::1", 22, "info", false, true},
		{"公网普通高端口不报 high", "8.8.8.8", 12345, "low", true, false},
		{"空对端不报", "", 443, "info", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sev, isPub, risky := connVerdict(tc.raddr, tc.rport)
			if sev != tc.wantSev || isPub != tc.wantPub || risky != tc.wantRis {
				t.Fatalf("connVerdict(%q,%d)=(%s,%v,%v), want (%s,%v,%v)",
					tc.raddr, tc.rport, sev, isPub, risky, tc.wantSev, tc.wantPub, tc.wantRis)
			}
		})
	}
}

// TestListenVerdict 监听端口的严重度与回环降级，双向。
func TestListenVerdict(t *testing.T) {
	cases := []struct {
		name     string
		lip      string
		lport    int
		wantSev  string
		wantSvc  string
		wantLoop bool
	}{
		{"全网卡 mysql", "0.0.0.0", 3306, "high", "mysql", false},
		{"通配 mysql（lsof 写作 *）", "*", 3306, "high", "mysql", false},
		{"IPv6 通配 redis", "[::]", 6379, "high", "redis", false},
		{"全网卡 telnet", "0.0.0.0", 23, "high", "telnet", false},
		{"VNC", "10.0.0.5", 5900, "high", "vnc", false},
		{"RDP", "0.0.0.0", 3389, "high", "rdp", false},

		// —— 反例：回环上的高危端口降一档，但不能降到 info ——
		{"仅回环 mysql 降为 medium", "127.0.0.1", 3306, "medium", "mysql", true},
		{"仅回环 vnc 降为 medium", "127.0.0.1", 5900, "medium", "vnc", true},
		{"IPv6 回环 postgres", "[::1]", 5432, "medium", "postgres", true},

		// —— 反例：普通端口就是 info，别把「开了端口」当信号 ——
		{"HTTP 未收录", "0.0.0.0", 80, "info", "未知服务", false},
		{"HTTPS 未收录", "*", 443, "info", "未知服务", false},
		{"高端口未收录", "0.0.0.0", 62961, "info", "未知服务", false},
		{"低危端口不升级", "127.0.0.1", 22, "low", "ssh", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sev, svc, loop := listenVerdict(tc.lip, tc.lport)
			if sev != tc.wantSev || svc != tc.wantSvc || loop != tc.wantLoop {
				t.Fatalf("listenVerdict(%q,%d)=(%s,%s,%v), want (%s,%s,%v)",
					tc.lip, tc.lport, sev, svc, loop, tc.wantSev, tc.wantSvc, tc.wantLoop)
			}
		})
	}
}

// TestParseLsof 用真机 `lsof -nP -i -w` 的样例行（已脱敏）。
func TestParseLsof(t *testing.T) {
	out := `COMMAND     PID USER   FD   TYPE             DEVICE SIZE/OFF   NODE NAME
nginx       989  xu.    9u  IPv4 0x5ab38585e79b1d08      0t0    TCP *:80 (LISTEN)
mysqld     1513  xu.   19u  IPv6 0x1cc1990f89c35f7b      0t0    TCP *:3306 (LISTEN)
cloudd     1615  xu.   14u  IPv4 0x3700f2fae41788b5      0t0    TCP 127.0.0.1:53923->127.0.0.1:7897 (ESTABLISHED)
com.docke 82524  xu.  140u  IPv4 0x73d17efb63dde2c9      0t0    TCP 127.0.0.1:18081 (LISTEN)
ARDAgent   1614  xu.    8u  IPv6 0xf9f3c4ff98af6edb      0t0    UDP *:3283
Safari     2020  xu.   33u  IPv6 0x1111111111111111      0t0    TCP [::1]:5555->[::1]:8080 (ESTABLISHED)
`
	got := parseLsof(out)
	if len(got) != 6 {
		t.Fatalf("应解析出 6 条（表头不算），got %d: %+v", len(got), got)
	}

	// 1) *:80 LISTEN —— 通配绑定，loopback_only 必须为 false
	if got[0].LAddr != "*" || got[0].LPort != 80 || got[0].State != "LISTEN" ||
		got[0].Proto != "TCP" || got[0].PID != 989 {
		t.Fatalf("LISTEN 行解析错: %+v", got[0])
	}
	if !strings.HasPrefix(got[0].Process, "nginx") {
		t.Fatalf("process 列错: %q", got[0].Process)
	}

	// 2) IPv6 LISTEN
	if got[1].LAddr != "*" || got[1].LPort != 3306 {
		t.Fatalf("IPv6 LISTEN 行解析错: %+v", got[1])
	}

	// 3) IPv4 ESTABLISHED：本地/对端都要拆对
	if got[2].LAddr != "127.0.0.1" || got[2].LPort != 53923 ||
		got[2].RAddr != "127.0.0.1" || got[2].RPort != 7897 ||
		got[2].State != "ESTABLISHED" {
		t.Fatalf("ESTABLISHED 行解析错: %+v", got[2])
	}

	// 4) 长 COMMAND 被 lsof 截断（com.docke）—— 保持原样，不回填（对拍要求）
	if got[3].Process != "com.docke" {
		t.Fatalf("截断的 COMMAND 应原样保留, got %q", got[3].Process)
	}

	// 5) UDP 行没有状态段，且 *:* 的端口按 0 → 既不是连接也不是监听
	if got[4].Proto != "UDP" || got[4].RAddr != "" || got[4].RPort != 0 || got[4].State != "" {
		t.Fatalf("UDP 行解析错: %+v", got[4])
	}

	// 6) 带方括号的 IPv6 对端：地址去掉外层括号由 unbracket 负责，
	//    这里保留 lsof 原文（对拍时 path 与 Python 版一致）
	if got[5].RAddr != "[::1]" || got[5].RPort != 8080 {
		t.Fatalf("IPv6 连接行解析错: %+v", got[5])
	}
	if !isPrivateHost(got[5].RAddr) {
		t.Fatalf("[::1] 应判非公网")
	}
}

// TestParseLsofNoise 表头/垃圾行不能造出事件。
func TestParseLsofNoise(t *testing.T) {
	for _, in := range []string{"", "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n", "garbage\n"} {
		if got := parseLsof(in); len(got) != 0 {
			t.Fatalf("垃圾输入 %q 应解析出 0 条, got %+v", in, got)
		}
	}
}

// TestParseProcNet /proc/net/tcp 与 tcp6 的解码，重点是小端地址。
func TestParseProcNet(t *testing.T) {
	head := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	v4 := head +
		// 127.0.0.1:8080 -> 8.8.8.8:443 ESTABLISHED, uid 501, inode 987654
		"   0: 0100007F:1F90 08080808:01BB 01 00000000:00000000 02:00000000 00000000   501        0 987654 2 0000000000000000 20 4 30 10 -1\n" +
		// 0.0.0.0:22 LISTEN, inode 111
		"   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 111 1 0000000000000000 100 0 0 10 0\n" +
		// TIME_WAIT（inode 0）：本层照收，由 platformConns 负责丢
		"   2: 0100007F:C350 0100007F:1F90 06 00000000:00000000 03:00000000 00000000   501        0 0 3 0000000000000000\n"

	got := parseProcNet(v4, false)
	if len(got) != 3 {
		t.Fatalf("v4 应解析出 3 条, got %d", len(got))
	}
	if got[0].LAddr != "127.0.0.1" || got[0].LPort != 8080 {
		t.Fatalf("小端 IPv4 本地地址解错: %+v", got[0])
	}
	if got[0].RAddr != "8.8.8.8" || got[0].RPort != 443 || got[0].State != "ESTABLISHED" {
		t.Fatalf("小端 IPv4 对端解错: %+v", got[0])
	}
	if got[0].User != "501" || got[0].Inode != 987654 {
		t.Fatalf("uid/inode 列错: %+v", got[0])
	}
	if got[1].LAddr != "0.0.0.0" || got[1].LPort != 22 || got[1].State != "LISTEN" {
		t.Fatalf("LISTEN 行解错: %+v", got[1])
	}
	if got[2].State != "TIME_WAIT" || got[2].Inode != 0 {
		t.Fatalf("TIME_WAIT 行解错: %+v", got[2])
	}

	// IPv6：4 组小端 32 位字。::1 的原文是 ...0001000000，按大端直读会得到
	// ::100:0:0:0 —— 这个用例就是钉住这个坑的。
	v6 := head +
		"   0: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 222 1 0000000000000000 100 0 0 10 0\n" +
		"   1: 0000000000000000FFFF00000100007F:1F90 00000000000000000000000000000000:0000 01 00000000:00000000 00:00000000 00000000   501        0 333 1 0000000000000000 20 4 30 10 -1\n"
	got6 := parseProcNet(v6, true)
	if len(got6) != 2 {
		t.Fatalf("v6 应解析出 2 条, got %d", len(got6))
	}
	if got6[0].LAddr != "[::1]" || got6[0].LPort != 22 || got6[0].State != "LISTEN" {
		t.Fatalf("IPv6 ::1 解错（小端方向搞反了？）: %+v", got6[0])
	}
	// ::ffff:127.0.0.1（v4-mapped）也必须解出来，且判为非公网
	if got6[1].LAddr != "127.0.0.1" {
		t.Fatalf("v4-mapped IPv6 应归一成 IPv4（不加括号）: %+v", got6[1])
	}
	if !isPrivateHost(got6[1].LAddr) {
		t.Fatalf("v4-mapped 回环应判非公网")
	}
}

// TestParseNetstat Windows `netstat -ano` 解析。
func TestParseNetstat(t *testing.T) {
	out := `
活动连接

  协议  本地地址          外部地址        状态           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1234
  TCP    10.0.0.5:51544         1.1.1.1:443            ESTABLISHED     8877
  TCP    [::]:445               [::]:0                 LISTENING       4
  UDP    0.0.0.0:500            *:*                                    1234
  TCP    127.0.0.1:3306         127.0.0.1:51544        ESTABLISHED     5555
`
	got := parseNetstat(out)
	if len(got) != 5 {
		t.Fatalf("应解析出 5 条, got %d: %+v", len(got), got)
	}
	if got[0].LAddr != "0.0.0.0" || got[0].LPort != 135 || got[0].State != "LISTEN" || got[0].PID != 1234 {
		t.Fatalf("LISTEN 行解析错: %+v", got[0])
	}
	if got[1].RAddr != "1.1.1.1" || got[1].RPort != 443 || got[1].State != "ESTABLISHED" || got[1].PID != 8877 {
		t.Fatalf("ESTABLISHED 行解析错: %+v", got[1])
	}
	if got[2].LAddr != "[::]" || got[2].LPort != 445 || got[2].State != "LISTEN" {
		t.Fatalf("IPv6 通配行解析错: %+v", got[2])
	}
	// UDP 行没有状态列，PID 必须从最后一列拿
	if got[3].Proto != "UDP" || got[3].PID != 1234 || got[3].State != "" || got[3].RPort != 0 {
		t.Fatalf("UDP 行解析错: %+v", got[3])
	}
}

// TestDiffOnlyNew 差分：第一轮全出，第二轮同样的快照一条不出。
// 少了这个反例，采集器每 5s 就把整张连接表重报一遍。
func TestDiffOnlyNew(t *testing.T) {
	rows := []netRow{
		{Proto: "TCP", LAddr: "127.0.0.1", LPort: 53923, RAddr: "8.8.8.8", RPort: 443, State: "ESTABLISHED", PID: 100, Process: "curl"},
		{Proto: "TCP", LAddr: "*", LPort: 3306, State: "LISTEN", PID: 200, Process: "mysqld"},
	}
	n := &Network{}
	first := n.diff(rows)
	if len(first) != 2 {
		t.Fatalf("首轮应产出 2 条, got %d", len(first))
	}
	if first[0].Kind != "net.connect" || first[1].Kind != "net.listen" {
		t.Fatalf("kind 顺序错: %s / %s", first[0].Kind, first[1].Kind)
	}
	if second := n.diff(rows); len(second) != 0 {
		t.Fatalf("同快照第二轮应为 0 条, got %d: %+v", len(second), second)
	}
	// 连接消失后再出现 → 重新上报，且带 beacon 计数（只采不算）
	if gone := n.diff(nil); len(gone) != 0 {
		t.Fatalf("连接消失不应产事件, got %d", len(gone))
	}
	again := n.diff(rows)
	if len(again) != 2 {
		t.Fatalf("重连应重新上报 2 条, got %d", len(again))
	}
	hits, ok := again[0].Subject["beacon_hits"]
	if !ok {
		t.Fatalf("第二次连同一目的地应带 beacon_hits: %+v", again[0].Subject)
	}
	if hits.(int) != 2 {
		t.Fatalf("beacon_hits 应为 2, got %v", hits)
	}
	// beacon 只采不算：严重度必须还是 low（8.8.8.8:443 属公网普通端口）
	if again[0].Severity != "low" {
		t.Fatalf("beacon 不得改变严重度, got %s", again[0].Severity)
	}
}

// TestConnEventContract 事件字段与 Python 版逐字段对齐。
func TestConnEventContract(t *testing.T) {
	n := &Network{}
	evs := n.diff([]netRow{{
		Proto: "TCP", LAddr: "10.0.0.5", LPort: 51544,
		RAddr: "8.8.8.8", RPort: 4444, State: "ESTABLISHED",
		PID: 8877, User: "xu.", Process: "nc",
	}})
	if len(evs) != 1 {
		t.Fatalf("应产出 1 条, got %d", len(evs))
	}
	ev := evs[0]
	if ev.Kind != "net.connect" || ev.Source != "network" {
		t.Fatalf("kind/source 错: %s/%s", ev.Kind, ev.Source)
	}
	if ev.Path != "8.8.8.8:4444" {
		t.Fatalf("path 应为 rip:rport, got %q", ev.Path)
	}
	if ev.Severity != "high" {
		t.Fatalf("公网 + 4444 应为 high, got %s", ev.Severity)
	}
	if ev.PID == nil || *ev.PID != 8877 || ev.Process != "nc" || ev.User != "xu." {
		t.Fatalf("pid/process/user 错: %+v", ev)
	}
	if ev.Subject["raddr"] != "8.8.8.8" || ev.Subject["rip"] != "8.8.8.8" ||
		ev.Subject["laddr"] != "10.0.0.5" || ev.Subject["rport"] != 4444 ||
		ev.Subject["proto"] != "TCP" || ev.Subject["public"] != true ||
		ev.Subject["risky_port"] != true {
		t.Fatalf("subject 值错: %+v", ev.Subject)
	}
	if _, extra := ev.Subject["beacon_hits"]; extra {
		t.Fatalf("首轮不应出现 beacon_hits（会破坏与 Python 版的对拍）")
	}
	if missing, extra := diffKeys(ev.Subject, pythonConnKeys, []string{"beacon_hits", "proxy"}); len(missing) > 0 || len(extra) > 0 {
		t.Fatalf("subject 键集合与 Python 版不一致: 缺 %v 多 %v", missing, extra)
	}
}

// TestListenEventContract 监听事件的字段契约。
func TestListenEventContract(t *testing.T) {
	n := &Network{}
	evs := n.diff([]netRow{{Proto: "TCP", LAddr: "0.0.0.0", LPort: 3306, State: "LISTEN", PID: 200, Process: "mysqld"}})
	if len(evs) != 1 {
		t.Fatalf("应产出 1 条, got %d", len(evs))
	}
	ev := evs[0]
	if ev.Kind != "net.listen" || ev.Path != "0.0.0.0:3306" || ev.Severity != "high" {
		t.Fatalf("listen 事件字段错: %+v", ev)
	}
	if ev.Subject["addr"] != "0.0.0.0" || ev.Subject["port"] != 3306 ||
		ev.Subject["service"] != "mysql" || ev.Subject["loopback_only"] != false ||
		ev.Subject["proto"] != "TCP" {
		t.Fatalf("listen subject 值错: %+v", ev.Subject)
	}
	if missing, extra := diffKeys(ev.Subject, pythonListenKeys, []string{"workers"}); len(missing) > 0 || len(extra) > 0 {
		t.Fatalf("listen subject 键集合不一致: 缺 %v 多 %v", missing, extra)
	}

	// 反例：同一个 3306 绑在回环上，必须降级 —— 这是本采集器最容易误报的地方
	evs = (&Network{}).diff([]netRow{{Proto: "TCP", LAddr: "127.0.0.1", LPort: 3306, State: "LISTEN", PID: 201}})
	if len(evs) != 1 || evs[0].Severity != "medium" {
		t.Fatalf("回环 3306 应为 medium, got %+v", evs)
	}
	if evs[0].Subject["loopback_only"] != true {
		t.Fatalf("loopback_only 应为 true: %+v", evs[0].Subject)
	}
}

// TestNoEventForUnboundSockets 没有对端也没有监听状态的 socket 不产事件。
func TestNoEventForUnboundSockets(t *testing.T) {
	n := &Network{}
	rows := []netRow{
		{Proto: "UDP", LAddr: "*", LPort: 0, RAddr: "*", RPort: 0, State: "", PID: 9},   // lsof 的 *:*
		{Proto: "UDP", LAddr: "0.0.0.0", LPort: 3283, RAddr: "", RPort: 0, State: ""},   // 未连接 UDP
		{Proto: "TCP", LAddr: "0.0.0.0", LPort: 0, RAddr: "", RPort: 0, State: "CLOSE"}, // 已关闭
	}
	if evs := n.diff(rows); len(evs) != 0 {
		t.Fatalf("这些行不应产事件, got %d: %+v", len(evs), evs)
	}
}

// TestListenWildcardIsNotLoopbackOnly 通配绑定不能算回环——这是「本机起个
// redis 不设密码」和「全网可达的 redis」的区别，判错等于漏掉一个 high。
func TestListenWildcardIsNotLoopbackOnly(t *testing.T) {
	for _, addr := range []string{"*", "0.0.0.0", "[::]", "::"} {
		sev, _, loop := listenVerdict(addr, 6379)
		if loop {
			t.Fatalf("%q 是通配绑定，不能判 loopback_only", addr)
		}
		if sev != "high" {
			t.Fatalf("%q 上的 redis 应为 high, got %s", addr, sev)
		}
	}
	for _, addr := range []string{"127.0.0.1", "[::1]", "::1", "localhost"} {
		if _, _, loop := listenVerdict(addr, 6379); !loop {
			t.Fatalf("%q 应判 loopback_only", addr)
		}
	}
}

// TestListenDedupeAcrossWorkers 降噪：同一地址:端口上的多个 worker 合成一条。
// 反例同样重要：不同端口必须各出一条，否则就是把不同服务混成一个。
func TestListenDedupeAcrossWorkers(t *testing.T) {
	rows := []netRow{
		{Proto: "TCP", LAddr: "*", LPort: 443, State: "LISTEN", PID: 1001, Process: "nginx"},
		{Proto: "TCP", LAddr: "*", LPort: 443, State: "LISTEN", PID: 1002, Process: "nginx"},
		{Proto: "TCP", LAddr: "*", LPort: 443, State: "LISTEN", PID: 1003, Process: "nginx"},
		{Proto: "TCP", LAddr: "*", LPort: 80, State: "LISTEN", PID: 1004, Process: "nginx"},
	}
	// 降噪开：443 三个 worker 合一，80 单独一条 → 2 条
	n := &Network{denoise: true}
	evs := n.diff(rows)
	if len(evs) != 2 {
		t.Fatalf("降噪后应产出 2 条 (443 合并 + 80), got %d", len(evs))
	}
	if evs[0].Path != "*:443" || evs[0].Subject["workers"] != 3 {
		t.Fatalf("443 应带 workers=3: path=%s subject=%+v", evs[0].Path, evs[0].Subject)
	}
	if _, ok := evs[1].Subject["workers"]; ok {
		t.Fatalf("单 worker 不应带 workers 字段: %+v", evs[1].Subject)
	}
	// 第二轮不再重报（新 worker 加入也不该重新告警）
	rows = append(rows, netRow{Proto: "TCP", LAddr: "*", LPort: 443, State: "LISTEN", PID: 1005, Process: "nginx"})
	if again := n.diff(rows); len(again) != 0 {
		t.Fatalf("同一端口新增 worker 不应重复上报, got %d", len(again))
	}

	// 降噪关（对拍口径）：一个 worker 一条，与 Python 版一致
	raw := (&Network{denoise: false}).diff(rows[:4])
	if len(raw) != 4 {
		t.Fatalf("关闭降噪应产出 4 条, got %d", len(raw))
	}
}

// TestProxyEgressDowngrade 降噪：代理客户端连公网节点降为 info（不是丢弃）。
// 反例：普通进程连公网仍必须是 low；代理连内网端口不受影响。
func TestProxyEgressDowngrade(t *testing.T) {
	cases := []struct {
		name      string
		proc      string
		raddr     string
		rport     int
		denoise   bool
		wantSev   string
		wantProxy bool
	}{
		{"lsof 截断的 verge-mih 也要认得", "verge-mih", "108.162.198.60", 443, true, "info", true},
		{"完整名字 clash-verge", "clash-verge", "108.162.198.60", 443, true, "info", true},
		{"tailscaled 连公网", "tailscaled", "203.0.115.5", 443, true, "info", true},
		{"普通进程连公网仍是 low", "Safari", "203.0.115.5", 443, true, "low", false},
		{"名字太短不做前缀匹配", "sss", "203.0.115.5", 443, true, "low", false},
		{"关闭降噪时代理也是 low（对拍口径）", "verge-mih", "108.162.198.60", 443, false, "low", false},
		{"代理连高危端口不降级", "verge-mih", "108.162.198.60", 4444, true, "high", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := &Network{denoise: tc.denoise}
			evs := n.diff([]netRow{{Proto: "TCP", LAddr: "127.0.0.1", LPort: 50000,
				RAddr: tc.raddr, RPort: tc.rport, State: "ESTABLISHED", PID: 42, Process: tc.proc}})
			if len(evs) != 1 {
				t.Fatalf("应产出 1 条, got %d", len(evs))
			}
			if evs[0].Severity != tc.wantSev {
				t.Fatalf("严重度应为 %s, got %s", tc.wantSev, evs[0].Severity)
			}
			if _, ok := evs[0].Subject["proxy"]; ok != tc.wantProxy {
				t.Fatalf("proxy 标记应为 %v, got %+v", tc.wantProxy, evs[0].Subject)
			}
		})
	}
}

// TestNetworkCollectorDefaults 采集器元数据（对拍靠 name/interval 定位）。
func TestNetworkCollectorDefaults(t *testing.T) {
	n := NewNetwork(Config{})
	if n.Name() != "network" {
		t.Fatalf("名称应为 network, got %s", n.Name())
	}
	if n.Mode() != ModePoll {
		t.Fatalf("模式应为 poll, got %s", n.Mode())
	}
	if n.Interval().String() != "5s" {
		t.Fatalf("默认周期应为 5s, got %s", n.Interval())
	}
	// 配置显式关闭时 Enabled=false，但仍应可用（不可用是 Probe 的结论）
	off := false
	n2 := NewNetwork(Config{Enabled: &off, Interval: 30 * 1e9})
	if n2.Interval().String() != "30s" {
		t.Fatalf("应尊重配置周期, got %s", n2.Interval().String())
	}
	if nn := n2.(*Network); nn.Status.Enabled {
		t.Fatalf("配置关闭后 Enabled 应为 false")
	}
}

// TestLsofRemotePublicIPv6 端到端：lsof 的 [公网 v6]:443 必须判 low 而不是 info。
// Python 版这里恒为 info（方括号导致解析异常→兜底私有），差异方向是 Go 多报。
func TestLsofRemotePublicIPv6(t *testing.T) {
	rows := parseLsof("APP 42 u 3u IPv6 0x1 0t0 TCP [::1]:51544->[2606:4700::1]:443 (ESTABLISHED)\n")
	if len(rows) != 1 {
		t.Fatalf("应解析出 1 条, got %d", len(rows))
	}
	if isPrivateHost(rows[0].RAddr) {
		t.Fatalf("公网 IPv6 对端不应判非公网: %q", rows[0].RAddr)
	}
	evs := (&Network{}).diff(rows)
	if len(evs) != 1 || evs[0].Severity != "low" {
		t.Fatalf("公网 IPv6:443 应为 low, got %+v", evs)
	}
}

// diffKeys 比较实际键集合与期望键集合，双向返回缺失与多余。
// allowExtra 是已经写进文档的扩展键（beacon_hits / proxy / workers），
// 除此之外任何多余键都算契约破裂。
func diffKeys(got map[string]any, want, allowExtra []string) (missing, extra []string) {
	have := make([]string, 0, len(got))
	for k := range got {
		have = append(have, k)
	}
	sort.Strings(have)
	sort.Strings(want)
	set := map[string]bool{}
	for _, k := range have {
		set[k] = true
	}
	for _, k := range want {
		if !set[k] {
			missing = append(missing, k)
		}
	}
	wset := map[string]bool{}
	for _, k := range want {
		wset[k] = true
	}
	for _, k := range allowExtra {
		wset[k] = true
	}
	for _, k := range have {
		if !wset[k] {
			extra = append(extra, k)
		}
	}
	return missing, extra
}
