package collector

// network_parse.go —— 三平台连接表的**纯文本解析**，故意不带 build tag。
//
// 为什么解析器放在无 tag 文件里（而不是像 process_darwin.go 那样跟平台文件
// 待在一起）：这三段都是有格式规范的字符串处理，把 `lsof` / `/proc/net/tcp` /
// `netstat -ano` 的样例贴进表驱动测试，就能在没有对应系统的机器上回归。
// 放平台文件里的话，`go test ./...` 在 linux 上连编译都过不了（本仓库已有
// 同类问题：process_test.go 调用了 darwin 专属的 parsePS）。
//
// 平台文件只负责「跑命令/读文件 → 文本 → 调这里」。

import (
	"encoding/hex"
	"net"
	"strconv"
	"strings"
)

// tcpStates /proc/net/tcp 的状态码（st 列）。
var tcpStates = map[string]string{
	"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
	"04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
	"07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
	"0A": "LISTEN", "0B": "CLOSING", "0C": "NEW_SYN_RECV",
}

// parseLsof 解析 `lsof -nP -i -w` 的输出。
//
// 行格式（列宽随内容浮动，只能按 token 找锚点）：
//
//	COMMAND    PID USER  FD  TYPE  DEVICE  SIZE/OFF  NODE  NAME
//	nginx      989  xu.   9u IPv4  0x5ab...    0t0     TCP  *:80 (LISTEN)
//	cloudd    1615  xu.  14u IPv4  0x370...    0t0     TCP  127.0.0.1:53923->127.0.0.1:7897 (ESTABLISHED)
//
// 锚点选第 5 个 token 之后的第一个 TCP/UDP：DEVICE 列（0x…）和 SIZE/OFF（0t0）
// 都是单 token，COMMAND 里出现的空格会左移列位置，但从 TYPE 往右找 proto
// 不受影响——这也是 Python 版 `_from_lsof` 的做法，两边必须同算法。
func parseLsof(text string) []netRow {
	var out []netRow
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 6 {
			continue
		}
		idx := -1
		for i := 4; i < len(f); i++ {
			if f[i] == "TCP" || f[i] == "UDP" {
				idx = i
				break
			}
		}
		if idx < 0 || idx+1 >= len(f) {
			continue
		}
		proto := f[idx]
		name := f[idx+1]
		state := ""
		if idx+2 < len(f) {
			// 状态带括号：(LISTEN) / (ESTABLISHED)；UDP 行没有这一段
			state = strings.Trim(f[idx+2], "()")
		}
		pid, _ := strconv.Atoi(f[1]) // 非数字按 0（Python 版同口径）
		r := netRow{Proto: proto, State: state, PID: pid, User: f[2]}
		if left, right, ok := strings.Cut(name, "->"); ok {
			r.LAddr, r.LPort = splitHostPort(left)
			r.RAddr, r.RPort = splitHostPort(right)
		} else {
			r.LAddr, r.LPort = splitHostPort(name)
		}
		// lsof 的 COMMAND 列被固定宽度截断（cloudd 显示成 cloudd，长的显示成
		// 9 个字符），这是 lsof 的默认行为，Python 版拿到的也是截断值。
		// 需要完整进程名时用 PID 二次查（Windows/Linux 实现里就是这么做的）。
		r.Process = f[0]
		out = append(out, r)
	}
	return out
}

// splitHostPort 拆 "1.2.3.4:80" / "[::1]:631" / "*:443"。
// 端口不是数字时按 0（如 UDP 的 "*:*"）。
func splitHostPort(s string) (string, int) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return s, 0
	}
	port, err := strconv.Atoi(s[i+1:])
	if err != nil {
		return s[:i], 0
	}
	return s[:i], port
}

// parseProcNet 解析 /proc/net/tcp 或 /proc/net/tcp6。
//
// 格式（列以空白分隔，地址是**小端十六进制**）：
//
//	sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
//	0:  0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 501 0 123456 1 ...
//
// IPv4 地址 "0100007F" = 7F 00 00 01 = 127.0.0.1；IPv6 是 4 组小端 32 位字，
// 直接按大端读会得到反序地址，这条坑在测试里钉住了（::1 vs 100::）。
func parseProcNet(text string, v6 bool) []netRow {
	var out []netRow
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 10 || !strings.HasSuffix(f[0], ":") {
			continue // 表头 / 空行
		}
		laddr, lport := splitHexAddr(f[1], v6)
		raddr, rport := splitHexAddr(f[2], v6)
		if laddr == "" {
			continue
		}
		st := strings.ToUpper(f[3])
		uid, _ := strconv.Atoi(f[7])
		inode, _ := strconv.Atoi(f[9])
		out = append(out, netRow{
			Proto: "TCP",
			LAddr: laddr, LPort: lport,
			RAddr: raddr, RPort: rport,
			State: tcpStates[st],
			User:  strconv.Itoa(uid),
			Inode: inode,
		})
	}
	return out
}

// splitHexAddr 拆 "0100007F:1F90" 并解码地址。
func splitHexAddr(s string, v6 bool) (string, int) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return "", 0
	}
	port, err := strconv.ParseUint(s[i+1:], 16, 32)
	if err != nil {
		return "", 0
	}
	ip := decodeProcAddr(s[:i], v6)
	if ip == "" {
		return "", 0
	}
	if v6 {
		// v4-mapped（::ffff:127.0.0.1）本质是 IPv4 连接，不加括号；
		// 其余与 lsof 的书写风格统一成 [::1]，让回环判定只需要一套规则
		if pip := net.ParseIP(ip); pip != nil && pip.To4() != nil {
			return ip, int(port)
		}
		return "[" + ip + "]", int(port)
	}
	return ip, int(port)
}

// decodeProcAddr 把 /proc/net 的小端十六进制地址还原成可读 IP。
func decodeProcAddr(s string, v6 bool) string {
	if !v6 {
		if len(s) != 8 {
			return ""
		}
		b, err := hex.DecodeString(s)
		if err != nil {
			return ""
		}
		return net.IPv4(b[3], b[2], b[1], b[0]).String()
	}
	if len(s) != 32 {
		return ""
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return ""
	}
	var ip [16]byte
	for w := 0; w < 4; w++ { // 每 4 字节是一组小端 32 位字
		ip[w*4+0] = b[w*4+3]
		ip[w*4+1] = b[w*4+2]
		ip[w*4+2] = b[w*4+1]
		ip[w*4+3] = b[w*4+0]
	}
	return net.IP(ip[:]).String()
}

// parseNetstat 解析 Windows `netstat -ano`。
//
// 行格式：
//
//	TCP    0.0.0.0:135      0.0.0.0:0      LISTENING       1234
//	TCP    10.0.0.5:51544   93.184.216.34:443  ESTABLISHED  8877
//	UDP    0.0.0.0:500      *:*                            1234
//
// UDP 行没有状态列，所以 PID 取最后一列；TCP 行有 5 列。
// 注意：非英文 Windows 的 state 文本是本地化的（"ABHÖREN" 之类），
// 这里同时按英文与「含 LISTEN 子串」两种方式判，其余状态不参与判定。
func parseNetstat(text string) []netRow {
	var out []netRow
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		proto := strings.ToUpper(f[0])
		if proto != "TCP" && proto != "UDP" {
			continue // 表头 "活动连接"/"Proto" 以及空行
		}
		pid, err := strconv.Atoi(f[len(f)-1])
		if err != nil {
			continue
		}
		r := netRow{Proto: proto, PID: pid}
		r.LAddr, r.LPort = splitHostPort(f[1])
		r.RAddr, r.RPort = splitHostPort(f[2])
		if proto == "TCP" && len(f) >= 5 {
			r.State = strings.ToUpper(f[3])
			if strings.Contains(r.State, "LISTEN") {
				r.State = "LISTEN" // 兼容本地化状态文本
			}
		}
		if r.LAddr == "*" || r.LAddr == "" {
			continue
		}
		out = append(out, r)
	}
	return out
}

// 说明：三个解析器都不做「要不要报」的判断——判定只在 network.go 里，
// 保证四平台共用同一套严重度分支。
