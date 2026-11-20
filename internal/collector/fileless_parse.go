package collector

// fileless_parse.go —— 无文件证据的解析器（不带 build tag）。
//
// 三份输入形状在本机（darwin）都能测：
//
//	vmmap -pages        匿名可执行段（darwin）
//	/proc/<pid>/maps    匿名可执行段 + memfd（linux）
//	Get-CimInstance CSV Windows 进程表（windows）
//
// 解析器只负责「把文本变成数字」，不做判定——判定全在 fileless.go。

import (
	"encoding/csv"
	"strconv"
	"strings"
)

// ---- vmmap ------------------------------------------------------------

// vmmapRegion vmmap 的一行 region。
type vmmapRegion struct {
	Type  string
	Perm  string // "r-x/r-x"
	Path  string // 空 = 无磁盘后备
	Bytes int64
}

// parseVMmapAnonExec 从 `vmmap -pages` 输出里统计「当前权限可执行且无路径」的段。
//
// 输出形状（macOS 27.3 实测）：
//
//	__TEXT                      104b38000-104bc0000  [  34  27  0  0 ] r-x/r-x SM=COW   /bin/bash
//	App-Specific Tag 16         10dcc0000-11dcc0000  [16384  0  0  3 ] rwx/rwx SM=PRV
//	Stack Guard                 169aa0000-16d2a4000  [3585   0  0  0 ] ---/rwx SM=NUL   stack guard for thread 0
//
// 判据：PRT 列（当前权限）含 x 且第 6 列之后没有路径。
// 注意 `---/rwx` 这种「最大权限 rwx 但当前不可执行」的段不算——它们是
// malloc guard / stack guard，不是可执行内存。
func parseVMmapAnonExec(text string) (bytes int64, regions int) {
	pageSize := int64(16384) // darwin arm64 默认；下面用头部实际值覆盖
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "VM page size:") {
			for _, f := range strings.Fields(line) {
				if n, err := strconv.ParseInt(f, 10, 64); err == nil && n > 0 && n <= 65536 {
					pageSize = n
				}
			}
			continue
		}
		lb := strings.IndexByte(line, '[')
		rb := strings.IndexByte(line, ']')
		if lb < 0 || rb < lb {
			continue
		}
		sizeField := strings.Fields(line[lb+1 : rb])
		if len(sizeField) == 0 {
			continue
		}
		pages := int64(0)
		if v, err := strconv.ParseFloat(sizeField[0], 64); err == nil {
			pages = int64(v)
		}
		rest := strings.Fields(line[rb+1:])
		if len(rest) == 0 {
			continue
		}
		perm := rest[0] // r-x/r-x | rwx/rwx | ---/rwx
		if !strings.HasPrefix(perm, "r-x") && !strings.HasPrefix(perm, "rwx") {
			continue
		}
		// 去掉 SM=COW / SM=PRV / SM=NUL 后如果还有内容，就是路径或说明文字；
		// 只有「真的什么都没有」才算匿名。
		path := ""
		for _, f := range rest[1:] {
			if strings.HasPrefix(f, "SM=") {
				continue
			}
			path = f
			break
		}
		if path != "" {
			continue
		}
		bytes += pages * pageSize
		regions++
	}
	return bytes, regions
}

// ---- /proc/<pid>/maps -------------------------------------------------

// parseProcMaps 统计匿名可执行段，并收集 memfd 路径。
//
// maps 行形状（linux）：
//
//	55f0..-5600.. r-xp 00000000 08:01 1234   /usr/bin/bash
//	7f0a..-7f0b.. rwxp 00000000 00:00 0      /memfd:payload (deleted)
//	7f1c..-7f1d.. r-xp 00000000 00:00 0      [vdso]
//	7ffe..-7fff.. rw-p 00000000 00:00 0      [stack]
//
// 规则：
//   - perms 第 3 位是 x 且**没有第 6 列**（inode 0 且无路径）→ 匿名可执行
//   - 第 6 列以 `[` 开头的是内核合成区（vdso/vsyscall/stack）→ 不算匿名可执行
//     （vdso 是 r-xp 的合法系统内存，报了就是每个进程一条）
//   - 第 6 列含 `memfd:` → 收集到 memfd 列表（不论权限，先记下来）
func parseProcMaps(text string) (bytes int64, regions int, memfd []string) {
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		perms := f[1]
		if len(perms) < 3 {
			continue
		}
		lo, hi := f[0], ""
		if i := strings.IndexByte(lo, '-'); i > 0 {
			hi = lo[i+1:]
			lo = lo[:i]
		}
		start, err1 := strconv.ParseInt(lo, 16, 64)
		end, err2 := strconv.ParseInt(hi, 16, 64)
		if err1 != nil || err2 != nil || end <= start {
			continue
		}
		path := ""
		if len(f) >= 6 {
			path = strings.Join(f[5:], " ")
		}
		if strings.Contains(path, "memfd:") {
			name := path
			if i := strings.Index(name, "memfd:"); i >= 0 {
				name = name[i:]
			}
			memfd = append(memfd, strings.TrimSpace(name))
			continue
		}
		if perms[2] != 'x' || path != "" {
			continue
		}
		bytes += end - start
		regions++
	}
	return bytes, regions, memfd
}

// procExeDeleted /proc/<pid>/exe 的 readlink 结果是否带 "(deleted)"。
func procExeDeleted(link string) bool {
	return strings.HasSuffix(strings.TrimSpace(link), "(deleted)")
}

// parseLsofTxtLinkZero 从 `lsof -a -d txt +L1` 输出里取「链接数为 0 的 txt 映射」路径。
//
// 为什么需要它：macOS 上 /proc 不存在，ps 的 command 列也不带 "(deleted)"，
// 唯一可行的用户态证据是 lsof 的 NLINK 列。实测（macOS 27.3）：
//
//	lsof -p <pid> -a -d txt +L1
//	COMMAND   PID USER FD TYPE DEVICE SIZE/OFF NLINK NODE NAME
//	af-ghost  99650 xu. txt REG  1,14  1776194     0 12507612 /private/tmp/af-ghost-go2
//
// 注意必须带 `-d txt`：不带的话 `lsof +L1` 会把系统 JIT 缓存
// （/private/var/db/diagnostics/logd/.plist-cache.*）也列出来，
// 本机实测一次就 5 条噪声，全都会变成「映像已删除」的误报。
func parseLsofTxtLinkZero(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 10 || f[3] != "txt" {
			continue
		}
		// 列：COMMAND PID USER FD TYPE DEVICE SIZE/OFF NLINK NODE NAME
		// 路径可能含空格（"Google Chrome Helper"），所以取第 8 列之后全部。
		if f[7] != "0" {
			continue
		}
		name := strings.Join(f[8:], " ")
		// NODE 是纯数字，NAME 从第一个非数字列开始
		if i := strings.IndexAny(name, "/"); i >= 0 {
			name = name[i:]
		}
		if name != "" {
			out = append(out, name)
		}
	}
	return out
}

// parseLsofTxtLinkZeroByPID 与上面同一套解析，但按 PID 分组 —— 批量查询用。
//
// 为什么批量：lsof 一次启动 150-200ms（要遍历内核的打开文件表），
// 逐个 PID 问 16 次就是 3 秒。本机实测 fileless 的 --once 耗时
// 从 3.4s 降到 0.4s，靠的就是把候选 PID 用 `-p 1,2,3` 一次问完。
func parseLsofTxtLinkZeroByPID(text string) map[int][]string {
	out := map[int][]string{}
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 10 || f[3] != "txt" || f[7] != "0" {
			continue
		}
		pid, err := strconv.Atoi(f[1])
		if err != nil {
			continue
		}
		name := strings.Join(f[8:], " ")
		if i := strings.IndexAny(name, "/"); i >= 0 {
			name = name[i:]
		}
		if name != "" {
			out[pid] = append(out[pid], name)
		}
	}
	return out
}

// ---- Windows CIM CSV --------------------------------------------------

// parseCimProcessCSV 解析 PowerShell `ConvertTo-Csv` 的进程表。
//
// 输入（Get-CimInstance Win32_Process | Select-Object ... | ConvertTo-Csv）：
//
//	"ProcessId","ParentProcessId","Name","ExecutablePath","CommandLine"
//	"4321","1000","powershell.exe","C:\\Windows\\...\\powershell.exe","powershell -enc SQBFAFgA..."
//
// 用 encoding/csv 而不是按逗号切：CommandLine 里几乎必然有逗号与引号，
// 手切会把一整条命令行切碎（这是 Windows 采集器最常见的解析 bug）。
func parseCimProcessCSV(text string) []filelessFact {
	text = strings.TrimPrefix(text, "\ufeff") // PowerShell 5.1 的 BOM
	r := csv.NewReader(strings.NewReader(text))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	rows, err := r.ReadAll()
	if err != nil || len(rows) < 2 {
		return nil
	}
	idx := map[string]int{}
	for i, h := range rows[0] {
		idx[strings.ToLower(strings.TrimSpace(h))] = i
	}
	get := func(row []string, key string) string {
		if i, ok := idx[key]; ok && i < len(row) {
			return strings.TrimSpace(row[i])
		}
		return ""
	}
	var out []filelessFact
	for _, row := range rows[1:] {
		pid, _ := strconv.Atoi(get(row, "processid"))
		ppid, _ := strconv.Atoi(get(row, "parentprocessid"))
		exe := get(row, "executablepath")
		name := get(row, "name")
		if exe == "" && name == "" {
			continue
		}
		out = append(out, filelessFact{
			Source:  "cim",
			PID:     pid,
			PPID:    ppid,
			HasPID:  pid > 0,
			Process: name,
			Exe:     exe,
			Cmdline: get(row, "commandline"),
		})
	}
	return out
}
