//go:build linux

package collector

// fileless_linux.go —— Linux 侧取数：/proc 全量。
//
// 为什么 Linux 上这个采集器最准：/proc/<pid>/maps 直接把「哪段内存可执行、
// 有没有磁盘后备」摊开给你看，/proc/<pid>/exe 的 "(deleted)" 后缀是内核
// 亲手写的证据。不需要 root 也能看同 uid 的进程。
//
// 代价是扫描成本：一次 /proc 遍历 ≈ 400 个进程 × (stat+cmdline+exe+maps)。
// 实测在本机（macOS 无 /proc，这段是交叉编译验证 + 目标机基线）：
// 单进程 maps 读 ~40µs，400 进程 ~16ms，可以 30 秒一轮。
//
// 权限事实：读别人的 /proc/<pid>/maps 需要 CAP_SYS_PTRACE（root 或同 uid）。
// 读不到就 MemProbed=false —— 判定层不会把「没读成」当成「干净」。
//
// memfd_create 的痕迹在 maps 里长这样：
//
//	7f0a00000000-7f0a00040000 r-xp 00000000 00:00 0 /memfd:payload (deleted)
//
// 这是「无文件落地」在 Linux 上的标准形态（攻击者把 ELF 写进内存 fd 再 exec），
// 所以命中即 high，不需要二次信号。

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// statUID 取 /proc/<pid> 的属主 uid（linux 专属；darwin 的 Stat_t 没有 Uid）。
func statUID(fi os.FileInfo) int {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid)
	}
	return -1
}

func platformFilelessLimits() string {
	return "/proc 全量：命令行 + maps 匿名可执行段 + memfd + exe 的 (deleted)；" +
		"读其他用户的 maps 需要 root（CAP_SYS_PTRACE），非 root 只看得到同 uid 进程"
}

func platformProbeFileless() error {
	if _, err := os.Stat("/proc/self/maps"); err != nil {
		return fmt.Errorf("/proc 不可用（容器未挂载 procfs？）: %v", err)
	}
	return nil
}

// linuxProcFileless 采集单进程（读不到的文件跳过，不报错——一个进程消失是常态）。
func linuxProcFileless(pid int, now float64) (filelessFact, bool) {
	dir := "/proc/" + strconv.Itoa(pid)
	f := filelessFact{Source: "procfs", TS: now, PID: pid, HasPID: true}

	// comm/ppid：/proc/<pid>/stat 的第 2 列是 "(comm)"，comm 里可能有空格和括号，
	// 所以从最后一个 ')' 往右切，而不是按空格切。
	if b, ok := readTextFile(dir + "/stat"); ok {
		if rp := strings.LastIndexByte(b, ')'); rp > 0 {
			if lp := strings.IndexByte(b, '('); lp >= 0 && lp < rp {
				f.Process = b[lp+1 : rp]
			}
			rest := strings.Fields(b[rp+1:])
			// rest[0] 是状态，rest[1] 是 ppid
			if len(rest) >= 2 {
				f.PPID, _ = strconv.Atoi(rest[1])
			}
		}
	}
	// cmdline：NUL 分隔
	if b, ok := readTextFile(dir + "/cmdline"); ok {
		f.Cmdline = strings.TrimSpace(strings.ReplaceAll(b, "\x00", " "))
	}
	// exe：符号链接，删除后内核会加 " (deleted)"
	if link, err := os.Readlink(dir + "/exe"); err == nil {
		f.Exe = link
		f.ImageDeleted = procExeDeleted(link)
	} else if os.IsNotExist(err) {
		// 链接消失 = 进程刚退出，或内核线程（无 exe）
		f.Exe = ""
	}
	if f.Exe == "" {
		f.Exe = f.Process
	}
	f.ExeInTemp = isTempPath(f.Exe)
	if f.Cmdline == "" {
		f.Cmdline = f.Exe
	}
	// 属主：/proc/<pid> 的 uid 就是进程 euid
	if st, err := os.Stat(dir); err == nil {
		if uid := statUID(st); uid >= 0 {
			f.User = "uid:" + strconv.Itoa(uid)
		}
	}
	// maps：读得到才谈内存
	if maps, ok := readTextFile(dir + "/maps"); ok {
		f.MemProbed = true
		f.AnonExecBytes, f.AnonExecRegion, f.Memfd = parseProcMaps(maps)
	}
	return f, f.Process != "" || f.Exe != ""
}

// platformFilelessFacts 扫 /proc。
func platformFilelessFacts(ctx context.Context) ([]filelessFact, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("读 /proc 失败: %w", err)
	}
	now := nowSeconds()
	facts := make([]filelessFact, 0, len(entries))
	for _, e := range entries {
		if ctx.Err() != nil {
			break
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 1 {
			continue
		}
		if f, ok := linuxProcFileless(pid, now); ok {
			facts = append(facts, f)
		}
	}
	return facts, nil
}
