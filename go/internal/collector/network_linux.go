//go:build linux

package collector

// Linux 连接表：/proc/net/{tcp,tcp6} + /proc/<pid>/fd 反查归属。
//
// 为什么不直接扫 /proc/<pid>/net/tcp：那是**网络命名空间视图**，同一个 netns
// 里所有进程看到的表一样，扫 N 个进程就得到 N 份重复数据。全局表只有一份，
// 进程归属靠 socket inode 反查——这也正是 psutil 在 Linux 上的做法。
//
// 已知边界：
//   - 非 root 只能读到自己进程的 fd，别人的 socket 反查不到 PID（inode 仍在，
//     pid=0）。与 darwin 的 lsof 边界同性质，控制台要标明。
//   - 只做 TCP。UDP 在 /proc/net/udp 里没有状态列，绑定了端口的 UDP socket
//     与「监听」无法区分，首版不收（Python 版走 psutil，只报已 connect 的
//     UDP，量极小）。这条写进 MIGRATION 的待办。

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

func platformProbeNet() error {
	for _, p := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		if _, err := os.Stat(p); err == nil {
			return nil
		}
	}
	return errors.New("/proc/net/tcp 不存在：无 /proc 的容器或已关闭 procfs")
}

func platformConns(ctx context.Context) ([]netRow, error) {
	var rows []netRow
	read := 0
	for _, spec := range []struct {
		path string
		v6   bool
	}{
		{"/proc/net/tcp", false},
		{"/proc/net/tcp6", true},
	} {
		b, err := os.ReadFile(spec.path)
		if err != nil {
			if os.IsNotExist(err) {
				continue // 内核未编 IPv6 时 tcp6 不存在，不是错误
			}
			return nil, fmt.Errorf("读 %s 失败: %w", spec.path, err)
		}
		read++
		rows = append(rows, parseProcNet(string(b), spec.v6)...)
	}
	if read == 0 {
		return nil, errors.New("/proc/net/tcp 不可读")
	}
	// 内核态的 TIME_WAIT / CLOSE 没有 owner（inode=0），一台正常机器每分钟会
	// 攒出成百上千条 pid=0 的记录。它们对「谁在连哪儿」零信息量，直接丢掉：
	// 这不是调阈值，是不产生没有主语的事件。
	kept := rows[:0]
	for _, r := range rows {
		if r.Inode == 0 && (r.State == "TIME_WAIT" || r.State == "CLOSE") {
			continue
		}
		kept = append(kept, r)
	}
	rows = kept

	attrPIDs(rows)
	attrUsers(rows)
	return rows, nil
}

// attrPIDs 用 socket inode 反查 PID。
//
// 成本：一次 /proc 全量 fd 遍历（本机数千个 readlink，约 10–30ms）。
// 只反查表里出现的 inode（want 集合），命中一个删一个，集合空了立刻收工。
// PID 按数值升序扫描，保证同一 socket 被父子进程共享时归属稳定——
// 按字符串序遍历会让 "999" 排在 "1000" 后面，同一份数据两轮给出不同 pid。
func attrPIDs(rows []netRow) {
	want := make(map[int]bool, len(rows))
	for _, r := range rows {
		if r.Inode > 0 {
			want[r.Inode] = true
		}
	}
	if len(want) == 0 {
		return
	}
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	pids := make([]int, 0, len(ents))
	for _, e := range ents {
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			pids = append(pids, pid)
		}
	}
	sort.Ints(pids)

	owner := make(map[int]int, len(want))
	for _, pid := range pids {
		if len(want) == 0 {
			break
		}
		fdDir := filepath.Join("/proc", strconv.Itoa(pid), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue // 别人的进程（EACCES）：已知边界，跳过
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]"))
			if err != nil || !want[inode] {
				continue
			}
			owner[inode] = pid
			delete(want, inode)
		}
	}
	for i := range rows {
		if pid, ok := owner[rows[i].Inode]; ok {
			rows[i].PID = pid
			rows[i].Process = linuxProcName(pid)
		}
	}
}

// linuxProcName 读 /proc/<pid>/comm（内核截断到 15 字符，psutil 同）。
func linuxProcName(pid int) string {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// attrUsers 把 /proc/net/tcp 里的数字 uid 换成用户名（socket 属主 = 进程属主，
// 少读一次 /proc/<pid>/status）。查不到就保留数字，绝不因此丢行。
func attrUsers(rows []netRow) {
	cache := map[string]string{}
	for i := range rows {
		uid := rows[i].User
		if uid == "" {
			continue
		}
		if name, ok := cache[uid]; ok {
			rows[i].User = name
			continue
		}
		name := uid
		if u, err := user.LookupId(uid); err == nil && u.Username != "" {
			name = u.Username
		}
		cache[uid] = name
		rows[i].User = name
	}
}
