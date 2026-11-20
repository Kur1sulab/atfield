//go:build linux

package collector

// privileged_linux.go —— auditd 取数（tail /var/log/audit/audit.log）。
//
// 为什么读日志文件而不是连 auditd 的 netlink socket：netlink 要 root、
// 要自己维护 audit 规则（audit_add_watch 之类），一旦程序崩了规则还留在内核里；
// 读日志则是最小侵入——谁配的规则就按谁的规则看，程序挂了也不会影响审计。
//
// 代价是「要等 auditd 落盘」，延迟 0.2～1 秒。对提权检测完全可以接受
// （sudo 到 root 之后攻击者还要做下一步，秒级延迟不影响关联）。
//
// 三种失败要分开报，因为处置动作不同：
//
//	没装 auditd（无 auditctl 且无日志）→ 去装
//	装了没跑（有 auditctl 无日志）    → systemctl enable --now auditd
//	跑着但没权限（日志 0600 root:root）→ 用 root 或加 adm 组

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// linuxAuditLog auditd 默认日志路径。
const linuxAuditLog = "/var/log/audit/audit.log"

// linuxAuditLookback 首次打开时回看多少字节。
//
// 不回看整个文件：一台跑了半年的服务器 audit.log 能到几个 GB，
// 全量解析会让第一轮采集卡住几十秒。256KB ≈ 最近的几千条记录，
// 足够覆盖「刚发生的提权」。
const linuxAuditLookback = 256 * 1024

func platformPrivLimits() string {
	return "auditd 日志（/var/log/audit/audit.log）；需要 root 或 adm 组；" +
		"只覆盖 audit 规则命中的系统调用（默认规则下 sudo/su/setuid 有，任意 exec 没有）"
}

func platformProbePrivileged() error {
	st, err := os.Stat(linuxAuditLog)
	if err != nil {
		if _, e := exec.LookPath("auditctl"); e != nil {
			return fmt.Errorf("auditd 未安装：%s 不存在且找不到 auditctl（apt install auditd / dnf install audit）", linuxAuditLog)
		}
		return fmt.Errorf("auditd 已安装但未运行：%s 不存在（systemctl enable --now auditd）", linuxAuditLog)
	}
	if st.IsDir() {
		return fmt.Errorf("%s 是目录，不是 auditd 日志", linuxAuditLog)
	}
	f, err := os.Open(linuxAuditLog)
	if err != nil {
		return fmt.Errorf("无权读取 %s（需要 root 或 adm 组）: %v", linuxAuditLog, err)
	}
	_ = f.Close()
	return nil
}

// platformPrivSource 跟随 audit.log 追加内容（尾部跟随，不是全量重读）。
//
// offset 记在内存里：进程重启后回看 linuxAuditLookback 字节，
// 这样「重启采集器」不会把陈年 sudo 当成新事件重报一遍
// （judge 层还有 120s 去重，但去重键不含时间，历史事件压不住）。
func platformPrivSource(ctx context.Context, sink func(privRecord)) error {
	f, err := os.Open(linuxAuditLog)
	if err != nil {
		return fmt.Errorf("打开 %s 失败: %w", linuxAuditLog, err)
	}
	defer f.Close()

	br := bufio.NewReaderSize(f, 256*1024)

	if st, err := f.Stat(); err == nil {
		off := st.Size() - linuxAuditLookback
		if off < 0 {
			off = 0
		}
		if _, err := f.Seek(off, io.SeekStart); err != nil {
			return fmt.Errorf("audit.log 定位失败: %w", err)
		}
		// 从中间切进去时第一行通常是半截，丢掉。
		br = bufio.NewReaderSize(f, 256*1024)
		if off > 0 {
			if _, err := br.ReadString('\n'); err != nil && !errors.Is(err, io.EOF) {
				return fmt.Errorf("audit.log 跳过半行失败: %w", err)
			}
		}
	} else {
		br = bufio.NewReaderSize(f, 256*1024)
	}

	var pending string
	for ctx.Err() == nil {
		line, rerr := br.ReadString('\n')
		if rerr == nil {
			if pending != "" {
				line = pending + line
				pending = ""
			}
			for _, rec := range parseAuditLog(strings.TrimRight(line, "\n")) {
				sink(rec)
			}
			continue
		}
		if !errors.Is(rerr, io.EOF) {
			return fmt.Errorf("读 audit.log 失败: %w", rerr)
		}
		// 半行留在 pending 里等下一次读：auditd 写一条记录是多次 write，
		// 直接解析半行会得到「字段少了一半」的假记录。
		pending += line
		if len(pending) > 512*1024 {
			pending = "" // 异常长的行（二进制垃圾）直接丢，别把内存吃满
		}
		// auditd 轮转日志：inode 变了就重开（否则会一直读已删除的旧文件）
		if st, err := os.Stat(linuxAuditLog); err == nil {
			if cur, err2 := f.Stat(); err2 == nil && !os.SameFile(st, cur) {
				return errors.New("audit.log 已轮转，重开")
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(500 * time.Millisecond):
		}
	}
	return nil
}
