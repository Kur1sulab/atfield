//go:build linux

package collector

// Linux 默认完整性监控清单。
//
// 与 macOS 版同一思路（「改一条就能拿到持久访问权」），换成本平台的位置：
//   /etc/passwd /etc/shadow  加个 uid=0 账户 —— 最经典的留后门手法
//   /etc/sudoers /etc/sudoers.d/*  NOPASSWD
//   /etc/ssh/sshd_config      PermitRootLogin / AuthorizedKeysFile 改写
//   ~/.ssh/authorized_keys    加公钥
//   /etc/crontab /etc/cron.d  计划任务注入（persistence 采集器也会看到，
//                             但这里能定位到「谁在什么时候改的」这一层）
//   /etc/ld.so.preload       **Linux 独有**：一行 so 路径就能劫持全系统
//                             的 libc 调用，是最隐蔽的持久化之一
//   /etc/pam.d/*             PAM 后门（pam_exec 挂个脚本，登录即执行）
//
// 刻意不含 /etc/hosts：容器化环境里它被 k8s/docker 反复改写，
// 报出来全是运维噪音，信噪比比 macOS 差得多。

import (
	"os"
	"path/filepath"
)

func platformDefaultWatchPaths() []string {
	home, _ := os.UserHomeDir()
	var out []string
	if home != "" {
		out = append(out, filepath.Join(home, ".ssh", "authorized_keys"))
	}
	out = append(out,
		"/etc/passwd",
		"/etc/shadow",
		"/etc/sudoers",
		"/etc/ssh/sshd_config",
		"/etc/ld.so.preload",
		"/etc/crontab",
		"/etc/pam.d/sshd",
		"/etc/pam.d/su",
		"/etc/pam.d/sudo",
	)
	return out
}
