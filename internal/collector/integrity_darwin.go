//go:build darwin

package collector

// macOS 默认完整性监控清单。
//
// 与 Python 版 atfield/config.py 的 watch_paths 逐条相同（顺序也相同）：
// 那 9 条是「改一条就能直接拿到持久访问权」的文件——authorized_keys 加个
// 公钥、sudoers 加个 NOPASSWD、hosts 劫持域名、pf.conf 放行回连。
//
// 为什么不多加：清单越长，每轮 sha256 越贵（45s 周期），而且真实攻击者
// 改的多是这些老位置。要加走 Options["watch_paths"]，别改这里——
// 改这里等于改两版共用的默认口径。

import (
	"os"
	"path/filepath"
)

func platformDefaultWatchPaths() []string {
	home, _ := os.UserHomeDir()
	join := func(parts ...string) string {
		if home == "" {
			return ""
		}
		return filepath.Join(append([]string{home}, parts...)...)
	}
	return []string{
		"/etc/hosts",
		"/etc/ssh/sshd_config",
		"/etc/pf.conf",
		"/etc/sudoers",
		join(".ssh", "authorized_keys"),
		join(".ssh", "config"),
		join(".zshrc"),
		join(".bash_profile"),
		join("Library", "Preferences", "com.apple.SoftwareUpdate.plist"),
	}
}
