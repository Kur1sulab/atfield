//go:build linux

package collector

// 平台注册表：Linux。
//
// 与 macOS 的差异：
//   - 进程/连接直接从 /proc 读，不依赖 ps/lsof（容器里也能跑）。
//   - 文件事件走 inotify/fanotify；更强的审计走 auditd，需要 root 且要
//     用户态配置规则 → privileged 采集器 Probe 会检查 auditctl 是否存在。
//
// 迁移进度：
//   ✅ process      —— /proc/<pid>/{stat,cmdline}
//   ✅ network      —— /proc/net/{tcp,tcp6} + /proc/<pid>/fd 归属（UDP 待做）
//   ✅ persistence  —— cron（/etc/cron*、spool、~/.crontab）+ systemd unit
//   ✅ privileged   —— auditd（tail /var/log/audit/audit.log；非 root/未启用分别报原因）
//   ✅ fileless     —— /proc/<pid>/maps（匿名可执行段 + memfd）+ exe 的 "(deleted)"
//
// fileless 在 Python 侧没有对应实现（那边的 FilelessWatcher 是 shell 历史监控），
// 对拍时归入「Go 独有」。

const Platform = "linux"

// Registry 返回本平台采集器构造函数。
func Registry() []func(Config) Collector {
	return []func(Config) Collector{
		NewProcess,
		NewNetwork,
		NewPersistence,
		// 提权（Security 日志轮询）与无文件（CIM 命令行 + 签名）：
		// 顺序与 Python REGISTRY 一致，改顺序等于改行为。
		NewPrivileged,
		NewFileless,
	}
}
