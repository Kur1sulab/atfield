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
//   ✅ session      —— utmpx 读登录/注销 + wtmp 轮转重开
//   ✅ integrity    —— /etc /usr/local/bin 等关键路径 mtime/size 基线比对
//   ✅ baseline     —— 关键可执行文件指纹基线（首轮建库，后续只报差异）
//   ✅ logstream    —— /var/log 关键日志 tail（stream 模式）
//   ✅ authlog      —— /var/log/auth.log 失败登录聚合（非 root 时 Probe 明说原因）
//
// fileless 在 Python 侧没有对应实现（那边的 FilelessWatcher 是 shell 历史监控），
// 对拍时归入「Go 独有」。

const Platform = "linux"

// Registry 返回本平台采集器构造函数。
//
// 顺序与 Python 版 atfield/collectors/__init__.py 的 REGISTRY 逐项对齐：
// Process → Network → Session → Persistence → Integrity → Baseline →
// LogStream → Privileged → AuthLog →（LoginItem 未实现）→ Fileless。
// 对拍按位置逐条比对，改顺序等于改行为。
func Registry() []func(Config) Collector {
	return []func(Config) Collector{
		NewProcess,
		NewNetwork,
		NewSession,
		NewPersistence,
		NewIntegrity,
		NewBaseline,
		NewLogStream,
		NewPrivileged,
		NewAuthLog,
		// Fileless：Go 独有能力，Python 无对应项，固定收尾。
		NewFileless,
	}
}
