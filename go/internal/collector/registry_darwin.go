//go:build darwin

package collector

// 平台注册表：macOS。
//
// 与 Python 版 collectors/__init__.py 的 REGISTRY 对齐；顺序影响控制台展示
// 与对拍输出顺序，改顺序等于改行为。
//
// 迁移进度（对拍时按这张表算覆盖率）：
//   ✅ process      —— 本轮完成
//   ✅ persistence  —— LaunchAgents/Daemons plist + crontab + /etc/periodic
//   ✅ privileged   —— eslogger（root + Full Disk Access；非 root 时 Probe 明说原因）
//   ✅ fileless     —— 命令行（ps）+ 映像删除（lsof +L1）+ 匿名可执行段（vmmap）
//   ✅ network      —— lsof（macOS 26+ netstat 失效）
//   ✅ session      —— utmpx 读登录/注销 + wtmp 轮转重开
//   ✅ integrity    —— /etc /Library/Launch* 等关键路径 mtime/size 基线比对
//   ✅ baseline     —— 关键可执行文件指纹基线（首轮建库，后续只报差异）
//   ✅ logstream    —— /var/log/system.log 等 tail（stream 模式）
//   ✅ authlog      —— sudo/tccd/lwcrashreporter 失败登录聚合
//
// fileless 在 Python 侧**没有对应实现**（那边的 FilelessWatcher 实际是
// shell 历史监控，name="shellhist"），所以它不是迁移项而是新增能力；
// 对拍脚本要把它列进「Go 独有」而不是「Python 缺失」。
//
// 未做：Python 版的 LoginItemCollector（securitysw，读 backgrounditems.btm）。
// 它的告警语义是「登录项消失了」，必须依赖 state store 才有意义——
// store 层已落地，但 LoginItem 的基线比对还没写，故注册表里仍缺这一项。

// Platform 平台标识，写进报告与状态页。
const Platform = "darwin"

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
