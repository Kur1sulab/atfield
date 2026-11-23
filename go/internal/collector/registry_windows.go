//go:build windows

package collector

// 平台注册表：Windows。
//
// 与 macOS 的差异（必须显式声明，不许假装一样）：
//   - 没有 EndpointSecurity；文件级事件要靠 ETW，更强一级的 minifilter
//     需要内核驱动 WHQL 签名，个人项目做不了 → privileged 采集器在本平台
//     会 Probe 失败并给出原因，控制台显示「该采集器不可用」，其余不受影响。
//   - 进程归属要靠 IP Helper API（GetExtendedTcpTable）拿 PID，
//     netstat -ano 只是退化路径。
//
// 迁移进度：
//   ✅ process      —— tasklist（首版无 PPID/命令行，见文件内说明）
//   ✅ network      —— netstat -ano（**退化路径**：PID 有、进程路径无；
//                       完整方案 GetExtendedTcpTable 本版未做，见 network_windows.go）
//   ✅ persistence  —— 注册表 Run/RunOnce（含 Wow6432Node）+ 启动目录 + 计划任务
//   ✅ privileged   —— Security 事件日志 4672/4688/1102 轮询（**不是 ETW**；
//                       4688 依赖「审核进程创建」策略，默认关闭——Limits 里写明）
//   ✅ fileless     —— CIM 命令行（PowerShell 编码命令/IEX）+ 临时目录未签名执行
//                       （**不读进程内存**：无 VAD 遍历，匿名段恒为「未探测」）
//   ✅ session      —— Event Log 4624/4634 登录/注销轮询（依赖审核登录策略）
//   ✅ integrity    —— 关键目录（System32、Program Files、启动目录）mtime/size 基线
//   ✅ baseline     —— 关键可执行文件指纹基线（首轮建库，后续只报差异）
//   ✅ logstream    —— 事件日志 stream tail（Security/System/Application）
//   ✅ authlog      —— 4625 失败登录聚合（登录类型/来源 IP 分桶）
//
// fileless 在 Python 侧没有对应实现（那边的 FilelessWatcher 是 shell 历史监控），
// 对拍时归入「Go 独有」。

const Platform = "windows"

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
