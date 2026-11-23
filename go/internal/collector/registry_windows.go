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
//
// fileless 在 Python 侧没有对应实现（那边的 FilelessWatcher 是 shell 历史监控），
// 对拍时归入「Go 独有」。

const Platform = "windows"

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
