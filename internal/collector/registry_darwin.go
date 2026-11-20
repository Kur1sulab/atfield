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
//   ⬜ network      —— lsof（macOS 26+ netstat 失效）
//   ⬜ privileged   —— eslogger（需 root + TCC 授权）
//   ⬜ session/authlog / logstream / integrity / baseline / fileless
//
// 未做：Python 版的 LoginItemCollector（securitysw，读 backgrounditems.btm）。
// 它的告警语义是「登录项消失了」，必须依赖 state store 才有意义——
// Go 版 store 层还没落地，先不写一个只能空转的采集器。

// Platform 平台标识，写进报告与状态页。
const Platform = "darwin"

// Registry 返回本平台采集器构造函数。
func Registry() []func(Config) Collector {
	return []func(Config) Collector{
		NewProcess,
		NewNetwork,
		NewPersistence,
	}
}
