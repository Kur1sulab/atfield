//go:build windows

package collector

// Windows 默认完整性监控清单。
//
// 与 macOS/Linux 版同一思路，换成本平台的「改一条就持久」位置：
//   hosts                 域名劫持（微软自己的遥测/更新域名常被针对）
//   RDP 配置              fDenyTSConnections=0 就是开远程桌面后门
//   Winlogon 相关          Shell / Userinit 改写 → 登录即执行
//   LSA 配置              RunAsPPL 关掉 = 关掉 LSASS 保护
//   Run/RunOnce 键位置本身不监控（那是 persistence 采集器的活，
//                         这里监控的是「系统策略被改」）
//
// %SystemRoot% 用环境变量拼：写死 C:\Windows 在装在 D 盘的机器上全错。

import (
	"os"
	"path/filepath"
)

func platformDefaultWatchPaths() []string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	sys32 := filepath.Join(root, "System32")
	return []string{
		filepath.Join(sys32, "drivers", "etc", "hosts"),
		filepath.Join(root, "System32", "GroupPolicy", "Machine", "registry.pol"),
		filepath.Join(sys32, "config", "SAM"),
		filepath.Join(sys32, "config", "SECURITY"),
		filepath.Join(sys32, "config", "SYSTEM"),
	}
}
