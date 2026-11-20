package enforcer

// platform.go —— 平台选路。
//
// 三个后端本身是「纯命令构造」，不含任何 syscall/平台 API，所以可以在任意
// 平台上编译并单测：macOS 上也能断言 nft 与 netsh 的命令序列是否正确。
// 平台差异只体现在这里——运行时选哪个后端。

import "runtime"

// New 按运行平台选后端。未支持平台返回 Unsupported（明确报错，不装死）。
func New(opts Options) Backend {
	return NewFor(runtime.GOOS, opts)
}

// NewFor 按名字选后端，不受编译平台限制。
//
// 用途：跨平台对拍（在 macOS 上验证 Linux/Windows 的命令构造）、
// 排障时强制指定后端、以及测试。goos 取 runtime.GOOS 的取值。
func NewFor(goos string, opts Options) Backend {
	switch goos {
	case "darwin":
		return NewPF(opts)
	case "linux":
		return NewNFT(opts)
	case "windows":
		return NewNetsh(opts)
	default:
		return NewUnsupported(opts, goos)
	}
}
