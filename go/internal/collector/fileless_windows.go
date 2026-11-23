//go:build windows

package collector

// fileless_windows.go —— Windows 侧取数：CIM 进程表 + Authenticode 签名。
//
// Windows 是「无文件」概念的发源地，但**能拿到的证据反而最少**：
//
//	命令行    Get-CimInstance Win32_Process → CommandLine（普通用户可读）
//	签名      Get-AuthenticodeSignature（每文件一次，慢，只查临时目录里的）
//	内存      **拿不到**：枚举另一个进程的 VAD 要 NtQueryVirtualMemory +
//	          PEB 遍历，本版不做 → MemProbed 恒 false，判定不会假装看过内存
//
// 所以 Windows 侧的判定重心是命令行：PowerShell 编码命令、IEX 下载执行、
// 临时目录未签名执行。这三条恰好覆盖了实际攻防里最常见的落地方式
// （Cobalt Strike 的 powershell 反射加载、各类 loader 的 %TEMP% 落地）。
//
// 为什么用 PowerShell 而不是 wmic：wmic 在 Windows 11 24H2 起是
// 「按需功能」，默认不装；PowerShell 5.1 是系统自带。Probe 里先查
// powershell.exe，再退到 pwsh.exe，最后才报不可用。

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// osStat 抽成变量便于测试时替换（Windows 路径只有目标机能验证）。
var osStat = os.Stat

// winCimScript 一次取全量进程（CSV 便于用 encoding/csv 解析）。
const winCimScript = `Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine | ConvertTo-Csv -NoTypeInformation`

// winSigScript 取签名状态（只对单个文件调用）。
const winSigScript = `(Get-AuthenticodeSignature -LiteralPath '%s').Status`

// winSigCap 每轮最多查几个文件的签名（每次 ~80ms）。
const winSigCap = 6

func platformFilelessLimits() string {
	return "CIM 进程命令行 + Authenticode 签名（仅临时目录文件）；" +
		"**不读进程内存**（无 VAD 遍历），所以匿名可执行段在 Windows 上恒为「未探测」；" +
		"PowerShell 需 5.1+"
}

func platformProbeFileless() error {
	if winPowerShell() == "" {
		return errors.New("找不到 powershell.exe / pwsh.exe，无法读取进程命令行（无文件检测不可用）")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := runUTF8(ctx, winPowerShell(), "-NoProfile", "-NonInteractive", "-Command", "Get-CimInstance Win32_Process | Select-Object -First 1 ProcessId | ConvertTo-Csv -NoTypeInformation")
	if err != nil {
		return fmt.Errorf("PowerShell 取进程表失败: %v", err)
	}
	if !strings.Contains(decodeWinOutput(out), "ProcessId") {
		return errors.New("PowerShell 能跑但取不到 Win32_Process（WMI 服务异常？）")
	}
	return nil
}

// winPowerShell 返回可用的 PowerShell 可执行文件名（空 = 没有）。
func winPowerShell() string {
	for _, name := range []string{"powershell.exe", "pwsh.exe"} {
		if _, err := exec.LookPath(name); err == nil {
			return name
		}
	}
	return ""
}

// platformFilelessFacts 取进程表并对临时目录里的可执行文件补签名状态。
func platformFilelessFacts(ctx context.Context) ([]filelessFact, error) {
	ps := winPowerShell()
	if ps == "" {
		return nil, errors.New("找不到 powershell.exe / pwsh.exe")
	}
	out, err := runUTF8(ctx, ps, "-NoProfile", "-NonInteractive", "-Command", winCimScript)
	if err != nil {
		return nil, fmt.Errorf("取进程表失败: %w", err)
	}
	facts := parseCimProcessCSV(decodeWinOutput(out))
	now := nowSeconds()

	checked := 0
	for i := range facts {
		f := &facts[i]
		f.TS = now
		f.ExeInTemp = isTempPath(f.Exe)
		if f.Exe != "" {
			// 映像还在不在：Windows 允许删除正在运行的 exe 的**目录项**
			// （FILE_SHARE_DELETE），这时 Stat 会失败而进程还在跑。
			if strings.HasPrefix(f.Exe, `\\`) || (len(f.Exe) > 2 && f.Exe[1] == ':') {
				if _, err := osStat(f.Exe); err != nil {
					f.ImageDeleted = true
				}
			}
		}
		// 签名只查临时目录（全量查 400 个文件要 30 秒，且绝大多数是微软签名的系统程序）
		if f.ExeInTemp && f.Exe != "" && checked < winSigCap && ctx.Err() == nil {
			checked++
			if st, ok := winSignatureStatus(ctx, ps, f.Exe); ok {
				f.HasSigInfo = true
				f.Signed = st == "Valid"
			}
		}
	}
	return facts, nil
}

// winSignatureStatus 取单个文件的 Authenticode 状态。
// ok=false 表示「没查成」（路径含引号/超时），调用方不得把它当成未签名。
func winSignatureStatus(ctx context.Context, ps, path string) (string, bool) {
	if strings.ContainsAny(path, `'"`) {
		return "", false // 单引号会被 PowerShell 当字符串结束，直接放弃（不拼）
	}
	script := fmt.Sprintf(winSigScript, path)
	out, err := runUTF8(ctx, ps, "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil {
		return "", false
	}
	st := strings.TrimSpace(decodeWinOutput(out))
	if st == "" {
		return "", false
	}
	return st, true
}
