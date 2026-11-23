//go:build windows

package collector

// Windows 开机自启采集。
//
// 采集面（三处覆盖了实战里 95% 的持久化落点）：
//   HKLM/HKCU \SOFTWARE\Microsoft\Windows\CurrentVersion\Run 与 RunOnce
//   外加 Wow6432Node 的 32 位视图（32 位程序写的是这一份）
//   %APPDATA% / %ProgramData% 的 Start Menu\Programs\Startup 目录
//   schtasks /query /fo csv /v 计划任务
//
// 全部走系统自带命令（reg.exe / schtasks.exe），不碰注册表 API：
// 只读、无 cgo、交叉编译不受影响。均带超时（ctx），schtasks 在某些机器上
// 会卡十几秒，卡住时宁可本轮返回部分数据，也不拖死轮询循环。
//
// 编码：这两个工具的 stdout 走控制台代码页，中文系统上是 GBK，直接读会乱码。
// 这里先用同一行 cmd 里的 chcp 65001 把代码页切到 UTF-8 再执行；没有控制台
// 的会话（服务方式运行）里 chcp 可能不生效，所以再加一道保险：解不出合法
// UTF-8 的值不做路径判定（见 guardProgram），免得把乱码路径判成 prog-missing。

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

// 判定用的两个路径谓词（winTempPath / winUserBinaryPath）放在
// persistence_parse.go（不带 build tag），这样 macOS 上也能跑它们的测试。
// 这里只做平台接线。
func isTempPath(p string) bool { return winTempPath(p) }

// isImmutableItemPath Windows 没有 SIP 那种不可变区：HKLM 的 Run 键与
// ProgramData 启动目录都是管理员可写的持久化落点，一律参与完整判定。
func isImmutableItemPath(string) bool { return false }

// isUserBinaryPath 用户可写目录 → 提权持久化信号，细节见 winUserBinaryPath。
func isUserBinaryPath(p string) bool { return winUserBinaryPath(p) }

func platformProbePersistence() error {
	for _, bin := range []string{"reg.exe", "schtasks.exe"} {
		if _, err := exec.LookPath(bin); err != nil {
			return fmt.Errorf("缺少 %s，无法采集自启项", bin)
		}
	}
	return nil
}

// runUTF8 在 cmd 里先切代码页再跑命令，尽量拿到 UTF-8 输出。
func runUTF8(ctx context.Context, bin string, args ...string) ([]byte, error) {
	line := "chcp 65001>nul & " + bin
	for _, a := range args {
		if strings.ContainsAny(a, " \t") {
			line += ` "` + a + `"`
		} else {
			line += " " + a
		}
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	return exec.CommandContext(cctx, "cmd", "/c", line).Output()
}

// winRunKeys 注册表自启键。Wow6432Node 是 32 位视图，不能省。
func winRunKeys() []struct{ Key, Scope string } {
	base := winSep + `SOFTWARE` + winSep
	wow := winSep + `SOFTWARE` + winSep + `Wow6432Node` + winSep
	cv := winSep + `Microsoft` + winSep + `Windows` + winSep + `CurrentVersion` + winSep
	return []struct{ Key, Scope string }{
		{"HKLM" + base + cv + "Run", "system"},
		{"HKLM" + base + cv + "RunOnce", "system"},
		{"HKLM" + wow + cv + "Run", "system"},
		{"HKLM" + wow + cv + "RunOnce", "system"},
		{"HKCU" + base + cv + "Run", "user"},
		{"HKCU" + base + cv + "RunOnce", "user"},
	}
}

func platformPersistenceItems(ctx context.Context) ([]persistenceItem, error) {
	var items []persistenceItem

	ok := 0
	for _, rk := range winRunKeys() {
		out, err := runUTF8(ctx, "reg.exe", "query", rk.Key)
		if err != nil {
			continue // 键不存在是常态，不是错误
		}
		ok++
		for _, e := range parseRegQuery(string(out)) {
			// RunOnce 里 Deleting/Deleting2 是系统清理标记，没有命令
			if strings.HasPrefix(e.Name, "Deleting") && e.Value == "" {
				continue
			}
			it := persistenceItem{
				Kind:    "registry-run",
				ID:      rk.Key + winSep + e.Name,
				Path:    rk.Key,
				Label:   e.Name,
				Command: e.Value,
				Scope:   rk.Scope,
			}
			it.Program = guardProgram(commandToProgram(e.Value))
			items = append(items, it)
		}
	}

	items = append(items, winStartupFolders()...)
	items = append(items, winScheduledTasks(ctx)...)

	if ok == 0 && len(items) == 0 {
		return nil, fmt.Errorf("注册表自启键与启动目录都无法读取（权限不足？）")
	}
	return items, nil
}

// guardProgram 解不出合法 UTF-8 的路径不当路径看。
// 否则 GBK 乱码会让 prog-missing 对所有非 ASCII 路径误报。
func guardProgram(p string) string {
	if p == "" || !utf8.ValidString(p) {
		return ""
	}
	return p
}

func winStartupFolders() []persistenceItem {
	var out []persistenceItem
	startup := winSep + `Microsoft` + winSep + `Windows` + winSep + `Start Menu` + winSep + `Programs` + winSep + `Startup`
	specs := []struct{ Dir, Scope string }{
		{joinKeepAbs(os.Getenv("APPDATA"), startup), "user"},
		{joinKeepAbs(os.Getenv("ProgramData"), startup), "system"},
	}
	for _, s := range specs {
		if s.Dir == "" {
			continue
		}
		ents, err := os.ReadDir(s.Dir)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if e.IsDir() || strings.HasPrefix(e.Name(), ".") || strings.EqualFold(e.Name(), "desktop.ini") {
				continue
			}
			full := filepath.Join(s.Dir, e.Name())
			it := persistenceItem{
				Kind:  "startup-folder",
				ID:    full,
				Path:  full,
				Label: e.Name(),
				Scope: s.Scope,
			}
			if info, err := e.Info(); err == nil {
				it.MTime = info.ModTime().Unix()
				it.Mode = uint32(info.Mode().Perm())
				it.HasMode = true
			}
			// .lnk 的目标要 COM(IShellLink) 才能解，首版不解析：
			// 解不出目标就做路径判定，只会把每个正常启动项都判成「路径不存在」。
			// 启动目录的价值本来就在「多了一个快捷方式」这个差分上。
			if !strings.EqualFold(filepath.Ext(e.Name()), ".lnk") {
				it.Program = guardProgram(full)
				it.Command = full
			}
			out = append(out, it)
		}
	}
	return out
}

// joinKeepAbs 环境变量缺失时返回空串（而不是相对路径），
// 免得拿 "" 去 ReadDir 把当前目录当启动目录扫。
func joinKeepAbs(base, sub string) string {
	if base == "" || !filepath.IsAbs(base) {
		return ""
	}
	return filepath.Join(base, sub)
}

func winScheduledTasks(ctx context.Context) []persistenceItem {
	out, err := runUTF8(ctx, "schtasks.exe", "/query", "/fo", "csv", "/v")
	if err != nil {
		return nil
	}
	var items []persistenceItem
	msRoot := winSep + `Microsoft` + winSep + `Windows` + winSep
	for _, t := range parseSchtasksCSV(string(out)) {
		// 系统自带任务（\Microsoft\Windows\...）量极大且不可写，
		// 只保留非系统目录的任务，避免把真正的手工投放淹没。
		low := strings.ToLower(t.Name)
		if strings.HasPrefix(low, strings.ToLower(msRoot)) {
			continue
		}
		it := persistenceItem{
			Kind:    "scheduled-task",
			ID:      "schtask:" + low,
			Path:    winSep + "SchTasks",
			Label:   t.Name,
			Command: t.Run,
		}
		// 任务以 SYSTEM/服务账户跑 → 系统级；用具体用户名跑 → 用户级
		if strings.Contains(strings.ToLower(t.Status), "system") ||
			strings.Contains(strings.ToLower(t.Run), "system32") {
			it.Scope = "system"
		} else {
			it.Scope = "user"
		}
		it.Program = guardProgram(commandToProgram(t.Run))
		items = append(items, it)
	}
	return items
}
