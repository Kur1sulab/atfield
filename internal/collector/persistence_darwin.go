//go:build darwin

package collector

// macOS 开机自启采集。
//
// 采集面（与 Python 版 PersistenceCollector 对齐，另补 macOS 特有的 periodic）：
//   ~/Library/LaunchAgents        用户级 LaunchAgent（最常见的手工落地位置）
//   /Library/LaunchAgents         全局 LaunchAgent
//   /Library/LaunchDaemons        全局 LaunchDaemon（root 运行，提权持久化首选）
//   /System/Library/Launch*       系统自带（只读基线：数量突变本身就是信号）
//   crontab -l / /etc/crontab / /etc/cron.d / /etc/periodic/*
//
// 为什么把 /System/Library 也扫进来：一是基线，二是「系统目录里突然多出一条」
// 在有 SIP 的机器上是异常中的异常，值得有据可查。代价是 900+ 个 plist，
// 所以加了解析缓存（path+mtime+size），第二圈起只做 stat。
//
// 二进制 plist 交给 /usr/bin/plutil 转 XML（`-o -` 输出到 stdout，只读）。
// 不自己写 bplist 解析器：那是 150 行易错的偏移表代码，而 plutil 是系统自带的
// 唯一权威实现；也不引第三方库（任务约束）。

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

type launchDirSpec struct {
	Dir   string
	Scope string
}

// darwinTempPrefixes 临时/共享目录：任何本地用户都能写，落在这里的开机项不可信。
var darwinTempPrefixes = []string{
	"/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/",
	"/Users/Shared/", "/dev/shm/", "/var/folders/", "/private/var/folders/",
}

func isTempPath(p string) bool {
	for _, pre := range darwinTempPrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// isImmutableItemPath 条目所在位置不可被攻击者修改（macOS：SIP 保护 /System）。
// 这类条目只做「存在即清点」，不参与 prog-*/watchdog 判定，理由见
// persistence.go 里 suspicion() 的收敛说明。
func isImmutableItemPath(p string) bool {
	return strings.HasPrefix(p, "/System/")
}

// isUserBinaryPath 普通用户可写的家目录区域。
// 只用于「系统级条目却指向用户目录」这一条：LaunchDaemon 以 root 运行，
// 却去执行 /Users/xxx 下可被普通用户替换的二进制 → 提权持久化。
// 用户级 LaunchAgent 指向 /Users/xxx 完全正常，不算（见 Scope 判定）。
func isUserBinaryPath(p string) bool {
	if strings.HasPrefix(p, "/Users/Shared/") {
		return false // 共享目录已由 item-in-temp/prog-in-temp 覆盖
	}
	return strings.HasPrefix(p, "/Users/")
}

func darwinLaunchDirs() []launchDirSpec {
	var dirs []launchDirSpec
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		dirs = append(dirs, launchDirSpec{filepath.Join(home, "Library", "LaunchAgents"), "user"})
	}
	dirs = append(dirs,
		launchDirSpec{"/Library/LaunchAgents", "system"},
		launchDirSpec{"/Library/LaunchDaemons", "system"},
		launchDirSpec{"/System/Library/LaunchAgents", "system"},
		launchDirSpec{"/System/Library/LaunchDaemons", "system"},
	)
	return dirs
}

func platformProbePersistence() error {
	n := 0
	for _, d := range darwinLaunchDirs() {
		if fi, err := os.Stat(d.Dir); err == nil && fi.IsDir() {
			n++
		}
	}
	if n == 0 {
		return fmt.Errorf("没有可读的 launchd 目录")
	}
	return nil
}

func platformPersistenceItems(ctx context.Context) ([]persistenceItem, error) {
	var items []persistenceItem
	scanErrs := 0
	for _, d := range darwinLaunchDirs() {
		ents, err := os.ReadDir(d.Dir)
		if err != nil {
			scanErrs++
			continue // 单个目录不可读（TCC/权限）不该让整轮失败
		}
		for _, e := range ents {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".plist") {
				continue
			}
			full := filepath.Join(d.Dir, e.Name())
			it := persistenceItem{
				Kind:  "launchd",
				ID:    full,
				Path:  full,
				Scope: d.Scope,
				Label: strings.TrimSuffix(e.Name(), ".plist"),
			}
			if info, err := e.Info(); err == nil {
				it.MTime = info.ModTime().Unix()
				it.Mode = uint32(info.Mode().Perm())
				it.HasMode = true
			}
			if f, ok := launchPlistFields(full); ok {
				if f.Label != "" {
					it.Label = f.Label
				}
				it.Program = f.Program
				it.Args = f.Args
				it.RunAtLoad = f.RunAtLoad
				it.KeepAlive = f.KeepAlive
			}
			it.Command = joinCommand(it.Program, it.Args)
			items = append(items, it)
		}
	}
	items = append(items, darwinCronItems(ctx)...)
	if len(items) == 0 && scanErrs > 0 {
		return nil, fmt.Errorf("launchd 目录全部不可读（需要授予完全磁盘访问？）")
	}
	return items, nil
}

// ---------------------------------------------------------------- plist

type plistCacheEntry struct {
	mtime int64
	size  int64
	f     plistFields
	ok    bool
}

var (
	plistCacheMu sync.Mutex
	plistCache   = map[string]plistCacheEntry{}
)

// launchPlistFields 带缓存地读一个 plist。缓存键是 path，校验 mtime(ns)+size：
// 攻击者改了 plist 但不改 mtime 的情况极罕见，且还有 cmdHash 兜底。
func launchPlistFields(path string) (plistFields, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return plistFields{}, false
	}
	mt, size := fi.ModTime().UnixNano(), fi.Size()

	plistCacheMu.Lock()
	if c, hit := plistCache[path]; hit && c.mtime == mt && c.size == size {
		plistCacheMu.Unlock()
		return c.f, c.ok
	}
	plistCacheMu.Unlock()

	f, ok := readLaunchPlist(path)

	plistCacheMu.Lock()
	if len(plistCache) > 4096 {
		plistCache = map[string]plistCacheEntry{} // 目录被替换过就别无限长
	}
	plistCache[path] = plistCacheEntry{mtime: mt, size: size, f: f, ok: ok}
	plistCacheMu.Unlock()
	return f, ok
}

func readLaunchPlist(path string) (plistFields, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return plistFields{}, false
	}
	if bytes.HasPrefix(data, []byte("bplist")) {
		// 二进制 plist：plutil 转 XML 到 stdout，不改文件、不落临时文件
		out, err := exec.Command("/usr/bin/plutil", "-convert", "xml1", "-o", "-", path).Output()
		if err != nil || len(out) == 0 {
			return plistFields{}, false
		}
		data = out
	}
	dict, err := parsePlistXML(data)
	if err != nil {
		return plistFields{}, false
	}
	return plistFieldsFromDict(dict), true
}

// ---------------------------------------------------------------- cron

func darwinCronItems(ctx context.Context) []persistenceItem {
	var out []persistenceItem

	// 当前用户 crontab：`crontab -l` 只读，不动任何任务
	if bin, err := exec.LookPath("crontab"); err == nil {
		if b, err := exec.CommandContext(ctx, bin, "-l").Output(); err == nil {
			out = append(out, cronItemsFromText(string(b), "user", "crontab:user", false, "crontab://user")...)
		}
	}
	// 系统级 crontab（macOS 默认没有，但存在就必须采）
	out = append(out, cronItemsFromFile("/etc/crontab", "system", true)...)
	for _, f := range globPlists("/etc/cron.d/*") {
		out = append(out, cronItemsFromFile(f, "system", true)...)
	}
	// macOS 自己的周期任务机制：放个可执行脚本进去就会被 periodic 拉起
	for _, dir := range []string{"/etc/periodic/daily", "/etc/periodic/weekly", "/etc/periodic/monthly"} {
		out = append(out, periodicItems(dir)...)
	}
	return out
}

func globPlists(pattern string) []string {
	m, _ := filepath.Glob(pattern)
	sort.Strings(m)
	return m
}

func cronItemsFromFile(path, scope string, hasUser bool) []persistenceItem {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return cronItemsFromText(string(data), scope, "cron:"+path, hasUser, path)
}

// cronItemsFromText 把 crontab 文本切成条目。ID 用 `前缀:命令行指纹`，
// 这样改一行的时间表不会被当成「删一条+加一条」——但改了命令就是新条目，
// 那正是需要看见的。
func cronItemsFromText(text, scope, idPrefix string, hasUser bool, itemPath string) []persistenceItem {
	var out []persistenceItem
	for _, line := range strings.Split(text, "\n") {
		e, ok := parseCronLine(line, hasUser)
		if !ok {
			continue
		}
		prog := commandToProgram(e.Command)
		out = append(out, persistenceItem{
			Kind:    "cron",
			ID:      idPrefix + ":" + cmdHash(e.Command),
			Path:    itemPath,
			Label:   e.Schedule + " " + e.Command,
			Program: prog,
			Command: e.Command,
			Scope:   scope,
		})
	}
	return out
}

// periodicItems /etc/periodic/* 下每个可执行文件都是一条开机（周期）任务。
func periodicItems(dir string) []persistenceItem {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []persistenceItem
	for _, e := range ents {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		full := filepath.Join(dir, e.Name())
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.Mode().Perm()&0o111 == 0 {
			continue // periodic 只跑可执行文件，不可执行的不是任务
		}
		out = append(out, persistenceItem{
			Kind:    "cron",
			ID:      full,
			Path:    full,
			Label:   e.Name(),
			Program: full,
			Command: full,
			Scope:   "system",
			MTime:   info.ModTime().Unix(),
			Mode:    uint32(info.Mode().Perm()),
			HasMode: true,
		})
	}
	return out
}
