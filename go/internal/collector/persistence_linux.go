//go:build linux

package collector

// Linux 开机自启采集。
//
// 采集面：
//   /etc/crontab                   系统格式（第 6 列是用户）
//   /etc/cron.d/*                  系统格式
//   /etc/cron.{hourly,daily,...}/* 目录里每个文件就是一条任务
//   /var/spool/cron/{crontabs/,}*  各用户 crontab（需 root 才能读别人的）
//   ~/.crontab + `crontab -l`      当前用户
//   /etc/systemd/system/*.service  系统级 unit
//   /etc/systemd/user/*.service    全局用户 unit
//   ~/.config/systemd/user/*.service
//
// 刻意没做：apt/dpkg 包自带的 /lib/systemd/system/*.service。
// 那些是发行版内容，量大且不可写；采进来只会把真正的「手工投放」淹没。
// 需要「包完整性」时那是 integrity 采集器的活，不是这里。

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

var linuxTempPrefixes = []string{
	"/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "/run/user/",
}

func isTempPath(p string) bool {
	for _, pre := range linuxTempPrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// isImmutableItemPath Linux 上我们扫的 cron/systemd 位置都由管理员维护
// （/etc 可写、spool 可写），没有 macOS 那种 SIP 不可变区，所以恒为 false。
// 保留这个钩子是为了让三平台共用一套判定顺序。
func isImmutableItemPath(string) bool { return false }

// isUserBinaryPath 普通用户可写目录。
// 用于「系统级 unit 却执行家目录里的程序」：
// systemd 以 root 跑 /home/x/.payload/p.sh 是提权持久化的典型形态。
func isUserBinaryPath(p string) bool {
	for _, pre := range []string{"/home/", "/root/", "/mnt/", "/media/", "/srv/"} {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

func platformProbePersistence() error {
	n := 0
	for _, d := range []string{"/etc", "/proc/1"} {
		if _, err := os.Stat(d); err == nil {
			n++
		}
	}
	if n == 0 {
		return fmt.Errorf("/etc 与 /proc 都不可读，无法采集开机项")
	}
	return nil
}

func platformPersistenceItems(ctx context.Context) ([]persistenceItem, error) {
	var items []persistenceItem

	// systemd
	for _, spec := range linuxUnitDirs() {
		ents, err := os.ReadDir(spec.Dir)
		if err != nil {
			continue
		}
		for _, e := range ents {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".service") {
				continue
			}
			full := filepath.Join(spec.Dir, name)
			data, err := os.ReadFile(full)
			if err != nil {
				continue
			}
			u := parseSystemdUnit(string(data))
			it := persistenceItem{
				Kind:  "systemd",
				ID:    full,
				Path:  full,
				Label: strings.TrimSuffix(name, ".service"),
				Scope: spec.Scope,
			}
			if info, err := e.Info(); err == nil {
				it.MTime = info.ModTime().Unix()
				it.Mode = uint32(info.Mode().Perm())
				it.HasMode = true
			}
			if len(u.Exec) > 0 {
				it.Program = commandToProgram(u.Exec[0])
				it.Command = strings.Join(u.Exec, " ; ")
			}
			// RunAtLoad/KeepAlive 只作展示：systemd 里「enabled + Restart=always」
			// 太常见（nginx/docker/ssh 全中），拿它当可疑判据等于全量噪音。
			// run-at-load-keep-alive 这条规则也因此在判定里限定 Kind=="launchd"。
			it.RunAtLoad = len(u.WantedBy) > 0
			it.KeepAlive = strings.EqualFold(u.Restart, "always")
			items = append(items, it)
		}
	}

	// 系统级 crontab
	items = append(items, cronItemsFromFile("/etc/crontab", "system", true)...)
	for _, f := range globSorted("/etc/cron.d/*") {
		items = append(items, cronItemsFromFile(f, "system", true)...)
	}
	for _, dir := range []string{"/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"} {
		items = append(items, periodicItems(dir)...)
	}

	// 各用户 crontab（root 才能读全；读不到的跳过，不报错）
	for _, dir := range []string{"/var/spool/cron/crontabs", "/var/spool/cron"} {
		ents, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if e.IsDir() {
				continue
			}
			items = append(items, cronItemsFromFile(filepath.Join(dir, e.Name()), "user", false)...)
		}
	}

	// 当前用户
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		items = append(items, cronItemsFromFile(filepath.Join(home, ".crontab"), "user", false)...)
	}
	if bin, err := exec.LookPath("crontab"); err == nil {
		if b, err := exec.CommandContext(ctx, bin, "-l").Output(); err == nil {
			items = append(items, cronItemsFromText(string(b), "user", "crontab:user", false, "crontab://user")...)
		}
	}

	return items, nil
}

type unitDirSpec struct {
	Dir   string
	Scope string
}

func linuxUnitDirs() []unitDirSpec {
	specs := []unitDirSpec{
		{"/etc/systemd/system", "system"},
		{"/etc/systemd/user", "user"},
	}
	// 被 enable 的 unit 在 multi-user.target.wants 里是符号链接，
	// ReadDir 在 /etc/systemd/system 下已经覆盖；子目录不重复扫。
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		specs = append(specs, unitDirSpec{filepath.Join(home, ".config", "systemd", "user"), "user"})
	}
	return specs
}

func globSorted(pattern string) []string {
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

func cronItemsFromText(text, scope, idPrefix string, hasUser bool, itemPath string) []persistenceItem {
	var out []persistenceItem
	for _, line := range strings.Split(text, "\n") {
		e, ok := parseCronLine(line, hasUser)
		if !ok {
			continue
		}
		out = append(out, persistenceItem{
			Kind:    "cron",
			ID:      idPrefix + ":" + cmdHash(e.Command),
			Path:    itemPath,
			Label:   e.Schedule + " " + e.Command,
			Program: commandToProgram(e.Command),
			Command: e.Command,
			Scope:   scope,
		})
	}
	return out
}

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
		if err != nil || info.Mode().Perm()&0o111 == 0 {
			continue
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
