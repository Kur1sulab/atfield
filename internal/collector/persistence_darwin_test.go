//go:build darwin

package collector

// persistence_darwin_test.go —— macOS 专有的判定与真机清点测试。
//
// 两类用例：
//   1) 依赖平台路径语义的判定（/Users/ 对 darwin 才是家目录）；
//   2) 真机清点：直接跑 platformPersistenceItems，断言「能采到、ID 唯一、
//      误报率不失控」。第 2 类会在别的 Mac 上跑，所以断言用的是比例而不是
//      具体数字——写死「本机 989 条」的测试第二天就会红。

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDarwinRootItemPointingAtUserBinary(t *testing.T) {
	fs := fakeFS{
		"/Users/xxx/Library/Application Support/Updater/up": 0o755,
		"/Library/PrivilegedHelperTools/com.vendor.helper":  0o755,
	}
	// 系统级（LaunchDaemon）指向普通用户可写目录 → 提权持久化信号
	daemon := persistenceItem{
		Kind: "launchd", Path: "/Library/LaunchDaemons/com.evil.plist",
		Program: "/Users/xxx/Library/Application Support/Updater/up",
		Command: "/Users/xxx/Library/Application Support/Updater/up",
		Scope:   "system", Mode: 0o644, HasMode: true,
	}
	if got := daemon.suspicion(fs); !reflect.DeepEqual(got, []string{reasonRootUserBin}) {
		t.Fatalf("root 条目指向用户目录没报: %v", got)
	}

	// 反向：同一个用户目录，但它是用户级 LaunchAgent → 完全正常（不许报）
	agent := daemon
	agent.Scope = "user"
	agent.Path = "/Users/xxx/Library/LaunchAgents/com.evil.plist"
	if got := agent.suspicion(fs); len(got) != 0 {
		t.Fatalf("用户级 Agent 指向自己家目录被误报: %v", got)
	}

	// 反向：系统级，但指向 /Library/PrivilegedHelperTools（系统可信位置）→ 不报
	good := daemon
	good.Program = "/Library/PrivilegedHelperTools/com.vendor.helper"
	good.Command = good.Program
	if got := good.suspicion(fs); len(got) != 0 {
		t.Fatalf("PrivilegedHelperTools 被误报: %v", got)
	}
}

func TestDarwinTempPlistFixtureIsReported(t *testing.T) {
	// 双向测试的「该报」一侧：在临时目录里放一个指向已删临时路径的 launchd plist。
	// 只在 os.MkdirTemp 里造样本——绝不往 ~/Library/LaunchAgents 写东西，
	// 采集器对真实开机项必须只读。
	dir, err := os.MkdirTemp("", "atfield-persist")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	payload := filepath.Join(dir, "payload.sh") // 故意不创建：模拟「指向已删路径」
	plistPath := filepath.Join(dir, "com.evil.agent.plist")
	plist := strings.Replace(sampleAgentPlist,
		"<key>ProgramArguments</key>", "<key>Program</key>\n	<string>"+payload+"</string>\n	<key>ProgramArguments</key>", 1)
	if err := os.WriteFile(plistPath, []byte(plist), 0o644); err != nil {
		t.Fatal(err)
	}
	f, ok := launchPlistFields(plistPath)
	if !ok {
		t.Fatal("自家写的 plist 都解析不了")
	}
	if f.Program != payload {
		t.Fatalf("Program 解析错: %q", f.Program)
	}
	it := persistenceItem{
		Kind: "launchd", ID: plistPath, Path: plistPath, Label: f.Label,
		Program: f.Program, Args: f.Args, Command: joinCommand(f.Program, f.Args),
		Scope: "user", RunAtLoad: f.RunAtLoad, KeepAlive: f.KeepAlive,
		Mode: 0o644, HasMode: true,
	}
	got := it.suspicion(realFS{})
	for _, want := range []string{
		reasonItemTemp, reasonCmdToken + "curl", reasonCmdToken + "/bin/sh -c",
		reasonRunKeepAlive, reasonProgTemp, reasonProgMissing,
	} {
		if !contains(got, want) {
			t.Errorf("缺少理由 %q，实际 %v", want, got)
		}
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func TestDarwinCollectRealInventory(t *testing.T) {
	items, err := platformPersistenceItems(context.Background())
	if err != nil {
		t.Fatalf("真机清点失败: %v", err)
	}
	if len(items) < 50 {
		t.Fatalf("只采到 %d 条，macOS 上不可能这么少（launchd 目录没读到？）", len(items))
	}

	seen := map[string]bool{}
	var withCmd, susCount int
	var susSamples []string
	for i := range items {
		it := &items[i]
		if it.ID == "" {
			t.Fatalf("条目没有 ID: %+v", it)
		}
		if seen[it.ID] {
			t.Fatalf("ID 重复（会把两条合并成一条，差分就废了）: %s", it.ID)
		}
		seen[it.ID] = true
		if it.Kind == "" || it.Scope == "" {
			t.Fatalf("条目字段缺失: %+v", it)
		}
		if it.Command != "" {
			withCmd++
		}
		if r := it.suspicion(realFS{}); len(r) > 0 {
			susCount++
			susSamples = append(susSamples, it.ID+" => "+strings.Join(r, ","))
		}
	}
	t.Logf("清点 %d 条（有命令行 %d 条），可疑 %d 条", len(items), withCmd, susCount)
	for _, s := range susSamples {
		t.Logf("  可疑: %s", s)
	}
	if withCmd < 10 {
		t.Fatalf("只有 %d 条解析出命令行，plist 解析大概是瞎的", withCmd)
	}
	// 硬不变量：SIP 保护的 /System 条目一条都不许报。
	// 这条一旦红，说明某条规则又开始把 Apple 自己的看门狗当威胁了。
	for i := range items {
		it := &items[i]
		if strings.HasPrefix(it.Path, "/System/") {
			if r := it.suspicion(realFS{}); len(r) > 0 {
				t.Fatalf("/System 条目被误报: %s => %v", it.ID, r)
			}
		}
	}
	// 误报闸门：可疑率超过 2% 说明某条规则在真机上泛滥，必须在合并前收紧。
	limit := len(items) * 2 / 100
	if limit < 10 {
		limit = 10
	}
	if susCount > limit {
		t.Fatalf("可疑项 %d 条超过闸门 %d 条，规则在真机上失控", susCount, limit)
	}
}

func TestDarwinBinaryPlistParsed(t *testing.T) {
	// 系统 plist 里有一部分是 bplist00：验证 plutil 兜底那条路真的通
	dirs := []string{"/System/Library/LaunchDaemons", "/System/Library/LaunchAgents"}
	for _, dir := range dirs {
		ents, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for i, e := range ents {
			if i > 40 {
				break
			}
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".plist") {
				continue
			}
			full := filepath.Join(dir, e.Name())
			head, err := os.ReadFile(full)
			if err != nil || !strings.HasPrefix(string(head), "bplist") {
				continue
			}
			f, ok := launchPlistFields(full)
			if !ok {
				t.Fatalf("二进制 plist 解析失败: %s", full)
			}
			if f.Label == "" && f.Program == "" && len(f.Args) == 0 {
				t.Fatalf("二进制 plist 解析出来是空的: %s", full)
			}
			t.Logf("二进制 plist 解析成功: %s label=%q", filepath.Base(full), f.Label)
			return
		}
	}
	t.Skip("这台机器上没有二进制 plist 可验证")
}

func TestDarwinCronPickedUp(t *testing.T) {
	items := darwinCronItems(context.Background())
	total := 0
	for _, it := range items {
		if it.Kind != "cron" || it.ID == "" {
			t.Fatalf("cron 条目字段缺失: %+v", it)
		}
		total++
	}
	t.Logf("cron/periodic 条目 %d 条", total)
	// 没装 cron 任务的机器上可以是 0；这里只验证不 panic、字段完整。
}

func TestDarwinPlistCacheWarms(t *testing.T) {
	// 944 个 plist、104 个二进制 plist 要 fork plutil：不做缓存的话每 60s
	// 都要重新解析一遍，纯属白烧 CPU。第二轮必须只做 stat。
	plistCacheMu.Lock()
	plistCache = map[string]plistCacheEntry{} // 先清空，否则前面跑过的用例已经把缓存捂热了
	n0 := 0
	plistCacheMu.Unlock()

	t0 := time.Now()
	if _, err := platformPersistenceItems(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := time.Since(t0)

	t1 := time.Now()
	if _, err := platformPersistenceItems(context.Background()); err != nil {
		t.Fatal(err)
	}
	second := time.Since(t1)

	plistCacheMu.Lock()
	n1 := len(plistCache)
	plistCacheMu.Unlock()

	if n1 <= n0 {
		t.Fatalf("plist 缓存没被填充: %d -> %d", n0, n1)
	}
	t.Logf("冷 %dms → 热 %dms（缓存 %d 条 plist）", first.Milliseconds(), second.Milliseconds(), n1)
	if second >= first {
		t.Fatalf("第二轮没变快（%v vs %v），缓存大概没生效", second, first)
	}
}
