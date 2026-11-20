package collector

// integrity_test.go —— 文件完整性监控的双向测试。
//
// 双向的含义（每条规则都配反例）：
//
//	首次见到            → 建基线，**0 事件**（不是「新文件也算改动」）
//	内容没变            → **0 事件**（不是「每轮都报一遍」）
//	内容变了            → 1 条 modified
//	文件被删            → 1 条 deleted
//	文件重新出现        → 1 条 created
//	不可读（digest 空） → **0 事件**（不能把「读不到」判成「被清空」）
//	authorized_keys 等  → severity=high；其他路径 → medium
//
// 基线持久化也测：重启进程（新建实例）后不许把已有文件重报一遍——
// 那会让每次重启都刷一屏假告警。

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newTestIntegrity 造一个监控临时目录里指定文件的 Integrity。
func newTestIntegrity(t *testing.T, paths ...string) (*Integrity, string) {
	t.Helper()
	dir := t.TempDir()
	ig := &Integrity{known: map[string]integrityRecord{}}
	ig.paths = paths
	ig.state = filepath.Join(dir, "integrity.json")
	ig.hashFn = sha256File
	ig.statFn = os.Stat
	ig.Init("integrity", ModePoll, time.Second, ig.probe)
	return ig, dir
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrityBaselineThenUnchanged(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "authorized_keys")
	writeFile(t, p, "ssh-ed25519 AAAA test\n")

	ig, _ := newTestIntegrity(t, p)
	evs, err := ig.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 0 {
		t.Fatalf("首轮建基线不该出事件，实际 %d 条: %+v", len(evs), evs)
	}
	if n := ig.Items(); n != 1 {
		t.Fatalf("监控条数 = %d，期望 1", n)
	}
	// 反例：内容没变，第二轮必须是 0
	evs, err = ig.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 0 {
		t.Fatalf("内容没变却报了 %d 条: %+v", len(evs), evs)
	}
}

func TestIntegrityModifiedHighRisk(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "authorized_keys")
	writeFile(t, p, "ssh-ed25519 AAAA original\n")

	ig, _ := newTestIntegrity(t, p)
	if _, err := ig.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	writeFile(t, p, "ssh-ed25519 AAAA original\nssh-rsa BBBB attacker\n")

	evs, err := ig.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 {
		t.Fatalf("改了内容却报了 %d 条，期望 1: %+v", len(evs), evs)
	}
	ev := evs[0]
	if ev.Kind != EventIntegrityChange {
		t.Fatalf("kind = %q，期望 %q", ev.Kind, EventIntegrityChange)
	}
	if ev.Source != "integrity" {
		t.Fatalf("source = %q", ev.Source)
	}
	if ev.Path != p {
		t.Fatalf("path = %q，期望 %q", ev.Path, p)
	}
	if ev.Process != "authorized_keys" {
		t.Fatalf("process = %q，期望 authorized_keys", ev.Process)
	}
	if ev.Severity != "high" {
		t.Fatalf("severity = %q，期望 high（authorized_keys 在硬名单里）", ev.Severity)
	}
	// reason 与 Python 逐字相同（中文原串），slug 在 reason_slug
	if ev.Subject["reason"] != "内容哈希变化" {
		t.Fatalf("reason = %v，期望 内容哈希变化（与 Python 逐字相同）", ev.Subject["reason"])
	}
	if ev.Subject["reason_slug"] != reasonModified {
		t.Fatalf("reason_slug = %v，期望 %q", ev.Subject["reason_slug"], reasonModified)
	}
	old, _ := ev.Subject["old_digest"].(string)
	nw, _ := ev.Subject["new_digest"].(string)
	if len(old) != 16 || len(nw) != 16 {
		t.Fatalf("digest 没截到 16 位: old=%q new=%q", old, nw)
	}
	if old == nw {
		t.Fatalf("新旧 digest 相同，说明没重算: %q", old)
	}

	// 反例：紧接着再采一轮，内容没再变 → 0 事件（不能反复报同一处改动）
	evs, err = ig.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 0 {
		t.Fatalf("同一处改动被重复报 %d 次: %+v", len(evs), evs)
	}
}

func TestIntegrityModifiedMediumRisk(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "app.conf")
	writeFile(t, p, "a=1\n")

	ig, _ := newTestIntegrity(t, p)
	if _, err := ig.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	writeFile(t, p, "a=2\n")

	evs, err := ig.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 {
		t.Fatalf("报了 %d 条，期望 1", len(evs))
	}
	// 反例：普通配置文件不许被抬成 high
	if evs[0].Severity != "medium" {
		t.Fatalf("severity = %q，期望 medium", evs[0].Severity)
	}
}

func TestIntegrityDeletedAndCreated(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sshd_config")
	writeFile(t, p, "PermitRootLogin no\n")

	ig, _ := newTestIntegrity(t, p)
	if _, err := ig.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}

	// 删除 → deleted
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	evs, err := ig.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 || evs[0].Subject["reason_slug"] != reasonDeleted {
		t.Fatalf("删除没报 deleted: %+v", evs)
	}
	if evs[0].Subject["reason"] != "文件被删除" {
		t.Fatalf("reason = %v，期望 文件被删除", evs[0].Subject["reason"])
	}
	if evs[0].Severity != "high" {
		t.Fatalf("sshd_config 的 severity = %q，期望 high", evs[0].Severity)
	}

	// 再出现 → created
	writeFile(t, p, "PermitRootLogin yes\n")
	evs, err = ig.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 || evs[0].Subject["reason_slug"] != reasonCreated {
		t.Fatalf("重现没报 created: %+v", evs)
	}
	if evs[0].Subject["reason"] != "新增关键文件" {
		t.Fatalf("reason = %v，期望 新增关键文件", evs[0].Subject["reason"])
	}

	// 反例：状态稳定后必须 0
	evs, err = ig.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 0 {
		t.Fatalf("稳定后还在报: %+v", evs)
	}
}

func TestIntegrityUnreadableNoFalsePositive(t *testing.T) {
	// 读不到的文件 digest 恒为空：两轮都空 → 不许报「内容变化」。
	// 这是 Python 里 `prev.get("digest") and rec["digest"]` 双非空才比的原意。
	dir := t.TempDir()
	p := filepath.Join(dir, "sudoers")
	writeFile(t, p, "root ALL=(ALL) ALL\n")

	ig, _ := newTestIntegrity(t, p)
	ig.hashFn = func(string) string { return "" } // 模拟「读不到」
	if _, err := ig.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	writeFile(t, p, "root ALL=(ALL) NOPASSWD: ALL\n")
	evs, err := ig.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 0 {
		t.Fatalf("digest 读不到却报了内容变化: %+v", evs)
	}
}

func TestIntegrityMissingFileIsBaselineNotAlert(t *testing.T) {
	// 监控清单里有一条本来就不存在的路径（Linux 清单在 macOS 上就是这样）：
	// 首轮只记 exists=false，不许报「文件被删除」。
	dir := t.TempDir()
	p := filepath.Join(dir, "does-not-exist")
	ig, _ := newTestIntegrity(t, p)
	evs, err := ig.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 0 {
		t.Fatalf("不存在的路径首轮就报警: %+v", evs)
	}
	if snap := ig.Snapshot(); len(snap["missing"].([]string)) != 1 {
		t.Fatalf("missing 清单 = %v", snap["missing"])
	}
}

func TestIntegrityBaselinePersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "hosts")
	writeFile(t, p, "127.0.0.1 localhost\n")

	ig, stateDir := newTestIntegrity(t, p)
	if _, err := ig.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(ig.state); err != nil {
		t.Fatalf("基线文件没落盘: %v", err)
	}

	// 新实例（模拟重启），共用同一份基线文件
	ig2 := &Integrity{known: map[string]integrityRecord{}}
	ig2.paths = []string{p}
	ig2.state = filepath.Join(stateDir, "integrity.json")
	ig2.hashFn = sha256File
	ig2.statFn = os.Stat
	ig2.Init("integrity", ModePoll, time.Second, ig2.probe)

	evs, err := ig2.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 0 {
		t.Fatalf("重启后把已有文件重报了一遍: %+v", evs)
	}

	// 但改动仍然要被抓到（基线不是「一次性打卡」）
	writeFile(t, p, "127.0.0.1 localhost\n10.0.0.1 attacker\n")
	evs, err = ig2.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 {
		t.Fatalf("重启后的改动没被抓到: %+v", evs)
	}
	if evs[0].Severity != "high" {
		t.Fatalf("hosts 的 severity = %q，期望 high", evs[0].Severity)
	}
}

func TestIntegritySeverityTable(t *testing.T) {
	cases := map[string]string{
		"/Users/x/.ssh/authorized_keys": "high",
		"/etc/ssh/sshd_config":          "high",
		"/etc/sudoers":                  "high",
		"/etc/pf.conf":                  "high",
		"/etc/hosts":                    "high",
		"/etc/hosts.deny":               "high", // 子串匹配，与 Python 一致
		"/Users/x/.zshrc":               "medium",
		"/etc/ld.so.preload":            "medium",
		"/var/db/something/else.conf":   "medium",
	}
	for path, want := range cases {
		if got := integritySeverity(path); got != want {
			t.Fatalf("%s 的 severity = %q，期望 %q", path, got, want)
		}
	}
}

func TestIntegrityWatchPathsConfig(t *testing.T) {
	// Options["watch_paths"] 覆盖默认清单；~ 要展开
	cfg := Config{Options: map[string]any{
		"watch_paths": []any{"/etc/hosts", "~/.ssh/authorized_keys", "/etc/hosts"},
	}}
	got := integrityWatchPaths(cfg)
	if len(got) != 2 {
		t.Fatalf("监控清单 = %v（去重后应为 2 条）", got)
	}
	if !strings.HasPrefix(got[1], "/") || strings.Contains(got[1], "~") {
		t.Fatalf("~ 没展开: %q", got[1])
	}
	// 反例：不配置时用平台默认，且不能为空
	if len(integrityWatchPaths(Config{})) == 0 {
		t.Fatal("默认监控清单为空")
	}
}

func TestIntegrityDigestStable(t *testing.T) {
	// sha256 必须与 Python hashlib.sha256 同值（同一份内容 → 同一串）
	dir := t.TempDir()
	p := filepath.Join(dir, "x")
	writeFile(t, p, "hello\n")
	const want = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
	if got := sha256File(p); got != want {
		t.Fatalf("sha256 = %q，期望 %q（与 Python hashlib 对齐）", got, want)
	}
	// 反例：不存在的文件返回空串，不是 panic 也不是全零哈希
	if got := sha256File(filepath.Join(dir, "nope")); got != "" {
		t.Fatalf("不存在的文件 digest = %q，期望空串", got)
	}
}
