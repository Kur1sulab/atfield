package store

// audit_test.go —— 审计链的核心承诺：「改过、删过、截断过、整链替换过」都要查得出来。
//
// 只测「写完能读回」是没有意义的——普通日志文件也能读回。审计链的价值全在
// 篡改检测上，所以每条篡改手法都必须有一个用例真的动手改文件再验一遍。

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestAudit(t *testing.T) *AuditLog {
	t.Helper()
	a, err := OpenAudit(AuditConfig{Dir: t.TempDir(), Enabled: true, AnchorEvery: 5})
	if err != nil {
		t.Fatalf("OpenAudit: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}

// TestAuditChainSelfConsistent 正常追加后链自洽，seq 从 1 连续。
func TestAuditChainSelfConsistent(t *testing.T) {
	a := newTestAudit(t)
	for i := 0; i < 12; i++ {
		r := a.Append(AuditInput{
			Action: "terminate", Actor: "responder", Role: "responder",
			Target: fmt.Sprintf("pid=%d", 100+i), Result: "ok",
			Detail: map[string]any{"note": "已隔离"},
		})
		if !r.OK {
			t.Fatalf("第 %d 条 Append 失败：%+v", i+1, r)
		}
		if r.Record.Seq != i+1 {
			t.Fatalf("seq = %d，期望 %d", r.Record.Seq, i+1)
		}
		if len(r.Record.Hash) != 64 {
			t.Fatalf("hash 长度 = %d，期望 64", len(r.Record.Hash))
		}
		if i == 0 && r.Record.Prev != Genesis {
			t.Errorf("创世 prev = %q，期望全 0", r.Record.Prev)
		}
	}
	res := a.Verify()
	if !res.OK {
		t.Fatalf("链不自洽：%v", res.Problems)
	}
	if res.Records != 12 || res.LastSeq != 12 {
		t.Errorf("records=%d lastSeq=%d，期望 12/12", res.Records, res.LastSeq)
	}
	if !res.AnchorOK {
		t.Errorf("锚点未通过：%s", res.AnchorDetail)
	}
}

// TestAuditDetectsContentTamper 改写一条记录的内容 → hash 不符。
func TestAuditDetectsContentTamper(t *testing.T) {
	dir := t.TempDir()
	a, err := OpenAudit(AuditConfig{Dir: dir, Enabled: true, AnchorEvery: 100})
	if err != nil {
		t.Fatalf("OpenAudit: %v", err)
	}
	for i := 0; i < 4; i++ {
		a.Append(AuditInput{Action: "terminate", Actor: "responder", Target: fmt.Sprintf("pid=%d", i)})
	}
	a.Close()

	// 内部人把第 2 条的 target 从 pid=1 改成 pid=999（掩盖处置了谁）
	path := filepath.Join(dir, FileAuditLog)
	lines, err := readJSONL(path)
	if err != nil {
		t.Fatalf("readJSONL: %v", err)
	}
	var rec AuditRecord
	if err := json.Unmarshal(lines[1], &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	rec.Target = "pid=999"
	tampered, _ := json.Marshal(rec)
	lines[1] = tampered
	if err := rewriteLines(path, lines); err != nil {
		t.Fatalf("rewrite: %v", err)
	}

	a2, err := OpenAudit(AuditConfig{Dir: dir, Enabled: true, AnchorEvery: 100})
	if err != nil {
		t.Fatalf("OpenAudit#2: %v", err)
	}
	defer a2.Close()
	res := a2.Verify()
	if res.OK {
		t.Fatal("内容被改写却验过了：哈希链失效")
	}
	if !hasProblem(res.Problems, "hash 不符") {
		t.Errorf("问题列表没指出 hash 不符：%v", res.Problems)
	}
}

// TestAuditDetectsDeletedRecord 删掉中间一条 → seq 不连续 + prev 断链。
func TestAuditDetectsDeletedRecord(t *testing.T) {
	dir := t.TempDir()
	a, err := OpenAudit(AuditConfig{Dir: dir, Enabled: true, AnchorEvery: 100})
	if err != nil {
		t.Fatalf("OpenAudit: %v", err)
	}
	for i := 0; i < 5; i++ {
		a.Append(AuditInput{Action: "suspend", Actor: "responder", Target: fmt.Sprintf("pid=%d", i)})
	}
	a.Close()

	path := filepath.Join(dir, FileAuditLog)
	lines, err := readJSONL(path)
	if err != nil {
		t.Fatalf("readJSONL: %v", err)
	}
	// 删掉第 3 条（seq=3），掩盖一次处置
	lines = append(lines[:2], lines[3:]...)
	if err := rewriteLines(path, lines); err != nil {
		t.Fatalf("rewrite: %v", err)
	}

	a2, err := OpenAudit(AuditConfig{Dir: dir, Enabled: true, AnchorEvery: 100})
	if err != nil {
		t.Fatalf("OpenAudit#2: %v", err)
	}
	defer a2.Close()
	res := a2.Verify()
	if res.OK {
		t.Fatal("记录被删却验过了")
	}
	if !hasProblem(res.Problems, "seq 不连续") {
		t.Errorf("没指出 seq 不连续：%v", res.Problems)
	}
	if !hasProblem(res.Problems, "prev 断链") {
		t.Errorf("没指出 prev 断链：%v", res.Problems)
	}
}

// TestAuditDetectsTailTruncation 砍掉尾部 → 最后 seq 小于锚点 seq。
func TestAuditDetectsTailTruncation(t *testing.T) {
	dir := t.TempDir()
	// AnchorEvery=2：写 6 条会留下 seq=6 的锚点
	a, err := OpenAudit(AuditConfig{Dir: dir, Enabled: true, AnchorEvery: 2})
	if err != nil {
		t.Fatalf("OpenAudit: %v", err)
	}
	for i := 0; i < 6; i++ {
		a.Append(AuditInput{Action: "block", Actor: "responder", Target: fmt.Sprintf("ip=10.0.0.%d", i)})
	}
	a.Close()

	anc := readAnchorFile(t, dir)
	if anc.Seq == 0 {
		t.Fatal("没写出锚点")
	}

	// 砍掉最后两条（内部人删掉自己越权处置的记录）
	path := filepath.Join(dir, FileAuditLog)
	lines, err := readJSONL(path)
	if err != nil {
		t.Fatalf("readJSONL: %v", err)
	}
	if err := rewriteLines(path, lines[:len(lines)-2]); err != nil {
		t.Fatalf("rewrite: %v", err)
	}

	a2, err := OpenAudit(AuditConfig{Dir: dir, Enabled: true, AnchorEvery: 2})
	if err != nil {
		t.Fatalf("OpenAudit#2: %v", err)
	}
	defer a2.Close()
	res := a2.Verify()
	if res.OK {
		t.Fatal("尾部被截断却验过了")
	}
	if !hasProblem(res.Problems, "尾部被截断") {
		t.Errorf("没指出尾部截断：%v（锚点 seq=%d 链尾 seq=%d）", res.Problems, anc.Seq, res.LastSeq)
	}
}

// TestAuditDetectsWholeChainReplacement 整链重写成一条自洽的新链 → 锚点 HMAC 不过。
//
// 这是最狠的一种：新链自己 hash 全对、seq 连续，只有锚点能证明它是假的。
func TestAuditDetectsWholeChainReplacement(t *testing.T) {
	dir := t.TempDir()
	a, err := OpenAudit(AuditConfig{Dir: dir, Enabled: true, AnchorEvery: 3})
	if err != nil {
		t.Fatalf("OpenAudit: %v", err)
	}
	for i := 0; i < 6; i++ {
		a.Append(AuditInput{Action: "terminate", Actor: "responder", Target: fmt.Sprintf("pid=%d", i)})
	}
	a.Close()

	// 攻击者用另一个密钥重建一条「干净的」链
	other, err := OpenAudit(AuditConfig{Dir: t.TempDir(), Enabled: true, AnchorEvery: 3})
	if err != nil {
		t.Fatalf("OpenAudit(other): %v", err)
	}
	for i := 0; i < 6; i++ {
		other.Append(AuditInput{Action: "view", Actor: "admin", Target: "nothing"})
	}
	other.Close()

	// 把伪造链的日志搬到真目录，锚点保持原样（攻击者没拿到真密钥）
	from, err := os.ReadFile(filepath.Join(other.Dir(), FileAuditLog))
	if err != nil {
		t.Fatalf("read forged: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, FileAuditLog), from, 0o600); err != nil {
		t.Fatalf("write forged: %v", err)
	}

	a2, err := OpenAudit(AuditConfig{Dir: dir, Enabled: true, AnchorEvery: 3})
	if err != nil {
		t.Fatalf("OpenAudit#2: %v", err)
	}
	defer a2.Close()
	res := a2.Verify()
	if res.OK {
		t.Fatal("整链被替换却验过了：锚点没起作用")
	}
	if !hasProblem(res.Problems, "锚点") {
		t.Errorf("没指出锚点问题：%v", res.Problems)
	}
	if res.AnchorOK {
		t.Error("AnchorOK 应为 false")
	}
}

// TestAuditResumesAcrossRestart 重启后 seq/head 从文件尾部续上，链不断。
func TestAuditResumesAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	a, err := OpenAudit(AuditConfig{Dir: dir, Enabled: true, AnchorEvery: 100})
	if err != nil {
		t.Fatalf("OpenAudit: %v", err)
	}
	for i := 0; i < 5; i++ {
		a.Append(AuditInput{Action: "terminate", Actor: "responder", Target: "pid=1"})
	}
	headBefore := a.Head()
	seqBefore := a.Seq()
	a.Close()

	a2, err := OpenAudit(AuditConfig{Dir: dir, Enabled: true, AnchorEvery: 100})
	if err != nil {
		t.Fatalf("OpenAudit#2: %v", err)
	}
	defer a2.Close()
	if a2.Seq() != seqBefore {
		t.Errorf("重启后 seq = %d，期望 %d", a2.Seq(), seqBefore)
	}
	if a2.Head() != headBefore {
		t.Errorf("重启后 head 没续上")
	}
	r := a2.Append(AuditInput{Action: "resume", Actor: "responder", Target: "pid=1"})
	if !r.OK {
		t.Fatalf("重启后 Append 失败：%+v", r)
	}
	if r.Record.Seq != seqBefore+1 {
		t.Errorf("重启后 seq = %d，期望 %d（跳号或重号）", r.Record.Seq, seqBefore+1)
	}
	if r.Record.Prev != headBefore {
		t.Errorf("重启后 prev 没接上链头")
	}
	if res := a2.Verify(); !res.OK {
		t.Errorf("跨重启链不自洽：%v", res.Problems)
	}
}

// TestAuditDisabledIsNoop Enabled=false 时不写任何东西。
func TestAuditDisabledIsNoop(t *testing.T) {
	dir := t.TempDir()
	a, err := OpenAudit(AuditConfig{Dir: dir, Enabled: false})
	if err != nil {
		t.Fatalf("OpenAudit: %v", err)
	}
	defer a.Close()
	r := a.Append(AuditInput{Action: "terminate", Actor: "x"})
	if r.OK {
		t.Error("禁用时 Append 应返回 ok=false")
	}
	if r.Skipped == "" {
		t.Error("应给出 skipped 原因")
	}
	if _, err := os.Stat(filepath.Join(dir, FileAuditLog)); !os.IsNotExist(err) {
		t.Error("禁用时不该创建 audit.log")
	}
}

// TestAuditScrubsSecrets 敏感字段打码，其余原样保留。
func TestAuditScrubsSecrets(t *testing.T) {
	a := newTestAudit(t)
	a.Append(AuditInput{
		Action: "credscan", Actor: "analyst", Target: "host",
		Detail: map[string]any{
			"password":  "hunter2",
			"api_token": "tok_abc",
			"note":      "正常字段",
			"count":     3,
		},
	})
	lines, err := readJSONL(filepath.Join(a.Dir(), FileAuditLog))
	if err != nil {
		t.Fatalf("readJSONL: %v", err)
	}
	var rec AuditRecord
	if err := json.Unmarshal(lines[len(lines)-1], &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rec.Detail["password"] != Masked {
		t.Errorf("password 没打码：%v", rec.Detail["password"])
	}
	if rec.Detail["api_token"] != Masked {
		t.Errorf("api_token 没打码：%v", rec.Detail["api_token"])
	}
	if rec.Detail["note"] != "正常字段" {
		t.Errorf("正常字段被误打码：%v", rec.Detail["note"])
	}
	if fmt.Sprint(rec.Detail["count"]) != "3" {
		t.Errorf("非字符串字段被改：%v", rec.Detail["count"])
	}
	if res := a.Verify(); !res.OK {
		t.Errorf("打码后链不自洽：%v", res.Problems)
	}
}

// TestStoreLogActionNeverFabricatesActor actor 缺省落 system 并打标记，
// 绝不编造 "analyst"。
func TestStoreLogActionNeverFabricatesActor(t *testing.T) {
	s := newTestStore(t, Config{})

	// 具体身份：原样保留、不打标
	r1 := s.LogAction("alice", "terminate", "pid=1", "ok")
	if r1.Actor != "alice" || r1.ActorDefaulted || r1.ActorIsRole {
		t.Errorf("具体身份被改动：%+v", r1)
	}
	// 空 actor：system + 标记
	r2 := s.LogAction("", "auto:isolate", "pid=2", "ok")
	if r2.Actor != "system" {
		t.Errorf("空 actor 兜底 = %q，期望 system", r2.Actor)
	}
	if !r2.ActorDefaulted {
		t.Error("ActorDefaulted 未置位：事后无法区分「系统自动」与「研判员操作」")
	}
	// 明确不写死 analyst
	if r2.Actor == "analyst" {
		t.Fatal("空 actor 被编造成了 analyst（Python 版缺陷）")
	}
	// 空白也算缺省
	r3 := s.LogAction("   ", "x", "y", "z")
	if r3.Actor != "system" || !r3.ActorDefaulted {
		t.Errorf("空白 actor 未兜底：%+v", r3)
	}
	// 角色名：不改写（改写=伪造证据），但必须标出来
	r4 := s.LogAction("analyst", "suppress:add", "AEG-001", "ok")
	if r4.Actor != "analyst" {
		t.Errorf("角色名被改写成 %q（存储层不该替调用方编造身份）", r4.Actor)
	}
	if !r4.ActorIsRole {
		t.Error("角色名未标记 ActorIsRole：硬编码调用点将无法被检索")
	}
	if r4.ActorDefaulted {
		t.Error("角色名不是「缺省」，不该置 ActorDefaulted")
	}
	// 四个角色名都要识别
	for _, role := range Roles {
		if r := s.LogAction(role, "x", "y", "z"); !r.ActorIsRole {
			t.Errorf("角色 %q 没被识别为角色名", role)
		}
	}
	// 近似但不是角色名的（比如带后缀）不算
	if r := s.LogAction("analyst-2", "x", "y", "z"); r.ActorIsRole {
		t.Errorf("analyst-2 被误判成角色名：%+v", r)
	}
}

// TestStoreLogActionFeedsAuditChain Store 挂上审计链后，处置动作同时进链。
func TestStoreLogActionFeedsAuditChain(t *testing.T) {
	dir := t.TempDir()
	s, err := New(Config{DataDir: dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()
	a, err := OpenAudit(AuditConfig{Dir: filepath.Join(dir, dirAudit), Enabled: true, AnchorEvery: 2})
	if err != nil {
		t.Fatalf("OpenAudit: %v", err)
	}
	defer a.Close()
	s.AttachAudit(a)

	if s.Audit() == nil {
		t.Fatal("AttachAudit 没生效")
	}
	s.LogAction("responder", "terminate", "pid=4242", "ok")
	s.LogAction("admin", "block:generate", "10.0.0.9", "ok")
	s.LogAction("", "auto:isolate", "pid=7", "ok")

	if a.Seq() != 3 {
		t.Errorf("审计链 seq = %d，期望 3（LogAction 没进链）", a.Seq())
	}
	res := a.Verify()
	if !res.OK {
		t.Errorf("链不自洽：%v", res.Problems)
	}
	// 内存环里也要有
	if n := len(s.SnapshotActions(10)); n != 3 {
		t.Errorf("内存动作环 = %d，期望 3", n)
	}
	// 落盘
	lines, err := readJSONL(filepath.Join(dir, FileActions))
	if err != nil {
		t.Fatalf("readJSONL: %v", err)
	}
	if len(lines) != 3 {
		t.Errorf("actions.jsonl = %d 行，期望 3", len(lines))
	}
}

// TestAuditSegmentsAcrossSeal 分片封存后链仍连续可验（跨文件不重启）。
//
// 分片是最容易断链的地方：封存时如果重开文件把 head 弄丢，或锚点写在
// 封存前后错位，链会在文件边界处断开——而边界恰好是「想把日志按天归档」
// 的人最常动的地方。
func TestAuditSegmentsAcrossSeal(t *testing.T) {
	dir := t.TempDir()
	a, err := OpenAudit(AuditConfig{Dir: dir, Enabled: true, AnchorEvery: 3, MaxMB: 1})
	if err != nil {
		t.Fatalf("OpenAudit: %v", err)
	}
	// 手工把阈值调成几百字节，逼出 3 个分片
	a.maxBytes = 900
	defer a.Close()

	const n = 30
	for i := 0; i < n; i++ {
		r := a.Append(AuditInput{
			Action: "terminate", Actor: "responder", Role: "responder",
			Target: fmt.Sprintf("pid=%d", 1000+i), Result: "ok",
		})
		if !r.OK {
			t.Fatalf("第 %d 条 Append 失败：%+v", i+1, r)
		}
	}

	segs := a.segmentNames()
	if len(segs) < 2 {
		t.Fatalf("只出了 %d 个分片，测试没打到位", len(segs))
	}

	res := a.Verify()
	if !res.OK {
		t.Fatalf("跨分片链不自洽：%v（分片 %v）", res.Problems, segs)
	}
	// 记录总数 = 30 条业务记录 + 每次封存写的 audit:seal 记录
	if res.Records < n {
		t.Errorf("records = %d，少于业务记录数 %d（分片里的丢了）", res.Records, n)
	}
	if res.LastSeq != res.Records {
		t.Errorf("lastSeq = %d，records = %d：seq 有跳号", res.LastSeq, res.Records)
	}

	// 重启后仍要能验（resume 必须从当前文件尾部接上）
	a.Close()
	a2, err := OpenAudit(AuditConfig{Dir: dir, Enabled: true, AnchorEvery: 3})
	if err != nil {
		t.Fatalf("OpenAudit#2: %v", err)
	}
	defer a2.Close()
	if res2 := a2.Verify(); !res2.OK {
		t.Fatalf("重启后跨分片链不自洽：%v", res2.Problems)
	}
	if a2.Seq() != res.LastSeq {
		t.Errorf("重启后 seq = %d，期望 %d", a2.Seq(), res.LastSeq)
	}
}

// TestAuditSealRecordIsAudited 封存动作本身入链。
//
// 「谁把日志归档了」和「谁删了日志」在审计里必须可区分；
// 封存不留痕的话，删掉一个分片和正常归档看起来一样。
func TestAuditSealRecordIsAudited(t *testing.T) {
	dir := t.TempDir()
	a, err := OpenAudit(AuditConfig{Dir: dir, Enabled: true, AnchorEvery: 1000})
	if err != nil {
		t.Fatalf("OpenAudit: %v", err)
	}
	defer a.Close()
	a.maxBytes = 600
	for i := 0; i < 12; i++ {
		a.Append(AuditInput{Action: "block", Actor: "responder", Target: fmt.Sprintf("ip=10.0.0.%d", i)})
	}
	if len(a.segmentNames()) == 0 {
		t.Fatal("没发生封存")
	}

	found := false
	for _, seg := range a.segmentNames() {
		lines, err := readJSONL(filepath.Join(dir, seg))
		if err != nil {
			continue
		}
		for _, line := range lines {
			if strings.Contains(string(line), `"audit:seal"`) {
				found = true
			}
		}
	}
	if !found {
		t.Error("分片里没有 audit:seal 记录：归档动作不可追溯")
	}
}

// TestAuditTailAndStats 读取接口：倒序、过滤、统计。
func TestAuditTailAndStats(t *testing.T) {
	dir := t.TempDir()
	a, err := OpenAudit(AuditConfig{Dir: dir, Enabled: true, AnchorEvery: 2})
	if err != nil {
		t.Fatalf("OpenAudit: %v", err)
	}
	defer a.Close()
	for i := 0; i < 6; i++ {
		actor := "responder"
		if i%2 == 0 {
			actor = "admin"
		}
		a.Append(AuditInput{
			Action: "terminate", Actor: actor, Role: actor,
			Target: fmt.Sprintf("pid=%d", i), Result: "ok",
		})
	}
	a.Append(AuditInput{Action: "suppress:add", Actor: "analyst", Role: "analyst", Target: "AEG-001"})

	all := a.Tail(100, "", "")
	if len(all) != 7 {
		t.Fatalf("Tail 全量 = %d 条，期望 7", len(all))
	}
	// 倒序：seq 递减
	for i := 1; i < len(all); i++ {
		if all[i-1].Seq <= all[i].Seq {
			t.Errorf("Tail 不是倒序：%d 在 %d 前", all[i-1].Seq, all[i].Seq)
			break
		}
	}
	if n := len(a.Tail(3, "", "")); n != 3 {
		t.Errorf("Tail(3) = %d 条", n)
	}
	if n := len(a.Tail(100, "suppress", "")); n != 1 {
		t.Errorf("按 action 过滤 = %d 条，期望 1", n)
	}
	if n := len(a.Tail(100, "", "admin")); n != 3 {
		t.Errorf("按 actor 过滤 = %d 条，期望 3", n)
	}
	if n := len(a.Tail(100, "no-such-action", "")); n != 0 {
		t.Errorf("不存在的 action 过滤出 %d 条", n)
	}

	st := a.Stats()
	if !st.Enabled {
		t.Error("Stats.Enabled 应为 true")
	}
	if st.Records != 7 {
		t.Errorf("Stats.Records = %d，期望 7", st.Records)
	}
	if st.Head == "" || st.Head != a.Head() {
		t.Errorf("Stats.Head 与 Head() 不一致")
	}
	if st.Bytes <= 0 {
		t.Errorf("Stats.Bytes = %d，期望 > 0", st.Bytes)
	}
	if st.AnchorSeq == 0 {
		t.Error("Stats 没读到锚点")
	}
	if st.Segments < 1 {
		t.Errorf("Stats.Segments = %d，期望 >= 1", st.Segments)
	}
}

// TestAuditNestedDetailVerifies 嵌套 detail 写入后链仍能验过。
//
// 规范化器对 int/float 的处理不同（Python 写 "3"，Go 默认写 "3"、但 float64(3)
// 会被 encoding/json 写成 "3" 而非 "3.0"）。写路径与校验路径必须用同一个
// 规范化器，否则自己写的链自己验不过——这条测试钉住那个闭环。
func TestAuditNestedDetailVerifies(t *testing.T) {
	a := newTestAudit(t)
	a.Append(AuditInput{
		Action: "credscan", Actor: "alice", Target: "host-1",
		Detail: map[string]any{
			"count":  3,   // int
			"ratio":  0.5, // float
			"whole":  4.0, // 整数值的 float → Python 写 4.0
			"ok":     true,
			"nested": map[string]any{"deep": 1, "list": []any{1, 2.0, "三"}},
		},
	})
	res := a.Verify()
	if !res.OK {
		t.Fatalf("带嵌套 detail 的链验不过：%v", res.Problems)
	}
	// 写出去的字面量必须是 Python 口径
	lines, err := readJSONL(filepath.Join(a.Dir(), FileAuditLog))
	if err != nil {
		t.Fatalf("readJSONL: %v", err)
	}
	body := string(lines[len(lines)-1])
	if !strings.Contains(body, `"whole":4.0`) {
		t.Errorf("浮点整数值没写成 4.0：%s", body)
	}
	if !strings.Contains(body, `"count":3`) {
		t.Errorf("整数没写成 3：%s", body)
	}
	if !strings.Contains(body, `"三"`) {
		t.Errorf("中文被转义了：%s", body)
	}
}

// ---------------- 辅助 ----------------

func hasProblem(problems []string, frag string) bool {
	for _, p := range problems {
		if strings.Contains(p, frag) {
			return true
		}
	}
	return false
}

// rewriteLines 覆盖写回 JSONL 行（模拟篡改）。
func rewriteLines(path string, lines [][]byte) error {
	var sb strings.Builder
	for _, l := range lines {
		sb.Write(l)
		sb.WriteByte('\n')
	}
	return os.WriteFile(path, []byte(sb.String()), 0o600)
}

func readAnchorFile(t *testing.T, dir string) Anchor {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, FileAnchor))
	if err != nil {
		t.Fatalf("读锚点: %v", err)
	}
	var a Anchor
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatalf("解析锚点: %v", err)
	}
	return a
}
