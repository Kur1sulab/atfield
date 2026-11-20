//go:build darwin

package collector

// baseline_darwin_test.go —— macOS 专有：真机跑一遍 + 判定口径的机器无关部分。
//
// 两类用例：
//  1) TestBaselineDarwinRealMachine：直接跑 platformBaselineFacts（真的执行
//     csrutil / spctl / fdesetup / socketfilterfw / defaults / lsof / sqlite3），
//     断言「17 项全有结论、status 合法、非 pass 项必须带 evidence」。
//     断言用**结构**而不是具体数值：写死「本机 SIP pass」的测试换台 Mac 就红。
//  2) TestBaselineDarwinDriftOnRealFacts：拿真机事实跑两轮，第二轮只把
//     「监听端口」注入一个 445，验证差分链路在真实数据上确实会产出事件
//     ——单元测试用的是合成事实，这一条补上「真实数据 + 真差分」的证据。
//
// 跑法：go test ./internal/collector -run TestBaselineDarwin -v
// （会真的执行系统命令，约 200ms；不需要 root）

import (
	"context"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

// TestBaselineDarwinRealMachine 真机采集 + 判定。
func TestBaselineDarwinRealMachine(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := platformProbeBaseline(); err != nil {
		t.Skipf("本机不可用: %v", err)
	}
	facts, err := platformBaselineFacts(ctx)
	if err != nil {
		t.Fatalf("真机采集失败: %v", err)
	}
	results := judgeBaseline(facts, float64(time.Now().UnixNano())/1e9)

	if len(results) != 17 {
		t.Fatalf("真机应产出 17 项，得到 %d", len(results))
	}
	valid := map[string]bool{baselinePass: true, baselineWarn: true, baselineFail: true, baselineUnknown: true}
	for _, r := range results {
		if !valid[r.Status] {
			t.Fatalf("%s 的 status 非法: %q", r.ID, r.Status)
		}
		if r.Status != baselinePass && strings.TrimSpace(r.Evidence) == "" {
			t.Errorf("%s 判为 %s 却没写 evidence —— 控制台无法解释为什么", r.ID, r.Status)
		}
		if r.Status == baselinePass && r.Severity != "info" {
			t.Errorf("%s pass 但 severity=%q", r.ID, r.Severity)
		}
		if r.TS <= 0 {
			t.Errorf("%s 缺 ts", r.ID)
		}
	}

	// 真机上这三样必须读得到（读不到说明采集层坏了，不是「机器有问题」）：
	// 端口表、进程表、SIP 状态。它们同时是 SSH_EXPOSED / SHARING / TIMESYNC 的前提。
	if !facts.PortsKnown {
		t.Error("真机读不到连接表（lsof 失败？）—— 端口类两项会退化成 unknown")
	}
	if !facts.TimeSyncKnown {
		t.Error("真机读不到进程表 —— TIMESYNC 会退化成 unknown")
	}
	if facts.SIP.Missing {
		t.Error("SIP 应可读（csrutil 是系统自带）")
	}

	// 打印一份摘要，方便与 Python 版 eye-diff（也是 --once 之外的人工核对入口）。
	type row struct {
		ID       string `json:"id"`
		Status   string `json:"status"`
		Severity string `json:"severity"`
		Evidence string `json:"evidence"`
	}
	out := make([]row, 0, len(results))
	for _, r := range results {
		out = append(out, row{r.ID, r.Status, r.Severity, truncRunes(r.Evidence, 120)})
	}
	b, _ := json.MarshalIndent(map[string]any{
		"checks": len(results), "counts": countStatuses(results), "results": out,
	}, "", "  ")
	t.Logf("真机基线结果:\n%s", b)
}

// TestBaselineDarwinDriftOnRealFacts 真实数据 + 真差分：第二轮人为放开 445，
// 必须产出恰好一条 SHARING 事件（说明采集→判定→差分→事件这条链是通的）。
func TestBaselineDarwinDriftOnRealFacts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	real, err := platformBaselineFacts(ctx)
	if err != nil {
		t.Fatalf("真机采集失败: %v", err)
	}

	round := 1
	b := newBaselineForTest(func(context.Context) (baselineFacts, error) {
		f := real
		if round == 2 {
			// 只动端口集合的副本：模拟「本机突然开始监听 445」。
			// 其余 16 项的输入保持真机原值，所以这测的是真差分，不是假数据。
			ports := make(map[int]bool, len(real.Ports)+1)
			for k, v := range real.Ports {
				ports[k] = v
			}
			ports[445] = true
			f.Ports = ports
		}
		return f, nil
	})

	first, err := b.Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// 首轮只出「已经不合格/需关注」的审计事件，不该有 pass 项凑热闹。
	for _, ev := range first {
		if ev.Subject["to"] == baselinePass {
			t.Fatalf("首轮不该给 pass 项发事件: %+v", ev.Subject)
		}
	}
	firstIDs := make([]string, 0, len(first))
	for _, ev := range first {
		firstIDs = append(firstIDs, ev.Path)
	}
	sort.Strings(firstIDs)

	round = 2
	second, err := b.Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 1 {
		t.Fatalf("第二轮应只有 1 条事件（445 放开），得到 %d 条: %v", len(second), second)
	}
	ev := second[0]
	if ev.Path != "SHARING" || ev.Subject["to"] != baselineFail {
		t.Fatalf("事件不对: path=%s subject=%+v", ev.Path, ev.Subject)
	}
	if !strings.Contains(ev.Subject["evidence"].(string), "445/SMB") {
		t.Fatalf("evidence 没带上 445/SMB: %q", ev.Subject["evidence"])
	}
	if _, ok := ev.Subject["baselined"]; ok {
		t.Fatal("第二轮事件不该带 baselined 键")
	}

	t.Logf("首轮审计事件 %d 条 %v；第二轮漂移 1 条 → %s(%s→%s)",
		len(first), firstIDs, ev.Path, ev.Subject["from"], ev.Subject["to"])

	// 真机上不该出现「端口表为空」这种退化：空集合会让 SSH/SHARING 都 pass。
	if len(real.Ports) == 0 {
		t.Skip("本机没有可见的监听端口（lsof 权限过窄），跳过端口断言")
	}
	if _, err := os.Stat("/usr/sbin/lsof"); err != nil {
		t.Log("lsof 不在 /usr/sbin，端口视图可能不完整")
	}
}
