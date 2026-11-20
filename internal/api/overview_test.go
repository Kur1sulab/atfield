package api

// overview_test.go —— 量化算法的对拍测试。
//
// 这些数字是给人做决策的，所以不能只测「有没有这个键」，必须测**数值**：
// 同一个输入，Python scoring.py 算出来是多少，这里就得是多少。
// 期望值都是按 Python 公式手算的（注释里带算式），不是抄一遍 Go 的输出。

import (
	"math"
	"testing"

	"github.com/Kur1sulab/atfield/internal/model"
)

func mkFinding(sev string, ts float64) *model.Finding {
	return &model.Finding{ID: "f", RuleID: "r", Name: "n", Severity: sev, TS: ts}
}

// TestThreatSingleCritical 单条新鲜 critical：
//
//	raw = 18 * 0.5^0 = 18
//	risk = 100*(1-e^(-18/45)) = 100*(1-e^-0.4) = 32.968 → 33.0
func TestThreatSingleCritical(t *testing.T) {
	now := 1700000000.0
	th := computeThreat([]*model.Finding{mkFinding("critical", now)}, nil, now)
	got := asFloat(th["risk"])
	if math.Abs(got-33.0) > 0.1 {
		t.Fatalf("risk=%.2f, 期望 33.0", got)
	}
	if th["level"] != "中" {
		t.Fatalf("level=%v, 期望 中（25≤risk<50）", th["level"])
	}
	if asInt(th["recent_1h"]) != 1 {
		t.Fatalf("recent_1h=%v", th["recent_1h"])
	}
}

// TestThreatFourCritical 四条新鲜 critical：
//
//	raw = 72 → risk = 100*(1-e^-1.6) = 79.81 → 79.8，level=严重（≥75）
func TestThreatFourCritical(t *testing.T) {
	now := 1700000000.0
	var fs []*model.Finding
	for i := 0; i < 4; i++ {
		fs = append(fs, mkFinding("critical", now))
	}
	th := computeThreat(fs, nil, now)
	got := asFloat(th["risk"])
	if math.Abs(got-79.8) > 0.1 {
		t.Fatalf("risk=%.2f, 期望 79.8", got)
	}
	if th["level"] != "严重" {
		t.Fatalf("level=%v", th["level"])
	}
	bySev := th["by_severity"].(map[string]int)
	if bySev["critical"] != 4 {
		t.Fatalf("by_severity[critical]=%d", bySev["critical"])
	}
}

// TestThreatDecay 半衰期 6 小时：6 小时前的 critical 只值一半。
//
//	raw = 18*0.5 = 9 → risk = 100*(1-e^-0.2) = 18.13 → 18.1
func TestThreatDecay(t *testing.T) {
	now := 1700000000.0
	th := computeThreat([]*model.Finding{mkFinding("critical", now-6*3600)}, nil, now)
	got := asFloat(th["risk"])
	if math.Abs(got-18.1) > 0.1 {
		t.Fatalf("risk=%.2f, 期望 18.1", got)
	}
	if asInt(th["recent_1h"]) != 0 {
		t.Fatalf("陈旧告警不该算进 recent_1h: %v", th["recent_1h"])
	}
}

// TestThreatEmpty 空集：risk=0、level=平静、by_severity 五个档位都在。
func TestThreatEmpty(t *testing.T) {
	th := computeThreat(nil, nil, 1700000000)
	if asFloat(th["risk"]) != 0 || th["level"] != "平静" {
		t.Fatalf("空集 threat=%v", th)
	}
	bySev := th["by_severity"].(map[string]int)
	if len(bySev) != 5 {
		t.Fatalf("by_severity 应含 5 档: %v", bySev)
	}
}

// TestThreatIncidentContribution 一条攻击链按 Python 缺省 score=50 计入：
//
//	raw += (50/10)*1.6 = 8 → risk = 100*(1-e^-8/45) = 16.31 → 16.3
func TestThreatIncidentContribution(t *testing.T) {
	now := 1700000000.0
	th := computeThreat(nil, []model.Incident{{ID: "i", TS: now}}, now)
	got := asFloat(th["risk"])
	if math.Abs(got-16.3) > 0.1 {
		t.Fatalf("risk=%.2f, 期望 16.3", got)
	}
	if asInt(th["incidents_total"]) != 1 {
		t.Fatalf("incidents_total=%v", th["incidents_total"])
	}
}

func TestThreatColorThresholds(t *testing.T) {
	cases := map[float64]string{
		0: "calm", 7.9: "calm", 8: "low", 24.9: "low",
		25: "medium", 49.9: "medium", 50: "high", 74.9: "high",
		75: "critical", 100: "critical",
	}
	for risk, want := range cases {
		if got := threatColor(risk); got != want {
			t.Fatalf("threatColor(%v)=%q, 期望 %q", risk, got, want)
		}
	}
}

func TestGradeThresholds(t *testing.T) {
	cases := map[float64]string{
		100: "优秀", 92: "优秀", 91.9: "良好", 80: "良好",
		79.9: "一般", 65: "一般", 64.9: "薄弱", 45: "薄弱", 44.9: "危险", 0: "危险",
	}
	for v, want := range cases {
		if got := grade(v); got != want {
			t.Fatalf("grade(%v)=%q, 期望 %q", v, got, want)
		}
	}
}

// TestPostureWeighted 维度分是加权平均、总分再按维度权重平均。
//
//	data 维度：fail(18)*3 + pass(100)*1 = 154 / 4 = 38.5
//	network  维度：pass(100)*2 = 200/2 = 100
//	其余三个维度无检查项 → 70 分、权重 1
//	总分 = (38.5*4 + 100*2 + 70*3) / (4+2+3) = (154+200+210)/9 = 62.67 → 62.7
func TestPostureWeighted(t *testing.T) {
	baseline := map[string]any{
		"results": []any{
			map[string]any{"name": "磁盘加密", "category": "数据保护", "status": "fail", "weight": 3},
			map[string]any{"name": "文件权限", "category": "数据保护", "status": "pass", "weight": 1},
			map[string]any{"name": "防火墙", "category": "网络防线", "status": "pass", "weight": 2},
		},
		"counts": map[string]any{"fail": 1, "pass": 2},
	}
	p := computePosture(baseline)
	if got := asFloat(p["health"]); math.Abs(got-62.7) > 0.05 {
		t.Fatalf("health=%.2f, 期望 62.7", got)
	}
	if p["grade"] != "薄弱" {
		t.Fatalf("grade=%v, 期望 薄弱（45≤62.7<65）", p["grade"])
	}
	dims := p["dimensions"].([]map[string]any)
	if len(dims) != 5 {
		t.Fatalf("维度数=%d", len(dims))
	}
	// data 维度按权重算：38.5 分、2 项检查、1 项不合格
	for _, d := range dims {
		if d["key"] != "data" {
			continue
		}
		if got := asFloat(d["score"]); math.Abs(got-38.5) > 0.05 {
			t.Fatalf("data.score=%.2f, 期望 38.5", got)
		}
		if asInt(d["checks"]) != 2 || asInt(d["failed"]) != 1 {
			t.Fatalf("data 计数不对: %v", d)
		}
		if d["top_issue"] != "磁盘加密" {
			t.Fatalf("data.top_issue=%v", d["top_issue"])
		}
	}
}

// TestPostureUnknownCategory 未识别 category 归到 detection（Python CATEGORY_MAP 缺省）。
func TestPostureUnknownCategory(t *testing.T) {
	p := computePosture(map[string]any{
		"results": []any{
			map[string]any{"name": "某检查", "category": "没见过的分类", "status": "fail", "weight": 1},
		},
	})
	for _, d := range p["dimensions"].([]map[string]any) {
		if d["key"] == "detection" {
			if asInt(d["failed"]) != 1 {
				t.Fatalf("未知分类应归入 detection: %v", d)
			}
			return
		}
	}
	t.Fatal("找不到 detection 维度")
}

// TestPostureEmptyBaseline 无基线数据：健康度 70、评级「一般」、无 top_issue。
func TestPostureEmptyBaseline(t *testing.T) {
	p := computePosture(map[string]any{})
	if asFloat(p["health"]) != 70 {
		t.Fatalf("health=%v, 期望 70", p["health"])
	}
	if p["grade"] != "一般" {
		t.Fatalf("grade=%v", p["grade"])
	}
	for _, d := range p["dimensions"].([]map[string]any) {
		if d["top_issue"] != "" {
			t.Fatalf("空基线不该有 top_issue: %v", d)
		}
	}
}

func TestSeverityCN(t *testing.T) {
	cases := map[string]string{
		"info": "信息", "low": "低危", "medium": "中危", "high": "高危",
		"critical": "严重", "weird": "weird",
	}
	for in, want := range cases {
		if got := severityCN(in); got != want {
			t.Fatalf("severityCN(%q)=%q, 期望 %q", in, got, want)
		}
	}
}
