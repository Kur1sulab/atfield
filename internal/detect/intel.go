package detect

// 情报闸门接口与定级函数。
//
// Python 侧在 atfield/intel.py（547 行）里：match_ip 做 CIDR 最长前缀 +
// allowlist 前置，命中条目按置信度 × 衰减算分，score_to_severity 再把分档成
// 等级。intel 包本身尚未移植到 Go，这里只固定**规则层依赖的那一面契约**
// （接口 + 评分/定级纯函数），实现由 intel 包提供，保证 AEG-043 的
// severity_fn 语义可以独立验证。

// IntelHit 情报闸门的一次命中。
type IntelHit struct {
	Value      string  `json:"value"`
	Kind       string  `json:"kind,omitempty"`
	Source     string  `json:"source"`
	Score      float64 `json:"score"`
	Severity   string  `json:"severity"`
	Confidence string  `json:"confidence,omitempty"`
	Lifecycle  string  `json:"lifecycle,omitempty"`
}

// Intel 规则层需要的情报能力。
type Intel interface {
	// MatchIP 按 CIDR 最长前缀匹配，allowlist（保留/共享基础设施）已在实现内前置。
	MatchIP(ip string) *IntelHit
	// MatchDomain 精确/后缀匹配域名情报。
	MatchDomain(domain string) *IntelHit
	// AllowedIP 保留/共享基础设施判定（RFC1918、回环、CGNAT、Cloudflare…）。
	AllowedIP(ip string) bool
	// AllowedDomain 同上，域名侧。
	AllowedDomain(domain string) bool
}

// CONF_MAP 置信档 → 基础分（intel.py:53）。
const (
	ConfLow    = 0.15
	ConfMedium = 0.50
	ConfHigh   = 0.85

	// CriticalAt / HighAt 分档阈值（intel.py:57-58）。
	CriticalAt = 0.7
	HighAt     = 0.4
)

// ConfidenceScore 置信档转基础分，未知档按 medium（与 Python 缺省一致）。
func ConfidenceScore(conf string) float64 {
	switch conf {
	case "low":
		return ConfLow
	case "medium":
		return ConfMedium
	case "high":
		return ConfHigh
	}
	return ConfMedium
}

// ScoreToSeverity 分数分档（intel.py:71-77）：≥0.7 critical，≥0.4 high，其余 medium。
// 注意没有 low/空档——闸门永远给得出一个等级，只有 score=0（衰减到期）由
// HitCounts/HitSeverity 判为「不再计分」。
func ScoreToSeverity(score float64) string {
	switch {
	case score >= CriticalAt:
		return "critical"
	case score >= HighAt:
		return "high"
	}
	return "medium"
}

// HitCounts 命中是否仍然计分（衰减到期 score=0 视为不再计分）。
func HitCounts(h *IntelHit) bool {
	return h != nil && h.Score > 0
}

// HitSeverity 命中的最终等级：不计分退回 default；否则条目 severity 优先，
// 缺失/非法再按分数换算。
func HitSeverity(h *IntelHit, def string) string {
	if !HitCounts(h) {
		return def
	}
	if validSeverity(h.Severity) {
		return h.Severity
	}
	return ScoreToSeverity(h.Score)
}
