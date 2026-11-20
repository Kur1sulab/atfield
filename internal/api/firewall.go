package api

// firewall.go —— 封禁执行层的 HTTP 面。
//
// 契约照抄 Python 版 _firewall：
//   - 路径 /api/firewall/{block,unblock,flush}
//   - 请求体字段 ip / reason
//   - 返回码：ok=200、失败=400、skipped=409（「未启用」不是错误，是状态不对）
//   - 每个动作都进审计链（拦截是能影响业务的动作，必须留痕）
//
// 两处刻意的 Go 侧加强（都不改响应形状）：
//  1. CSRF 头 X-Requested-With: atfield 必须在写操作上出现（Python 也有，缺了 403）。
//  2. 能力校验：block/unblock=respond、flush=admin（Python POST_CAP 同）。
//
// attach/detach（改 /etc/pf.conf）**不实现**：enforcer 的设计前提就是
// 「只操作自己的 anchor/table，不动系统规则」。把 anchor 挂进主规则集是安装步骤，
// 由运维显式执行；API 不提供这条路径，也就不存在「一个 POST 就把主机 DNS 改坏」的风险。

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/Kur1sulab/atfield/internal/enforcer"
	"github.com/Kur1sulab/atfield/internal/store"
)

// csrfHeader 写操作必须带的头（与前端 API() 封装一致）。
const csrfHeader = "X-Requested-With"

// csrfValue CSRF 头的期望值。
const csrfValue = "atfield"

// maxBody 请求体上限。封禁请求只有一个 IP + 一句原因，8KB 足够，
// 不设上限等于把内存交给对端。
const maxBody = 8 << 10

// firewallReq 封禁请求体。字段名与 Python 一致：ip / reason。
type firewallReq struct {
	IP     string `json:"ip"`
	Reason string `json:"reason"`
}

// handleFirewallStatus 现状。外层键与 Python firewall.status() 对齐：
// available / reason / blocked / count / backend / anchor / caps / dry_run。
func (s *Server) handleFirewallStatus(w http.ResponseWriter, r *http.Request) {
	if s.guard(w, r, "read") == nil {
		return
	}
	if s.cfg.Enforcer == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"available": false,
			"reason":    "封禁执行层未接入（enforcer 未注入）",
			"blocked":   []string{},
			"count":     0,
		})
		return
	}
	st := s.cfg.Enforcer.Status(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"available": st.Available,
		"reason":    st.Reason,
		"blocked":   keysOf(st.IPS),
		"ips":       st.IPS,
		"count":     st.Count,
		"rules":     st.Rules,
		"attached":  st.Attached,
		"anchor":    st.Anchor,
		"backend":   st.Backend,
		"dry_run":   st.DryRun,
		"caps":      st.Caps,
	})
}

// handleFirewallBlock 封禁一个地址。
func (s *Server) handleFirewallBlock(w http.ResponseWriter, r *http.Request) {
	body, ok := s.firewallPre(w, r, "respond")
	if !ok {
		return
	}
	tgt, err := enforcer.ParseTarget(body.IP)
	if err != nil {
		// 目标校验失败是调用方的问题：400 + 原因，不进审计（没发生动作）。
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.cfg.Enforcer == nil {
		writeErr(w, http.StatusBadRequest, "封禁执行层未接入（enforcer 未注入）")
		return
	}
	sess := s.guardSession(r)
	actor := "system"
	if sess != nil {
		actor = sess.User
	}
	res := s.cfg.Enforcer.Block(r.Context(), tgt, body.Reason, actor)
	s.auditFirewall(r, "firewall.block", tgt.Key(), res)
	writeJSON(w, firewallCode(res), res)
}

// handleFirewallUnblock 解封。
func (s *Server) handleFirewallUnblock(w http.ResponseWriter, r *http.Request) {
	body, ok := s.firewallPre(w, r, "respond")
	if !ok {
		return
	}
	tgt, err := enforcer.ParseTarget(body.IP)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.cfg.Enforcer == nil {
		writeErr(w, http.StatusBadRequest, "封禁执行层未接入（enforcer 未注入）")
		return
	}
	res := s.cfg.Enforcer.Unblock(r.Context(), tgt)
	s.auditFirewall(r, "firewall.unblock", tgt.Key(), res)
	writeJSON(w, firewallCode(res), res)
}

// handleFirewallFlush 清空自己的全部阻断。
func (s *Server) handleFirewallFlush(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.firewallPre(w, r, "admin"); !ok {
		return
	}
	if s.cfg.Enforcer == nil {
		writeErr(w, http.StatusBadRequest, "封禁执行层未接入（enforcer 未注入）")
		return
	}
	res := s.cfg.Enforcer.Flush(r.Context())
	s.auditFirewall(r, "firewall.flush", "all", res)
	writeJSON(w, firewallCode(res), res)
}

// firewallPre 写操作前置检查：能力校验 → CSRF 头 → 解析请求体。
// 任一不通过都已写好响应（含具体错误），返回 ok=false。
func (s *Server) firewallPre(w http.ResponseWriter, r *http.Request, capability string) (firewallReq, bool) {
	if s.guard(w, r, capability) == nil {
		return firewallReq{}, false
	}
	if strings.TrimSpace(r.Header.Get(csrfHeader)) != csrfValue {
		writeErr(w, http.StatusForbidden, "缺少 X-Requested-With 头（CSRF 防护）")
		return firewallReq{}, false
	}
	// flush 无请求体：空体也要能过。
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "读取请求体失败")
		return firewallReq{}, false
	}
	var body firewallReq
	if len(strings.TrimSpace(string(raw))) > 0 {
		if err := json.Unmarshal(raw, &body); err != nil {
			writeErr(w, http.StatusBadRequest, "请求体不是合法 JSON")
			return firewallReq{}, false
		}
	}
	return body, true
}

// guardSession 取当前会话（不做校验，只用于审计 actor）。
func (s *Server) guardSession(r *http.Request) *Session {
	if s.cfg.Auth == nil {
		return &Session{User: "system", Role: "admin"}
	}
	return s.cfg.Auth.Session(s.token(r))
}

// firewallCode 结果码：ok=200、skipped=409、其余失败=400（Python 同）。
func firewallCode(res enforcer.Result) int {
	if res.Skipped {
		return http.StatusConflict
	}
	if res.OK {
		return http.StatusOK
	}
	return http.StatusBadRequest
}

// auditFirewall 把一次防火墙动作写进审计链。失败绝不影响业务返回（Python 同口径）。
func (s *Server) auditFirewall(r *http.Request, action, target string, res enforcer.Result) {
	a := s.audit()
	if a == nil {
		return
	}
	actor, role := "system", "system"
	if sess := s.guardSession(r); sess != nil {
		actor, role = sess.User, sess.Role
	}
	result := "ok"
	if !res.OK {
		result = "error"
	}
	if res.Skipped {
		result = "skip"
	}
	detail := map[string]any{
		"backend": res.Backend, "dry_run": res.DryRun,
		"changed": res.Changed, "detail": res.Detail,
		"commands": len(res.Commands),
	}
	if res.Err != "" {
		detail["error"] = res.Err
	}
	a.Append(store.AuditInput{
		Action: action, Actor: actor, Role: role,
		Target: target, Result: result, Detail: detail,
	})
}

// keysOf 把 map 的键排成切片（稳定输出，便于前端 diff）。
func keysOf(m map[string]enforcer.Entry) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
