// Package api 是心之壁的 HTTP JSON API 层。
//
// 设计目标只有一个：**契约与 Python 版逐字段一致**。前端 app.js 是同一份，
// 字段名漂一个字母，控制台就白屏或者数字变 —— 这种 bug 在迁移里最难查
// （HTTP 200、JSON 合法、就是没数据）。因此这里的规矩是：
//
//  1. 响应字段名一律照抄 Python 版 server.py 的返回结构，不新增、不改名。
//     唯一例外是 /api/version 的 "python" 键——Go 版没有 Python 版本号，
//     用 "go" 取代并在端点对齐表里写明（宁可显式不同，也不填假值）。
//  2. 端点路径、查询参数名、默认值照抄（limit 默认 200、audit 默认 100…）。
//  3. 错误响应形状照抄：{"ok":false,"error":"..."}；401 追加 login_required，
//     403 追加 need/role。
//
// 与 Python 版的差异只有「加法」，且都在文档里标注：
//   - /api/events 支持 offset（分页）；不带 offset 时行为与 Python 完全一致。
//   - /api/event?eid= 事件详情（Python 无此端点，字段沿用事件元素结构）。
//   - /api/firewall* 接封禁执行层（Python 走 root helper 的 unix socket）。
package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Kur1sulab/atfield/go/internal/detect"
	"github.com/Kur1sulab/atfield/go/internal/enforcer"
	"github.com/Kur1sulab/atfield/go/internal/store"
)

// Product 产品名（与 Python 版 __product__ 一致）。
const Product = "心之壁"

// DefaultVersion 未注入版本号时的兜底。
const DefaultVersion = "0.1.0-go"

// Session 一次已认证会话。字段对应 Python 版 auth.session() 的返回。
type Session struct {
	User       string  `json:"user"`
	Role       string  `json:"role"`
	ExpiresAt  float64 `json:"expires_at"`
	MustChange bool    `json:"must_change"`
}

// Authorizer 鉴权后端。auth 包迁完后由父代理注入；nil 表示「开放模式」。
//
// 为什么接口放在这里而不是直接依赖 auth 包：API 层要能独立测试，
// 也要能在 auth 还没迁完时先把控制台跑起来（开放模式 + 明确文档告警）。
type Authorizer interface {
	// Session 按 token 取会话，无效返回 nil。
	Session(token string) *Session
	// Caps 角色能力清单（/api/auth/me 的 caps 字段）。
	Caps(role string) []string
	// Can 判断角色是否具备某能力。
	Can(role, capability string) bool
	// Enabled 鉴权是否启用。
	Enabled() bool
}

// Config 构造 API 服务所需依赖。除 Store 外都可缺省。
type Config struct {
	// Store 存储层（必填）。
	Store *store.Store
	// Audit 审计链；nil 时用 Store.Audit()（可能也是 nil，此时审计端点返回空）。
	Audit *store.AuditLog
	// Engine 检测引擎；nil 时 /api/rules 返回空目录。
	Engine *detect.Engine
	// Web 静态资源 handler（internal/webui.Handler()）；nil 时非 API 路径一律 404。
	Web http.Handler
	// Enforcer 封禁执行层；nil 时 /api/firewall 返回 available=false。
	Enforcer enforcer.Backend
	// Auth 鉴权；nil = 开放模式（仅建议在回环地址上这样跑）。
	Auth Authorizer
	// Version 产品版本；空用 DefaultVersion。
	Version string
	// Host / User 展示用；空则取 os.Hostname() / 环境变量。
	Host string
	User string
	// StartedAt 进程启动时间（unix 秒）；0 用构造时刻。
	StartedAt float64
	// Now 注入时钟（测试固定时间用）。
	Now func() time.Time
}

// Server HTTP API 服务。持有全部依赖，线程安全（只读依赖 + 存储层自带锁）。
type Server struct {
	cfg Config
	mux *http.ServeMux
	t0  float64
}

// New 构造 API 服务并注册全部路由。
//
// Store 必填：没有存储的 API 只能返回空壳，那比启动失败更难排查。
func New(cfg Config) *Server {
	if cfg.Store == nil {
		panic("api: Config.Store 必填（用 store.New 构造，测试可传 MemoryOnly）")
	}
	if cfg.Version == "" {
		cfg.Version = DefaultVersion
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Host == "" {
		if h, err := os.Hostname(); err == nil {
			cfg.Host = h
		}
	}
	if cfg.User == "" {
		cfg.User = firstNonEmpty(os.Getenv("USER"), os.Getenv("USERNAME"), "unknown")
	}
	s := &Server{cfg: cfg, mux: http.NewServeMux()}
	s.t0 = cfg.StartedAt
	if s.t0 == 0 {
		s.t0 = float64(cfg.Now().UnixNano()) / 1e9
	}
	s.routes()
	return s
}

// routes 注册路由。用 Go 1.22+ 的方法+路径模式：未知方法自动 405，
// 更长的模式优先匹配，所以 "/" 上的静态资源不会抢走 /api/*。
func (s *Server) routes() {
	m := s.mux

	// 健康 / 版本
	m.HandleFunc("GET /api/ping", s.handlePing)
	m.HandleFunc("GET /api/version", s.handleVersion)

	// 鉴权现状（auth 未接入时返回开放模式说明）
	m.HandleFunc("GET /api/auth/me", s.handleAuthMe)

	// 主体数据
	m.HandleFunc("GET /api/overview", s.handleOverview)
	m.HandleFunc("GET /api/events", s.handleEvents)
	m.HandleFunc("GET /api/event", s.handleEventDetail)
	m.HandleFunc("GET /api/findings", s.handleFindings)
	m.HandleFunc("GET /api/incidents", s.handleIncidents)
	m.HandleFunc("GET /api/actions", s.handleActions)
	m.HandleFunc("GET /api/tickets", s.handleTickets)
	m.HandleFunc("GET /api/timeline", s.handleTimeline)
	m.HandleFunc("GET /api/rules", s.handleRules)
	m.HandleFunc("GET /api/assets", s.handleAssets)
	m.HandleFunc("GET /api/governance", s.handleGovernance)

	// 审计链
	m.HandleFunc("GET /api/audit", s.handleAudit)
	m.HandleFunc("GET /api/audit/verify", s.handleAuditVerify)
	m.HandleFunc("POST /api/audit/verify", s.handleAuditVerify)

	// 实时推送
	m.HandleFunc("GET /api/stream", s.handleStream)

	// 封禁执行层
	m.HandleFunc("GET /api/firewall", s.handleFirewallStatus)
	m.HandleFunc("POST /api/firewall/block", s.handleFirewallBlock)
	m.HandleFunc("POST /api/firewall/unblock", s.handleFirewallUnblock)
	m.HandleFunc("POST /api/firewall/flush", s.handleFirewallFlush)

	// 其余一切：静态资源（/api/ 前缀在 webui 里 404 unknown api）
	web := s.cfg.Web
	if web == nil {
		web = http.HandlerFunc(s.fallback404)
	}
	m.Handle("GET /", web)
}

// Handler 返回可直接 ListenAndServe 的 handler。
func (s *Server) Handler() http.Handler { return s.mux }

// Mux 暴露底层 ServeMux（父代理要额外挂 /metrics 之类时用）。
func (s *Server) Mux() *http.ServeMux { return s.mux }

// fallback404 没有静态资源时的兜底：与 Python _static 的文案一致。
func (s *Server) fallback404(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		writeErr(w, http.StatusNotFound, "unknown api")
		return
	}
	writeErr(w, http.StatusNotFound, "not found")
}

// ---------------- 响应 ----------------

// writeJSON 输出 JSON。头与 Python 版 _send 逐项一致：no-store + nosniff。
func writeJSON(w http.ResponseWriter, code int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		// 序列化失败不能返回 200 + 半个对象：降级成 500 错误信封。
		body = []byte(`{"ok":false,"error":"encode failed"}`)
		code = http.StatusInternalServerError
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

// writeErr 错误信封：{"ok":false,"error":msg}（与 Python _err 同形）。
func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"ok": false, "error": msg})
}

// ---------------- 鉴权 ----------------

// token 取会话 token：Authorization: Bearer 优先，其次 atfield_session cookie。
// 与 Python 版 _token 同序。
func (s *Server) token(r *http.Request) string {
	if auth := r.Header.Get("Authorization"); auth != "" {
		if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
			if tok := strings.TrimSpace(auth[7:]); tok != "" {
				return tok
			}
		}
	}
	if c, err := r.Cookie("atfield_session"); err == nil {
		return c.Value
	}
	return ""
}

// guard 校验能力。不通过时已写好响应，调用方直接 return。
// Auth 未注入（开放模式）时一律放行，并返回一个 system/admin 的虚拟会话，
// 让写操作仍能在审计里留下 actor。
func (s *Server) guard(w http.ResponseWriter, r *http.Request, capability string) *Session {
	if s.cfg.Auth == nil {
		return &Session{User: "system", Role: "admin"}
	}
	sess := s.cfg.Auth.Session(s.token(r))
	if sess == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"ok": false, "error": "未登录", "login_required": true,
		})
		return nil
	}
	if capability != "" && !s.cfg.Auth.Can(sess.Role, capability) {
		if a := s.audit(); a != nil {
			a.Append(store.AuditInput{
				Action: "auth.deny", Actor: sess.User, Role: sess.Role,
				Target: r.URL.Path, Result: "deny",
				Detail: map[string]any{"need": capability},
			})
		}
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok": false, "error": "权限不足", "need": capability, "role": sess.Role,
		})
		return nil
	}
	return sess
}

// audit 取审计链（Config.Audit 优先，其次 Store 上挂的）。
func (s *Server) audit() *store.AuditLog {
	if s.cfg.Audit != nil {
		return s.cfg.Audit
	}
	if s.cfg.Store == nil {
		return nil
	}
	return s.cfg.Store.Audit()
}

// ---------------- 查询参数 ----------------

// qStr 取查询参数首个值，缺省返回 def（对应 Python _q）。
func qStr(q url.Values, key, def string) string {
	if v := q.Get(key); v != "" {
		return v
	}
	return def
}

// qInt 取整型查询参数。非法值退回 def（Python 会抛 ValueError → 500，
// Go 侧选择「退回默认」：查询参数写错不该把面板打挂）。
// 负数一律归零：limit=-1 在 Python 里等于「取到末尾」，在 Go 里语义不同，
// 这里明确成 0（返回空列表）而不是静默返回全量。
func qInt(q url.Values, key string, def int) int {
	raw := q.Get(key)
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	if n < 0 {
		return 0
	}
	return n
}

// ts 当前时间（unix 秒，浮点，与 Python time.time() 同精度）。
func (s *Server) ts() float64 { return float64(s.cfg.Now().UnixNano()) / 1e9 }

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// goVersion 供 /api/version 的 "go" 字段。
func goVersion() string { return runtime.Version() }

func platformOS() string   { return runtime.GOOS }
func platformArch() string { return runtime.GOARCH }
