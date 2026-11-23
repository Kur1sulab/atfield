// Package webui 把心之壁的前端静态资源用 go:embed 打进二进制，并提供
// http.Handler 供 API 层挂载。
//
// 为什么内嵌而不是读目录：心之壁是「装到目标机上就能跑」的单文件产品
// （macOS/Linux/Windows 三平台单二进制分发）。外部 web/ 目录一旦缺失，
// 控制台就白屏，而运维最怕的正是「装完打不开」。embed 把前端变成二进制的一部分：
// 复制一个可执行文件过去，UI 必然在。
//
// 静态服务语义逐条对齐 Python 版 server.py 的 _static()：
//   - "/" 与 "" → index.html
//   - "api/" 前缀 → 404 {"ok":false,"error":"unknown api"}（API 路由漏到这里说明路径不存在）
//   - 其余不存在 → 404 {"ok":false,"error":"not found"}
//   - text/* 与 application/javascript、application/json 补 "; charset=utf-8"
//   - 路径穿越一律 404（embed.FS 天然拒绝 ".."，这里再挡一层）
package webui

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
)

// assets 前端资源。用 all: 前缀是为了把 index.html 之外的点文件也带上——
// 目前没有点文件，但将来加 .well-known 之类不会被静默忽略。
//
//go:embed all:assets
var assets embed.FS

// Dir 资源在 embed 里的子目录名。
const Dir = "assets"

// Files 返回 assets 子树的只读文件系统（不含 "assets" 这一层前缀）。
func Files() fs.FS {
	sub, err := fs.Sub(assets, Dir)
	if err != nil {
		// 只可能在 embed 声明与目录名不一致时发生，属于编译期错误，
		// 这里退化成空 FS 而不是 panic：服务能起来，UI 404，问题可见。
		return emptyFS{}
	}
	return sub
}

// IndexHTML 返回 index.html 内容（SSE/健康检查里想嵌版本号时用）。
func IndexHTML() []byte {
	b, err := assets.ReadFile(Dir + "/index.html")
	if err != nil {
		return nil
	}
	return b
}

// List 返回内嵌资源清单（按路径排序）。测试与 /api/version 的排障信息用。
func List() []string {
	sub := Files()
	var out []string
	_ = fs.WalkDir(sub, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // 遍历失败就少列一个，不影响服务
		}
		out = append(out, p)
		return nil
	})
	sort.Strings(out)
	return out
}

// Digest 全部资源的 sha256 前 12 位。用于「前端换了没换」的快速判定
// （发布校验、缓存对比），不依赖文件时间戳。
func Digest() string {
	h := sha256.New()
	for _, p := range List() {
		b, err := assets.ReadFile(Dir + "/" + p)
		if err != nil {
			continue
		}
		h.Write([]byte(p))
		h.Write([]byte{0})
		h.Write(b)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}

// Handler 返回静态资源 handler。挂到 "/" 上即可（API 路由要更具体，
// Go 1.22+ 的 ServeMux 会优先匹配更长的模式）。
func Handler() http.Handler { return &handler{fsys: Files()} }

type handler struct{ fsys fs.FS }

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// Python: rel = "index.html" if path in ("/", "") else path.lstrip("/")
	rel := "index.html"
	if p := strings.TrimPrefix(r.URL.Path, "/"); p != "" {
		rel = p
	}
	if strings.HasPrefix(rel, "api/") || rel == "api" {
		writeErr(w, http.StatusNotFound, "unknown api")
		return
	}
	// 路径归一化后再挡一次穿越：embed.FS 本身会拒绝 ".."，但归一化能保证
	// "/a/../index.html" 这类写法不会被当成合法别名。
	clean := path.Clean("/" + rel)
	if strings.Contains(clean, "..") || clean == "/" {
		clean = "/index.html"
	}
	name := strings.TrimPrefix(clean, "/")
	body, err := fs.ReadFile(h.fsys, name)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	w.Header().Set("Content-Type", contentType(name))
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
}

// contentType 与 Python 版同口径：text/* 与 js/json 补 charset。
func contentType(name string) string {
	ct := mime.TypeByExtension(path.Ext(name))
	if ct == "" {
		ct = "application/octet-stream"
	}
	// mime.TypeByExtension 在部分系统上返回带 charset 的形式，先剥掉再统一加。
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	if strings.HasPrefix(ct, "text/") || ct == "application/javascript" || ct == "application/json" {
		ct += "; charset=utf-8"
	}
	return ct
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	body := []byte(`{"ok":false,"error":"` + msg + `"}`)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

// emptyFS 兜底：embed 声明异常时服务仍能启动（所有资源 404）。
type emptyFS struct{}

func (emptyFS) Open(string) (fs.File, error) { return nil, fs.ErrNotExist }
