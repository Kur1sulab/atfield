package webui

// webui_test.go —— 内嵌资源可读性与静态服务语义测试。
//
// 重点不是「能不能返回 200」，而是三件容易在迁移中悄悄坏掉的事：
//  1. embed 真的把前端打进去了（清单齐全、非空、没有把 .bak-wall 带进来）
//  2. "/" 落到 index.html、未知路径 404、api/ 前缀 404 的文案与 Python 一致
//  3. 路径穿越被挡住（".." 不能读到 MIGRATION.md 之类仓库文件）

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// wantFiles 前端发布清单。少一个都会让控制台某块功能白屏，所以逐个钉住。
var wantFiles = []string{
	"aegis-artex.css",
	"app.js",
	"apple-touch-icon.png",
	"artex.css",
	"favicon-32.png",
	"favicon.svg",
	"index.html",
	"style.css",
}

func TestEmbedHasAllAssets(t *testing.T) {
	got := map[string]bool{}
	for _, p := range List() {
		got[p] = true
	}
	for _, f := range wantFiles {
		if !got[f] {
			t.Fatalf("embed 缺少 %s（现有：%v）", f, List())
		}
	}
	for _, f := range wantFiles {
		b, err := Files().Open(f)
		if err != nil {
			t.Fatalf("打开 %s 失败: %v", f, err)
		}
		st, err := b.Stat()
		if err != nil {
			t.Fatalf("stat %s 失败: %v", f, err)
		}
		if st.Size() == 0 {
			t.Fatalf("%s 是空文件", f)
		}
		_ = b.Close()
	}
}

func TestEmbedExcludesBackups(t *testing.T) {
	for _, p := range List() {
		if strings.Contains(p, ".bak") {
			t.Fatalf("备份文件被打进 embed 了: %s", p)
		}
	}
}

func TestIndexHTMLReadable(t *testing.T) {
	b := IndexHTML()
	if len(b) == 0 {
		t.Fatal("index.html 为空")
	}
	s := string(b)
	for _, want := range []string{"<html", "app.js", "style.css"} {
		if !strings.Contains(s, want) {
			t.Fatalf("index.html 缺少 %q", want)
		}
	}
}

func TestDigestStable(t *testing.T) {
	a, b := Digest(), Digest()
	if a != b {
		t.Fatalf("Digest 不稳定: %s vs %s", a, b)
	}
	if len(a) != 12 {
		t.Fatalf("Digest 长度=%d, 期望 12", len(a))
	}
}

func TestServeIndexAtRoot(t *testing.T) {
	for _, p := range []string{"/", ""} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.URL.Path = p // 覆盖 "" 这个分支：Python 侧 path in ("/", "") 都当首页
		Handler().ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("GET %q 状态=%d", p, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
			t.Fatalf("GET %q Content-Type=%q", p, ct)
		}
		if !strings.Contains(rec.Body.String(), "<html") {
			t.Fatalf("GET %q 返回的不是首页", p)
		}
		if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatal("缺少 nosniff 头")
		}
		if rec.Header().Get("Cache-Control") != "no-store, no-cache, must-revalidate" {
			t.Fatalf("Cache-Control=%q", rec.Header().Get("Cache-Control"))
		}
	}
}

func TestServeAssetsContentType(t *testing.T) {
	cases := map[string]string{
		"/app.js":               "text/javascript; charset=utf-8",
		"/style.css":            "text/css; charset=utf-8",
		"/favicon.svg":          "image/svg+xml",
		"/favicon-32.png":       "image/png",
		"/apple-touch-icon.png": "image/png",
	}
	for p, wantPrefix := range cases {
		rec := httptest.NewRecorder()
		Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != 200 {
			t.Fatalf("GET %s 状态=%d", p, rec.Code)
		}
		ct := rec.Header().Get("Content-Type")
		// js 的 MIME 在不同 Go 版本/系统上可能是 text/javascript 或
		// application/javascript，两者都合法；这里只要求「带 charset 且不是 octet-stream」。
		if !strings.HasPrefix(ct, strings.Split(wantPrefix, ";")[0]) {
			t.Fatalf("GET %s Content-Type=%q, 期望前缀 %q", p, ct, wantPrefix)
		}
		if strings.Contains(ct, "text/") && !strings.Contains(ct, "charset=utf-8") {
			t.Fatalf("GET %s 文本类型缺 charset: %q", p, ct)
		}
		if rec.Body.Len() == 0 {
			t.Fatalf("GET %s 返回空 body", p)
		}
	}
}

func TestServeUnknown404(t *testing.T) {
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/nope.js", nil))
	if rec.Code != 404 {
		t.Fatalf("状态=%d, 期望 404", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("404 body 不是 JSON: %s", rec.Body.String())
	}
	if body["ok"] != false || body["error"] != "not found" {
		t.Fatalf("404 body=%v, 期望 {ok:false,error:\"not found\"}", body)
	}
}

func TestServeAPIPrefix404(t *testing.T) {
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/does-not-exist", nil))
	if rec.Code != 404 {
		t.Fatalf("状态=%d, 期望 404", rec.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["error"] != "unknown api" {
		t.Fatalf("error=%v, 期望 unknown api", body["error"])
	}
}

func TestTraversalBlocked(t *testing.T) {
	for _, p := range []string{
		"/../MIGRATION.md",
		"/../../etc/passwd",
		"/assets/../../go.mod",
		"/..%2fgo.mod",
	} {
		rec := httptest.NewRecorder()
		Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != 404 {
			t.Fatalf("GET %s 状态=%d, 期望 404（路径穿越必须挡住）", p, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "module github.com") {
			t.Fatalf("GET %s 读到了仓库文件", p)
		}
	}
}

func TestHeadAndMethodGuard(t *testing.T) {
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodHead, "/", nil))
	if rec.Code != 200 || rec.Body.Len() != 0 {
		t.Fatalf("HEAD 语义不对: code=%d bodylen=%d", rec.Code, rec.Body.Len())
	}
	rec = httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST 静态路径状态=%d, 期望 405", rec.Code)
	}
}
