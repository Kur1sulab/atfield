package api_test

// example_test.go —— 接线范式（可直接复制到 cmd/atfieldd/main.go）。
//
// 放在 api_test 外部包里是刻意的：它只能看到 api 的公开 API，
// 因此这段代码就是父代理真正要写的东西，编不过就说明公开接口不好用。
// Example 带 Output 会在 go test 里真跑一遍（起服务 → 打一个 /api/ping），
// 所以「接线说明」不是文档，是可执行的验收。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"github.com/Kur1sulab/atfield/internal/api"
	"github.com/Kur1sulab/atfield/internal/enforcer"
	"github.com/Kur1sulab/atfield/internal/store"
	"github.com/Kur1sulab/atfield/internal/webui"
)

func Example_wiring() {
	// 1) 存储层（生产用 DataDir，测试/演示用 MemoryOnly）
	st, err := store.New(store.Config{MemoryOnly: true})
	if err != nil {
		panic(err)
	}
	defer func() { _ = st.Close() }()

	// 2) 审计链（可选；nil 时 /api/audit 返回空壳而不是报错）
	//
	// 示例里用临时目录，避免在开发机上写出真审计链；生产接线时
	// auditCfg.Dir 留空即可（默认 <DataDir>/audit，与 Python 版同路径）。
	tmp, err := os.MkdirTemp("", "atfield-example")
	if err != nil {
		panic(err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	auditCfg := store.DefaultAuditConfig()
	auditCfg.Dir = tmp
	audit, err := store.OpenAudit(auditCfg)
	if err == nil {
		defer func() { _ = audit.Close() }()
		st.AttachAudit(audit)
	}

	// 3) API 服务：把四块拼起来
	srv := api.New(api.Config{
		Store:    st,
		Audit:    audit,           // 可省
		Engine:   nil,             // detect.Engine，可省
		Web:      webui.Handler(), // 前端静态资源（embed）
		Enforcer: enforcer.New(enforcer.Options{DryRun: true}),
		Version:  "v1.0.0-go",
	})

	// 4) 起服务（生产换成 http.Server{Addr:"127.0.0.1:8866"}）
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/ping")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	var obj map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&obj)
	fmt.Println(obj["ok"], obj["version"])

	// Output:
	// true v1.0.0-go
}

// Example_static 前端资源直接从二进制里出，不需要外部 web/ 目录。
func Example_static() {
	srv := httptest.NewServer(webui.Handler())
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(srv.URL + "/")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	fmt.Println(resp.StatusCode, resp.Header.Get("Content-Type"))

	// Output:
	// 200 text/html; charset=utf-8
}
