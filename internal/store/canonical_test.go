package store

// canonical_test.go —— 与 Python 版的哈希/序列化对拍。
//
// 这里的期望值全部由 Python 侧真实跑出来（atfield/audit.py 的 _canonical +
// _sha256），不是手算的。对拍的意义：迁移期两版共用一个 data_dir，
// Python 写的 audit.log 必须能被 Go 验过，反之亦然；差一个字节就是全链报错。
//
// 复现方法（Python 侧）：
//
//	body = json.dumps(rec_without_hash, ensure_ascii=False, sort_keys=True,
//	                  separators=(",", ":"))
//	hash = sha256(prev + body).hexdigest()

import (
	"fmt"
	"testing"
)

// TestCanonicalMatchesPython 规范化 JSON 逐字节对齐。
func TestCanonicalMatchesPython(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
	}{
		{
			name: "键排序 + 中文不转义",
			in:   map[string]any{"b": 1, "a": "中文", "c": true},
			want: `{"a":"中文","b":1,"c":true}`,
		},
		{
			name: "HTML 字符不转义",
			in:   map[string]any{"t": "pid=4242 <bash> & \"x\""},
			want: `{"t":"pid=4242 <bash> & \"x\""}`,
		},
		{
			name: "整数值的 float 必须带 .0",
			in:   map[string]any{"v": 1700000000.0},
			want: `{"v":1700000000.0}`,
		},
		{
			name: "小 float",
			in:   map[string]any{"v": 0.5},
			want: `{"v":0.5}`,
		},
		{
			name: "1e15 用定点",
			in:   map[string]any{"v": 1e15},
			want: `{"v":1000000000000000.0}`,
		},
		{
			name: "1e16 转科学计数",
			in:   map[string]any{"v": 1e16},
			want: `{"v":1e+16}`,
		},
		{
			name: "1e-05 转科学计数",
			in:   map[string]any{"v": 0.00001},
			want: `{"v":1e-05}`,
		},
		{
			name: "0.0001 用定点",
			in:   map[string]any{"v": 0.0001},
			want: `{"v":0.0001}`,
		},
		{
			name: "控制字符转义",
			in:   map[string]any{"v": "a\nb\tc"},
			want: `{"v":"a\nb\tc"}`,
		},
		{
			name: "嵌套结构",
			in: map[string]any{
				"z": []any{1, "二", false},
				"a": map[string]any{"y": 2, "x": 1},
			},
			want: `{"a":{"x":1,"y":2},"z":[1,"二",false]}`,
		},
		{
			name: "int 与 float 保持类型差异",
			in:   map[string]any{"i": 3, "f": 3.0},
			want: `{"f":3.0,"i":3}`,
		},
	}
	for _, c := range cases {
		got, err := canonicalJSON(c.in)
		if err != nil {
			t.Errorf("%s: canonicalJSON 报错 %v", c.name, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s:\n  got  %s\n  want %s", c.name, got, c.want)
		}
	}
}

// TestHashMatchesPython 两条记录的真实 hash（Python 侧算出）。
func TestHashMatchesPython(t *testing.T) {
	rec := AuditRecord{
		Seq: 1, TS: 1700000000.125, Time: "2023-11-14 22:13:20",
		Action: "terminate", Actor: "responder", Role: "responder",
		Target: "pid=4242 <bash> 中文", Result: "ok",
		Detail: map[string]any{"note": "已隔离", "n": 3, "flag": true, "ratio": 0.5},
		Prev:   Genesis,
	}
	got := hashRecord(Genesis, rec)
	const want = "cfac9279dc112d74090d47986f19e5bfa0921c07f094937577267e0d2d4fe56a"
	if got != want {
		t.Fatalf("genesis 记录 hash 与 Python 不一致：\n  got  %s\n  want %s", got, want)
	}

	rec2 := rec
	rec2.Seq = 2
	rec2.Prev = got
	rec2.TS = 1700000000.0
	const want2 = "dab1cceda9891a3dacc2376b522d3cf88dc14d1ae3f12dc1eb05e71a8fa4b8ac"
	if got2 := hashRecord(rec2.Prev, rec2); got2 != want2 {
		t.Fatalf("第二条 hash 与 Python 不一致：\n  got  %s\n  want %s", got2, want2)
	}
}

// TestVerifyExternalChain 端到端：Go 写的链重开后仍验得过（跨进程同一份文件）。
func TestVerifyExternalChain(t *testing.T) {
	dir := t.TempDir()

	a, err := OpenAudit(AuditConfig{Dir: dir, Enabled: true, AnchorEvery: 100})
	if err != nil {
		t.Fatalf("OpenAudit: %v", err)
	}
	for i := 0; i < 3; i++ {
		r := a.Append(AuditInput{
			Action: "terminate", Actor: "responder", Role: "responder",
			Target: fmt.Sprintf("pid=%d", i), Result: "ok",
			Detail: map[string]any{"n": i, "ratio": 0.5},
		})
		if !r.OK {
			t.Fatalf("Append: %+v", r)
		}
	}
	a.Close()

	// 重开再验：覆盖「跨进程读同一份文件」
	a2, err := OpenAudit(AuditConfig{Dir: dir, Enabled: true, AnchorEvery: 100})
	if err != nil {
		t.Fatalf("OpenAudit#2: %v", err)
	}
	defer a2.Close()
	res := a2.Verify()
	if !res.OK {
		t.Fatalf("自写链验不过：%v", res.Problems)
	}
	if res.Records != 3 {
		t.Errorf("records = %d，期望 3", res.Records)
	}
}

// TestScrubRecursesNested 嵌套 detail 里的敏感字段也要打码。
func TestScrubRecursesNested(t *testing.T) {
	out := scrub(map[string]any{
		"outer": map[string]any{"password": "hunter2", "ok": "visible"},
		"list":  []any{map[string]any{"token": "tok"}},
		"pass":  "top",
	})
	outer, ok := out["outer"].(map[string]any)
	if !ok {
		t.Fatalf("嵌套 map 丢了：%v", out["outer"])
	}
	if outer["password"] != Masked {
		t.Errorf("嵌套 password 没打码：%v", outer["password"])
	}
	if outer["ok"] != "visible" {
		t.Errorf("嵌套正常字段被改：%v", outer["ok"])
	}
	if out["pass"] != Masked {
		t.Errorf("顶层 pass 没打码：%v", out["pass"])
	}
}
