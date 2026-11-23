package collector

// fileless.go —— 无文件执行检测：判定只有这一份，取数按平台。
//
// 「无文件」不是一个动作，而是三类互相独立的证据：
//
//	命令行证据   解释器把 payload 编码进参数（powershell -enc / python -c exec(b64decode)）
//	内存证据     可执行内存没有磁盘后备（memfd、匿名 RWX、映像已删除）
//	签名证据     可执行文件在临时目录且没有有效签名
//
// 三类之间**不做与运算**：任一类单独成立就足以看一眼。把三类串成一条链
// （必须「编码 + 匿名内存 + 未签名」）会漏掉最典型的场景——PowerShell
// 编码命令跑的是签名过的 powershell.exe，内存里也不会留下可疑映射，
// 但那条命令行本身就是攻击。
//
// 平台能力（这就是「拿不到就降级」的实话）：
//
//	darwin  命令行（ps）+ 已删除映像（os.Stat/ lsof +L1）+ 匿名可执行段（vmmap，需同 uid）
//	        实测：非 root 时 vmmap 打不开其他用户的进程
//	        （"cannot examine process ... you do not have appropriate privileges"）。
//	        另实测：macOS 27.3 arm64 上**无签名进程无法建 PROT_EXEC 匿名映射**
//	        （python mmap(PROT_READ|PROT_WRITE|PROT_EXEC) → PermissionError 13），
//	        所以 darwin 的匿名可执行段基本只出现在带 MAP_JIT 的 JIT 引擎里——
//	        这就是为什么必须有 JIT 白名单，否则 Chrome/Node 会被天天报。
//	linux   命令行 + /proc/pid/maps（匿名可执行段、memfd）+ /proc/pid/exe（"(deleted)"）
//	        同 uid 才能读别人的 maps；非 root 只看得到自己的进程 + 全局 cmdline。
//	windows PowerShell 编码命令行 + 临时目录 + Authenticode 签名状态。
//	        匿名可执行内存需要读另一个进程的 VAD，本版不做（要 NtQueryVirtualMemory），
//	        所以在 windows 上 MemProbed 恒为 false，判定不会假装看过内存。
//
// 与 process 采集器的分工：process.go 已经在盯 cmdline-b64（≥120 字符）、
// exe-deleted、pipe-to-shell。本采集器不重复那三条，只补它看不见的：
// PowerShell 编码命令的**参数解析**（-enc 与 -Encoding 的区别是这里的核心用例）、
// IEX 下载执行、memfd、匿名可执行内存、临时目录未签名执行。

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/Kur1sulab/atfield/go/internal/model"
)

// 事件类型。
const (
	EventFilelessPSEncoded = "fileless.ps_encoded"
	EventFilelessPSIEX     = "fileless.ps_iex_download"
	EventFilelessB64Pipe   = "fileless.b64_pipe_exec"
	EventFilelessInline    = "fileless.inline_decode"
	EventFilelessMemfd     = "fileless.memfd_exec"
	EventFilelessAnonExec  = "fileless.anon_exec"
	EventFilelessImageGone = "fileless.exe_deleted"
	EventFilelessUnsigned  = "fileless.unsigned_temp"
)

// 判定理由 slug（对拍时逐字比）。
const (
	flReasonPSEncoded = "ps-encoded"
	flReasonPSIEX     = "ps-iex-download"
	flReasonB64Pipe   = "b64-pipe-exec"
	flReasonInline    = "inline-decode"
	flReasonMemfd     = "memfd"
	flReasonAnonExec  = "anon-exec"
	flReasonImageGone = "image-deleted"
	flReasonUnsigned  = "unsigned-temp"
)

// flAnonExecFloor 匿名可执行段的判定下限。
//
// 256 KiB 的来历：Cobalt Strike 的反射加载器与最常见的 shellcode loader
// 都在几百 KB 量级，低于这个数的可执行段通常只有 JIT 的 trampoline 页。
// 但**大小不是判据**——真正决定命中的是「谁在跑」（见 flJITEngines）：
// 实测本机 node 的 V8 JIT cage 是 256 MiB（vmmap: rwx/rwx SM=PRV, 无路径），
// 只看大小会把每一个 Node/Chrome 进程都报成无文件攻击。
const flAnonExecFloor = 256 * 1024

// flJITEngines 合法使用可执行匿名内存的运行时（基名小写，含 .exe 变体由调用方去后缀）。
//
// 这不是「白名单免检」：它们仍然会被命令行规则检查（PowerShell 编码命令、
// base64 管道），只是不因「有可执行匿名内存」这一条被报——那条对它们是常态。
var flJITEngines = map[string]bool{
	"node": true, "nodejs": true, "deno": true, "bun": true,
	"chrome": true, "google chrome": true, "chromium": true, "msedge": true,
	"microsoft edge": true, "firefox": true, "safari": true, "webkit": true,
	"java": true, "javaw": true, "javaws": true, "dotnet": true, "mono": true,
	"electron": true, "code helper": true, "code helper (renderer)": true,
	"hermes": true, "jsc": true, "qjs": true,
}

// filelessFact 一条进程级的无文件证据（平台取数填，判定只读）。
type filelessFact struct {
	Source  string  // ps | procfs | cim
	TS      float64 //
	PID     int     //
	PPID    int     //
	HasPID  bool    //
	User    string  //
	Process string  // 进程名（原生）
	Exe     string  // 可执行文件路径（可能是 "(deleted)" 结尾）
	Cmdline string  // 完整命令行

	// 内存证据。MemProbed=false 表示「这一轮没看成内存」（权限/平台不支持），
	// 判定不得把「没看成」当成「没有」。
	MemProbed      bool
	AnonExecBytes  int64
	AnonExecRegion int
	Memfd          []string
	ImageDeleted   bool

	// 签名/落地证据。
	ExeInTemp  bool
	Signed     bool
	HasSigInfo bool
}

// filelessHit 一条命中的判定。
type filelessHit struct {
	Slug     string
	Kind     string
	Severity string
	Note     string
}

// flExeBase 取进程基名（小写、去 .exe）。
func flExeBase(f filelessFact) string {
	name := strings.ToLower(baseNameAnyOS(firstNonEmpty(f.Exe, f.Process)))
	return strings.TrimSuffix(name, ".exe")
}

// isJITEngine 该进程是否属于「可执行匿名内存是常态」的运行时。
func isJITEngine(f filelessFact) bool {
	return flJITEngines[flExeBase(f)]
}

// 注：临时目录判定复用 persistence 各平台的 isTempPath（_darwin/_linux/_windows
// 各一份，口径与「自启项落在临时目录」完全一致）。这里不另立一套，
// 否则同一个 /private/var/tmp 会在两个采集器里得出不同结论。

// isASCII 是否纯 ASCII。
// 用途：非 ASCII 路径不做「磁盘上还在不在」的判定（NFD/NFC 规范化差异会导致误报）。
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// isPowerShell 判断是不是 PowerShell（含 pwsh / powershell.exe）。
func isPowerShell(f filelessFact) bool {
	return flExeBase(f) == "powershell" || flExeBase(f) == "pwsh"
}

// judgeFileless 纯函数判定：输入一条进程事实，输出命中的规则（顺序固定）。
func judgeFileless(f filelessFact) []filelessHit {
	var hits []filelessHit
	low := strings.ToLower(f.Cmdline)

	// 1) PowerShell 编码命令：-enc / -EncodedCommand 后面跟长 base64
	if isPowerShell(f) {
		if blob, ok := psEncodedArg(f.Cmdline); ok && len(blob) >= 40 {
			hits = append(hits, filelessHit{
				Slug: flReasonPSEncoded, Kind: EventFilelessPSEncoded, Severity: "high",
				Note: "PowerShell 编码命令（-EncodedCommand，base64 长度 " + itoa(len(blob)) + "）",
			})
		}
		// 2) 下载即执行：IEX/Invoke-Expression 与 DownloadString/Invoke-WebRequest 同现
		if (strings.Contains(low, "iex") || strings.Contains(low, "invoke-expression")) &&
			(strings.Contains(low, "downloadstring") || strings.Contains(low, "invoke-webrequest") ||
				strings.Contains(low, "downloadfile") || strings.Contains(low, "net.webclient")) {
			hits = append(hits, filelessHit{
				Slug: flReasonPSIEX, Kind: EventFilelessPSIEX, Severity: "high",
				Note: "PowerShell 下载即执行（IEX + 远程取件）",
			})
		}
	}

	// 3) base64 解码后直接喂给 shell：`base64 -d <<<... | sh`
	if (isInterpreter(f.Exe) || isInterpreter(f.Process)) && strings.Contains(low, "base64") &&
		(strings.Contains(low, " -d") || strings.Contains(low, " --decode") || strings.Contains(low, " -D ")) &&
		hasPipeToShell(low) {
		hits = append(hits, filelessHit{
			Slug: flReasonB64Pipe, Kind: EventFilelessB64Pipe, Severity: "high",
			Note: "base64 解码后管道进 shell",
		})
	}

	// 4) 解释器内联解码执行：python -c "exec(base64.b64decode(...))"
	if isInterpreter(f.Exe) && (strings.Contains(f.Cmdline, " -c") || strings.Contains(f.Cmdline, " -e")) &&
		(strings.Contains(low, "b64decode") || strings.Contains(low, "frombase64string") ||
			strings.Contains(low, "decode_base64") || strings.Contains(low, "atob(")) &&
		(strings.Contains(low, "exec") || strings.Contains(low, "eval") || strings.Contains(low, "system(")) {
		hits = append(hits, filelessHit{
			Slug: flReasonInline, Kind: EventFilelessInline, Severity: "high",
			Note: "解释器内联 base64 解码后执行",
		})
	}

	// 5) memfd：文件系统上没有名字的可执行文件（Linux 无文件落地首选）
	if len(f.Memfd) > 0 {
		hits = append(hits, filelessHit{
			Slug: flReasonMemfd, Kind: EventFilelessMemfd, Severity: "high",
			Note: "memfd 可执行映射（" + clip(f.Memfd[0], 80) + "）",
		})
	}

	// 6) 映像已从磁盘删除：进程还在跑，文件没了
	if f.ImageDeleted || hasDeletedExe(f.Exe) {
		hits = append(hits, filelessHit{
			Slug: flReasonImageGone, Kind: EventFilelessImageGone, Severity: "high",
			Note: "进程映像已从磁盘删除（仍在运行）",
		})
	}

	// 7) 匿名可执行段：只在「看成了内存」且不是 JIT 引擎时成立
	if f.MemProbed && !isJITEngine(f) && f.AnonExecBytes >= flAnonExecFloor {
		// 有可执行匿名内存还不够，要有一个「不该有它」的理由。
		if f.ImageDeleted || f.ExeInTemp || len(f.Memfd) > 0 || hiddenDirSuspicious(f.Exe) {
			hits = append(hits, filelessHit{
				Slug: flReasonAnonExec, Kind: EventFilelessAnonExec, Severity: "high",
				Note: "匿名可执行内存 " + humanBytes(f.AnonExecBytes) + "（" + itoa(f.AnonExecRegion) + " 段）",
			})
		}
	}

	// 8) 临时目录 + 无有效签名
	if f.ExeInTemp && f.HasSigInfo && !f.Signed {
		hits = append(hits, filelessHit{
			Slug: flReasonUnsigned, Kind: EventFilelessUnsigned, Severity: "medium",
			Note: "临时目录内的可执行文件无有效签名",
		})
	}
	return hits
}

// psEncodedArg 从命令行里取出 -EncodedCommand 的载荷。
//
// 这里是本文件最容易写错的一处：PowerShell 的 `-Encoding` 前缀与 `-enc` 相同，
// 用 strings.Contains(cmd, "-enc") 会把 `powershell -Encoding utf8 -File x.ps1`
// 判成编码命令。所以按 token 精确匹配，且要求**下一个 token 是 base64**。
func psEncodedArg(cmd string) (string, bool) {
	toks := strings.Fields(cmd)
	for i := 0; i < len(toks); i++ {
		t := strings.ToLower(strings.Trim(toks[i], `"'`))
		switch t {
		case "-enc", "-encodedcommand", "/enc", "/encodedcommand":
			if i+1 < len(toks) {
				return strings.Trim(toks[i+1], `"'`), true
			}
			return "", false
		case "-e", "/e":
			// 单字母别名歧义大（-e 也可能是 -ExecutionPolicy 的误写），
			// 只在载荷很长（≥64）时认，标准编码命令都远超这个长度。
			if i+1 < len(toks) {
				blob := strings.Trim(toks[i+1], `"'`)
				if len(blob) >= 64 {
					return blob, true
				}
			}
		}
	}
	return "", false
}

// hasPipeToShell 命令行里是否把输出管道给了 shell。
func hasPipeToShell(low string) bool {
	for _, pat := range []string{"| sh", "|sh", "| bash", "|bash", "| zsh", "|zsh", "| python", "|python", "| perl"} {
		if strings.Contains(low, pat) {
			return true
		}
	}
	return false
}

// humanBytes 人可读大小（事件 subject 用）。
func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return itoa(int(n>>30)) + " GiB"
	case n >= 1<<20:
		return itoa(int(n>>20)) + " MiB"
	case n >= 1<<10:
		return itoa(int(n>>10)) + " KiB"
	}
	return itoa(int(n)) + " B"
}

// flDedupTTL 同一 (pid, 规则) 的去重窗口。
//
// 10 分钟：无文件执行的证据（编码命令行、匿名内存）在一个进程生命周期内
// 是常量，每 30 秒报一次会让同一条 PowerShell 刷满控制台。
const flDedupTTL = 10 * time.Minute

// Fileless 无文件执行采集器。
type Fileless struct {
	Base

	mu      sync.Mutex
	seen    map[string]float64
	scanned int
	hits    int
	limits  string

	// factsFn 取数入口。默认 platformFilelessFacts；测试注入合成事实，
	// 这样「事件构造 + 去重 + subject」这条链路也能在没有目标平台时验证。
	factsFn func(ctx context.Context) ([]filelessFact, error)
}

// NewFileless 构造并自检。
//
// 周期 30 秒：一次采集要跑 ps（~30ms）+ 若干次 vmmap（~0.5s/个），
// 比 process（5s）重得多；而无文件证据是长驻的，30 秒不会漏掉短命进程
// 之外的任何东西——短命编码命令由 process 采集器的 cmdline 规则兜。
func NewFileless(cfg Config) Collector {
	fl := &Fileless{
		seen:    map[string]float64{},
		limits:  platformFilelessLimits(),
		factsFn: platformFilelessFacts,
	}
	interval := 30 * time.Second
	if cfg.Interval > 0 {
		interval = cfg.Interval
	}
	fl.Init("fileless", ModePoll, interval, platformProbeFileless)
	if !cfg.WantEnabled() {
		fl.Status.Enabled = false
	}
	return fl
}

// Limits 本平台能力边界。
func (fl *Fileless) Limits() string { return fl.limits }

// available 用 Init 时算好的结论，不在采集路径上重跑 Probe。
// Windows 上 Probe 会起一次 PowerShell（~200ms），30 秒一轮虽不致命，
// 但没有理由每轮都问一遍「我还能用吗」。
func (fl *Fileless) available() bool {
	fl.mu.Lock()
	defer fl.mu.Unlock()
	return fl.Status.Available
}

// Reprobe 重新自检并刷新状态。
func (fl *Fileless) Reprobe() error {
	err := fl.Probe()
	fl.mu.Lock()
	defer fl.mu.Unlock()
	if err != nil {
		fl.Status.Available = false
		fl.Status.Enabled = false
		fl.Status.Reason = err.Error()
		return err
	}
	fl.Status.Available = true
	fl.Status.Enabled = true
	fl.Status.Reason = ""
	return nil
}

// Collect 扫一轮进程表，对命中规则的进程产出事件。
func (fl *Fileless) Collect(ctx context.Context) ([]model.Event, error) {
	if !fl.available() {
		return nil, nil
	}
	factsFn := fl.factsFn
	if factsFn == nil {
		factsFn = platformFilelessFacts
	}
	facts, err := factsFn(ctx)
	if err != nil {
		return nil, err
	}

	now := nowSeconds()
	var out []model.Event
	fl.mu.Lock()
	defer fl.mu.Unlock()
	fl.scanned = len(facts)

	for _, f := range facts {
		hits := judgeFileless(f)
		for _, h := range hits {
			if !fl.flAccept(flKey(f, h), now) {
				continue
			}

			ev := model.NewEvent(h.Kind, "fileless")
			if f.TS > 0 {
				ev.TS = f.TS
			}
			if f.HasPID {
				pid := f.PID
				ev.PID = &pid
			}
			if f.PPID > 0 {
				ppid := f.PPID
				ev.PPID = &ppid
			}
			ev.User = f.User
			ev.Process = firstNonEmpty(baseNameAnyOS(f.Exe), f.Process)
			ev.Cmdline = clip(f.Cmdline, 400)
			ev.Path = f.Exe
			ev.Severity = h.Severity
			subj := map[string]any{
				"reason": h.Slug,
				"note":   h.Note,
				"source": f.Source,
			}
			if f.MemProbed {
				subj["anon_exec_bytes"] = f.AnonExecBytes
				subj["anon_exec_regions"] = f.AnonExecRegion
			} else {
				subj["mem_probed"] = false // 明确写「没看成内存」，别让读者以为看过
			}
			if len(f.Memfd) > 0 {
				subj["memfd"] = f.Memfd
			}
			if f.ImageDeleted {
				subj["image_deleted"] = true
			}
			if f.HasSigInfo {
				subj["signed"] = f.Signed
			}
			ev.Subject = subj
			out = append(out, *ev)
			fl.hits++
		}
	}
	// 清过期去重键（长跑时 map 只增不减）
	for k, ts := range fl.seen {
		if now-ts > flDedupTTL.Seconds()*2 {
			delete(fl.seen, k)
		}
	}
	return out, nil
}

// flAccept 去重判定：同一 (pid, 规则) 在 TTL 内只放行一次。
//
// 调用方必须持有 fl.mu（Collect 在锁内调用）。抽成方法是为了让去重
// 本身可以被单测钉住——「TTL 内第二次必须被吞」是这类采集器最容易写错的一步。
func (fl *Fileless) flAccept(key string, now float64) bool {
	if last, ok := fl.seen[key]; ok && now-last < flDedupTTL.Seconds() {
		return false
	}
	fl.seen[key] = now
	return true
}

// flKey 去重键：pid + 规则。命令行变化不影响键——同一个进程换了命令行
// 是极小概率事件，而键里带命令行会让「每轮重新编码」的样本重复上报。
func flKey(f filelessFact, h filelessHit) string {
	return itoa(f.PID) + "|" + h.Slug
}

// Snapshot 采集器状态（控制台展示）。
func (fl *Fileless) Snapshot() map[string]any {
	fl.mu.Lock()
	defer fl.mu.Unlock()
	return map[string]any{
		"scanned": fl.scanned,
		"hits":    fl.hits,
		"limits":  fl.limits,
		"ts":      nowSeconds(),
	}
}
