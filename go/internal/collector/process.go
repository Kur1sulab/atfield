package collector

// process.go —— 进程采集的通用部分：判定逻辑在这里，取进程表按平台实现。
//
// 判定为什么这么写：进程列表本身没有价值，有价值的是「不寻常」。
// 这里的每条规则都对应一个真实的持久化/无文件手法，且都能在 Python 版
// 找到同名规则——对拍时两边必须给出同一批可疑进程。

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Kur1sulab/atfield/internal/model"
)

// procInfo 统一的进程信息（各平台把原生字段映射到这里再判定）。
type procInfo struct {
	PID  int
	PPID int
	User string
	Comm string
	Args string
}

// Process 进程采集器。
type Process struct {
	Base
}

// NewProcess 构造并自检。
func NewProcess(cfg Config) Collector {
	p := &Process{}
	interval := 5 * time.Second
	if cfg.Interval > 0 {
		interval = cfg.Interval
	}
	p.Init("process", ModePoll, interval, platformProbeProc)
	if !cfg.WantEnabled() {
		p.Status.Enabled = false
	}
	return p
}

// Collect 采集一轮进程并只对可疑项产出事件。
func (p *Process) Collect(ctx context.Context) ([]model.Event, error) {
	procs, err := platformProcs(ctx)
	if err != nil {
		return nil, err
	}
	var out []model.Event
	for _, pi := range procs {
		reasons := suspiciousProc(pi)
		if len(reasons) == 0 {
			continue
		}
		ev := model.NewEvent("process.suspicious", "process")
		pid, ppid := pi.PID, pi.PPID
		ev.PID, ev.PPID = &pid, &ppid
		ev.User = pi.User
		ev.Process = baseName(pi.Comm)
		ev.Cmdline = pi.Args
		ev.Path = pi.Comm
		ev.Severity = "medium"
		if hasDeletedExe(pi.Comm) {
			ev.Severity = "high" // 可执行文件已从磁盘消失：典型无文件落地
		}
		ev.Subject = map[string]any{
			"pid": pi.PID, "ppid": pi.PPID, "exe": pi.Comm,
			"reasons": reasons,
		}
		out = append(out, *ev)
	}
	return out, nil
}

// suspiciousProc 返回命中的可疑理由（空 = 正常）。
// 顺序固定，保证对拍时 reasons 数组逐字一致。
//
// 误报纪律：系统二进制的命令行里天然带 base64（LaunchArguments、XPC 服务参数），
// 实测第一版对 macOS 系统进程产生 118 条误报。所以系统路径下的进程只保留
// 「exe 已删除」这类硬信号，不做命令行特征匹配。
func suspiciousProc(pi procInfo) []string {
	var r []string
	exe := pi.Comm
	args := pi.Args
	// 系统路径可信，但解释器必须排除在外：/bin/bash 的二进制本身可信，
	// 它承载的命令行不可信。否则 `bash -c "curl x|sh"` 会一路绿灯——
	// 这是决定检测有效性的一条，测试里专门钉住。
	trusted := isSystemExe(exe) && !isInterpreter(exe)

	// 1) 可执行文件已删除：进程还在跑但磁盘上没了（内存马/清理痕迹）
	if hasDeletedExe(exe) {
		r = append(r, "exe-deleted")
	}
	// 2) 从临时目录或隐藏目录启动
	for _, dir := range []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/private/tmp/"} {
		if strings.HasPrefix(exe, dir) {
			r = append(r, "exe-in-tmp")
			break
		}
	}
	if hiddenDirSuspicious(exe) && !trusted {
		r = append(r, "exe-hidden-dir")
	}
	if trusted {
		return r // 系统进程不做命令行特征判定
	}
	low := strings.ToLower(args)
	// 3) base64 长串：仅在「解释器命令行」或「伴随解码/执行指令」时成立。
	// 实测教训：GUI 应用的启动参数天然带 base64（Termius/recentfiles/IPN-Widgets
	// 各中一条），只要出现长串就报，等于把正常软件全判成恶意。
	if hasLongB64(args) && (isInterpreter(exe) || hasDecodeHint(low)) {
		r = append(r, "cmdline-b64")
	}
	// 4) 典型反弹 shell 形态：/dev/tcp、nc -e、bash -i >&
	for _, pat := range []string{"/dev/tcp/", "nc -e", "ncat -e", "bash -i >&", "sh -i >&"} {
		if strings.Contains(low, pat) {
			r = append(r, "reverse-shell-shape")
			break
		}
	}
	// 5) 解释器执行远程内容（curl|sh 类）
	if strings.Contains(low, "curl ") && strings.Contains(low, "| sh") ||
		strings.Contains(low, "curl ") && strings.Contains(low, "| bash") ||
		strings.Contains(low, "wget ") && strings.Contains(low, "| sh") {
		r = append(r, "pipe-to-shell")
	}
	return r
}

func hasDeletedExe(exe string) bool {
	return strings.HasSuffix(exe, "(deleted)") || strings.Contains(exe, " (deleted)")
}

// benignHiddenDirs 正常工具链会把自己的二进制放进隐藏目录。
// 不设白名单的代价很实在：实测本机 59 条事件里绝大多数是 .hermes/.local
// 下的解释器——把开发者自己判成攻击者，等于让真告警失去意义。
var benignHiddenDirs = map[string]bool{
	".local": true, ".config": true, ".cache": true, ".hermes": true,
	".npm": true, ".cargo": true, ".rustup": true, ".nvm": true,
	".pyenv": true, ".venv": true, ".git": true, ".vscode": true,
	".docker": true, ".gradle": true, ".m2": true, ".Trash": true,
	".cache2": true, ".bun": true, ".deno": true, ".volta": true,
}

// hiddenDirSuspicious 判断可执行文件是否落在「白名单之外的隐藏目录」。
// 注意 .ssh 不在白名单：那个目录里出现可执行文件本身就值得看一眼。
func hiddenDirSuspicious(exe string) bool {
	parts := strings.Split(exe, "/")
	for i, p := range parts {
		if i == 0 || i == len(parts)-1 {
			continue
		}
		if strings.HasPrefix(p, ".") && len(p) > 1 && !benignHiddenDirs[p] {
			return true
		}
	}
	return false
}

func baseName(p string) string {
	if p == "" {
		return ""
	}
	return filepath.Base(strings.TrimSuffix(p, " (deleted)"))
}

// interpreterNames 解释器基名集合：只有解释器命令行里的 base64 才值得看——
// 攻击者把 payload 编码进 `bash -c`/`python -c` 是常见落地手法，
// 而 GUI 应用把状态塞进 argv 是正常工程行为。
var interpreterNames = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true,
	"python": true, "python2": true, "python3": true, "perl": true, "ruby": true,
	"node": true, "php": true, "pwsh": true, "powershell": true, "osascript": true,
}

func isInterpreter(exe string) bool {
	name := strings.ToLower(baseName(exe))
	name = strings.TrimSuffix(name, ".exe")
	return interpreterNames[name]
}

// hasDecodeHint 命令行里出现解码/就地执行的痕迹。
func hasDecodeHint(low string) bool {
	for _, p := range []string{
		"base64 -d", "base64 --decode", "base64 -D",
		"| base64", "xxd -r", "openssl enc -d", "certutil -decode",
	} {
		if strings.Contains(low, p) {
			return true
		}
	}
	return false
}

// hasLongB64 找长度 ≥ 120 的 base64 片段（短串误报太多，宁漏不错报）。
func hasLongB64(s string) bool {
	cur := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' ||
			c >= '0' && c <= '9' || c == '+' || c == '/' || c == '=' {
			cur++
			if cur >= 120 {
				return true
			}
			continue
		}
		cur = 0
	}
	return false
}

// selfExe 用于排除自身进程（采集器不该把自己的读取算成可疑行为）。
func selfExe() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return exe
}

// procListUnsupported 给没有实现采集的平台的统一错误文本。
func procListUnsupported(platform string) error {
	return fmt.Errorf("%s 上的进程采集尚未实现", platform)
}
