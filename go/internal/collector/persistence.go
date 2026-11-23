package collector

// persistence.go —— 开机自启采集的通用部分：条目模型 + 可疑判定 + 基线差分。
//
// 三平台把原生结构（launchd plist / cron 行 / systemd unit / 注册表值 / 计划任务）
// 归一成 persistenceItem，判定与差分只有这一份实现。判定用例在
// persistence_test.go，平台解析器在 persistence_parse.go（不带 build tag，
// 在 macOS 上也能测 Windows 的 reg query 输出解析）。
//
// 与 Python 版 atfield/collectors/persistence.py 的 _suspicion() 对齐关系
// （前四条顺序与判据完全一致，后四条是本轮增量，只追加不动前面）：
//
//	python 判据                                 go reason
//	命令含 SUSPICIOUS_BIN 片段                  cmd-token:<token>
//	plist 位于临时/共享目录                     item-in-temp
//	plist 权限过宽（group/other 可写）          perm-too-wide
//	RunAtLoad 且 KeepAlive                      run-at-load-keep-alive
//	（新增）可执行文件在临时目录                prog-in-temp
//	（新增）可执行文件已不存在                  prog-missing
//	（新增）可执行文件在非白名单隐藏目录        prog-hidden-dir
//	（新增）系统级条目的可执行文件在家目录      root-item-user-binary
//
// 为什么 reason 用英文 slug 而不是 Python 的中文串：Go 版所有采集器
// （process.go 已如此）统一用 slug 做机器可读键，中文进 subject/UI。
// 对拍脚本按「slug ↔ 中文」映射表比较，顺序与集合仍然逐条可比。
//
// 误报纪律（实测数字见 MIGRATION.md 第七节）：
//   - 「不在 Program Files / 不在系统目录」这种判据一律不要。本机实测
//     13 个用户 LaunchAgent 里 5 个指向 ~/、~/Library/Application Support/，
//     那是正常软件的正常装法。只有当条目本身是**系统级**（root/LaunchDaemon/
//     HKLM 服务）却指向普通用户可写目录时，才是提权持久化的硬信号。
//   - 解释器（/bin/sh、/usr/bin/env、osascript）本身不算可疑，命令里的
//     可疑片段由 cmd-token 负责——两层分开，避免互相掩护。

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Kur1sulab/atfield/internal/model"
)

// 判定理由 slug（顺序即输出顺序，对拍时逐字比对）。
const (
	reasonCmdToken     = "cmd-token:"
	reasonItemTemp     = "item-in-temp"
	reasonPermWide     = "perm-too-wide"
	reasonRunKeepAlive = "run-at-load-keep-alive"
	reasonProgTemp     = "prog-in-temp"
	reasonProgMissing  = "prog-missing"
	reasonProgHidden   = "prog-hidden-dir"
	reasonRootUserBin  = "root-item-user-binary"
)

// 事件类型。
const (
	EventPersistenceAdd        = "persistence.add"
	EventPersistenceModify     = "persistence.modify"
	EventPersistenceRemove     = "persistence.remove"
	EventPersistenceSuspicious = "persistence.suspicious"
)

// suspiciousCmdTokens 与 Python 版 SUSPICIOUS_BIN 逐条相同、顺序相同。
//
//	"/tmp/"、"/Users/Shared/" 这类是「落地在临时/共享目录」；
//	curl/wget/base64/osascript/nc 是「远程取件 + 编码 + 自动化」三件套；
//	"python -c"、"/bin/sh -c"、"bash -c" 是「不落盘执行」。
var suspiciousCmdTokens = []string{
	"/tmp/", "/var/tmp/", "/Users/Shared/", "/dev/shm/",
	"/private/var/folders/", "curl", "wget", "base64",
	"python -c", "osascript", "nc ", "/bin/sh -c", "bash -c",
}

// persistenceItem 一条开机自启项（三平台归一）。
type persistenceItem struct {
	Kind      string   `json:"kind"`    // launchd | cron | systemd | registry-run | startup-folder | scheduled-task
	ID        string   `json:"id"`      // 稳定唯一键（跨轮差分用）
	Path      string   `json:"path"`    // 承载它的文件 / 注册表键 / 目录
	Label     string   `json:"label"`   // 人可读标识（label / 任务名 / 值名）
	Program   string   `json:"program"` // 可执行文件（未知为空 → 不做路径判定）
	Args      []string `json:"args,omitempty"`
	Command   string   `json:"command"` // 完整命令行（cmd-token 判定对象）
	Scope     string   `json:"scope"`   // system | user
	RunAtLoad bool     `json:"run_at_load"`
	KeepAlive bool     `json:"keep_alive"`
	MTime     int64    `json:"mtime,omitempty"`
	Mode      uint32   `json:"mode,omitempty"`
	HasMode   bool     `json:"-"`
	Hash      string   `json:"hash,omitempty"` // 命令行指纹：注册表项没有 mtime，靠它判改动
	Susp      []string `json:"-"`              // 上一轮判定快照
}

// fsProbe 判定只需要「路径在不在、权限位多少」，抽成接口是为了让测试
// 能在不碰真实文件系统的前提下双向验证（正常项不报 / 可疑项要报）。
type fsProbe interface {
	Stat(path string) (mode uint32, ok bool)
}

type realFS struct{}

func (realFS) Stat(path string) (uint32, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, false
	}
	return uint32(fi.Mode().Perm()), true
}

// suspicion 返回命中的理由（空 = 正常）。顺序固定，见文件头映射表。
//
// 收敛纪律（真机实测数字，944 条）：第一版把四条规则无差别应用，报了 51 条。
// 构成：24 条 Apple 自己的守护进程（AirPlayUIAgent/bluetoothd/apsd 天然是
// RunAtLoad+KeepAlive 的看门狗）、4 条 /System 里按 CPU 架构缺失的
// cvmsCompAgent（prog-missing）、1 条 kdumpd（命令行里带 /tmp、/var/tmp——
// 它本来就是写崩溃转储的）。这些条目全在 SIP 保护下，攻击者改不了，
// 报它们只是把系统噪音当威胁。
//
// 所以：条目位于**不可变的系统位置**时直接返回空——只参与清点，不参与判定。
// 理由不是「省事」：在 SIP 机器上要让 /System 变样，得先关 SIP，那是
// integrity 采集器的战场；这里再报一遍只会污染持久化告警的信噪比。
// 攻击者真正能动的是 ~/Library/LaunchAgents 与 /Library/Launch*，一条没少判。
func (it *persistenceItem) suspicion(fs fsProbe) []string {
	if it.Path != "" && isImmutableItemPath(it.Path) {
		return nil
	}
	var r []string
	cmd := strings.ToLower(it.Command)

	// 1) 命令含可疑片段（与 Python SUSPICIOUS_BIN 同一张表）
	for _, tok := range suspiciousCmdTokens {
		if cmdTokenHit(cmd, tok) {
			r = append(r, reasonCmdToken+strings.TrimSpace(tok))
		}
	}
	// 2) 条目自身落在临时/共享目录
	if it.Path != "" && isTempPath(it.Path) {
		r = append(r, reasonItemTemp)
	}
	// 3) 条目文件 group/other 可写：任何本地用户都能改你的开机项
	if it.HasMode && it.Mode&0o022 != 0 {
		r = append(r, reasonPermWide)
	}
	// 4) launchd 专属：RunAtLoad + KeepAlive = 开机即起、被杀就重启
	if it.Kind == "launchd" && it.RunAtLoad && it.KeepAlive {
		r = append(r, reasonRunKeepAlive)
	}
	// 5) 可执行文件落在临时/共享目录
	// 6) 可执行文件已不存在（指向已删路径 = 残留或清理痕迹）
	// 7) 可执行文件在非白名单隐藏目录
	// 8) 系统级条目却指向普通用户可写目录（提权持久化）
	if prog := it.Program; prog != "" && looksLikePath(prog) {
		_, exists := fs.Stat(prog)
		if isTempPath(prog) {
			r = append(r, reasonProgTemp)
		}
		if !exists {
			r = append(r, reasonProgMissing)
		}
		if hiddenDirSuspicious(prog) {
			r = append(r, reasonProgHidden)
		}
		if it.Scope == "system" && isUserBinaryPath(prog) {
			// 「在哪」与「在不在」是两件事：指向用户目录本身就是提权链的一环，
			// 不因为文件暂时缺失就不报（攻击者也会先清文件再等下次投放）。
			r = append(r, reasonRootUserBin)
		}
	}
	return r
}

// cmdTokenHit 判断一行命令是否命中某个可疑片段。
//
// 与 Python 的一处有意收紧：纯路径类 token（以 / 开头）继续用子串匹配，
// 命令类 token（curl/wget/base64/nc/osascript…）要求词边界。
// 原因：Python 的裸子串匹配会把 "curly"、"sync" 里的 "nc" 也算命中，
// 实测这类假阳性只在正常软件上出现，攻击者的 curl 一定在词边界上。
// 含空格的 token（"python -c"、"/bin/sh -c"）无法用词边界，退回子串。
func cmdTokenHit(cmd, tok string) bool {
	tok = strings.ToLower(strings.TrimSpace(tok))
	if tok == "" {
		return false
	}
	if strings.ContainsAny(tok, " /") && !isWordToken(tok) {
		return strings.Contains(cmd, tok)
	}
	return wordBoundaryHit(cmd, tok)
}

func isWordToken(tok string) bool {
	for i := 0; i < len(tok); i++ {
		c := tok[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func wordBoundaryHit(s, word string) bool {
	from := 0
	for {
		i := strings.Index(s[from:], word)
		if i < 0 {
			return false
		}
		i += from
		beforeOK := i == 0 || !isWordByte(s[i-1])
		afterOK := i+len(word) == len(s) || !isWordByte(s[i+len(word)])
		if beforeOK && afterOK {
			return true
		}
		from = i + 1
		if from >= len(s) {
			return false
		}
	}
}

func isWordByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_'
}

// looksLikePath 判断 Program 是不是一个「可以直接 stat」的路径。
// 注册表里偶尔出现裸命令名（"iexplore.exe"），那种交给 token 判定就够了。
func looksLikePath(p string) bool {
	return strings.ContainsAny(p, `/\`)
}

// Persistence 开机自启采集器。
type Persistence struct {
	Base

	source func(context.Context) ([]persistenceItem, error)
	probe  fsProbe // 判定用的文件系统视图（测试注入假实现）
	known  map[string]persistenceItem
	seeded bool
	items  int
}

// fsView 返回判定用的文件系统视图。
func (p *Persistence) fsView() fsProbe {
	if p.probe != nil {
		return p.probe
	}
	return realFS{}
}

// NewPersistence 构造并自检。
func NewPersistence(cfg Config) Collector {
	p := &Persistence{known: map[string]persistenceItem{}}
	interval := 60 * time.Second
	if cfg.Interval > 0 {
		interval = cfg.Interval
	}
	p.source = platformPersistenceItems
	p.Init("persistence", ModePoll, interval, platformProbePersistence)
	if !cfg.WantEnabled() {
		p.Status.Enabled = false
	}
	return p
}

// Items 本轮回填的清点条数（含正常项）。
// 单条 suspicious 事件只说明「有一条可疑」，控制台更需要「一共清点了多少」，
// 否则 1000 条里 1 条命中会被读成「只看了 1 条」。
func (p *Persistence) Items() int { return p.items }

// Collect 采集一轮并做差分。
//
// 与 Python 版的一处有意差异（必须记下来，否则对拍会困惑）：
// Python 首轮只建基线、一条事件都不出（`if not self._seeded: continue`）。
// 那在常驻服务里没问题，但 `atfieldd --once` 这种「跑一次就退出」的场景
// 下等于永远零输出——审机器的人看不到任何东西。所以这里：
//   - 首轮：不出 add（那是噪声），但对**已可疑**的条目出一条
//     persistence.suspicious（severity=high，subject.baselined=false）；
//   - 之后：新条目出 add、内容变了出 modify、判定集合变了出 suspicious、
//     消失出 remove。
//
// 对拍时只比 add/modify/remove 三类，suspicious 额外用来验证「首轮审计」。
func (p *Persistence) Collect(ctx context.Context) ([]model.Event, error) {
	items, err := p.source(ctx)
	if err != nil {
		return nil, err
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })

	fs := p.fsView()
	var out []model.Event
	seen := make(map[string]bool, len(items))

	for i := range items {
		it := &items[i]
		if it.ID == "" {
			continue
		}
		if seen[it.ID] {
			continue // 同一 ID 出现两次（crontab 里两行一样的命令）：只算一条
		}
		seen[it.ID] = true
		it.Hash = cmdHash(it.Command)
		sus := it.suspicion(fs)
		prev, known := p.known[it.ID]

		switch {
		case !known:
			if p.seeded {
				out = append(out, *p.event(EventPersistenceAdd, it, sus, sevWith(sus, "low")))
			} else if len(sus) > 0 {
				out = append(out, *p.event(EventPersistenceSuspicious, it, sus, "high"))
			}
		case prev.MTime != it.MTime && prev.MTime != 0 && it.MTime != 0,
			prev.Hash != it.Hash && prev.Hash != "":
			out = append(out, *p.event(EventPersistenceModify, it, sus, sevWith(sus, "medium")))
		case len(sus) > 0 && !sameReasons(prev.Susp, sus):
			out = append(out, *p.event(EventPersistenceSuspicious, it, sus, "high"))
		}

		it.Susp = sus
		p.known[it.ID] = *it
	}

	// 消失的条目：攻击者常靠删掉开机项来关掉防护/清理痕迹，
	// 静默消失本身是信号，不能只看「新增」。
	gone := make([]string, 0)
	for id := range p.known {
		if !seen[id] {
			gone = append(gone, id)
		}
	}
	sort.Strings(gone)
	for _, id := range gone {
		prev := p.known[id]
		out = append(out, *p.event(EventPersistenceRemove, &prev, prev.Susp, "medium"))
		delete(p.known, id)
	}

	p.seeded = true
	p.items = len(items)
	return out, nil
}

func (p *Persistence) event(kind string, it *persistenceItem, sus []string, severity string) *model.Event {
	ev := model.NewEvent(kind, "persistence")
	ev.Path = it.Path
	ev.Process = baseName(it.Program)
	ev.Cmdline = clip(it.Command, 600)
	ev.Severity = severity
	reasons := append([]string{}, sus...)
	ev.Subject = map[string]any{
		"kind":        it.Kind,
		"id":          it.ID,
		"label":       it.Label,
		"program":     it.Program,
		"scope":       it.Scope,
		"run_at_load": it.RunAtLoad,
		"keep_alive":  it.KeepAlive,
		"reasons":     reasons,
		"baselined":   p.seeded,
	}
	if it.Path != "" {
		ev.Subject["item_path"] = it.Path
	}
	return ev
}

func sevWith(sus []string, base string) string {
	if len(sus) > 0 {
		return "high"
	}
	return base
}

func sameReasons(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// cmdHash 命令行指纹：用来发现「注册表值被改但没法看 mtime」的改动。
func cmdHash(s string) string {
	sum := sha1.Sum([]byte(s))
	return hex.EncodeToString(sum[:6])
}

// joinCommand plist 的 Program + ProgramArguments → 一行命令。
// ProgramArguments[0] 通常就是 Program，重复时不要拼两遍。
func joinCommand(program string, args []string) string {
	parts := args
	if program != "" && (len(parts) == 0 || parts[0] != program) {
		parts = append([]string{program}, parts...)
	}
	return strings.Join(parts, " ")
}
