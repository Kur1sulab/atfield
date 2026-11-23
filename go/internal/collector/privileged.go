package collector

// privileged.go —— 提权行为采集：三平台把原始遥测归一成 privRecord，判定只有这一份。
//
// 为什么单独一个采集器：process 采集器看到的是「谁在跑」，看不到「谁把权限换成了
// root」。提权是攻击链里承上启下的一步（初始落地 → 提权 → 持久化），
// 而它只在三个地方留痕：EndpointSecurity 的 setuid/sudo 事件、auditd 的
// SYSCALL/USER_CMD 记录、Windows 安全日志的 4672/4688/1102。三处形状完全不同，
// 但语义可以归一，所以取数按平台、判定只此一份。
//
// 平台能力（取数实现见 _darwin/_linux/_windows.go，Probe 里逐字写清）：
//
//	darwin  eslogger（EndpointSecurity）。需要 root + Full Disk Access。
//	        实测非 root 下 `eslogger exec` 退出码 1、stderr 为
//	        "Failed to create ES client: Not privileged to create an ES client,
//	         need to be superuser (ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED)"，
//	        所以 Probe 在 euid != 0 时直接给原因，不去起子进程。
//	linux   /var/log/audit/audit.log（auditd）。非 root 打不开（0600 root:root），
//	        auditd 没启用则文件根本不存在——两种原因分开报，因为处置动作不同。
//	windows Security 事件日志 4688/4672/1102。**ETW 实时订阅本版没做**：
//	        要么引 syscall 调 wevtapi，要么上管理员 + 会话管理，都不划算。
//	        所以这里是轮询 wevtutil，能力有限，Probe 的 Limits 里写明。
//
// 与 Python 版 atfield/collectors/privileged.py 的关系：
//   - kind 命名沿用它的 ES_INTEREST 映射（process.exec / cred.setuid /
//     defense.cs_invalidated …），对拍按 kind 逐条比。
//   - **刻意分歧（待收口时补进 MIGRATION.md 第七节，本模块未改该文档）**：
//     Python 把每条 exec/fork/exit/open
//     都塞进 600 条环形缓冲。本机实测 eslogger 在编译或浏览时每秒数百条 exec，
//     控制台看到的其实是「最后 600 条随机 exec」——等于噪声，还挤掉了真正的
//     提权事件。Go 版只产出有提权语义的事件：cred.* / priv.* / 敏感路径 file.* /
//     defense.* / system.kextload。普通 exec 一律丢弃。
//
// 误报纪律（本机实测）：
//   - 文件类事件只在「敏感路径」上产出。Python 的 SENSITIVE 前缀表照抄，
//     但去掉了 /Users/Shared/ 之外的宽口径：本机 30 分钟 eslogger 采样里
//     非敏感路径的 file.write 占 92%，全留下会把缓冲冲干净。
//   - `sudo` 成功本身不算告警（开发机上一天几十次），但**无 TTY 的 sudo**
//     和**临时目录里的 sudo** 算——这两条才对应「脚本/服务在提权」。

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/Kur1sulab/atfield/internal/model"
)

// 归一动作。平台解析器只负责填这个字段，判定只看它。
const (
	privActElevate      = "elevate"        // sudo/su/runas/doas 提权成功
	privActSetuid       = "setuid"         // setuid(0)
	privActSeteuid      = "seteuid"        // seteuid(0)
	privActAuthFail     = "auth_fail"      // 提权认证失败
	privActFileCreate   = "file_create"    //
	privActFileWrite    = "file_write"     //
	privActFileDelete   = "file_delete"    //
	privActFileRename   = "file_rename"    //
	privActFileOpen     = "file_open"      //
	privActKextload     = "kextload"       // 内核扩展 / 系统扩展加载
	privActMount        = "mount"          //
	privActCSInvalid    = "cs_invalidated" // 代码签名失效（进程被改后仍在跑）
	privActGKOverride   = "gk_override"    // 用户绕过 Gatekeeper
	privActLogCleared   = "log_cleared"    // 安全日志被清空
	privActPrivAssigned = "priv_assigned"  // 特权分配给新登录（Windows 4672）
	privActAuditRuleOff = "audit_rule_removed"
)

// 事件类型。ES 系列与 Python 版 ES_INTEREST 逐字对齐；priv.* 是本轮增量。
const (
	EventPrivEscalate   = "priv.escalate"
	EventPrivAssigned   = "priv.privilege_assigned"
	EventCredSetuid     = "cred.setuid"
	EventCredSeteuid    = "cred.seteuid"
	EventFileCreate     = "file.create"
	EventFileWrite      = "file.write"
	EventFileDelete     = "file.delete"
	EventFileRename     = "file.rename"
	EventFileOpen       = "file.open"
	EventSystemKextload = "system.kextload"
	EventSystemMount    = "system.mount"
	EventDefenseCSInv   = "defense.cs_invalidated"
	EventDefenseGKOver  = "defense.gatekeeper_override"
	EventDefenseLogClr  = "defense.log_cleared"
)

// privRecord 一条提权相关原始观察（三平台归一）。
type privRecord struct {
	Source     string   // eslogger | auditd | security-log
	EType      string   // 原始事件类型：eslogger 的 event.event / auditd 的 type= / Windows EventID
	Action     string   // 归一动作，见 privAct*
	TS         float64  //
	PID        int      //
	PPID       int      //
	HasPID     bool     //
	User       string   // 发起者
	Process    string   // 进程名（平台原生名字，exe 缺失时兜底）
	Exe        string   // 发起者可执行文件
	Argv       []string //
	Cmdline    string   //
	Target     string   // 目标文件路径 / 目标账户 / 目标 uid
	TTY        string   // 终端；HasTTY 为 false 表示平台没提供这个字段
	HasTTY     bool     //
	Success    bool     // 事件本身是否成功（setuid 失败不算提权）
	HasSuccess bool     // 平台给没给 success 字段（没给 = 不据此过滤）
	Signing    string   // 签名标识（eslogger 的 signing_id / Windows 的签名状态）
	Raw        string   // 原始行（截断后进 Raw，便于复核）
}

// privSensitivePrefixes 文件类事件的保留前缀（与 Python SENSITIVE 对齐，
// 顺序固定：判定按顺序短路，对拍靠它逐条比）。
var privSensitivePrefixes = []string{
	"/etc/", "/private/etc/", "/var/db/sudo", "/var/at/tabs",
	"/Library/LaunchDaemons/", "/Library/LaunchAgents/",
	"/System/Library/", "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
	"/Library/Apple/", "/Users/Shared/", "/tmp/", "/var/tmp/", "/dev/shm/",
	"/Library/Application Support/com.apple.TCC/",
	"/.ssh/", "/Library/Keychains/",
}

// privCriticalSuffixes 命中即 high：这些文件被写，等价于「已经拿到 root 之后
// 在装持久化」。普通敏感路径（/tmp 下的写）只到 medium。
var privCriticalSuffixes = []string{
	"/etc/sudoers", "/etc/sudoers.d/", "/etc/pam.d/", "/etc/master.passwd",
	"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/hosts",
	"/.ssh/authorized_keys", "/.ssh/authorized_keys2",
	"/Library/LaunchDaemons/", "/var/db/sudo/",
}

// privTempPrefixes 提权程序自身落在这些目录 → 高置信（伪装 sudo 是常见手法）。
var privTempPrefixes = []string{
	"/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/",
	"/dev/shm/", "/Users/Shared/", "/private/var/folders/",
}

// privSensitiveTarget 目标文件是否值得上报（空目标 = 不上报）。
func privSensitiveTarget(p string) bool {
	if p == "" {
		return false
	}
	for _, pre := range privSensitivePrefixes {
		if strings.Contains(p, pre) {
			return true
		}
	}
	return false
}

// privCriticalTarget 目标是否属于「写一次就该高危」的那批文件。
func privCriticalTarget(p string) bool {
	if p == "" {
		return false
	}
	low := strings.ToLower(p)
	for _, suf := range privCriticalSuffixes {
		// 后缀表里带大写（/Library/LaunchDaemons/），比较前统一降小写：
		// 第一版忘了这步，写 LaunchDaemon 只判到 medium —— 测试当场抓住。
		if strings.Contains(low, strings.ToLower(suf)) {
			return true
		}
	}
	return false
}

// privTempAnyOS 临时/共享目录判定，三平台路径同时认。
//
// 为什么不用各平台的 isTempPath：解析器（privileged_parse.go）不带 build tag，
// Windows 的事件文本在 macOS 上也要能被判对；如果判据随编译平台变，
// 同一份样本在 CI 和开发机上会得出两种结论。
// 各平台 isTempPath 仍服务于 persistence（它只处理本机路径），两者不冲突。
func privTempAnyOS(p string) bool {
	if p == "" {
		return false
	}
	for _, pre := range privTempPrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	low := strings.ToLower(p)
	for _, frag := range []string{`\temp\`, `\tmp\`, `\appdata\local\temp\`} {
		if strings.Contains(low, frag) {
			return true
		}
	}
	return false
}

// privExeSuspect 发起提权的程序本身可疑：落在临时/共享目录，
// 或落在白名单之外的隐藏目录（复用 process.go 的 hiddenDirSuspicious，
// 保持两条采集器对「可疑路径」的口径一致）。
func privExeSuspect(exe string) bool {
	if exe == "" {
		return false
	}
	if privTempAnyOS(exe) {
		return true
	}
	return hiddenDirSuspicious(exe)
}

// judgePriv 把一条归一记录判成事件；第二个返回值为 false 表示「不上报」。
//
// 这个函数是纯函数：不碰文件系统、不读时钟（TS 来自记录），
// 所以三平台解析出的样本都能在 macOS 上直接单测（privileged_test.go）。
func judgePriv(rec privRecord) (model.Event, bool) {
	action := strings.ToLower(strings.TrimSpace(rec.Action))
	if action == "" {
		return model.Event{}, false
	}

	exe := firstNonEmpty(rec.Exe, rec.Process)
	ev := model.NewEvent("", "privileged")
	if rec.TS > 0 {
		ev.TS = rec.TS
	}
	ev.User = rec.User
	if rec.HasPID {
		pid := rec.PID
		ev.PID = &pid
	}
	if rec.PPID > 0 {
		ppid := rec.PPID
		ev.PPID = &ppid
	}
	ev.Process = firstNonEmpty(baseNameAnyOS(exe), rec.Process)
	ev.Cmdline = clip(firstNonEmpty(rec.Cmdline, strings.Join(rec.Argv, " ")), 400)
	// ev.Path 只给「文件事件」填（见下面 file.* 分支）：提权记录的 target 是
	// 目标账户/uid，塞进 Path 会让控制台把 "root" 当成文件路径展示。

	suspect := privExeSuspect(exe)
	subj := map[string]any{
		"action":     action,
		"source":     rec.Source,
		"event_type": rec.EType,
	}
	if exe != "" {
		subj["exe"] = exe
	}
	if rec.Target != "" {
		subj["target"] = rec.Target
	}
	if rec.HasTTY {
		subj["tty"] = rec.TTY
	}
	if suspect {
		subj["exe_suspect"] = true
	}
	if rec.Signing != "" {
		subj["signing"] = rec.Signing
	}

	switch action {
	case privActElevate:
		ev.Kind = EventPrivEscalate
		ev.Severity = "medium"
		// 无 TTY 的提权：人不会在没终端的时候敲 sudo，这是脚本/服务/远程会话。
		if rec.HasTTY && rec.TTY == "" {
			ev.Severity = "high"
			subj["no_tty"] = true
		}
		if suspect {
			ev.Severity = "high"
			subj["suspect_exe"] = true
		}

	case privActSetuid, privActSeteuid:
		// 只关心「提到 root」。setuid 到自己的 uid 是守护进程正常降权/回升，
		// 全报会把每一个 daemon 的启动都刷成事件。
		if strings.TrimSpace(rec.Target) != "0" {
			return model.Event{}, false
		}
		// 失败的 setuid 不是提权：auditd 只在成功时给 syscall，但 eslogger
		// 会为失败调用也发一条（success=false），不过滤就会把「尝试失败」当既遂。
		if rec.HasSuccess && !rec.Success {
			return model.Event{}, false
		}
		if action == privActSetuid {
			ev.Kind = EventCredSetuid
		} else {
			ev.Kind = EventCredSeteuid
		}
		ev.Severity = "medium"
		if suspect {
			ev.Severity = "high"
		}
		subj["target_uid"] = 0

	case privActAuthFail:
		ev.Kind = EventAuthFail
		ev.Severity = "medium"
		subj["via"] = "privileged"

	case privActFileCreate, privActFileWrite, privActFileDelete,
		privActFileRename, privActFileOpen:
		// 非敏感路径的文件事件一律丢弃：这是本采集器不变成噪声源的关键。
		if !privSensitiveTarget(rec.Target) {
			return model.Event{}, false
		}
		ev.Path = rec.Target
		switch action {
		case privActFileCreate:
			ev.Kind = EventFileCreate
		case privActFileWrite:
			ev.Kind = EventFileWrite
		case privActFileDelete:
			ev.Kind = EventFileDelete
		case privActFileRename:
			ev.Kind = EventFileRename
		default:
			ev.Kind = EventFileOpen
		}
		ev.Severity = "medium"
		if privCriticalTarget(rec.Target) {
			ev.Severity = "high"
			subj["critical"] = true
		}

	case privActKextload:
		ev.Kind = EventSystemKextload
		ev.Severity = "high"

	case privActMount:
		ev.Kind = EventSystemMount
		ev.Severity = "medium"

	case privActCSInvalid:
		ev.Kind = EventDefenseCSInv
		ev.Severity = "high"

	case privActGKOverride:
		ev.Kind = EventDefenseGKOver
		ev.Severity = "medium"

	case privActLogCleared:
		ev.Kind = EventDefenseLogClr
		ev.Severity = "critical"

	case privActPrivAssigned:
		ev.Kind = EventPrivAssigned
		ev.Severity = "medium"

	case privActAuditRuleOff:
		// 审计规则被删 = 攻击者在关摄像头（T1562.006）。这条只有 auditd 能看见，
		// 而它恰恰是「先关审计再动手」的第一现场。
		ev.Kind = EventDefenseEvent
		ev.Severity = "high"
		subj["audit_rule_removed"] = true

	default:
		return model.Event{}, false
	}

	ev.Subject = subj
	if rec.Raw != "" {
		ev.Raw = map[string]any{"line": clip(rec.Raw, 600)}
	}
	return *ev, true
}

// privDedupTTL 同一 (动作, pid, 目标) 的去重窗口。
//
// 为什么需要：eslogger 的 write 事件按写入次数逐条吐，一个进程写 /etc/hosts
// 三次就是三条一模一样的告警；auditd 的 SYSCALL/EXECVE 是同一事件的两条记录，
// 解析层已经合并，但相邻两轮轮询会重复读到同一行（offset 没推进时）。
const privDedupTTL = 120 * time.Second

// privAuthDedupTTL 认证失败窗口更短：爆破的特征就是「密集重复」，
// 两分钟内合并成一条会看不到节奏。
const privAuthDedupTTL = 20 * time.Second

// privDedupKey 去重键：动作 + pid + 目标（不含时间戳）。
func privDedupKey(rec privRecord, ev model.Event) string {
	pid := 0
	if ev.PID != nil {
		pid = *ev.PID
	}
	return ev.Kind + "|" + itoa(pid) + "|" + rec.Target
}

// Privileged 提权采集器。
type Privileged struct {
	Base

	mu         sync.Mutex
	buf        []model.Event
	seen       map[string]float64
	started    bool
	connected  bool
	drops      int64
	suppressed int64
	rate       int
	rateWin    time.Time
	maxRate    int
	autoSync   bool
	autoSyncOn bool
	limits     string

	src func(ctx context.Context, sink func(privRecord)) error
}

// NewPrivileged 构造并自检。
//
// 周期用 1s：ModeStream 下 Collect 只是「取缓冲」，1s 的取用节奏让事件延迟
// 不超过 1 秒；真正的取数在 Start() 起的常驻订阅里（--once 走惰性补采）。
func NewPrivileged(cfg Config) Collector {
	p := &Privileged{
		seen:       map[string]float64{},
		maxRate:    120, // 每秒最多 120 条，超了计数丢弃（不是静默丢）
		autoSyncOn: true,
		src:        platformPrivSource,
		limits:     platformPrivLimits(),
	}
	interval := time.Second
	if cfg.Interval > 0 {
		interval = cfg.Interval
	}
	p.Init("privileged", ModeStream, interval, platformProbePrivileged)
	if !cfg.WantEnabled() {
		p.Status.Enabled = false
	}
	return p
}

// Limits 本平台的能力边界（控制台显示「能用，但只到这一步」）。
func (p *Privileged) Limits() string { return p.limits }

// available 用 Init 时算好的结论，不在采集路径上重跑 Probe。
//
// 为什么必须缓存：root 下 Probe 会真的起一个 eslogger 试跑（最长 6 秒），
// 而 Collect 每 1 秒被调一次——不缓存就是「每秒一个 eslogger 子进程」，
// 比采集本身还费资源。环境变化（后来拿到 root）由 Reprobe 显式触发。
func (p *Privileged) available() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.Status.Available
}

// Reprobe 重新做一次可用性自检并刷新状态（控制台的「重新检测」按钮用）。
func (p *Privileged) Reprobe() error {
	err := p.Probe()
	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil {
		p.Status.Available = false
		p.Status.Enabled = false
		p.Status.Reason = err.Error()
		return err
	}
	p.Status.Available = true
	p.Status.Enabled = true
	p.Status.Reason = ""
	return nil
}

// Start 启动长驻订阅（对应 Python 的 start()）。
func (p *Privileged) Start(ctx context.Context) {
	if !p.available() {
		return
	}
	p.mu.Lock()
	p.started = true
	p.mu.Unlock()
	go func() {
		for ctx.Err() == nil {
			p.mu.Lock()
			p.connected = true
			p.mu.Unlock()
			err := p.src(ctx, p.handleRecord)
			p.mu.Lock()
			p.connected = false
			p.mu.Unlock()
			if err == nil || ctx.Err() != nil {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}()
}

// SyncOnce 单轮拉取：给 --once 与测试用（平台数据源是流，用短超时拉一小段）。
func (p *Privileged) SyncOnce(ctx context.Context, window time.Duration) int {
	if !p.available() {
		return 0
	}
	cctx, cancel := context.WithTimeout(ctx, window)
	defer cancel()
	_ = p.src(cctx, p.handleRecord)
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.buf)
}

// handleRecord 判定 → 去重 → 限速 → 入缓冲。
func (p *Privileged) handleRecord(rec privRecord) {
	ev, ok := judgePriv(rec)
	if !ok {
		return
	}
	key := privDedupKey(rec, ev)
	now := time.Now()

	p.mu.Lock()
	defer p.mu.Unlock()

	ttl := privDedupTTL
	if ev.Kind == EventAuthFail {
		ttl = privAuthDedupTTL
	}
	if last, ok := p.seen[key]; ok && now.Sub(time.Unix(0, int64(last*1e9))) < ttl {
		p.suppressed++
		return
	}
	p.seen[key] = nowSeconds()

	if now.Sub(p.rateWin) >= time.Second {
		p.rate = 0
		p.rateWin = now
	}
	p.rate++
	if p.rate > p.maxRate {
		p.drops++
		return
	}
	p.buf = append(p.buf, ev)
	if len(p.seen) > 4096 {
		p.privSeenPrune(nowSeconds())
	}
	if len(p.buf) > 800 {
		// 只留最近的：控制台展示按时间倒序，老的先丢。
		p.buf = p.buf[len(p.buf)-800:]
	}
}

// Collect 取走缓冲。不可用时返回空（原因已在 Status.Reason 里，不重复报错）。
func (p *Privileged) Collect(ctx context.Context) ([]model.Event, error) {
	if !p.available() {
		return nil, nil
	}
	p.mu.Lock()
	needSync := p.autoSyncOn && !p.started && !p.autoSync && len(p.buf) == 0
	if needSync {
		p.autoSync = true
	}
	p.mu.Unlock()
	if needSync {
		p.SyncOnce(ctx, 2*time.Second)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.buf) == 0 {
		return nil, nil
	}
	buf := p.buf
	p.buf = nil
	if len(buf) > 500 {
		buf = buf[len(buf)-500:]
	}
	return buf, nil
}

// Snapshot 等价于 Python 的 store.set_state("privileged", ...)。
func (p *Privileged) Snapshot() map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	return map[string]any{
		"connected":  p.connected,
		"started":    p.started,
		"buffered":   len(p.buf),
		"drops":      p.drops,
		"suppressed": p.suppressed,
		"limits":     p.limits,
		"ts":         nowSeconds(),
	}
}

// Close 停订阅。数据源靠 ctx 取消退出，这里只清状态。
func (p *Privileged) Close() error {
	p.mu.Lock()
	p.connected = false
	p.started = false
	p.mu.Unlock()
	return nil
}

// privSeenPrune 清掉过期去重键，避免长跑时 map 只增不减。
func (p *Privileged) privSeenPrune(now float64) {
	for k, ts := range p.seen {
		if now-ts > privDedupTTL.Seconds()*2 {
			delete(p.seen, k)
		}
	}
}

// itoa 小工具：避免为了拼一个 key 引 strconv 到热路径（调用频率高）。
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
