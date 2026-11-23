// Package enforcer 是心之壁的封禁执行层：把「这个地址要断」翻译成三套防火墙
// 各自的原生指令，并且保证三件事——幂等、可回滚、只碰自己的命名空间。
//
// 为什么单独一层：检测层（internal/detect）只负责「判断」，处置决策在 API/responder，
// 真正动防火墙的必须是最薄的一层，薄到能一眼看完、能逐条断言它到底执行了什么命令。
// 这一层不允许有任何「顺手把系统规则重写一遍」的行为——封禁是外科手术，不是大扫除。
//
// 三个后端的能力并不对等，接口因此显式暴露 Caps，让上层能按能力降级而不是假装对齐：
//
//	darwin  pfctl      anchor 独立命名空间，可整表替换、可回滚、可 flush
//	linux   nftables   table/set 独立命名空间，元素级增删（add 天然幂等），可回滚
//	windows netsh      advfirewall 规则级，无事务、无批量枚举 → 降级路径（见 Caps.Note）
//
// DryRun 是硬约束：dry-run 下不调用 Runner（一次都不），只把将要执行的命令
// 连同 stdin 内容构造出来交给调用方/测试断言。这条保证让「跑测试」和
// 「别把本机网络切断」两件事不再冲突。
package enforcer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

// MaxEntries 单后端阻断表上限。与 Python 版 pfhelper 的 500 条一致：
// 再多就不是「封禁几个攻击源」而是「全网段拉黑」，那是策略引擎的活。
const MaxEntries = 500

// DefaultAnchor 默认命名空间名。与 Python 版 --anchor 缺省值同名，
// 两版指向同一个 anchor 时规则可以互认（迁移期灰度用）。
const DefaultAnchor = "atfield"

// Command 一条待执行命令。Stdin 非空时以 stdin 喂给进程——
// pfctl 用 `-f -` 从 stdin 读规则，用参数传会把规则文本暴露在 ps 里。
type Command struct {
	Bin   string   `json:"bin"`
	Args  []string `json:"args"`
	Stdin string   `json:"stdin,omitempty"`
}

// String 便于日志与断言的可读形式（不含 stdin，规则文本可能很长）。
func (c Command) String() string {
	parts := make([]string, 0, len(c.Args)+1)
	parts = append(parts, c.Bin)
	parts = append(parts, c.Args...)
	return strings.Join(parts, " ")
}

// Runner 执行一条命令。生产实现是 ExecRunner，测试实现只记录不执行。
type Runner interface {
	Run(ctx context.Context, c Command) (stdout, stderr string, err error)
}

// ExecRunner 真执行。超时由 ctx 控制（调用方给 deadline），这里不另设。
type ExecRunner struct{}

// Run 执行命令并返回 stdout/stderr。
func (ExecRunner) Run(ctx context.Context, c Command) (string, string, error) {
	cmd := exec.CommandContext(ctx, c.Bin, c.Args...)
	if c.Stdin != "" {
		cmd.Stdin = strings.NewReader(c.Stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	return out.String(), errb.String(), err
}

// Target 一个通过校验的封禁目标（单地址或网段）。
type Target struct {
	// Raw 用户原始输入，仅用于错误信息与审计。
	Raw string
	// Net 归一化后的网段；单地址也表示为 /32 或 /128。
	Net *net.IPNet
}

// Key 稳定标识，同时是阻断表的键。与 Python 版 `str(net)` 同形
// （单地址带 /32），两版状态文件可以直接互读。
func (t Target) Key() string {
	if t.Net == nil {
		return ""
	}
	return t.Net.String()
}

// IsV6 是否 IPv6。
func (t Target) IsV6() bool { return t.Net != nil && t.Net.IP.To4() == nil }

// PrefixLen 前缀长度。
func (t Target) PrefixLen() int {
	if t.Net == nil {
		return 0
	}
	ones, _ := t.Net.Mask.Size()
	return ones
}

// ParseTarget 把用户输入变成一个可封禁的网段，并挡掉会造成自伤的目标。
//
// 这里的拒绝清单不是洁癖，每一条都对应一次真实事故：
//   - 回环：封了 127.0.0.1 本机服务立刻全断（控制台自己都连不上）
//   - 全零：0.0.0.0/:: 等价于「所有地址」，一封就是断网
//   - 组播：组播地址不是「一台主机」，封它没有意义还会影响发现协议
//   - 过宽：v4 短于 /8、v6 短于 /16 等于把半个互联网拉黑
func ParseTarget(raw string) (Target, error) {
	s := strings.TrimSpace(raw)
	if s == "" || len(s) > 64 {
		return Target{}, errors.New("地址为空或过长")
	}
	var ipnet *net.IPNet
	if strings.Contains(s, "/") {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return Target{}, fmt.Errorf("不是合法的 IP 或网段: %s", clip(s, 40))
		}
		ipnet = n
	} else {
		ip := net.ParseIP(s)
		if ip == nil {
			return Target{}, fmt.Errorf("不是合法的 IP 或网段: %s", clip(s, 40))
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
	}
	switch {
	case ipnet.IP.IsLoopback():
		return Target{}, errors.New("拒绝：回环地址（封了会断本机服务）")
	case ipnet.IP.IsUnspecified():
		return Target{}, errors.New("拒绝：0.0.0.0/:: 这类全零地址")
	case ipnet.IP.IsMulticast():
		return Target{}, errors.New("拒绝：组播地址")
	}
	minPrefix := 8
	if ipnet.IP.To4() == nil {
		minPrefix = 16
	}
	if ones, _ := ipnet.Mask.Size(); ones < minPrefix {
		return Target{}, fmt.Errorf("拒绝：网段过大（/%d），一封就是一片", ones)
	}
	return Target{Raw: raw, Net: ipnet}, nil
}

// Entry 阻断表里的一条。字段名对齐 Python 版 state["ips"][ip]
// （reason/ts/uid），actor 是 Go 版追加的追责字段。
type Entry struct {
	Reason string `json:"reason"`
	TS     int64  `json:"ts"`
	UID    int    `json:"uid"`
	Actor  string `json:"actor,omitempty"`
}

// Table 进程内阻断表。它是「期望状态」，后端负责把期望状态落到内核。
// 幂等判定全部基于这张表：表里已有 → 不重复下发命令。
type Table struct {
	mu    sync.Mutex
	m     map[string]Entry
	order []string
}

// NewTable 建空表。
func NewTable() *Table { return &Table{m: map[string]Entry{}} }

// Len 条数。
func (t *Table) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.m)
}

// Has 是否已在表内。
func (t *Table) Has(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.m[key]
	return ok
}

// Get 取一条。
func (t *Table) Get(key string) (Entry, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.m[key]
	return e, ok
}

// Put 写入并返回是否新增（已存在则覆盖，返回 false）。
func (t *Table) Put(key string, e Entry) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, existed := t.m[key]
	t.m[key] = e
	if !existed {
		t.order = append(t.order, key)
	}
	return !existed
}

// Delete 删除并返回是否真的删掉了。
func (t *Table) Delete(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.m[key]; !ok {
		return false
	}
	delete(t.m, key)
	for i, k := range t.order {
		if k == key {
			t.order = append(t.order[:i], t.order[i+1:]...)
			break
		}
	}
	return true
}

// Clear 清空，返回清掉的条数。
func (t *Table) Clear() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := len(t.m)
	t.m = map[string]Entry{}
	t.order = nil
	return n
}

// Keys 按加入顺序返回 key 副本（渲染/展示要稳定，不能受 map 随机序影响）。
func (t *Table) Keys() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]string, len(t.order))
	copy(out, t.order)
	return out
}

// SnapshotMap 返回 key → Entry 的副本（Status/API 用）。
func (t *Table) SnapshotMap() map[string]Entry {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[string]Entry, len(t.m))
	for k, v := range t.m {
		out[k] = v
	}
	return out
}

// Caps 后端能力声明。上层据此决定「能不能回滚」「要不要提示重启后失效」，
// 而不是假设三家行为一致。
type Caps struct {
	Backend  string `json:"backend"`
	DryRun   bool   `json:"dry_run"`
	Rollback bool   `json:"rollback"`
	Flush    bool   `json:"flush"`
	CIDR     bool   `json:"cidr"`
	IPv6     bool   `json:"ipv6"`
	Persist  bool   `json:"persist"`
	Root     bool   `json:"root_required"`
	Note     string `json:"note,omitempty"`
}

// Status 后端现状快照。available=false 时必须给 reason——绝不把
// 「读不到」伪装成「没有阻断」。
type Status struct {
	Backend   string           `json:"backend"`
	Available bool             `json:"available"`
	Reason    string           `json:"reason,omitempty"`
	Anchor    string           `json:"anchor,omitempty"`
	Attached  bool             `json:"attached"`
	IPS       map[string]Entry `json:"ips"`
	Count     int              `json:"count"`
	// Rules 后端里实际生效的规则条数（pf 读 anchor、nft 读 table）；
	// 读不到时保持 0，由 Reason 说明——不猜。
	Rules  int  `json:"rules"`
	DryRun bool `json:"dry_run"`
	Caps   Caps `json:"caps"`
}

// Result 一次操作的结果。字段名沿用 Python 版 pfhelper 的返回键
// （ok/detail/ip/dry_run/validated/removed/flushed/stage/rolled_back），
// 追加的只有 Go 侧需要的 backend/op/changed/skipped/commands/unsupported。
type Result struct {
	OK          bool      `json:"ok"`
	Backend     string    `json:"backend"`
	Op          string    `json:"op"`
	IP          string    `json:"ip,omitempty"`
	DryRun      bool      `json:"dry_run"`
	Changed     bool      `json:"changed"`
	Skipped     bool      `json:"skipped,omitempty"`
	Validated   bool      `json:"validated,omitempty"`
	Removed     bool      `json:"removed,omitempty"`
	Flushed     int       `json:"flushed,omitempty"`
	Stage       string    `json:"stage,omitempty"`
	RolledBack  bool      `json:"rolled_back,omitempty"`
	Unsupported bool      `json:"unsupported,omitempty"`
	Detail      string    `json:"detail,omitempty"`
	Err         string    `json:"error,omitempty"`
	Commands    []Command `json:"commands,omitempty"`
}

// Backend 封禁执行层接口。三平台各自实现；调用方只依赖这个接口。
//
// 约定：所有方法都不得 panic；失败必须回填 Result.Err/Detail。
// 实现必须自身线程安全（内部持锁），因为 HTTP 与调度器会并发调用。
type Backend interface {
	// Name 后端名：pf / nftables / netsh / unsupported。
	Name() string
	// Caps 能力声明。
	Caps() Caps
	// Status 读现状。DryRun 下不执行任何命令。
	Status(ctx context.Context) Status
	// Block 封禁。已在表内 → Skipped=true 且不下发命令（幂等）。
	Block(ctx context.Context, t Target, reason, actor string) Result
	// Unblock 解封。不在表内 → OK=true、Removed=false（幂等）。
	Unblock(ctx context.Context, t Target) Result
	// Flush 清空自己命名空间内的全部阻断。
	Flush(ctx context.Context) Result
	// Rollback 回到上一次成功下发前的状态；不支持的后端返回 Unsupported。
	Rollback(ctx context.Context) Result
}

// Options 构造后端的参数。零值可用：dry-run 关闭、anchor=atfield、真执行。
type Options struct {
	// DryRun 只构造命令不执行（也不读系统状态）。
	DryRun bool
	// Runner 命令执行器；nil 用 ExecRunner。
	Runner Runner
	// Anchor 命名空间名；空用 DefaultAnchor。
	Anchor string
	// Bin 覆盖可执行文件路径（测试/非标准安装位置）。
	Bin string
	// MaxEntries 阻断表上限；<=0 用 MaxEntries。
	MaxEntries int
	// Now 注入时钟（测试固定时间用）；nil 用 time.Now。
	Now func() time.Time
}

func (o Options) withDefaults() Options {
	if o.Anchor == "" {
		o.Anchor = DefaultAnchor
	}
	if o.Runner == nil {
		o.Runner = ExecRunner{}
	}
	if o.MaxEntries <= 0 {
		o.MaxEntries = MaxEntries
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return o
}

// backend 三个实现共用的骨架：表、锁、执行器、dry-run 开关、上次成功状态。
type backend struct {
	opts Options

	mu  sync.Mutex
	tbl *Table

	// lkgText pf 专用：上一次成功加载的 anchor 全文（回滚就重放它）。
	lkgText string
	// lkgEntries nft 专用：上一次成功下发后的期望集合（回滚就重建它）。
	lkgEntries []keyedEntry

	// attached 主规则集里是否已挂上本 anchor（只读探测结果，绝不自动挂）。
	attached bool
}

func newBackend(opts Options) *backend {
	return &backend{opts: opts.withDefaults(), tbl: NewTable()}
}

// run 依次执行命令。dry-run 时只把命令记进结果并返回 true——这是本包
// 最重要的一条不变式：dry-run 路径上 Runner 一次都不会被调用。
func (b *backend) run(ctx context.Context, cmds []Command, res *Result) bool {
	res.Commands = append(res.Commands, cmds...)
	if b.opts.DryRun {
		return true
	}
	for _, c := range cmds {
		out, errText, err := b.opts.Runner.Run(ctx, c)
		if err != nil {
			msg := firstNonEmpty(errText, out, err.Error())
			res.OK = false
			res.Err = clip(strings.TrimSpace(msg), 300)
			res.Detail = res.Err
			return false
		}
	}
	return true
}

// statusOf 填公共的 Status 字段。
func (b *backend) statusOf(name string) Status {
	ips := b.tbl.SnapshotMap()
	return Status{
		Backend:  name,
		Anchor:   b.opts.Anchor,
		Attached: b.attached,
		IPS:      ips,
		Count:    len(ips),
		DryRun:   b.opts.DryRun,
	}
}

// Unsupported 未支持平台的后端：不装死、不静默成功，直接说明原因。
type Unsupported struct {
	*backend
	reason string
}

// NewUnsupported 构造「本平台没有实现」的后端。
func NewUnsupported(opts Options, goos string) *Unsupported {
	return &Unsupported{backend: newBackend(opts),
		reason: fmt.Sprintf("平台 %s 暂无封禁实现（已实现 darwin/pf、linux/nftables、windows/netsh）", goos)}
}

// Name 后端名。
func (u *Unsupported) Name() string { return "unsupported" }

// Caps 能力声明：全否。
func (u *Unsupported) Caps() Caps {
	return Caps{Backend: u.Name(), DryRun: u.opts.DryRun, Note: u.reason}
}

// Status 永远 unavailable + 原因。
func (u *Unsupported) Status(context.Context) Status {
	st := u.statusOf(u.Name())
	st.Available = false
	st.Reason = u.reason
	st.Caps = u.Caps()
	return st
}

// Block 直接拒绝。
func (u *Unsupported) Block(_ context.Context, t Target, _, _ string) Result {
	return Result{Backend: u.Name(), Op: "block", IP: t.Key(), DryRun: u.opts.DryRun,
		OK: false, Unsupported: true, Detail: u.reason, Err: u.reason}
}

// Unblock 直接拒绝。
func (u *Unsupported) Unblock(_ context.Context, t Target) Result {
	return Result{Backend: u.Name(), Op: "unblock", IP: t.Key(), DryRun: u.opts.DryRun,
		OK: false, Unsupported: true, Detail: u.reason, Err: u.reason}
}

// Flush 直接拒绝。
func (u *Unsupported) Flush(context.Context) Result {
	return Result{Backend: u.Name(), Op: "flush", DryRun: u.opts.DryRun,
		OK: false, Unsupported: true, Detail: u.reason, Err: u.reason}
}

// Rollback 直接拒绝。
func (u *Unsupported) Rollback(context.Context) Result {
	return Result{Backend: u.Name(), Op: "rollback", DryRun: u.opts.DryRun,
		OK: false, Unsupported: true, Detail: u.reason, Err: u.reason}
}

// cleanReason 清洗写进规则注释的原因文本：去掉控制字符、把 # 换成全角，
// 避免注释提前结束导致后面的规则被当成注释吃掉（规则注入）。
func cleanReason(s string) string {
	var sb strings.Builder
	for _, ch := range s {
		if ch == '\t' {
			ch = ' '
		}
		if ch < 32 || ch == 127 {
			continue
		}
		if ch == '#' {
			sb.WriteRune('＃')
			continue
		}
		sb.WriteRune(ch)
	}
	return clip(strings.TrimSpace(sb.String()), 180)
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// 按 rune 截断，避免切出半个汉字
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// sortEntries 按 key 稳定排序（pf 渲染要可复现：同样的表必须渲染出同样的文本，
// 否则每次 block 都产生一次无意义的内核重载，回滚对比也失去意义）。
func sortEntries(m map[string]Entry) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
