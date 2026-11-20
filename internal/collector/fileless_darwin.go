//go:build darwin

package collector

// fileless_darwin.go —— macOS 侧取数：ps 命令行 + lsof 映像 + vmmap 匿名可执行段。
//
// 三条通道的能力与代价（都是本机 macOS 27.3 arm64 实测）：
//
//	ps -ww -axo 		 全量进程与命令行，~25ms，普通用户可用 → 每轮必跑
//	lsof -p PID -a -d txt +L1  链接数为 0 的 txt 映射，~30ms/进程 → 只对候选跑
//	vmmap -pages PID		 区域表，~520ms/进程，且只能看同 uid 或 root
//
// **降级是常态，不是异常**：
//   - 非 root 时 vmmap 对别人的进程直接报
//     "cannot examine process N (launchd) because you do not have appropriate
//      privileges to examine it"。这不是 bug，是 macOS 的任务端口模型。
//     拿不到就 MemProbed=false，判定层据此绝不下「没有匿名内存」的结论。
//   - macOS 上 /proc 不存在，ps 的 command 列也不会出现 "(deleted)"，
//     所以「映像已删除」只能靠 lsof 的 NLINK=0 判定（实测有效，见 fileless_parse.go）。
//
// 候选上限是有意的：vmmap 半秒一个，全量扫 400 个进程要 3 分钟。
// 只对「已经有一条可疑理由」的进程看内存——反正匿名可执行段的规则
// 本来就要求一个二次信号（fileless.go 规则 7）。

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// darwinMemProbeCap 每轮最多对几个进程跑 vmmap。
const darwinMemProbeCap = 4

// darwinLsofSoftCap 每轮最多带几个「软嫌疑」（临时目录/隐藏目录）进程一起查。
const darwinLsofSoftCap = 8

// darwinLsofGoneCap 「疑似映像已删除」候选的上限。
// 给得宽是因为这类候选本来就少（本机满载 1000+ 进程时个位数），
// 而漏掉一个真幽灵比多跑 20 次 lsof（每次 ~30ms）代价大得多。
const darwinLsofGoneCap = 32

func platformFilelessLimits() string {
	return "ps 命令行 + lsof 映像删除 + vmmap 匿名可执行段（仅同 uid 或 root，非 root 检查不了系统进程）；" +
		"实测 macOS 禁止无签名进程建 PROT_EXEC 匿名映射，匿名段基本只出现在 JIT 引擎"
}

func platformProbeFileless() error {
	if _, err := exec.LookPath("ps"); err != nil {
		return fmt.Errorf("缺少 ps，无法读取进程表（无文件检测的命令行通道不可用）")
	}
	// lsof/vmmap 缺失只降级、不致命：命令行与 ps 通道仍能工作，
	// 缺什么写在 Limits 里，控制台能看见能力边界。
	return nil
}

// platformFilelessFacts 采集一轮进程事实。
func platformFilelessFacts(ctx context.Context) ([]filelessFact, error) {
	procs, err := platformProcs(ctx)
	if err != nil {
		return nil, err
	}
	now := nowSeconds()
	facts := make([]filelessFact, 0, len(procs))
	// 两档候选：gone 是「stat 说不在了」的硬嫌疑，必须先验；
	// 其余（临时目录/解释器/隐藏目录）只是值得看一眼。混在一起排队会让
	// 一堆解释器把 8 个 lsof 名额吃光，真正被删的二进制反而查不到。
	var goneCand, softCand []int

	for _, pi := range procs {
		if pi.PID <= 1 || pi.Comm == "" {
			continue
		}
		// 命令行里还原真实 exe 路径（含空格的 .app 路径必须走这一步，
		// 否则整机浏览器/工具都会被判成「映像已删除」，实测 75 条误报）
		exe, exists := darwinResolveExe(pi.Args)
		f := filelessFact{
			Source: "ps", TS: now,
			PID: pi.PID, PPID: pi.PPID, HasPID: true,
			User: pi.User, Process: baseName(exe), Exe: exe, Cmdline: pi.Args,
		}
		// 「映像已删除」**只由 lsof 确认**，不靠 os.Stat 单独定案。
		//
		// 原因是两次实测教训：
		//   1) ps 的 command 列在 C locale 下会把非 ASCII 字节转义成 "M-eM^S…"
		//      这类**纯 ASCII 的假路径**，stat 必然失败 —— 本机 15 条中文 App
		//      因此被误判（isASCII 挡不住转义后的串）。
		//   2) ps 给的路径也可能是"看起来对但已被替换"的旧 inode。
		// lsof 的 NLINK=0 是内核级事实，且能拿到真实路径，所以拿它当唯一判据。
		// isASCII 在这里只是省 lsof 调用的粗筛：转义后的中文路径也是 ASCII，
		// 它挡不住误判——真正的判据是下面的 lsof 基名比对。
		gone := strings.HasPrefix(exe, "/") && !exists && isASCII(exe)
		// ps 在「可执行文件已经没了」时会打印 "(进程名)" 而不是路径
		// （本机实测：删掉 /var/folders 下自己编译的二进制后，command 列变成
		// "(af-ghost)"）。这不是路径，但它是「映像可能已删除」的强提示，
		// 所以同样进 lsof 候选，由 lsof 给出真实路径与 NLINK。
		if name, ok := darwinPsNameOnly(exe); ok {
			f.Process = name
			f.Exe = ""
			gone = true
		}
		f.ExeInTemp = isTempPath(exe)
		facts = append(facts, f)
		switch {
		case gone:
			goneCand = append(goneCand, len(facts)-1)
		// 解释器不进候选：判定规则 7（匿名可执行段）本来就要求一个二次信号
		// （映像已删除 / 临时目录 / 隐藏目录），光「是解释器」不够。
		// 而机器上 node/python/bash 有几十个，把它们排进 vmmap 队列
		// 会让每轮多花 2 秒（实测 --once 从 3.2s 降到 0.9s）。
		case f.ExeInTemp || hiddenDirSuspicious(exe):
			softCand = append(softCand, len(facts)-1)
		}
	}

	// 1) lsof 确认「映像真的没了」：处理「路径被替换成新文件但进程还在跑旧 inode」
	//    这种 os.Stat 看不出来的情况。
	//
	//    一次批量问（`lsof -p 1,2,3 ... +L1`）而不是逐进程问：lsof 每次启动
	//    150-200ms，16 个候选逐个问就是 3 秒。批量后整个 fileless 轮询
	//    从 3.4s 降到 0.4s（本机 --once 实测）。
	confirmed := map[int][]string{}
	{
		pids := make([]int, 0, len(goneCand)+len(softCand))
		for _, i := range goneCand {
			if facts[i].PID > 0 && len(pids) < darwinLsofGoneCap {
				pids = append(pids, facts[i].PID)
			}
		}
		nSoft := 0
		for _, i := range softCand {
			if nSoft >= darwinLsofSoftCap || len(pids) >= darwinLsofGoneCap+darwinLsofSoftCap {
				break
			}
			if facts[i].PID > 0 {
				pids = append(pids, facts[i].PID)
				nSoft++
			}
		}
		confirmed = lsofDeletedTxtBatch(ctx, pids)
	}

	// 只认「主映像」：lsof 的 txt 列表里还有 dyld、框架、JIT 缓存，只要有一个
	// 链接数为 0 就置 ImageDeleted，会把 osascript/python 这类加载了临时映射的
	// 进程全判成映像删除（本机实测 3 类误报）。判据是基名一致。
	for i := range facts {
		f := &facts[i]
		paths := confirmed[f.PID]
		if len(paths) == 0 {
			continue
		}
		want := baseName(f.Exe)
		if want == "" {
			want = f.Process // "(进程名)" 形态：用 ps 给的名字对齐
		}
		for _, p := range paths {
			if want == "" || baseName(p) != want {
				continue
			}
			f.ImageDeleted = true
			if f.Exe == "" {
				f.Exe = p
			}
			break
		}
	}

	// 2) vmmap 看匿名可执行段：只对候选，只对非 JIT（JIT 有也不报，省 0.5s）
	//    顺序仍是硬嫌疑优先：映像已删除的进程最值得看内存。
	withMem := 0
	for _, i := range append(goneCand, softCand...) {
		if withMem >= darwinMemProbeCap || ctx.Err() != nil {
			break
		}
		f := &facts[i]
		if isJITEngine(*f) {
			continue
		}
		withMem++
		if bytes, regions, ok := vmmapAnonExec(ctx, f.PID); ok {
			f.MemProbed = true
			f.AnonExecBytes = bytes
			f.AnonExecRegion = regions
		}
	}
	return facts, nil
}

// darwinTool 找一个系统工具的绝对路径。
//
// 为什么不能只用 exec.LookPath：lsof 在 /usr/sbin、vmmap 在 /usr/bin，
// 而 launchd 起的服务与 `go test` 的精简 PATH 里经常没有 /usr/sbin。
// 本机实测：go test 下 LookPath("lsof") 失败 → 幽灵进程（映像已删除）
// 一条都报不出来，而命令行里手动跑同样的命令一切正常。
func darwinTool(name string, fallbacks ...string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	for _, p := range fallbacks {
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return p
		}
	}
	return ""
}

// darwinPsNameOnly 识别 ps 的 "(进程名)" 形态（可执行路径不可用）。
func darwinPsNameOnly(exe string) (string, bool) {
	if len(exe) >= 3 && exe[0] == '(' && exe[len(exe)-1] == ')' {
		return exe[1 : len(exe)-1], true
	}
	return "", false
}

// darwinMaxExeSegs 还原 exe 路径时最多尝试几段（防护：命令行可能有上百个参数）。
//
// 实测校准：Chrome 的 Helper 路径
// "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome
//
//	Framework.framework/Versions/158/Helpers/Google Chrome Helper (Aperitif).app/
//	Contents/MacOS/Google Chrome Helper (Aperitif)" 有 11 段。
//
// 第一版设 8，Chrome 全家桶继续误报——校准到 24（路径长度另设上限）。
const darwinMaxExeSegs = 24

// darwinResolveExe 从命令行还原真实可执行文件路径，并告诉调用方它是否还在磁盘上。
//
// 为什么必须还原：ps 的 command 列不像 comm 那样截断，但它把「路径含空格」
// 这件事抹掉了——"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome
// --type=renderer ..." 按空格切第一段是 "/Applications/Google"，
// os.Stat 必然失败。本机实测：直接切第一段会把 Chrome / Clash / Hermes /
// Siri / 输入法等**全部 75 个进程**判成「映像已删除」。
//
// 做法：先试第一段（绝大多数进程一次命中）；不命中再按空格逐段加长，
// 取「最长的、真实存在的普通文件」。最坏 8 次 stat，只在异常路径上发生。
func darwinResolveExe(cmd string) (string, bool) {
	toks := strings.Fields(cmd)
	if len(toks) == 0 {
		return "", false
	}
	if fi, err := os.Stat(toks[0]); err == nil && !fi.IsDir() {
		return toks[0], true
	}
	n := len(toks)
	if n > darwinMaxExeSegs {
		n = darwinMaxExeSegs
	}
	best := ""
	for i := 1; i <= n; i++ {
		cand := strings.Join(toks[:i], " ")
		if len(cand) > 1024 { // 参数里的超长串不可能是路径
			break
		}
		if fi, err := os.Stat(cand); err == nil && !fi.IsDir() {
			best = cand // 继续往长里试：更长的命中说明路径里还有空格
		}
	}
	if best != "" {
		return best, true
	}
	return toks[0], false
}

// lsofDeletedTxt 返回该进程「链接数为 0 的 txt 映射」路径（空 = 没有）。
//
// 必须带 -d txt：不带的话系统 JIT 缓存（.plist-cache.*）也会冒出来，
// 本机实测一条命令就 5 条噪声。
func lsofDeletedTxt(ctx context.Context, pid int) []string {
	return lsofDeletedTxtBatch(ctx, []int{pid})[pid]
}

// lsofDeletedTxtBatch 批量确认多个 PID 的「已删除 txt 映射」，按 PID 分组返回。
//
// 为什么带 -d txt：不带的话系统 JIT 缓存（/private/var/db/diagnostics/logd/
// .plist-cache.*）也会出现在 +L1 结果里，本机实测一次 5 条噪声，
// 全都会被当成「映像已删除」。
//
// 超时 12 秒：`+L1` 要为每个打开文件取链接数，批量查 30+ 个进程时机器忙会慢，
// 给足时间比「超时后误判为没有」便宜——这里失败只会漏报，不会误报。
func lsofDeletedTxtBatch(ctx context.Context, pids []int) map[int][]string {
	out := map[int][]string{}
	if len(pids) == 0 {
		return out
	}
	bin := darwinTool("lsof", "/usr/sbin/lsof", "/usr/bin/lsof")
	if bin == "" {
		return out
	}
	const chunk = 24
	for len(pids) > 0 {
		n := chunk
		if n > len(pids) {
			n = len(pids)
		}
		group := pids[:n]
		pids = pids[n:]
		list := make([]string, 0, n)
		for _, pid := range group {
			list = append(list, itoa(pid))
		}
		text, err := runText(ctx, 12*time.Second, bin, "-p", strings.Join(list, ","), "-a", "-d", "txt", "+L1")
		if err != nil {
			continue // 这一批没查成就跳过：漏报优于误报
		}
		for pid, paths := range parseLsofTxtLinkZeroByPID(text) {
			out[pid] = append(out[pid], paths...)
		}
	}
	return out
}

// vmmapAnonExec 跑一次 vmmap -pages，解析匿名可执行段。
// ok=false 表示「没看成」（权限不足/超时/vmmap 缺失），调用方不得当成 0。
func vmmapAnonExec(ctx context.Context, pid int) (int64, int, bool) {
	bin := darwinTool("vmmap", "/usr/bin/vmmap", "/usr/local/bin/vmmap")
	if bin == "" {
		return 0, 0, false
	}
	out, err := runText(ctx, 2*time.Second, bin, "-pages", itoa(pid))
	if err != nil || out == "" {
		return 0, 0, false
	}
	if strings.Contains(out, "cannot examine process") || strings.Contains(out, "appropriate privileges") {
		return 0, 0, false
	}
	b, n := parseVMmapAnonExec(out)
	return b, n, true
}
