package store

// jsonl.go —— append-only JSONL 文件句柄与原子重写。
//
// 为什么是 JSONL 而不是 SQLite：取证现场的存储介质可能是只读挂载、
// 可能是被写坏的 U 盘，JSONL 坏一行只丢一行，其余全部可读；
// SQLite 坏一个页就是整库打不开。Python 版选 JSONL 的理由同样成立，Go 版沿用。
//
// 为什么每次写都 fsync：告警落盘的价值在于「断电后还在」。攒批写省的那点 IO
// 换不来一次漏证据的代价。批量写共用一次 fsync，不是每条一次。

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// errClosed 存储已关闭。
var errClosed = errors.New("store: 已关闭")

// jsonlFile 一个 append-only JSONL 文件。
type jsonlFile struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	fh       *os.File
	written  int64
	rotateN  int
}

// openJSONL 打开（不存在则创建）一个 JSONL 文件，追加模式。
func openJSONL(path string, maxBytes int64) (*jsonlFile, error) {
	f := &jsonlFile{path: path, maxBytes: maxBytes}
	if err := f.open(); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *jsonlFile) open() error {
	fh, err := os.OpenFile(f.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("store: 打开 %s: %w", f.path, err)
	}
	f.fh = fh
	if st, err := fh.Stat(); err == nil {
		f.written = st.Size()
	}
	return nil
}

// appendRows 追加一批已序列化的 JSON 行（每行补换行），一次 fsync。
//
// 单行写失败不回滚已写部分：append-only 文件的语义就是「写了就是写了」，
// 回滚反而会制造一个洞。
func (f *jsonlFile) appendRows(rows [][]byte) error {
	if len(rows) == 0 {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fh == nil {
		return errClosed
	}

	// 一次写完整批：避免部分行落盘、部分行还在用户态缓冲。
	buf := make([]byte, 0, 512*len(rows))
	for _, r := range rows {
		buf = append(buf, r...)
		buf = append(buf, '\n')
	}
	n, err := f.fh.Write(buf)
	f.written += int64(n)
	if err != nil {
		return fmt.Errorf("store: 写 %s: %w", f.path, err)
	}
	if err := f.fh.Sync(); err != nil {
		return fmt.Errorf("store: fsync %s: %w", f.path, err)
	}

	if f.maxBytes > 0 && f.written >= f.maxBytes {
		f.rotateLocked()
	}
	return nil
}

// rotateLocked 超过阈值就把当前文件滚动一代：.4→.5, .3→.4, … , current→.1。
//
// 为什么保留多代而不是像 Python 只留 .1：只留一代时，轮转频率赶上采集频率
// （阈配小了，或者一天写满一次）就会把上一代直接覆盖掉——丢的是整整一代
// 告警，而且**不会有任何报错**。5 代 × 64MB 是 320MB 上限，可控。
func (f *jsonlFile) rotateLocked() {
	if f.fh == nil {
		return
	}
	_ = f.fh.Close()
	f.fh = nil

	// 最老的一代先删，再逐代后移
	oldest := fmt.Sprintf("%s.%d", f.path, maxRotations)
	_ = os.Remove(oldest)
	for i := maxRotations - 1; i >= 1; i-- {
		from := fmt.Sprintf("%s.%d", f.path, i)
		to := fmt.Sprintf("%s.%d", f.path, i+1)
		_ = os.Rename(from, to)
	}
	if err := os.Rename(f.path, f.path+".1"); err != nil {
		// 改名失败就继续写原文件，别把数据通道关了
		if err := f.open(); err != nil {
			return
		}
		f.rotateN++
		return
	}
	f.rotateN++
	if err := f.open(); err != nil {
		return
	}
	f.written = 0
}

// maxRotations 保留的历史代数。
const maxRotations = 5

func (f *jsonlFile) close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fh == nil {
		return nil
	}
	err := f.fh.Close()
	f.fh = nil
	return err
}

// readTailLines 从文件尾部倒着读，取最后 n 行（时间正序返回）。
//
// 事件回填专用：环形缓冲只留最新 maxEvents 条，而 events.jsonl 最大是
// 64MB × 5 代。整份读会白吃几百 MB 内存和几秒启动时间，换来的还是同一批
// 会被淘汰掉的行。倒着读到够数就停：20k 条事件约 8MB，比 320MB 快一个量级。
func readTailLines(path string, n int) [][]byte {
	if n <= 0 {
		return nil
	}
	fh, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer fh.Close()
	st, err := fh.Stat()
	if err != nil || st.Size() == 0 {
		return nil
	}

	const chunk = 256 * 1024
	var data []byte
	newlines := 0
	off := st.Size()
	for off > 0 && newlines <= n {
		size := int64(chunk)
		if size > off {
			size = off
		}
		buf := make([]byte, size)
		if _, err := fh.ReadAt(buf, off-size); err != nil {
			break
		}
		data = append(buf, data...)
		off -= size
		for _, b := range buf {
			if b == '\n' {
				newlines++
			}
		}
	}

	lines := splitRawBytes(data)
	// 没读到文件头时首行可能是被切断的半行，丢掉（半行 JSON 解不出来，
	// 留着只会被当成坏行跳过，丢掉还省一次解析）
	if off > 0 && len(lines) > 0 {
		lines = lines[1:]
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines
}

// splitRawBytes 按换行切分（去尾部 \r 与空格，跳过空行）。
func splitRawBytes(raw []byte) [][]byte {
	var out [][]byte
	start := 0
	for i := 0; i <= len(raw); i++ {
		if i < len(raw) && raw[i] != '\n' {
			continue
		}
		line := trimLine(raw[start:i])
		start = i + 1
		if len(line) > 0 {
			out = append(out, line)
		}
	}
	return out
}

// tailLinesRotated 跨全部留存代取最后 n 行（越新的代越先取）。
func tailLinesRotated(path string, n int) [][]byte {
	need := n
	var parts [][][]byte // 新→旧
	for i := 0; i <= maxRotations && need > 0; i++ {
		p := path
		if i > 0 {
			p = fmt.Sprintf("%s.%d", path, i)
		}
		lines := readTailLines(p, need)
		if len(lines) == 0 {
			continue
		}
		parts = append(parts, lines)
		need -= len(lines)
	}
	// 旧→新拼回
	total := 0
	for _, p := range parts {
		total += len(p)
	}
	out := make([][]byte, 0, total)
	for i := len(parts) - 1; i >= 0; i-- {
		out = append(out, parts[i]...)
	}
	return out
}

// scanJSONL 逐行流式读一个 JSONL 文件，把每行交给 fn。
//
// 为什么流式：events.jsonl 可能是 64MB × 5 代。一次性 os.ReadFile 会把几百 MB
// 塞进堆里，而环形缓冲最终只留最新 N 条——白吃内存换同一个结果。
// 流式读的时间开销只有磁盘 IO，内存只跟「留下了多少」有关，与文件大小无关。
//
// fn 返回 false 时提前停止（调用方凑够了就别再读了）。
// 坏行不在这里判断：fn 自己解不出来就跳过，历史坏行不能挡住启动。
func scanJSONL(path string, fn func(line []byte) bool) error {
	fh, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer fh.Close()

	// 初始 1MB，长行自动增长；单行上限 8MB（一条事件不可能这么大）
	r := bufio.NewReaderSize(fh, 1<<20)
	line := make([]byte, 0, 4096)
	for {
		chunk, err := r.ReadSlice('\n')
		if len(chunk) > 0 {
			line = append(line, chunk...)
		}
		if err == bufio.ErrBufferFull {
			if len(line) > 8<<20 {
				return fmt.Errorf("store: %s 有超长行", path)
			}
			continue
		}
		if len(line) > 0 {
			trimmed := trimLine(line)
			line = line[:0]
			if len(trimmed) > 0 {
				if !fn(trimmed) {
					return nil
				}
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// trimLine 去掉行尾的 \r 与空格。
func trimLine(line []byte) []byte {
	for len(line) > 0 && (line[len(line)-1] == '\r' || line[len(line)-1] == ' ') {
		line = line[:len(line)-1]
	}
	return line
}

// readJSONL 整份读（只用于小文件：审计分片校验、单测）。
func readJSONL(path string) ([][]byte, error) {
	var out [][]byte
	err := scanJSONL(path, func(line []byte) bool {
		out = append(out, append([]byte(nil), line...))
		return true
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// scanJSONLRotated 按「最老 → 最新」的顺序扫全部留存代。
//
// 只读当前文件会在轮转后丢掉上一代历史；只读 .1 会在多次轮转后丢中间代。
// 两处都会让告警行、以及它们的 count/首末样本静默消失。
func scanJSONLRotated(path string, fn func(line []byte) bool) {
	for i := maxRotations; i >= 1; i-- {
		if err := scanJSONL(fmt.Sprintf("%s.%d", path, i), fn); err != nil {
			continue
		}
	}
	_ = scanJSONL(path, fn)
}

// writeFileAtomic 原子重写一个小文件（工单表）。临时文件 + rename，
// 断电最多丢这一次写，不会留下半个文件。
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	fh, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("store: 建临时文件 %s: %w", tmp, err)
	}
	if _, err := fh.Write(data); err != nil {
		fh.Close()
		os.Remove(tmp)
		return fmt.Errorf("store: 写 %s: %w", tmp, err)
	}
	if err := fh.Sync(); err != nil {
		fh.Close()
		os.Remove(tmp)
		return fmt.Errorf("store: fsync %s: %w", tmp, err)
	}
	if err := fh.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// ---------------- 小工具 ----------------

// mustJSON 序列化，失败时返回一个可解析的错误对象而不是 panic。
// 存储层不该因为一个不可序列化的字段把采集线程带崩。
func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte(`{"__marshal_error__":"` + err.Error() + `"}`)
	}
	return b
}

func nowTS() float64 { return float64(time.Now().UnixNano()) / 1e9 }

func nowNano() int64 { return time.Now().UnixNano() }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// 按 rune 截，别把一个汉字切成半个
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

func lower(s string) string {
	b := []byte(s)
	changed := false
	for i := 0; i < len(b); i++ {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
			changed = true
		}
	}
	if !changed {
		return s
	}
	return string(b)
}

// containsFold 大小写不敏感的包含判断（ASCII 折叠）。
//
// 为什么不用 strings.Contains(strings.ToLower(hay), needle)：事件快照的每个
// 元素都要比一次，ToLower 会给每条事件复制一份完整字符串，20k 条事件的
// 面板查询凭空多出几 MB 垃圾。这里就地折叠，零分配。
//
// needle 必须已经是小写（调用方统一 lower 过一次）。
func containsFold(hay, lowerNeedle string) bool {
	n := len(lowerNeedle)
	if n == 0 {
		return true
	}
	for i := 0; i+n <= len(hay); i++ {
		match := true
		for j := 0; j < n; j++ {
			c := hay[i+j]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != lowerNeedle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func round1(v float64) float64 {
	return float64(int64(v*10+0.5)) / 10
}

// round3 与 Python round(x, 3) 一致（审计记录的 ts 精度）。
// 审计记录的 ts 在 Python 侧是 round(time.time(), 3)，Go 侧必须同样截断，
// 否则同一条记录两版算出的 hash 不同。
func round3(v float64) float64 {
	return math.Round(v*1000) / 1000
}

func shortID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%012x", time.Now().UnixNano()&0xffffffffffff)
	}
	const hexd = "0123456789abcdef"
	out := make([]byte, 12)
	for i, c := range b {
		out[i*2] = hexd[c>>4]
		out[i*2+1] = hexd[c&0x0f]
	}
	return string(out)
}
