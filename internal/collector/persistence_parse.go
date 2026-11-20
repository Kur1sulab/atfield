package collector

// persistence_parse.go —— 各平台原生格式的解析器。
//
// 这一层故意**不带 build tag**：在 macOS 上 `go test ./...` 也能验证
// Windows 的 `reg query` / `schtasks` 输出解析、Linux 的 systemd unit 解析。
// 否则「Windows 采集器」在本机永远只有编译通过这一条证据，等于没测。
//
// plist 只用 encoding/xml + 手写最小结构（按任务约束不许引第三方库）。
// 二进制 plist 交给系统自带 plutil 转 XML（只读，输出到 stdout，不改文件）。

import (
	"bytes"
	"encoding/csv"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------- plist

// pval plist 的最小值模型：只认判定需要的类型。
type pval struct {
	kind string // string | array | dict | bool | integer | real | data | date | other
	s    string
	b    bool
	n    int64
	arr  []pval
	dict map[string]pval
}

func (v pval) asString() string {
	switch v.kind {
	case "string", "date", "data":
		return v.s
	case "integer":
		return strconv.FormatInt(v.n, 10)
	}
	return ""
}

// asBool plist 的 KeepAlive 可以是 <true/> 也可以是 <dict>（条件保活），
// 后者同样意味着「保活」，所以 dict 也算真。
func (v pval) asBool() bool {
	switch v.kind {
	case "bool":
		return v.b
	case "dict", "array":
		return true
	}
	return false
}

func (v pval) asStrings() []string {
	out := make([]string, 0, len(v.arr))
	for _, e := range v.arr {
		if s := e.asString(); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// plistFields launchd plist 里判定用得到的字段。
type plistFields struct {
	Label     string
	Program   string
	Args      []string
	RunAtLoad bool
	KeepAlive bool
}

func plistFieldsFromDict(d map[string]pval) plistFields {
	f := plistFields{
		Label:     d["Label"].asString(),
		Program:   d["Program"].asString(),
		Args:      d["ProgramArguments"].asStrings(),
		RunAtLoad: d["RunAtLoad"].asBool(),
		KeepAlive: d["KeepAlive"].asBool(),
	}
	if f.Program == "" && len(f.Args) > 0 {
		f.Program = f.Args[0]
	}
	return f
}

// parsePlistXML 解析 XML plist 的根 dict。
// 只支持 plist 的这几种元素；碰到不认识的元素整段跳过（Sockets/Environment
// 之类对判定无用，没必要为它们写结构体）。
func parsePlistXML(data []byte) (map[string]pval, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil, fmt.Errorf("plist: 没有找到根 dict")
		}
		if err != nil {
			return nil, fmt.Errorf("plist: %w", err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if se.Name.Local == "plist" {
			continue // 进到 <plist> 里继续找第一个值元素
		}
		v, err := parsePlistValue(dec, se)
		if err != nil {
			return nil, err
		}
		if v.kind != "dict" {
			return nil, fmt.Errorf("plist: 根节点是 <%s>，期望 <dict>", se.Name.Local)
		}
		return v.dict, nil
	}
}

func parsePlistValue(dec *xml.Decoder, se xml.StartElement) (pval, error) {
	switch se.Name.Local {
	case "dict":
		d := make(map[string]pval)
		var key string
		for {
			tok, err := dec.Token()
			if err != nil {
				return pval{}, err
			}
			switch t := tok.(type) {
			case xml.StartElement:
				if t.Name.Local == "key" {
					k, err := elementText(dec, t)
					if err != nil {
						return pval{}, err
					}
					key = strings.TrimSpace(k)
					continue
				}
				v, err := parsePlistValue(dec, t)
				if err != nil {
					return pval{}, err
				}
				if key != "" {
					d[key] = v
					key = ""
				}
			case xml.EndElement:
				return pval{kind: "dict", dict: d}, nil
			}
		}
	case "array":
		var arr []pval
		for {
			tok, err := dec.Token()
			if err != nil {
				return pval{}, err
			}
			switch t := tok.(type) {
			case xml.StartElement:
				v, err := parsePlistValue(dec, t)
				if err != nil {
					return pval{}, err
				}
				arr = append(arr, v)
			case xml.EndElement:
				return pval{kind: "array", arr: arr}, nil
			}
		}
	case "true", "false":
		if err := skipElement(dec, se); err != nil {
			return pval{}, err
		}
		return pval{kind: "bool", b: se.Name.Local == "true"}, nil
	case "string", "date", "data":
		s, err := elementText(dec, se)
		return pval{kind: se.Name.Local, s: s}, err
	case "integer":
		s, err := elementText(dec, se)
		n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		return pval{kind: "integer", s: strings.TrimSpace(s), n: n}, err
	case "real":
		s, err := elementText(dec, se)
		f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
		return pval{kind: "real", s: strings.TrimSpace(s), n: int64(f)}, err
	default:
		if err := skipElement(dec, se); err != nil {
			return pval{}, err
		}
		return pval{kind: "other"}, nil
	}
}

func elementText(dec *xml.Decoder, se xml.StartElement) (string, error) {
	var b strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			return b.String(), err
		}
		switch t := tok.(type) {
		case xml.CharData:
			b.Write(t)
		case xml.EndElement:
			return b.String(), nil
		}
	}
}

func skipElement(dec *xml.Decoder, se xml.StartElement) error {
	depth := 1
	for depth > 0 {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		switch tok.(type) {
		case xml.StartElement:
			depth++
		case xml.EndElement:
			depth--
		}
	}
	return nil
}

// ---------------------------------------------------------------- cron

// cronEntry 一行 crontab 的解析结果。
type cronEntry struct {
	Schedule string
	User     string // 仅系统格式（/etc/crontab、/etc/cron.d/*）有
	Command  string
}

// parseCronLine 解析 crontab 一行。hasUser=true 表示系统格式（第 6 列是用户）。
// 环境变量行（SHELL=/bin/sh）、注释、空行都不是任务，返回 false。
func parseCronLine(line string, hasUser bool) (cronEntry, bool) {
	s := strings.TrimSpace(line)
	if s == "" || strings.HasPrefix(s, "#") {
		return cronEntry{}, false
	}
	// NAME=value：等号左边没有空格才是环境变量行
	if i := strings.IndexByte(s, '='); i > 0 && !strings.ContainsAny(s[:i], " \t") {
		return cronEntry{}, false
	}
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return cronEntry{}, false
	}
	var e cronEntry
	idx := 0
	if strings.HasPrefix(fields[0], "@") {
		e.Schedule = fields[0]
		idx = 1
	} else {
		if len(fields) < 6 {
			// 5 个时间列 + 至少 1 列命令（系统格式再加 1 列用户）
			return cronEntry{}, false
		}
		e.Schedule = strings.Join(fields[:5], " ")
		idx = 5
	}
	if hasUser {
		if idx >= len(fields) {
			return cronEntry{}, false
		}
		e.User = fields[idx]
		idx++
	}
	if idx >= len(fields) {
		return cronEntry{}, false
	}
	e.Command = strings.Join(fields[idx:], " ")
	return e, true
}

// ---------------------------------------------------------------- systemd

// systemdUnit 一个 .service 里判定用得到的字段。
type systemdUnit struct {
	Description string
	Exec        []string
	Restart     string
	User        string
	WorkDir     string
	WantedBy    []string
}

// parseSystemdUnit 解析 unit 文件。行尾 `\` 是续行；ExecStart= 空赋值表示
// 清空之前的赋值（systemd 的真实语义，攻击者常用它把合法启动项抹掉）。
func parseSystemdUnit(text string) systemdUnit {
	var u systemdUnit
	for _, ln := range joinContinuations(text) {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") || strings.HasPrefix(ln, ";") {
			continue
		}
		k, v, ok := strings.Cut(ln, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "Description":
			u.Description = v
		case "ExecStart":
			if v == "" {
				u.Exec = nil
				continue
			}
			u.Exec = append(u.Exec, stripSystemdPrefixes(v))
		case "Restart":
			u.Restart = v
		case "User":
			u.User = v
		case "WorkingDirectory":
			u.WorkDir = v
		case "WantedBy":
			u.WantedBy = append(u.WantedBy, strings.Fields(v)...)
		}
	}
	return u
}

// stripSystemdPrefixes 去掉 ExecStart 前的 `-`/`@`/`+`/`!` 修饰符，
// 否则 Program 会以 "-" 开头，路径判定永远判不存在。
func stripSystemdPrefixes(v string) string {
	v = strings.TrimSpace(v)
	for len(v) > 0 && strings.IndexByte("-@+!:", v[0]) >= 0 {
		v = strings.TrimSpace(v[1:])
	}
	return v
}

func joinContinuations(text string) []string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	var out []string
	var cur strings.Builder
	for _, ln := range strings.Split(text, "\n") {
		t := strings.TrimRight(ln, " \t")
		if strings.HasSuffix(t, "\\") {
			cur.WriteString(strings.TrimSuffix(t, "\\"))
			cur.WriteString(" ")
			continue
		}
		cur.WriteString(t)
		out = append(out, cur.String())
		cur.Reset()
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// ---------------------------------------------------------------- 注册表

// regEntry `reg query` 输出里的一行值。
type regEntry struct {
	Key   string
	Name  string
	Type  string
	Value string
}

// parseRegQuery 解析 `reg query <key>` 的输出：
//
//	HKEY_LOCAL_MACHINE\SOFTWARE\...\Run
//	    SecurityHealth    REG_EXPAND_SZ    C:\Windows\system32\SecurityHealthSystray.exe
//
// 值本身可以含空格，所以以「第一个 REG_ 开头的列」为类型列切分，而不是按列号。
func parseRegQuery(text string) []regEntry {
	var out []regEntry
	key := ""
	for _, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "HKEY_") || strings.HasPrefix(trimmed, "HKLM\\") || strings.HasPrefix(trimmed, "HKCU\\") {
			key = trimmed
			continue
		}
		fields := strings.Fields(line)
		typeIdx := -1
		for i, f := range fields {
			if strings.HasPrefix(f, "REG_") {
				typeIdx = i
				break
			}
		}
		if typeIdx <= 0 || key == "" {
			continue
		}
		out = append(out, regEntry{
			Key:   key,
			Name:  strings.Join(fields[:typeIdx], " "),
			Type:  fields[typeIdx],
			Value: strings.Join(fields[typeIdx+1:], " "),
		})
	}
	return out
}

// ---------------------------------------------------------------- 计划任务

// schedTask `schtasks /query /fo csv /v` 里的一行。
type schedTask struct {
	Name     string
	Run      string
	Status   string
	Schedule string
}

// parseSchtasksCSV 解析 CSV 格式的计划任务表。
// 表头在中文系统上是本地化的（「任务名」「要运行的任务」），
// 所以列名匹配同时接受英文与中文，缺列时退化为按已知英文列名的位置猜。
func parseSchtasksCSV(text string) []schedTask {
	r := csv.NewReader(strings.NewReader(strings.TrimPrefix(text, "\ufeff")))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	recs, err := r.ReadAll()
	if err != nil || len(recs) < 2 {
		return nil
	}
	hdr := recs[0]
	find := func(names ...string) int {
		for i, h := range hdr {
			h = strings.TrimSpace(h)
			for _, n := range names {
				if strings.EqualFold(h, n) {
					return i
				}
			}
		}
		return -1
	}
	iName := find("TaskName", "任务名")
	iRun := find("Task To Run", "要运行的任务")
	iStatus := find("Status", "状态")
	iSched := find("Schedule Type", "计划类型")
	if iName < 0 {
		return nil
	}
	get := func(rec []string, i int) string {
		if i < 0 || i >= len(rec) {
			return ""
		}
		return strings.TrimSpace(rec[i])
	}
	var out []schedTask
	for _, rec := range recs[1:] {
		name := get(rec, iName)
		if name == "" || strings.EqualFold(name, "TaskName") {
			continue
		}
		out = append(out, schedTask{
			Name:     name,
			Run:      get(rec, iRun),
			Status:   get(rec, iStatus),
			Schedule: get(rec, iSched),
		})
	}
	return out
}

// ---------------------------------------------------------------- 命令行

// commandToProgram 从一行命令里取出可执行文件路径。
//
// 三种形态都要处理，否则 prog-* 判定会全部落空或误判：
//   - 带引号："C:\Program Files\A\a.exe" -k
//   - 裸路径带空格：C:\Program Files\A\a.exe -k   （注册表里非常常见）
//   - 无扩展名：/usr/bin/python3 script.py
func commandToProgram(cmd string) string {
	s := strings.TrimSpace(cmd)
	if s == "" {
		return ""
	}
	if s[0] == '"' {
		if i := strings.IndexByte(s[1:], '"'); i >= 0 {
			return s[1 : i+1]
		}
		return strings.Trim(s, `"`)
	}
	if s[0] == '\'' {
		if i := strings.IndexByte(s[1:], '\''); i >= 0 {
			return s[1 : i+1]
		}
	}
	low := strings.ToLower(s)
	for _, ext := range []string{".exe", ".com", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".scr", ".pif"} {
		i := strings.Index(low, ext)
		if i < 0 {
			continue
		}
		end := i + len(ext)
		if end == len(s) || s[end] == ' ' || s[end] == '\t' || s[end] == ',' {
			return s[:end]
		}
	}
	if i := strings.IndexAny(s, " \t"); i > 0 {
		return s[:i]
	}
	return s
}

// normalizeWinPath 统一成小写 + 反斜杠，供 Windows 前缀判定用。
func normalizeWinPath(p string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(p)), "/", winSep)
}

// winSep 反斜杠。用常量而不是字面量：源码里到处写转义反斜杠极易出错。
const winSep = `\`

// Windows 临时/共享目录与用户可写目录的判定放在这里（不带 build tag），
// 好让 macOS 上的 `go test` 也能验证 Windows 的判定——否则 Windows 采集器
// 在本机永远只有「编译通过」这一条证据。
var winTempFragments = []string{
	winSep + `windows` + winSep + `temp` + winSep,
	winSep + `appdata` + winSep + `local` + winSep + `temp` + winSep,
	winSep + `users` + winSep + `public` + winSep,
	winSep + `temp` + winSep,
	winSep + `programdata` + winSep + `temp` + winSep,
}

// winTempPath 是否落在临时/共享目录。
func winTempPath(p string) bool {
	n := normalizeWinPath(p)
	for _, frag := range winTempFragments {
		if strings.Contains(n, frag) {
			return true
		}
	}
	return false
}

// winUserBinaryPath 是否落在普通用户可写目录（不含 ProgramData：那是管理员
// 可写的正规安装位置，Defender 自己就住在 ProgramData\Microsoft\Windows Defender）。
func winUserBinaryPath(p string) bool {
	n := normalizeWinPath(p)
	for _, frag := range []string{winSep + `users` + winSep, winSep + `appdata` + winSep} {
		if strings.Contains(n, frag) {
			return true
		}
	}
	return false
}
