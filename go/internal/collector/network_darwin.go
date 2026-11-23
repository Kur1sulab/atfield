//go:build darwin

package collector

// macOS 连接表：lsof。
//
// 为什么不是 netstat：macOS 26+ 的 netstat 已不再输出常规 TCP/UDP 表
// （只剩有限的几类统计），采集连接必须走 lsof。这是平台事实，不是选型偏好
// ——Python 版 network.py 起手也是 lsof，Go 版照抄同一数据源，对拍才可能一致。
//
// 为什么参数是 `-nP -i -w` 而不是 `-nP -iTCP -sTCP:ESTABLISHED`：
// 同一轮采集还要产出 net.listen 事件，`-sTCP:ESTABLISHED` 会把所有 LISTEN
// 行一起滤掉。拆成两次 lsof（一次 ESTABLISHED、一次 LISTEN）本机实测
// 43ms/次、491 行输出，5s 周期下多一次 fork 不划算，更要紧的是两次调用
// 取样时刻不同，刚建立又断开的连接在两份快照里会对不上，diff 会漏事件。
// 单次 `-i` 与 Python 版 `_from_lsof` 的参数完全同源。
//
// 已知边界（必须写进产品口径，不许假装完整）：
//   - **没有 root 时 lsof 只能看到当前用户的连接**——其他用户的 socket fd
//     不可读，lsof 直接跳过。普通用户运行时覆盖面 = 本用户 + 系统可见部分；
//     root 运行才是全机。这是 lsof 的权限语义，不是实现缺陷，Probe 不因此
//     判不可用（采一半比不采有用），但控制台应标明本机采集口径。
//   - `COMMAND` 列被 lsof 截断到 9 字符（`identitys`、`com.docke`），所以
//     `process` 字段只是前缀。Python 版拿到的同样是截断值，**故意不回填**：
//     回填会让两版 process 字段不等，对拍失效。要修就两版一起修。

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
)

// lsofPath 定位 lsof（macOS 自带在 /usr/sbin）。
func lsofPath() (string, error) {
	if p, err := exec.LookPath("lsof"); err == nil {
		return p, nil
	}
	for _, p := range []string{"/usr/sbin/lsof", "/usr/bin/lsof"} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", errors.New("找不到 lsof（macOS 自带 /usr/sbin/lsof，缺失说明系统被裁剪过）")
}

// platformProbeNet 可用性自检：lsof 在不在、能不能跑。
// 非 root 只影响覆盖范围，不影响可用性，所以这里不报错。
func platformProbeNet() error {
	p, err := lsofPath()
	if err != nil {
		return err
	}
	// -v 只打印版本，不需要权限，也不会因为「没有匹配的连接」返回 1
	if out, err := exec.Command(p, "-v").CombinedOutput(); err != nil && len(out) == 0 {
		return fmt.Errorf("lsof 无法执行: %w", err)
	}
	return nil
}

// platformConns 跑一次 lsof 并解析。
func platformConns(ctx context.Context) ([]netRow, error) {
	bin, err := lsofPath()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, bin, "-nP", "-i", "-w")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		// lsof 在「没有匹配项」时退出码为 1，那不算失败；只有一行输出都没有、
		// 且 stderr 有内容时才是真错误（缺权限 / 参数不支持）。
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return nil, fmt.Errorf("lsof 执行失败: %w", err)
		}
		if stdout.Len() == 0 {
			msg := firstLine(stderr.String())
			if msg == "" {
				msg = "无输出"
			}
			return nil, fmt.Errorf("lsof 执行失败: %s", msg)
		}
	}
	return parseLsof(stdout.String()), nil
}

func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			return s[:i]
		}
	}
	return s
}
