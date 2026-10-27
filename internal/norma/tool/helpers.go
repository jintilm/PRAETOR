package tool

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

const defaultMaxOutput = 30000

func maxOut(tc *ToolContext) int {
	if tc != nil && tc.MaxOutputChars > 0 {
		return tc.MaxOutputChars
	}
	return defaultMaxOutput
}

var spillSeq atomic.Int64

// Capture bounds a tool's textual output for the model. When the output exceeds
// the limit (ToolContext.MaxOutputChars, default 30000) and the host configured
// an OutputDir, the FULL output is written to a file there and a tight head + a
// pointer to that file is returned — so the model can read slices on demand
// (grep/sed) instead of losing the overflow. Without an OutputDir it falls back
// to a head+tail truncation (the overflow is discarded). Tools that produce
// potentially large output should return Capture(tc, output) rather than the raw
// string.
func Capture(tc *ToolContext, s string) string {
	max := maxOut(tc)
	if len(s) <= max {
		return s
	}
	if tc != nil && tc.OutputDir != "" {
		if path, err := spillOutput(tc.OutputDir, s); err == nil {
			ref := path
			if tc.WorkingDir != "" {
				if rel, e := filepath.Rel(tc.WorkingDir, path); e == nil && !strings.HasPrefix(rel, "..") {
					ref = rel
				}
			}
			lines := strings.Count(s, "\n") + 1
			return s[:max] + fmt.Sprintf(
				"\n\n... <persisted-output>[Output too large: full %d bytes / %d lines.Full output saved to  %s </persisted-output>",
				len(s), lines, ref)
		}
	}
	return truncate(s, max)
}

// alreadyCaptured reports whether s already carries a marker Capture leaves
// behind — a spill pointer or a head+tail truncation notice. It is how a global
// post-tool net recognises output a tool already ran through Capture itself.
//
// A false negative (legitimate text that happens to contain a marker) only means
// the guard fails to re-cap already-large output; it never corrupts. The markers
// are distinctive enough that this is vanishingly rare.
func alreadyCaptured(s string) bool {
	return strings.Contains(s, "<persisted-output>") || strings.Contains(s, "characters truncated]")
}

// CaptureOnce is Capture with an idempotency guard: output a tool already ran
// through Capture (so it carries a spill pointer or truncation notice) is
// returned unchanged. This lets a single post-tool net cap every tool's output
// without re-truncating or re-spilling what built-in / MCP / custom tools
// already handled themselves. Output within the limit is a no-op either way,
// since Capture returns it unchanged.
func CaptureOnce(tc *ToolContext, s string) string {
	if alreadyCaptured(s) {
		return s
	}
	return Capture(tc, s)
}

func spillOutput(dir, s string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	name := fmt.Sprintf("output-%d-%d.txt", time.Now().Unix(), spillSeq.Add(1))
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// resolvePath joins a relative path against the working directory.
func resolvePath(tc *ToolContext, p string) string {
	// 沙箱优先：命中挂载点就翻成宿主路径，之后的 os.ReadDir/os.Open 才打得开。
	// 这一步必须在 IsAbs 判断之前——容器内路径以 "/" 开头，而 Windows 的 filepath.IsAbs
	// 不认它，会把它当相对路径拼到工作目录下（报错信息里会突兀地出现宿主的 data 目录）。
	if tc != nil && tc.SandboxPath != nil {
		if host, ok := tc.SandboxPath(p); ok {
			return host
		}
		// 沙箱模式下，以 "/" 开头却没命中挂载点 = 容器里那条路径在宿主上没有对应位置
		// （比如 /etc/passwd、/usr/bin/xx）。原样返回让 os 去报 ENOENT ——
		// 比拼到工作目录下"假装找到一个同名文件"诚实得多，也避免把宿主文件当成容器文件。
		//
		// 只在沙箱模式这么做：宿主模式（渗透任务）下 "/" 开头的相对写法是既有行为，
		// 改它会波及与沙箱无关的任务。
		if strings.HasPrefix(filepath.ToSlash(p), "/") {
			return p
		}
	}
	if filepath.IsAbs(p) || tc == nil || tc.WorkingDir == "" {
		return p
	}
	return filepath.Join(tc.WorkingDir, p)
}

// denyReadOnly 拦下「往只读挂载里写」。
//
// 容器里 /chal 是 `-v ...:ro`，Bash 写不进去；但写文件的三件工具（Write/Edit/MultiEdit）
// 跑在宿主进程上，拿到的是普通宿主路径 —— 内核不知道"这块在容器里是只读的"，
// 于是会真的写进题面目录。没有答案文件的题，脱敏视图就是题库原目录本身，
// 一次误写会污染之后所有跑同一道题的运行，而现象只是"题目好像被改坏了"。
//
// 报错要说明原因，否则模型会以为路径打错了、换个写法重试。
func denyReadOnly(tc *ToolContext, p string) error {
	if tc == nil || tc.SandboxReadOnly == nil || !tc.SandboxReadOnly(p) {
		return nil
	}
	return fmt.Errorf("Error: %s 是只读挂载（题面附件），不能修改；把产物写到工作目录（如 /work/ 下）", p)
}

// truncate trims s to max characters, keeping head and tail.
func truncate(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	half := max / 2
	return s[:half] + fmt.Sprintf("\n\n... [%d characters truncated] ...\n\n", len(s)-max) + s[len(s)-half:]
}
