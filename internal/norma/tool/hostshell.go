package tool

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// Host shell resolution.
//
// Every Bash-family surface (foreground bash, background tasks, interactive PTY
// sessions) shells out through shellCmd(), so this one function decides which
// language the model's commands are interpreted in.
//
// On Windows the historical default was PowerShell. That is a lexical mismatch:
// the prompt and the model both speak POSIX (`2>/dev/null`, `$?`, `&&`, heredocs,
// `cut -d: -f1`, `for i in $(seq ...)`). Commands that work on every other host
// died on Windows with parser errors, costing whole tool calls. Windows now
// prefers a real POSIX shell (Git for Windows) and only falls back to PowerShell
// when none is installed.
//
// WSL's bash (C:\Windows\System32\bash.exe) is deliberately NOT a candidate: the
// working directory we hand the tool is a Win32 path like `E:\Code\...`, which
// does not exist inside the WSL mount namespace, so every command would fail on
// the initial `cd` before doing any work at all.

// hostShellEnv lets an operator pin the host shell explicitly, e.g.
// PRAETOR_HOST_SHELL=D:\tools\Git\bin\bash.exe. The value is taken verbatim (no
// existence check) so a typo surfaces as an exec error naming the bad path
// instead of silently degrading to PowerShell.
const hostShellEnv = "PRAETOR_HOST_SHELL"

var (
	// Plain -c on every platform, including Git Bash on Windows. Verified: the
	// MSYS runtime prepends /ucrt64/bin and /usr/bin to PATH at process start, so
	// sed/grep/awk/cut resolve without a profile. A login shell (-l) must NOT be
	// used: Git Bash's /etc/profile sources /etc/msystem, which prints
	// "/etc/msystem: line 26: /etc/msystem.d/MSYS: No such file or directory" to
	// stderr on every single invocation when MSYSTEM is unset, polluting the
	// captured output of every tool call.
	posixFlags = []string{"-c"}
	// PowerShell must never load a user profile (banners/prompts hang unattended
	// runs) and must not wait on interactive input.
	winPSFlags = []string{"-NoProfile", "-NonInteractive", "-Command"}

	winPSShell = "powershell"
	posixShell = "bash"
)

var (
	hostShellOnce sync.Once
	hostShellCmd  string
	hostShellArgs []string
)

// shellCmd returns the host shell and the flags that precede the command string.
// The probe hits the filesystem, so its result is cached: this is on the hot path
// of every Bash call and must not re-run LookPath each time.
func shellCmd() (string, []string) {
	hostShellOnce.Do(func() {
		hostShellCmd, hostShellArgs = resolveShell(runtime.GOOS, os.Getenv, exec.LookPath, os.Stat)
	})
	return hostShellCmd, hostShellArgs
}

// resolveShell picks the host shell for goos. getenv/lookpath/stat are injected
// so the resolution order is testable without a Windows host.
func resolveShell(goos string, getenv func(string) string, lookpath func(string) (string, error), stat func(string) (os.FileInfo, error)) (string, []string) {
	cmd, args, _ := resolveShellSource(goos, getenv, lookpath, stat)
	return cmd, args
}

// resolveShellSource is resolveShell plus the provenance of the decision
// ("环境变量 PRAETOR_HOST_SHELL" / "PATH" / "Git 安装目录" / "回退"), which the
// startup log needs: on someone else's machine the only useful question is
// "why did it end up as PowerShell", and answering it from a bare path is
// guesswork.
func resolveShellSource(goos string, getenv func(string) string, lookpath func(string) (string, error), stat func(string) (os.FileInfo, error)) (string, []string, string) {
	if goos != "windows" {
		return posixShell, posixFlags, "POSIX 宿主默认"
	}
	if p := strings.TrimSpace(getenv(hostShellEnv)); p != "" {
		return p, shellFlagsFor(p), "环境变量 " + hostShellEnv
	}
	for _, cand := range windowsShellCandidates(getenv, lookpath) {
		if !isUsablePOSIXShell(cand.path) {
			continue
		}
		if stat != nil {
			if _, err := stat(cand.path); err != nil {
				continue
			}
		}
		return cand.path, posixFlags, cand.src
	}
	return winPSShell, winPSFlags, "回退：未找到可用的 POSIX shell"
}

// LogHostShell emits the one startup line that makes shell problems diagnosable
// on a machine you cannot inspect: which shell Bash will use, and how it was
// chosen. Called once from main so it shows up even on tasks that never run a
// command (e.g. everything sandboxed).
func LogHostShell() {
	cmd, args, src := resolveShellSource(runtime.GOOS, os.Getenv, exec.LookPath, os.Stat)
	log.Printf("[shell] 宿主 shell: %s %v ← %s", cmd, args, src)
	if runtime.GOOS == "windows" && !isUsablePOSIXShell(cmd) {
		// 这条不是噪音：用户在 Windows 上跑 CTF/逆向类任务时，模型会发 POSIX 语法，
		// PowerShell 一条都解析不了。给出确切动作，别让人自己去猜哪里能改。
		log.Printf("[shell] 警告：没找到 Git Bash，Bash 将用 PowerShell 执行，POSIX 语法（2>/dev/null、$?、&&、heredoc）会失败；"+
			"装 Git for Windows 或设 %s=<…\\Git\\bin\\bash.exe> 后重启即可", hostShellEnv)
	}
}

// HostShellIsPOSIX reports whether shellCmd resolves to a POSIX shell.
//
// 供需要 Linux 语义的调用方（agent 的 ctf/reverse/redteam 域）判断"宿主 Bash 能不能
// 就当 Linux shell 用"：Linux 宿主上可以，Windows 上只有装了 Git Bash 才可以，
// 其余情况是 PowerShell —— 那已经不叫方言差异，是另一门语言。
func HostShellIsPOSIX() bool {
	sh, _ := shellCmd()
	return isUsablePOSIXShell(sh)
}

// shellCandidate 是"某条值得一试的 shell 路径 + 它是怎么被想到的"。
// 带上来源而不是靠下标反推：候选表会随布局继续增长，下标对不上时
// 日志会把"从 PATH 找到"说成"固定安装点"，正好骗过最需要这条日志的人。
type shellCandidate struct {
	path string
	src  string
}

// windowsShellCandidates lists POSIX shell paths worth probing, in priority
// order. LookPath comes first because it honours the operator's PATH, but it is
// not sufficient on its own: when WSL is installed it resolves to
// System32\bash.exe, which is rejected later, and the Git locations below are
// what actually save the run.
//
// The fixed install roots are not exhaustive. A real host checked during smoke
// testing carried its bash only at
// D:\Software\WorkBuddy\resources\vendor\PortableGit\usr\bin\bash.exe — neither
// ProgramFiles nor LOCALAPPDATA had a Git, so the whole candidate list missed
// and the run silently degraded to PowerShell, i.e. straight back to the bug
// this file exists to fix. Deriving the shell from whichever git.exe is on PATH
// covers every layout (Git for Windows, PortableGit, MSYS2) without hardcoding
// vendor paths.
func windowsShellCandidates(getenv func(string) string, lookpath func(string) (string, error)) []shellCandidate {
	var out []shellCandidate
	if lookpath != nil {
		if p, err := lookpath("bash.exe"); err == nil && p != "" {
			out = append(out, shellCandidate{p, "PATH 上的 bash.exe"})
		}
		// bash 之后再试 git 反推：我们要的是 bash（工具叫 Bash，语义也按 bash 写），
		// sh.exe 只是兜底，不能抢在它前面。
		for _, p := range gitDerivedShells(lookpath) {
			out = append(out, shellCandidate{p, "PATH 上的 git.exe 反推"})
		}
		// sh.exe 不会命中 System32（WSL 只装 bash.exe），所以这条没有 WSL 风险。
		if p, err := lookpath("sh.exe"); err == nil && p != "" {
			out = append(out, shellCandidate{p, "PATH 上的 sh.exe"})
		}
	}
	// 有序切片而不是 map：map 的迭代顺序随机，而这里"先 ProgramFiles 再
	// ProgramFiles(x86)"本身就是优先级（64 位安装在前面）。
	for _, r := range []struct{ env, label string }{
		{"ProgramFiles", "固定安装点 %ProgramFiles%\\Git"},
		{"ProgramW6432", "固定安装点 %ProgramW6432%\\Git"},
		{"ProgramFiles(x86)", "固定安装点 %ProgramFiles(x86)%\\Git"},
	} {
		root := getenv(r.env)
		if root == "" {
			continue
		}
		out = append(out, shellCandidate{filepath.Join(root, "Git", "bin", "bash.exe"), r.label})
	}
	if la := getenv("LOCALAPPDATA"); la != "" {
		out = append(out, shellCandidate{
			filepath.Join(la, "Programs", "Git", "bin", "bash.exe"), "固定安装点 %LOCALAPPDATA%\\Programs\\Git",
		})
	}
	if sd := getenv("SystemDrive"); sd != "" {
		out = append(out, shellCandidate{
			filepath.Join(sd+`\`, "msys64", "usr", "bin", "bash.exe"), "固定安装点 %SystemDrive%\\msys64",
		})
	}
	return out
}

// gitDerivedShells walks up from the git.exe found on PATH and offers every
// plausible POSIX shell next to it. Two directory levels are enough for the
// layouts in the wild: `...\Git\cmd\git.exe` (2 up = install root) and
// `...\PortableGit\mingw64\bin\git.exe` (2 up = install root), with
// `<root>\bin\bash.exe` and `<root>\usr\bin\bash.exe` as the two real shells.
func gitDerivedShells(lookpath func(string) (string, error)) []string {
	if lookpath == nil {
		return nil
	}
	git, err := lookpath("git.exe")
	if err != nil || strings.TrimSpace(git) == "" {
		return nil
	}
	var out []string
	dir := filepath.Dir(filepath.Clean(strings.Trim(git, `"`)))
	for i := 0; i < 3; i++ {
		out = append(out,
			filepath.Join(dir, "bin", "bash.exe"),
			filepath.Join(dir, "usr", "bin", "bash.exe"),
		)
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return out
}

// isUsablePOSIXShell rejects anything that is not a POSIX shell, and in
// particular WSL's bash, which cannot resolve Win32 paths.
func isUsablePOSIXShell(p string) bool {
	clean := strings.ToLower(filepath.Clean(strings.Trim(strings.TrimSpace(p), `"`)))
	switch strings.TrimSuffix(filepath.Base(clean), ".exe") {
	case "bash", "sh", "zsh", "dash":
	default:
		return false
	}
	unix := strings.ReplaceAll(clean, `\`, "/")
	if strings.Contains(unix, "/windows/system32/") || strings.Contains(unix, "/windows/sysnative/") {
		return false // WSL / LXSS stub.
	}
	return true
}

// shellFlagsFor maps an explicit PRAETOR_HOST_SHELL value to its flags. The value
// is expected to be a POSIX shell; PowerShell is recognised so an operator can
// pin the old behaviour.
func shellFlagsFor(path string) []string {
	base := strings.ToLower(strings.TrimSuffix(filepath.Base(strings.Trim(strings.TrimSpace(path), `"`)), ".exe"))
	if base == "powershell" || base == "pwsh" {
		return winPSFlags
	}
	return posixFlags
}
