// Package sandbox 提供「工具在隔离容器里执行」的统一入口。
//
// 为什么需要它：agent 的 Bash 工具默认在宿主进程里跑，一条 rm -rf 就能波及宿主机；
// 渗透/红队/CTF 场景还要装一大堆攻击工具，不能都塞进主镜像。
//
// 方案（形态 A）：**常驻工具容器 + docker exec**。
//   - 快：无冷启动；
//   - 简单：不依赖 Docker SDK，只调 CLI；
//   - 可替换：上层只认 Runner 接口，将来换「一任务一容器」不用动调度。
//
// 降级语义由 PRAETOR_SANDBOX 控制：
//
//	required（默认） Docker 不可用 → 直接拒绝执行，绝不悄悄跑在宿主上
//	optional         Docker 不可用 → 告警一次后降级到宿主执行（本地调试用）
//	off              永不使用沙箱（等价于改造前行为）
package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Mode 是沙箱工作模式。
type Mode string

const (
	ModeRequired Mode = "required"
	ModeOptional Mode = "optional"
	ModeOff      Mode = "off"
)

// EnvMode 是读取模式的环境变量名（不含前缀，由 config.Env 补 PRAETOR_）。
const EnvMode = "PRAETOR_SANDBOX"

// EnvContainer 指定常驻容器名，默认 praetor-sandbox。
const EnvContainer = "PRAETOR_SANDBOX_CONTAINER"

// DefaultContainer 与 docker-compose 里的服务对应。
const DefaultContainer = "praetor-sandbox"

// DefaultWorkDir 是容器内的工作目录（compose 把宿主 data 目录挂到这里）。
const DefaultWorkDir = "/work"

// ErrUnavailable 表示沙箱不可用（Docker 未运行 / 容器不存在）。
// required 模式下调用方应据此拒绝执行，而不是回退到宿主。
var ErrUnavailable = errors.New("sandbox unavailable")

// Request 是一次沙箱执行请求。
type Request struct {
	Cmd     string            // 要执行的命令（经 sh -lc 解释）
	WorkDir string            // 容器内工作目录；空 = Runner 默认
	Timeout time.Duration     // 0 = 默认 120s
	Env     map[string]string // 额外环境变量
}

// Result 是执行结果。故意只暴露合并前后都有的字段，调用方不需要关心底层是 docker 还是宿主。
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Runner   string // 实际执行的 Runner 名，进审计日志
}

// Flatten 返回适合直接回给模型的文本（与 Bash 工具的「合并输出」语义一致）。
func (r Result) Flatten() string {
	var b strings.Builder
	if r.Stdout != "" {
		b.WriteString(r.Stdout)
	}
	if r.Stderr != "" {
		if b.Len() > 0 && !strings.HasSuffix(b.String(), "\n") {
			b.WriteString("\n")
		}
		b.WriteString(r.Stderr)
	}
	if r.ExitCode != 0 {
		fmt.Fprintf(&b, "\n[exit code %d]", r.ExitCode)
	}
	return b.String()
}

// Runner 是执行后端。
type Runner interface {
	// Name 用于日志与审计（docker:<container> / host）。
	Name() string
	// Available 探测后端是否可用；nil 表示可用。
	Available(ctx context.Context) error
	// Exec 执行一条命令。非零退出码不算 error（体现在 Result.ExitCode），
	// error 只表示「没能执行」（容器不可用、启动失败等）。
	Exec(ctx context.Context, req Request) (Result, error)
}

// ModeFromEnv 解析 PRAETOR_SANDBOX；缺省/非法值一律 required（安全默认）。
func ModeFromEnv() Mode {
	switch Mode(strings.ToLower(strings.TrimSpace(os.Getenv(EnvMode)))) {
	case ModeOptional:
		return ModeOptional
	case ModeOff:
		return ModeOff
	default:
		return ModeRequired
	}
}

// ContainerFromEnv 解析 PRAETOR_SANDBOX_CONTAINER。
func ContainerFromEnv() string {
	if v := strings.TrimSpace(os.Getenv(EnvContainer)); v != "" {
		return v
	}
	return DefaultContainer
}

// Options 是 Select 的输入。
type Options struct {
	Mode      Mode
	Container string
	WorkDir   string
	// Warnf 用于一次性告警（optional 降级时）。nil = 丢弃。
	Warnf func(format string, args ...any)
}

// Select 按模式挑一个可用的 Runner。
//
// 返回值里的 Mode 是「实际生效的模式」：optional 降级后仍然是 optional，
// 调用方据此可以决定是否在 UI 上标注降级状态。
func Select(ctx context.Context, o Options) (Runner, Mode, error) {
	if o.Mode == "" {
		o.Mode = ModeRequired
	}
	if o.Container == "" {
		o.Container = DefaultContainer
	}
	if o.WorkDir == "" {
		o.WorkDir = DefaultWorkDir
	}

	if o.Mode == ModeOff {
		return &HostRunner{workDir: o.WorkDir}, ModeOff, nil
	}

	d := NewDocker(o.Container, o.WorkDir)
	if err := d.Available(ctx); err == nil {
		return d, o.Mode, nil
	} else if o.Mode == ModeOptional {
		warnOnce(o.Warnf, "沙箱不可用（%v），已按 %s=optional 降级为宿主执行——工具将直接跑在本机，仅限本地调试！", err, EnvMode)
		return &HostRunner{workDir: o.WorkDir}, ModeOptional, nil
	} else {
		return nil, o.Mode, fmt.Errorf("%w: 容器 %q 不可用（%v）。请 `docker compose up -d sandbox`，"+
			"或设 %s=optional 降级到宿主执行", ErrUnavailable, o.Container, err, EnvMode)
	}
}

var warnMu sync.Mutex
var warned = map[string]bool{}

// warnOnce 让同一条告警只出现一次，避免每个工具调用都刷屏。
func warnOnce(fn func(format string, args ...any), format string, args ...any) {
	if fn == nil {
		return
	}
	warnMu.Lock()
	defer warnMu.Unlock()
	if warned[format] {
		return
	}
	warned[format] = true
	fn(format, args...)
}

// Failing 返回一个「永远拒绝」的 Runner。
//
// 用途：required 模式下启动期探测就失败了，但服务仍需起来（否则连 UI 都进不去）。
// 这时不能把 SandboxExec 置空——置空等于不包 Bash，Bash 会**回落宿主执行**，
// 正好是 fail-open。必须注入一个会报错的 Runner，让每次调用都明确失败。
func Failing(cause error) Runner { return failingRunner{cause: cause} }

type failingRunner struct{ cause error }

func (f failingRunner) Name() string { return "unavailable" }

func (f failingRunner) Available(context.Context) error { return f.cause }

func (f failingRunner) Exec(context.Context, Request) (Result, error) {
	return Result{}, fmt.Errorf("%w: %v", ErrUnavailable, f.cause)
}
