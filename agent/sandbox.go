package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	actool "github.com/jintilm/praetor/internal/norma/tool"
	"github.com/jintilm/praetor/sandbox"
)

// SandboxExec 非 nil 时，worker 的 Bash 会被改路由到沙箱执行。
// 由 server 在启动期装配（见 server.WireSandbox），这里只做「有就用」。
var SandboxExec sandbox.Runner

// sandboxContainerRoot 是容器内的任务工作根（如 /work），由装配层在容器真的可用时写入。
// 只在启动期写一次，之后只读，所以用 atomic.Value 而不是锁。
//
// 它存在的唯一理由：Bash 的 cwd 必须与提示词里那条路径（Worker.promptRunDir 拼出的
// <root>/i<intentID>）严格一致。两处各写一个 "/work" 字面量迟早会分叉，所以根由装配层
// 单一来源注入，agent 侧只负责拼 "/i<id>"。
var sandboxContainerRoot atomic.Value // string

// SetSandboxContainerRoot 告知容器内工作根。空串 = 未宣告，Bash 的 cwd 交回 Runner
// 自己的 ContainerRoot（改造前行为）。
func SetSandboxContainerRoot(root string) {
	sandboxContainerRoot.Store(strings.TrimSpace(root))
}

// containerRunDir 返回本次 Bash 该在容器里的哪个目录执行。
func containerRunDir(ctx context.Context) string {
	root, _ := sandboxContainerRoot.Load().(string)
	if root == "" {
		return ""
	}
	if iid := RunInfoFrom(ctx).IntentID; iid > 0 {
		return path.Join(root, "i"+strconv.FormatInt(iid, 10))
	}
	return root
}

// SandboxMode 报告「worker 的 Bash 最终跑在哪里」。
//
// 由 server.WireSandbox 在启动期写入 —— 只有它知道探测结果（mode 环境变量、
// 隔离方式、Available() 的真实返回值）。agent 侧只读，不要自己在内部重猜环境：
// 重猜的两种错法（说 per-task 其实是宿主、说开着其实降级了）都要真跑才暴露。
type SandboxMode int32

const (
	// SandboxHost：没有装配过程序（CLI、单测），Bash 跑在宿主。零值取这个，
	// 与改造前的行为一致，不给未装配的调用方凭空造出"沙箱已就绪"的假象。
	SandboxHost SandboxMode = iota
	// SandboxOff：显式 PRAETOR_SANDBOX=off，Bash 跑在宿主。
	SandboxOff
	// SandboxContainer：Bash 真的跑在容器里。
	SandboxContainer
	// SandboxUnavailable：要求沙箱但 Docker/镜像不可用，执行时必然拒绝（fail-closed）。
	SandboxUnavailable
)

var sandboxMode atomic.Int32

// SandboxState 返回当前沙箱状态。
func SandboxState() SandboxMode { return SandboxMode(sandboxMode.Load()) }

// SetSandboxState 由 server 装配期写入。
func SetSandboxState(m SandboxMode) { sandboxMode.Store(int32(m)) }

func (m SandboxMode) String() string {
	switch m {
	case SandboxOff:
		return "off"
	case SandboxContainer:
		return "container"
	case SandboxUnavailable:
		return "unavailable"
	default:
		return "host"
	}
}

// bashRefusalReason 判断「本 worker 的 Bash 现在能不能用」，不能用时给出原因。
//
// 只针对需要 POSIX 语义的域（ctf/reverse/redteam）。三档判定：
//   - Bash 在容器里 → 可用，目标环境就在那；
//   - 沙箱被要求却不可用 → 拒（fail-closed，别让宿主替容器回答）；
//   - 其余情况看宿主 shell 是不是 POSIX：Linux 宿主上宿主 bash 就是 Linux shell，
//     老行为照旧可用；Windows 宿主上它可能是 PowerShell，命令行立刻语法错。
func bashRefusalReason(state SandboxMode, hostShellPOSIX bool) (string, bool) {
	switch state {
	case SandboxContainer:
		return "", false
	case SandboxUnavailable:
		return "Error: 本任务需要 Linux 环境，但沙箱被要求且当前不可用（Docker/镜像未就绪），" +
			"已拒绝在宿主执行 Bash。请让运维修好沙箱后端后重试；在此之前不要再用 Bash 猜命令，" +
			"改用 Read/Write/Grep/WebFetch 等宿主工具推进，或直接报告环境阻塞。", true
	}
	if !hostShellPOSIX {
		return "Error: 本任务需要 POSIX/Linux shell，但宿主 shell 不是 POSIX（未找到 Git Bash），" +
			"Bash 的 POSIX 语法（2>/dev/null、$()、管道、heredoc）在这里无法执行，已拒绝。" +
			"请让运维安装 Git for Windows 或启用沙箱；在此之前改用 Read/Write/Grep 等宿主工具，" +
			"不要再用 Bash 猜命令。", true
	}
	return "", false
}

// sandboxAgentKeys 决定哪些 agent 的 Bash 进沙箱。
//
// 目前只放 worker：它是唯一对目标发真实流量的角色，blast radius 最大。planner/mainagent
// 主要读写图与文件，若把它们的 Bash 也搬进容器，会出现「Read 读宿主、Bash 在容器」的
// 路径错位（模型看到 /work/x 但 Read 打不开），反而制造混乱。等 P1 引入统一的容器工作区
// 视图后，再把它们一起搬。
var sandboxAgentKeys = map[string]bool{"worker": true}

// ApplySandbox 把 Bash 换成沙箱执行版本（其它工具原样返回）。
// SandboxExec 为 nil 时完全不动，等价于改造前行为。
func ApplySandbox(agentKey string, tools []actool.CoreTool) []actool.CoreTool {
	if SandboxExec == nil || !sandboxAgentKeys[agentKey] {
		return tools
	}
	out := make([]actool.CoreTool, len(tools))
	for i, t := range tools {
		if t.Name() == "Bash" {
			out[i] = &sandboxedBash{CoreTool: t}
			continue
		}
		out[i] = t
	}
	return out
}

// sandboxedBash 是 Bash 的装饰器：名字/描述/schema/权限全部沿用 SDK 原实现，
// 只把「执行」这一层换成 sandbox.Runner，因此模型侧看到的工具没有变化。
type sandboxedBash struct{ actool.CoreTool }

func (b *sandboxedBash) Call(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	var req struct {
		Command         string `json:"command"`
		TimeoutMS       int    `json:"timeout_ms"`
		RunInBackground bool   `json:"run_in_background"`
	}
	if err := json.Unmarshal(in, &req); err != nil {
		return actool.Result{}, err
	}
	if strings.TrimSpace(req.Command) == "" {
		return actool.Errorf("Error: command is required"), nil
	}
	taskID := taskIDFromCtx(ctx)
	// 容器内的 cwd 必须和提示词（promptRunDir）说的那条路径一致。不传的话
	// per-task runner 回落到 ContainerRoot(/work)，于是提示词说"你在 /work/i190"、
	// 而 `pwd` 打出 /work —— 模型用相对路径写的产物全部落到任务根、两个并发意图
	// 还会互相覆盖。目录由 server.prepareIntentWorkDir 在任何 worker run 之前建好。
	workDir := containerRunDir(ctx)

	// 后台执行：per-task 容器实现了 BackgroundRunner（docker exec -d + 日志文件），
	// 交给它立即返回；常驻容器没有该能力时明确拒绝，绝不悄悄回退宿主执行。
	if req.RunInBackground {
		br, ok := SandboxExec.(sandbox.BackgroundRunner)
		if !ok {
			return actool.Errorf(fmt.Sprintf("当前沙箱后端不支持 run_in_background（%s）。请改为前台执行，或改用 per-task 隔离模式。", SandboxExec.Name())), nil
		}
		res, err := br.ExecBackground(ctx, sandbox.Request{Cmd: req.Command, TaskID: taskID, WorkDir: workDir})
		if err != nil {
			return actool.Errorf(fmt.Sprintf("后台启动失败：%v", err)), nil
		}
		return actool.Text(res.Stdout), nil
	}

	timeout := 120 * time.Second
	if req.TimeoutMS > 0 {
		timeout = time.Duration(req.TimeoutMS) * time.Millisecond
		if timeout > 600*time.Second {
			timeout = 600 * time.Second
		}
	}

	res, err := SandboxExec.Exec(ctx, sandbox.Request{Cmd: req.Command, Timeout: timeout, TaskID: taskID, WorkDir: workDir})
	// Bash 的既有语义是 stdout+stderr 合并回显；沙箱分管道收集，这里按 stdout→stderr 拼接。
	out := actool.Capture(tc, res.Stdout+res.Stderr)

	if err != nil {
		if errors.Is(err, sandbox.ErrUnavailable) {
			return actool.Errorf(fmt.Sprintf("沙箱不可用，已拒绝执行该命令。\n\n%s", err.Error())), nil
		}
		if out == "" {
			out = "(no output)"
		}
		return actool.Errorf(fmt.Sprintf("%s\n\n[failed to run in sandbox: %v]", out, err)), nil
	}
	if res.ExitCode != 0 {
		if out == "" {
			out = "(no output)"
		}
		return actool.Errorf(fmt.Sprintf("%s\n\n[exit code %d]", out, res.ExitCode)), nil
	}
	return actool.Text(out), nil
}

// taskIDFromCtx 取当前 worker run 的任务 id，用于 per-task 隔离。
// 没有任务上下文（chat 等）时返回空串，per-task 会落到 shared 容器。
func taskIDFromCtx(ctx context.Context) string {
	ri := RunInfoFrom(ctx)
	if ri.TaskID <= 0 {
		return ""
	}
	return fmt.Sprintf("%d", ri.TaskID)
}

// refusingBash 是 Bash 的装饰器：名字/描述/schema/权限全部保留，只让每次调用返回
// 一条自解释的拒绝。刻意不做成"把工具摘掉"——摘掉后模型看不到 Bash 存在，会以为是
// 自己记错了工具名，反复试别的名字；留着它、每次给出同一句原因，模型才会转向别的路径。
type refusingBash struct {
	actool.CoreTool
	reason string
}

func (r *refusingBash) Call(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
	return actool.Errorf(r.reason), nil
}

// refuseTool 把名为 name 的工具换成「永远拒绝」的版本（不存在则原样返回）。
func refuseTool(tools []actool.CoreTool, name, reason string) []actool.CoreTool {
	out := make([]actool.CoreTool, len(tools))
	copy(out, tools)
	for i, t := range out {
		if t.Name() == name {
			out[i] = &refusingBash{CoreTool: t, reason: reason}
		}
	}
	return out
}

// dropTool 按名字移除工具（不存在则原样返回一份拷贝）。
func dropTool(tools []actool.CoreTool, name string) []actool.CoreTool {
	out := make([]actool.CoreTool, 0, len(tools))
	for _, t := range tools {
		if t.Name() == name {
			continue
		}
		out = append(out, t)
	}
	return out
}
