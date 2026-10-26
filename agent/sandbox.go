package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/praetor/sandbox"
)

// SandboxExec 非 nil 时，worker 的 Bash 会被改路由到沙箱执行。
// 由 server 在启动期装配（见 server.WireSandbox），这里只做「有就用」。
var SandboxExec sandbox.Runner

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

	// 后台执行：per-task 容器实现了 BackgroundRunner（docker exec -d + 日志文件），
	// 交给它立即返回；常驻容器没有该能力时明确拒绝，绝不悄悄回退宿主执行。
	if req.RunInBackground {
		br, ok := SandboxExec.(sandbox.BackgroundRunner)
		if !ok {
			return actool.Errorf(fmt.Sprintf("当前沙箱后端不支持 run_in_background（%s）。请改为前台执行，或改用 per-task 隔离模式。", SandboxExec.Name())), nil
		}
		res, err := br.ExecBackground(ctx, sandbox.Request{Cmd: req.Command, TaskID: taskID})
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

	res, err := SandboxExec.Exec(ctx, sandbox.Request{Cmd: req.Command, Timeout: timeout, TaskID: taskID})
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
