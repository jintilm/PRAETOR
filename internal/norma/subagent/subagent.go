// Package subagent lets the agent delegate to isolated child agents (FR-09).
// A subagent reuses the same harness loop with its own prompt, tool subset, and
// permission mode, giving context isolation. It is exposed to the parent as an
// "Agent" CoreTool; recursion is bounded by a depth guard carried on the
// context.
package subagent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/jintilm/praetor/internal/norma/harness"
	"github.com/jintilm/praetor/internal/norma/llm"
	"github.com/jintilm/praetor/internal/norma/permission"
	"github.com/jintilm/praetor/internal/norma/tool"
	"github.com/jintilm/praetor/internal/norma/transcript"
)

// Definition configures a named subagent (FR-09.1).
type Definition struct {
	Description    string          // shown to the parent model in the Agent tool prompt
	Prompt         []string        // the subagent's system prompt
	Tools          []string        // tool names it may use (empty = inherit all)
	PermissionMode permission.Mode // its permission mode (default: parent's)
	MaxTurns       int
	// MaxDuration bounds THIS child's wall clock (0 = inherit the parent's run
	// deadline, i.e. the pre-P1-4 behaviour). It exists because the parent's run
	// timeout used to be the child's death sentence: the child inherited the
	// parent's toolCtx deadline, so at the parent's 20-minute mark every subagent
	// in flight was cut mid-tool with no wrap-up and no partial output — the whole
	// dispatch was then thrown away and retried (task 35 burned 2x that way).
	//
	// Sizing rule: keep MaxDuration comfortably below the parent's run budget minus
	// dispatchSettleMargin. If it exceeds what the parent has left, run() no longer
	// refuses outright — it clamps this child's wall clock to the remaining time
	// (down to minSubagentWall) so a late dispatch still produces a settled result.
	// A declared value larger than the whole run budget is still a configuration
	// smell: the child would always run on a shortened leash. The server layer warns
	// about that pair at startup.
	MaxDuration time.Duration
	// Provider, when non-nil, overrides Config.Provider for THIS agent only —
	// per-role model binding (e.g. a local model for reverse analysts while the
	// lead rides the task's cloud provider). nil = inherit the shared one.
	Provider llm.Provider
}

// Config wires the Agent tool.
type Config struct {
	Provider    llm.Provider
	ParentTools *tool.Registry
	Agents      map[string]Definition
	MaxDepth    int // default 3
	CanUseTool  permission.CanUseTool
	Hooks       harness.HookRunner
	// Transcript, when non-nil, persists each subagent run to its own sidechain
	// file under the parent session (whose id is read from the context). Subagent
	// tokens are recorded there, separate from the parent's totals.
	Transcript *transcript.Store
	// TagCtx, when non-nil, decorates the child context with the running agent type
	// before the subagent's turns begin. The agent layer wires it to the usage-ledger
	// tagger (llmrec.WithAgentType) so a derived role's spend lands in the ledger as
	// agent_type='solver_pwn' while its lane stays 'worker'.
	//
	// It is a func rather than an import because this package must not depend on the
	// ledger (nor on anything that does): norma is the framework, the ledger is app
	// infrastructure. nil = no tagging, which is the correct behaviour for embedders
	// that do not meter.
	TagCtx func(ctx context.Context, agentType string) context.Context
	// BaseCtx, when non-nil, supplies the ROOT context for a child run. The host
	// uses it to hand over a context that has the same cancellation (pause / kill /
	// task deadline) but NOT this run's wall-clock deadline, so a child's life is
	// not bounded by "however much of the parent's 20 minutes is left".
	//
	// It receives the parent's tool context and returns the context to derive the
	// child from. nil = inherit the caller's ctx unchanged (pre-P1-4 behaviour).
	//
	// Cancellation is NOT negotiable here: whatever the host returns must still die
	// when the parent run dies. Go has no "drop the deadline keep the cancel", so
	// the only correct implementation is "return an ANCESTOR of the ctx you were
	// given" (the parent's workCtx, which has no run deadline but is still cancelled
	// by pause/delete and by the engine when the run ends). Returning
	// context.WithoutCancel would trade "child gets cut" for "pause no longer
	// works" — a strictly worse deal.
	BaseCtx func(parent context.Context) context.Context
	// OnEvent, when non-nil, receives every harness event of each subagent run
	// (same stream the parent loop consumes, minus errors), prefixed with the
	// running agent type. The agent layer uses it to mirror the subagent's tool
	// calls into the activity feed — without it a spawned solver is a black box:
	// the UI shows the parent's Agent call hanging while the subagent does
	// dozens of invisible tool calls inside.
	OnEvent func(agentType string, ev harness.Event)
}

type ctxKey int

const depthKey ctxKey = 0

// dispatchSettleMargin is the slack the pre-dispatch check demands on top of the
// child's own budget: the child needs time to settle (1-2 wrap-up turns) and the
// parent still has to consume the answer. Dispatching with exactly zero slack means
// the parent's deadline fires while the child is reporting — the result is produced
// and then thrown away, which is the failure this whole mechanism exists to avoid.
//
// 为什么是 120s 而不是最初的 30s（真机实测，task 185 第三次派发）：那次父 run 只剩
// 231s，压到 3m21s 派出去；子 agent 自己的硬 deadline 到点后开始收尾（写 NOTES 文件 +
// 产出结论文本），**到父 run 截止时它还在写**，工具调用被 `tool execution interrupted`
// 打断 —— 收尾做了一半，产物丢了一半。
//
// 30s 的假设错在把"收尾"当成一瞬间：`subagentSettlePrompt` 要求先落库再写结论，
// 那是 2~3 次模型往返 + 若干工具调用，实测 > 30s（该次到截止时仍在写文件）。
// 120s 覆盖三次往返并留出父 agent 读结论、写回图谱的时间。
const dispatchSettleMargin = 120 * time.Second

// minSubagentWall 是"压缩后仍值得派"的下限。
//
// 低于这个值就不要派：子 agent 要先读自己的系统提示词、再摸环境，两分钟之内
// 交不出任何可用结论，派出去只会把父 run 最后那点收尾时间也吃掉。宁可让父 agent
// 自己做，也不要制造一个注定空手而归的子 agent。
const minSubagentWall = 2 * time.Minute

// subagentSettlePrompt is injected when a child hits its own wall clock or turn
// budget. Short and action-oriented on purpose: a child's job is to hand back a
// usable result, not to write a report — every extra turn here is spent at the
// exact moment the budget says "stop".
const subagentSettlePrompt = "预算到点，立刻收手：不要再开新的探索方向。先用最少的工具调用把【已经确认】的东西落库" +
	"（图谱写回 / 已拿到的结果写文件 / flag 提交），然后单独用一段纯文本说清三件事：" +
	"①做到哪一步 ②已经拿到什么结论或产物 ③下一步该试什么。这段文本会被父 agent 直接使用。"

func depth(ctx context.Context) int {
	v, _ := ctx.Value(depthKey).(int)
	return v
}

// NewTool builds the "Agent" CoreTool that dispatches to a named subagent.
func NewTool(cfg Config) tool.CoreTool {
	if cfg.MaxDepth <= 0 {
		cfg.MaxDepth = 3
	}
	var names string
	for n, d := range cfg.Agents {
		names += fmt.Sprintf("\n- %s: %s", n, d.Description)
	}
	return tool.Build(tool.Spec{
		Name:        "Agent",
		Description: "Delegates a self-contained sub-task to an isolated subagent that runs with its own prompt and tools, returning only its final answer. Use it to parallelize independent work or to keep large intermediate output out of the main context.",
		Prompt:      "Available agent_type values:" + names,
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"agent_type": map[string]any{"type": "string", "description": "Which subagent to run."},
				"prompt":     map[string]any{"type": "string", "description": "The task for the subagent."},
			},
			"required": []any{"agent_type", "prompt"},
		},
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed() // the subagent's own tool calls are gated internally
		},
		Run: func(ctx context.Context, input json.RawMessage, tc *tool.ToolContext) (tool.Result, error) {
			var in struct {
				AgentType string `json:"agent_type"`
				Prompt    string `json:"prompt"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return tool.Result{}, err
			}
			if depth(ctx) >= cfg.MaxDepth {
				return tool.Errorf(fmt.Sprintf("Error: subagent recursion depth %d exceeded", cfg.MaxDepth)), nil
			}
			def, ok := cfg.Agents[in.AgentType]
			if !ok {
				return tool.Errorf(fmt.Sprintf("Error: unknown agent_type %q", in.AgentType)), nil
			}
			text, err := run(ctx, cfg, def, in.AgentType, in.Prompt, tc)
			if err != nil {
				return tool.Errorf("Error: subagent failed: " + err.Error()), nil
			}
			return tool.Text(text), nil
		},
	})
}

// Run executes the named agent from cfg.Agents to completion and returns its
// final text. It is the programmatic entry point (the Agent tool uses the same
// machinery); callers like the coordinator use it to fan out work directly.
//
// 只带 workDir 的轻量版。程序化派发若发生在工具调用之外（run 开头、收尾阶段），
// 用 RunWithContext 把完整的工具上下文传进来 —— 否则子 agent 会丢掉沙箱视角。
func Run(ctx context.Context, cfg Config, agentType, prompt, workDir string) (string, error) {
	return RunWithContext(ctx, cfg, agentType, prompt, &tool.ToolContext{WorkingDir: workDir})
}

// RunWithContext 是 Run 的完整版：调用方提供父 agent 当次的工具上下文。
//
// 为什么必须提供：子 agent 从 tc 继承的不只是工作目录，还有沙箱路径映射、写拒绝规则、
// 后台任务管理、大输出落盘目录与 bash 环境变量（见 run 的注释）。只传 workDir 时这些
// 全为零值，子 agent 读不到 /chal、写不进 /work，表现像"环境坏了"而不是"参数没传"。
//
// 这是「程序化派发」的入口：真机四道题证明模型不会自觉调用 Agent 工具
// （docs §5.5(6)），必须派发的场景只能在代码里派，而代码派发同样要继承上下文。
func RunWithContext(ctx context.Context, cfg Config, agentType, prompt string, tc *tool.ToolContext) (string, error) {
	def, ok := cfg.Agents[agentType]
	if !ok {
		return "", fmt.Errorf("subagent: unknown agent_type %q", agentType)
	}
	if tc == nil {
		tc = &tool.ToolContext{}
	}
	return run(ctx, cfg, def, agentType, prompt, tc)
}

// resolveDispatchWall 决定这次派发允许子 agent 跑多久（三档）。
//
//	declared     角色声明的单次墙钟（0 = 不设限，继承父 run）
//	left         父 run 还剩多久（hasDeadline=false 时无意义）
//	hasDeadline  父 run 有没有墙钟 deadline
//
// 返回：
//
//	wall     本次实际使用的子墙钟（可能被压缩）
//	clamped  是否发生了压缩（调用方据此打日志）
//	err      连最小可用时间都不够 —— 派出去必然空手而归
//
// 抽成纯函数是因为这里的风险不在算术，而在**判定之后的分支**：三档里任何一档写错，
// 表现都只是"子 agent 派不出去"或"派出去跑一半被砍"，没有报错、没有日志，
// 而 run() 需要完整 harness 才能构造，端到端测这三档代价太高。
func resolveDispatchWall(declared, left time.Duration, hasDeadline bool) (time.Duration, bool, error) {
	if declared <= 0 {
		// 声明为 0 = 继承父 run 的期限（改造前行为），没有可压缩的东西。
		return declared, false, nil
	}
	if !hasDeadline {
		// 父 run 不设墙钟 → 子 agent 声明多久就多久。
		return declared, false, nil
	}
	if left >= declared+dispatchSettleMargin {
		return declared, false, nil
	}
	usable := left - dispatchSettleMargin
	if usable < minSubagentWall {
		return 0, false, fmt.Errorf(
			"父 agent 剩余 %.0fs，不足以完成该子任务所需的 %s（含 %.0fs 收尾余量），"+
				"压缩后也不够最小可用时间 %s。请缩小这次派发的范围、拆成多步执行，或直接自己做。",
			left.Seconds(), declared, dispatchSettleMargin.Seconds(), minSubagentWall)
	}
	return usable, true, nil
}

// run executes a subagent to completion and returns its final text.
//
// tc 是父 agent 当次的工具上下文：子 agent 从它继承的不只是工作目录，还有
// 沙箱视角（SandboxPath/SandboxWriteDeny —— 模型活在容器里，文件工具跑在宿主）、
// 后台任务管理、大输出落盘目录与 bash 环境变量。不继承这些的子 agent 等于
// 被扔进了另一个世界：读不到 /chal、写不进 /work、行为与父不一致。
// 图写回归口（IntentID 归属）由 agent 层的 ToolSet 处理，不经过这里。
func run(ctx context.Context, cfg Config, def Definition, agentType, prompt string, tc *tool.ToolContext) (string, error) {
	// 派发前检查：按【父 run 剩下的时间】决定能不能派、以及这次派多久。
	//
	// 看的是 ctx（父的 toolCtx，仍带父 run 的墙钟 deadline），不是 BaseCtx 返回的那个
	// ——两者各司其职：BaseCtx 决定子 agent「能不能活着」，ctx 决定「够不够用」。
	// 硬派下去的结果是「跑到一半父 run 结束、子 agent 被取消」，产出全丢，任务 35 就是
	// 这么烧掉两倍的。把"来不及"变成派发前的一句可读错误，比跑 15 分钟再丢掉便宜得多。
	//
	// 但**拒绝不是唯一答案**。原来这里只有两档：够（按声明墙钟跑）或不够（一律拒绝）。
	// 实测这个二元判定把派发窗口压得极窄：worker run_seconds=1200s、solver 声明 900s，
	// 于是父 run 开始 270 秒之后，任何派发都会被拒 —— 而模型光侦察就要 3~5 分钟，
	// 结果是"工具在、提示词也说了，但永远派不出去"（task 183 实测：15 次 Bash 后才想起来派，
	// 那时窗口已经关了）。对模型来说这看起来像工具坏了，它会重试、然后放弃。
	//
	// 所以改成三档：够 → 按声明值；不够但还剩得下最小可用时间 → **压缩子墙钟**照派
	// （子 agent 自己到点会走 Settlement 交结论，这正是 P1-4 给它独立墙钟的意义）；
	// 连最小可用时间都不够 → 仍然拒绝，理由写清楚。
	left, hasDeadline := time.Duration(0), false
	if dl, ok := ctx.Deadline(); ok {
		left, hasDeadline = time.Until(dl), true
	}
	dispatchWall, clamped, wallErr := resolveDispatchWall(def.MaxDuration, left, hasDeadline)
	if wallErr != nil {
		return "", wallErr
	}
	if clamped {
		// 这行日志是给运营看的：它解释"为什么这个 solver 只跑了 6 分钟"，
		// 否则事后只能从"它没干完"倒推，而看不出是被父 run 的剩余预算压短的。
		log.Printf("[subagent] 派发 %s：父 run 剩余不足（声明墙钟 %s），本次压缩为 %s",
			agentType, def.MaxDuration, dispatchWall.Round(time.Second))
	}
	if cfg.Hooks != nil {
		if hs, ok := cfg.Hooks.(interface {
			FireSubagentStart(context.Context, string)
		}); ok {
			hs.FireSubagentStart(ctx, agentType)
		}
	}
	registry := filterTools(cfg.ParentTools, def.Tools)
	// Root context: by default the caller's ctx (pre-P1-4 behaviour). BaseCtx lets the
	// host swap in the parent's workCtx, which keeps cancellation but drops this run's
	// wall-clock deadline — see Config.BaseCtx for why it must be an ancestor.
	base := ctx
	if cfg.BaseCtx != nil {
		base = cfg.BaseCtx(ctx)
	}
	childCtx := context.WithValue(base, depthKey, depth(ctx)+1)
	// Tag the child BEFORE the first turn so every one of its LLM calls carries the
	// role. Applied to childCtx (not ctx) on purpose: the parent's own calls must not
	// inherit a child's role label.
	if cfg.TagCtx != nil {
		childCtx = cfg.TagCtx(childCtx, agentType)
	}

	provider := cfg.Provider
	if def.Provider != nil {
		provider = def.Provider // 角色级绑定优先（Agent 管理页给该角色单独配的模型）
	}
	seed := llm.UserText(prompt)
	if tc == nil {
		tc = &tool.ToolContext{}
	}
	in := harness.QueryInput{
		Provider:           provider,
		System:             def.Prompt,
		Messages:           []llm.Message{seed},
		Tools:              registry,
		MaxTurns:           def.MaxTurns,
		MaxDuration:        dispatchWall, // 可能被父 run 的剩余时间压缩，见 run() 开头的三档判定
		WorkingDir:         tc.WorkingDir,
		AgentID:            agentType,
		PermissionMode:     def.PermissionMode,
		CanUseTool:         cfg.CanUseTool,
		Hooks:              cfg.Hooks,
		Tasks:              tc.Tasks,
		ToolOutputDir:      tc.OutputDir,
		MaxToolOutputChars: tc.MaxOutputChars,
		BashEnv:            tc.Env,
		SandboxPath:        tc.SandboxPath,
		SandboxWriteDeny:   tc.SandboxWriteDeny,
		// 到点走收尾而不是硬死：子 agent 的产出是父 agent 唯一的收获，烂尾等于这次派发
		// 全亏。不收尾的话 MaxTurns/MaxDuration 命中即 terminal，什么都不会交回来。
		Settlement: &harness.Settlement{Prompt: subagentSettlePrompt},
	}
	// Persist this run to its own sidechain under the parent session.
	if cfg.Transcript != nil {
		parentSID := transcript.SessionIDFrom(ctx)
		if parentSID == "" {
			parentSID = transcript.NewSessionID()
		}
		w := cfg.Transcript.NewWriter(parentSID, transcript.NewAgentID())
		w.RecordMessage(seed, llm.Usage{})
		in.Recorder = w
	}
	var final string
	var rerr error
	for ev, err := range harness.Query(childCtx, in, harness.QueryDeps{}) {
		if err != nil {
			return "", err
		}
		if cfg.OnEvent != nil {
			cfg.OnEvent(agentType, ev)
		}
		if ev.Kind == harness.KindResult && ev.Terminal != nil {
			final = ev.Terminal.Text
			rerr = ev.Terminal.Err
		}
	}
	return final, rerr
}

// filterTools returns a registry with only the named tools (all if names empty).
func filterTools(parent *tool.Registry, names []string) *tool.Registry {
	if parent == nil {
		return tool.NewRegistry()
	}
	if len(names) == 0 {
		return parent
	}
	keep := map[string]bool{}
	for _, n := range names {
		keep[n] = true
	}
	var sel []tool.CoreTool
	for _, t := range parent.List() {
		if keep[t.Name()] {
			sel = append(sel, t)
		}
	}
	return tool.NewRegistry(sel...)
}
