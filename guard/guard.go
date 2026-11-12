// Package guard implements the safety boundary layer (docs §11): an audit log,
// user-configured intercept-rule evaluation, and Observer/G5 failure attribution.
// Every tool call passes through the PreToolUse hook before executing.
// (The RoE authorization-scope mechanism was removed; a replacement may be added
// later.) Destructive/exfil gating is no longer hard-coded here — it lives in the
// DB intercept rules (seeded as ordinary [内置] rules, so users can disable or
// delete them), evaluated via applyIntercept.
package guard

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jintilm/praetor/intercept"
	"github.com/jintilm/praetor/internal/norma/hook"
)

// AuditEntry records one gated tool call.
type AuditEntry struct {
	TS      int64  `json:"ts"`
	Tool    string `json:"tool"`
	Action  string `json:"action"` // allow|block
	Reason  string `json:"reason,omitempty"`
	Command string `json:"command,omitempty"`
}

// DynamicGrantChecker 是「任务级动态授权」的执行层判定。
//
// 为什么定义在 guard 而不是 server：授权要挂在**每次工具调用前**的硬边界上，
// 与取证边界并列，不能依赖提示词、DB 里用户可编辑的拦截规则，也不能让模型
// 有机会签发或扩大授权。实现放在 server（那里能读库），guard 只认这个接口，
// 于是 guard 包不依赖 db，硬闸仍是 code-owned 的独立一层。
//
// Check 返回 nil = 放行；返回 error = 立即 block 并把原因交给模型（引导降级静态）。
// 非动态调用必须直接返回 nil —— 实现方负责识别，guard 不做业务判断。
type DynamicGrantChecker interface {
	Check(ctx context.Context, tool string, input json.RawMessage) error
}

// Guard enforces the side-effect policy via agent-core hooks.
type Guard struct {
	mu          sync.Mutex
	audit       []AuditEntry
	attrib      map[string]int // failure attribution counts (Observer / G5)
	reg         *hook.Registry
	interceptor *intercept.Interceptor // optional; nil disables user-configured rules
	dynamic     DynamicGrantChecker    // optional; nil = 该任务没有动态授权闸
}

// SetDynamicGrantChecker 装配任务级动态授权闸。
// 由 Manager 在 Task 装配时调用（每个 Task 有自己的 Guard 实例）。
// 传 nil 表示不启用 —— 此时任何动态工具调用都会因为「没有闸」而在 server 侧
// 被识别为未授权？不：server 必须给**每个**任务都装上闸，未签发授权的任务由闸
// 自己 fail-closed。这里留 nil 只为聊天会话（chatGuard）等无任务上下文的场景。
func (g *Guard) SetDynamicGrantChecker(c DynamicGrantChecker) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.dynamic = c
}

// New creates a Guard without user-configured intercept rules (used for pentest
// tasks where the Interceptor is not yet available).
func New() *Guard { return newGuard(nil) }

// NewWithInterceptor creates a Guard with user-configured intercept rules.
func NewWithInterceptor(ic *intercept.Interceptor) *Guard { return newGuard(ic) }

func newGuard(ic *intercept.Interceptor) *Guard {
	g := &Guard{attrib: map[string]int{}, interceptor: ic}
	g.reg = hook.NewRegistry().
		On(hook.PreToolUse, g.preToolUse).
		On(hook.PostToolUse, g.postToolUse)
	return g
}

// Hooks returns the hook registry to attach to an agent session.
func (g *Guard) Hooks() *hook.Registry { return g.reg }

// 取证边界（evidence boundary）—— 与拦截规则**并列**的硬约束，不依赖 DB 配置。
//
// 为什么是硬约束而不是提示词：
//
//	这类行为对**任何授权的渗透/红队作业**都是红线，而不仅影响基准跑分：
//	合规报告里若出现「从靶场宿主机 .env / 镜像层里读到口令」，这本身就是
//	越界取证，客户现场是不可接受的；同时它还会把预算烧在找答案而非打漏洞上
//	（实测一道题 70 次调用里 22 次是这类动作）。
//
//	提示词能做的是「劝」，模型仍可能绕；DB 拦截规则是**用户可编辑可删除**的
//	（设计如此——用户该有权改自己的规则），因此不能承载系统级不变量。
//	这里与 destructive/exfil 那层不同：那层刻意下放给用户，这层必须留在代码里。
//
// 拦截的是「读取非目标侧内容」与「自建/伪造目标服务」两类动作，**只针对 Bash
// 命令串**做模式匹配（不做语义判断，避免误伤正常探测）：
//   - 容器/镜像自省：docker exec / inspect / history / cp / save / export
//   - 自建服务：docker run / docker compose up / build（用于重搭靶场）
//   - 直接读行内敏感文件：cat/type/Get-Content 等指向 .env、/flag*、题目目录
//
// 允许的正常行为（明确不拦）：docker ps/logs、卷/网络自省类只读查询、
// 一切指向目标地址的 curl/扫描。误拦的代价（挡掉合法探测）比漏拦更大。
var (
	// 容器/镜像自省：能把靶场内部（或构建历史里的 FLAG）直接读出来的动作。
	reContainerIntrospect = regexp.MustCompile(`(?i)\bdocker\s+(exec|inspect|history|cp|save|export|diff)\b`)
	// 自建/重搭服务：把「跑自己搭的东西」当成通关手段。
	// 注意 allow 中间参数（compose 的 -p/-f 等要跳过去才轮到子命令）：
	// 只写 `compose\s+(run|build|up)` 会漏掉 `compose -p mypoc up`（实测踩到）。
	reSelfBuiltService = regexp.MustCompile(`(?i)\bdocker(\s+compose)?(\s+(-\S+\s+\S+|--\S+=\S+))*\s+(run|build|up|start|create)\b`)
	// 直接读承载答案的本地文件（含题目目录的 .env / flag 文件）。
	reReadAnswerFile = regexp.MustCompile(`(?i)\b(cat|type|head|tail|more|less|get-content|select-string)\s+[^\n|]{0,120}(\.env\b|/flag|\\flag|flag\.txt)`)
)

// evidenceBoundaryReason 返回命中的越界取证原因（空 = 放行）。
// 抽成纯函数便于单测覆盖各类合法/非法命令。
func evidenceBoundaryReason(tool, command string) string {
	if tool != "Bash" && tool != "shell_open" && tool != "shell_send" {
		return ""
	}
	if strings.TrimSpace(command) == "" {
		return ""
	}
	switch {
	case reContainerIntrospect.MatchString(command):
		return "读取容器/镜像内部内容（docker exec/inspect/history/cp/save/export）不是对目标的取证。" +
			"漏洞结论必须来自目标资产的真实请求/响应；请改为针对目标 URL 探测。"
	case reSelfBuiltService.MatchString(command):
		return "自行启动或构建服务来复现/伪造目标不被允许（docker run/build/up）。" +
			"验证必须针对任务给定的目标地址，而不是你新起的服务。"
	case reReadAnswerFile.MatchString(command):
		return "直接读取宿主或容器内的答案文件（.env / flag）属于越界取证，不是漏洞利用。" +
			"请通过目标接口获取数据；这类本地文件读到的内容不得作为 finding 证据。"
	}
	return ""
}

func (g *Guard) preToolUse(ctx context.Context, ev hook.Event) hook.Result {
	// Extract the shell-command surface for the audit log: Bash + the interactive-shell
	// tools (shell_open's command, shell_send's text). Destructive/exfil gating is no
	// longer hard-coded here — it now lives in the DB intercept rules, evaluated by
	// applyIntercept below. Other tools record an empty command.
	var cmd string
	switch ev.ToolName {
	case "Bash", "shell_open":
		var in struct {
			Command string `json:"command"`
		}
		_ = json.Unmarshal(ev.Input, &in)
		cmd = in.Command
	case "shell_send":
		var in struct {
			Text string `json:"text"`
		}
		_ = json.Unmarshal(ev.Input, &in)
		cmd = in.Text
	}
	// 取证边界：在执行前拦掉越界取证（见 evidenceBoundaryReason 的说明）。
	if reason := evidenceBoundaryReason(ev.ToolName, cmd); reason != "" {
		return g.block(ev.ToolName, systemBlockMessage(reason), cmd)
	}
	// 任务级动态授权：与取证边界同级的硬约束，先于 DB 拦截规则求值。
	// 放在 record("allow") 之前，避免同一次调用先记一条 allow 再记一条 block。
	if c := g.dynamicChecker(); c != nil {
		if err := c.Check(ctx, ev.ToolName, ev.Input); err != nil {
			return g.block(ev.ToolName, dynamicBlockMessage(err.Error()), cmd)
		}
	}
	g.record(ev.ToolName, "allow", "", cmd)
	return g.applyIntercept(ctx, ev)
}

// dynamicChecker 取 checker 快照：装配发生在任务创建期，调用发生在 worker 期，
// 没有并发写，但用同一把锁读可以让 -race 下的语义明确。
func (g *Guard) dynamicChecker() DynamicGrantChecker {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.dynamic
}

// dynamicBlockMessage 把动态授权拒绝框定为平台决策，并明确给出可走的替代路线。
// 只说「禁止」会让 agent 反复改写命令试图绕过（与 systemBlockMessage 同款坑）；
// 告诉它静态路线仍然可行，卡住的任务才会继续产出结论而不是空转烧预算。
func dynamicBlockMessage(reason string) string {
	return systemBlockMessage(reason) +
		" 这不是目标侧的限制，改写命令、换端口、换工具都无法获得授权。" +
		"请立即改走静态分析路线（解包、清单、静态规则扫描），并在结论里注明动态验证未执行的原因。"
}

// applyIntercept evaluates user-configured intercept rules against the tool call.
// Both rules and the fallback judge receive the complete tool input.
func (g *Guard) applyIntercept(ctx context.Context, ev hook.Event) hook.Result {
	if g.interceptor == nil {
		return hook.Result{}
	}
	if !g.interceptor.IsToolEnabled(ev.ToolName) {
		return hook.Result{}
	}
	ctx = intercept.WithCall(ctx, ev.ToolName, ev.Input)
	dec, matched := g.interceptor.Match(ev.ToolName, ev.Input)
	if !matched {
		// No rule matched. Ask the LLM fallback judge (if enabled); when it is off
		// or unwired, keep current behavior and allow.
		d, judged := g.interceptor.Judge(ctx, ev.ToolName, ev.Input)
		if !judged {
			return hook.Result{}
		}
		dec = d
	}
	switch dec.Action {
	case "deny":
		// 观测:deny 命中不阻塞审批,直接记一条 denied（历史/任务拦截页可见）。
		g.interceptor.Log(ctx, intercept.ConvIDFromContext(ctx), dec, ev.ToolName, ev.Input, "denied")
		return g.block(ev.ToolName, systemBlockMessage(dec.Message), "")
	case "allow":
		// Record explicit rule and model approvals so review details remain auditable.
		g.interceptor.Log(ctx, intercept.ConvIDFromContext(ctx), dec, ev.ToolName, ev.Input, "allowed")
		return hook.Result{}
	case "ask":
		// If the worker context is already cancelled (task stopped / killed), block
		// immediately without creating a pending record — avoids orphaned DB entries
		// and makes execOne complete fast, reducing the race against drainSynthetic.
		if ctx.Err() != nil {
			return g.block(ev.ToolName, systemBlockMessage("工作已取消，平台安全管控阻止执行"), "")
		}
		convID := intercept.ConvIDFromContext(ctx)
		if !g.interceptor.HandleAsk(ctx, convID, dec, ev.ToolName, ev.Input) {
			return g.block(ev.ToolName, systemBlockMessage("人工审批未通过（用户拒绝或审批超时）"), "")
		}
		return hook.Result{}
	}
	return hook.Result{}
}

// systemBlockMessage frames an intercept block as an PRAETOR platform-governance
// decision so the agent does not mistake it for a target-side defense.
//
// The bare reasons ("禁止执行此工具" / "用户拒绝") read exactly like a WAF/403 on
// the target, so a pentest agent's instinct is to bypass them — rewrite the
// command, swap the payload, re-encode, retry. That is both futile (the platform
// blocks the class of action, not one string) and wrong (it's a policy decision,
// not an obstacle to defeat). This prefix states plainly that the block comes
// from the platform, is not the target's protection, and that the operation is
// forbidden — so the agent pivots to another approach instead of evading it.
// Audit/history rows keep the raw reason (see Interceptor.Log); only the
// model-facing tool_result carries this framing.
func systemBlockMessage(reason string) string {
	return "【PRAETOR 平台管控·非目标防御】此调用被平台拦截。" +
		"原因：" + reason + "。此操作被禁止。"
}

var reBlocked = regexp.MustCompile(`(?i)\b(403|forbidden|waf|blocked|rate.?limit|429|captcha|denied)\b`)

// postToolUse is the Observer failure-attribution hook (G5): it classifies tool
// results into blocked / error / ok so the planner can change strategy instead
// of giving up at a WAF.
func (g *Guard) postToolUse(_ context.Context, ev hook.Event) hook.Result {
	if ev.ToolName != "Bash" {
		return hook.Result{}
	}
	class := "ok"
	switch {
	case reBlocked.Match(ev.Result):
		class = "blocked"
	case ev.IsError:
		class = "error"
	}
	g.mu.Lock()
	g.attrib[class]++
	g.mu.Unlock()
	return hook.Result{}
}

// Attributions returns failure-attribution counts (Observer / G5).
func (g *Guard) Attributions() map[string]int {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[string]int, len(g.attrib))
	for k, v := range g.attrib {
		out[k] = v
	}
	return out
}

func (g *Guard) block(tool, reason, cmd string) hook.Result {
	g.record(tool, "block", reason, cmd)
	return hook.Result{Decision: "block", Message: reason}
}

func (g *Guard) record(tool, action, reason, cmd string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.audit = append(g.audit, AuditEntry{TS: time.Now().Unix(), Tool: tool, Action: action, Reason: reason, Command: cmd})
	if len(g.audit) > 2000 {
		g.audit = g.audit[len(g.audit)-2000:]
	}
}

// Audit returns a snapshot of recent gated calls (most recent last).
func (g *Guard) Audit() []AuditEntry {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]AuditEntry, len(g.audit))
	copy(out, g.audit)
	return out
}
