package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"runtime/debug"
	"strings"

	actool "github.com/jintilm/praetor/internal/norma/tool"
)

// DeferredInfo carries the deferred-tools wiring an agent needs to build its
// Options: the MCP tool names whose schemas are withheld, the subset listed in the
// global system-prompt block (non-skill-gated), and the shared session unlock set.
// UnlockSkill unlocks a named skill's MCPs — hosts call it to rebuild the unlock set
// from history on a resumed session (design doc C2).
type DeferredInfo struct {
	FindingGuidance string            // derived from the final permitted tools, including DB overrides
	Deferred        []string          // all MCP tool names (schema withheld)
	GlobalNames     []string          // MCP names to list in the system-prompt block
	Unlock          *actool.UnlockSet // shared call-gate; nil when no MCP tools
	UnlockSkill     func(skillName string)
}

// ToolAugment, if set, returns the EXTRA tools an agent should see beyond its
// built-in base set — the agent's visible skills (packed into one Skill meta-tool)
// and visible MCP servers (expanded to mcp__server__tool). It also returns the
// DeferredInfo describing how those MCP tools are deferred/gated. The server wires
// it to the PG agent_visibility table. cleanup releases any spawned MCP clients.
//
// When nil, agents run with only their built-in tools — behavior is unchanged
// until a user assigns a skill/MCP to the agent in the UI.
var ToolAugment func(ctx context.Context, agentKey string) (extra []actool.CoreTool, def DeferredInfo, cleanup func())

// AugmentTools returns base plus the agent's visible skill/MCP tools, the
// DeferredInfo, and a cleanup func the caller must defer (closes MCP clients).
// Built-in base tools are kept as-is — never filtered (内置工具留代码层，不做可见性过滤).
func AugmentTools(ctx context.Context, agentKey string, base []actool.CoreTool) ([]actool.CoreTool, []actool.CoreTool, DeferredInfo, func()) {
	var (
		def     DeferredInfo
		cleanup = func() {}
		out     = base
	)
	if ToolAugment != nil {
		var extra []actool.CoreTool
		var cl func()
		extra, def, cl = ToolAugment(ctx, agentKey)
		if cl != nil {
			cleanup = cl
		}
		if len(extra) > 0 {
			out = append(append([]actool.CoreTool{}, base...), extra...)
		}
	}
	// DB tools table has the final say on the built-in tools: drop the ones this
	// agent isn't bound to (or that are disabled) and swap in overridden
	// descriptions/schemas + default injection. MCP/skill/host tools have no row
	// and pass through untouched, so deferred/unlock wiring stays consistent.
	if ToolResolve != nil {
		out = ToolResolve(ctx, agentKey, out)
	}
	out, def.FindingGuidance = findingWorkflowTools(agentKey, out)
	// 沙箱：只把 worker 的 Bash 换成容器执行（SandboxExec 为 nil 时完全不动）。
	// 放在 guardPanic 之前，让 panic 兜底覆盖到装饰后的工具。
	out = ApplySandbox(agentKey, out)
	for i, t := range out {
		out[i] = guardPanic(t)
	}
	// full 是**未按域裁剪**的完整工具集：子 agent 的白名单要从这里过滤。
	// 用裁剪后的集合会让 solver_web 也拿不到浏览器（白名单里写了也白写）。
	full := out
	// 给模型看的工具面按域裁剪（CTF/逆向不需要浏览器自动化，见 dropDomainNoise）。
	out, def = dropDomainNoise(RunInfoFrom(ctx).Domain, out, def)
	return out, full, def, cleanup
}

// guardPanic turns a panicking tool handler into an ordinary tool error. The
// harness runs each tool on its own goroutine, so a panic inside a handler can't
// be recovered by the caller that started the run — it takes the whole process
// down, and on restart the agent replays the same call and crashes again. Applied
// last, so it covers every tool the agent can reach: domain, SDK, MCP and skill.
func guardPanic(t actool.CoreTool) actool.CoreTool { return &guardedTool{CoreTool: t} }

type guardedTool struct{ actool.CoreTool }

func (g *guardedTool) Call(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (res actool.Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[tools] %s panic: %v\n%s", g.Name(), r, debug.Stack())
			res, err = actool.Errorf(fmt.Sprintf("工具 %s 内部错误：%v（本次调用已失败，可换个参数或改用别的工具）", g.Name(), r)), nil
		}
	}()
	return g.CoreTool.Call(ctx, in, tc)
}

// dropDomainNoise 去掉该域用不上的 MCP 工具，并同步清理 Deferred/GlobalNames。
//
// 为什么（2026-10-30 实测）：CTF worker 的工具面是 54 个，其中 **25 个是
// mcp__browser__***（浏览器自动化）。task 202 全程只用了 Bash + 图写回类工具，
// 那 25 个 schema 每轮都进上下文——31 次调用、每次约 17K 输入，粗算约 150K token
// （≈28%）付给了从未被调用过的工具描述。CTF / 逆向的题面要么是附件、要么是裸
// TCP 服务，浏览器工具在这两个域没有使用场景。
//
// 必须同步过滤 Deferred / GlobalNames：只删工具不删清单，模型会看到"有个可解锁的
// 浏览器工具"却永远调不到 —— 那比留着更糟（它会反复尝试一个不存在的动作）。
func dropDomainNoise(domain string, tools []actool.CoreTool, def DeferredInfo) ([]actool.CoreTool, DeferredInfo) {
	if domain != "ctf" && domain != "reverse" {
		return tools, def
	}
	keep := func(name string) bool { return !strings.HasPrefix(name, "mcp__browser__") }
	out := make([]actool.CoreTool, 0, len(tools))
	for _, t := range tools {
		if keep(t.Name()) {
			out = append(out, t)
		}
	}
	def.Deferred = filterNames(def.Deferred, keep)
	def.GlobalNames = filterNames(def.GlobalNames, keep)
	return out, def
}

func filterNames(in []string, keep func(string) bool) []string {
	if len(in) == 0 {
		return in
	}
	out := make([]string, 0, len(in))
	for _, n := range in {
		if keep(n) {
			out = append(out, n)
		}
	}
	return out
}
