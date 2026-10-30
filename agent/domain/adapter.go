package domain

import (
	"fmt"
	"sort"

	"github.com/jintilm/praetor/internal/norma/harness"
	"github.com/jintilm/praetor/internal/norma/llm"
	"github.com/jintilm/praetor/internal/norma/permission"
	"github.com/jintilm/praetor/internal/norma/subagent"
	actool "github.com/jintilm/praetor/internal/norma/tool"
	"github.com/jintilm/praetor/internal/norma/transcript"
)

// 本文件把 DomainPack（零依赖的声明）翻译成 norma SDK 的真实装配件：
// subagent.Definition + 工具白名单 + 预算 + 审批档位。
//
// 分工约定：
//   - pack.go / *_pack.go 只声明「要什么」，不 import 任何业务或 SDK 包；
//   - adapter.go 是唯一 import norma 的地方，所有 SDK 细节收敛在这里。
// 这样以后 norma 升级、或换掉某段 SDK 用法，改动面只有本文件。

// Host 是 engine 在装配期提供的宿主能力，与具体领域无关。
type Host struct {
	Provider   llm.Provider          // 该域的模型（混合部署：逆向域传本地模型）
	Tools      *actool.Registry      // 父工具集（通常是 agent.ToolSet + 默认工具）
	CanUseTool permission.CanUseTool // 审批回调（接到现有 guard/intercept）
	Hooks      harness.HookRunner    // 生命周期钩子（留痕、预算计数）
	Transcript *transcript.Store     // 会话持久化（nil = 不落盘）
}

// Definitions 把一个域的角色翻译成 Agent 工具的 agent_type 定义表。
//
// 生成的 Tools 语义与 norma subagent.filterTools 一致：非空即白名单，
// 空则由 SDK 继承父工具集。
func (h Host) Definitions(p DomainPack) (map[string]subagent.Definition, error) {
	if p == nil {
		return nil, fmt.Errorf("domain: nil pack")
	}
	roles := p.Roles()
	if len(roles) == 0 {
		return nil, fmt.Errorf("domain %q: no roles", p.Key())
	}
	defs := make(map[string]subagent.Definition, len(roles))
	for _, r := range roles {
		if _, dup := defs[r.Key]; dup {
			return nil, fmt.Errorf("domain %q: duplicate role %q", p.Key(), r.Key)
		}
		defs[r.Key] = subagent.Definition{
			Description:    r.Description,
			Prompt:         RolePrompt(p, r),
			Tools:          EffectiveTools(p, r),
			PermissionMode: approvalMode(r.Approval),
			MaxTurns:       r.MaxTurns,
			// 单次派发自己的墙钟。0 = 继承父 run 期限（改造前行为）。
			// 注意别把 Budget.MaxWall 塞这里 —— 那是域级总预算，见 RoleSpec.MaxDuration 注释。
			MaxDuration: r.MaxDuration,
		}
	}
	return defs, nil
}

// SubagentConfig 组装「Agent 工具」的完整配置，engine 拿它和 ParentTools 一起
// 交给 subagent.NewTool 即可获得派生能力。
func (h Host) SubagentConfig(p DomainPack) (subagent.Config, error) {
	if h.Provider == nil {
		return subagent.Config{}, fmt.Errorf("domain %q: Host.Provider is required", p.Key())
	}
	defs, err := h.Definitions(p)
	if err != nil {
		return subagent.Config{}, err
	}
	depth := BudgetFor(p, RoleSpec{}).MaxDepth
	if depth <= 0 {
		depth = 2 // 默认两层：Lead → Specialist，禁止无限递归派生
	}
	return subagent.Config{
		Provider:    h.Provider,
		ParentTools: h.Tools,
		Agents:      defs,
		MaxDepth:    depth,
		CanUseTool:  h.CanUseTool,
		Hooks:       h.Hooks,
		Transcript:  h.Transcript,
	}, nil
}

// EffectiveTools 返回角色实际可用的工具 key：
// 角色显式声明了 ToolKeys 就用它，否则继承该域的 Tools()。
func EffectiveTools(p DomainPack, r RoleSpec) []string {
	if len(r.ToolKeys) > 0 {
		return dedupe(r.ToolKeys)
	}
	return dedupe(p.Tools())
}

// RolePrompt 拼出角色的系统提示词：域级约束在前，角色细节在后。
func RolePrompt(p DomainPack, r RoleSpec) []string {
	out := make([]string, 0, len(p.Prompt())+1)
	out = append(out, p.Prompt()...)
	if r.PromptSection != "" {
		out = append(out, r.PromptSection)
	}
	return out
}

// FilterTools 复刻 norma/subagent.filterTools 的语义：names 非空即白名单，
// 空则原样返回父集；未知名字静默丢弃（这是 SDK 的既有行为，保持一致）。
//
// 单独导出是为了「直接派一个 specialist、不走 Agent 工具」的路径复用。
func FilterTools(parent *actool.Registry, names []string) *actool.Registry {
	if parent == nil {
		return actool.NewRegistry()
	}
	if len(names) == 0 {
		return parent
	}
	keep := make(map[string]bool, len(names))
	for _, n := range names {
		keep[n] = true
	}
	var sel []actool.CoreTool
	for _, t := range parent.List() {
		if keep[t.Name()] {
			sel = append(sel, t)
		}
	}
	return actool.NewRegistry(sel...)
}

// Missing 返回「角色声明了、但父工具集里没有」的工具 key，按字母序。
//
// 用途：装配期打一条警告。领域包里声明的很多 key（如 ghidra_decompile）
// 要等对应 MCP 接进来才存在，静默缺失会让 worker 手里没有工具却照常开跑。
func Missing(p DomainPack, reg *actool.Registry) []string {
	if p == nil || reg == nil {
		return nil
	}
	have := map[string]bool{}
	for _, t := range reg.List() {
		have[t.Name()] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, r := range p.Roles() {
		for _, k := range EffectiveTools(p, r) {
			if !have[k] && !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	sort.Strings(out)
	return out
}

// BudgetFor 返回角色预算：角色未设的字段回落到域预算。
// 传零值 RoleSpec 即取域级预算。
func BudgetFor(p DomainPack, r RoleSpec) Budget {
	base := p.Budget()
	pick := func(role, domain int) int {
		if role > 0 {
			return role
		}
		return domain
	}
	wall := r.Budget.MaxWall
	if wall <= 0 {
		wall = base.MaxWall
	}
	return Budget{
		MaxTokens:    pick(r.Budget.MaxTokens, base.MaxTokens),
		MaxWall:      wall, // 角色可缩短墙钟，未设则继承域
		MaxToolCalls: pick(r.Budget.MaxToolCalls, base.MaxToolCalls),
		MaxDepth:     pick(r.Budget.MaxDepth, base.MaxDepth),
		MaxParallel:  pick(r.Budget.MaxParallel, base.MaxParallel),
	}
}

// approvalMode 把域内抽象映射到 SDK 的权限模式。
func approvalMode(m ApprovalMode) permission.Mode {
	switch m {
	case ApprovalAuto:
		return permission.ModeAuto
	case ApprovalPlan:
		return permission.ModePlan
	default:
		return permission.ModeDefault
	}
}

// dedupe 保序去重，返回新切片（绝不改动调用方传入的声明）。
func dedupe(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
