package server

import (
	"log"
	"strings"

	"github.com/jintilm/praetor/agent/domain"
	"github.com/jintilm/praetor/db"
	"github.com/jintilm/praetor/internal/norma/subagent"
)

// spawnEnabledDomains 是「子 agent 派生已接线」的领域。只有这些域的 RoleSpec
// 会播种成 agents 表的行（Agent 管理页可见/可编辑提示词/可绑 LLM）。
// 渗透/红团队刻意不接派生（planner/worker 与战役闸门是既有秩序），
// 所以它们声明的角色不播种 —— 往库里塞一堆永远不会跑的角色只会误导运营。
var spawnEnabledDomains = []string{"ctf", "reverse"}

// seedDomainAgents 把已接派生的领域角色播种成一等 agent 行（幂等）。
//
// 为什么播种：领域角色此前只是运行时的 spawn 定义（RoleSpec → subagent.Definition），
// Agent 管理页看不到、提示词改不了、模型绑不了 —— 运营想给 solver 换个更便宜的模型
// 只能改代码。播种后它们与内置 agent 同权：提示词进 agent_prompts（代码默认兜底、
// DB 编辑生效）、llm_profile_id 走 per-role 模型绑定（运行时在 task_llm 装配处消费）。
//
// 与 BuiltinPromptSeeds 的差异：领域角色的提示词 = 域约束 + 角色片段（RolePrompt），
// 是纯静态文本（没有 {{.Goal}} 这类变量 —— 任务上下文由派生时的 prompt 参数携带）。
func seedDomainAgents(pg *db.DB) {
	for _, domainKey := range spawnEnabledDomains {
		pack, ok := domain.Get(domain.Key(domainKey))
		if !ok {
			continue
		}
		for _, r := range pack.Roles() {
			if r.Name == "" {
				continue // 没起展示名的角色不播种
			}
			var agentID int64
			err := pg.QueryRow(`
INSERT INTO agents(key, name, description, role, builtin, enabled)
VALUES ($1, $2, NULLIF($3,''), 'specialist', true, true)
ON CONFLICT (key) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description
RETURNING id`, r.Key, r.Name, r.Description).Scan(&agentID)
			if err != nil {
				log.Printf("[domain-agents] seed %s 失败: %v", r.Key, err)
				continue
			}
			// 提示词正文：域约束 + 角色片段，与运行时 RolePrompt 同源（仅空时播种，
			// 编辑过的版本重启不丢 —— 与内置 agent 同一套纪律）。
			prompt := strings.Join(domain.RolePrompt(pack, r), "\n\n")
			if err := pg.SeedPromptIfEmpty(agentID, prompt); err != nil {
				log.Printf("[domain-agents] seed %s 提示词失败: %v", r.Key, err)
			}
		}
	}
}

// applyAgentOverrides 把 Agent 管理页的运营配置叠加到 spawn 定义上：
// 提示词以 DB 为权威（seedDomainAgents 播种、页面编辑即时生效、重启不丢）；
// 绑定 llm_profile 的角色用 per-role provider（如逆向 analyst 走本地模型）。
// 无行/无 prompt/绑定解析失败时保持代码默认 —— 播种缺失不该让派生失效。
func (s *Server) applyAgentOverrides(defs map[string]subagent.Definition) {
	for key, def := range defs {
		a, err := s.m.PG().GetAgentByKey(key)
		if err != nil || a == nil {
			continue
		}
		if tmpl, perr := s.m.PG().CurrentPrompt(a.ID); perr == nil && strings.TrimSpace(tmpl) != "" {
			def.Prompt = []string{tmpl}
		}
		if a.LLMProfileID != nil {
			if prov, _, ok := s.providerForProfile(*a.LLMProfileID); ok {
				def.Provider = prov
			}
		}
		defs[key] = def
	}
}
