package server

import (
	"log"
	"strings"
	"time"

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
func (s *Server) applyAgentOverrides(defs map[string]subagent.Definition, pack domain.DomainPack) {
	for key, def := range defs {
		a, err := s.m.PG().GetAgentByKey(key)
		if err != nil || a == nil {
			continue
		}
		if tmpl, perr := s.m.PG().CurrentPrompt(a.ID); perr == nil && strings.TrimSpace(tmpl) != "" {
			def.Prompt = []string{tmpl}
		}
		if a.LLMProfileID != nil {
			if prov, cfg, ok := s.providerForProfile(*a.LLMProfileID); ok {
				if pack != nil && pack.Model().LocalOnly && !cfg.LocalOnly {
					log.Printf("[domain-agents] %s 绑定 #%d 非本地模型，但领域 %s 要求 LocalOnly；忽略该绑定并继承任务本地模型",
						key, *a.LLMProfileID, pack.Key())
				} else {
					def.Provider = prov
				}
			}
		}
		// 轮次：库里这一列默认 0 = 未设置，语义干净，接上就能让运营在页面上给 solver 加轮次
		// （此前是纯死配置：改了不生效）。
		if a.MaxTurns > 0 {
			def.MaxTurns = a.MaxTurns
		}
		// 角色级单次派发墙钟：读**可空**的 max_duration_seconds（NULL/0 = 继承 pack 声明）。
		//
		// 为什么不用 run_seconds：那一列是 NOT NULL DEFAULT 1200，播种角色行时也落 1200，
		// 「未设置」在库里表达不出来。按"大于 0 就覆盖"接上，每个角色的 MaxDuration 都会
		// 变成 1200s —— 而 worker 自己的 run_seconds 也是 1200s，subagent.run() 的派发前
		// 检查要求父 run 还剩 1200+120s，于是**所有派发一律被拒**，子 agent 静默全废。
		// 可空的新列才能区分「没配过」和「配了 1200」。
		if d, ok := resolveRoleMaxDuration(def.MaxDuration, a.MaxDurationSecs); ok {
			def.MaxDuration = d
		}
		defs[key] = def
	}
}

// warnSubagentBudgets 在启动期检查「最大角色的墙钟」与「worker 的 run 预算」是否匹配。
//
// 为什么不交给运行时才发现：不匹配的后果是 subagent.run() 的派发前检查拒绝每一次派发，
// 而拒绝是一条工具错误，模型会照常换个说法继续跑 —— 任务不会失败，只是子 agent 静默没了。
// 那种"功能消失但没人报错"的状态最难查，所以在这里显式喊一声。
func warnSubagentBudgets(workerRunSecs int) {
	if workerRunSecs <= 0 {
		return // 0 = worker 墙钟不设限，子 agent 的 MaxDuration 总是装得下
	}
	budget := time.Duration(workerRunSecs) * time.Second
	worst, worstRole := time.Duration(0), ""
	for _, domainKey := range spawnEnabledDomains {
		pack, ok := domain.Get(domain.Key(domainKey))
		if !ok {
			continue
		}
		for _, r := range pack.Roles() {
			// 余量取 120s（与 subagent.dispatchSettleMargin 同值）：这里不 import 那个包的
			// 常量只是为了少一条跨层依赖，数值改一处要记得另一处。
			//
			// 曾经是 30s。真机 task 185 证明 30s 不够：子 agent 硬 deadline 到点后还要
			// 写 NOTES、产出结论文本，1~3 分钟，30s 的余量让父 run 在它收尾时就把工具调用
			// 打断了（`tool execution interrupted`）。告警阈值必须跟判定阈值同源，
			// 否则会出现"启动期不告警、运行期照样派不出去/收不了尾"。
			if r.MaxDuration > 0 && r.MaxDuration+120*time.Second > budget && r.MaxDuration > worst {
				worst, worstRole = r.MaxDuration, r.Key
			}
		}
	}
	if worst == 0 {
		return
	}
	log.Printf("[subagent] 警告：角色 %s 需要 %s，但 worker 的 run_seconds 只有 %ds —— "+
		"派发前检查会拒绝它，该角色实际不可用。把 worker 的 run_seconds 调大（Agent 管理页），"+
		"或调小 domain.RoleSpec.MaxDuration。", worstRole, worst, workerRunSecs)
}

// resolveRoleMaxDuration 决定一个角色的「单次派发墙钟」。
//
//	declared  pack 里声明的值（domain.RoleSpec.MaxDuration）
//	cfg       库里配的秒数；nil 或 <=0 表示没配 / 已清除
//
// 返回 (最终值, 是否被配置覆盖)。覆盖时不校验"是否超过父 run 预算" —— 那是
// warnSubagentBudgets（启动期）与 subagent 的派发前检查（运行期）的职责：
// 在这里悄悄改小用户的配置，会让"配了 20 分钟却只跑 10 分钟"变成无法解释的行为。
func resolveRoleMaxDuration(declared time.Duration, cfg *int) (time.Duration, bool) {
	if cfg == nil || *cfg <= 0 {
		return declared, false
	}
	return time.Duration(*cfg) * time.Second, true
}
