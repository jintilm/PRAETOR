package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jintilm/praetor/agent/domain"
	"github.com/jintilm/praetor/db"
	"github.com/jintilm/praetor/internal/campaign"
)

// 本文件把 internal/campaign 的纯判定接到「意图下发」这个动作上（P4-1）。
//
// 不新增调度拓扑：战役走的还是 1 planner + 1 worker（见 SchedulerPlanFor 的 campaign 分支），
// 红队的结构性差别是**顺序**，而顺序靠下发口的闸门实现 —— 前置没完成的阶段根本创建不出意图。
// 这样做的好处是整条执行链（领取、并发、收尾、预算）都不必为红队再写一遍。
//
// 设计参考（只读思路）：m-sec-org/BreachWeave 的 Manager/Observer/Solver 分工 —— Manager
// 决定节奏、Solver 执行、Observer 纠偏。本项目只取"谁决定下一阶段"，不引入三角色的并发形态。

// campaignPlanFor 返回该任务的战役 DAG。
//
// 抽成函数而不是包级变量：将来按任务定制 DAG（不同靶场暴露的战术面不同）时，
// 只改这里，闸门与文档不用动。
func campaignPlanFor(t *Task) campaign.Plan {
	return campaign.Default()
}

// campaignGate 返回注入给 ToolSet 的阶段闸门；非红队域返回 nil（不校验阶段）。
//
// 为什么在 server 侧读进度：阶段完成与否是**图的事实**（意图节点 state=done + payload.phase），
// 工具侧只有"这一次要写什么"，两边的信息来源不同，判定必须放在能同时看到全局的那一侧。
func (s *Server) campaignGate(t *Task) func(string) error {
	if s == nil || t == nil || t.Store == nil {
		return nil
	}
	p := DomainPackFor(t)
	if p == nil || p.Key() != domain.RedTeam {
		return nil
	}
	plan := campaignPlanFor(t)
	return func(phase string) error {
		ph := strings.TrimSpace(phase)
		if ph == "" {
			return fmt.Errorf("红队战役必须给 phase（%s）：跳步会让后续结论失去事实支撑，"+
				"也无法判断清理范围", strings.Join(plan.Phases(), "/"))
		}
		done, err := campaignDone(t, plan)
		if err != nil {
			// 读不到进度时**拒绝**而不是放行：放行会让"前置未满足"变成静默可能。
			return fmt.Errorf("读取战役进度失败，本次不下发：%w", err)
		}
		if why := plan.Blocked(done, campaign.Phase(ph)); why != "" {
			return errors.New(why)
		}
		return nil
	}
}

// campaignDone 把"已完成的意图"折成"哪些阶段已完成"。
//
// 只认 state=done：blocked/exhausted 的意图表示"这一步没做成"，不能当作前置已完成 ——
// 那会让后续阶段建立在一个没验证过的假设上。
func campaignDone(t *Task, plan campaign.Plan) (map[campaign.Phase]bool, error) {
	nodes, err := t.Store.ListByKind(db.KindIntent, 500)
	if err != nil {
		return nil, err
	}
	valid := map[campaign.Phase]bool{}
	for _, ph := range plan.Phases() {
		valid[campaign.Phase(ph)] = true
	}
	done := map[campaign.Phase]bool{}
	for _, n := range nodes {
		if n == nil || n.State != "done" {
			continue
		}
		var payload struct {
			Phase string `json:"phase"`
		}
		if len(n.Payload) > 0 {
			_ = json.Unmarshal(n.Payload, &payload)
		}
		ph := campaign.Phase(strings.TrimSpace(payload.Phase))
		if valid[ph] {
			done[ph] = true
		}
	}
	return done, nil
}

// campaignCleanupGuard 返回注入给工具面的清理判定；非红队域返回 nil。
func (s *Server) campaignCleanupGuard(t *Task) func() (bool, []string) {
	if s == nil || t == nil || t.Store == nil {
		return nil
	}
	p := DomainPackFor(t)
	if p == nil || p.Key() != domain.RedTeam {
		return nil
	}
	return func() (bool, []string) { return campaignCleanupPending(t) }
}

// campaignCleanupPending 是收尾判定：有留痕阶段做过、清理没做 → 任务不该判完成。
// 返回 (是否待清理, 涉及的阶段)。
func campaignCleanupPending(t *Task) (bool, []string) {
	if t == nil || t.Store == nil {
		return false, nil
	}
	p := DomainPackFor(t)
	if p == nil || p.Key() != domain.RedTeam {
		return false, nil
	}
	plan := campaignPlanFor(t)
	done, err := campaignDone(t, plan)
	if err != nil {
		return false, nil
	}
	return plan.PendingCleanup(done, done[campaign.Cleanup])
}
