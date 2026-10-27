package server

import (
	"context"
	"log"
	"strconv"
	"time"

	"github.com/jintilm/praetor/agent/domain"
	"github.com/jintilm/praetor/internal/budget"
)

// 预算闸门：把 `domain.Budget` 里的 MaxTokens / MaxToolCalls / MaxWall 真正接上执行层。
//
// 背景（执行文档 §7 遗留 6）：这三项此前**没有任何消费方**，只有 MaxDepth 透传给了
// subagent。也就是说各域声明的「3M tokens / 800 次工具调用 / 90 分钟」从来没生效过。
//
// 作用范围（刻意保守）：**只对 evidence 调度器启用**。
// 原因：渗透域（explore）现在的预算是 3M/800，而实测单题就跑过 2.57M token ——
// 若立刻对渗透生效，等于给正在产基线的那条路径加了个可能误杀的闸。
// 先在逆向域验证闸门行为（它有明确的"到顶就收束"语义），再决定是否推到 explore。
const budgetPollInterval = 20 * time.Second

// startBudgetGate 启动预算闸门（每个任务一个协程，去重由 registerTaskRoutines 管）。
func (e *Engine) startBudgetGate(ctx context.Context, t *Task, p domain.DomainPack) {
	if t == nil || p == nil {
		return
	}
	b := p.Budget()
	limits := budget.FromDomain(b.MaxTokens, b.MaxToolCalls, b.MaxWall)
	if limits.Tokens == 0 && limits.ToolCalls == 0 && limits.Wall == 0 {
		return // 域没声明任何上限 → 不启协程，别白占资源
	}

	e.deleteMu.RLock()
	if e.IsDeleting(t.ID) {
		e.deleteMu.RUnlock()
		return
	}
	rt := e.registerTaskRoutines(ctx, t.ID, 1)
	e.deleteMu.RUnlock()
	runTaskRoutine(rt, func(loopCtx context.Context) { e.budgetGateLoop(loopCtx, t, limits) })
}

// budgetGateLoop 周期性读取账本用量并判定；超限则走与墙钟超时**同一套**收尾时序。
//
// 为什么复用 settleTaskCause 而不是自己写停止逻辑：收尾要等在跑 worker drain、
// 跑终局 planner 判定、再带守卫落终态。这些顺序错一步就会留下"状态说停了但还在跑"
// 或"结论没落库就被砍"的烂摊子。所以闸门只负责**判定**，停止动作交给既有收尾。
func (e *Engine) budgetGateLoop(ctx context.Context, t *Task, limits budget.Limits) {
	tick := time.NewTicker(budgetPollInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if isTerminalStatus(e.m.TaskStatus(t.ID)) || e.isSettling(t.ID) {
			return
		}
		usage, err := e.budgetUsage(ctx, t)
		if err != nil {
			// 读不到用量不是停任务的理由（可能是瞬时 DB 抖动），记一条继续。
			log.Printf("[budget] task %s 读取用量失败: %v", t.ID, err)
			continue
		}
		d := budget.Evaluate(limits, usage)
		if !d.Stop {
			continue
		}
		log.Printf("[budget] task %s 触发停止：%s（tokens=%d calls=%d elapsed=%s）",
			t.ID, d.Detail, usage.Tokens, usage.ToolCalls, usage.Elapsed.Round(time.Second))
		// 终态用 timeout：tasks.status 只允许 created/running/paused/done/failed/timeout，
		// "预算用尽"在语义上就是"到限未完成"，与超时同类；具体原因由 cause 写进日志。
		e.settleTaskCause(ctx, t, "预算闸门触发："+d.Detail, "timeout")
		return
	}
}

// budgetUsage 从账本表读累计用量。
//
// 用账本而不是内存计数器，是因为要能跨重启：进程重启后内存归零，
// 但任务还在跑（续跑），预算不能因此"重置"。
func (e *Engine) budgetUsage(ctx context.Context, t *Task) (budget.Usage, error) {
	var u budget.Usage
	tokens, err := e.m.pg.TaskTokenTotal(t.ID)
	if err != nil {
		return u, err
	}
	u.Tokens = tokens

	taskID, _ := strconv.ParseInt(t.ID, 10, 64)
	calls, err := e.m.pg.ToolCallsForTask(taskID, t.ExpID)
	if err != nil {
		return u, err
	}
	u.ToolCalls = calls

	if t.CreatedAt > 0 {
		u.Elapsed = time.Since(time.Unix(t.CreatedAt, 0))
	}
	return u, nil
}
