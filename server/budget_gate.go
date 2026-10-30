package server

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/jintilm/praetor/agent/domain"
	"github.com/jintilm/praetor/config"
	"github.com/jintilm/praetor/db"
	"github.com/jintilm/praetor/internal/budget"
)

// 预算闸门：把 `domain.Budget` 里的 MaxTokens / MaxToolCalls / MaxWall 真正接上执行层。
//
// 背景（执行文档 §7 遗留 6）：这三项此前**没有任何消费方**，只有 MaxDepth 透传给了
// subagent。也就是说各域声明的「3M tokens / 800 次工具调用 / 90 分钟」从来没生效过。
//
// 两种模式，刻意分两批上（P1-6）：
//
//   - enforce=true（硬闸）：超限即走既有收尾时序停任务。用于 evidence（逆向/红队）
//     与 race（CTF）—— 这两个调度器本身就有"到顶就收束"的语义，停是被设计过的结局。
//   - enforce=false（dry-run，只告警）：超限只落一条 system 活动 + 一行日志，**绝不停止**。
//     用于 explore（渗透）—— 实测单题跑到过 3.63M 而 pentest 声明上限是 3M，
//     直接开硬闸等于在产基线的路径上装一个可能误杀的闸。先只记录"若当时是硬闸会被杀多少"，
//     一周后按账本算误杀率，<5% 再翻开关。
//
// 为什么 dry-run 必须真的只"记账"而不是"少停一点"：误杀是**不可观测**的——任务一旦被
// 预算闸门停掉，终态与"跑到墙钟超时"、"模型自己放弃"完全一样，事后无法从账本区分。
// 所以第一阶段必须一次都不停，否则拿到的样本自带幸存者偏差。
const budgetPollInterval = 20 * time.Second

// startBudgetGate 启动预算闸门（每个任务一个协程，去重由 registerTaskRoutines 管）。
//
// enforce 见文件头注：false = dry-run，只告警不停任务。
func (e *Engine) startBudgetGate(ctx context.Context, t *Task, p domain.DomainPack, enforce bool) {
	if t == nil || p == nil {
		return
	}
	// 口径提示（每个任务一条）：闸门读的是**供应商上报的** input_tokens。
	//
	// 实测（2026-10-30，loxo.cc + deepseek-v4.1-flash）：system 消息 4492 字符时
	// `prompt_tokens` 仍报 57 —— 该供应商的 usage 完全不计 system。prätor 的 system 里
	// 装着工具面、域规则、意图块，量级远大于对话本身，所以这类供应商上闸门会**系统性低估**。
	// 外部无法从 usage 内部判断"system 计不计费"，只能提示运维拿账单核对。
	mode := "dry-run（只告警）"
	if enforce {
		mode = "硬闸（超限即收尾）"
	}
	log.Printf("[budget] task %s 闸门口径=%s，依据是供应商上报的 input_tokens；"+
		"部分供应商不计 system（实测可差数倍），账本对不上时用 /api/usage/summary 的 full_price_equiv 交叉核对", t.ID, mode)
	b := p.Budget()
	limits := budget.FromDomain(b.MaxTokens, b.MaxToolCalls, b.MaxWall)
	// 调试覆盖：把 tokens 上限压低，用来在真实任务上验「超限只告警、绝不停止」
	// 这条路径，而不必真的烧到域声明的 3M。空或非正数 = 用域声明值（生产默认）。
	//
	// 只覆盖 tokens：tool_calls 与 wall 的触发现有各自的测试覆盖，而压低它们会改变
	// 任务本来该什么时候收束，事后分不清「闸门没停」与「任务自己就该结束了」。
	if v := config.Env("BUDGET_TOKEN_LIMIT"); v != "" {
		before := limits.Tokens
		var ok bool
		limits.Tokens, ok = overrideTokenLimit(before, v)
		if ok {
			log.Printf("[budget] task %s tokens 上限被 PRAETOR_BUDGET_TOKEN_LIMIT 覆盖：%d → %d", t.ID, before, limits.Tokens)
		} else {
			log.Printf("[budget] PRAETOR_BUDGET_TOKEN_LIMIT=%q 无效，按域声明值 %d 执行", v, limits.Tokens)
		}
	}
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
	runTaskRoutine(rt, func(loopCtx context.Context) { e.budgetGateLoop(loopCtx, t, limits, enforce) })
}

// budgetGateLoop 周期性读取账本用量并判定；硬闸超限则走与墙钟超时**同一套**收尾时序。
//
// 为什么复用 settleTaskCause 而不是自己写停止逻辑：收尾要等在跑 worker drain、
// 跑终局 planner 判定、再带守卫落终态。这些顺序错一步就会留下"状态说停了但还在跑"
// 或"结论没落库就被砍"的烂摊子。所以闸门只负责**判定**，停止动作交给既有收尾。
func (e *Engine) budgetGateLoop(ctx context.Context, t *Task, limits budget.Limits, enforce bool) {
	tick := time.NewTicker(budgetPollInterval)
	defer tick.Stop()
	// reported 只活在本协程里：dry-run 的"每个维度只报一次"是进程内状态。
	// 重启后重报一次是可接受的（多一条记录，不会多停一次），而落库去重会为一个
	// 纯观察功能引入一张表，不值得。
	reported := make(map[budget.Breach]bool, 3)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if isTerminalStatus(e.m.TaskStatus(t.ID)) || e.isSettling(t.ID) {
			return
		}
		if e.IsPaused(t.ID) {
			// 暂停期间不判预算 —— 两条理由：
			//  1. 此刻这个任务什么都没在消耗。判它超限只可能是在算"排队/挂起的那段时间"，
			//     而那不是成本。
			//  2. 与超时协调器保持一致（engine_timeout.go:163 同样在暂停时跳过）。同一件事
			//     两个组件给两个答案，必然有一个是错的，而"闸门在暂停时把任务杀了"属于
			//     最坏的那种错：用户明明按了暂停，回来发现任务没了。
			// 恢复后下一轮 tick 自然回到正常判定（deadline 的顺延也发生在恢复那一刻）。
			continue
		}
		usage, err := e.budgetUsage(ctx, t)
		if err != nil {
			// 读不到用量不是停任务的理由（可能是瞬时 DB 抖动），记一条继续。
			log.Printf("[budget] task %s 读取用量失败: %v", t.ID, err)
			continue
		}
		settle, report, done := budgetGateDecide(limits, usage, enforce, reported)
		if settle {
			d := budget.Evaluate(limits, usage)
			log.Printf("[budget] task %s 触发停止：%s（tokens=%d calls=%d elapsed=%s）",
				t.ID, d.Detail, usage.Tokens, usage.ToolCalls, usage.Elapsed.Round(time.Second))
			// 终态用 timeout：tasks.status 只允许 created/running/paused/done/failed/timeout，
			// "预算用尽"在语义上就是"到限未完成"，与超时同类；具体原因由 cause 写进日志。
			e.settleTaskCause(ctx, t, "预算闸门触发："+d.Detail, "timeout")
			return
		}
		for _, d := range report {
			reported[d.Breach] = true
			e.reportBudgetOverrun(t, d, usage)
		}
		if done {
			// 所有声明了上限的维度都已超限并记录完毕，再轮询也学不到新东西。
			// 峰值不需要在这里采：账本（llm_usage）本身就有全量 token 与调用数，
			// 事后算"超了多少"直接查库，比让协程陪跑到任务结束更省也更新。
			log.Printf("[budget] task %s 预算 dry-run 已记录全部超限维度，闸门退出（任务继续）", t.ID)
			return
		}
	}
}

// overrideTokenLimit 解析 PRAETOR_BUDGET_TOKEN_LIMIT，返回（生效值，是否覆盖）。
//
// 非整数、零、负数一律视为「没设」：这个开关只该把上限压低去验 dry-run 路径，
// 不能变成「设成 0 就关闭闸门」的隐式后门 —— 那会让一次调试遗留的 env 把预算保护
// 静默关掉，而账本上看不出任何区别。
func overrideTokenLimit(declared int64, raw string) (int64, bool) {
	n, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || n <= 0 {
		return declared, false
	}
	return n, true
}

// budgetGateDecide 是闸门的全部判定，**纯函数**：给定上限、用量、模式与已报维度，
// 回答三件事——要不要停、这一轮要记哪些账、dry-run 是不是已经没事可做了。
//
// 单独抽出来是为了让"dry-run 永不停止"这条契约能在没有数据库的情况下被断言。
// 一个只测 budget.Evaluate 的用例证明不了这件事：真正的风险不在判定，而在判定之后
// 有人把 report 分支也接上了 settleTaskCause。测试要卡的是那个分叉。
func budgetGateDecide(limits budget.Limits, usage budget.Usage, enforce bool, reported map[budget.Breach]bool) (settle bool, report []budget.Decision, done bool) {
	crossed := budget.Breaches(limits, usage)
	if len(crossed) == 0 {
		return false, nil, false
	}
	if enforce {
		// 硬闸只需要"停一次"，交给 Evaluate 取第一条（tokens 优先），与改造前完全一致。
		return true, nil, false
	}
	for _, d := range crossed {
		if !reported[d.Breach] {
			report = append(report, d)
		}
	}
	return false, report, budgetGateReportedAll(limits, reported, report)
}

// budgetGateReportedAll 判断"所有声明了上限的维度是否都已超限且记录过"。
//
// 注意必须把本轮 report 一起算进去：调用方是在决定之后就记账，若只看 reported，
// 最后一个维度总要在多等一个轮询周期后才被认定完成。
func budgetGateReportedAll(limits budget.Limits, reported map[budget.Breach]bool, pending []budget.Decision) bool {
	seen := func(b budget.Breach) bool {
		if reported[b] {
			return true
		}
		for _, d := range pending {
			if d.Breach == b {
				return true
			}
		}
		return false
	}
	if limits.Tokens > 0 && !seen(budget.BreachTokens) {
		return false
	}
	if limits.ToolCalls > 0 && !seen(budget.BreachToolCalls) {
		return false
	}
	if limits.Wall > 0 && !seen(budget.BreachWall) {
		return false
	}
	return true
}

// reportBudgetOverrun 是 dry-run 的唯一输出：一条 system 活动 + 一行日志，**不碰任务状态**。
//
// 为什么要落 activity 而不是只写日志：日志会随容器重启/轮转丢失，而这条记录要在
// 一周后被 SQL 统计（"finish 了却撞过墙的任务有几个"）。Worker 固定为 "system"，
// 前端据此把它归到系统会话，不会混进某个 intent 的执行轨迹里。
func (e *Engine) reportBudgetOverrun(t *Task, d budget.Decision, usage budget.Usage) {
	log.Printf("[budget] task %s 超限（dry-run，不停止）：%s（tokens=%d calls=%d elapsed=%s）",
		t.ID, d.Detail, usage.Tokens, usage.ToolCalls, usage.Elapsed.Round(time.Second))
	e.emitActivity(t, db.Activity{
		Worker:  "system",
		Kind:    "text",
		Summary: "[预算告警·只告警不停止] " + d.Detail,
		Detail: fmt.Sprintf("limit_breach=%s\n%s\n当前用量：tokens=%d，工具调用=%d，已跑=%s\n"+
			"本次仅记录，任务未停止。用于评估是否可以把该维度的闸门切成硬闸。",
			d.Breach, d.Detail, usage.Tokens, usage.ToolCalls, usage.Elapsed.Round(time.Second)),
	})
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

	u.Elapsed = wallElapsed(t.FirstRunAt, t.CreatedAt, t.PausedAt, time.Now())
	return u, nil
}

// wallElapsed 算"这个任务真正消耗了多少墙钟"，供预算判定使用。
//
// 三个字段各有原因，缺一个就会误判：
//
//  1. 起点用 FirstRunAt 而不是 CreatedAt。created_at 含排队时间——任务排队一小时才被
//     调度，它一秒还没跑就已经"用掉"一小时墙钟。dry-run 上线第一天就撞到了这个：
//     三个任务 tokens=0 / calls=0 却报"墙钟预算用尽 2h"。
//  2. FirstRunAt=0（从未运行）时退回 CreatedAt：这是唯一能用的下界，且此时通常
//     立刻就会被调度，误差可忽略。
//  3. 暂停时长要扣掉。P0-3 已经在 admission 里把 deadline 按"暂停了多久"顺延过
//     （manager.go:1265），但那是给超时协调器用的；预算闸门自己算 elapsed，
//     不扣就会和 deadline 口径打架——一个暂停两小时的任务恢复后立刻被闸门判超限，
//     而超时协调器认为它还剩 90 分钟。同一件事两个答案，必然有一个是错的。
//
// 注意 pausedAt 是**本次**暂停起点（恢复时清零），不是累计值。暂停中它会随
// 时间往前走，所以扣的量自然等于"到目前为止暂停了多久"。多段暂停的累计由
// deadline 的多次顺延承担，这里只扣当前这一段 —— 与超时协调器的视图保持一致。
func wallElapsed(firstRunAt, createdAt, pausedAt int64, now time.Time) time.Duration {
	start := firstRunAt
	if start == 0 {
		start = createdAt
	}
	if start == 0 {
		return 0
	}
	begin := time.Unix(start, 0)
	elapsed := now.Sub(begin)
	if pausedAt > 0 {
		if p := time.Unix(pausedAt, 0); p.After(begin) {
			elapsed -= now.Sub(p)
		} else {
			// 暂停起点早于首次运行（理论上不该发生，但脏数据不能变成"负时长"
			// 或"凭空多出来的时间"）：直接不计这段，保留 elapsed 全量。
			_ = p
		}
	}
	if elapsed < 0 {
		return 0
	}
	return elapsed
}
