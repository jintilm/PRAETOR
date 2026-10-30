package server

import (
	"log"
)

// escalationMinDensity 是「工具调用密度」门槛（次/轮）。
//
// 依据：10-28 账本里成功意图的中位数是 4.1 次工具/轮。低于 2 意味着每轮做不到两次
// 工具调用 —— 这是空转/原地重试的形态，换更强模型只会让它更贵地空转；密度高说明它在
// 努力试只是没解出，那才是「升级模型可能有用」的场景。
//
// 这个数是可修正的：攒够两周账本后按 P25 重算，而不是继续用今天的估计值。
const escalationMinDensity = 2.0

// intentStat 是判据的输入：一个意图的终态 + 它这一生用掉的轮次与工具次数。
type intentStat struct {
	IntentID  int64
	State     string // done / exhausted / blocked / stopped
	Rounds    int
	ToolCalls int
}

func (s intentStat) density() float64 {
	if s.Rounds <= 0 {
		return 0 // 一轮都没有 = 完全空转
	}
	return float64(s.ToolCalls) / float64(s.Rounds)
}

// StalledForEscalation 报告「这个任务是否满足升级模型的候选条件」。
//
// 三个条件同时成立才算：
//  1. stats 至少两条（stats 按时间升序，末位最新）；
//  2. 最近两个意图都是 exhausted —— blocked 不算：那是环境/权限/配置问题，
//     换模型救不了，把它算进来会让升级动作被无关失败触发；
//  3. 两个意图的工具密度都低于门槛 —— 只满足 1、2 就升级，会把「努力但没解出」的
//     情况也送去更贵的模型，成本翻倍而解出率未必涨。
//
// 这是 dry-run 判据：满足只打日志，不改任何 provider 选择。理由见
// docs/next-batch-plan-2026-10-29.md §C.1：P1-5 的 agent_type 今天才上线，
// 账本里还没有「升级前 vs 升级后」的对照，现在切等于拍脑袋改成本结构。
func StalledForEscalation(stats []intentStat) bool {
	if len(stats) < 2 {
		return false
	}
	last := stats[len(stats)-1]
	prev := stats[len(stats)-2]
	if last.State != "exhausted" || prev.State != "exhausted" {
		return false
	}
	return last.density() < escalationMinDensity && prev.density() < escalationMinDensity
}

// stallStats 读出本探索最近的意图终态与计数（按时间升序返回最近 limit 条）。
//
// 计数口径与 activity 的写入方一致：worker 每次模型往返写一条 kind='round'，
// 每次工具结果写一条 kind='tool_result'（都带 node_id=意图 id，见 worker.execute 的
// emitWrap）。用 activity 而不是 llm_usage，是因为轮次与工具调用本来就是 activity 的
// 既有语义，而 llm_usage 记的是 token（一轮可能零次工具，也可能多次）。
func (e *Engine) stallStats(expID int64, limit int) ([]intentStat, error) {
	if e.m == nil || e.m.pg == nil || expID <= 0 {
		return nil, nil
	}
	rows, err := e.m.pg.Query(`
		SELECT n.id, n.state,
		       count(*) FILTER (WHERE a.kind = 'round')       AS rounds,
		       count(*) FILTER (WHERE a.kind = 'tool_result') AS tools
		FROM exploration_nodes n
		LEFT JOIN activity a ON a.node_id = n.id
		WHERE n.exploration_id = $1
		  AND n.kind = 'intent'
		  AND n.state IN ('exhausted','done','blocked','stopped')
		GROUP BY n.id, n.state
		ORDER BY n.id DESC
		LIMIT $2`, expID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []intentStat
	for rows.Next() {
		var s intentStat
		if err := rows.Scan(&s.IntentID, &s.State, &s.Rounds, &s.ToolCalls); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// 查询按 id DESC（最新在前），判据要按时间升序 —— 在这里反转，而不是让判据
	// 自己猜顺序：顺序错了不会报错，只会让「最近两个」变成「最早两个」，静默误判。
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// reportStallEscalation 在任务收尾时算一次，满足条件只记日志（dry-run）。
func (e *Engine) reportStallEscalation(t *Task) {
	if t == nil || t.ExpID <= 0 {
		return
	}
	stats, err := e.stallStats(t.ExpID, 12)
	if err != nil {
		// 观测失败不打扰任务收尾：这条线当前只产出日志。
		log.Printf("[escalation] task %s 读取意图统计失败（跳过判据）: %v", t.ID, err)
		return
	}
	if !StalledForEscalation(stats) {
		return
	}
	last := stats[len(stats)-1]
	prev := stats[len(stats)-2]
	log.Printf("[escalation] task %s 满足升级候选（dry-run，不切换）：最近两个意图 #%d/#%d 均 exhausted，"+
		"工具密度 %.1f/%.1f 次每轮 < %.1f",
		t.ID, prev.IntentID, last.IntentID, prev.density(), last.density(), escalationMinDensity)
}
