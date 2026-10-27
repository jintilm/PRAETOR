package server

import (
	"context"
	"log"
	"strconv"
	"strings"
	"sync"

	"github.com/jintilm/praetor/agent"
	"github.com/jintilm/praetor/agent/domain"
	"github.com/jintilm/praetor/config"
	"github.com/jintilm/praetor/db"
)

// 竞速拓扑下按 lane 分模型（P2-5）。
//
// 为什么需要：race 的两条路现在换的是「起点」（另一条攻击面），不是「脑子」。
// 同一个模型在同一道题上会犯同一个错 —— 两条路都没想到 filter 绕过，加第三条路
// 也一样。让两路跑在不同模型上，才有"一个卡住另一个想到"的可能。
//
// 为什么不给任务加开关：race 这个调度器的语义就是"两路竞速"，把它跑成
// "两路同模型"等于只有一路。判定条件因此写死为「race 拓扑 + 至少两个可用模型」，
// 反悔只需把链缩短到 1 个（模型链本来就是可编辑的），或者设环境变量关掉。
//
// 语义边界（重要）：
//   - 只影响 worker 的**单次 run**；planner / mainagent / 摘要压缩仍走任务游标，
//     否则规划者跟着换模型会让"这一轮为什么这么规划"变得无法复盘。
//   - 「可用模型链」= `task_llm_profiles` 里 status=ready 的项，按 position 排序。
//     某个模型额度耗尽被标掉之后，lane 会自动在剩下的里重选，不需要额外状态。
//   - 链里只剩 1 个可用模型时**不走路由**（两路必然同模型），保持原行为。

const laneModelModeEnv = "LANE_MODELS" // off | auto（默认）| force

// laneModelMode 解析开关。
//
// force 不是给生产的：它让任何领域只要有 2 个可用模型就按 lane 分，
// 用来在没有 CTF 题库时验证路由本身（或排查"到底是不是路由生效了"）。
func laneModelMode() string {
	switch strings.ToLower(strings.TrimSpace(config.Env(laneModelModeEnv))) {
	case "off", "0", "false", "none":
		return "off"
	case "force", "on", "always":
		return "force"
	}
	return "auto"
}

// laneIndexOf 把 worker 协程名解析成 0 起的 lane 序号。
//
// 名字由 engine 生成（"work#1"、"work#2"…）。解析不出来就**明确报告不知道**，
// 由调用方回落到原行为 —— 猜一个 0 会让两路都落到同一个模型上，比不路由更糟。
func laneIndexOf(worker string) (int, bool) {
	name := strings.TrimSpace(worker)
	if !strings.HasPrefix(name, "work#") {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(name, "work#"))
	if err != nil || n <= 0 {
		return 0, false
	}
	return n - 1, true
}

// pickLaneProfile 从可用模型链里按 lane 取一个。
//
// 取模而不是"越界就退回第一个"：链比 lane 少时，lane 会绕回去共享模型；
// 链比 lane 多时（3 个模型 2 条路）多出来的那个留给"某路额度耗尽后重选"。
func pickLaneProfile(ready []int64, lane int) (int64, bool) {
	if len(ready) == 0 || lane < 0 {
		return 0, false
	}
	return ready[lane%len(ready)], true
}

// readyProfileIDs 按 position 返回链上仍可用的模型 id。
func (s *Server) readyProfileIDs(taskID int64) []int64 {
	chain, err := s.m.pg.TaskLLMProfiles(taskID)
	if err != nil {
		log.Printf("[llm] 读取任务 %d 的模型链失败（本次不按 lane 路由）：%v", taskID, err)
		return nil
	}
	out := make([]int64, 0, len(chain))
	for _, e := range chain {
		if e.Status == db.TaskLLMProfileStatusReady {
			out = append(out, e.ProfileID)
		}
	}
	return out
}

// laneRoutingEnabled 判定该任务是否按 lane 分模型（纯函数，便于把规则钉住）。
//
// 默认只在竞速拓扑上生效：串行调度（explore/evidence）只有一路，分模型没有意义，
// 反而会让"这一轮为什么用的是这个模型"变成干扰。
func laneRoutingEnabled(mode string, t *Task) bool {
	if mode == "off" || t == nil {
		return false
	}
	if mode != "force" && DomainPackFor(t).Scheduler() != domain.ScheduleRace {
		return false
	}
	return true
}

// laneChoice 是纯决策：给定任务、run 身份与可用模型链，选出该 run 用的模型。
//
// 所有"不确定"都返回 false（走原有游标），因为没有一条失败值得让任务跑不起来。
func laneChoice(ctx context.Context, t *Task, ready []int64, mode string) (int64, bool) {
	if !laneRoutingEnabled(mode, t) {
		return 0, false
	}
	lane, ok := laneIndexOf(agent.RunInfoFrom(ctx).Worker)
	if !ok {
		return 0, false
	}
	if len(ready) < 2 { // 一个模型没有"分"的意义
		return 0, false
	}
	return pickLaneProfile(ready, lane)
}

// laneOrDefault 只用于日志：解析不出来就按第 1 路算。
func laneOrDefault(ctx context.Context) int {
	if lane, ok := laneIndexOf(agent.RunInfoFrom(ctx).Worker); ok {
		return lane
	}
	return 0
}

// laneProfileFor 返回该 run 应该用的模型 id；ok=false 表示走原有游标逻辑。
//
// 返回 false 的每一种情况都对应"不路由更安全"：不是竞速拓扑、不知道是哪一路、
// 只有一个可用模型、模型不可解析。路由不是正确性必需，任何不确定都应回落而不是硬猜。
func (r *taskLLMRuntime) laneProfileFor(ctx context.Context, t *Task, taskID int64) (int64, bool) {
	mode := laneModelMode()
	if !laneRoutingEnabled(mode, t) {
		return 0, false
	}
	// 先判身份再查库：planner/mainagent 的 run 没有 worker 名（不分模型），
	// 为了它们每次都读一遍模型链是纯浪费。
	if _, ok := laneIndexOf(agent.RunInfoFrom(ctx).Worker); !ok {
		return 0, false
	}
	id, ok := laneChoice(ctx, t, r.s.readyProfileIDs(taskID), mode)
	if !ok {
		return 0, false
	}
	r.s.noteLaneProfile(r.taskID, laneOrDefault(ctx), id)
	return id, true
}

// laneLogSeen 记住上次为某 (任务, lane) 打的日志，避免每次 LLM 调用都刷一行。
var laneLogSeen sync.Map // "task|lane" -> int64(profileID)

func (s *Server) noteLaneProfile(taskID string, lane int, profileID int64) {
	key := taskID + "|" + strconv.Itoa(lane)
	if prev, ok := laneLogSeen.Load(key); ok && prev.(int64) == profileID {
		return
	}
	laneLogSeen.Store(key, profileID)
	// 带上模型名：复盘时"第 2 路用的是哪个模型"要能直接看出来，
	// 只给 profile id 还得回去查库。
	model := ""
	if cfg, ok := s.loadProfileConfig(profileID); ok {
		model = cfg.Model
	}
	log.Printf("[llm] task %s 第 %d 路 → 模型 #%d %s（竞速分模型）", taskID, lane+1, profileID, model)
}
