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
)

// 竞速调度（P2-1）：同题多路并行、首解收敛。
//
// 核心取舍是**延迟竞速（lazy race）**：
//   - 并行是唯一会把成本 ×N 倍放大的操作（单路 ~450K/题，eager 2 路 ~900K）；
//   - 而实测多数题单路就能解，一上来就铺 2~8 路是纯浪费。
//
// 所以拓扑上仍然注册 2 条 worker 例程（例程账本固定，避免运行中动态增删），
// 但**第二条一开始就阻塞在放行信号上**，只有出现停滞信号才放行。
// 这样"省钱"和"能并行"两者都有，且不需要改任务运行时。
const (
	raceModeEnv        = "CTF_RACE"              // lazy（默认）| eager
	raceStallRoundsEnv = "CTF_RACE_STALL_ROUNDS" // 连续多少轮规划无产出视为停滞，默认 3
	raceEagerAfterEnv  = "CTF_RACE_EAGER_AFTER"  // 兜底：单路跑这么久还没停滞信号也放行，默认 15m
)

// raceConfig 是竞速放行策略。
type raceConfig struct {
	Eager        bool          // true = 直接两路（比赛抢时间时用）
	StallRounds  int64         // 规划轮数达到该值且没有任何 finding → 视为停滞
	EagerAfter   time.Duration // 单路跑满该时长仍未停滞 → 也放行（避免"永远单路"）
	PollInterval time.Duration // 检测间隔（默认 20s）
}

// raceConfigFromEnv 解析环境变量。
//
// 默认值刻意保守：lazy + 3 轮 + 15 分钟。想抢时间的人显式设 eager 或调小阈值。
func raceConfigFromEnv() raceConfig {
	cfg := raceConfig{
		StallRounds:  3,
		EagerAfter:   15 * time.Minute,
		PollInterval: 20 * time.Second,
	}
	mode := strings.ToLower(strings.TrimSpace(config.Env(raceModeEnv)))
	if mode == "eager" || mode == "parallel" {
		cfg.Eager = true
	}
	if v := strings.TrimSpace(config.Env(raceStallRoundsEnv)); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			cfg.StallRounds = n
		}
	}
	if v := strings.TrimSpace(config.Env(raceEagerAfterEnv)); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cfg.EagerAfter = d
		}
	}
	return cfg
}

// raceGateState 是判定用的观测值（纯数据，便于单测）。
type raceGateState struct {
	Rounds   int64         // 已完成的规划轮数
	Findings int           // 已产出的 finding 数（有产出说明单路在推进，不必加路）
	Elapsed  time.Duration // 单路已跑时长
}

// shouldReleaseLane2 判定是否放行第二路。
//
// 规则（按顺序）：
//  1. eager 模式 → 立即放行；
//  2. 已有 finding → **不放行**（单路在推进，加路只是重复烧钱）；
//  3. 规划轮数 ≥ StallRounds → 放行（连续多轮没有产出 = 卡住了）；
//  4. 时长 ≥ EagerAfter → 放行（兜底：慢但没停滞的题也给一次换思路的机会）。
//
// 返回原因是为了让日志能解释"为什么这里起了第二路"——竞速的成本分析全靠这个。
func shouldReleaseLane2(cfg raceConfig, st raceGateState) (bool, string) {
	if cfg.Eager {
		return true, "eager 模式"
	}
	if st.Findings > 0 {
		// 已产出说明单路在推进：此时加路等于重复烧钱，不加。
		// 这里不返回原因——原因只在"放行"时被日志使用，返回了也是死信息。
		return false, ""
	}
	if cfg.StallRounds > 0 && st.Rounds >= cfg.StallRounds {
		return true, fmt.Sprintf("%d 轮规划无产出（阈值 %d）", st.Rounds, cfg.StallRounds)
	}
	if cfg.EagerAfter > 0 && st.Elapsed >= cfg.EagerAfter {
		return true, fmt.Sprintf("单路已跑 %s（兜底阈值 %s）", st.Elapsed.Round(time.Minute), cfg.EagerAfter)
	}
	return false, ""
}

// startRaceGate 启动竞速放行器：轮询观测值，条件满足就关闭 release 通道（只关一次）。
//
// release 用 channel 而不是 bool：worker 侧直接 `<-release` 阻塞等待，
// 不需要自己轮询/加锁；close 天然幂等且对所有等待者广播。
func (e *Engine) startRaceGate(ctx context.Context, t *Task, plan SchedulerPlan) <-chan struct{} {
	release := make(chan struct{})
	if plan.Workers <= plan.Lanes {
		close(release) // 没有需要放行的额外路（evidence/explore）
		return release
	}
	cfg := raceConfigFromEnv()
	if cfg.Eager {
		log.Printf("[race] task %s eager 模式：两条 worker 立即并行", t.ID)
		close(release)
		return release
	}

	e.deleteMu.RLock()
	if e.IsDeleting(t.ID) {
		e.deleteMu.RUnlock()
		return release
	}
	rt := e.registerTaskRoutines(ctx, t.ID, 1)
	e.deleteMu.RUnlock()

	runTaskRoutine(rt, func(loopCtx context.Context) {
		tick := time.NewTicker(cfg.PollInterval)
		defer tick.Stop()
		start := time.Now()
		for {
			select {
			case <-loopCtx.Done():
				return
			case <-tick.C:
			}
			if isTerminalStatus(e.m.TaskStatus(t.ID)) || e.isSettling(t.ID) {
				// 任务已经结束/在收尾：把通道关掉，避免第二路永远阻塞导致例程无法退出
				close(release)
				return
			}
			st, err := e.raceState(t, start)
			if err != nil {
				log.Printf("[race] task %s 读取状态失败: %v", t.ID, err)
				continue
			}
			ok, why := shouldReleaseLane2(cfg, st)
			if !ok {
				continue
			}
			log.Printf("[race] task %s 放行第二路：%s（rounds=%d findings=%d elapsed=%s）",
				t.ID, why, st.Rounds, st.Findings, st.Elapsed.Round(time.Second))
			close(release)
			return
		}
	})
	return release
}

// raceState 读取判定所需的三个观测值。
//
// 数据都来自既有表/存储，不新建结构：轮数用 planner round（digest），
// finding 数用探索图节点，时长按本任务容器启动时刻算。
func (e *Engine) raceState(t *Task, start time.Time) (raceGateState, error) {
	st := raceGateState{Elapsed: time.Since(start)}
	if t.Store != nil {
		rounds, err := t.Store.RoundNo()
		if err == nil {
			st.Rounds = rounds
		}
		findings, err := t.Store.ListByKind(db.KindFinding, 100)
		if err == nil {
			st.Findings = len(findings)
		}
	}
	return st, nil
}

// ConvergeTask 是「首解收敛」的原语：把"本题已解出，立即停止"推给所有在跑的意图。
//
// 为什么用 steer 而不是硬 cancel：
//   - steer 让 worker 在**下一个工具调用前**收到指令并自行收尾，已有进展不丢；
//   - 硬 cancel 会丢掉半截输出，而且把"谁赢了"这一步也砍掉了（赢了的那条要写 writeup）。
//
// 调用方是 P2-2 的 ctf_submit：平台判 accepted 时调它。放在 engine 上而不是工具里，
// 是因为工具拿不到"本任务所有在跑意图"的视图。
func (e *Engine) ConvergeTask(taskID, cause string) int {
	t, ok := e.m.Task(taskID)
	if !ok || t.Store == nil {
		return 0
	}
	running, err := t.Store.ListByKind(db.KindIntent, 200)
	if err != nil {
		return 0
	}
	msg := "【已解出，立即停止】" + cause +
		"\n本题已经产出平台认可的结论，你不需要再做任何探测。请立刻用一句话收尾（说明你做到哪一步、留下了什么证据），不要再调用工具。"
	n := 0
	for _, node := range running {
		if node.State != "running" {
			continue
		}
		if err := e.SteerWork(node.ID, msg); err == nil {
			n++
		}
	}
	if n > 0 {
		log.Printf("[race] task %s 首解收敛：向 %d 条在跑意图注入停止指令", taskID, n)
	}
	return n
}

// raceLaneCount 返回该领域下 race 拓扑应有的 worker 路数（不含 planner）。
//
// 目前固定 2（1 路探测 + 1 路挑战）。放多少个由 CTF 域的 Budget.MaxParallel 表达，
// 这里只取上限，避免配置写成 8 就把成本放大 8 倍。
func raceLaneCount(p domain.DomainPack) int {
	if p == nil {
		return 1
	}
	n := p.Budget().MaxParallel
	if n <= 0 {
		return 1
	}
	if n > 2 {
		n = 2 // 硬上限：竞速的价值在"首解收敛"，不在"铺得越多越好"
	}
	return n
}
