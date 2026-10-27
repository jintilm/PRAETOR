// Package ctfplan 是 CTF 的「先做哪题、什么时候放弃」决策内核（P2-6）。
//
// 为什么单独成包，而且是纯函数：
//   - 决策一旦散在调度器、提示词、跑分器三处，就会各自漂移——分数上去了也不知道
//     是"模型变强"还是"顺序变好"；
//   - 纯函数可测：给定预算与已花，输出排序与放弃结论，单测就能把「先易后难」
//     「预算不够就别开工」这些规则钉死。
//
// 它**不读数据库、不发 HTTP、不看真实时钟**：所有观测值由调用方测量后喂进来，
// 时间只以 time.Duration 的形式进入，所以测试不需要 mock 时钟。
//
// 一条纪律：**估算可以有偏差，但结论必须可解释**。每个 Verdict 都带 Reason，
// 因为"为什么放弃这题"比"放弃了"重要得多。
package ctfplan

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// 成本模型常量。
//
// TokensPerMinute 来自实测：单题 ~450K tokens / ~18 分钟 ≈ 25K/min。
// 它只用于"剩余时间够不够"的判断，不参与分数计算。
const (
	TokensPerMinute = 25_000

	// DefaultPoints 是"没有分值信息"时的中性权重。
	// 离线题库常常不写分值，此时所有题等权，排序自然退化为「按预估成本升序」＝先易后难。
	DefaultPoints = 100

	// DefaultBase 是分类未知时的单题预估成本（实测中位）。
	DefaultBase int64 = 450_000

	// MinSliceTokens 是单题切片下限：低于这个数，任何题都不值得开（连一轮完整
	// 侦察-验证循环都撑不住）。
	MinSliceTokens int64 = 120_000

	// sliceGrace 让单题可以用到"均分预算"的 1.25 倍再放弃：
	// 卡在恰好均分上会让"马上要出结果"的题被砍掉，而多花 25% 是最便宜的容错。
	sliceGrace = 1.25
)

// categoryBase 是各题型的单题成本基线（tokens）。
//
// 差异来自工具链深度：pwn 要反复调试、rev 要静态+动态来回，web 多数一次打穿，
// forensics 往往几步就出。数值是**排序用的相对值**，不是精确预测。
var categoryBase = map[string]int64{
	"web":       420_000,
	"pwn":       600_000,
	"rev":       560_000,
	"crypto":    480_000,
	"forensics": 380_000,
	"misc":      340_000,
}

// State 是题目在**本任务内**的进度状态。
type State string

const (
	StateNew       State = "new"       // 没碰过
	StateActive    State = "active"    // 正在做（同一时刻只应有一道）
	StateSolved    State = "solved"    // 已判对
	StateAbandoned State = "abandoned" // 已放弃（不再回头，除非人手动改）
)

// Challenge 是一道题的观测值。**只放决策需要的东西**，题面正文不进这里。
type Challenge struct {
	ID        string
	Name      string
	Category  string // web/pwn/rev/crypto/forensics/misc；空 = 未知
	Points    int    // 分值；0 = 未知（按 DefaultPoints 处理）
	Solves    int    // 解出人数；<=0 = 未知。这是最便宜的难度信号
	EstTokens int64  // 调用方的预估；0 = 用分类基线

	SpentTokens int64 // 本任务内该题已花
	State       State
}

// Budget 是**整场**剩余预算（不是单题）。
//
// Unlimited=true 时忽略下面两个字段（不设上限的场景：本地刷题、人盯着跑）。
// 其余时候 TokenLeft/TimeLeft **就是剩余量**，0 表示已用尽——
// 不用"<=0 表示不限"这种约定，是因为那种写法会把"预算耗尽"误读成"无限"。
type Budget struct {
	TokenLeft int64
	TimeLeft  time.Duration
	Unlimited bool
}

// exhausted 报告预算是否已经不能支撑任何新工作。
func (b Budget) exhausted() bool {
	if b.Unlimited {
		return false
	}
	return b.TokenLeft <= 0 || b.TimeLeft < 0
}

// slicesEnabled 报告是否要按 token 切片（时间预算不参与切片：切片是"每题花多少 token"）。
func (b Budget) slicesEnabled() bool { return !b.Unlimited && b.TokenLeft > 0 }

// exhaustReason 说清是**哪一条**限住了。
//
// 只写"预算或时间已用尽"会让复盘无从下手：一个是应该早点收敛，另一个是该提前
// 挑便宜的题——处置完全不同，所以原因必须能区分。
func (b Budget) exhaustReason() string {
	switch {
	case b.TokenLeft <= 0 && b.TimeLeft < 0:
		return "token 预算与截止时间都已用尽"
	case b.TimeLeft < 0:
		return "任务已过截止时间"
	case b.TokenLeft <= 0:
		return "整场 token 预算已用尽"
	}
	return "预算已用尽"
}

// Action 是决策结论。
type Action string

const (
	ActionStart    Action = "start"    // 开始做
	ActionContinue Action = "continue" // 继续做（已在做）
	ActionGiveUp   Action = "give_up"  // 放弃（含"之前已放弃"）
)

// Verdict 是一道题的结论（带可解释的原因）。
type Verdict struct {
	ID     string
	Name   string
	Action Action
	Est    int64   // 预估成本（tokens）
	Score  float64 // 性价比 = 分值 / 预估成本（越大越值得先做）
	Spent  int64   // 已花（tokens）
	Reason string
}

// Plan 是一轮决策的结果。
type Plan struct {
	Strategy  string    // easy-first | value-first
	Todo      []Verdict // 建议做，已排序（第一个就是 Recommend）
	GiveUp    []Verdict // 放弃/不必做（含已解出之外的不可行项）
	Solved    []string  // 已解出（不进 Todo，也不再花预算）
	Recommend string    // 建议下一题 id；"" = 没有可做的了
	Exhausted bool      // 预算/时间已耗尽，整场该收工
	Slice     int64     // 本轮单题切片（tokens）
	Note      string    // 给模型看的一句话总述
}

// Estimate 估算单题成本。
//
// 三个信号按可信度排序：调用方显式预估 > 分类基线 > 全局中位；
// 然后用"解出人数"做难度修正，最后用**已花**校准（已经花超了，说明它确实比想的贵）。
func Estimate(c Challenge) int64 {
	base := c.EstTokens
	if base <= 0 {
		base = categoryBase[strings.ToLower(strings.TrimSpace(c.Category))]
		if base <= 0 {
			base = DefaultBase
		}
	}
	if c.Solves > 0 {
		switch {
		case c.Solves >= 300:
			base = base * 70 / 100 // 大路货：套路现成
		case c.Solves >= 80:
			base = base * 85 / 100
		case c.Solves >= 20:
			// 中位区间，不动
		default:
			base = base * 130 / 100 // 少数人解出：要么很硬，要么有坑
		}
	}
	if c.SpentTokens > base {
		base = c.SpentTokens
	}
	if base < 1 {
		base = 1
	}
	return base
}

// Score 返回性价比：每百万 token 能换多少分。
func Score(c Challenge) float64 {
	pts := c.Points
	if pts <= 0 {
		pts = DefaultPoints
	}
	return float64(pts) * 1e6 / float64(Estimate(c))
}

// Build 计算本轮决策。
//
// 规则顺序（先硬后软，每步都能单独解释）：
//  1. 已解出的题：不排、不花预算；
//  2. 已放弃的题：不回头（除非人手动改状态）——反复回到同一道废题是最大的浪费；
//  3. 预算/时间耗尽：整场收工（Exhausted），不是"再挤一点"；
//  4. 剩余预算 < 该题预估：不开工（做了也做不完，等于把预算扔进黑洞）；
//  5. 在做的题已花 ≥ 单题切片：放弃，换下一题；
//  6. 其余按策略排序。
//
// 策略：预算/时间相对总预估紧张时用 value-first（抢高分易题），
// 宽裕时用 easy-first（先把手边的分拿到手，减少后面的不确定性）。
func Build(chs []Challenge, b Budget) Plan { return BuildWith(chs, b, "") }

// BuildWith 与 Build 相同，但可以**强制**策略（"easy-first" / "value-first" / ""=自动）。
//
// 存在的理由是对照实验："先易后难"和"抢性价比"到底哪个分高，只能跑同一套题比出来。
// 生产路径永远走自动（Build），强制策略只给跑分器/调试用。
func BuildWith(chs []Challenge, b Budget, force string) Plan {
	p := Plan{Strategy: "easy-first"}

	var pend []Challenge
	for _, c := range chs {
		switch c.State {
		case StateSolved:
			p.Solved = append(p.Solved, idOrName(c))
		case StateAbandoned:
			p.GiveUp = append(p.GiveUp, Verdict{
				ID: idOrName(c), Name: c.Name, Action: ActionGiveUp,
				Est: Estimate(c), Score: Score(c), Spent: c.SpentTokens,
				Reason: "之前已放弃，不再回头（换下一题比原地重试划算）",
			})
		default:
			pend = append(pend, c)
		}
	}
	if len(pend) == 0 {
		p.Exhausted = true
		p.Note = "没有待做的题了"
		return p
	}
	if b.exhausted() {
		why := b.exhaustReason()
		p.Exhausted = true
		p.Note = why + "，收工"
		for _, c := range pend {
			p.GiveUp = append(p.GiveUp, Verdict{
				ID: idOrName(c), Name: c.Name, Action: ActionGiveUp,
				Est: Estimate(c), Score: Score(c), Spent: c.SpentTokens,
				Reason: why,
			})
		}
		return p
	}

	// 单题切片：把剩余预算均分给待做的题，再给一点宽限。
	p.Slice = sliceFor(b, len(pend))

	var sumEst int64
	for _, c := range pend {
		sumEst += Estimate(c)
	}

	for _, c := range pend {
		est := Estimate(c)
		v := Verdict{ID: idOrName(c), Name: c.Name, Est: est, Score: Score(c), Spent: c.SpentTokens}
		switch {
		case b.slicesEnabled() && est > b.TokenLeft:
			v.Action, v.Reason = ActionGiveUp,
				fmt.Sprintf("剩余预算 %s 少于该题预估 %s，开了也做不完", kilo(b.TokenLeft), kilo(est))
			p.GiveUp = append(p.GiveUp, v)
		case c.State == StateActive && p.Slice > 0 && c.SpentTokens >= p.Slice:
			v.Action, v.Reason = ActionGiveUp,
				fmt.Sprintf("单题已花 %s，达到切片 %s，换题比继续磨更划算", kilo(c.SpentTokens), kilo(p.Slice))
			p.GiveUp = append(p.GiveUp, v)
		case c.State == StateActive:
			v.Action, v.Reason = ActionContinue, "正在做"
			p.Todo = append(p.Todo, v)
		default:
			v.Action = ActionStart
			p.Todo = append(p.Todo, v)
		}
	}

	// 策略选择：预算或时间相对总预估紧张 → 抢性价比；否则先易后难。
	sumTime := time.Duration(sumEst/TokensPerMinute) * time.Minute
	tightBudget := b.slicesEnabled() && b.TokenLeft < sumEst
	tightTime := !b.Unlimited && b.TimeLeft > 0 && b.TimeLeft < sumTime*3/2
	if tightBudget || tightTime {
		p.Strategy = "value-first"
	}
	switch force {
	case "easy-first", "value-first":
		p.Strategy = force
	}

	sortBy(p.Todo, p.Strategy)

	if len(p.Todo) > 0 {
		p.Recommend = p.Todo[0].ID
	}
	p.Note = noteFor(p, len(chs))
	return p
}

// sliceFor 计算单题切片；预算不设上限（或时间型预算）时返回 0（不切片）。
func sliceFor(b Budget, n int) int64 {
	if !b.slicesEnabled() || n <= 0 {
		return 0
	}
	s := int64(float64(b.TokenLeft) / float64(n) * sliceGrace)
	if s < MinSliceTokens {
		s = MinSliceTokens
	}
	return s
}

func sortBy(vs []Verdict, strategy string) {
	if strategy == "value-first" {
		sort.SliceStable(vs, func(i, j int) bool {
			if vs[i].Score != vs[j].Score {
				return vs[i].Score > vs[j].Score
			}
			if vs[i].Est != vs[j].Est {
				return vs[i].Est < vs[j].Est
			}
			return vs[i].ID < vs[j].ID
		})
		return
	}
	// easy-first：成本升序，同成本看分值与 id（保证稳定、可复现）
	sort.SliceStable(vs, func(i, j int) bool {
		if vs[i].Est != vs[j].Est {
			return vs[i].Est < vs[j].Est
		}
		if vs[i].Score != vs[j].Score {
			return vs[i].Score > vs[j].Score
		}
		return vs[i].ID < vs[j].ID
	})
}

func noteFor(p Plan, total int) string {
	if p.Exhausted && len(p.Todo) == 0 {
		return fmt.Sprintf("共 %d 题：解出 %d、放弃 %d、无题可做", total, len(p.Solved), len(p.GiveUp))
	}
	s := fmt.Sprintf("共 %d 题：解出 %d、待做 %d、放弃 %d；策略=%s",
		total, len(p.Solved), len(p.Todo), len(p.GiveUp), p.Strategy)
	if p.Slice > 0 {
		s += fmt.Sprintf("；单题切片≈%s", kilo(p.Slice))
	}
	return s
}

func idOrName(c Challenge) string {
	if strings.TrimSpace(c.ID) != "" {
		return c.ID
	}
	return c.Name
}

// kilo 把 token 数渲染成便于阅读的短串（决策理由要进上下文，别写 450000 这种）。
func kilo(n int64) string {
	if n >= 1_000_000 {
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	}
	return fmt.Sprintf("%dK", n/1000)
}
