package agent

import (
	"fmt"
	"time"
)

// 轮次/预算余量注入（P2-8）：
//
// 问题不是「模型不知道有上限」——上限写在提示词里。问题是它**不知道离上限还有多远**：
// 实测里 worker 会在第 25 轮才开始铺一条需要 15 轮的新方向，然后在第 30 轮被 SDK 砍进
// 收尾。收尾只能救回"已经拿到的东西"，救不回"刚铺开、还没验证的那条线"。
//
// 为什么不做成提示词里的一行静态文本：这个数字每轮都在变，第 1 轮写"剩 30 轮"，到第
// 20 轮它还是写着 30，比没有更糟（模型会以为自己很宽裕）。所以要按轮播报。
//
// 播报通道是**普通 user 消息**（harness.QueryInput.BudgetNotice），不是 system：
// system 是稳定前缀，塞会变的东西会打掉 prompt cache；也不是 PreToolUse 的 block 通道
// ——那会把它触发的那次工具调用**打断**成一个错误，等于每次提醒都浪费一轮。
const (
	// budgetNoticeEveryTurns 是常规播报的间隔。5 轮一次是成本/时效的折中：
	// 每条提醒约 60 token 且会留在上下文里被反复重发，每轮播等于每轮多付一次。
	budgetNoticeEveryTurns = 5
	// budgetWarnRatio / budgetCriticalRatio 是两档告警线（按**剩余比例**算，不是绝对轮次）。
	// 用比例是因为不同角色的预算差一个数量级（solver 12 轮 vs worker 40 轮），
	// 绝对阈值必然对某一档完全失效。
	budgetWarnRatio     = 0.20
	budgetCriticalRatio = 0.10
)

// 播报档位。数值有序，用于「只升不降」的去重：已经报过 critical 就不再回头报 routine。
const (
	budgetLevelNone = iota
	budgetLevelRoutine
	budgetLevelWarn
	budgetLevelCritical
)

// budgetNotice 是每轮预算提醒的判定与渲染。
//
// 它**不持有时钟**：轮次由 harness 给，已用墙钟也由 harness 给（同一个 startTime，
// 也就是 MaxDuration 判定的那个起点）。这样「提醒说还剩 2 分钟」和「2 分钟后真的被砍」
// 是同一个口径——P1-4 已经踩过一次「两处阈值不同源」的亏。
//
// 拆成结构体而不是一个裸闭包，是为了让「第几轮该报哪一档」能被测试直接钉住。
type budgetNotice struct {
	maxTurns int           // 0 = 轮次不限
	wall     time.Duration // 0 = 墙钟不限

	// fired 是已经播报过的最高档位。两档告警各只报一次：
	// 剩余比例在 20% 附近抖动时（比如一轮里连开几个工具），不设去重会连报好几条。
	fired int
}

// newBudgetNotice 返回可直接挂到 agentcore.Options.BudgetNotice 的回调。
// 两个预算都不限时返回 nil（harness 见到 nil 就完全不介入，零成本）。
func newBudgetNotice(maxTurns int, wall time.Duration) func(turn int, elapsed time.Duration) string {
	if maxTurns <= 0 && wall <= 0 {
		return nil
	}
	n := &budgetNotice{maxTurns: maxTurns, wall: wall}
	return n.notice
}

// notice 返回本轮要注入的提醒文本；"" = 本轮不打扰。
func (n *budgetNotice) notice(turn int, elapsed time.Duration) string {
	lvl := n.level(turn, elapsed)
	if lvl == budgetLevelNone || lvl <= n.fired {
		return ""
	}
	n.fired = lvl
	return n.render(turn, elapsed, lvl)
}

// level 判定本轮属于哪一档。优先级：critical > warn > 常规播报。
//
// 用「剩余比例的最小值」而不是分别判断：轮次和墙钟哪个先耗尽就先撞哪堵墙，
// 提醒必须跟着更紧的那个走（否则会出现"轮次还剩一半、墙钟只剩 2 分钟"却报 routine）。
func (n *budgetNotice) level(turn int, elapsed time.Duration) int {
	ratio, limited := 1.0, false
	if n.maxTurns > 0 {
		left := n.maxTurns - turn
		if left < 0 {
			left = 0
		}
		ratio = float64(left) / float64(n.maxTurns)
		limited = true
	}
	if n.wall > 0 {
		left := n.wall - elapsed
		if left < 0 {
			left = 0
		}
		if r := left.Seconds() / n.wall.Seconds(); !limited || r < ratio {
			ratio = r
		}
		limited = true
	}
	if !limited {
		return budgetLevelNone
	}
	switch {
	case ratio <= budgetCriticalRatio:
		return budgetLevelCritical
	case ratio <= budgetWarnRatio:
		return budgetLevelWarn
	case turn > 0 && turn%budgetNoticeEveryTurns == 0:
		return budgetLevelRoutine
	}
	return budgetLevelNone
}

// render 渲染一条提醒。三种档位的差别不只是语气——是**动作**：
// 常规播报只报数（让模型自己权衡），warn 要求停止铺新方向，critical 要求立刻收尾。
// 只说"还剩 X 轮"而不说该干什么，等于把判断推回给模型，实测里模型会继续做下去。
func (n *budgetNotice) render(turn int, elapsed time.Duration, lvl int) string {
	out := ""
	switch lvl {
	case budgetLevelCritical:
		out = "【预算提醒·收尾】"
	case budgetLevelWarn:
		out = "【预算提醒】"
	default:
		out = "【预算播报】"
	}

	out += "第 " + itoa(turn)
	if n.maxTurns > 0 {
		left := n.maxTurns - turn
		if left < 0 {
			left = 0
		}
		out += "/" + itoa(n.maxTurns) + " 轮"
		if left == 0 {
			out += "（本轮是最后一轮）"
		} else {
			out += "（剩 " + itoa(left) + " 轮）"
		}
	} else {
		out += " 轮（轮次不限）"
	}
	if n.wall > 0 {
		left := n.wall - elapsed
		if left < 0 {
			left = 0
		}
		out += "；墙钟剩 " + shortDur(left) + "（预算 " + shortDur(n.wall) + "）"
	}
	out += "。"

	switch lvl {
	case budgetLevelCritical:
		out += "现在停止侦察：立刻把已经拿到的结论写回（record_fact / report_finding），" +
			"然后结束本次 run。不要再开新的工具链、不要重试已经失败两次以上的路子。"
	case budgetLevelWarn:
		out += "不要再铺新方向。先把已经确认的结论写回（record_fact / report_finding），" +
			"剩余时间只用来补最关键的一两个缺口。"
	}
	return out
}

// shortDur 是给模型看的时长格式：只保留一个量级，避免 "1m59.999s" 这种噪音。
// 与 roundDur（日志用）分开：日志要精确到秒，提示词要短。
func shortDur(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	default:
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	}
}

// itoa 只为避免在字符串拼接里反复 fmt.Sprintf（这条路径每轮都会走）。
func itoa(n int) string { return fmt.Sprintf("%d", n) }
