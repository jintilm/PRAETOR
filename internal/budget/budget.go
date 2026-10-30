// Package budget 是任务预算的**判定逻辑**（纯函数，不碰 DB/时钟）。
//
// 存在理由：执行文档里 `domain.Budget` 的 MaxTokens / MaxToolCalls / MaxWall 长期
// **没有任何执行层消费**（全仓只有 MaxDepth 透传给了 subagent）——
// 也就是说「3M tokens / 800 次工具调用」这些数字从来没生效过，只是注释。
// 这里把"该不该停"的判断单独抽出来，让它可测、可复用（evidence 串行调度先接，
// P2 的 race 调度将来直接复用同一份）。
//
// 边界：本包只回答"超没超"，**不负责停谁**。停任务的动作在引擎层（settle 时序），
// 因为只有引擎知道怎么优雅收尾（等 drain、跑终局 planner、定终态）。
package budget

import (
	"fmt"
	"time"
)

// Limits 是上限；0 表示该项不限制。
type Limits struct {
	Tokens    int64
	ToolCalls int64
	Wall      time.Duration
}

// Usage 是当前累计用量。
type Usage struct {
	Tokens    int64
	ToolCalls int64
	Elapsed   time.Duration
}

// Breach 是触发停止的维度。
type Breach string

const (
	BreachNone      Breach = ""
	BreachTokens    Breach = "tokens"
	BreachToolCalls Breach = "tool_calls"
	BreachWall      Breach = "wall"
)

// Decision 是判定结果。Stop=false 时 Detail 为空。
type Decision struct {
	Stop   bool
	Breach Breach
	Detail string // 人可读，直接进日志/任务备注
}

// Breaches 返回**所有**已超限的维度，顺序固定为 tokens → tool_calls → wall。
//
// 与 Evaluate 的分工：Evaluate 是"只需一个结论"的便捷版（取这里的第一条），
// 硬闸用它就够——停一次就够了，多报没有意义。
//
// 但 dry-run 需要**全部**：它问的是"这个任务会撞到哪几堵墙"。
// 只看第一条的话，一个同时超 tokens 和 tool_calls 的任务在账本里永远只留 token 一条，
// 一周后据此决定要不要开硬闸时，就会漏掉一整个维度（而 tool_calls 恰恰是唯一
// 与"钱"无关、只防死循环的维度，最容易被漏）。
func Breaches(l Limits, u Usage) []Decision {
	var out []Decision
	if l.Tokens > 0 && u.Tokens >= l.Tokens {
		out = append(out, Decision{
			Stop: true, Breach: BreachTokens,
			Detail: fmt.Sprintf("token 预算用尽（%s / %s）", fmtInt(u.Tokens), fmtInt(l.Tokens)),
		})
	}
	if l.ToolCalls > 0 && u.ToolCalls >= l.ToolCalls {
		out = append(out, Decision{
			Stop: true, Breach: BreachToolCalls,
			Detail: fmt.Sprintf("工具调用次数用尽（%d / %d）", u.ToolCalls, l.ToolCalls),
		})
	}
	if l.Wall > 0 && u.Elapsed >= l.Wall {
		out = append(out, Decision{
			Stop: true, Breach: BreachWall,
			Detail: fmt.Sprintf("墙钟预算用尽（%s / %s）", roundDur(u.Elapsed), roundDur(l.Wall)),
		})
	}
	return out
}

// Evaluate 判定是否应停止。
//
// 判定顺序固定为 tokens → tool_calls → wall：
// 同时超多个时，报 token 更有信息量（它直接对应钱），而 wall 是既有超时协调器也管的事，
// 晚了会先被那边接走。顺序固定也让日志可预测、测试可断言。
func Evaluate(l Limits, u Usage) Decision {
	if ds := Breaches(l, u); len(ds) > 0 {
		return ds[0]
	}
	return Decision{}
}

// Remaining 返回各维度的剩余量（0 上限的维度返回 -1 表示不限）。
//
// 给 planner 用：让模型知道"还剩多少"比"已经用了多少"更有行动指导性
// （剩余少时它会主动收束，而不是继续铺新方向）。
func Remaining(l Limits, u Usage) (tokens, toolCalls int64, wall time.Duration) {
	tokens, toolCalls, wall = -1, -1, -1
	if l.Tokens > 0 {
		tokens = l.Tokens - u.Tokens
		if tokens < 0 {
			tokens = 0
		}
	}
	if l.ToolCalls > 0 {
		toolCalls = l.ToolCalls - u.ToolCalls
		if toolCalls < 0 {
			toolCalls = 0
		}
	}
	if l.Wall > 0 {
		wall = l.Wall - u.Elapsed
		if wall < 0 {
			wall = 0
		}
	}
	return
}

// FromDomain 把领域包的预算换算成 Limits。
//
// 单独一层是为了让"领域声明 → 执行上限"只有一个转换点：
// 以后改 Budget 字段语义（比如 MaxTokens 变成只算 input）只需动这里。
func FromDomain(maxTokens, maxToolCalls int, maxWall time.Duration) Limits {
	return Limits{Tokens: int64(maxTokens), ToolCalls: int64(maxToolCalls), Wall: maxWall}
}

func fmtInt(n int64) string {
	// 千分位，便于人读（日志里 1500000 和 1,500,000 的可读性差别很大）
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var b []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			b = append(b, ',')
		}
		b = append(b, c)
	}
	return string(b)
}

func roundDur(d time.Duration) time.Duration {
	if d >= time.Minute {
		return d.Round(time.Minute)
	}
	return d.Round(time.Second)
}
