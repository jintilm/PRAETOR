package agent

import (
	"github.com/jintilm/praetor/db"
	"github.com/jintilm/praetor/internal/norma/harness"
)

// subagentActivityTap 把子 agent 的事件流镜像进 activity 表。
//
// 为什么需要它：子 agent 的 harness 循环发生在 Agent 工具的 Call 内部，事件
// 不经过父 run 的 captureRunSession —— 没有这个 tap，派生出去的 solver/
// analyst 就是个黑盒：UI 上只见 lead 的 Agent 调用挂着，里面几十次工具调用
// 全部不可见（真机验证 task 35 时确认的缺口）。
//
// 记录口径与父 run 的 captureRunSession 保持一致（tool_use/tool_result/
// 最终文本），差异只有两处：
//   - Tool 名前缀 "agentType:"，混排时能一眼分辨这步是谁做的；
//   - 不记 thinking 与 usage —— thinking 噪音大，usage 由 llmrec 在 provider
//     层记账（子 agent 用同一个 wrapped provider，token 已按任务入账）。
// 返回的闭包按 agentType 分前缀；tool_use id → 工具名的映射必须按子 agent 隔离
//（不同 solver 的 id 空间互不相干，共享一张表会串名）。
func subagentActivityTap(emit func(db.Activity)) func(string, harness.Event) {
	if emit == nil {
		return nil
	}
	names := map[string]map[string]string{} // agentType -> tool_use id -> name
	return func(agentType string, ev harness.Event) {
		toolNames := names[agentType]
		if toolNames == nil {
			toolNames = map[string]string{}
			names[agentType] = toolNames
		}
		switch ev.Kind {
		case harness.KindToolUse:
			if ev.ToolUse == nil {
				return
			}
			toolNames[ev.ToolUse.ID] = ev.ToolUse.Name
			in := string(ev.ToolUse.Input)
			emit(db.Activity{
				Kind: "tool_use", Tool: agentType + ":" + ev.ToolUse.Name, ToolUseID: ev.ToolUse.ID,
				Summary: agentType + " " + ev.ToolUse.Name + " " + firstLine(in, 200), Detail: in,
			})
		case harness.KindToolResult:
			if ev.ToolResult == nil {
				return
			}
			out := blocksText(ev.ToolResult.Content)
			emit(db.Activity{
				Kind: "tool_result", Tool: agentType + ":" + toolNames[ev.ToolResult.ToolUseID],
				ToolUseID: ev.ToolResult.ToolUseID, IsError: ev.ToolResult.IsError,
				Summary: agentType + " " + firstLine(out, 200), Detail: out,
			})
		case harness.KindResult:
			if ev.Terminal == nil {
				return
			}
			text := ev.Terminal.Text
			if text == "" {
				return
			}
			emit(db.Activity{
				Kind: "text", Tool: agentType,
				Summary: agentType + " 完成：" + firstLine(text, 200), Detail: text,
			})
		}
	}
}
