package agent

import (
	"context"
	"fmt"

	"github.com/jintilm/praetor/agent/domain"
	"github.com/jintilm/praetor/internal/norma/subagent"
	actool "github.com/jintilm/praetor/internal/norma/tool"
)

// Dispatch 程序化派一个 specialist：由代码决定派谁、派什么，不经过模型对
// Agent 工具的调用决策。
//
// 为什么需要（docs §5.5(6)）：task 182/183/184 在「Agent 工具已在工具面上、提示词也
// 明确要求默认先派」的条件下，自发派发次数是 0；task 185 人明确要求才有 1 次。
// 结论是「必须派发」的场景（多题竞速、多方向并行）不能指望模型自觉 —— 只能在代码里派。
//
// 与 Agent 工具的唯一区别是「谁决定派」；独立上下文、独立墙钟、agent_type 记账、
// 事件镜像、取消传播全部复用 subagent 的同一套实现。
//
// tools 非空时按白名单裁剪父工具集（语义与 SDK 一致：未知名字静默丢弃）。
// tc 必须是父 agent 当次的工具上下文 —— 传 nil 会退化成只有空目录，子 agent 会丢失
// 沙箱视角（读不到 /chal、写不进 /work），表现为「环境坏了」而不是「参数没传」。
func Dispatch(ctx context.Context, cfg subagent.Config, agentType, prompt string, tc *actool.ToolContext, tools []string) (string, error) {
	if agentType == "" {
		return "", fmt.Errorf("agent: Dispatch 需要 agentType")
	}
	if len(tools) > 0 {
		cfg.ParentTools = domain.FilterTools(cfg.ParentTools, tools)
	}
	return subagent.RunWithContext(ctx, cfg, agentType, prompt, tc)
}
