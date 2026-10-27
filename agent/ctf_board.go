package agent

import (
	"context"
	"encoding/json"
	"strings"

	actool "github.com/jintilm/praetor/internal/norma/tool"
)

// CTFBoardEntry 是看板上的一道题：决策输入 + 结论一起给模型，避免它再自己算一遍。
type CTFBoardEntry struct {
	ID          string  `json:"id"`
	Name        string  `json:"name,omitempty"`
	Category    string  `json:"category,omitempty"`
	Points      int     `json:"points"`
	Solves      int     `json:"solves"`
	State       string  `json:"state"`  // new | active | solved | abandoned
	Action      string  `json:"action"` // start | continue | give_up
	EstTokens   int64   `json:"est_tokens"`
	SpentTokens int64   `json:"spent_tokens"`
	Score       float64 `json:"score,omitempty"`
	Reason      string  `json:"reason,omitempty"`
}

// CTFBoard 是「做哪题、什么时候放弃」的结论（P2-6）。
//
// 为什么把这些字段直接摊开给模型：它需要的是**可执行的下一步**（先做哪题、
// 这题还剩多少额度、为什么该放弃），而不是一堆原始数字自己去推。
type CTFBoard struct {
	Strategy  string          `json:"strategy"` // easy-first | value-first
	Recommend string          `json:"recommend,omitempty"`
	Note      string          `json:"note,omitempty"`
	Slice     int64           `json:"slice_tokens,omitempty"`
	TokenLeft int64           `json:"token_left,omitempty"`
	Exhausted bool            `json:"exhausted,omitempty"`
	Todo      []CTFBoardEntry `json:"todo,omitempty"`
	GiveUp    []CTFBoardEntry `json:"give_up,omitempty"`
	Solved    []string        `json:"solved,omitempty"`
}

// CTFBoardProvider 提供看板与放弃记录。
//
// 实现在 server：它同时握着题目来源、DB 进度和任务预算，这三样 agent 包里都没有。
// 抽成接口是为了让工具层可单测（注入假实现就能锁住"放弃必须写原因"这类约束）。
type CTFBoardProvider interface {
	// Board 返回当前排序与建议。
	Board(ctx context.Context) (*CTFBoard, error)
	// GiveUp 记录放弃并返回刷新后的看板（省掉模型再调一次）。
	GiveUp(ctx context.Context, challengeID, reason string) (*CTFBoard, error)
}

// SetCTFBoard 注入看板提供者（nil = ctf_board 明确报不可用）。
func (t *ToolSet) SetCTFBoard(b CTFBoardProvider) { t.ctfBoard = b }

// ctfBoardTool 把「先做哪题 / 什么时候放弃」变成一次可查的决策，而不是让模型自己猜。
//
// 为什么必须有这个工具：多题任务里，模型看不到"还有哪些题、各值多少分、我花了多少"，
// 只能凭题面印象决定——于是常见行为是死磕第一道看到的题直到预算烧光。
// 看板把分值/难度/已花/剩余额度摊开，并直接给出「下一个做哪道」。
//
// 两个动作合成一个工具（而不是 ctf_board + ctf_giveup 两个）：schema 是每轮都要付的钱。
func (t *ToolSet) ctfBoardTool() actool.CoreTool {
	return writeTool("ctf_board",
		"查题目看板（CTF 域）：按性价比排序的可做题目、建议的下一题、每题预估与已花、剩余预算。\n"+
			"开始一题之前先看一眼：**先做性价比高的题**，别死磕当前这题。\n"+
			"要放弃某题时传 give_up=<id> + reason=<试过什么、卡在哪>；放弃会被记录，之后不再推荐它。\n"+
			"预算/时间快用完时看板会直接给 exhausted=true，那时应该停下并说明做到哪一步。",
		obj(map[string]any{
			"give_up": str("可选：要放弃的题目 id（传了就记录放弃并返回刷新后的看板）"),
			"reason":  str("放弃原因（give_up 时必填）：已经试过哪些思路、卡在什么地方"),
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				GiveUp string `json:"give_up"`
				Reason string `json:"reason"`
			}
			_ = json.Unmarshal(in, &a)
			if t.ctfBoard == nil {
				return actool.Errorf("ctf_board 当前不可用：本任务没有配置题目来源（离线需设 settings ctf.challenge_dir.<taskID> 或 PRAETOR_CTF_CHALLENGE_DIR；在线需配 CTFd）"), nil
			}
			id := strings.TrimSpace(a.GiveUp)
			if id == "" {
				b, err := t.ctfBoard.Board(ctx)
				if err != nil {
					return actool.Errorf("读取看板失败：" + err.Error()), nil
				}
				return jsonResult(boardView(b))
			}
			// 放弃必须写原因：没有原因的放弃等于"这题我不想做了"，
			// 下一轮（或换人接手）看到这条记录什么也学不到。
			reason := strings.TrimSpace(a.Reason)
			if reason == "" {
				return actool.Errorf("放弃 " + id + " 需要给出 reason（试过什么、卡在哪）；空原因的放弃记录没有价值"), nil
			}
			b, err := t.ctfBoard.GiveUp(ctx, id, reason)
			if err != nil {
				return actool.Errorf("记录放弃失败：" + err.Error()), nil
			}
			out := boardView(b)
			out["gave_up"] = id
			return jsonResult(out)
		})
}

// boardView 把看板压成工具输出。
//
// 刻意只给字段的子集：GiveUp 里的历史项按"只留 id + 原因"精简，
// 否则看板一长，光是"已放弃清单"就能占满一屏上下文。
func boardView(b *CTFBoard) map[string]any {
	if b == nil {
		return map[string]any{"note": "看板为空"}
	}
	out := map[string]any{
		"strategy": b.Strategy,
		"note":     b.Note,
	}
	if b.Recommend != "" {
		out["recommend"] = b.Recommend
	}
	if b.Slice > 0 {
		out["slice_tokens"] = b.Slice
	}
	if b.TokenLeft > 0 {
		out["token_left"] = b.TokenLeft
	}
	if b.Exhausted {
		out["exhausted"] = true
	}
	if len(b.Todo) > 0 {
		out["todo"] = b.Todo
	}
	if len(b.Solved) > 0 {
		out["solved"] = b.Solved
	}
	if len(b.GiveUp) > 0 {
		gave := make([]map[string]any, 0, len(b.GiveUp))
		for _, e := range b.GiveUp {
			item := map[string]any{"id": e.ID, "reason": e.Reason}
			if e.SpentTokens > 0 {
				item["spent_tokens"] = e.SpentTokens
			}
			gave = append(gave, item)
		}
		out["give_up"] = gave
	}
	return out
}
