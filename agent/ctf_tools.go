package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	actool "github.com/jintilm/praetor/internal/norma/tool"
)

// CTF 提交结果。Verdict 的取值与判分口径绑定，别随意外扩：
//
//	accepted  平台判对（离线模式=与期望 flag 完全一致）
//	rejected  平台判错（离线模式=不一致）
//	duplicate 该 flag 之前提交过，本次没有再次打到平台
type CTFSubmitResult struct {
	Verdict string `json:"verdict"`
	Detail  string `json:"detail,omitempty"`
	Raw     string `json:"raw,omitempty"` // 平台原文（离线模式为空）
}

// CTFSubmitter 是 CTF 的提交后端（去重 + 判题 + 首解收敛都在实现侧）。
//
// 为什么做成接口而不是在工具里直接发 HTTP：
//   - 工具在 agent 包里，不该知道 CTFd 的 URL/Token 长什么样；
//   - 去重和"判对之后收敛全任务"需要 DB 与 Engine，那两样只有 server 拿得到；
//   - 测试可以注入假实现，把"同一 flag 只打一次平台"这类行为锁死。
type CTFSubmitter interface {
	SubmitFlag(ctx context.Context, challengeID, flag string) (*CTFSubmitResult, error)
}

// SetCTFSubmitter 注入提交后端（nil = 工具不可用，会明确报错而不是静默成功）。
func (t *ToolSet) SetCTFSubmitter(s CTFSubmitter) { t.ctfSubmitter = s }

// ctfSubmit 是 CTF 域的**唯一提交出口**。
//
// 三条硬约束（都在实现侧，不靠模型自觉）：
//  1. 同一个 flag 全局只提交一次（去重表主键就是 flag 的 sha256）；
//  2. 被判错的 flag 不允许复投（复投只会浪费判题次数，平台还可能风控）；
//  3. 判对之后由后端触发**首解收敛**，同题其余 solver 收到停止指令。
func (t *ToolSet) ctfSubmit() actool.CoreTool {
	return writeTool("ctf_submit",
		"提交一个 flag 给平台判题（CTF 域**唯一提交出口**；只在正文里写\"解出来了\"不算数）。\n"+
			"拿到 flag 立刻提交，不要等\"完全确认\"——竞速里晚一步就白干。\n"+
			"返回 verdict：accepted（判对，任务会被收敛）/ rejected（判错，**不要重复提交同一个 flag**）/ "+
			"duplicate（这个 flag 之前提交过，直接看上次结论）。\n"+
			"不要猜格式硬凑：flag 必须是你从目标实例真实拿到的串。",
		obj(map[string]any{
			"flag":         str("要提交的 flag 原文（从目标实例真实获取，不要拼接猜测）"),
			"challenge_id": str("可选：题目 id（多题任务里用来归属，离线判分可留空）"),
			"evidence":     str("可选：一句话说明从哪里拿到的（URL/参数/命令），便于复盘"),
		}, "flag"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Flag        string `json:"flag"`
				ChallengeID string `json:"challenge_id"`
				Evidence    string `json:"evidence"`
			}
			_ = json.Unmarshal(in, &a)

			flag, err := normalizeCTFFlag(a.Flag)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if t.ctfSubmitter == nil {
				// 明确不可用，而不是假装成功——否则模型会以为交过了。
				return actool.Errorf("ctf_submit 当前不可用：本任务没有配置判题后端（离线模式需设 PRAETOR_CTF_EXPECTED_FLAG；在线模式需配 CTFd）"), nil
			}
			res, err := t.ctfSubmitter.SubmitFlag(ctx, strings.TrimSpace(a.ChallengeID), flag)
			if err != nil {
				return actool.Errorf("提交失败：" + err.Error()), nil
			}
			out := map[string]any{"verdict": res.Verdict}
			if res.Detail != "" {
				out["detail"] = res.Detail
			}
			if res.Raw != "" {
				out["raw"] = res.Raw
			}
			switch res.Verdict {
			case "accepted":
				out["hint"] = "已判对。本任务会收束，不要再做新探测。"
			case "rejected":
				out["hint"] = "平台判错。**不要重复提交同一个 flag**；重新确认校验逻辑，或换一条思路。"
			case "duplicate":
				out["hint"] = "该 flag 之前提交过，本次没有再次打到平台。按上一次的 verdict 决定下一步。"
			}
			return jsonResult(out)
		})
}

// normalizeCTFFlag 做**最轻**的形状校验：只挡明显不是 flag 的输入（空、带空白、没有花括号）。
//
// 刻意不在这里套用 domain 的严格正则：不同比赛的 flag 格式差异很大，
// 工具层过严会把合法 flag 挡在门外。严格判定交给判题后端/Verifier。
func normalizeCTFFlag(s string) (string, error) {
	f := strings.TrimSpace(s)
	if f == "" {
		return "", fmt.Errorf("flag 不能为空")
	}
	if strings.ContainsAny(f, " \t\r\n") {
		return "", fmt.Errorf("flag 里不能有空白字符（粘贴时可能带进了换行）")
	}
	if !strings.Contains(f, "{") || !strings.HasSuffix(f, "}") {
		return "", fmt.Errorf("flag 形状不对（应形如 flag{...}）；请提交从目标实例真实获取的串")
	}
	if len(f) > 512 {
		return "", fmt.Errorf("flag 过长（%d 字符），确认是否粘错内容", len(f))
	}
	return f, nil
}
