package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	actool "github.com/jintilm/praetor/internal/norma/tool"
)

// CTFChallengeFile 是一个已落盘的附件（只给路径与元信息，不给内容）。
type CTFChallengeFile struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	Bytes int64  `json:"bytes"`
}

// CTFChallenge 是一次题面拉取的结果。
//
// 为什么带 Source/Dir：模型需要知道"这些文件在哪、我能不能直接 Read"，
// 运维排查时也要知道是离线目录还是 CTFd 拉的。
type CTFChallenge struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Category    string             `json:"category,omitempty"`
	Description string             `json:"description,omitempty"`
	ConnInfo    string             `json:"connection_info,omitempty"`
	Files       []CTFChallengeFile `json:"files,omitempty"`
	Dir         string             `json:"dir,omitempty"` // 附件落盘目录
	Resets      int                `json:"resets"`        // 剩余重置次数；-1 = 平台不提供
	Source      string             `json:"source"`        // offline | ctfd
	Truncated   bool               `json:"truncated,omitempty"`
}

// CTFChallengeSource 拉取题面并把附件落盘。
//
// 抽成接口的理由与 submitter 相同：离线（题库/本地目录）与 CTFd 两套来源要能互换，
// 而工具本身不该知道 HTTP 细节；测试也能注入假实现把"只回摘要不回正文"锁死。
type CTFChallengeSource interface {
	Fetch(ctx context.Context, challengeID string) (*CTFChallenge, error)
}

// SetCTFChallengeSource 注入题面来源（nil = 工具明确报不可用）。
func (t *ToolSet) SetCTFChallengeSource(s CTFChallengeSource) { t.ctfChallenge = s }

// ctfChallengeDescriptionMax 是题面正文进上下文的上限。
//
// 题面动辄几千字，但它**只在开局读一次**，所以给得比工具输出宽松些；
// 仍然封顶是为了防止某些平台把整页 HTML 塞在 description 里（实测见过）。
const ctfChallengeDescriptionMax = 4000

// ctfChallengeTool 把题面与附件整理成"模型能直接用"的形态。
//
// 关键约束：**附件落盘、只回路径**。把附件正文塞进工具结果会让上下文一次性膨胀，
// 而且模型之后每次 Read 都要重新付这笔钱——它需要时自己去读就够了。
func (t *ToolSet) ctfChallengeTool() actool.CoreTool {
	return writeTool("ctf_challenge",
		"拉取题面并把附件**落盘**（CTF 域）。返回题目名称/分类/题面摘要/实例地址/附件路径/剩余重置次数。\n"+
			"附件不会以正文返回——你需要内容时用 Read 打开返回里的 path（大文件先看大小再决定读多少）。\n"+
			"拿到题面后：先判断题型（web/pwn/rev/crypto/forensics），再决定用哪些工具；"+
			"实例地址有重置次数限制时，别把实例玩坏。",
		obj(map[string]any{
			"id": str("题目 id（多题任务里指定；省略=用任务配置的默认题目）"),
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				ID string `json:"id"`
			}
			_ = json.Unmarshal(in, &a)
			if t.ctfChallenge == nil {
				return actool.Errorf("ctf_challenge 当前不可用：本任务没有配置题面来源（离线需设 settings ctf.challenge_dir.<taskID> 或 PRAETOR_CTF_CHALLENGE_DIR；在线需配 CTFd）"), nil
			}
			ch, err := t.ctfChallenge.Fetch(ctx, strings.TrimSpace(a.ID))
			if err != nil {
				return actool.Errorf("拉取题面失败：" + err.Error()), nil
			}
			// 题面截断：标记出来，让模型知道"题面可能不完整"，而不是以为就这么多。
			desc := ch.Description
			if len([]rune(desc)) > ctfChallengeDescriptionMax {
				desc = string([]rune(desc)[:ctfChallengeDescriptionMax])
				ch.Truncated = true
			}
			out := map[string]any{
				"id": ch.ID, "name": ch.Name, "source": ch.Source,
				"description": desc,
				"resets":      ch.Resets,
			}
			if ch.Category != "" {
				out["category"] = ch.Category
			}
			if ch.ConnInfo != "" {
				out["connection_info"] = ch.ConnInfo
			}
			if ch.Dir != "" {
				out["dir"] = ch.Dir
			}
			if len(ch.Files) > 0 {
				out["files"] = ch.Files
			}
			if ch.Truncated {
				out["truncated"] = true
				out["hint"] = fmt.Sprintf("题面超过 %d 字已截断；完整内容看 dir 里的文件或用 Read 打开", ctfChallengeDescriptionMax)
			}
			if ch.Resets < 0 {
				out["resets_note"] = "平台未提供重置次数"
			}
			return jsonResult(out)
		})
}
