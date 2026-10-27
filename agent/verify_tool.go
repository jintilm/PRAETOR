package agent

import (
	"context"
	"encoding/json"

	actool "github.com/jintilm/praetor/internal/norma/tool"
)

// FindingVerifyResult 是确定性验证的结构化结论，直接作为工具结果回给模型。
//
// 为什么不回一句「已验证」：模型需要知道**为什么**没过（状态码变了 / 长度缩水 /
// 相似度不够），才能决定是换个证据、补一次复现，还是老实标成疑似。
type FindingVerifyResult struct {
	FindingID  int64    `json:"finding_id"`
	BindingID  int64    `json:"binding_id"`
	State      string   `json:"state"` // verified / suspected
	Reproduced bool     `json:"reproduced"`
	Status     int      `json:"status"`
	Similarity float64  `json:"similarity"`
	LenRatio   float64  `json:"len_ratio"`
	Reasons    []string `json:"reasons"`
}

// FindingVerifier 是宿主注入的确定性验证器（server 侧用 evidence.Store + 记录代理实现）。
//
// bindingID<=0 表示「让实现自己挑一条证据」：优先 role=proof，其次 verification，最后一条。
// minSimilarity<=0 表示用默认阈值。
type FindingVerifier interface {
	VerifyFinding(ctx context.Context, findingID, bindingID int64, minSimilarity float64) (*FindingVerifyResult, error)
}

// SetFindingVerifier 注入验证器；nil = 该 agent 看不到 verify_finding 的能力（调用会明确报错）。
func (t *ToolSet) SetFindingVerifier(v FindingVerifier)   { t.findingVerifier = v }
func (w *Worker) SetFindingVerifier(v FindingVerifier)    { w.findingVerifier = v }
func (p *Planner) SetFindingVerifier(v FindingVerifier)   { p.findingVerifier = v }
func (m *MainAgent) SetFindingVerifier(v FindingVerifier) { m.findingVerifier = v }

// verifyFinding 是「确定性验证」工具：重放绑定的证据，判定漏洞是否仍成立。
func (t *ToolSet) verifyFinding() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "verify_finding",
		Description: "对已登记漏洞执行确定性复现验证：重放它绑定的证据请求，比对状态码、响应长度与结构相似度，" +
			"把结论落库为 verified（仍可复现）或 suspected（不一致/证据不足）。不依赖模型判断。",
		Prompt: "在 report_finding 且 bind_finding_traffic 成功后调用。可选 binding_id 指定证据；不传则自动挑 proof/verification 那条。" +
			"返回 suspected 时要看 reasons：状态码变化通常意味着已修复或被 WAF 拦，长度/相似度不足可能是页面改版或证据过期。" +
			"不要为了让它变绿而反复重放同一请求；也不能用它替代真实复现——它只回答「原证据是否仍成立」。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"finding_id": map[string]any{
					"type":        "integer",
					"description": "独立漏洞记录 ID（report_finding / get_finding_traffic 用的那个 finding_id，不是节点 ID）。",
				},
				"binding_id": map[string]any{
					"type":        "integer",
					"description": "可选：指定哪条绑定的流量证据用于重放；省略则自动挑选。",
				},
				"min_similarity": map[string]any{
					"type":        "number",
					"description": "可选：响应结构相似度阈值（0~1），默认 0.85。调高更严格。",
				},
			},
			"required": []any{"finding_id"},
		},
		ReadOnly:   func(json.RawMessage) bool { return false }, // 会写库里的验证状态
		Concurrent: func(json.RawMessage) bool { return false },
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var req struct {
				FindingID     int64   `json:"finding_id"`
				BindingID     int64   `json:"binding_id"`
				MinSimilarity float64 `json:"min_similarity"`
			}
			if err := json.Unmarshal(in, &req); err != nil {
				return actool.Errorf("参数解析失败：" + err.Error()), nil
			}
			if req.FindingID <= 0 {
				return actool.Errorf("finding_id 必填，且应为正整数的独立漏洞 ID（不是探索节点 ID）"), nil
			}
			if t.findingVerifier == nil {
				return actool.Errorf("确定性验证未启用：宿主没有注入 verifier（检查流量采集/证据存储是否开启）"), nil
			}
			res, err := t.findingVerifier.VerifyFinding(ctx, req.FindingID, req.BindingID, req.MinSimilarity)
			if err != nil {
				return actool.Errorf("验证失败：" + err.Error()), nil
			}
			if res == nil {
				return actool.Errorf("验证器没有返回结论"), nil
			}
			body, _ := json.MarshalIndent(res, "", "  ")
			return actool.Text(string(body)), nil
		},
	})
}
