package agent

import (
	"context"
	"encoding/json"

	actool "github.com/jintilm/praetor/internal/norma/tool"
)

// IdentityDiffRequest 是一次越权差分的入参：只给对象 URL 和两个身份名。
// 凭据由服务端从库里的 task_identities 取，模型不用把 Cookie 抄一遍。
type IdentityDiffRequest struct {
	URL       string
	Method    string
	LabelA    string
	LabelB    string
	Canary    string
	Anonymous bool
}

// IdentityDiffResult 是差分结论：状态 + 理由 + 三条流量的归属。
type IdentityDiffResult struct {
	State     string         `json:"state"`
	Reason    string         `json:"reason"`
	Canary    string         `json:"canary,omitempty"`
	TrafficID []string       `json:"traffic_ids,omitempty"`
	Statuses  map[string]int `json:"statuses,omitempty"`
}

// IdentityDiffer 由宿主注入（server 侧持有记录代理与范围校验）。
type IdentityDiffer interface {
	DiffIdentity(ctx context.Context, in IdentityDiffRequest) (*IdentityDiffResult, error)
}

func (t *ToolSet) SetIdentityDiffer(d IdentityDiffer) { t.identityDiffer = d }

func (w *Worker) SetIdentityDiffer(d IdentityDiffer) { w.identityDiffer = d }

func (t *ToolSet) identityDiff() actool.CoreTool {
	schema := obj(map[string]any{
		"url":     str("要判定的对象 URL（必须在本任务范围内），例如受害者名下的 /api/orders/1001"),
		"method":  str("HTTP 方法，默认 GET"),
		"label_a": str("拥有者身份名（先用 register_identity 登记）"),
		"label_b": str("另一身份名；用它去读 A 的对象"),
		"canary":  str("可选：覆盖身份上已登记的 canary，一般留空"),
	}, "url", "label_a", "label_b")
	return actool.Build(actool.Spec{
		Name: "identity_diff",
		Description: "越权（BOLA/IDOR）确定性判定：用 A、B 两个身份请求同一个对象，再加一条匿名对照，" +
			"由程序判 confirmed / rejected / inconclusive。三次请求都走记录代理并返回 traffic_id。" +
			"两边都能打开但内容相同、或匿名也能打开，都不算越权。",
		Prompt: "判定前确保两个身份是不同凭据、且 A 的 canary 是它独有的值（私有邮箱/订单号）。" +
			"返回 rejected 说明另一身份被挡住或这是公开资源；inconclusive 通常是缺 canary 或页面动态。" +
			"confirmed 后把 traffic_id 绑定到漏洞，再用 record_impact 提取物（idor 的 metrics 填 victim_canary）。",
		Schema:     schema,
		ReadOnly:   func(json.RawMessage) bool { return false },
		Concurrent: func(json.RawMessage) bool { return false },
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			if t.identityDiffer == nil {
				return actool.Errorf("identity_diff 未启用：本任务没有可用的记录代理或范围校验"), nil
			}
			var a struct {
				URL    string `json:"url"`
				Method string `json:"method"`
				LabelA string `json:"label_a"`
				LabelB string `json:"label_b"`
				Canary string `json:"canary"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if a.URL == "" || a.LabelA == "" || a.LabelB == "" {
				return actool.Errorf("url / label_a / label_b 都必填"), nil
			}
			if a.LabelA == a.LabelB {
				return actool.Errorf("label_a 与 label_b 不能同名"), nil
			}
			res, err := t.identityDiffer.DiffIdentity(ctx, IdentityDiffRequest{
				URL: a.URL, Method: a.Method, LabelA: a.LabelA, LabelB: a.LabelB, Canary: a.Canary, Anonymous: true,
			})
			if err != nil {
				return actool.Errorf("差分执行失败：" + err.Error()), nil
			}
			return jsonResult(res)
		},
	})
}
