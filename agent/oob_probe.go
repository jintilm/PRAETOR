package agent

import (
	"context"
	"encoding/json"

	actool "github.com/jintilm/praetor/internal/norma/tool"
)

// OOBProbeRequest 是一条带外回连探测：请求里用 {{OOB}} 占位，实际发出时替换成一次性回连地址。
type OOBProbeRequest struct {
	URL     string
	Method  string
	Headers map[string]string
	Body    string
	TTLSec  int
}

// OOBProbeResult 是回连结论。无回连是 inconclusive，不是"不存在"。
type OOBProbeResult struct {
	Token       string `json:"token"`
	CallbackURL string `json:"callback_url"`
	State       string `json:"state"`
	Reason      string `json:"reason"`
	Status      int    `json:"status,omitempty"`
	TrafficID   string `json:"traffic_id,omitempty"`
	HitMethod   string `json:"hit_method,omitempty"`
	HitRemote   string `json:"hit_remote,omitempty"`
	HitAt       string `json:"hit_at,omitempty"`
}

// OOBProber 由宿主注入（持有回连捕获器与记录代理）。
type OOBProber interface {
	ProbeOOB(ctx context.Context, in OOBProbeRequest) (*OOBProbeResult, error)
}

func (t *ToolSet) SetOOBProber(p OOBProber) { t.oobProber = p }
func (w *Worker) SetOOBProber(p OOBProber)  { w.oobProber = p }

func (t *ToolSet) oobProbe() actool.CoreTool {
	schema := obj(map[string]any{
		"url":         str("目标请求 URL，回连地址用 {{OOB}} 占位，例如 http://t/api/fetch?u={{OOB}}"),
		"method":      str("HTTP 方法，默认 GET"),
		"headers":     map[string]any{"type": "object", "description": "可选请求头"},
		"body":        str("可选请求体"),
		"ttl_seconds": map[string]any{"type": "integer", "description": "等待回连的秒数，默认 15，最大 60"},
	}, "url")
	return actool.Build(actool.Spec{
		Name: "oob_probe",
		Description: "带外回连探测：发一条请求，把其中 {{OOB}} 换成本次专用回连地址，等目标自己回连。" +
			"用于盲 SSRF、盲命令注入、盲 XXE 这类响应里看不出结果的漏洞。有回连=confirmed，等待超时=inconclusive（不等于没有）。" +
			"**装了 Burp 时优先用 MCP**：mcp__burp__generate_collaborator_payload 生成地址 → 注入请求 → mcp__burp__get_collaborator_interactions(payloadId) 取回连，命中明细也最全；本工具在没配 Burp 时兜底。",
		Prompt: "拿到 confirmed 后把 token 与回连时间记进漏洞证据，traffic_id 用于绑定。用 Burp MCP 时把 payload 与交互时间写进 evidence。" +
			"没回连先确认目标是否出网：可能是目标网络封了出站，换 DNS/HTTP 通道再说，别直接判不存在。",
		Schema:     schema,
		ReadOnly:   func(json.RawMessage) bool { return false },
		Concurrent: func(json.RawMessage) bool { return true },
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			if t.oobProber == nil {
				return actool.Errorf("oob_probe 未启用：未配置回连地址或记录代理"), nil
			}
			var a struct {
				URL     string            `json:"url"`
				Method  string            `json:"method"`
				Headers map[string]string `json:"headers"`
				Body    string            `json:"body"`
				TTLSec  int               `json:"ttl_seconds"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if a.URL == "" {
				return actool.Errorf("url 必填"), nil
			}
			res, err := t.oobProber.ProbeOOB(ctx, OOBProbeRequest{URL: a.URL, Method: a.Method, Headers: a.Headers, Body: a.Body, TTLSec: a.TTLSec})
			if err != nil {
				return actool.Errorf("回连探测失败：" + err.Error()), nil
			}
			return jsonResult(res)
		},
	})
}
