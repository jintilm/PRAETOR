package agent

import (
	"context"
	"encoding/json"

	actool "github.com/jintilm/praetor/internal/norma/tool"
)

// HTTPProber 是受控 HTTP 探针：由 server 注入，走记录代理 + 范围校验。
//
// 为什么不直接让模型用 Bash+curl：那样流量不进索引（拿不到 traffic_id）、
// 不校验任务范围、也没有统一上限。取证要的是可复核的请求记录，不是对话里的命令。
type HTTPProber interface {
	Probe(ctx context.Context, in ProbeRequest) (*ProbeResult, error)
}

// 探针原语。
const (
	ProbePrimitiveRequest = "request" // 单发一条，建立对照
	ProbePrimitiveCompare = "compare" // A/B 两条：给相似度与状态差异（布尔盲注、双身份越权的基础）
	ProbePrimitiveTiming  = "timing"  // 重复发送：给耗时分布（时间盲注）
)

// ProbeTarget 是一次请求的描述。
type ProbeTarget struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// ProbeRequest 是一次探针调用的输入。
type ProbeRequest struct {
	Primitive string      `json:"primitive"`
	A         ProbeTarget `json:"a"`
	B         ProbeTarget `json:"b"`
	Runs      int         `json:"runs"`
	TimeoutMS int         `json:"timeout_ms"`
}

// ProbeAttempt 是一次实际发出的请求的测量结果。
type ProbeAttempt struct {
	Label     string `json:"label"`
	Status    int    `json:"status"`
	RespLen   int    `json:"resp_len"`
	RespHash  string `json:"resp_hash"`
	ElapsedMS int64  `json:"elapsed_ms"`
	// TrafficID 是这次请求在流量索引里的 id；拿到它才能 bind_finding_traffic。
	TrafficID string `json:"traffic_id,omitempty"`
	Error     string `json:"error,omitempty"`
}

// ProbeResult 是探针的测量结果：只描述事实（状态码/长度/耗时/相似度），
// 不给出「有没有漏洞」的结论——结论由 record_impact 依据提取物产生。
type ProbeResult struct {
	Primitive     string         `json:"primitive"`
	Attempts      []ProbeAttempt `json:"attempts"`
	StatusChanged bool           `json:"status_changed"`
	LenRatio      float64        `json:"len_ratio"`
	Similarity    float64        `json:"similarity"`
	Notes         []string       `json:"notes,omitempty"`
}

// SetHTTPProber 注入探针；nil = 该任务看不到 http_probe 的能力（调用会明确报不可用）。
func (t *ToolSet) SetHTTPProber(p HTTPProber) { t.prober = p }

// httpProbe 是「受控取证探针」：只测量，不下结论。
//
// 存在的理由：取证要的是「同一参数 +1/+2 的响应差」「A/B 身份拿到的东西是否一样」
// 「SLEEP(3) 是否真的慢 3 秒」——这些是测量。判断留给 record_impact：
// 它按 kind + metrics 决定这算几级危害。
func (t *ToolSet) httpProbe() actool.CoreTool {
	schema := obj(map[string]any{
		"primitive": map[string]any{
			"type": "string",
			"enum": []string{ProbePrimitiveRequest, ProbePrimitiveCompare, ProbePrimitiveTiming},
			"description": "request=单发一条（建立对照）；compare=A/B 两条对比（布尔盲注、双身份越权）；" +
				"timing=重复发送看耗时分布（时间盲注）",
		},
		"url":       str("请求 URL（必须在本任务范围内）"),
		"method":    str("HTTP 方法，默认 GET"),
		"headers":   map[string]any{"type": "object", "description": "请求头（如 Cookie/Authorization）"},
		"body":      str("请求体"),
		"b_url":     str("compare/timing 的 B 请求 URL"),
		"b_method":  str("B 请求方法，默认同 A"),
		"b_headers": map[string]any{"type": "object", "description": "B 请求头"},
		"b_body":    str("B 请求体"),
		"runs": map[string]any{
			"type": "integer", "description": "timing 的采样次数（默认 3，最多 5）",
		},
		"timeout_ms": map[string]any{"type": "integer", "description": "单请求超时（默认 10000，最大 30000）"},
	}, "primitive", "url")
	return writeTool("http_probe",
		"受控 HTTP 探针：请求走记录代理（流量入库并返回 traffic_id）、发送前做任务范围校验、不跟随重定向、响应体截断后算哈希。"+
			"compare 返回两次响应的相似度/长度比/状态差异，timing 返回每次耗时。"+
			"它只测量，不下结论——拿到结果后用 record_impact 落库（提取物 + metrics），由程序判定危害等级。",
		schema,
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if t.prober == nil {
				return actool.Errorf("http_probe 未启用：本任务没有可用的记录代理或范围校验（确认 traffic_capture 已开启）"), nil
			}
			var a struct {
				Primitive string            `json:"primitive"`
				URL       string            `json:"url"`
				Method    string            `json:"method"`
				Headers   map[string]string `json:"headers"`
				Body      string            `json:"body"`
				BURL      string            `json:"b_url"`
				BMethod   string            `json:"b_method"`
				BHeaders  map[string]string `json:"b_headers"`
				BBody     string            `json:"b_body"`
				Runs      int               `json:"runs"`
				TimeoutMS int               `json:"timeout_ms"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			res, err := t.prober.Probe(ctx, ProbeRequest{
				Primitive: a.Primitive,
				A:         ProbeTarget{Method: a.Method, URL: a.URL, Headers: a.Headers, Body: a.Body},
				B:         ProbeTarget{Method: a.BMethod, URL: a.BURL, Headers: a.BHeaders, Body: a.BBody},
				Runs:      a.Runs,
				TimeoutMS: a.TimeoutMS,
			})
			if err != nil {
				return actool.Errorf("探针执行失败：" + err.Error()), nil
			}
			return jsonResult(res)
		})
}
