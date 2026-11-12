package agent

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/jintilm/praetor/internal/norma/permission"
	actool "github.com/jintilm/praetor/internal/norma/tool"
)

type VulnKnowledgeQuery struct {
	Query     string
	VulnClass string
	Limit     int
}

type VulnKnowledgeHit struct {
	ID                  int64    `json:"id"`
	Kind                string   `json:"kind"`
	Title               string   `json:"title"`
	Summary             string   `json:"summary"`
	VulnClass           string   `json:"vuln_class,omitempty"`
	CWE                 string   `json:"cwe,omitempty"`
	Technology          []string `json:"technology,omitempty"`
	Preconditions       string   `json:"preconditions,omitempty"`
	TestSteps           string   `json:"test_steps"`
	ExpectedSignals     string   `json:"expected_signals"`
	FalsePositiveChecks string   `json:"false_positive_checks"`
	Confidence          int      `json:"confidence"`
	SourceRef           string   `json:"source_ref,omitempty"`
}

// VulnKnowledgeSearcher is the model-facing read-only view of the curated
// vulnerability knowledge base. Implementations must return active entries only.
type VulnKnowledgeSearcher interface {
	SearchActiveVulnKnowledge(ctx context.Context, query VulnKnowledgeQuery) ([]VulnKnowledgeHit, error)
}

func (t *ToolSet) SetVulnKnowledge(s VulnKnowledgeSearcher) { t.vulnKnowledge = s }

func (t *ToolSet) searchVulnKnowledgeTool() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "search_vuln_knowledge",
		Description: "检索已审核启用的漏洞模式记忆。只在需要复用同类漏洞的测试路线、验证信号或误报检查时调用；" +
			"返回最多 5 条，包含来源和置信度。不要把候选或未验证结论当作事实。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"query":      map[string]any{"type": "string", "description": "关键词，例如技术栈、参数名、现象或漏洞描述"},
				"vuln_class": map[string]any{"type": "string", "description": "可选漏洞类别，例如 ssti / idor / ssrf"},
				"limit":      map[string]any{"type": "integer", "description": "返回条数，1-5，默认 3"},
			},
		},
		ReadOnly:   func(json.RawMessage) bool { return true },
		Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			if t.vulnKnowledge == nil {
				return actool.Text(`{"items":[],"note":"漏洞知识库未启用"}`), nil
			}
			var req struct {
				Query     string `json:"query"`
				VulnClass string `json:"vuln_class"`
				Limit     int    `json:"limit"`
			}
			if err := json.Unmarshal(in, &req); err != nil {
				return actool.Errorf("参数无效: " + err.Error()), nil
			}
			req.Query = strings.TrimSpace(req.Query)
			req.VulnClass = strings.TrimSpace(req.VulnClass)
			if req.Query == "" && req.VulnClass == "" {
				return actool.Errorf("query 和 vuln_class 至少提供一个"), nil
			}
			if req.Limit <= 0 {
				req.Limit = 3
			}
			if req.Limit > 5 {
				req.Limit = 5
			}
			hits, err := t.vulnKnowledge.SearchActiveVulnKnowledge(ctx, VulnKnowledgeQuery{
				Query: req.Query, VulnClass: req.VulnClass, Limit: req.Limit,
			})
			if err != nil {
				return actool.Errorf("漏洞知识检索失败: " + err.Error()), nil
			}
			if len(hits) == 0 {
				return actool.Text(`{"items":[],"note":"没有匹配的已启用漏洞知识条目"}`), nil
			}
			// Tool results live in the model context for the rest of the run. Trim
			// long prose fields while preserving the test/verification essentials.
			for i := range hits {
				hits[i].Summary = truncateKnowledgeText(hits[i].Summary, 500)
				hits[i].Preconditions = truncateKnowledgeText(hits[i].Preconditions, 500)
				hits[i].TestSteps = truncateKnowledgeText(hits[i].TestSteps, 1200)
				hits[i].ExpectedSignals = truncateKnowledgeText(hits[i].ExpectedSignals, 800)
				hits[i].FalsePositiveChecks = truncateKnowledgeText(hits[i].FalsePositiveChecks, 800)
			}
			raw, _ := json.Marshal(map[string]any{"items": hits})
			return actool.Text(string(raw)), nil
		},
	})
}

func truncateKnowledgeText(s string, maxRunes int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) <= maxRunes {
		return string(r)
	}
	return string(r[:maxRunes]) + " …"
}
