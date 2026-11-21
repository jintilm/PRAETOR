package agent

import (
	"context"
	"encoding/json"

	"github.com/jintilm/praetor/db"
	actool "github.com/jintilm/praetor/internal/norma/tool"
)

// recordImpact 是「实质危害证明」的落库入口。
//
// 为什么单独做一个工具而不是塞进 report_finding：报告只是**声明**漏洞存在，
// 危害是**另一件事**——它要的是从目标抠出来的东西（数据行/文件/回连/状态变更）。
// 两件事混在一个调用里，模型就会用一段形容词代替取证。
func (t *ToolSet) recordImpact() actool.CoreTool {
	schema := obj(map[string]any{
		"evidence_version": map[string]any{"type": "integer", "minimum": 0, "description": "get_finding_traffic 返回的 version；用于验证本次取证所依据的版本。缺省保留为待复核，不进入严格验收"},
		"finding_id":       idp("独立漏洞记录 ID（report_finding 返回的 finding_id，不是节点 ID）"),
		"kind": map[string]any{
			"type":        "string",
			"enum":        []string{"sqli", "rce", "ssrf", "idor", "upload", "disclosure", "logic"},
			"description": "危害类别，决定 metrics 的必填字段",
		},
		"artifact_traffic_ids": map[string]any{
			"type":        "array",
			"items":       map[string]any{"type": "string"},
			"description": "已绑定到该漏洞的真实流量 ID（report_finding.traffic_refs 或 bind_finding_traffic）。提取物必须来自目标返回的报文，不能是自述。",
		},
		"metrics": map[string]any{
			"type": "object",
			"description": "按 kind 必填：sqli{table,rows_read} / rce{marker,fingerprint} / ssrf{internal_target|oob_source} / " +
				"idor{victim_canary} / upload{landing_url,exec_marker} / disclosure{sensitive_fields|rows_read} / " +
				"logic{state_changed,invariant}；升 3 级另需 write_confirmed / privilege / metadata_credential / business_loss / rows_read>=1000。",
		},
		"summary": str("可选：一句话说明提取到什么（只写观察到的事实，不写推断）"),
	}, "finding_id", "kind", "artifact_traffic_ids", "metrics")

	return t.writeExpTool("record_impact",
		"为已登记漏洞补「实质危害证明」：把目标侧真实提取物（数据行/文件/回连/状态变更）结构化落库，"+
			"并自动判定危害等级（0 无 / 1 可复现 / 2 已提取 / 3 已利用）。等级由程序按 metrics 推导，不接受自报。"+
			"报告与验收只认这一级证据；返回的 gaps 说明离下一级还差什么。",
		schema,
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if t.taskID <= 0 {
				return actool.Errorf("record_impact 需要任务上下文（取不到 task_id）"), nil
			}
			var a struct {
				EvidenceVersion    *int64         `json:"evidence_version"`
				FindingID          int64          `json:"finding_id"`
				Kind               string         `json:"kind"`
				ArtifactTrafficIDs []string       `json:"artifact_traffic_ids"`
				Metrics            map[string]any `json:"metrics"`
				Summary            string         `json:"summary"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if a.FindingID <= 0 {
				return actool.Errorf("finding_id 必填，且应为 report_finding 返回的独立漏洞 ID"), nil
			}

			level, gaps := DeriveImpactLevel(a.Kind, a.Metrics, len(a.ArtifactTrafficIDs))
			imp, err := t.ts.RecordFindingImpact(ctx, t.taskID, db.FindingImpactInput{
				FindingID: a.FindingID, EvidenceVersion: a.EvidenceVersion,
				Kind:      a.Kind,
				Level:     level,
				Summary:   a.Summary,
				Metrics:   a.Metrics,
				Artifacts: a.ArtifactTrafficIDs,
			})
			if err != nil {
				return actool.Errorf("危害取证未落库：" + err.Error()), nil
			}
			if imp.EvidenceVersion == nil {
				gaps = append(gaps, "缺少取证依据的 evidence_version，记录保留为待复核；请核对 get_finding_traffic 的 version 后重新提交")
			}
			return jsonResult(map[string]any{
				"finding_id":  imp.FindingID,
				"kind":        imp.Kind,
				"level":       imp.Level,
				"level_name":  ImpactLevelName(imp.Level),
				"artifacts":   len(imp.Artifacts),
				"gaps":        gaps,
				"recorded_at": imp.RecordedAt, "evidence_version": imp.EvidenceVersion, "pending_review": imp.EvidenceVersion == nil,
			})
		})
}
