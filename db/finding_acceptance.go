package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

// AcceptedFinding 是「可以作为目标达成证据」的漏洞的最小投影。
type AcceptedFinding struct {
	ID              int64
	Name            string
	VulnClass       string
	EvidenceVersion int64
	NodeID          int64
	// ProofTrafficID 是复现用的那条流量（报告能贴出原报文）。
	ProofTrafficID string
	// ProofHash 是证据哈希：优先响应体，没有响应体时退化到请求体。
	ProofHash string
	// ImpactCurrent 要求取证与当前版本一致，且所有引用仍在绑定中。
	ImpactCurrent bool
	// 危害取证投影：供闸门判断「够不够 2 级」并把缺口回给模型。
	ImpactKind      string
	ImpactLevel     int
	ImpactMetrics   map[string]any
	ImpactArtifacts []string
}

// FindingAcceptance 是渗透域完成判定需要的全部事实。
//
// 单独返回 Total/Verified 而不是只返回「有没有」，是因为拒绝时必须告诉模型
// 「你有 3 个漏洞，但 0 个过了验证」——只说「没有」会让它继续瞎猜。
type FindingAcceptance struct {
	Total    int
	Verified int
	// ImpactReady 是「既通过验证、又达到 2 级危害（且有绑定流量）」的漏洞数。
	// 审核卡的就是这一级：能复现不等于有危害证明。
	ImpactReady int
	// Latest 是最近验证的当前版本发现，用于诊断。
	Latest *AcceptedFinding
	// Best 是 verified 里危害最高的一条（给闸门算缺口）。
	Best *AcceptedFinding
	// Ready 是满足全部条件的同一条发现。
	Ready *AcceptedFinding
}

// TaskFindingAcceptance 在单个 SQL 快照中读取验收事实，避免并发改绑导致各查询看到不同版本。
func (s *ExplorationStore) TaskFindingAcceptance(ctx context.Context, taskID int64, evidenceNodes ...int64) (*FindingAcceptance, error) {
	var evidenceNode int64
	if len(evidenceNodes) > 1 {
		return nil, errors.New("只允许一个证明节点")
	}
	if len(evidenceNodes) == 1 {
		evidenceNode = evidenceNodes[0]
	}
	if s == nil || s.db == nil {
		return nil, errors.New("exploration store 未就绪")
	}
	if taskID <= 0 {
		return nil, errors.New("task id 无效")
	}
	return taskFindingAcceptance(ctx, s.db, taskID, evidenceNode)
}

type acceptanceReader interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func taskFindingAcceptance(ctx context.Context, reader acceptanceReader, taskID, evidenceNode int64) (*FindingAcceptance, error) {
	const query = `
WITH task_findings AS (
    SELECT * FROM findings WHERE task_id = $1 AND ($2::bigint=0 OR node_id=$2)
), verified AS (
    SELECT * FROM task_findings
    WHERE verification_state = 'verified'
      AND verification_evidence_version = evidence_version
      AND COALESCE(status, 'pending') NOT IN ('false_positive', 'ignored', 'duplicate')
)
SELECT totals.n, COALESCE(f.id, 0), COALESCE(f.name, ''), COALESCE(f.vulnclass, ''), COALESCE(f.node_id,0),
       COALESCE(f.evidence_version, 0), COALESCE(proof.source_traffic_id, ''),
       COALESCE(NULLIF(proof.resp_hash, ''), proof.req_hash, ''),
       COALESCE(f.impact_kind, ''), COALESCE(f.impact_level, 0), f.impact_metrics, f.impact_artifacts,
       COALESCE(f.impact_evidence_version = f.evidence_version
           AND jsonb_typeof(f.impact_artifacts) = 'array'
           AND f.impact_artifacts <> '[]'::jsonb
           AND NOT EXISTS (
               SELECT 1 FROM jsonb_array_elements_text(
                   CASE WHEN jsonb_typeof(f.impact_artifacts) = 'array' THEN f.impact_artifacts ELSE '[]'::jsonb END
               ) AS a(traffic_id)
               WHERE NOT EXISTS (
                   SELECT 1 FROM finding_traffic_bindings b
                   JOIN traffic_evidence_snapshots snap ON snap.id = b.snapshot_id
                   WHERE b.finding_id = f.id AND snap.source_traffic_id = a.traffic_id
               )
           ), false)
FROM (SELECT count(*) AS n FROM findings WHERE task_id=$1) totals
LEFT JOIN verified f ON true
LEFT JOIN finding_traffic_bindings b ON b.finding_id = f.id AND b.id = f.verification_binding_id
LEFT JOIN traffic_evidence_snapshots proof ON proof.id = b.snapshot_id
ORDER BY f.verified_at DESC NULLS LAST, f.id DESC`
	rows, err := reader.QueryContext(ctx, query, taskID, evidenceNode)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	acc := &FindingAcceptance{}
	for rows.Next() {
		f := &AcceptedFinding{}
		var metrics, artifacts []byte
		if err := rows.Scan(&acc.Total, &f.ID, &f.Name, &f.VulnClass, &f.NodeID, &f.EvidenceVersion,
			&f.ProofTrafficID, &f.ProofHash, &f.ImpactKind, &f.ImpactLevel, &metrics, &artifacts, &f.ImpactCurrent); err != nil {
			return nil, err
		}
		if f.ID == 0 {
			continue
		}
		if err := json.Unmarshal(metrics, &f.ImpactMetrics); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(artifacts, &f.ImpactArtifacts); err != nil {
			return nil, err
		}
		acc.Verified++
		if acc.Latest == nil {
			acc.Latest = f
		}
		if acc.Best == nil || f.ImpactLevel > acc.Best.ImpactLevel {
			acc.Best = f
		}
		if f.ProofTrafficID != "" && f.ProofHash != "" && f.ImpactCurrent && f.ImpactLevel >= 2 {
			acc.ImpactReady++
			if acc.Ready == nil {
				acc.Ready = f
			}
		}
	}
	return acc, rows.Err()
}
