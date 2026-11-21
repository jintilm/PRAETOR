package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// 危害类别：与 agent.DeriveImpactLevel 使用同一枚举，kind 决定 metrics 的必填字段。
const (
	ImpactKindSQLi       = "sqli"
	ImpactKindRCE        = "rce"
	ImpactKindSSRF       = "ssrf"
	ImpactKindIDOR       = "idor"
	ImpactKindUpload     = "upload"
	ImpactKindDisclosure = "disclosure"
	ImpactKindLogic      = "logic"
)

// ValidImpactKind 是白名单。不让模型自定义 kind：kind 决定「什么算提取物」。
func ValidImpactKind(k string) bool {
	switch k {
	case ImpactKindSQLi, ImpactKindRCE, ImpactKindSSRF, ImpactKindIDOR,
		ImpactKindUpload, ImpactKindDisclosure, ImpactKindLogic:
		return true
	}
	return false
}

// FindingImpactInput 是一次危害取证请求。
//
// Level 由 agent.DeriveImpactLevel 依据 kind + metrics 推导后传入，**不接受模型自报**。
type FindingImpactInput struct {
	FindingID       int64
	Kind            string
	Level           int
	Summary         string
	Metrics         map[string]any
	Artifacts       []string // 已绑定到该漏洞的 traffic id
	EvidenceVersion *int64   // version read with the evidence; nil keeps a pending-review record
}

// FindingImpact 是落库后的危害证据。
type FindingImpact struct {
	FindingID       int64
	Kind            string
	Level           int
	Summary         string
	Metrics         map[string]any
	Artifacts       []string
	RecordedAt      time.Time
	EvidenceVersion *int64
}

// RecordFindingImpact 落库一次危害取证。
//
// 三条硬校验（缺一条就拒绝，不做「尽力而为」）：
//  1. 漏洞必须属于本任务 —— 否则就是跨任务改别人的证据；
//  2. artifact 必须是**已绑定到该漏洞**的真实 traffic id —— 否则「提取物」会退化成模型
//     编的一段文字，那正是「危害不足」的原始形态；
//  3. level>=2 必须至少有一个 artifact，level 只允许 0..3。
func (s *ExplorationStore) RecordFindingImpact(ctx context.Context, taskID int64, in FindingImpactInput) (*FindingImpact, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("exploration store 未就绪")
	}
	if taskID <= 0 {
		return nil, errors.New("task id 无效")
	}
	if in.FindingID <= 0 {
		return nil, errors.New("finding id 无效")
	}
	if !ValidImpactKind(in.Kind) {
		return nil, fmt.Errorf("无效的危害类别 %q", in.Kind)
	}
	if in.Level < 0 || in.Level > 3 {
		return nil, fmt.Errorf("无效的危害等级 %d", in.Level)
	}
	if in.EvidenceVersion != nil && *in.EvidenceVersion < 0 {
		return nil, errors.New("证据版本无效")
	}
	arts := dedupeStrings(in.Artifacts)
	if in.Level >= 2 && len(arts) == 0 {
		return nil, errors.New("危害等级 >=2 必须提供至少一个绑定到该漏洞的流量证据（artifact_traffic_ids）；请核对原始报文后绑定")
	}

	metrics := in.Metrics
	if metrics == nil {
		metrics = map[string]any{}
	}
	metricsJSON, err := json.Marshal(metrics)
	if err != nil {
		return nil, fmt.Errorf("metrics 无法序列化: %w", err)
	}
	artifactsJSON, err := json.Marshal(arts)
	if err != nil {
		return nil, fmt.Errorf("artifacts 无法序列化: %w", err)
	}

	// 一次取证 = 一次事务：更新 findings 投影 + 追加历史行。
	// 历史不能省：下一版指标被改小时，只有历史能说明「原来到过几级、为什么」。
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := LockFindingEvidenceTx(tx, in.FindingID, in.EvidenceVersion); err != nil {
		return nil, err
	}

	var owner sql.NullInt64
	var version int64
	switch err := tx.QueryRowContext(ctx, "SELECT task_id, evidence_version FROM findings WHERE id=$1", in.FindingID).Scan(&owner, &version); {
	case errors.Is(err, sql.ErrNoRows):
		return nil, ErrFindingNotFound
	case err != nil:
		return nil, err
	}
	if !owner.Valid || owner.Int64 != taskID {
		return nil, fmt.Errorf("漏洞 %d 不属于本任务，拒绝写入危害证据", in.FindingID)
	}

	if len(arts) > 0 {
		bound, err := boundTrafficIDs(ctx, tx, in.FindingID)
		if err != nil {
			return nil, err
		}
		var unknown []string
		for _, id := range arts {
			if !bound[id] {
				unknown = append(unknown, id)
			}
		}
		if len(unknown) > 0 {
			return nil, fmt.Errorf("这些流量不在该漏洞的证据链里，先用 bind_finding_traffic 绑定：%s。"+
				"用 traffic_search 筛选候选后核对原始报文并确认归属，避免按主机或时间推断",
				strings.Join(unknown, ", "))
		}
	}

	// A legacy caller may still save its observations, but cannot stamp them as
	// reviewed against a version it never supplied.
	var recordedVersion any
	var resultVersion *int64
	if in.EvidenceVersion != nil {
		recordedVersion = version
		resultVersion = &version
	}
	const updateQ = "UPDATE findings SET impact_kind=$2, impact_level=$3, impact_summary=$4, " +
		"impact_metrics=$5, impact_artifacts=$6, impact_recorded_at=now(), impact_evidence_version=$7 WHERE id=$1 " +
		"RETURNING impact_recorded_at"
	var recorded time.Time
	if err := tx.QueryRowContext(ctx, updateQ,
		in.FindingID, in.Kind, in.Level, strings.TrimSpace(in.Summary), metricsJSON, artifactsJSON, recordedVersion,
	).Scan(&recorded); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrFindingNotFound
		}
		return nil, err
	}

	const insertQ = "INSERT INTO finding_impacts(finding_id, kind, level, summary, metrics, artifacts, evidence_version) " +
		"VALUES($1,$2,$3,$4,$5,$6,$7)"
	if _, err := tx.ExecContext(ctx, insertQ, in.FindingID, in.Kind, in.Level, strings.TrimSpace(in.Summary), metricsJSON, artifactsJSON, recordedVersion); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &FindingImpact{
		FindingID:  in.FindingID,
		Kind:       in.Kind,
		Level:      in.Level,
		Summary:    strings.TrimSpace(in.Summary),
		Metrics:    metrics,
		Artifacts:  arts,
		RecordedAt: recorded, EvidenceVersion: resultVersion,
	}, nil
}

// GetFindingImpact 读回危害证据（报告与验收用）。
func (s *ExplorationStore) GetFindingImpact(ctx context.Context, findingID int64) (*FindingImpact, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("exploration store 未就绪")
	}
	const q = "SELECT impact_kind, impact_level, impact_summary, impact_metrics, impact_artifacts, " +
		"COALESCE(impact_recorded_at, 'epoch'::timestamptz), impact_evidence_version FROM findings WHERE id=$1"
	var out FindingImpact
	var metricsJSON, artifactsJSON []byte
	if err := s.db.QueryRowContext(ctx, q, findingID).Scan(
		&out.Kind, &out.Level, &out.Summary, &metricsJSON, &artifactsJSON, &out.RecordedAt, &out.EvidenceVersion,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrFindingNotFound
		}
		return nil, err
	}
	out.FindingID = findingID
	if len(metricsJSON) > 0 {
		_ = json.Unmarshal(metricsJSON, &out.Metrics)
	}
	if len(artifactsJSON) > 0 {
		_ = json.Unmarshal(artifactsJSON, &out.Artifacts)
	}
	return &out, nil
}

// boundTrafficIDs 返回该漏洞已绑定的全部 source_traffic_id。
func boundTrafficIDs(ctx context.Context, tx *sql.Tx, findingID int64) (map[string]bool, error) {
	rows, err := tx.QueryContext(ctx, "SELECT COALESCE(s.source_traffic_id,'') "+
		"FROM finding_traffic_bindings b JOIN traffic_evidence_snapshots s ON s.id=b.snapshot_id "+
		"WHERE b.finding_id=$1", findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		if id != "" {
			out[id] = true
		}
	}
	return out, rows.Err()
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// FindingImpactHistory 是一条危害取证历史。
type FindingImpactHistory struct {
	ID              int64
	FindingID       int64
	Kind            string
	Level           int
	Summary         string
	Metrics         map[string]any
	Artifacts       []string
	CreatedAt       time.Time
	EvidenceVersion *int64
}

// ListFindingImpacts 读某个漏洞的危害取证历史（新 → 旧）。
func (d *DB) ListFindingImpacts(ctx context.Context, findingID int64, limit int) ([]FindingImpactHistory, error) {
	if findingID <= 0 {
		return nil, errors.New("finding id 无效")
	}
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	const q = "SELECT id, finding_id, kind, level, summary, metrics, artifacts, created_at, evidence_version " +
		"FROM finding_impacts WHERE finding_id=$1 ORDER BY created_at DESC, id DESC LIMIT $2"
	rows, err := d.QueryContext(ctx, q, findingID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FindingImpactHistory
	for rows.Next() {
		var h FindingImpactHistory
		var metricsJSON, artifactsJSON []byte
		if err := rows.Scan(&h.ID, &h.FindingID, &h.Kind, &h.Level, &h.Summary, &metricsJSON, &artifactsJSON, &h.CreatedAt, &h.EvidenceVersion); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(metricsJSON, &h.Metrics)
		_ = json.Unmarshal(artifactsJSON, &h.Artifacts)
		out = append(out, h)
	}
	return out, rows.Err()
}

// GetFindingImpactByNodeID 按探索节点 id 取危害取证（报告工具用的是节点 id 句柄）。
// 没有记录时返回 (nil, nil)。
func (d *DB) GetFindingImpactByNodeID(ctx context.Context, nodeID int64) (*FindingImpact, error) {
	if nodeID <= 0 {
		return nil, errors.New("node id 无效")
	}
	const q = "SELECT id, impact_kind, impact_level, impact_summary, impact_metrics, impact_artifacts, " +
		"COALESCE(impact_recorded_at, 'epoch'::timestamptz), impact_evidence_version FROM findings WHERE node_id=$1"
	var out FindingImpact
	var metricsJSON, artifactsJSON []byte
	err := d.QueryRowContext(ctx, q, nodeID).Scan(
		&out.FindingID, &out.Kind, &out.Level, &out.Summary, &metricsJSON, &artifactsJSON, &out.RecordedAt, &out.EvidenceVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(metricsJSON, &out.Metrics)
	_ = json.Unmarshal(artifactsJSON, &out.Artifacts)
	return &out, nil
}

// ImpactLevelLabel 是危害等级的中文标签（报告渲染用）。
func ImpactLevelLabel(level int) string {
	switch level {
	case 1:
		return "reproduced（可复现）"
	case 2:
		return "extracted（已提取目标侧内容）"
	case 3:
		return "exploited（已产生业务副作用）"
	}
	return "none（只有结论）"
}

// 证据来源与任务范围的匹配程度（标注用，不阻断）。
const (
	ScopeIn         = "in"         // 命中显式声明的范围行
	ScopeAssumed    = "assumed"    // 只命中从任务文本自动解析的行
	ScopeUnverified = "unverified" // 没有任何主机维度命中
	ScopeUndeclared = "undeclared" // 任务没声明主机维度，无法判定
)

// SetFindingScopeState 记录一次证据来源的范围评估结果。
func (d *DB) SetFindingScopeState(ctx context.Context, findingID int64, state string) error {
	if findingID <= 0 {
		return errors.New("finding id 无效")
	}
	const q = "UPDATE findings SET scope_state=$2, scope_checked_at=now() WHERE id=$1"
	_, err := d.ExecContext(ctx, q, findingID, state)
	return err
}

// FindingTaskID 返回漏洞所属任务 id（0 = 没有任务归属）。
func (d *DB) FindingTaskID(ctx context.Context, findingID int64) (int64, error) {
	var tid sql.NullInt64
	if err := d.QueryRowContext(ctx, "SELECT task_id FROM findings WHERE id=$1", findingID).Scan(&tid); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrFindingNotFound
		}
		return 0, err
	}
	if !tid.Valid {
		return 0, nil
	}
	return tid.Int64, nil
}
