package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	VulnKBCandidate  = "candidate"
	VulnKBActive     = "active"
	VulnKBDeprecated = "deprecated"

	VulnKBPattern   = "pattern"
	VulnKBTechnique = "technique"
	VulnKBNegative  = "negative"
)

var (
	ErrVulnKBNotFound      = errors.New("漏洞知识条目不存在")
	ErrVulnKBVersion       = errors.New("漏洞知识条目已被其他操作修改，请刷新后重试")
	ErrVulnKBInvalidStatus = errors.New("无效的漏洞知识状态")
	ErrVulnKBInvalidKind   = errors.New("无效的漏洞知识类型")
)

type VulnKnowledge struct {
	ID                  int64      `json:"id"`
	Fingerprint         string     `json:"-"`
	Kind                string     `json:"kind"`
	Title               string     `json:"title"`
	Summary             string     `json:"summary"`
	VulnClass           string     `json:"vuln_class"`
	CWE                 string     `json:"cwe"`
	Severity            string     `json:"severity"`
	Technology          []string   `json:"technology"`
	Preconditions       string     `json:"preconditions"`
	TestSteps           string     `json:"test_steps"`
	ExpectedSignals     string     `json:"expected_signals"`
	FalsePositiveChecks string     `json:"false_positive_checks"`
	SourceKind          string     `json:"source_kind"`
	SourceRef           string     `json:"source_ref"`
	License             string     `json:"license"`
	Confidence          int        `json:"confidence"`
	Status              string     `json:"status"`
	Version             int        `json:"version"`
	UsageCount          int        `json:"usage_count"`
	SuccessCount        int        `json:"success_count"`
	FalsePositiveCount  int        `json:"false_positive_count"`
	LastVerifiedAt      *time.Time `json:"last_verified_at,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

type VulnKnowledgeSource struct {
	FindingID       int64     `json:"finding_id"`
	TaskID          *int64    `json:"task_id,omitempty"`
	TaskName        string    `json:"task_name,omitempty"`
	TaskDescription string    `json:"task_description,omitempty"`
	FindingName     string    `json:"finding_name,omitempty"`
	VulnClass       string    `json:"vuln_class,omitempty"`
	Severity        string    `json:"severity,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

type VulnKnowledgeDetail struct {
	VulnKnowledge
	Sources []VulnKnowledgeSource `json:"sources"`
}

type VulnKnowledgeFilter struct {
	Status string
	Kind   string
	Query  string
	Limit  int
	Offset int
}

type VulnKnowledgeStats struct {
	Total             int64 `json:"total"`
	Candidate         int64 `json:"candidate"`
	Active            int64 `json:"active"`
	Deprecated        int64 `json:"deprecated"`
	VerifiedSources   int64 `json:"verified_sources"`
	SearchUses        int64 `json:"search_uses"`
	SuccessfulUses    int64 `json:"successful_uses"`
	FalsePositiveUses int64 `json:"false_positive_uses"`
}

type VulnKnowledgeUpdate struct {
	ID                  int64    `json:"id"`
	Version             int      `json:"version"`
	Kind                string   `json:"kind"`
	Title               string   `json:"title"`
	Summary             string   `json:"summary"`
	VulnClass           string   `json:"vuln_class"`
	CWE                 string   `json:"cwe"`
	Severity            string   `json:"severity"`
	Technology          []string `json:"technology"`
	Preconditions       string   `json:"preconditions"`
	TestSteps           string   `json:"test_steps"`
	ExpectedSignals     string   `json:"expected_signals"`
	FalsePositiveChecks string   `json:"false_positive_checks"`
	License             string   `json:"license"`
	Confidence          int      `json:"confidence"`
	Status              string   `json:"status"`
}

func ValidVulnKBStatus(s string) bool {
	switch s {
	case VulnKBCandidate, VulnKBActive, VulnKBDeprecated:
		return true
	default:
		return false
	}
}

func ValidVulnKBKind(s string) bool {
	switch s {
	case VulnKBPattern, VulnKBTechnique, VulnKBNegative:
		return true
	default:
		return false
	}
}

const vulnKBCols = `id,fingerprint,kind,title,summary,vuln_class,cwe,severity,technology,
preconditions,test_steps,expected_signals,false_positive_checks,source_kind,source_ref,license,
confidence,status,version,usage_count,success_count,false_positive_count,last_verified_at,created_at,updated_at`

func scanVulnKnowledge(sc interface{ Scan(...any) error }) (*VulnKnowledge, error) {
	var k VulnKnowledge
	var technology string
	var lastVerified sql.NullTime
	if err := sc.Scan(
		&k.ID, &k.Fingerprint, &k.Kind, &k.Title, &k.Summary, &k.VulnClass, &k.CWE, &k.Severity, &technology,
		&k.Preconditions, &k.TestSteps, &k.ExpectedSignals, &k.FalsePositiveChecks, &k.SourceKind, &k.SourceRef, &k.License,
		&k.Confidence, &k.Status, &k.Version, &k.UsageCount, &k.SuccessCount, &k.FalsePositiveCount,
		&lastVerified, &k.CreatedAt, &k.UpdatedAt,
	); err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(technology), &k.Technology)
	if lastVerified.Valid {
		k.LastVerifiedAt = &lastVerified.Time
	}
	return &k, nil
}

func vulnKBWhere(f VulnKnowledgeFilter) (string, []any) {
	var conds []string
	var args []any
	if s := strings.TrimSpace(f.Status); s != "" {
		args = append(args, s)
		conds = append(conds, fmt.Sprintf("status=$%d", len(args)))
	}
	if k := strings.TrimSpace(f.Kind); k != "" {
		args = append(args, k)
		conds = append(conds, fmt.Sprintf("kind=$%d", len(args)))
	}
	if q := strings.TrimSpace(f.Query); q != "" {
		args = append(args, "%"+q+"%")
		p := fmt.Sprintf("$%d", len(args))
		conds = append(conds, fmt.Sprintf(`(
			title ILIKE %s OR summary ILIKE %s OR vuln_class ILIKE %s OR cwe ILIKE %s
			OR preconditions ILIKE %s OR test_steps ILIKE %s OR expected_signals ILIKE %s
			OR false_positive_checks ILIKE %s
		)`, p, p, p, p, p, p, p, p))
	}
	if len(conds) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

func (d *DB) ListVulnKnowledge(filter VulnKnowledgeFilter) ([]*VulnKnowledge, int, error) {
	if filter.Limit <= 0 || filter.Limit > 100 {
		filter.Limit = 50
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}
	if filter.Status != "" && !ValidVulnKBStatus(filter.Status) {
		return nil, 0, ErrVulnKBInvalidStatus
	}
	if filter.Kind != "" && !ValidVulnKBKind(filter.Kind) {
		return nil, 0, ErrVulnKBInvalidKind
	}
	where, args := vulnKBWhere(filter)
	var total int
	if err := d.QueryRow(`SELECT count(*) FROM vuln_kb`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, filter.Limit, filter.Offset)
	rows, err := d.Query(`
		SELECT `+vulnKBCols+`
		FROM vuln_kb`+where+`
		ORDER BY CASE status WHEN 'active' THEN 0 WHEN 'candidate' THEN 1 ELSE 2 END,
		         confidence DESC, updated_at DESC, id DESC
		LIMIT $`+fmt.Sprint(len(args)-1)+` OFFSET $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []*VulnKnowledge{}
	for rows.Next() {
		k, err := scanVulnKnowledge(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, k)
	}
	return out, total, rows.Err()
}

func (d *DB) VulnKnowledgeStats() (*VulnKnowledgeStats, error) {
	var st VulnKnowledgeStats
	err := d.QueryRow(`
		SELECT count(*),
		       count(*) FILTER (WHERE status='candidate'),
		       count(*) FILTER (WHERE status='active'),
		       count(*) FILTER (WHERE status='deprecated'),
		       COALESCE(sum(usage_count),0),
		       COALESCE(sum(success_count),0),
		       COALESCE(sum(false_positive_count),0)
		FROM vuln_kb`).Scan(
		&st.Total, &st.Candidate, &st.Active, &st.Deprecated,
		&st.SearchUses, &st.SuccessfulUses, &st.FalsePositiveUses,
	)
	if err != nil {
		return nil, err
	}
	_ = d.QueryRow(`SELECT count(DISTINCT finding_id) FROM vuln_kb_sources`).Scan(&st.VerifiedSources)
	return &st, nil
}

func (d *DB) GetVulnKnowledge(id int64) (*VulnKnowledgeDetail, error) {
	if id <= 0 {
		return nil, ErrVulnKBNotFound
	}
	k, err := scanVulnKnowledge(d.QueryRow(`SELECT `+vulnKBCols+` FROM vuln_kb WHERE id=$1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrVulnKBNotFound
	}
	if err != nil {
		return nil, err
	}
	rows, err := d.Query(`
		SELECT s.finding_id, f.task_id, COALESCE(t.name,''), COALESCE(t.description,''),
		       COALESCE(f.name,''), COALESCE(f.vulnclass,''), COALESCE(f.severity,''), s.created_at
		FROM vuln_kb_sources s
		JOIN findings f ON f.id=s.finding_id
		LEFT JOIN tasks t ON t.id=f.task_id
		WHERE s.kb_id=$1
		ORDER BY s.created_at DESC, f.id DESC`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	detail := &VulnKnowledgeDetail{VulnKnowledge: *k, Sources: []VulnKnowledgeSource{}}
	for rows.Next() {
		var source VulnKnowledgeSource
		if err := rows.Scan(
			&source.FindingID, &source.TaskID, &source.TaskName, &source.TaskDescription,
			&source.FindingName, &source.VulnClass, &source.Severity, &source.CreatedAt,
		); err != nil {
			return nil, err
		}
		detail.Sources = append(detail.Sources, source)
	}
	return detail, rows.Err()
}

func normalizeVulnKBFingerprint(vulnClass, title string) string {
	base := strings.ToLower(strings.Join(strings.Fields(vulnClass+" "+title), " "))
	if base == "" {
		base = "unnamed-vulnerability-pattern"
	}
	sum := sha256.Sum256([]byte(base))
	return hex.EncodeToString(sum[:])
}

func (d *DB) UpsertVulnKnowledgeFromFinding(ctx context.Context, findingID int64) (int64, error) {
	var (
		kbID         int64
		findingName  string
		vulnClass    string
		severity     string
		summary      string
		status       string
		verification string
	)
	err := d.QueryRowContext(ctx, `
		SELECT COALESCE(name,''), COALESCE(vulnclass,''), COALESCE(severity,''), COALESCE(summary,''),
		       COALESCE(status,'pending'), COALESCE(verification_state,'unverified')
		FROM findings WHERE id=$1`, findingID).Scan(
		&findingName, &vulnClass, &severity, &summary, &status, &verification,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if verification != VerificationVerified ||
		status == FindingFalsePositive || status == FindingDuplicate || status == FindingIgnored {
		return 0, nil
	}
	title := strings.TrimSpace(findingName)
	if title == "" {
		title = strings.TrimSpace(vulnClass)
	}
	if title == "" {
		title = "已验证漏洞模式"
	}
	if len([]rune(summary)) > 1200 {
		summary = string([]rune(summary)[:1200])
	}
	fingerprint := normalizeVulnKBFingerprint(vulnClass, title)
	tech, _ := json.Marshal([]string{})
	err = d.QueryRowContext(ctx, `
		INSERT INTO vuln_kb(
			fingerprint,kind,title,summary,vuln_class,severity,technology,source_kind,source_ref,confidence,status
		) VALUES($1,'pattern',$2,$3,$4,$5,$6,'internal_finding',$7,60,'candidate')
		ON CONFLICT (fingerprint) DO UPDATE SET
			summary=CASE WHEN vuln_kb.summary='' THEN EXCLUDED.summary ELSE vuln_kb.summary END,
			severity=CASE WHEN vuln_kb.severity='' THEN EXCLUDED.severity ELSE vuln_kb.severity END,
			updated_at=now()
		RETURNING id`,
		fingerprint, title, summary, vulnClass, severity, string(tech), fmt.Sprint(findingID),
	).Scan(&kbID)
	if err != nil {
		return 0, err
	}
	_, err = d.ExecContext(ctx, `
		INSERT INTO vuln_kb_sources(kb_id,finding_id) VALUES($1,$2)
		ON CONFLICT (kb_id,finding_id) DO NOTHING`, kbID, findingID)
	return kbID, err
}

func (d *DB) BackfillVulnKnowledgeCandidates(ctx context.Context) (int, error) {
	var before int
	if err := d.QueryRowContext(ctx, `SELECT count(*) FROM vuln_kb_sources`).Scan(&before); err != nil {
		return 0, err
	}
	rows, err := d.QueryContext(ctx, `
		SELECT id FROM findings
		WHERE verification_state=$1
		  AND COALESCE(status,'pending') NOT IN ('false_positive','duplicate','ignored')`,
		VerificationVerified)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return 0, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, id := range ids {
		if _, err := d.UpsertVulnKnowledgeFromFinding(ctx, id); err != nil {
			return 0, err
		}
	}
	var after int
	if err := d.QueryRowContext(ctx, `SELECT count(*) FROM vuln_kb_sources`).Scan(&after); err != nil {
		return 0, err
	}
	return after - before, nil
}

func (d *DB) UpdateVulnKnowledge(ctx context.Context, u VulnKnowledgeUpdate) (*VulnKnowledge, error) {
	if u.ID <= 0 {
		return nil, ErrVulnKBNotFound
	}
	if !ValidVulnKBKind(u.Kind) {
		return nil, ErrVulnKBInvalidKind
	}
	if !ValidVulnKBStatus(u.Status) {
		return nil, ErrVulnKBInvalidStatus
	}
	u.Title = strings.TrimSpace(u.Title)
	if u.Title == "" {
		return nil, errors.New("标题不能为空")
	}
	if u.Confidence < 0 {
		u.Confidence = 0
	}
	if u.Confidence > 100 {
		u.Confidence = 100
	}
	if u.Status == VulnKBActive &&
		(strings.TrimSpace(u.TestSteps) == "" || strings.TrimSpace(u.ExpectedSignals) == "" ||
			strings.TrimSpace(u.FalsePositiveChecks) == "") {
		return nil, errors.New("启用前必须填写测试步骤、预期信号和误报检查")
	}
	tech, _ := json.Marshal(u.Technology)
	res, err := d.ExecContext(ctx, `
		UPDATE vuln_kb SET
			kind=$3,title=$4,summary=$5,vuln_class=$6,cwe=$7,severity=$8,technology=$9,
			preconditions=$10,test_steps=$11,expected_signals=$12,false_positive_checks=$13,
			license=$14,confidence=$15,status=$16,version=version+1,
			last_verified_at=CASE WHEN $16='active' THEN now() ELSE last_verified_at END,
			updated_at=now()
		WHERE id=$1 AND version=$2`,
		u.ID, u.Version, u.Kind, u.Title, u.Summary, u.VulnClass, u.CWE, u.Severity, string(tech),
		u.Preconditions, u.TestSteps, u.ExpectedSignals, u.FalsePositiveChecks,
		u.License, u.Confidence, u.Status)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if _, getErr := d.GetVulnKnowledge(u.ID); getErr == nil {
			return nil, ErrVulnKBVersion
		}
		return nil, ErrVulnKBNotFound
	}
	detail, err := d.GetVulnKnowledge(u.ID)
	if err != nil {
		return nil, err
	}
	return &detail.VulnKnowledge, nil
}

// SearchActiveVulnKnowledge is the only model-facing retrieval path. It never
// returns candidates/deprecated rows and caps the result set independently of
// caller input.
func (d *DB) SearchActiveVulnKnowledge(ctx context.Context, query, vulnClass string, limit int) ([]*VulnKnowledge, error) {
	if limit <= 0 {
		limit = 3
	}
	if limit > 5 {
		limit = 5
	}
	var conds = []string{"status='active'"}
	var args []any
	if q := strings.TrimSpace(query); q != "" {
		args = append(args, "%"+q+"%")
		p := fmt.Sprintf("$%d", len(args))
		conds = append(conds, fmt.Sprintf(`(
			title ILIKE %s OR summary ILIKE %s OR vuln_class ILIKE %s OR cwe ILIKE %s
			OR test_steps ILIKE %s OR expected_signals ILIKE %s
		)`, p, p, p, p, p, p))
	}
	if class := strings.TrimSpace(vulnClass); class != "" {
		args = append(args, "%"+class+"%")
		conds = append(conds, fmt.Sprintf("vuln_class ILIKE $%d", len(args)))
	}
	args = append(args, limit)
	rows, err := d.QueryContext(ctx, `
		SELECT `+vulnKBCols+`
		FROM vuln_kb WHERE `+strings.Join(conds, " AND ")+`
		ORDER BY confidence DESC,
		         CASE WHEN usage_count=0 THEN 0 ELSE success_count::float/usage_count END DESC,
		         updated_at DESC, id DESC
		LIMIT $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*VulnKnowledge{}
	for rows.Next() {
		k, err := scanVulnKnowledge(rows)
		if err != nil {
			return nil, err
		}
		k.UsageCount++
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) > 0 {
		ids := make([]int64, 0, len(out))
		for _, k := range out {
			ids = append(ids, k.ID)
		}
		_, _ = d.ExecContext(ctx, `UPDATE vuln_kb SET usage_count=usage_count+1 WHERE id=ANY($1)`, ids)
	}
	return out, nil
}

func (d *DB) RecordVulnKnowledgeOutcome(ctx context.Context, kbID, taskID, intentID int64, outcome, detail string) error {
	if kbID <= 0 {
		return ErrVulnKBNotFound
	}
	var tid, iid any
	if taskID > 0 {
		tid = taskID
	}
	if intentID > 0 {
		iid = intentID
	}
	_, err := d.ExecContext(ctx, `
		INSERT INTO vuln_kb_usage(kb_id,task_id,intent_id,outcome,detail)
		VALUES($1,$2,$3,$4,NULLIF($5,''))`, kbID, tid, iid, outcome, detail)
	if err != nil {
		return err
	}
	switch outcome {
	case "success":
		_, err = d.ExecContext(ctx, `UPDATE vuln_kb SET success_count=success_count+1,updated_at=now() WHERE id=$1`, kbID)
	case "false_positive":
		_, err = d.ExecContext(ctx, `UPDATE vuln_kb SET false_positive_count=false_positive_count+1,updated_at=now() WHERE id=$1`, kbID)
	}
	return err
}
