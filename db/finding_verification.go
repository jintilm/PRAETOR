package db

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// 漏洞「确定性验证」状态。与 status（人工处置状态）是两条独立维度：
//
//	status              人怎么处理这个漏洞（待处理/已修复/误报…）
//	verification_state  证据是否仍能成立（程序重放得出的结论）
//
// 分开存是刻意的：人工可以把一个无法复现的漏洞标成「风险接受」，也可能在修复前
// 就把验证状态刷成 suspected；两个字段互相覆盖会让审计链断掉。
const (
	VerificationUnverified = "unverified" // 默认：还没跑过确定性验证
	VerificationVerified   = "verified"   // 重放一致：漏洞仍成立
	VerificationSuspected  = "suspected"  // 重放不一致 / 证据不足：疑似，需人工复核
)

// ValidVerificationState 是白名单（与 status 一样不加 CHECK 约束，便于旧库升级）。
func ValidVerificationState(s string) bool {
	switch s {
	case VerificationUnverified, VerificationVerified, VerificationSuspected:
		return true
	}
	return false
}

// SetFindingVerification 写入确定性验证结论。
//
// similarity < 0 表示「本次没有相似度可比」（例如只有哈希或长度证据），落 NULL。
// 返回受影响行数：0 表示 finding 不存在（调用方据此报错，而不是静默成功）。
func (d *DB) SetFindingVerification(ctx context.Context, findingID int64, state string, similarity float64, note string) (int64, error) {
	if findingID <= 0 {
		return 0, errors.New("finding id 无效")
	}
	if !ValidVerificationState(state) {
		return 0, fmt.Errorf("无效的验证状态 %q", state)
	}
	var sim any
	if similarity >= 0 {
		sim = similarity
	}
	res, err := d.ExecContext(ctx, `
UPDATE findings
   SET verification_state = $2,
       verification_similarity = $3,
       verification_note = $4,
       verification_binding_id = NULL,
       verified_at = now()
 WHERE id = $1`, findingID, state, sim, note)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// VerificationStale 是「本次结论没有落库」的结果态：验证期间证据版本变了。
//
// 它只出现在工具结果里，不写进 findings.verification_state —— 那四列描述的是
// 当前证据的结论，而 stale 描述的是「这次验证作废」，两者不是一回事。
const VerificationStale = "stale"

// FindingVerification 是一条验证历史记录。
type FindingVerification struct {
	ID              int64
	FindingID       int64
	EvidenceVersion int64
	BindingID       *int64
	Engine          string
	State           string
	Similarity      *float64
	Detail          string
	CreatedAt       time.Time
}

// RecordFindingVerification 以「调用方读到的证据版本」为条件写入验证结论。
//
// 返回 (stale, err)：stale=true 表示期间 evidence_version 已变，本次结论没有落库，
// 调用方应把它当成「验证作废」而不是「验证失败」。冲突原语复用 LockFindingEvidenceTx
// （与流量绑定写入共用同一把行锁，避免两条路径互相踩）。
func (d *DB) RecordFindingVerification(ctx context.Context, findingID, evidenceVersion int64, engine, state string, similarity float64, note string, bindingIDs ...int64) (bool, error) {
	var bindingID int64
	if len(bindingIDs) > 1 {
		return false, errors.New("仅允许一个验证绑定")
	}
	if len(bindingIDs) == 1 {
		bindingID = bindingIDs[0]
	}
	if findingID <= 0 {
		return false, errors.New("finding id 无效")
	}
	if !ValidVerificationState(state) {
		return false, fmt.Errorf("无效的验证状态 %q", state)
	}
	if evidenceVersion < 0 {
		return false, errors.New("证据版本无效")
	}

	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	if err := LockFindingEvidenceTx(tx, findingID, &evidenceVersion); err != nil {
		if errors.Is(err, ErrEvidenceConflict) {
			return true, nil
		}
		return false, err
	}

	var verifiedBinding any
	if bindingID > 0 {
		var exists bool
		if err := tx.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM finding_traffic_bindings WHERE finding_id=$1 AND id=$2)", findingID, bindingID).Scan(&exists); err != nil {
			return false, err
		}
		if !exists {
			return false, ErrEvidenceNotFound
		}
		verifiedBinding = bindingID
	}
	var sim any
	if similarity >= 0 {
		sim = similarity
	}
	updateSQL := "UPDATE findings SET verification_state = $2, verification_similarity = $3, " +
		"verification_note = $4, verification_evidence_version = $5, verification_binding_id = $6, verified_at = now() WHERE id = $1"
	res, err := tx.ExecContext(ctx, updateSQL, findingID, state, sim, note, evidenceVersion, verifiedBinding)
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false, ErrFindingNotFound
	}
	insertSQL := "INSERT INTO finding_verifications(finding_id, evidence_version, engine, state, similarity, detail, binding_id) " +
		"VALUES($1,$2,$3,$4,$5,$6,$7)"
	if _, err := tx.ExecContext(ctx, insertSQL, findingID, evidenceVersion, engine, state, sim, note, verifiedBinding); err != nil {
		return false, err
	}
	return false, tx.Commit()
}

// ListFindingVerifications 读某个漏洞的验证历史（新 → 旧）。
func (d *DB) ListFindingVerifications(ctx context.Context, findingID int64, limit int) ([]FindingVerification, error) {
	if findingID <= 0 {
		return nil, errors.New("finding id 无效")
	}
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	query := "SELECT id, finding_id, evidence_version, engine, state, similarity, detail, created_at, binding_id " +
		"FROM finding_verifications WHERE finding_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2"
	rows, err := d.QueryContext(ctx, query, findingID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []FindingVerification
	for rows.Next() {
		var v FindingVerification
		var sim *float64
		if err := rows.Scan(&v.ID, &v.FindingID, &v.EvidenceVersion, &v.Engine, &v.State, &sim, &v.Detail, &v.CreatedAt, &v.BindingID); err != nil {
			return nil, err
		}
		v.Similarity = sim
		out = append(out, v)
	}
	return out, rows.Err()
}
