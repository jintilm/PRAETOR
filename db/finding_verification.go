package db

import (
	"context"
	"errors"
	"fmt"
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
       verified_at = now()
 WHERE id = $1`, findingID, state, sim, note)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
