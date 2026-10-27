package db

import (
	"database/sql"
	"errors"
	"time"
)

// CTF 逐题进度状态（P2-6）。与 ctfplan.State 一一对应，别各写一套字符串。
const (
	CTFProgressNew       = "new"
	CTFProgressActive    = "active"
	CTFProgressSolved    = "solved"
	CTFProgressAbandoned = "abandoned"
)

// CTFProgress 是一道题在某个任务内的进度。
//
// BaseTokens 是激活那一刻的任务累计 tokens：当前花费 = 任务累计 - BaseTokens。
// 之所以不在每轮写死 SpentTokens，是因为账本只有任务级（llm_usage），
// 逐题单独记账需要另一套采集器，收益抵不过复杂度。
type CTFProgress struct {
	TaskID      int64     `json:"task_id"`
	ChallengeID string    `json:"challenge_id"`
	State       string    `json:"state"`
	Reason      string    `json:"reason,omitempty"`
	SpentTokens int64     `json:"spent_tokens"`
	BaseTokens  int64     `json:"base_tokens"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ListCTFProgress 返回某任务的全部逐题进度（按题目 id 排序，便于稳定输出）。
func (d *DB) ListCTFProgress(taskID int64) ([]CTFProgress, error) {
	rows, err := d.Query(`
SELECT task_id, challenge_id, state, reason, spent_tokens, base_tokens, updated_at
FROM ctf_progress WHERE task_id=$1 ORDER BY challenge_id`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CTFProgress{}
	for rows.Next() {
		var p CTFProgress
		if err := rows.Scan(&p.TaskID, &p.ChallengeID, &p.State, &p.Reason,
			&p.SpentTokens, &p.BaseTokens, &p.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetCTFProgress 取单题进度；没有返回 (nil, nil)。
func (d *DB) GetCTFProgress(taskID int64, challengeID string) (*CTFProgress, error) {
	var p CTFProgress
	err := d.QueryRow(`
SELECT task_id, challenge_id, state, reason, spent_tokens, base_tokens, updated_at
FROM ctf_progress WHERE task_id=$1 AND challenge_id=$2`, taskID, challengeID).
		Scan(&p.TaskID, &p.ChallengeID, &p.State, &p.Reason, &p.SpentTokens, &p.BaseTokens, &p.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// ActivateCTFChallenge 把某题标为"正在做"，并把基线重置到当前任务用量。
//
// 已解出的题不会被降级（重复激活只会白白多花预算）；
// 已放弃的题允许重新激活（人/模型坚持要做就让它做），但** reason 保留 **——
// "上次为什么放弃"对下一轮判断仍然有用。
func (d *DB) ActivateCTFChallenge(taskID int64, challengeID string, baseTokens int64) error {
	_, err := d.Exec(`
INSERT INTO ctf_progress(task_id, challenge_id, state, base_tokens)
VALUES ($1,$2,'active',$3)
ON CONFLICT (task_id, challenge_id) DO UPDATE
SET state = CASE WHEN ctf_progress.state = 'solved' THEN 'solved' ELSE 'active' END,
    base_tokens = EXCLUDED.base_tokens,
    spent_tokens = CASE WHEN ctf_progress.state = 'solved' THEN ctf_progress.spent_tokens ELSE 0 END,
    updated_at = now()`, taskID, challengeID, baseTokens)
	return err
}

// MarkCTFProgress 写入终态（solved / abandoned）并冻结该题花费。
func (d *DB) MarkCTFProgress(taskID int64, challengeID, state, reason string, spentTokens int64) error {
	if state != CTFProgressSolved && state != CTFProgressAbandoned {
		return errors.New("MarkCTFProgress 只接受 solved / abandoned")
	}
	_, err := d.Exec(`
INSERT INTO ctf_progress(task_id, challenge_id, state, reason, spent_tokens, base_tokens)
VALUES ($1,$2,$3,$4,$5,0)
ON CONFLICT (task_id, challenge_id) DO UPDATE
SET state = CASE WHEN ctf_progress.state = 'solved' THEN 'solved' ELSE EXCLUDED.state END,
    reason = EXCLUDED.reason,
    spent_tokens = GREATEST(ctf_progress.spent_tokens, EXCLUDED.spent_tokens),
    updated_at = now()`, taskID, challengeID, state, reason, spentTokens)
	return err
}

// MarkCTFChallengeSolved 按 challenge_id 标记解出。
//
// 提交侧拿到的 challenge_id 可能为空（离线单题模式），此时调用方应跳过——
// 拿空 id 去写一条 "solved 空串" 的记录只会污染看板。
func (d *DB) MarkCTFChallengeSolved(taskID int64, challengeID string, spentTokens int64) error {
	if challengeID == "" {
		return nil
	}
	return d.MarkCTFProgress(taskID, challengeID, CTFProgressSolved, "", spentTokens)
}
