package db

import (
	"database/sql"
	"errors"
	"time"
)

// CTF 提交结论（判分口径的唯一来源，别在别处写字符串字面量）。
const (
	CTFVerdictAccepted  = "accepted"
	CTFVerdictRejected  = "rejected"
	CTFVerdictDuplicate = "duplicate"
)

// CTFSubmission 是一次 flag 提交的去重记录（主键 = flag 的 sha256）。
type CTFSubmission struct {
	FlagSHA     string    `json:"flag_sha256"`
	TaskID      int64     `json:"task_id,omitempty"` // 归属任务（0 = 无任务上下文）
	ChallengeID string    `json:"challenge_id,omitempty"`
	Flag        string    `json:"flag"`
	Verdict     string    `json:"verdict"` // accepted | rejected
	Raw         string    `json:"raw_response,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// GetCTFSubmission 按 flag 哈希取已有记录；没有返回 (nil, nil)。
//
// 同一个 flag 现在可能有多行（每个任务各一行），取**最早**那一行的判定：
// 平台的结论不会因为谁提交而变，最早的结论最接近原始判定。
func (d *DB) GetCTFSubmission(flagSHA string) (*CTFSubmission, error) {
	var s CTFSubmission
	err := d.QueryRow(`
SELECT flag_sha256, COALESCE(task_id,0), challenge_id, flag, verdict, raw_response, created_at
FROM ctf_submissions WHERE flag_sha256=$1
ORDER BY created_at LIMIT 1`, flagSHA).
		Scan(&s.FlagSHA, &s.TaskID, &s.ChallengeID, &s.Flag, &s.Verdict, &s.Raw, &s.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// GetCTFSubmissionForTask 取**本任务**对这个 flag 的提交记录；没有返回 (nil, nil)。
//
// 判重必须按任务粒度问：只查全局最早一条会让"本任务已交过"和"别的任务交过"混在一起。
// 后者要走"沿用判定并落库"，前者只是 duplicate —— 两者后果不同（前者不该再收敛一次）。
func (d *DB) GetCTFSubmissionForTask(flagSHA string, taskID int64) (*CTFSubmission, error) {
	var s CTFSubmission
	err := d.QueryRow(`
SELECT flag_sha256, COALESCE(task_id,0), challenge_id, flag, verdict, raw_response, created_at
FROM ctf_submissions WHERE flag_sha256=$1 AND task_id=$2
ORDER BY created_at LIMIT 1`, flagSHA, taskID).
		Scan(&s.FlagSHA, &s.TaskID, &s.ChallengeID, &s.Flag, &s.Verdict, &s.Raw, &s.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// ListCTFSubmissions 返回某任务的提交记录（按时间倒序）。
//
// 评分要用它：bench 只能从"平台判对过没有"来判分，而不是看模型说自己解出来了。
func (d *DB) ListCTFSubmissions(taskID int64, limit int) ([]CTFSubmission, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := d.Query(`
SELECT flag_sha256, COALESCE(task_id,0), challenge_id, flag, verdict, raw_response, created_at
FROM ctf_submissions
WHERE task_id = $1
ORDER BY created_at DESC, flag_sha256
LIMIT $2`, taskID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CTFSubmission{}
	for rows.Next() {
		var s CTFSubmission
		if err := rows.Scan(&s.FlagSHA, &s.TaskID, &s.ChallengeID, &s.Flag, &s.Verdict, &s.Raw, &s.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// AcceptedFlagForTask 报告该任务是否至少有一个被判对的 flag（bench 判分口径）。
func (d *DB) AcceptedFlagForTask(taskID int64) (string, bool, error) {
	var flag string
	err := d.QueryRow(`
SELECT flag FROM ctf_submissions
WHERE task_id = $1 AND verdict = 'accepted'
ORDER BY created_at LIMIT 1`, taskID).Scan(&flag)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return flag, true, nil
}

// InsertCTFSubmission 只在「该任务还没记过这个 flag」时写入，返回是否真的插入了。
//
// 主键是 (flag_sha256, task_id)：同一任务重复提交同一个 flag 只留一行（去重），
// 但不同任务各留一行 —— 否则重跑同一道题时第二个任务永远没有 accepted 记录，
// 评分会把"已经解出来"算成未解出。
//
// 用 ON CONFLICT DO NOTHING 而不是"先查再写"：并发下两个 solver 可能同时拿到同一个 flag，
// 先查再写会让两边都判"没提交过"，于是都打到平台（正是去重要避免的事）。
// 让主键做仲裁，插入失败的那一方按"已提交过"处理。
func (d *DB) InsertCTFSubmission(s *CTFSubmission) (bool, error) {
	tag, err := d.Exec(`
INSERT INTO ctf_submissions(flag_sha256, task_id, challenge_id, flag, verdict, raw_response)
VALUES ($1,$2,$3,$4,$5,$6)
ON CONFLICT (flag_sha256, task_id) DO NOTHING`,
		s.FlagSHA, s.TaskID, s.ChallengeID, s.Flag, s.Verdict, s.Raw)
	if err != nil {
		return false, err
	}
	n, err := tag.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// AcceptedFlagForTask 的 store 转发：agent 层只持有 ExplorationStore，
// 不该为了查一次判题结果再持一个 *db.DB 句柄。
//
// taskID<=0（测试/跨任务读取）时返回 false，调用方按"没有 accepted"处理 ——
// fail closed 是这里的正确方向：拿不到判题记录就不该让人标目标达成。
func (s *ExplorationStore) AcceptedFlagForTask(taskID int64) (string, bool, error) {
	if s == nil || s.db == nil || taskID <= 0 {
		return "", false, nil
	}
	return s.db.AcceptedFlagForTask(taskID)
}
