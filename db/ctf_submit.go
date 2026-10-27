package db

import (
	"database/sql"
	"errors"
	"time"
)

// CTFSubmission 是一次 flag 提交的去重记录（主键 = flag 的 sha256）。
type CTFSubmission struct {
	FlagSHA     string    `json:"flag_sha256"`
	ChallengeID string    `json:"challenge_id,omitempty"`
	Flag        string    `json:"flag"`
	Verdict     string    `json:"verdict"` // accepted | rejected
	Raw         string    `json:"raw_response,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// GetCTFSubmission 按 flag 哈希取已有记录；没有返回 (nil, nil)。
func (d *DB) GetCTFSubmission(flagSHA string) (*CTFSubmission, error) {
	var s CTFSubmission
	err := d.QueryRow(`
SELECT flag_sha256, challenge_id, flag, verdict, raw_response, created_at
FROM ctf_submissions WHERE flag_sha256=$1`, flagSHA).
		Scan(&s.FlagSHA, &s.ChallengeID, &s.Flag, &s.Verdict, &s.Raw, &s.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// InsertCTFSubmission 只在 flag 未提交过时写入，返回是否真的插入了。
//
// 用 ON CONFLICT DO NOTHING 而不是"先查再写"：并发下两个 solver 可能同时拿到同一个 flag，
// 先查再写会让两边都判"没提交过"，于是都打到平台（正是去重要避免的事）。
// 让主键做仲裁，插入失败的那一方按"已提交过"处理。
func (d *DB) InsertCTFSubmission(s *CTFSubmission) (bool, error) {
	tag, err := d.Exec(`
INSERT INTO ctf_submissions(flag_sha256, challenge_id, flag, verdict, raw_response)
VALUES ($1,$2,$3,$4,$5)
ON CONFLICT (flag_sha256) DO NOTHING`,
		s.FlagSHA, s.ChallengeID, s.Flag, s.Verdict, s.Raw)
	if err != nil {
		return false, err
	}
	n, err := tag.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}
