package server

import (
	"net/http"
	"strconv"
	"time"

	"github.com/jintilm/praetor/db"
)

// CTF 逐题进度看板（P2-6 的可见面）。
//
// 数据本来就在 `ctf_progress` 里（worker 的 ctf_board 工具读的是同一张表），
// 但只有任务内可见。这里给 UI 一个只读出口：谁解出了哪道题、花了多少 token、什么时候解的。
//
// 为什么不在这里现算：`spent_tokens` 是**判题通过那一刻**由 TaskTokenTotal 减
// base_tokens 得到的快照。事后重算会把"之后又跑了多少"算进去，跨任务比较就失真了。

type ctfBoardRow struct {
	TaskID      string     `json:"task_id"`
	ChallengeID string     `json:"challenge_id"`
	State       string     `json:"state"`
	Reason      string     `json:"reason,omitempty"`
	SpentTokens int64      `json:"spent_tokens"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty"`
	TaskStatus  string     `json:"task_status,omitempty"`
	TaskDomain  string     `json:"task_domain,omitempty"`
	TaskGoal    string     `json:"task_goal,omitempty"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
}

type ctfBoardSummary struct {
	Challenges int   `json:"challenges"`
	Solved     int   `json:"solved"`
	Tokens     int64 `json:"tokens"`
}

// getCTFBoard 返回最近的逐题进度 + 汇总。
func (s *Server) getCTFBoard(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	rows, err := pg.Query(`
		SELECT p.task_id::text, p.challenge_id, p.state, p.reason, p.spent_tokens, p.updated_at,
		       COALESCE(t.status,''), COALESCE(t.domain,''), COALESCE(t.goal,''),
		       t.first_run_at, t.completed_at
		FROM ctf_progress p
		LEFT JOIN tasks t ON t.id = p.task_id
		ORDER BY p.updated_at DESC
		LIMIT $1`, limit)
	if err != nil {
		writeErr(w, 500, "读取 CTF 进度失败："+err.Error())
		return
	}
	defer rows.Close()

	out := make([]ctfBoardRow, 0, limit)
	var sum ctfBoardSummary
	for rows.Next() {
		var b ctfBoardRow
		var updated, started, finished *time.Time
		var tid int64
		if err := rows.Scan(&tid, &b.ChallengeID, &b.State, &b.Reason, &b.SpentTokens, &updated,
			&b.TaskStatus, &b.TaskDomain, &b.TaskGoal, &started, &finished); err != nil {
			writeErr(w, 500, "解析 CTF 进度失败："+err.Error())
			return
		}
		b.TaskID = strconv.FormatInt(tid, 10)
		b.UpdatedAt, b.StartedAt, b.FinishedAt = updated, started, finished
		out = append(out, b)
		sum.Challenges++
		sum.Tokens += b.SpentTokens
		if b.State == db.CTFProgressSolved {
			sum.Solved++
		}
	}
	if err := rows.Err(); err != nil {
		writeErr(w, 500, "读取 CTF 进度失败："+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"summary": sum, "items": out})
}
