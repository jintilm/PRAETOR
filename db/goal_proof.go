package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ProvePentestGoal rechecks the exact finding under the evidence writer locks.
// The edge and goal state commit together, after rechecking current versions.
func (s *ExplorationStore) ProvePentestGoal(ctx context.Context, taskID, goalID, evidenceID int64) error {
	if s == nil || s.db == nil || taskID <= 0 || goalID <= 0 || evidenceID <= 0 {
		return errors.New("目标证明需要完整的任务和证据上下文")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := LockTaskEvidenceTx(tx, taskID); err != nil {
		return err
	}
	var expID int64
	if err := tx.QueryRowContext(ctx, "SELECT exploration_id FROM tasks WHERE id=$1", taskID).Scan(&expID); err != nil {
		return err
	}
	if expID != s.expID {
		return errors.New("目标证明与任务探索不匹配")
	}
	var findingID int64
	if err := tx.QueryRowContext(ctx, "SELECT id FROM findings WHERE task_id=$1 AND node_id=$2", taskID, evidenceID).Scan(&findingID); err != nil {
		return fmt.Errorf("证明节点未对应本任务发现: %w", err)
	}
	if err := LockFindingEvidenceTx(tx, findingID, nil); err != nil {
		return err
	}
	var evidenceKind string
	if err := tx.QueryRowContext(ctx, "SELECT kind FROM exploration_nodes WHERE id=$1 AND exploration_id=$2 FOR UPDATE", evidenceID, s.expID).Scan(&evidenceKind); err != nil {
		return err
	}
	if evidenceKind != KindFinding {
		return errors.New("严格验收需要当前任务的发现节点，其他证据保留待复核")
	}
	acc, err := taskFindingAcceptance(ctx, tx, taskID, evidenceID)
	if err != nil {
		return err
	}
	if acc.Ready == nil || acc.Ready.ID != findingID || acc.Ready.NodeID != evidenceID {
		return errors.New("证明证据已变化或尚未完成同版本验证与危害取证，请复核后重试")
	}
	if err := linkGoalTx(ctx, tx, s.expID, goalID, evidenceID); err != nil {
		return err
	}
	return tx.Commit()
}

// ProveGoal stores the two graph writes atomically for the other acceptance modes.
func (s *ExplorationStore) ProveGoal(ctx context.Context, goalID, evidenceID int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := linkGoalTx(ctx, tx, s.expID, goalID, evidenceID); err != nil {
		return err
	}
	return tx.Commit()
}

func linkGoalTx(ctx context.Context, tx *sql.Tx, expID, goalID, evidenceID int64) error {
	var kind string
	if err := tx.QueryRowContext(ctx, "SELECT kind FROM exploration_nodes WHERE id=$1 AND exploration_id=$2 FOR UPDATE", goalID, expID).Scan(&kind); err != nil {
		return err
	}
	if kind != KindGoal {
		return errors.New("goal_id 不是当前任务目标")
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING", expID, evidenceID, RelProves, goalID); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, "UPDATE exploration_nodes SET state='met', blocked_reason=NULL, content_version=content_version+1 WHERE id=$1 AND exploration_id=$2", goalID, expID)
	return err
}

// CompleteTaskAfterAcceptance consumes current evidence in the same transaction
// that persists done. Explicit operator lifecycle overrides use SetStatus instead.
func (d *DB) CompleteTaskAfterAcceptance(ctx context.Context, taskID int64, requireFinding bool) (bool, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if err := LockTaskEvidenceTx(tx, taskID); err != nil {
		return false, err
	}
	var expID int64
	var domain, status string
	var paused bool
	if err := tx.QueryRowContext(ctx, "SELECT exploration_id, COALESCE(domain,'pentest'), status, paused FROM tasks WHERE id=$1", taskID).Scan(&expID, &domain, &status, &paused); err != nil {
		return false, err
	}
	if IsTerminal(status) || paused {
		return false, nil
	}
	var proofID, proofVersion, proofBinding any
	if requireFinding && (domain == "" || domain == "pentest") {
		// Lock in ID order; triage writers also acquire the row lock on UPDATE.
		rows, err := tx.QueryContext(ctx, "SELECT id FROM findings WHERE task_id=$1 ORDER BY id FOR UPDATE", taskID)
		if err != nil {
			return false, err
		}
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return false, err
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return false, err
		}
		rows.Close()
		acc, err := taskFindingAcceptance(ctx, tx, taskID, 0)
		if err != nil {
			return false, err
		}
		if acc.Ready == nil {
			return false, errors.New("任务完成前证据已变化或尚未完成同版本验收，保留为待复核")
		}
		proofID, proofVersion = acc.Ready.ID, acc.Ready.EvidenceVersion
		if err := tx.QueryRowContext(ctx, "SELECT verification_binding_id FROM findings WHERE id=$1", acc.Ready.ID).Scan(&proofBinding); err != nil {
			return false, err
		}
	}
	if _, err := tx.ExecContext(ctx, "UPDATE tasks SET status='done', completed_at=COALESCE(completed_at,now()), accepted_finding_id=$2, accepted_evidence_version=$3, accepted_binding_id=$4 WHERE id=$1", taskID, proofID, proofVersion, proofBinding); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}
