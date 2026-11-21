package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

var (
	ErrIdentityNameRequired = errors.New("身份名（label）必填")
	ErrIdentityHeadersEmpty = errors.New("身份必须至少带一个请求头（Cookie / Authorization 等）")
)

// TaskIdentity 是一个可复用的测试身份。
//
// 为什么要落库而不是让模型自己拼 Cookie：差分判定依赖「A、B 是两个真的不同的人」，
// 模型每次现编，B 很容易又被写成 A 的凭据，这时 any 判定都会退化成「同一凭据」。
type TaskIdentity struct {
	ID        int64             `json:"id,string"`
	TaskID    int64             `json:"task_id,string"`
	Label     string            `json:"label"`
	Role      string            `json:"role,omitempty"`
	Headers   map[string]string `json:"headers"`
	Canary    string            `json:"canary,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

// MaskedHeaders 把值打码，给模型/页面看用（凭据本体不进上下文）。
func (t TaskIdentity) MaskedHeaders() map[string]string {
	out := make(map[string]string, len(t.Headers))
	for k, v := range t.Headers {
		if len(v) <= 8 {
			out[k] = "***"
			continue
		}
		out[k] = v[:4] + "…" + v[len(v)-4:]
	}
	return out
}

// Fingerprint 用来判断两个身份是不是同一份凭据（差分前提）。
func (t TaskIdentity) Fingerprint() string {
	keys := make([]string, 0, len(t.Headers))
	for k := range t.Headers {
		keys = append(keys, strings.ToLower(k))
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteString("=")
		for hk, hv := range t.Headers {
			if strings.EqualFold(hk, k) {
				b.WriteString(hv)
				break
			}
		}
		b.WriteString(";")
	}
	return b.String()
}

func normalizeIdentityHeaders(in map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(in))
	for k, v := range in {
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k == "" || v == "" {
			continue
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil, ErrIdentityHeadersEmpty
	}
	return out, nil
}

// UpsertTaskIdentity 登记/覆盖一个身份；同名覆盖（凭据更新）。
func (s *ExplorationStore) UpsertTaskIdentity(ctx context.Context, taskID int64, label, role string, headers map[string]string, canary string) (*TaskIdentity, error) {
	return s.db.UpsertTaskIdentity(ctx, taskID, label, role, headers, canary)
}

func (d *DB) UpsertTaskIdentity(ctx context.Context, taskID int64, label, role string, headers map[string]string, canary string) (*TaskIdentity, error) {
	label = strings.TrimSpace(label)
	if label == "" {
		return nil, ErrIdentityNameRequired
	}
	if len([]rune(label)) > 80 {
		return nil, fmt.Errorf("身份名最多 80 个字符")
	}
	if taskID <= 0 {
		return nil, errors.New("任务 ID 无效")
	}
	norm, err := normalizeIdentityHeaders(headers)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(norm)
	if err != nil {
		return nil, err
	}
	var id int64
	var created time.Time
	if err := d.QueryRowContext(ctx, `
INSERT INTO task_identities(task_id, label, role, headers, canary)
VALUES ($1,$2,$3,$4::jsonb,$5)
ON CONFLICT (task_id, label) DO UPDATE
  SET role=EXCLUDED.role, headers=EXCLUDED.headers, canary=EXCLUDED.canary
RETURNING id, created_at`, taskID, label, strings.TrimSpace(role), string(raw), strings.TrimSpace(canary)).Scan(&id, &created); err != nil {
		return nil, err
	}
	return &TaskIdentity{ID: id, TaskID: taskID, Label: label, Role: strings.TrimSpace(role), Headers: norm, Canary: strings.TrimSpace(canary), CreatedAt: created}, nil
}

// ListTaskIdentities 按名称排序返回本任务的身份。
func (s *ExplorationStore) ListTaskIdentities(ctx context.Context, taskID int64) ([]TaskIdentity, error) {
	return s.db.ListTaskIdentities(ctx, taskID)
}

func (d *DB) ListTaskIdentities(ctx context.Context, taskID int64) ([]TaskIdentity, error) {
	rows, err := d.QueryContext(ctx, `SELECT id, task_id, label, role, headers, canary, created_at FROM task_identities WHERE task_id=$1 ORDER BY label`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TaskIdentity
	for rows.Next() {
		var t TaskIdentity
		var raw []byte
		if err := rows.Scan(&t.ID, &t.TaskID, &t.Label, &t.Role, &raw, &t.Canary, &t.CreatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &t.Headers); err != nil {
			return nil, fmt.Errorf("身份 %s 的请求头解析失败: %w", t.Label, err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteTaskIdentity 删除一个身份。
func (s *ExplorationStore) DeleteTaskIdentity(ctx context.Context, taskID int64, label string) (bool, error) {
	return s.db.DeleteTaskIdentity(ctx, taskID, label)
}

func (d *DB) DeleteTaskIdentity(ctx context.Context, taskID int64, label string) (bool, error) {
	res, err := d.ExecContext(ctx, `DELETE FROM task_identities WHERE task_id=$1 AND label=$2`, taskID, strings.TrimSpace(label))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}
