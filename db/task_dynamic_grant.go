package db

// Android 真机动态授权的数据层。设计约束见 schema.sql 的 §Android 真机动态授权。
//
// 这一层只做三件事：与任务创建同事务写入授权、只读查询/撤销、append-only 审计与
// 带租约的设备锁。它**不判断**「这次工具调用能不能做」—— 那是 server 侧执行链的事，
// 放这里会让 guard 依赖 db，硬闸就不再是 code-owned 的独立边界了。

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// DynamicOps 是允许被授权的原子操作集。刻意做成闭集：agent 无法创造一个没在
// 白名单里的 op，也无法通过提交新 op 扩大授权。新增能力必须改这张表并重新签发。
var DynamicOps = map[string]string{
	"install":   "安装/卸载目标 APK",
	"launch":    "启动目标 App 或组件",
	"shell":     "adb shell 交互式命令",
	"frida":     "启动 frida-server / frida-tools",
	"hook":      "注入脚本 hook 进程",
	"proxy":     "在设备上设置/重置抓包代理",
	"logcat":    "读取设备日志",
	"pull_data": "从设备拉取 App 数据作为证据",
	"cleanup":   "收尾清理（清数据、卸残留、复位代理）",
}

// DynamicOpNames 返回排序后的 op 名，用于前端下拉与错误提示（顺序稳定）。
func DynamicOpNames() []string {
	out := make([]string, 0, len(DynamicOps))
	for k := range DynamicOps {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ValidDynamicOps 校验并归一 op 列表：去空白、去重、按字典序，空列表报错。
func ValidDynamicOps(ops []string) ([]string, error) {
	seen := map[string]bool{}
	out := make([]string, 0, len(ops))
	for _, raw := range ops {
		op := strings.TrimSpace(raw)
		if op == "" {
			continue
		}
		if _, ok := DynamicOps[op]; !ok {
			return nil, fmt.Errorf("未知动态操作 %q（可用：%s）", op, strings.Join(DynamicOpNames(), "/"))
		}
		if !seen[op] {
			seen[op] = true
			out = append(out, op)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("动态授权必须至少勾选一项允许的操作")
	}
	sort.Strings(out)
	return out, nil
}

// DynamicGrantInput 是创建任务时随任务提交的人工签发内容。
type DynamicGrantInput struct {
	GrantRef             string
	Operator             string
	WrittenAuthorization bool
	DeviceSerial         string
	APKSha256            string
	Ops                  []string
	// ValidHours 是授权有效期（小时）。刻意用「时长」而不是客户端传的绝对时间：
	// valid_from / valid_until 都由数据库时钟生成，避免应用与 PG 时钟不一致
	// 让一条刚签发的授权立刻被判过期（或未生效）。
	ValidHours int
}

// DynamicGrant 是落库后的授权事实。
type DynamicGrant struct {
	ID                   int64      `json:"id"`
	TaskID               int64      `json:"task_id"`
	GrantRef             string     `json:"grant_ref"`
	Operator             string     `json:"operator"`
	WrittenAuthorization bool       `json:"written_authorization"`
	DeviceSerial         string     `json:"device_serial"`
	APKSha256            string     `json:"apk_sha256"`
	Ops                  []string   `json:"ops"`
	ValidFrom            time.Time  `json:"valid_from"`
	ValidUntil           time.Time  `json:"valid_until"`
	RevokedAt            *time.Time `json:"revoked_at,omitempty"`
	RevokeReason         string     `json:"revoke_reason,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
}

// Active 判定授权此刻是否可用。撤销、未生效、已过期都算不可用。
func (g *DynamicGrant) Active(now time.Time) bool {
	return g != nil && g.WrittenAuthorization && g.RevokedAt == nil &&
		!now.Before(g.ValidFrom) && now.Before(g.ValidUntil)
}

// Allows 判定某个 op 是否在签发范围内。
func (g *DynamicGrant) Allows(op string) bool {
	if g == nil {
		return false
	}
	for _, allowed := range g.Ops {
		if allowed == op {
			return true
		}
	}
	return false
}

const dynamicGrantCols = `id, task_id, grant_ref, operator, written_authorization,
       device_serial, apk_sha256, ops, valid_from, valid_until,
       revoked_at, revoke_reason, created_at`

func scanDynamicGrant(row interface{ Scan(...any) error }) (*DynamicGrant, error) {
	var g DynamicGrant
	var opsJSON string
	var revoked sql.NullTime
	if err := row.Scan(
		&g.ID, &g.TaskID, &g.GrantRef, &g.Operator, &g.WrittenAuthorization,
		&g.DeviceSerial, &g.APKSha256, &opsJSON, &g.ValidFrom, &g.ValidUntil,
		&revoked, &g.RevokeReason, &g.CreatedAt,
	); err != nil {
		return nil, err
	}
	if strings.TrimSpace(opsJSON) != "" {
		if err := json.Unmarshal([]byte(opsJSON), &g.Ops); err != nil {
			return nil, fmt.Errorf("解析动态授权 ops: %w", err)
		}
	}
	if revoked.Valid {
		t := revoked.Time
		g.RevokedAt = &t
	}
	return &g, nil
}

// insertTaskDynamicGrant 在任务创建事务里写入授权。nil = 该任务未申请动态授权，
// 此时执行链会把所有动态工具调用 fail-closed 降级到静态。
func insertTaskDynamicGrant(tx *sql.Tx, taskID int64, in *DynamicGrantInput) error {
	if in == nil {
		return nil
	}
	ops, err := json.Marshal(in.Ops)
	if err != nil {
		return fmt.Errorf("序列化动态授权 ops: %w", err)
	}
	_, err = tx.Exec(`
INSERT INTO task_dynamic_grants(task_id, grant_ref, operator, written_authorization,
                                device_serial, apk_sha256, ops, valid_from, valid_until)
VALUES ($1,$2,$3,$4,$5,$6,$7,now(),now() + make_interval(hours => $8))`,
		taskID, in.GrantRef, in.Operator, in.WrittenAuthorization,
		in.DeviceSerial, in.APKSha256, string(ops), in.ValidHours)
	if err != nil {
		return fmt.Errorf("写入任务动态授权: %w", err)
	}
	return nil
}

// GetTaskDynamicGrant 返回任务的授权（含已撤销/已过期的，供审计展示）。
// 无授权返回 (nil, nil)，与 sql.ErrNoRows 区分开。
func (d *DB) GetTaskDynamicGrant(taskID int64) (*DynamicGrant, error) {
	row := d.QueryRow(`SELECT `+dynamicGrantCols+` FROM task_dynamic_grants WHERE task_id=$1`, taskID)
	g, err := scanDynamicGrant(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return g, err
}

// RevokeTaskDynamicGrant 撤销授权。只写撤销标记，不删行、不改任何签发字段 ——
// 授权一旦签发就不能被「改写」，否则审计与令牌绑定都会失去意义。操作者由调用方
// 另写一条 action=revoke 的审计，这里不重复记。
func (d *DB) RevokeTaskDynamicGrant(taskID int64, reason string) (bool, error) {
	res, err := d.Exec(`
UPDATE task_dynamic_grants
   SET revoked_at=now(), revoke_reason=$2
 WHERE task_id=$1 AND revoked_at IS NULL`, taskID, strings.TrimSpace(reason))
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// DynamicGrantAudit 是一条 append-only 的动态调用留痕。
type DynamicGrantAudit struct {
	ID           int64     `json:"id"`
	TaskID       int64     `json:"task_id"`
	Action       string    `json:"action"`
	Op           string    `json:"op"`
	Tool         string    `json:"tool"`
	DeviceSerial string    `json:"device_serial"`
	TicketDigest string    `json:"ticket_digest"`
	Reason       string    `json:"reason"`
	Operator     string    `json:"operator"`
	CreatedAt    time.Time `json:"created_at"`
}

// AppendDynamicGrantAudit 写一条审计。失败只返回 error，由调用方决定是否影响主流程：
// 放行判定绝不依赖审计写入成功（审计表不可用时宁可放行也不中断已授权作业），
// 但签发/撤销这类状态变更要求写成功。
func (d *DB) AppendDynamicGrantAudit(ctx context.Context, a DynamicGrantAudit) error {
	_, err := d.ExecContext(ctx, `
INSERT INTO dynamic_grant_audits(task_id, action, op, tool, device_serial, ticket_digest, reason, operator)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		a.TaskID, a.Action, a.Op, a.Tool, a.DeviceSerial, a.TicketDigest, a.Reason, a.Operator)
	return err
}

// ListDynamicGrantAudits 返回最近 limit 条审计（倒序）。
func (d *DB) ListDynamicGrantAudits(taskID int64, limit int) ([]DynamicGrantAudit, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	rows, err := d.Query(`
SELECT id, task_id, action, op, tool, device_serial, ticket_digest, reason, operator, created_at
  FROM dynamic_grant_audits WHERE task_id=$1 ORDER BY id DESC LIMIT $2`, taskID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DynamicGrantAudit{}
	for rows.Next() {
		var a DynamicGrantAudit
		if err := rows.Scan(&a.ID, &a.TaskID, &a.Action, &a.Op, &a.Tool,
			&a.DeviceSerial, &a.TicketDigest, &a.Reason, &a.Operator, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ErrDeviceBusy 表示设备正被另一个任务独占且租约未到期。
var ErrDeviceBusy = errors.New("设备已被其它任务占用（租约未到期）")

// AcquireDeviceLease 以数据库唯一约束抢占设备，ttl 是租约时长。
// 同一任务重复调用视为续租；别的任务只能在租约过期后抢走。
func (d *DB) AcquireDeviceLease(ctx context.Context, serial string, taskID int64, ttl time.Duration) error {
	var owner int64
	err := d.QueryRowContext(ctx, `
INSERT INTO device_leases(serial, task_id, lease_until)
VALUES ($1,$2,now() + make_interval(secs => $3))
ON CONFLICT (serial) DO UPDATE
   SET task_id=EXCLUDED.task_id, lease_until=EXCLUDED.lease_until, updated_at=now()
 WHERE device_leases.task_id=EXCLUDED.task_id OR device_leases.lease_until < now()
RETURNING task_id`, serial, taskID, ttl.Seconds()).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrDeviceBusy
	}
	return err
}

// RenewDeviceLease 延长本任务持有的设备租约；已被别人抢走时返回 false。
func (d *DB) RenewDeviceLease(ctx context.Context, serial string, taskID int64, ttl time.Duration) (bool, error) {
	res, err := d.ExecContext(ctx, `
UPDATE device_leases
   SET lease_until=now() + make_interval(secs => $3), updated_at=now()
 WHERE serial=$1 AND task_id=$2`, serial, taskID, ttl.Seconds())
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ReleaseDeviceLease 只释放本任务持有的锁，不会误删别人的。
func (d *DB) ReleaseDeviceLease(ctx context.Context, serial string, taskID int64) error {
	_, err := d.ExecContext(ctx, `DELETE FROM device_leases WHERE serial=$1 AND task_id=$2`, serial, taskID)
	return err
}
