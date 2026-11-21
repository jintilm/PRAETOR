package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// TaskTraffic 是一条「属于某任务」的 HTTP 流量记录。
//
// 只有平台代发、因而知道任务身份的请求会写进这里（目前是 http_probe）。
// 沙箱里 curl 直接发出的流量没有归属——不是漏写，是采集层拿不到任务身份。
type TaskTraffic struct {
	ID              int64     `json:"id,string"`
	TaskID          int64     `json:"task_id,string"`
	TrafficID       string    `json:"traffic_id"`
	Host            string    `json:"host,omitempty"`
	Method          string    `json:"method,omitempty"`
	URL             string    `json:"url,omitempty"`
	Status          int       `json:"status,omitempty"`
	Source          string    `json:"source,omitempty"`
	AttributionKind string    `json:"attribution_kind"`
	CreatedAt       time.Time `json:"created_at"`
}

// 归属来源。
const (
	TaskTrafficProbe    = "probe"    // http_probe 探针代发
	TaskTrafficReplay   = "replay"   // 证据重放
	TaskTrafficCaptured = "captured" // 采集成功回执
	TaskTrafficInferred = "inferred" // 历史推断，仅供审计
)

var ErrTrafficAttributionConflict = errors.New("流量归属冲突")

// RecordTaskTraffic 记录一条流量归属，幂等（同一 traffic_id 只留第一次）。
//
// 同一来源的重复写入保持幂等；不同任务、来源或归属类型冲突时显式报错。
// 历史推断保持原样，不会被自动升级成采集确认。
func (d *DB) RecordTaskTraffic(ctx context.Context, in TaskTraffic) error {
	if in.TaskID <= 0 {
		return errors.New("task_traffic: task id 无效")
	}
	trafficID := strings.TrimSpace(in.TrafficID)
	if trafficID == "" {
		return errors.New("task_traffic: traffic id 为空")
	}
	kind := in.AttributionKind
	if kind == "" {
		kind = TaskTrafficInferred
	}
	if kind != TaskTrafficCaptured && kind != TaskTrafficInferred {
		return errors.New("流量归属类型无效")
	}
	res, err := d.ExecContext(ctx, `
INSERT INTO task_traffic(task_id, traffic_id, host, method, url, status, source, attribution_kind)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (traffic_id) DO UPDATE SET traffic_id = task_traffic.traffic_id
WHERE task_traffic.task_id = EXCLUDED.task_id AND task_traffic.source = EXCLUDED.source AND task_traffic.attribution_kind = EXCLUDED.attribution_kind`,
		in.TaskID, trafficID, in.Host, strings.ToUpper(strings.TrimSpace(in.Method)), in.URL, in.Status, in.Source, kind)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return fmt.Errorf("流量 %s 已有其他任务或来源的归属: %w", trafficID, ErrTrafficAttributionConflict)
	}
	return nil
}

// ListTaskTraffic 按时间倒序返回该任务已归属的流量。
func (d *DB) ListTaskTraffic(ctx context.Context, taskID int64, limit int, attributionKinds ...string) ([]TaskTraffic, error) {
	kind := ""
	if len(attributionKinds) > 0 {
		kind = attributionKinds[0]
	}
	if len(attributionKinds) > 1 || (kind != "" && kind != TaskTrafficCaptured && kind != TaskTrafficInferred) {
		return nil, errors.New("流量归属筛选无效")
	}
	if taskID <= 0 {
		return nil, nil
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := d.QueryContext(ctx, `
SELECT id, task_id, traffic_id, host, method, url, status, source, created_at, attribution_kind
FROM task_traffic WHERE task_id=$1 AND ($3::text = '' OR attribution_kind=$3) ORDER BY id DESC LIMIT $2`, taskID, limit, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TaskTraffic
	for rows.Next() {
		var r TaskTraffic
		if err := rows.Scan(&r.ID, &r.TaskID, &r.TrafficID, &r.Host, &r.Method, &r.URL, &r.Status, &r.Source, &r.CreatedAt, &r.AttributionKind); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RecordTaskTraffic / ListTaskTraffic 让只持有 ExplorationStore 的 agent 工具也能用归属表。
func (s *ExplorationStore) RecordTaskTraffic(ctx context.Context, in TaskTraffic) error {
	return s.db.RecordTaskTraffic(ctx, in)
}

func (s *ExplorationStore) ListTaskTraffic(ctx context.Context, taskID int64, limit int, attributionKinds ...string) ([]TaskTraffic, error) {
	return s.db.ListTaskTraffic(ctx, taskID, limit, attributionKinds...)
}
