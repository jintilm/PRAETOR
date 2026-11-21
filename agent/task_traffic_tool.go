package agent

import (
	"context"
	"encoding/json"

	"github.com/jintilm/praetor/db"

	actool "github.com/jintilm/praetor/internal/norma/tool"
)

// listTaskTraffic 让 worker 直接拿到「本任务已归属的流量」。
//
// 存在的理由：绑定证据与危害取证都要真实 traffic_id，而模型此前只能靠
// traffic_search 按 host/时间猜，猜错就是错误绑定。归属表一有数据，这里就是
// 确定性答案——不过它只覆盖**平台代发的请求**（http_probe、后续重放），
// 沙箱里 curl 直接发出的流量采集层没有任务身份，仍然查不到。描述里必须写清这条边界，
// 否则模型会以为"查不到 = 没发过"，转而重复探测。
func (t *ToolSet) listTaskTraffic() actool.CoreTool {
	schema := obj(map[string]any{
		"limit": map[string]any{"type": "integer", "description": "返回条数（默认 10，最大 50）"},
	})
	return readTool("list_task_traffic",
		"列出本任务已归属的 HTTP 流量（traffic_id + host/method/url/status）。"+
			"绑定证据、record_impact 的 artifact 直接用这里返回的 traffic_id，不要猜。"+
			"只包含平台代发的请求（http_probe / 重放）；你在沙箱里用 curl 直接发的流量不在其中——"+
			"那种情况用 traffic_search 找。",
		schema,
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if t.ts == nil || t.taskID <= 0 {
				return actool.Errorf("list_task_traffic 需要任务上下文（当前没有 task_id）"), nil
			}
			var a struct {
				Limit int `json:"limit"`
			}
			if len(in) > 0 {
				if err := json.Unmarshal(in, &a); err != nil {
					return actool.Errorf(err.Error()), nil
				}
			}
			limit := a.Limit
			if limit <= 0 {
				limit = 10
			}
			if limit > 50 {
				limit = 50
			}
			rows, err := t.ts.ListTaskTraffic(ctx, t.taskID, limit, db.TaskTrafficCaptured)
			if err != nil {
				return actool.Errorf("读取流量归属失败：" + err.Error()), nil
			}
			if len(rows) == 0 {
				return actool.Text("本任务暂无采集侧确认归属的流量。历史推断记录仍保留供人工复核；不要为填充列表重复探测。" +
					"沙箱内 curl 的流量可通过 traffic_search 筛选候选，再核对原始报文；主机和时间不证明任务归属。"), nil
			}
			return jsonResult(map[string]any{"items": rows, "count": len(rows), "attribution_kind": db.TaskTrafficCaptured})
		})
}
