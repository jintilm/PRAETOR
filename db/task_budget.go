package db

// 任务预算用量查询（给引擎的预算闸门用，见 internal/budget）。
//
// 两个数字都必须来自**账本表**而不是内存计数器：
//   - 进程重启后内存归零，但账本还在（续跑时预算不能"重置"）；
//   - 账本是每次真实调用的落库记录，口径与报表一致，不会出现"日志说没超、账单超了"。

// TaskTokenTotal 返回任务累计 token（input+output）。
func (d *DB) TaskTokenTotal(taskID string) (int64, error) {
	var n int64
	err := d.QueryRow(`
SELECT COALESCE(SUM(input_tokens + output_tokens), 0)
FROM llm_usage
WHERE COALESCE(task_id,'') = $1`, taskID).Scan(&n)
	return n, err
}

// ToolCallsForTask 返回该任务实际发生的工具调用次数（tool_usage 一行 = 一次 CoreTool.Call）。
// 任务历史会同时按 task_id 与 exploration_id 记，所以两个维度都算。
func (d *DB) ToolCallsForTask(taskID, explorationID int64) (int64, error) {
	var n int64
	err := d.QueryRow(`
SELECT count(*) FROM tool_usage
WHERE task_id = $1 OR exploration_id = $2`, taskID, explorationID).Scan(&n)
	return n, err
}
