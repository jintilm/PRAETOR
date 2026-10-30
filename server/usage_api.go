package server

import (
	"net/http"
	"strconv"

	"github.com/jintilm/praetor/db"
)

// 用量成本汇总（P1-5 的前端缺口）。
//
// 为什么需要一个专门的接口而不是让前端自己算：成本口径有两层——**名义 token** 与
// **全价等价**（缓存命中按 1/10 计价）。实测（2026-10-30）同一个模型在不同供应商上
// cache 命中率从 0% 到 98.8% 不等，只看 input_tokens 会把成本算错 5 倍以上。
// 口径必须在服务端统一，否则每个页面都会各写一套。

type usageBucket struct {
	Key          string  `json:"key"` // agent_type / worker / task_id
	Calls        int     `json:"calls"`
	InputTokens  int64   `json:"input_tokens"`
	OutputTokens int64   `json:"output_tokens"`
	CacheRead    int64   `json:"cache_read"`
	CachePct     float64 `json:"cache_pct"`        // cache_read / input_tokens
	FullPrice    int64   `json:"full_price_equiv"` // (input-cache) + cache/10
}

// fullPriceEquiv 把"名义输入 token"折成"全价等价"：缓存命中的部分按 1/10 计。
//
// 系数 0.1 是主流供应商的缓存读价格（Anthropic / OpenAI / DeepSeek 都是这个量级）。
// 它只用于**横向比较**，不是账单——真实金额要看供应商后台。
func fullPriceEquiv(input, cache int64) int64 {
	if cache > input { // 脏数据保护：缓存不可能多于输入
		cache = input
	}
	if cache < 0 {
		cache = 0
	}
	return (input - cache) + cache/10
}

func cachePct(input, cache int64) float64 {
	if input <= 0 {
		return 0
	}
	if cache > input {
		cache = input
	}
	return float64(cache) * 100 / float64(input)
}

// getUsageSummary 返回最近 N 天的用量汇总：总量 + 按 agent_type + 按 worker + 按任务。
func (s *Server) getUsageSummary(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	days := 7
	if v := r.URL.Query().Get("days"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 90 {
			days = n
		}
	}

	query := func(groupExpr string, extraWhere string, limit int) ([]usageBucket, error) {
		sql := `SELECT ` + groupExpr + ` AS k, COUNT(*),
		               COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0), COALESCE(SUM(cache_read),0)
		        FROM llm_usage
		        WHERE ts >= now() - make_interval(days => $1)` + extraWhere + `
		        GROUP BY 1 ORDER BY 3 DESC`
		args := []any{days}
		if limit > 0 {
			sql += ` LIMIT $2`
			args = append(args, limit)
		}
		rows, err := pg.Query(sql, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := []usageBucket{}
		for rows.Next() {
			var b usageBucket
			if err := rows.Scan(&b.Key, &b.Calls, &b.InputTokens, &b.OutputTokens, &b.CacheRead); err != nil {
				return nil, err
			}
			b.CachePct = cachePct(b.InputTokens, b.CacheRead)
			b.FullPrice = fullPriceEquiv(b.InputTokens, b.CacheRead)
			out = append(out, b)
		}
		return out, rows.Err()
	}

	byAgent, err := query(`COALESCE(agent_type,'')`, ``, 0)
	if err != nil {
		writeErr(w, 500, "按角色聚合失败："+err.Error())
		return
	}
	byWorker, err := query(`COALESCE(worker,'')`, ``, 0)
	if err != nil {
		writeErr(w, 500, "按泳道聚合失败："+err.Error())
		return
	}
	byTask, err := query(`COALESCE(task_id,'')`, ` AND task_id IS NOT NULL AND task_id <> ''`, 15)
	if err != nil {
		writeErr(w, 500, "按任务聚合失败："+err.Error())
		return
	}

	// 总量单独算：分组聚合的 sum 相加虽然等价，但空组时容易算出 0/0。
	var total usageBucket
	total.Key = "全部"
	if err := pg.QueryRow(`SELECT COUNT(*), COALESCE(SUM(input_tokens),0),
	       COALESCE(SUM(output_tokens),0), COALESCE(SUM(cache_read),0)
	FROM llm_usage WHERE ts >= now() - make_interval(days => $1)`, days).
		Scan(&total.Calls, &total.InputTokens, &total.OutputTokens, &total.CacheRead); err != nil {
		writeErr(w, 500, "汇总失败："+err.Error())
		return
	}
	total.CachePct = cachePct(total.InputTokens, total.CacheRead)
	total.FullPrice = fullPriceEquiv(total.InputTokens, total.CacheRead)

	writeJSON(w, 200, map[string]any{
		"days":          days,
		"total":         total,
		"by_agent_type": byAgent,
		"by_worker":     byWorker,
		"by_task":       byTask,
	})
}

// 保证 db 包被这个文件使用（pg.Query 返回 *sql.Rows，走的是 db.DB 的嵌入方法）。
var _ = db.KindGoal
