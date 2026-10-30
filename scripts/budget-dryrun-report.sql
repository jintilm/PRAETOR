-- 预算闸门 dry-run 报告：回答「如果当时是硬闸，会误杀多少」。
--
-- 背景：pentest（explore）域现在是 dry-run（只告警、不停止），ctf/reverse/redteam 是硬闸。
-- 要决定「pentest 能不能翻硬闸」，需要的不是感觉，而是：历史上哪些任务在越过阈值之后
-- **仍然产出了价值**（新 finding / 已 done）。那类任务就是硬闸的误杀样本。
--
-- 用法：
--   docker exec -i praetor-pg psql -U praetor -d praetor < scripts/budget-dryrun-report.sql
--   或本机 psql "$PRAETOR_PG_DSN" -f scripts/budget-dryrun-report.sql
--
-- 阈值改下面 th 里的 3000000（与 domain.Budget.MaxTokens 一致）。
-- 只统计 task_id 是纯数字的用量行（聊天/旁问等没有任务号的行不参与）。

\pset pager off

DROP VIEW IF EXISTS budget_breaches;

CREATE TEMP VIEW budget_breaches AS
WITH th AS (
    SELECT 3000000::bigint AS t
),
ranked AS (
    -- 按 ts 累加，得到每条用量之后该任务的累计输入 token。
    SELECT u.task_id::bigint AS tid,
           u.ts,
           sum(u.input_tokens) OVER (PARTITION BY u.task_id ORDER BY u.ts, u.id) AS cum
    FROM llm_usage u
    WHERE u.task_id ~ '^[0-9]+$'
),
breach AS (
    -- 首次越过阈值的时刻。用 min(ts) 而不是「最后一次」：硬闸是在那一刻开枪的。
    SELECT r.tid, min(r.ts) AS breach_at
    FROM ranked r, th
    WHERE r.cum >= th.t
    GROUP BY r.tid
)
SELECT b.tid AS task_id,
       t.domain,
       CASE WHEN t.domain IN ('ctf', 'reverse', 'redteam') THEN 'hard' ELSE 'dry-run' END AS gate,
       (SELECT sum(input_tokens) FROM llm_usage WHERE task_id = b.tid::text) AS total_in,
       b.breach_at,
       (SELECT count(*) FROM findings f
         WHERE f.task_id = b.tid AND f.created_at > b.breach_at) AS findings_after,
       (SELECT count(*) FROM exploration_nodes n
         WHERE n.exploration_id = t.exploration_id
           AND n.kind = 'fact' AND n.created_at > b.breach_at) AS facts_after,
       t.status,
       t.completed_at,
       CASE
           WHEN (SELECT count(*) FROM findings f
                  WHERE f.task_id = b.tid AND f.created_at > b.breach_at) > 0
                OR (t.status = 'done' AND t.completed_at IS NOT NULL AND t.completed_at > b.breach_at)
           THEN 'WOULD_KILL_VALUE'
           ELSE '-'
       END AS verdict
FROM breach b
JOIN tasks t ON t.id = b.tid;

\echo ''
\echo '=== 1) 明细：越过阈值的任务（按总量降序）==='
SELECT task_id, domain, gate, total_in,
       to_char(breach_at, 'MM-DD HH24:MI') AS breach_at,
       findings_after, facts_after, status, verdict
FROM budget_breaches
ORDER BY total_in DESC;

\echo ''
\echo '=== 2) 汇总：按域看误杀率（verdict = 越限后仍产出价值）==='
SELECT domain, gate,
       count(*) AS tasks_over,
       count(*) FILTER (WHERE verdict = 'WOULD_KILL_VALUE') AS would_kill_value,
       round(100.0 * count(*) FILTER (WHERE verdict = 'WOULD_KILL_VALUE') / count(*), 1) AS kill_pct
FROM budget_breaches
GROUP BY 1, 2
ORDER BY 3 DESC;

\echo ''
\echo '=== 3) 结论提示 ==='
\echo 'pentest 的 kill_pct 就是「翻硬闸后的误杀率」。<5% 才可以翻（见 docs §7）。'
\echo 'hard 行是既有硬闸的真实误杀记录 —— 非 0 说明硬闸现在就在杀有价值的任务。'

DROP VIEW IF EXISTS budget_breaches;
