#!/usr/bin/env bash
# 测试门禁：跑全量测试，并把**被跳过**的用例数报出来。
#
# 为什么需要它：大量 DB 用例在没配 PRAETOR_PG_DSN 时会 t.Skip，而 `go test ./...`
# 照样打印 `ok`。于是"25 包全绿"看起来像"全都测过了"，实际上一整条数据库路径
# （提交去重、题目看板、任务生命周期…）根本没执行。这个坑真实坑过一次：
# ctf_submissions 的主键缺陷就是在这条被跳过的路径里藏了两周。
#
# 用法：
#   ./scripts/gate.sh              # 有 PRAETOR_PG_DSN 就一直用；没有则报告跳过数
#   ./scripts/gate.sh --db         # 要求必须跑 DB 用例：没 DSN 就推导一个 *_test 库并失败退出
#
# 退出码：0 = 全绿且（--db 时）没有跳过 DB 用例；1 = 有失败或缺 DSN。
set -uo pipefail
cd "$(dirname "$0")/.."

need_db=0
[ "${1:-}" = "--db" ] && need_db=1

# 读 .env 里的库连接（不 source 整个文件，避免把 .env 里的 export 带进当前 shell）
if [ -z "${PRAETOR_PG_DSN:-}" ] && [ -f .env ]; then
  user=$(grep -E '^POSTGRES_USER=' .env | cut -d= -f2-)
  pass=$(grep -E '^POSTGRES_PASSWORD=' .env | cut -d= -f2-)
  db=$(grep -E '^POSTGRES_DB=' .env | cut -d= -f2-)
  if [ -n "${user:-}" ] && [ -n "${pass:-}" ] && [ -n "${db:-}" ]; then
    # 指向 *_test 库：db.Open 会自动建库，且 testpg 只允许在测试库上跑
    export PRAETOR_PG_DSN="postgres://${user}:${pass}@127.0.0.1:55433/${db}_test?sslmode=disable"
    echo "导出门禁 DSN：${db}_test"
  fi
fi

if [ -z "${PRAETOR_PG_DSN:-}" ]; then
  if [ "$need_db" = "1" ]; then
    echo "错误：--db 要求 PRAETOR_PG_DSN（或 .env 里的 POSTGRES_*）可用" >&2
    exit 1
  fi
  echo "注意：没有 PRAETOR_PG_DSN，DB 用例会被跳过（下面会统计跳过数）"
fi

out=$(mktemp)
trap 'rm -f "$out"' EXIT
go test ./... -json -timeout 900s >"$out" 2>&1
status=$?

pass=$(grep -c '"Action":"pass"' "$out" || true)
fail=$(grep -c '"Action":"fail"' "$out" || true)
skip=$(grep -c '"Action":"skip"' "$out" || true)

echo
echo "===== 结果 ====="
echo "通过 $pass / 失败 $fail / 跳过 $skip"

if [ "$fail" != "0" ]; then
  echo
  echo "失败用例："
  grep '"Action":"fail"' "$out" | grep -o '"Test":"[^"]*"' | sort -u | sed 's/"Test":"/  - /; s/"$//'
fi

if [ "$skip" != "0" ]; then
  echo
  echo "被跳过的用例（前 10 个）："
  grep '"Action":"skip"' "$out" | grep -o '"Test":"[^"]*"' | sort -u | head -10 | sed 's/"Test":"/  - /; s/"$//'
fi

# 只有"因缺 DB 配置而跳过"才值得报警 —— 其余跳过各有正当理由（需要平台、需要网络等），
# 一律报错会让 --db 模式变成噪音，最后没人看。
#
# 必须查 **output** 事件而不是 skip 事件：`-json` 下 `{"Action":"skip"}` 那一行只有
# Test/Elapsed，跳过原因是上一行 output 里的 "--- SKIP: x" 之前的 t.Skipf 文案。
# 早期写成 grep '"Action":"skip"' | grep 'database config' 永远匹配不到 ——
# 也就是 --db 模式从来不会失败，这正是这个脚本本身要防的那种"看起来绿"。
# 匹配 t.Skipf 的固定前缀：postgres/database unavailable（覆盖缺配置、连不上、非测试库）。
db_skipped=0
if grep '"Action":"output"' "$out" | grep -qiE 'postgres unavailable|database unavailable|未找到数据库配置|非测试库'; then
  db_skipped=1
fi
if [ "$db_skipped" = "1" ]; then
  echo
  echo "其中包含因缺少数据库配置而跳过的用例：这条路径本次**未被执行**。"
  if [ "$need_db" = "1" ]; then
    echo "错误：--db 模式要求 DB 用例真的跑起来（检查 PRAETOR_PG_DSN 是否指向可连的 *_test 库）" >&2
    exit 1
  fi
  echo "要真正覆盖它：./scripts/gate.sh --db"
fi

exit $status
