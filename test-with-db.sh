#!/usr/bin/env bash
# 用独立的测试 PostgreSQL 跑全量测试，全程不触碰主栈（docker-compose.yml）。
#
#   ./test-with-db.sh                 # 起库 → 跑全部 → 拆库（默认）
#   ./test-with-db.sh ./agent/...     # 只跑指定包
#   KEEP_DB=1 ./test-with-db.sh       # 跑完保留容器，方便连续调试
#   PRAETOR_TEST_PG_PORT=55433 ./test-with-db.sh   # 端口被占时换一个
#
# 隔离说明见 docker-compose.test.yml。
set -euo pipefail
cd "$(dirname "$0")"

PORT="${PRAETOR_TEST_PG_PORT:-55432}"
PROJECT=praetor-test
COMPOSE=(docker compose -f docker-compose.test.yml -p "$PROJECT")

export PRAETOR_PG_DSN="postgres://praetor:praetorpw@127.0.0.1:${PORT}/praetor_test?sslmode=disable"

cleanup() {
  if [ "${KEEP_DB:-0}" = "1" ]; then
    echo "==> KEEP_DB=1：保留测试库（${PORT}），手动清理：docker compose -f docker-compose.test.yml -p ${PROJECT} down -v"
    return
  fi
  echo "==> 拆除测试库"
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> 启动独立测试库：项目 ${PROJECT} / 宿主端口 ${PORT} / 库 praetor_test"
if ! "${COMPOSE[@]}" up -d --wait; then
  echo "!! 启动失败。若端口 ${PORT} 被占用，换一个：PRAETOR_TEST_PG_PORT=55433 $0" >&2
  echo "!! 若 Docker 守护进程未运行，请先启动 Docker Desktop（不会影响已有容器）。" >&2
  exit 1
fi

echo "==> PRAETOR_PG_DSN=${PRAETOR_PG_DSN}"
echo "==> go test"
# -p 1：串行跑包。这五个包（agent/db/evidence/llmrec/server）共用一个测试库且都会清理
# 自己写的数据，并行跑会互相踩（表现为「每次失败的用例都不一样、单包跑全过」）。
# 它们各自有 advisory lock，但 ping 偶发超时会让某个包没拿锁就跑，所以用 -p 1 兜死。
go test -p 1 ./... -count=1 "$@"
