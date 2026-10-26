#!/usr/bin/env bash
# 开发模式：后端(:8797) + 流量代理(:8798) 与 前端 next dev(:5173) 一起跑。
# 前端 /api 反代到后端；Ctrl-C 一并退出。
#
# 端口刻意用 8797/8798（不是 8787/8788），避免和同机旧 ARTEX 栈抢端口。
# 单二进制（前端内嵌）方式见 README「单二进制」一节，不走这个脚本。
set -euo pipefail
cd "$(dirname "$0")"

# 读 .env（POSTGRES_PASSWORD / PRAETOR_* 等）。没有 .env 也能跑，只是数据库得靠外部环境变量。
if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

# 组装本项目自己的数据库 DSN：指向 praetor-pg（宿主 55433），与旧 ARTEX 的 5432 无关。
# 已显式设置 PRAETOR_PG_DSN 时不覆盖。
if [ -z "${PRAETOR_PG_DSN:-}" ] && [ -n "${POSTGRES_PASSWORD:-}" ]; then
  PRAETOR_PG_DSN="postgres://${POSTGRES_USER:-praetor}:${POSTGRES_PASSWORD}@127.0.0.1:${PRAETOR_PG_PORT:-55433}/${POSTGRES_DB:-praetor}?sslmode=disable"
  export PRAETOR_PG_DSN
fi

# 退出时结束本进程组内的所有子进程（后端 + 前端）。
cleanup() { kill 0 2>/dev/null || true; }
trap cleanup EXIT INT TERM

# 后端（普通 go run，不内嵌前端）；并发 work agent 数在「系统设置」里配置。
go run ./cmd/praetor -addr :8797 -proxy 127.0.0.1:8798 &

# 前端热更新（Vite/Next dev server，/api 反代到 :8797）。
( cd web && npm run dev ) &

echo "[dev] 后端 :8797 / 代理 :8798 / 前端 http://localhost:5173"
echo "[dev] DB: ${PRAETOR_PG_DSN:-<未配置>}"
wait
