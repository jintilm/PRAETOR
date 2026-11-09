#!/bin/sh
# PRAETOR 守护启动脚本（Linux / macOS / Docker ENTRYPOINT）
#
# 用法：
#   ./start.sh                       前台运行（Ctrl-C 停止）
#   nohup ./start.sh >praetor.log 2>&1 &   后台常驻
#   ./start.sh -addr :9000           额外参数原样透传给 praetor
#
# 它只做一件事：把 praetor 跑起来，进程退出后按退出码决定要不要再拉起。
#
#   0      用户正常停止        → 退出循环
#   75     程序请求重启        → 立刻重跑（页面点了"一键更新"或"回滚"）
#   其他   崩溃                → 退避后重跑（1→2→4…最多 60 秒）
#
# 刻意不在这里做下载、SHA256 校验或换装：那些逻辑在 sh 和 bat 上要写两套，
# 而它们恰恰是最不能出错的一环——一旦换上跑不起来的二进制，本脚本会忠实地
# 反复拉起它，用户只能上机器手工救。所以校验/换装全部留在 Go 里（selfupdate 包），
# 由 praetor 自己在启动时完成，脚本保持傻瓜化。
set -u

cd "$(dirname "$0")" || exit 1

BIN=./praetor
# Windows 的构建产物带 .exe 后缀；Git Bash 下也走这个脚本时别误报「找不到可执行文件」。
if [ ! -x "$BIN" ] && [ -x ./praetor.exe ]; then BIN=./praetor.exe; fi
[ -x "$BIN" ] || { echo "[praetor] 找不到可执行文件 $BIN" >&2; exit 1; }

# 二进制只读 config.json 和进程环境变量，**不读 .env**（.env 是 docker compose
# 的插值文件）。直接跑单二进制时不把 .env 搬进环境，启动日志就会显示
# 「未检测到任何 PRAETOR_* 变量」，而 config.json 又常按容器内端口写、连不上库。
# 这里补齐；调用方已 export 的同名变量优先，不覆盖。
# 只搬运白名单前缀，注释行与任意 shell 代码都不会被 source 执行。
load_dotenv() {
	[ -f .env ] || return 0
	while IFS= read -r line || [ -n "$line" ]; do
		line=$(printf '%s' "$line" | tr -d '\r')
		case "$line" in
			''|'#'*) continue ;;
			PRAETOR_*=*|ANTHROPIC_API_KEY=*|OPENAI_API_KEY=*|POSTGRES_USER=*|POSTGRES_PASSWORD=*|POSTGRES_DB=*) ;;
			*) continue ;;
		esac
		key=${line%%=*}
		[ -n "$key" ] || continue
		printenv "$key" >/dev/null 2>&1 && continue
		export "$key=${line#*=}"
	done < .env
}

load_dotenv

# compose 用 POSTGRES_* + PRAETOR_PG_PORT，二进制要的是一个完整 DSN。
# 仅在没有显式 PRAETOR_PG_DSN 时组装（CI / 手工配置永远优先）。
if [ -z "${PRAETOR_PG_DSN:-}" ] && [ -n "${POSTGRES_PASSWORD:-}" ] &&
   [ "$POSTGRES_PASSWORD" != "change-me-please" ]; then
	PRAETOR_PG_DSN="postgres://${POSTGRES_USER:-praetor}:${POSTGRES_PASSWORD}@127.0.0.1:${PRAETOR_PG_PORT:-55433}/${POSTGRES_DB:-praetor}?sslmode=disable"
	export PRAETOR_PG_DSN
	echo "[praetor] 已从 .env 组装 PRAETOR_PG_DSN → 127.0.0.1:${PRAETOR_PG_PORT:-55433}/${POSTGRES_DB:-praetor}"
fi

RESTART_CODE=75
MAX_DELAY=60

child=0
stopping=0

# 转发停止信号给 praetor 本体。
#
# Docker 下这是必需的：docker stop 只把 SIGTERM 发给 PID 1（也就是本脚本），
# 不会发给子进程。不转发的话 praetor 收不到信号、做不了优雅关闭，10 秒后被 SIGKILL
# 硬杀，正在跑的任务直接断在半路。
forward() {
	stopping=1
	if [ "$child" -ne 0 ]; then
		kill -TERM "$child" 2>/dev/null || true
	fi
}
trap forward INT TERM

delay=1
while :; do
	"$BIN" "$@" &
	child=$!

	# 信号会打断 wait 并让它返回 >128。此时子进程其实还在做优雅关闭，
	# 必须再 wait 一次才能拿到它真正的退出码。
	wait "$child"
	code=$?
	if [ "$code" -gt 128 ]; then
		wait "$child"
		code=$?
	fi
	child=0

	if [ "$stopping" -eq 1 ]; then
		echo "[praetor] 已停止"
		exit 0
	fi

	case "$code" in
		0)
			echo "[praetor] 正常退出"
			exit 0
			;;
		"$RESTART_CODE")
			# 更新/回滚已就绪：重跑后 praetor 会在启动时完成换装（见 selfupdate.Bootstrap）。
			echo "[praetor] 请求重启（应用新版本）…"
			delay=1
			;;
		*)
			echo "[praetor] 异常退出 (code=$code)，${delay}s 后重启" >&2
			sleep "$delay"
			delay=$((delay * 2))
			[ "$delay" -gt "$MAX_DELAY" ] && delay=$MAX_DELAY
			;;
	esac
done
