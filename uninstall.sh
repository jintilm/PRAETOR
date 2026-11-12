#!/usr/bin/env bash
# PRAETOR 卸载 / 清理脚本（与 install.sh / update.sh 配套）
#
# 设计原则，按重要性排序：
#   1. 默认只停服务，不删任何数据；任何「删」都必须显式选档 + 二次确认。
#   2. 删之前先备份：本地状态移进备份目录，Postgres 额外做一次 pg_dump。
#   3. 本地文件一律 mv 到 backups/uninstall-*/removed/ 而不是 rm —— 全部可回滚。
#   4. 只碰本栈资源：compose 项目 praetor、praetor-task-* 任务容器、
#      praetor-pgdata / praetor-pg 卷、praetor/praetor:* 与 praetor/sandbox:* 镜像。
#      绝不执行 docker system/image/volume prune 或任何通配删除。
#   5. 靶场网络、docker:27-cli 构建镜像、.workbuddy/、docs/、skills/ 不属于安装产物，
#      脚本只提示、不碰。其它 compose 项目一律不碰。
#
# 用法：
#   ./uninstall.sh                    交互菜单（默认「仅停止服务」）
#   ./uninstall.sh --dry-run          只打印将要执行的操作，不做任何改动
#   ./uninstall.sh --mode=N           非交互选档 1/2/3/4（选 3 仍需 stdin 输入 DELETE）
#   ./uninstall.sh --backup-dir=DIR   指定备份根目录（默认 ./backups）
#   ./uninstall.sh --help             帮助
#
# 注意：脚本不会 kill 宿主机上的 praetor / praetor.exe 进程（避免误杀同名进程），
# 本地二进制部署请自行停止 ./start.sh 或对应进程。
set -euo pipefail
cd "$(cd "$(dirname "$0")" && pwd)"

info(){ printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok(){   printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m[!]\033[0m %s\n' "$*"; }
die(){  printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
bold(){ printf '\033[1;31m%s\033[0m\n' "$*"; }
ask(){  local p="$1" d="${2:-}" a; read -rp "$p${d:+ [$d]}: " a || a=""; echo "${a:-$d}"; }

# .env 读写沿用 install.sh 的口径：只看最后一条同名 key，不做 sed 替换。
env_get(){ [ -f .env ] || return 0; grep -E "^$1=" .env | tail -1 | cut -d= -f2- || true; }

COMPOSE_ARGS=(-f docker-compose.yml)
OVERLAYS_LOADED=0
load_compose_overlays(){
  if [ "$OVERLAYS_LOADED" -eq 1 ]; then return 0; fi
  if [ "$(env_get PRAETOR_MOUNT_DOCKER_SOCKET)" = "1" ]; then
    COMPOSE_ARGS+=(-f docker-compose.socket.yml)
  fi
  OVERLAYS_LOADED=1
}
compose(){ docker compose "${COMPOSE_ARGS[@]}" "$@"; }
docker_ok(){
  command -v docker >/dev/null 2>&1 \
    && docker compose version >/dev/null 2>&1 \
    && docker info >/dev/null 2>&1
}

DRY_RUN=0
MODE=""
BACKUP_ROOT="${PRAETOR_UNINSTALL_BACKUP_DIR:-$PWD/backups}"
BACKUP_DIR=""
MANIFEST_ITEMS=()
DOCKER_SKIPPED=0
note(){ MANIFEST_ITEMS+=("$1"); }

usage(){
  cat <<'EOF'
PRAETOR 卸载 / 清理

  ./uninstall.sh                    交互菜单（默认档：仅停止服务，保留全部数据）
  ./uninstall.sh --dry-run          只打印将要执行的操作，不做任何改动
  ./uninstall.sh --mode=N           非交互选档 1/2/3/4（选 3 仍需 stdin 输入 DELETE）
  ./uninstall.sh --backup-dir=DIR   指定备份根目录（默认 ./backups）
  ./uninstall.sh --help             本帮助

档位：
  1  仅停止服务          compose down，数据卷 / .env / config.json / data 全部保留
  2  停止 + 清构建产物    归档可重建的二进制、前端产物、升级暂存件；数据仍保留
  3  彻底卸载            先备份 + pg_dump，再 down -v 删卷、删本栈镜像、归档本地状态
  4  仅备份              复制 .env/config.json/jwt.key/data/logs + pg_dump，不删任何东西
  0  取消

环境变量：
  PRAETOR_UNINSTALL_BACKUP_DIR   备份根目录（等价于 --backup-dir）
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run)        DRY_RUN=1 ;;
    --mode=*)         MODE="${1#*=}" ;;
    --backup-dir=*)   BACKUP_ROOT="${1#*=}" ;;
    -h|--help)        usage; exit 0 ;;
    *)                die "未知参数：$1（见 --help）" ;;
  esac
  shift
done

# 本地状态：含密码 / JWT 密钥 / 任务工作区。模式 3 会归档，模式 4 会复制。
STATE_PATHS=(.env config.json jwt.key scheduler_state.json data logs)
# 可重建的构建产物：删掉不影响数据，重新 ./install.sh 或 npm ci 即可生成。
BUILD_PATHS=(
  praetor praetor.exe praetor.exe~ bench.exe ctftarget.exe
  praetor.new praetor.new.sha256 praetor.old praetor.failed praetor.upgrade.json
  server/webui/dist web/out web/.next web/node_modules dist
)
# 只有这两个卷属于本部署：compose 用 praetor-pgdata，本地模式让 Docker 起 PG 时用 praetor-pg。
DOCKER_VOLUMES=(praetor-pgdata praetor-pg)

# 路径全部硬编码为项目内相对路径；这里再兜一层，防止以后改清单时引入 ../ 或绝对路径。
assert_safe_rel(){
  case "$1" in
    ""|/*|..|../*|*/../*|*/..) die "拒绝不安全的相对路径：$1" ;;
  esac
}
# Git Bash / MSYS 会把「无扩展名」路径自动解析到同名 .exe（stat/open 自动补后缀）：
# Windows 上只有一个 praetor.exe 时，`[ -e praetor ]` 也会返回真。若照此归档，主程序
# 会被改名成 removed/praetor 丢掉 .exe，恢复后根本跑不起来。所以这里不用 test -e，
# 改为枚举真实目录项做字符串比对 —— 纯 shell，不依赖 GNU find 的 -maxdepth。
path_exists_exact(){
  local p="$1" dir base f
  dir="$(dirname "$p")"; base="$(basename "$p")"
  [ -d "$dir" ] || return 1
  for f in "$dir"/* "$dir"/.[!.]* "$dir"/..?*; do
    [ -e "$f" ] || [ -L "$f" ] || continue
    if [ "$(basename "$f")" = "$base" ]; then return 0; fi
  done
  return 1
}
existing_paths(){
  local p
  for p in "$@"; do
    assert_safe_rel "$p"
    if path_exists_exact "$p"; then printf '%s\n' "$p"; fi
  done
}

# 所有有副作用的命令都经过 run：--dry-run 时只回显，绝不执行。
run(){
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '\033[35m[dry]\033[0m'
    printf ' %q' "$@"
    printf '\n'
    return 0
  fi
  "$@"
}

# 只计算路径，不落盘 —— 档位 3 在 DELETE 确认之前调用它，取消时零改动。
new_backup_dir(){
  BACKUP_DIR="$BACKUP_ROOT/uninstall-$(date +%Y%m%d-%H%M%S)-$$"
  info "备份目录：$BACKUP_DIR"
}
ensure_backup_dir(){
  if [ "$DRY_RUN" -eq 1 ]; then return 0; fi
  mkdir -p "$BACKUP_DIR"
  chmod 700 "$BACKUP_DIR" 2>/dev/null || true   # 里面会放 .env 与 jwt.key
}

write_manifest(){
  if [ "$DRY_RUN" -eq 1 ]; then info "[dry-run] 将写入 MANIFEST.txt"; return 0; fi
  {
    echo "# PRAETOR 卸载备份"
    echo "生成时间 : $(date '+%Y-%m-%d %H:%M:%S %z')"
    echo "项目根   : $PWD"
    echo "档位     : $MODE"
    echo "备份目录 : $BACKUP_DIR"
    echo
    echo "## 内容"
    local l
    if [ "${#MANIFEST_ITEMS[@]}" -eq 0 ]; then
      echo "  (无)"
    else
      for l in "${MANIFEST_ITEMS[@]}"; do echo "  - $l"; done
    fi
    echo
    echo "## 恢复本地文件"
    echo "  removed/ 下按原相对路径存放，逐项移回项目根即可，例如："
    echo "    mv \"$BACKUP_DIR/removed/.env\" \"$PWD/.env\""
    echo "    mv \"$BACKUP_DIR/removed/data\" \"$PWD/data\""
    echo "  state/ 下是「仅备份」档的副本（原件未动），按需 cp -a 覆盖回去。"
    echo
    echo "## 恢复数据库（praetor-pg.sql，仅当 pg_dump 成功时存在）"
    echo "  docker compose up -d postgres"
    echo "  docker exec -i praetor-pg psql -U ${POSTGRES_USER_LABEL:-praetor} -d ${POSTGRES_DB_LABEL:-praetor} < \"$BACKUP_DIR/praetor-pg.sql\""
    echo
    echo "## 未清理（需手动决定）"
    echo "  靶场网络 praetor-ctf / chal-*、docker:27-cli 构建镜像、.workbuddy/、docs/、skills/、"
    echo "  .tok / .playwright-mcp/ 等本地调试产物，以及宿主机上可能仍在运行的 praetor 进程。"
  } > "$BACKUP_DIR/MANIFEST.txt"
  chmod 600 "$BACKUP_DIR/MANIFEST.txt" 2>/dev/null || true
  ok "清单已写入 $BACKUP_DIR/MANIFEST.txt"
}

# 仅备份档：复制，原件保留。
copy_state(){
  local p
  for p in "${STATE_PATHS[@]}"; do
    assert_safe_rel "$p"
    if path_exists_exact "$p"; then
      run mkdir -p "$(dirname "$BACKUP_DIR/state/$p")"
      run cp -a -- "$p" "$BACKUP_DIR/state/$p"
      note "state/$p  (复制，原件保留)"
      ok "已复制 $p"
    fi
  done
}

# 归档 = 移动，不是删除；目录结构与原相对路径一致，随时可 mv 回来。
archive_paths(){
  local p target
  for p in "$@"; do
    assert_safe_rel "$p"
    if path_exists_exact "$p"; then
      target="$BACKUP_DIR/removed/$p"
      run mkdir -p "$(dirname "$target")"
      run mv -- "$p" "$target"
      note "removed/$p  (从项目根移出，可原样移回)"
      ok "已归档 $p"
    fi
  done
}

# pg_dump 必须在 down -v 之前、且 .env 尚未被归档时执行。
dump_database(){
  POSTGRES_USER_LABEL="$(env_get POSTGRES_USER)"; POSTGRES_USER_LABEL="${POSTGRES_USER_LABEL:-praetor}"
  POSTGRES_DB_LABEL="$(env_get POSTGRES_DB)";   POSTGRES_DB_LABEL="${POSTGRES_DB_LABEL:-praetor}"
  local out="$BACKUP_DIR/praetor-pg.sql"
  if [ "$DRY_RUN" -eq 1 ]; then
    info "[dry-run] pg_dump -U $POSTGRES_USER_LABEL -d $POSTGRES_DB_LABEL → $out"
    return 0
  fi
  if ! docker_ok; then warn "Docker 不可用，无法导出数据库"; return 1; fi
  local names
  names="$(docker ps --format '{{.Names}}' 2>/dev/null || true)"
  if ! printf '%s\n' "$names" | grep -qx 'praetor-pg'; then
    warn "容器 praetor-pg 未运行，无法导出数据库"
    return 1
  fi
  if docker exec praetor-pg pg_dump --clean --if-exists \
        -U "$POSTGRES_USER_LABEL" -d "$POSTGRES_DB_LABEL" \
        > "$out" 2> "$BACKUP_DIR/pg_dump.err" && [ -s "$out" ]; then
    rm -f "$BACKUP_DIR/pg_dump.err"
    note "praetor-pg.sql  (pg_dump --clean --if-exists, $(wc -c < "$out") bytes)"
    ok "数据库已导出 → $out"
    return 0
  fi
  warn "pg_dump 失败或输出为空（见 $BACKUP_DIR/pg_dump.err）"
  return 1
}

stop_stack(){
  if ! docker_ok; then
    warn "Docker 不可用（守护进程未运行？）：跳过容器停止"
    return 1
  fi
  load_compose_overlays
  info "停止 compose 项目 praetor（保留数据卷）…"
  run compose down --remove-orphans || warn "compose down 未能完成，请手动检查容器状态"
  return 0
}

purge_docker(){
  if ! docker_ok; then
    warn "Docker 不可用：容器 / 卷 / 镜像未清理，需启动 Docker 后手动处理"
    DOCKER_SKIPPED=1
    return 0
  fi
  load_compose_overlays

  # 一任务一容器留下的孤儿：只认 praetor.task 标签且名字以 praetor-task- 开头。
  local names n
  names="$(docker ps -a --filter label=praetor.task --format '{{.Names}}' 2>/dev/null || true)"
  if [ -n "$names" ]; then
    while IFS= read -r n; do
      if [ -z "$n" ]; then continue; fi
      case "$n" in
        praetor-task-*)
          run docker rm -f "$n" || warn "删除任务容器 $n 失败"
          note "docker 容器 $n  (已删除)"
          ok "已删除任务容器 $n" ;;
        *) warn "跳过带同标签但不属于本栈命名规范的容器：$n" ;;
      esac
    done <<< "$names"
  fi

  # down -v 只删本 compose 项目声明的卷（praetor-pgdata）；--rmi 故意不用，
  # 镜像在下面按精确前缀枚举后逐个删除，避免波及其它项目的镜像。
  info "删除本栈容器 / 网络 / 数据卷…"
  run compose down -v --remove-orphans || warn "compose down -v 未能完成，请手动检查"

  local v
  for v in "${DOCKER_VOLUMES[@]}"; do
    if docker volume inspect "$v" >/dev/null 2>&1; then
      run docker volume rm "$v" || warn "删除卷 $v 失败（可能被其它容器占用）"
      note "docker 卷 $v  (已删除，不可恢复，靠 pg_dump 兜底)"
      ok "已删除卷 $v"
    fi
  done

  local imgs img
  imgs="$(docker images --format '{{.Repository}}:{{.Tag}}' \
          | grep -E '^praetor/(praetor|sandbox):' || true)"
  if [ -n "$imgs" ]; then
    while IFS= read -r img; do
      if [ -z "$img" ]; then continue; fi
      run docker image rm "$img" || warn "删除镜像 $img 失败（可能被其它容器引用）"
      note "docker 镜像 $img  (已删除，可用 compose build 重建)"
      ok "已删除镜像 $img"
    done <<< "$imgs"
  fi
}

local_process_notice(){
  info "若你在宿主机用 ./start.sh / praetor.exe 跑二进制，请自行停止该进程 —— 脚本不会 kill 进程，避免误杀。"
}

# ── 档位实现 ─────────────────────────────────────
stop_only(){
  if stop_stack; then
    ok "已停止服务：数据卷、.env、config.json、data/、日志全部保留"
  else
    warn "Docker 资源未被停止；若本机跑的是宿主机二进制部署，可忽略这条"
  fi
  ok "恢复：docker compose up -d（或 ./install.sh / ./start.sh）"
  local_process_notice
}

clean_build(){
  new_backup_dir
  ensure_backup_dir
  info "将归档以下构建产物（可重建、可回滚）："
  existing_paths "${BUILD_PATHS[@]}" | sed 's/^/    /'
  stop_stack || true
  archive_paths "${BUILD_PATHS[@]}"
  write_manifest
  ok "构建产物已归档到 $BACKUP_DIR/removed/；数据未动"
  ok "重建：./update.sh（本地）或 docker compose build（Docker）"
  local_process_notice
}

preview_full(){
  bold "⚠️ 此操作非常危险，可能导致不可逆的数据丢失！"
  echo "即将执行："
  echo "  · 停止并删除 compose 项目 praetor 的容器与网络"
  echo "  · 删除数据卷 praetor-pgdata / praetor-pg —— 任务、发现、配置、CTF 记录全部清空"
  echo "    （会先尝试 pg_dump 导出到备份目录；导出失败需再单独确认）"
  echo "  · 删除镜像 praetor/praetor:* 与 praetor/sandbox:*"
  echo "  · 归档以下本地文件到 $BACKUP_DIR/removed/（移动，可原样移回）："
  existing_paths "${STATE_PATHS[@]}" "${BUILD_PATHS[@]}" | sed 's/^/      /'
  echo "  · 不碰：靶场网络(praetor-ctf / chal-*)、docker:27-cli 构建镜像、"
  echo "          .workbuddy/、docs/、skills/、其它 compose 项目"
  echo
}

full_uninstall(){
  new_backup_dir
  preview_full
  if [ "$(ask '输入 DELETE 确认彻底卸载（其它任意输入取消）' '')" != "DELETE" ]; then
    die "已取消，未做任何改动"
  fi
  ensure_backup_dir

  local db_status=0
  dump_database || db_status=1
  if [ "$db_status" -ne 0 ] && [ "$DRY_RUN" -eq 0 ]; then
    warn "数据库未能导出：继续执行将永久丢失 Postgres 卷内的数据。"
    if [ "$(ask '输入 I-UNDERSTAND 继续，或回车取消' '')" != "I-UNDERSTAND" ]; then
      die "已取消；已完成的备份仍保留在 $BACKUP_DIR"
    fi
  fi

  # 顺序要紧：compose down -v 需要 .env 里的 POSTGRES_PASSWORD（compose 用 :? 校验），
  # 所以必须在归档 .env 之前完成所有 docker 操作。
  purge_docker
  archive_paths "${STATE_PATHS[@]}" "${BUILD_PATHS[@]}"
  write_manifest

  ok "彻底卸载完成。备份与归档：$BACKUP_DIR"
  if [ "$DOCKER_SKIPPED" -eq 1 ]; then
    warn "本地文件已归档，但 Docker 容器 / 卷 / 镜像未清理（守护进程不可用）；启动 Docker 后可重跑档位 3"
  fi
  ok "恢复：把 removed/ 下文件按原路径移回，再执行 ./install.sh（数据库用 MANIFEST.txt 里的命令导入）"
  local_process_notice
}

backup_only(){
  new_backup_dir
  ensure_backup_dir
  copy_state
  dump_database || warn "数据库未导出（文件备份不受影响；卷仍在，数据没丢）"
  write_manifest
  ok "备份完成：$BACKUP_DIR（未删除或移动任何文件）"
}

# ── 入口 ─────────────────────────────────────────
[ -f docker-compose.yml ] || die "请在项目根目录运行（未找到 docker-compose.yml）"
# 在 .env 还在时解析覆盖层；模式 3 归档 .env 之后仍要用这份 COMPOSE_ARGS。
load_compose_overlays

if [ -z "$MODE" ]; then
  echo "=============================="
  echo "  PRAETOR 卸载 / 清理"
  echo "  1) 仅停止服务（保留全部数据，默认）"
  echo "  2) 停止 + 清理构建产物（数据保留）"
  echo "  3) 彻底卸载（先备份 + 二次确认，删数据卷）"
  echo "  4) 仅备份（不删任何东西）"
  echo "  0) 取消"
  echo "=============================="
  MODE="$(ask '选择' 1)"
fi

case "$MODE" in
  1) stop_only ;;
  2) clean_build ;;
  3) full_uninstall ;;
  4) backup_only ;;
  0|cancel) ok "已取消，未做任何改动" ;;
  *) die "无效选择：$MODE（见 --help）" ;;
esac
