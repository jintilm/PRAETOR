#!/usr/bin/env bash
# PRAETOR 更新脚本：① Docker 更新（按当前代码重建镜像 / 或拉取指定镜像）
#                  ② 本地编译更新（重建二进制）
# 与 install.sh 对应：install 负责首次落地，update 负责升级到新版本。
# DB 迁移无需手动执行——praetor 每次启动都会幂等重跑 schema.sql（含 ADD COLUMN/CREATE
# INDEX IF NOT EXISTS），所以“重启即迁移”。数据（pgdata 卷、./data、./skills）不受影响。
set -euo pipefail
cd "$(cd "$(dirname "$0")" && pwd)"

info(){ printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok(){   printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m[!]\033[0m %s\n' "$*"; }
die(){  printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
ask(){  local p="$1" d="${2:-}" a; read -rp "$p${d:+ [$d]}: " a; echo "${a:-$d}"; }

# .env 读写：删旧行 + 追加，避免值里的 | & / 破坏 sed 表达式
env_get(){ [ -f .env ] || return 0; grep -E "^$1=" .env | tail -1 | cut -d= -f2- || true; }
env_set(){
  local k="$1" v="$2" tmp
  tmp="$(mktemp)"
  if [ -f .env ]; then grep -vE "^$k=" .env > "$tmp" || true; fi
  printf '%s=%s\n' "$k" "$v" >> "$tmp"
  mv "$tmp" .env
}

COMPOSE_ARGS=(-f docker-compose.yml)
compose(){ docker compose "${COMPOSE_ARGS[@]}" "$@"; }
load_compose_overlays(){
  if [ "$(env_get PRAETOR_MOUNT_DOCKER_SOCKET)" = "1" ]; then
    COMPOSE_ARGS+=(-f docker-compose.socket.yml)
  fi
}
http_port(){ local p; p="$(env_get PRAETOR_HTTP_PORT)"; echo "${p:-8797}"; }

# ── 可选：同步仓库到最新代码（compose/脚本/本地编译源码都靠它更新）───────
sync_repo(){
  # 所有"跳过"分支都要 return 0：`return` 不带参数会继承上一条失败命令的退出码，
  # 在 set -e 下等于"用户答 n 就整个脚本退出"（这是原实现的隐雷，2026-11-01 桩测得现）。
  [ -d .git ] && command -v git >/dev/null 2>&1 || { warn "非 git 工作副本，跳过 git pull"; return 0; }
  [ "$(ask '拉取最新代码 (git pull --ff-only)? (y/n)' y)" = y ] || return 0
  if ! git pull --ff-only; then
    warn "git pull 未能快进（本地有改动或分支分叉）——请手动处理后重试，本次沿用当前代码"
  fi
  return 0
}

# ── ① Docker 更新 ───────────────────────────────
update_docker(){
  command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1 \
    || die "未检测到 docker / docker compose，请先用 ./install.sh 安装部署"
  [ -f .env ] || die "未找到 .env，请先运行 ./install.sh 完成首次部署"
  load_compose_overlays

  local img; img="$(env_get PRAETOR_IMAGE)"

  if [ -n "$img" ]; then
    # 用外部镜像：只换 tag，不构建。
    local tag; tag="$(ask "目标镜像 tag（当前 ${img}，回车不改）" '')"
    if [ -n "$tag" ]; then
      # 去掉旧 tag 再拼新的。只在「最后一个 / 之后」出现 ':' 时才算 tag ——
      # 否则会把 registry 的端口当 tag 切掉（ghcr.io:5000/praetor → ghcr.io）。
      local last="${img##*/}" repo="$img"
      if [ "${last##*:}" != "$last" ]; then repo="${img%:*}"; fi
      env_set PRAETOR_IMAGE "${repo}:${tag}"
      img="$(env_get PRAETOR_IMAGE)"
      ok "已改为 ${img}"
    fi
    # 只动 praetor：postgres 是固定的 16-alpine，不需要跟着升级（拉它纯属浪费带宽，
    # 且大版本变动还会有兼容风险）。praetor 声明了 depends_on postgres，所以带服务名
    # up 时若 pg 没起会自动拉起，已在跑的则原样保留、不重建。
    info "拉取镜像 ${img} …"
    compose pull praetor
  else
    # 源码构建：`git pull` 之后重建即可，镜像里就是当前代码。
    # PRAETOR_TAG 只决定打什么 tag（.env.example 默认 latest），与拉取无关。
    local tag; tag="$(ask '构建出的镜像 tag（回车沿用 .env 的 PRAETOR_TAG）' '')"
    if [ -n "$tag" ]; then
      env_set PRAETOR_TAG "$tag"
      ok "已将 PRAETOR_TAG 设为 ${tag}"
    fi
    info "按当前代码重建镜像（改了前端/后端才会真正重编，其余走层缓存）…"
    compose build --pull praetor
  fi

  info "重建并启动（praetor 重启时自动迁移 schema）…"
  compose up -d praetor
  ok "更新完成 → http://localhost:$(http_port)"
  info "查看日志：docker compose ${COMPOSE_ARGS[*]} logs -f praetor"
  info "清理旧镜像（可选）：docker image prune -f"
}

# ── ② 本地编译更新 ──────────────────────────────
update_local(){
  command -v go >/dev/null 2>&1 || die "未检测到 Go（>=1.26）：https://go.dev/dl/"
  [ -f config.json ] || warn "未找到 config.json——若首次部署请改用 ./install.sh"
  ok "Go: $(go version)"

  if command -v npm >/dev/null 2>&1; then
    info "重建前端静态产物…"
    ( cd web && npm ci && npm run build:static )
    rm -rf server/webui/dist && cp -r web/out server/webui/dist
    info "重新编译内嵌单二进制…"
    CGO_ENABLED=0 go build -tags embedui -trimpath -o praetor ./cmd/praetor
  else
    warn "未检测到 npm：编译**不内嵌前端**的后端（前端需另跑 npm run dev）"
    CGO_ENABLED=0 go build -o praetor ./cmd/praetor
  fi
  ok "编译完成 → ./praetor"
  warn "请重启正在运行的 praetor 进程以生效（重启时会自动迁移 schema）"
}

echo "=============================="
echo "  PRAETOR 更新"
echo "  1) Docker 更新（按当前代码重建镜像；设了 PRAETOR_IMAGE 则改为拉取）"
echo "  2) 本地更新（go 重新编译）"
echo "=============================="
case "$(ask '选择' 1)" in
  1) sync_repo; update_docker ;;
  2) sync_repo; update_local ;;
  *) die "无效选择" ;;
esac
