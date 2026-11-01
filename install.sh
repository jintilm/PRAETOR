#!/usr/bin/env bash
# PRAETOR 安装脚本：① 全部 Docker（从本仓库源码构建镜像）
#                  ② 本地编译运行（本机 Go 编译单二进制）
#
# 两种方式都**只用当前仓库的代码**：不会去 Docker Hub 拉别人的预编译镜像。
# 想改用已发布的镜像，在 .env 里设 PRAETOR_IMAGE=<registry>/<repo>:<tag>。
set -euo pipefail
cd "$(cd "$(dirname "$0")" && pwd)"

info(){ printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok(){   printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m[!]\033[0m %s\n' "$*"; }
die(){  printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
ask(){  local p="$1" d="${2:-}" a; read -rp "$p${d:+ [$d]}: " a; echo "${a:-$d}"; }
rand(){ head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24; }

# ── .env 读写 ───────────────────────────────────
# 用「删旧行 + 追加」而不是 sed 替换：值里可能带 / & | 等字符，
# 走 sed 的替换语法迟早会在某个密码上炸掉。
env_get(){ [ -f .env ] || return 0; grep -E "^$1=" .env | tail -1 | cut -d= -f2- || true; }
env_set(){
  local k="$1" v="$2" tmp
  tmp="$(mktemp)"
  if [ -f .env ]; then grep -vE "^$k=" .env > "$tmp" || true; fi
  printf '%s=%s\n' "$k" "$v" >> "$tmp"
  mv "$tmp" .env
}

# ── compose 调用（按 .env 里的开关决定是否带上 socket 覆盖层）──
COMPOSE_ARGS=(-f docker-compose.yml)
compose(){ docker compose "${COMPOSE_ARGS[@]}" "$@"; }
load_compose_overlays(){
  if [ "$(env_get PRAETOR_MOUNT_DOCKER_SOCKET)" = "1" ]; then
    COMPOSE_ARGS+=(-f docker-compose.socket.yml)
  fi
}

http_port(){ local p; p="$(env_get PRAETOR_HTTP_PORT)"; echo "${p:-8797}"; }

# ── docker 环境检测 / 自动安装 ───────────────────
ensure_docker(){
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    ok "已检测到 docker 与 docker compose"; return
  fi
  warn "未检测到 docker / docker compose"
  case "$(uname -s)" in
    Linux)
      if [ "$(ask '自动安装 Docker? (y/n)' y)" = y ]; then
        curl -fsSL https://get.docker.com | sh
        sudo usermod -aG docker "$USER" || true
        ok "Docker 安装完成（用户组变更需重新登录后免 sudo）"
      else
        die "请自行安装 docker 后重试"
      fi ;;
    Darwin) die "macOS 请安装 Docker Desktop：https://www.docker.com/products/docker-desktop/" ;;
    *)      die "请自行安装 docker 后重试" ;;
  esac
}

# ── ① 全部 Docker ───────────────────────────────
install_docker(){
  ensure_docker
  if [ ! -f .env ]; then
    [ -f .env.example ] || die "缺少 .env.example"
    cp .env.example .env
    local pw key
    pw="$(ask 'Postgres 密码（回车随机生成）' "$(rand)")"
    key="$(ask 'ANTHROPIC_API_KEY（可留空，后续在 UI 配）' '')"
    env_set POSTGRES_PASSWORD "$pw"
    # 用 if 而不是 `[ -n ] && env_set`：后者在 key 为空时返回 1，
    # 配合 set -e 会让脚本静默退出（正是最不该出错的地方）。
    if [ -n "$key" ]; then env_set ANTHROPIC_API_KEY "$key"; fi
    ok "已生成 .env（POSTGRES_PASSWORD 已设置）"
  else
    info "沿用已存在的 .env"
    if [ "$(env_get POSTGRES_PASSWORD)" = "change-me-please" ]; then
      warn ".env 里还是示例密码 change-me-please，建议换成随机值（改完重启生效）"
    fi
  fi

  # 容器里的 PRAETOR 要起沙箱容器，就得能访问宿主 Docker。不挂 socket 时
  # required 模式会把每次 Bash 都拒掉 —— 部署"成功"但一用就报 sandbox unavailable，
  # 这是最难自查的一种失败，所以让用户在这里显式选一次，而不是留个默认值埋雷。
  if [ -z "$(env_get PRAETOR_MOUNT_DOCKER_SOCKET)" ]; then
    echo "沙箱运行方式（agent 的 Bash 默认跑在一任务一容器里）："
    echo "  1) 挂载宿主 docker.sock —— 沙箱能力完整（推荐）"
    echo "     代价：应用容器因此持有宿主 Docker 控制权（≈root）"
    echo "  2) 不挂，沙箱降级 optional —— Bash 跑在应用容器内，用镜像自带工具链"
    case "$(ask '选择' 1)" in
      1)
        env_set PRAETOR_MOUNT_DOCKER_SOCKET 1
        env_set PRAETOR_SANDBOX required
        [ -S /var/run/docker.sock ] || warn "本机没找到 /var/run/docker.sock；Docker Desktop 里它在虚拟机内，容器仍可挂载"
        ;;
      *)
        env_set PRAETOR_MOUNT_DOCKER_SOCKET 0
        env_set PRAETOR_SANDBOX optional
        ;;
    esac
  fi
  load_compose_overlays

  local img; img="$(env_get PRAETOR_IMAGE)"
  if [ -n "$img" ]; then
    info "使用镜像 ${img}（.env 的 PRAETOR_IMAGE）…"
    compose pull praetor || die "拉取 ${img} 失败；确认仓库地址/tag，或清空 PRAETOR_IMAGE 改走源码构建"
  else
    info "从当前仓库源码构建镜像（先编 praetor：装 Go/Node 依赖与 Playwright，约 5~10 分钟；"
    info "随后构建沙箱镜像 praetor/sandbox —— 基于 Kali，装安全工具，时间取决于网络）…"
    # 不带服务名：praetor 与 sandbox 都要构建。沙箱镜像是 per-task 模式的基础
    # （agent 用 `docker run praetor/sandbox:latest` 起容器），缺了它工具调用会失败。
    compose build
  fi
  info "启动…"
  compose up -d
  ok "启动完成 → http://localhost:$(http_port)"
  info "查看日志：docker compose ${COMPOSE_ARGS[*]} logs -f praetor"
}

# ── ② 本地编译运行 ──────────────────────────────
install_local(){
  echo "数据库安装方式："
  echo "  1) 连接已有 PostgreSQL"
  echo "  2) 用 Docker 起一个 PostgreSQL（需要 docker）"
  case "$(ask '选择' 1)" in
    2)
      ensure_docker
      local pw; pw="$(ask 'Postgres 密码（回车随机）' "$(rand)")"
      docker run -d --name praetor-pg -p 5432:5432 \
        -e POSTGRES_USER=praetor -e POSTGRES_PASSWORD="$pw" -e POSTGRES_DB=praetor \
        -v praetor-pg:/var/lib/postgresql/data postgres:16-alpine
      DB_HOST=127.0.0.1 DB_PORT=5432 DB_USER=praetor DB_PASS="$pw" DB_NAME=praetor DB_SSL=disable ;;
    *)
      DB_HOST="$(ask '数据库地址' 127.0.0.1)"
      DB_PORT="$(ask '端口' 5432)"
      DB_USER="$(ask '账号' praetor)"
      DB_PASS="$(ask '密码' '')"
      DB_NAME="$(ask '数据库名' praetor)"
      DB_SSL="$(ask 'sslmode (disable/require)' disable)" ;;
  esac

  # 生成 config.json
  cat > config.json <<JSON
{
  "database": {
    "host": "${DB_HOST}",
    "port": ${DB_PORT},
    "user": "${DB_USER}",
    "password": "${DB_PASS}",
    "dbname": "${DB_NAME}",
    "sslmode": "${DB_SSL}"
  }
}
JSON
  ok "已生成 config.json"

  # go 环境检查
  command -v go >/dev/null 2>&1 || die "未检测到 Go，请先安装 Go（>=1.26）：https://go.dev/dl/"
  ok "Go: $(go version)"

  # 内嵌前端需要 node 出静态产物
  if command -v npm >/dev/null 2>&1; then
    info "构建前端静态产物…"
    ( cd web && npm ci && npm run build:static )
    rm -rf server/webui/dist && cp -r web/out server/webui/dist
    info "编译内嵌单二进制…"
    CGO_ENABLED=0 go build -tags embedui -trimpath -o praetor ./cmd/praetor
  else
    warn "未检测到 npm：将编译**不内嵌前端**的后端（前端需另跑 npm run dev）"
    CGO_ENABLED=0 go build -o praetor ./cmd/praetor
  fi
  ok "编译完成 → ./praetor"

  info "启动…（Ctrl-C 退出）→ http://localhost:8787"
  ./praetor
}

echo "=============================="
echo "  PRAETOR 安装"
echo "  1) 全部 Docker 安装（从本仓库源码构建镜像）"
echo "  2) 本地运行（go 编译）"
echo "=============================="
case "$(ask '选择' 1)" in
  1) install_docker ;;
  2) install_local ;;
  *) die "无效选择" ;;
esac
