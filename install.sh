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
# warn 必须走 stderr：read_db_password 在 $(...) 里调用，往 stdout 打的任何东西
# 都会被当成"密码"捕获并写进 .env（曾把警告文本整个塞进 POSTGRES_PASSWORD）。
warn(){ printf '\033[33m[!]\033[0m %s\n' "$*" >&2; }
die(){  printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
# stdin 关闭（CI / 管道）时 read 会返回非 0，配合 set -e 会让脚本静默退出；
# 这里让用户直接落到默认值，而不是半夜莫名中断。
ask(){  local p="$1" d="${2:-}" a; read -rp "$p${d:+ [$d]}: " a || a=""; echo "${a:-$d}"; }
# 32 字节 → base64 约 44 字符，剔除 +/ 后仍稳够 24，避免 18 字节时偶尔只出 22 位。
rand(){ head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24; }

# ── 端口 / 版本探测（只读，不改任何状态）─────────
# 用 bash 内建 /dev/tcp 探测，不依赖 nc / ss / lsof ——
# Windows Git Bash、macOS、Linux 都有，开箱即用。
port_in_use(){ (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
# 从给定端口向上找空闲端口；找满 20 个就原样返回，把决定权交回给用户。
# 只探测、绝不 bind、绝不 kill，不会影响任何已有服务。
pick_free_port(){
  local p="$1" n=0
  while [ "$n" -lt 20 ] && port_in_use "$p"; do p=$((p+1)); n=$((n+1)); done
  printf '%s' "$p"
}
# 版本比较：ver_ge A B → A >= B 返回 0。
# 不用 sort -V：macOS 自带的是 BSD sort，没有 -V，会直接报错。
ver_ge(){
  awk -v a="$1" -v b="$2" 'BEGIN{
    split(a,A,"."); split(b,B,".");
    for(i=1;i<=3;i++){ x=A[i]+0; y=B[i]+0
      if(x>y) exit 0
      if(x<y) exit 1 }
    exit 0
  }'
}

# compose 把密码原样拼进 PRAETOR_PG_DSN（postgres://user:密码@postgres:5432/...），
# 含 @ : / ? # % 或空格会截断 / 改义连接串：容器能起来，应用却连不上库。
# 随机值天然只含字母数字，这里约束的是用户手工输入的那一路。
read_db_password(){
  local def="$1" p
  while :; do
    p="$(ask 'Postgres 密码（回车随机生成；仅字母数字与 . _ - ~）' "$def")"
    if [[ "$p" =~ ^[A-Za-z0-9._~-]+$ ]]; then printf '%s' "$p"; return 0; fi
    warn "密码含 URL 保留字符（@ : / ? # % 空格等），会破坏数据库连接串，请换一个"
  done
}

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

# ── docker CLI 来源镜像 ──────────────────────────
# 应用容器靠 Dockerfile 顶部的 DOCKER_CLI_IMAGE 拿到 docker 命令；官方源拉不动时
# 自动切镜像源并写进 .env，否则 `compose build` 会在第一个 FROM 就失败。
ensure_docker_cli_image(){
  if [ -n "$(env_get PRAETOR_DOCKER_CLI_IMAGE)" ]; then return 0; fi
  if docker image inspect docker:27-cli >/dev/null 2>&1; then return 0; fi
  if docker pull docker:27-cli >/dev/null 2>&1; then return 0; fi
  local mirror="docker.m.daocloud.io/library/docker:27-cli"
  warn "官方 docker:27-cli 拉不动，改用镜像源 ${mirror}（可用 PRAETOR_DOCKER_CLI_IMAGE 覆盖）"
  if ! docker pull "$mirror" >/dev/null 2>&1; then
    die "docker CLI 镜像拉取失败：请在 .env 手动设置 PRAETOR_DOCKER_CLI_IMAGE 后重试"
  fi
  env_set PRAETOR_DOCKER_CLI_IMAGE "$mirror"
}

# ── 启动后验证 ──────────────────────────────────
# up -d 是异步的：端口冲突 / 库起不来 / 构建半途失败时，脚本照样会打印
# 「安装完成 → http://...」，用户打开是白页。这里把「真的能响应」作为成功前置。
wait_http_ready(){
  local port i ok_flag=0
  port="$(http_port)"
  info "等待服务就绪（最多 60 秒）…"
  for i in $(seq 1 30); do
    if command -v curl >/dev/null 2>&1; then
      if curl -fsS -o /dev/null "http://127.0.0.1:${port}/" 2>/dev/null; then ok_flag=1; break; fi
    elif port_in_use "$port"; then
      # 没有 curl 就退化到「端口在听」，聊胜于无
      ok_flag=1; break
    fi
    sleep 2
  done
  if [ "$ok_flag" != "1" ]; then
    warn "服务 60 秒内未响应，当前容器状态："
    compose ps 2>/dev/null || true
    die "排查：docker compose ${COMPOSE_ARGS[*]} logs --tail 50 praetor"
  fi
  ok "服务已就绪 → http://localhost:${port}"
}

# ── 安装完成摘要 ────────────────────────────────
# up -d 是后台启动，脚本到这里就该结束；但"结束"和用户"知道怎么用"是两回事。
# 把凭据位置、初始化入口、端口、日志命令一次讲清，别让人翻代码找密码。
show_install_summary(){
  local port pg_port
  port="$(http_port)"
  pg_port="$(env_get PRAETOR_PG_PORT)"; pg_port="${pg_port:-55433}"
  echo
  ok "安装完成 → http://localhost:${port}"
  echo "────────────────────────────────────────────────────────────"
  echo "  首次使用   打开上面的地址，在 /setup 设置「管理员登录密码」"
  echo "             （Web 登录用，和下面的数据库密码是两回事）"
  echo "  配置在哪   $(pwd)/.env —— docker compose 自动读取，不会 export 到当前 shell"
  echo "  数据库密码 grep '^POSTGRES_PASSWORD=' .env"
  echo "             普通使用不需要它：应用容器内由 compose 注入 PRAETOR_PG_DSN"
  echo "  直连数据库 postgres://praetor:<上面的密码>@127.0.0.1:${pg_port}/praetor"
  echo "  查看日志   docker compose ${COMPOSE_ARGS[*]} logs -f praetor"
  echo "  路径自查   docker compose ${COMPOSE_ARGS[*]} logs praetor | grep '沙箱工作区'"
  echo "             （宿主路径自动推导，.env 无需写任何本机绝对路径）"
  echo "  后续启动   docker compose ${COMPOSE_ARGS[*]} up -d（选项 1 是容器部署，"
  echo "             不要去跑 ./praetor.exe；那个二进制属于选项 2 / Releases 包）"
  echo "  停止卸载   ./uninstall.sh（默认只停服务，数据全保留）"
  echo "────────────────────────────────────────────────────────────"
  info "后台启动中：Postgres 首次健康检查要几秒，页面暂时打不开属正常"
}

# ── ① 全部 Docker ───────────────────────────────
install_docker(){
  ensure_docker
  if [ ! -f .env ]; then
    [ -f .env.example ] || die "缺少 .env.example"
    cp .env.example .env
    chmod 600 .env 2>/dev/null || true
    local default_pw pw key
    default_pw="$(rand)"
    pw="$(read_db_password "$default_pw")"
    key="$(ask 'ANTHROPIC_API_KEY（可留空，后续在 UI 配）' '')"
    env_set POSTGRES_PASSWORD "$pw"
    # 用 if 而不是 `[ -n ] && env_set`：后者在 key 为空时返回 1，
    # 配合 set -e 会让脚本静默退出（正是最不该出错的地方）。
    if [ -n "$key" ]; then env_set ANTHROPIC_API_KEY "$key"; fi
    ok "已生成 .env（POSTGRES_PASSWORD 已写入，权限 600）"
    if [ "$pw" = "$default_pw" ]; then
      info "随机生成的数据库密码：$pw"
      info "只显示这一次；之后用 grep '^POSTGRES_PASSWORD=' .env 查看"
    else
      info "你设置的密码已写入 .env；用 grep '^POSTGRES_PASSWORD=' .env 可核对"
    fi
  else
    info "沿用已存在的 .env（保留已有值；下面仍会补齐缺失的沙箱选项）"
    info "查看当前数据库密码：grep '^POSTGRES_PASSWORD=' .env"
    if [ "$(env_get POSTGRES_PASSWORD)" = "change-me-please" ]; then
      warn ".env 仍是示例弱密码 change-me-please（手动 cp .env.example 才会这样）"
      warn "注意：数据卷已初始化后，只改 .env 不会改库里的密码，反而会让应用连不上库。"
      info  "要改需两步：先在库里 ALTER USER，再同步 .env 并重启（命令见 README）"
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
  # 可移植性：任务工作区的宿主路径由程序在启动期自动推导，.env 里不写任何
  # 机器相关的绝对路径。老版本若手工填过 HOST_ROOT，它会覆盖自动推导 ——
  # 换机器 / 挪动仓库后就会挂错目录，这里明确提醒一次而不是静默沿用。
  if [ -n "$(env_get PRAETOR_SANDBOX_WORK_HOST_ROOT)" ]; then
    warn ".env 里的 PRAETOR_SANDBOX_WORK_HOST_ROOT 会覆盖自动推导的宿主路径"
    warn "换机器或挪动仓库后请清空该行；常规部署不需要它"
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
    ensure_docker_cli_image
    # 构建期换源：Dockerfile 里 NPM_REGISTRY / GOPROXY 是 ARG，不传就走官方源，
    # 国内环境基本都会卡在 npm ci 或 go mod download 上。留空则保持官方默认。
    # 用 set -- 累积参数而不是数组长度判断：macOS 自带 bash 3.2 在 set -u 下
    # 展开空数组的 ${#arr[@]} 会直接报 unbound，这里规避掉。
    local npm_r goproxy
    npm_r="$(env_get NPM_REGISTRY)"
    goproxy="$(env_get GOPROXY)"
    set --
    if [ -n "$npm_r" ]; then set -- "$@" --build-arg "NPM_REGISTRY=$npm_r"; fi
    if [ -n "$goproxy" ]; then set -- "$@" --build-arg "GOPROXY=$goproxy"; fi
    if [ "$#" -gt 0 ]; then info "构建期换源：$*"; fi
    compose build "$@"
  fi
  info "启动…"
  compose up -d
  wait_http_ready
  show_install_summary
}

# ── ② 本地编译运行 ──────────────────────────────
# Windows 下 `go build -o praetor` 会产出没有 .exe 后缀的 PE：文件在、双击不了、
# start.bat 也找不到。按目标平台给正确的名字，启动提示才和真实产物对得上。
local_binary_name(){
  if [ "$(go env GOOS 2>/dev/null)" = windows ]; then echo praetor.exe; else echo praetor; fi
}
# heredoc 拼 JSON 时密码里的 " 或 \ 会破坏结构；最小转义即可（密码不含控制字符）。
json_escape(){ printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

install_local(){
  # 之前用选项 1 装过的话 .env 已存在，把库参数带进默认值。否则用户按老习惯
  # 填 5432 + 空密码，会生成一份「看着有配置其实连不上库」的 config.json ——
  # 这正是「config 和环境变量都检测不到」最常见的来源。
  local env_pg_port env_pg_user env_pg_db env_pg_pass
  env_pg_port="$(env_get PRAETOR_PG_PORT)"; env_pg_port="${env_pg_port:-5432}"
  env_pg_user="$(env_get POSTGRES_USER)";  env_pg_user="${env_pg_user:-praetor}"
  env_pg_db="$(env_get POSTGRES_DB)";      env_pg_db="${env_pg_db:-praetor}"
  env_pg_pass="$(env_get POSTGRES_PASSWORD)"
  if [ "$env_pg_pass" = "change-me-please" ]; then env_pg_pass=""; fi

  echo "数据库安装方式："
  echo "  1) 连接已有 PostgreSQL"
  echo "  2) 用 Docker 起一个 PostgreSQL（需要 docker；已有实例会直接复用，不重建不删除）"
  case "$(ask '选择' 1)" in
    2)
      ensure_docker
      local pg_port pw actual
      pw="$env_pg_pass"
      # 红线：这个分支只做「探测 + 复用 + 首次创建」，任何路径都不执行 rm / down -v。
      #
      # 优先级 1：compose 栈里的 praetor-pg 已在跑 → 直接连它。
      # 再起一个只会打架，而且它的数据卷 praetor-pgdata 是显式命名的，不该被绕开。
      if docker ps --format '{{.Names}}' | grep -qx 'praetor-pg'; then
        actual="$(docker port praetor-pg 5432/tcp 2>/dev/null | head -1 | sed 's/.*://')"
        pg_port="${actual:-$(env_get PRAETOR_PG_PORT)}"; pg_port="${pg_port:-55433}"
        ok "检测到运行中的 praetor-pg（127.0.0.1:${pg_port}）→ 直接复用，不新建、不删除"
      # 优先级 2：本选项之前起过的独立库 → 复用，数据保留。
      elif docker ps -a --format '{{.Names}}' | grep -qx 'praetor-pg-local'; then
        actual="$(docker port praetor-pg-local 5432/tcp 2>/dev/null | head -1 | sed 's/.*://')"
        pg_port="${actual:-$(env_get PRAETOR_PG_PORT)}"; pg_port="${pg_port:-55433}"
        warn "容器 praetor-pg-local 已存在（127.0.0.1:${pg_port}）→ 复用，不重建、数据保留"
      # 优先级 3：都没有 → 起一个独立实例，端口从默认值起自动避开已占用。
      else
        pg_port="$(env_get PRAETOR_PG_PORT)"; pg_port="${pg_port:-55433}"
        pg_port="$(pick_free_port "$pg_port")"
        pg_port="$(ask 'Postgres 宿主机端口' "$pg_port")"
        case "$pg_port" in ''|*[!0-9]*) die "端口必须是数字，收到：$pg_port" ;; esac
        # 二次确认：ask 期间端口可能被别的进程抢走
        if port_in_use "$pg_port"; then
          die "127.0.0.1:$pg_port 已被占用；换一个端口，或改用「1) 连接已有 PostgreSQL」"
        fi
        pw="$(ask 'Postgres 密码（回车随机）' "$(rand)")"
        info "启动独立 PostgreSQL 容器 praetor-pg-local（独立数据卷，不碰 compose 的 praetor-pgdata）…"
        docker run -d --name praetor-pg-local -p "127.0.0.1:${pg_port}:5432" \
          -e POSTGRES_USER=praetor -e POSTGRES_PASSWORD="$pw" -e POSTGRES_DB=praetor \
          -v praetor-pg-local:/var/lib/postgresql/data postgres:16-alpine >/dev/null \
          || die "启动 PostgreSQL 失败；查看：docker logs praetor-pg-local"
      fi
      # 复用路径下 .env 可能没有密码（换过机器 / 手抄过配置），空密码连不上库
      if [ -z "$pw" ]; then
        pw="$(ask '该实例的 Postgres 密码（.env 里没有现成值）' '')"
        if [ -z "$pw" ]; then die "没有密码无法连接；先设 POSTGRES_PASSWORD 再重跑"; fi
      fi
      DB_HOST=127.0.0.1 DB_PORT="$pg_port" DB_USER=praetor DB_PASS="$pw" DB_NAME=praetor DB_SSL=disable ;;
    *)
      DB_HOST="$(ask '数据库地址' 127.0.0.1)"
      DB_PORT="$(ask '端口' "$env_pg_port")"
      DB_USER="$(ask '账号' "$env_pg_user")"
      DB_NAME="$(ask '数据库名' "$env_pg_db")"
      DB_SSL="$(ask 'sslmode (disable/require)' disable)"
      if [ -n "$env_pg_pass" ]; then
        # 不把 .env 里的密码回显在提示里：回车沿用，输入其它值才覆盖。
        printf '数据库密码（回车沿用 .env 中的值，不回显默认值）：'
        if ! read -r DB_PASS; then DB_PASS=""; fi
        if [ -z "$DB_PASS" ]; then DB_PASS="$env_pg_pass"; fi
      else
        DB_PASS="$(ask '数据库密码' '')"
      fi ;;
  esac
  case "$DB_PORT" in ''|*[!0-9]*) die "数据库端口必须是数字，收到：$DB_PORT" ;; esac

  # 生成 config.json
  cat > config.json <<JSON
{
  "database": {
    "host": "$(json_escape "$DB_HOST")",
    "port": ${DB_PORT},
    "user": "$(json_escape "$DB_USER")",
    "password": "$(json_escape "$DB_PASS")",
    "dbname": "$(json_escape "$DB_NAME")",
    "sslmode": "$(json_escape "$DB_SSL")"
  }
}
JSON
  ok "已生成 config.json → $(pwd)/config.json"
  info "连接目标 postgres://${DB_USER}:****@${DB_HOST}:${DB_PORT}/${DB_NAME}（密码不回显）"

  # go 环境检查
  command -v go >/dev/null 2>&1 || die "未检测到 Go，请先安装 Go（>=1.26）：https://go.dev/dl/"
  # 提前校验版本：不查的话要等前端编完、进到 go build 才报 go.mod requires go >= x，
  # 白等好几分钟。版本号从 go.mod 读，不在脚本里重复写死。
  local gov need
  gov="$(go env GOVERSION 2>/dev/null | sed 's/^go//')"
  need="$(awk '/^go /{print $2; exit}' go.mod)"
  if [ -n "$gov" ] && [ -n "$need" ] && ! ver_ge "$gov" "$need"; then
    die "Go 版本过低：当前 $gov，go.mod 要求 $need"
  fi
  ok "Go: $(go version)"
  local bin; bin="$(local_binary_name)"

  # 内嵌前端需要 node 出静态产物
  if command -v npm >/dev/null 2>&1; then
    info "构建前端静态产物…"
    local npm_reg
    npm_reg="$(env_get NPM_REGISTRY)"; npm_reg="${npm_reg:-https://registry.npmjs.org}"
    ( cd web && npm ci --registry="$npm_reg" && npm run build:static )
    rm -rf server/webui/dist && cp -r web/out server/webui/dist
    info "编译内嵌单二进制…"
    CGO_ENABLED=0 go build -tags embedui -trimpath -o "$bin" ./cmd/praetor
  else
    warn "未检测到 npm：将编译**不内嵌前端**的后端（前端需另跑 npm run dev）"
    CGO_ENABLED=0 go build -o "$bin" ./cmd/praetor
  fi
  ok "编译完成 → ./$bin"

  echo
  echo "────────────────────────────────────────────────────────────"
  echo "  本次启动   前台运行 ./$bin  → http://localhost:8787（Ctrl-C 停止）"
  echo "  后续启动   Linux/macOS: ./start.sh    Windows: start.bat"
  echo "             这两个脚本会自动读 .env 并组装 PRAETOR_PG_DSN"
  echo "  直接运行   ./$bin —— 只读 config.json + 环境变量，**不读 .env**"
  echo "  配置优先级 环境变量 PRAETOR_PG_DSN > config.json"
  echo "  启动日志   会打印配置路径、来源和已识别的 PRAETOR_* 变量名（值不打印）"
  # 本选项起的独立库不归 compose 栈管，交接清楚，避免用户以为 uninstall.sh 会顺手清掉
  if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qx 'praetor-pg-local'; then
    echo "  本地库实例 容器 praetor-pg-local / 数据卷 praetor-pg-local（本选项独立管理）"
    echo "             停止：docker stop praetor-pg-local（数据保留，不会自动删除）"
  fi
  echo "────────────────────────────────────────────────────────────"

  # 沙箱预判：宿主二进制直接摸本机 docker。
  # Docker Desktop（Windows/macOS）的 socket 在虚拟机内，宿主二进制通常连不上；
  # 而 PRAETOR_SANDBOX 默认 required —— 连不上就把每条 Bash 都拒掉，
  # 表现为「编译成功、页面能开、一用就废」。这里显式判一次再启动。
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    export PRAETOR_SANDBOX="${PRAETOR_SANDBOX:-required}"
    ok "沙箱：required（已探测到本机 docker，Bash 走一任务一容器）"
  else
    export PRAETOR_SANDBOX=optional
    warn "本机 docker 不可达 → 本次以 PRAETOR_SANDBOX=optional 启动"
    warn "Bash 将跑在宿主进程内，没有 per-task 隔离；需要隔离请先让 docker 对当前用户可用"
  fi

  info "启动…（Ctrl-C 退出）→ http://localhost:8787"
  "./$bin"
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
