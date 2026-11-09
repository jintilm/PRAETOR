# 两个构建目标 **共用同一个运行环境**（runtime-base），差别只在二进制从哪来：
#
#   --target runtime-with-source  （默认）在镜像里编前端 + Go，宿主不用装 Node/Go。
#                                  `docker compose build` / 别人复刻仓库走这条。
#   --target runtime-with-binary   CI 发布用：二进制由 release.yml 交叉编译后放进
#                                  dist/<TARGETARCH>/，镜像只装工具、不重编（多架构快得多）。
#
# 为什么不合成一个 stage：Dockerfile 的 COPY 不能按条件跳过，二进制要么来自
# dist/ 要么来自编译阶段。apt / Playwright 这些重活只在 runtime-base 写一份，
# 两条路径都继承，不会各维护一套工具链。

# 挂了 /var/run/docker.sock 只解决「能不能连到宿主 Docker」，容器里还得有
# docker CLI 才能 `docker image inspect` / `docker run`。官方 cli 镜像里的二进制
# 是静态链接的，直接拷过来即可（~40MB，不带 daemon，不引入 containerd）。
# 缺了它，required 模式启动期探测就失败，之后每条 Bash 都会被拒绝。
# 拉不到官方镜像时用 .env 换源，例如：
#   PRAETOR_DOCKER_CLI_IMAGE=docker.m.daocloud.io/library/docker:27-cli
ARG DOCKER_CLI_IMAGE=docker:27-cli
FROM ${DOCKER_CLI_IMAGE} AS docker-cli

# ── ① 前端静态导出 ─────────────────────────────
FROM node:22-bookworm-slim AS web

WORKDIR /src/web
# 允许换源：默认官方 registry；内网或被墙时用
#   --build-arg NPM_REGISTRY=https://registry.npmmirror.com
ARG NPM_REGISTRY=https://registry.npmjs.org
# 先只拷依赖清单：依赖没变时这层命中缓存，改前端代码不用重装 node_modules
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund --registry="${NPM_REGISTRY}"
COPY web/ ./
RUN npm run build:static

# ── ② 内嵌前端 + 编译单二进制 ───────────────────
FROM golang:1.26-bookworm AS source-bin

# 同上：默认官方代理；被墙时用 --build-arg GOPROXY=https://goproxy.cn,direct
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY}

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# -tags embedui 靠 go:embed 打包 server/webui/dist —— 必须在 go build 之前就位。
# （.dockerignore 排除了 web/out 与 server/webui/dist，所以这里显式从 web 阶段拷。）
COPY --from=web /src/web/out ./server/webui/dist
ENV CGO_ENABLED=0
RUN go build -tags embedui -trimpath -ldflags="-s -w" -o /out/praetor ./cmd/praetor

# ── ③ 运行环境（工具链 + Playwright）─────────────
FROM python:3.12-slim-bookworm AS runtime-base

# 全容器化部署时用它管理任务沙箱容器；不挂 socket 也无害（只是多 40MB）。
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker

# 常用工具：ripgrep / curl / vim，加一批 recon 常备件（按需增删）。
# Node 从 NodeSource 装 20.x：bookworm 自带的 apt nodejs 是 18，Playwright 要求 >=20。
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates ripgrep curl wget vim git jq unzip \
      dnsutils iputils-ping netcat-openbsd inetutils-telnet whois nmap \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*
# 预装 Playwright MCP 与 CLI（全局），运行时不再 npx 联网下载。
# @playwright/mcp：browser MCP 直接 `npx @playwright/mcp`（已全局装好，无需 -y/@latest）。
# @playwright/cli：提供 playwright-cli，装完顺带 --help 验证可执行。
# 再装 playwright（提供浏览器管理），装完用 --with-deps 预置 chromium 及其系统依赖，
# 这样容器内 MCP/CLI 首次启动即可用，不再联网下载浏览器。
RUN npm install -g @playwright/mcp@latest @playwright/cli@latest playwright@latest \
    && playwright-cli --help \
    && playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# data/（jwt.key、任务工作区等）持久化点
VOLUME ["/app/data"]
EXPOSE 8787 8788

# ── ④ CI 发布目标：用交叉编译好的二进制 ──────────
FROM runtime-base AS runtime-with-binary

ARG TARGETARCH
# 对应 dist/amd64/praetor 或 dist/arm64/praetor
COPY dist/${TARGETARCH}/praetor /app/praetor
# 守护启动脚本：进程退出后按退出码决定是否重新拉起，页面一键更新靠它完成换装。
# 它同时负责把 SIGTERM 转发给 praetor —— docker stop 只把信号发给 PID 1，
# 不转发的话 praetor 收不到、做不了优雅关闭，10 秒后被 SIGKILL 硬杀。
COPY start.sh /app/start.sh
RUN chmod +x /app/praetor /app/start.sh
COPY skills/ /app/skills/
ENTRYPOINT ["/app/start.sh"]
CMD ["-addr", ":8787", "-proxy", ":8788"]

# ── ⑤ 默认目标：从本仓库源码构建 ─────────────────
# 放在最后 = `docker build .` 的默认行为：克隆者不用装 Go/Node 也能出镜像，
# 且镜像里就是你当前这份代码（不会去拉别人的预编译镜像）。
FROM runtime-base AS runtime-with-source

COPY --from=source-bin /out/praetor /app/praetor
COPY start.sh /app/start.sh
RUN chmod +x /app/praetor /app/start.sh
COPY skills/ /app/skills/
ENTRYPOINT ["/app/start.sh"]
CMD ["-addr", ":8787", "-proxy", ":8788"]
