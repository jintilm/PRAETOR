<div align="center">

# PRAETOR

AI 自主渗透测试系统（Go 后端 + Next.js 前端）

二开ARTEX

</div>

---

## 截图预览

> 完整交互见[在线 Demo](https://praetor-demo.vercel.app/)。

| 仪表盘（总览 / Token 消耗 / 活动流） | 任务列表 |
| :---: | :---: |
| ![仪表盘](screenshots/dashboard.png) | ![任务](screenshots/tasks.png) |

| 任务 · 执行过程（会话 / 工具调用） | 探索链路 |
| :---: | :---: |
| ![执行过程](screenshots/sessions.png) | ![探索链路](screenshots/graph.png) |

| 发现 | 资产 |
| :---: | :---: |
| ![发现](screenshots/findings.png) | ![资产](screenshots/assets.png) |

| 资产覆盖图（力导向布局 · 已测高亮 · 节点折叠展开） |
| :---: |
| ![资产覆盖图](screenshots/assets_test.png) |

| 流量录制 | 人在环路对话 |
| :---: | :---: |
| ![流量](screenshots/traffic.png) | ![对话](screenshots/chat.png) |

| Agent 管理 | LLM 配置 |
| :---: | :---: |
| ![Agent](screenshots/agents.png) | ![LLM](screenshots/llm.png) |

| 拦截审批 | 后端日志 |
| :---: | :---: |
| ![拦截](screenshots/intercept.png) | ![日志](screenshots/logs.png) |


---

## 审批记录详情

全局「审批记录」、任务内「拦截审批」及对话中的审批卡片均支持展开查看详情。展示结构参考
[AegisHook 的审批详情组件](https://github.com/RuoJi6/AegisHook/blob/main/web/src/components/CallDetail.vue)，沿用 PRAETOR 的组件和主题：


## 资产同步（ScopeSentry）

支持从 [ScopeSentry](https://github.com/Autumn-27/ScopeSentry) 直接同步资产数据，免去重复收集：

- 在「**资产同步**」页填 ScopeSentry 的地址与 API Key，接入数据源；
- 按**项目**或**任务**维度选择要同步的目标与资产类型（域名 / 子域 / IP / 端口 / 站点 / 端点…）；
- 一键导入并按公司资产范围归并，直接进入 PRAETOR 的资产图供 agent 探索使用。

---

## 核心能力

### 任务领域：同一引擎，四套自主性形态

创建任务时选择**领域**（`domain`），调度拓扑、预算与硬约束随领域切换：

| 领域 | 调度拓扑 | 领域专属约束 |
| --- | --- | --- |
| **渗透测试**（默认） | 1 planner + N worker（探索并发） | 双图推进 + 资产覆盖度 |
| **CTF 靶场** | 延迟竞速（默认单路，停滞才起第二路） | `ctf_challenge` 拉题 / `ctf_board` 竞速看板与放弃决策 / `ctf_submit` 唯一提交出口（去重 + 平台判分）；任务详情有 **CTF 面板**（题面配置、看板、判分记录） |
| **逆向分析** | 1 planner + 1 worker（**证据串行**） | `re_triage` 定性 → `re_recipe` 8 条静态/动态配方（rizin / Ghidra headless / FLOSS / capa / DIE / gdb / apktool）→ `re_evidence` 证据链落图（claim/ref 硬校验，判据不通过也落库但标记 `inferred`） |
| **红队战役** | 1 planner + 1 worker（串行） | 意图携带 ATT&CK 阶段（`phase`），**前置未完成不下发**；做过持久化/外传而 cleanup 未完成时**禁止收尾**（`prove_goal` / `goal_met` 均被拦）；可接 Caldera（`caldera_operation` 列 ability / 下发 / 回收，未配置时明确报「未配置」） |

### 子 agent 派生（灰度开关）

CTF 与逆向域的 worker 即领域 lead，可通过 `Agent` 工具把「解一道题」「验证一条假设」派给**独立上下文**的子 agent（CTF：web/pwn/rev/crypto/forensics 五个 solver；逆向：re-analyst）。子 agent 继承父的沙箱视角（容器路径映射、写白名单）与输出目录，产物经共享工具集归口回本意图；中间过程镜像进 activity 流（UI 可见，带 `agentType:` 前缀）。这些角色在 **Agent 管理**页可见为一等 agent（role=specialist）：提示词可编辑（DB 权威，代码默认兜底）、可单独绑定 LLM 配置（如逆向 analyst 走本地模型）。逆向域的结论经 `re_evidence` 以**证据节点**落探索图（claim/ref 硬校验），任务详情的探索链路图对 evidence 类型有专属渲染。默认关闭，`PRAETOR_SUBAGENTS=ctf,reverse` 按域灰度开启。

### 每任务沙箱

开启后每任务一个一次性 Docker 容器（`PRAETOR_SANDBOX=required` + 隔离档位）：

- **全量出口隐身**（配置全局出口代理后自动生效）：容器全部出站 TCP 在 IP 层重定向到出口代理（iptables + redsocks）——不依赖环境变量，Go 工具、nmap `-sT` 等不读代理变量的程序同样被覆盖；本地网段（RFC1918）直连以保证内网靶场可达；
- **任务级出口池（IP 隔离，可选）**：设置页可配多个上游（mihomo 多 listener / gost / 商业隧道均可），按任务稳定分配（hash，同一任务重建容器不换出口，会话不漂移），不同任务出口互相隔离；不配则回落全局出口代理；
- **隐身边界（如实说明）**：SYN 扫描（`-sS`/masscan）承载不了——代理只能传 TCP，隐身语义下用 `-sT`，需要真 SYN 扫描走自建 WireGuard 出口；DNS 默认经宿主解析（上游用 mihomo/Clash 时可把容器 DNS 指向其 DNS 监听解决）；
- Bash 在容器内执行；文件工具（Read/Write/LS/Glob/Grep）跑在宿主进程，内置**容器路径 → 宿主路径**翻译与**写白名单**（只有工作挂载可写，题面挂载只读，未挂载路径一律拒绝）；
- 边界校验在解析符号链接后用真实路径重比，越界按「路径不存在」处理（fail closed）；
- 启动时扫描并清理本部署上次遗留的任务容器（按挂载源归属判断，不误删别的部署）。

### 样本治理（逆向域）

`internal/samplestore` 是唯一允许长期持有样本的地方：AES-256-GCM 分块加密（密钥 `PRAETOR_SAMPLE_KEY`，缺密钥直接报错，**没有明文降级**）、sha256 索引去重、入库走人工 CLI（`go run ./cmd/samplestore -put <样本>`）。工具只见路径不见字节：`target=sha256:<hex>` 解密到临时文件、用完即删，样本内容永远不会进 LLM 上下文。

### 系统人设

设置页可配置**系统级人设**（注入所有 agent、最高优先级）：声明平台身份与授权前提（典型场景：企业授权渗透 / CTF 靶场 / 自有样本分析 / SRC / 防御研究），带变更确认与审计留痕；per-agent 提示词在 Agent 管理页可编辑（DB 存储 + 代码内置默认兜底）。

---

## 安装

> 依赖数据库 **PostgreSQL**；探索需配置 **LLM**（`ANTHROPIC_API_KEY` 或 `OPENAI_API_KEY`，也可在 UI 里配）。
>
> Docker 部署的镜像是**从本仓库源码现编**的（不需要你装 Node/Go），首次构建要拉
> `node:22` / `golang:1.26` / `python:3.12-slim` 三个基础镜像并从 npm、Go proxy 取依赖，
> 大约 5~10 分钟；之后改代码只重编变化的那几层。网络受限时给 Docker 配镜像加速，
> 并在 `.env` 设 `PRAETOR_GOPROXY=https://goproxy.cn,direct`、
> `PRAETOR_NPM_REGISTRY=https://registry.npmmirror.com`。

### 方式一：一键安装脚本（推荐）

```bash
git clone https://github.com/jintilm/PRAETOR.git
cd PRAETOR
./install.sh
```

两种模式**都只用当前仓库的代码**：Docker 模式在镜像里从源码编译（`Dockerfile` 的
`runtime-with-source` 目标），不会去 Docker Hub 拉别人的预编译镜像。

脚本会：检测 / 自动安装 Docker → 让你选 **① 全部 Docker** 或 **② 本地编译运行**：

- **① 全部 Docker**：填一个 Postgres 密码（可回车随机）→ 写 `.env` → 询问沙箱方式（是否挂 `docker.sock`）→ `docker compose build` + `up -d`。
- **② 本地运行**：选数据库（连已有 / 用 Docker 起一个）→ 生成 `config.json` → `go` 编译内嵌单二进制 → 启动。

装好后打开 **http://localhost:8797**（方式①）或 **http://localhost:8787**（方式②，二进制默认端口）进入 `/setup` 设置管理员密码。

> 端口不是笔误：容器内固定监听 8787，宿主映射由 `PRAETOR_HTTP_PORT` 决定（默认 **8797**，避开旧栈常用的 8787/8788）；直接跑二进制时监听 **8787**。

#### 安装完成后：密码在哪、还要做什么

脚本结束会打印一份摘要（访问地址、配置路径、密码查看命令、日志命令）。几个最容易混淆的点：

| 问题 | 答案 |
| --- | --- |
| 为什么 shell 里 `echo $POSTGRES_PASSWORD` 是空的？ | `.env` 是 **docker compose 的变量插值文件**，不是 shell 环境。compose 读它把值写进容器 `environment:`，不会 export 到当前终端。宿主机直接跑二进制才需要 `set -a; . ./.env; set +a`（见下方「方式六：环境变量配置」） |
| 数据库密码是空的吗？ | **不是**。首次安装回车 = 脚本随机生成 24 位，或你自己输入；都会写进 `.env`。`docker-compose.yml` 用 `${POSTGRES_PASSWORD:?...}`，为空会直接拒绝启动，不存在「空密码也能跑」 |
| 我怎么查？ | `grep '^POSTGRES_PASSWORD=' .env`。用随机值时脚本会当场显示一次，之后只存 `.env`（文件权限 600） |
| 什么时候才需要它？ | 宿主机 `psql` 直连、`pg_dump` 备份、本地跑二进制时。全 Docker 下应用靠 compose 注入的 `PRAETOR_PG_DSN` 走内部网络 `postgres:5432`，不需要手工填 |
| 登录页面的密码是哪个？ | 打开 `/setup` 自己设的**管理员密码**，存在数据库里，与数据库账号密码完全无关 |

> 只有手动 `cp .env.example .env` 却没跑 `./install.sh` 时，密码才会停留在公开的示例值 `change-me-please`（脚本会警告）。密码只允许字母数字与 `. _ - ~` —— 它会被原样拼进连接串，含 `@ : / ? # %` 或空格会破坏 DSN。

#### 后续启动：按安装方式选命令

| 安装方式 | 后续启动 | 不要用 |
| --- | --- | --- |
| ① 全部 Docker（`./install.sh` 选 1） | `docker compose up -d`（挂了 socket 时加 `-f docker-compose.socket.yml`） | `./praetor.exe` —— 那是另一套部署的产物。硬跑会另起一个实例，而且读不到容器里由 compose 注入的 `PRAETOR_PG_DSN` |
| ② 本地编译运行（`./install.sh` 选 2） | `./start.sh` / `start.bat`（Git Bash 里 `./start.sh` 也行）；也可直接 `./praetor`，Windows 为 `./praetor.exe` | — |
| Releases 预编译包 | 用包里的 `start.sh` / `start.bat` | 直接双击 exe：跳过守护脚本，页面「一键更新」换完装不会被拉起 |

**启动横幅是 `PRAETOR` 字形。** 如果终端里看到的是 `ARTEX`，说明跑的是改名之前编译的旧二进制（看 `praetor.exe` 的时间戳）——字形跟着二进制一起编译，改文档不会变，必须重新编译才会更新。

#### 配置读不到时怎么自查

`./praetor -check-config`（Windows：`praetor.exe -check-config`）只打印配置来源，**不连数据库、不启动服务**。正常启动也会打印同样几行：

```text
[config] 配置文件: E:\...\config.json (已找到)
[config] 环境变量: 已识别 1 个 PRAETOR_* 变量：PRAETOR_PG_DSN（值不打印）
[config] 沙箱工作区: 应用内=E:\...\data\work | docker -v 源=E:/.../data/work | 依据=宿主进程（无需转换）
[config] 数据库配置: 来源=配置文件 ... (database 字段)，目标=postgres://praetor:REDACTED@127.0.0.1:55433/praetor
```

- 二进制**只读 `config.json` 和进程环境变量，不读 `.env`**；`.env` 是给 docker compose 用的插值文件。所以直接跑 exe 时「环境变量检测不到」是预期行为，不是故障。
- `start.sh` / `start.bat` 负责桥接：把 `.env` 里的 `PRAETOR_*` / `POSTGRES_*` 搬进环境，并从 `POSTGRES_PASSWORD` + `PRAETOR_PG_PORT` 自动组装 `PRAETOR_PG_DSN`（调用方已 export 的同名变量优先，不覆盖）。
- 优先级：`PRAETOR_PG_DSN` > `config.json`（`database.dsn` > 分字段）。两者都没有会**明确报错并指出该创建哪个文件**，不会悄悄连到某个默认库。
- `config.json` 按 `PRAETOR_CONFIG` → 当前目录 → 可执行文件同级的顺序找第一个存在的文件；启动日志会打印实际命中的绝对路径。常见错误是把端口号写进 `host`、或沿用容器内的 `5432` 而宿主实际是 `55433`。
- `[config] 沙箱工作区` 一行给出「应用内路径 / `docker -v` 宿主源 / 推导依据」。全 Docker 部署下两者不同是正常的；若显示「解析失败」，按报错检查容器内是否有 `docker` CLI、`PRAETOR_DATA_DIR` 是不是宿主目录，详见[两个路径视角](#任务工作区的两个路径视角全-docker-部署)。

`compose up -d` 是后台启动，Postgres 首次健康检查要几秒，页面短暂打不开属正常：`docker compose logs -f praetor` 看进度。

### 方式二：Docker Compose（手动）

```bash
git clone https://github.com/jintilm/PRAETOR.git
cd PRAETOR
cp .env.example .env            # 至少填 POSTGRES_PASSWORD
docker compose up -d --build    # 从本仓库源码构建 praetor 镜像 + 起 postgres
# → http://localhost:8797
```

镜像里已含常用工具（ripgrep/curl/vim/npm/nmap…）；`./skills` 与 `./data` 以绑定挂载持久化。

沙箱要真正可用，应用容器必须能访问宿主 Docker，再叠一层覆盖文件：

```bash
docker compose -f docker-compose.yml -f docker-compose.socket.yml up -d --build
```

> 不挂 `docker.sock` 时，`PRAETOR_SANDBOX=required` 会让每次 Bash 都被拒绝
> （`sandbox unavailable`）——部署看着成功、一用就报错。要么挂 socket，要么把
> `PRAETOR_SANDBOX` 改成 `optional`（Bash 跑在应用容器内，用镜像自带工具链）。
>
> **挂了 socket 还不够**：容器里必须有 `docker` CLI 才能起任务沙箱。镜像从
> `docker:27-cli` 拷入静态二进制（可用 `PRAETOR_DOCKER_CLI_IMAGE` 换源），否则启动日志是
> `exec: "docker": executable file not found in $PATH`，Bash 依旧全拒。

#### 从「宿主机跑二进制」切到「全部 Docker」必查

全容器化后，宿主机上原本成立的三处隐式依赖不会自动跟过来。典型症状是部署成功、页面 200，
但 agent 的 Bash / 浏览器 / WebFetch 全废：

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| 每条 Bash `sandbox unavailable: docker 不可用` | 应用容器缺 `docker` CLI | 重建带 CLI 的镜像；或临时设 `PRAETOR_SANDBOX=optional` 降级 |
| `npx playwright install chrome` 也被同一原因拒 | 它本身就是一条 Bash，走同一个拒绝通道 | 修好沙箱即可，不必单独装浏览器 |
| 浏览器提示 `/opt/google/chrome/chrome` 不存在 | 镜像预装的是 Playwright chromium（`~/.cache/ms-playwright`），不是 Chrome stable | 用 Playwright 自带 chromium；沙箱镜像里另需装浏览器 |
| WebFetch 对所有站点（含对照站点）都 502 | 设置里全局出口代理仍是 `http://127.0.0.1:7897`，容器内指向容器自己 | 系统设置改为 `http://host.docker.internal:7897`，或清空直连 |
| 修好 CLI 后又报「沙箱镜像不存在」 | 设置里记着旧机构建的 `praetor/sandbox:custom-*` tag | 组件面板重新应用预设，或清空 `sandbox.image` 回落 `PRAETOR_SANDBOX_IMAGE` |
| 每条 Bash `OCI runtime exec failed: chdir to cwd ("/work/i622")`，退出码 127 | 任务容器挂错了宿主目录，`/work` 里没有意图子目录 | 见下节；确认启动日志的「工作区」两行指向同一棵树 |

`required` 是 **fail-closed**：探测失败不阻断启动（UI 能进），但注入一个永远拒绝的 Runner，
绝不让 Bash 悄悄回落到宿主。所以启动日志里这两行就是总开关：

```text
[sandbox] 不可用（mode=required, isolation=per-task ...）：docker 不可用: ...
[sandbox] worker 的 Bash 将被拒绝；修好 Docker/镜像，或设 PRAETOR_SANDBOX=optional 降级
```

#### 任务工作区的两个路径视角（全 Docker 部署）

应用跑在容器里时，同一棵任务目录树有两个名字：

| 视角 | 例子 | 谁在用 |
| --- | --- | --- |
| 应用进程内 | `/app/data/work/214/i622` | `os.MkdirAll`、LS/Read/Write 等工具、提示词里的 `/work/i622` |
| Docker daemon（宿主） | `E:/Code/pentest/PRAETOR/data/work/214` 或 `/opt/praetor/data/work/214` | `docker run -v <源>:/work` |

老实现把前者原样交给 `-v`，宿主上没有 `/app/...`，Docker 就自动建了个空目录挂进任务容器：
宿主预建好的 `i622` 和容器里的 `/work` 变成两棵树，`docker exec --workdir /work/i622`
在 shell 启动之前就 `chdir` 失败，表现为 `OCI runtime exec failed: ... no such file or directory`
+ 退出码 127 —— 命令一行都没执行，26 个端口一个 `OPEN:` 都扫不出来。

现在的处理是**启动期自动推导**：程序 `docker inspect` 自身容器，把 Compose 已经解析好的
bind mount 宿主源读回来，再拼上 `work/<taskID>` 作为 `-v` 的源。因此：

- `.env` 里**不需要**填任何机器相关的绝对路径；全新 clone 后 `./install.sh` 选 1 在
  Windows / Linux / macOS 上都能直接跑，换 clone 目录、从别的目录执行 compose、事后挪动仓库也自愈。
- `PRAETOR_DATA_DIR` 必须是**宿主目录**（bind mount），不要填 Docker 命名卷名；落在命名卷里会
  明确报错并指出改法，而不是静默挂空目录。
- 只有 daemon 不在本机（远程 `DOCKER_HOST`）等非常规布局，才需要设 `PRAETOR_SANDBOX_WORK_HOST_ROOT`
  覆盖自动推导。设了它就会跳过推导，换机器后记得清空。
- 启动日志 / `-check-config` 会打印三元组：`应用内=… | docker -v 源=… | 依据=…`；
  路径推导不出来时按 `required` 的规则 fail-closed，不会退化成那个空目录。
- 兜底：正式 `exec` 前还会按容器缓存地补建一次 `--workdir` 指向的目录，防止目录在容器复用期间被删。

想改用现成的发布镜像（而不是自己构建）：在 `.env` 设
`PRAETOR_IMAGE=<registry>/<repo>:<tag>`，然后 `docker compose pull praetor && docker compose up -d`。

远程 MCP 可在系统设置中选择 `http`（Streamable HTTP）或 `sse`（旧版 SSE）。
旧版 SSE 服务通常使用 `GET /sse` 建立事件流，再通过服务返回的
`/message?sessionId=...` 接收 JSON-RPC 请求；配置时将 URL 填为 `/sse`，请求头按
`Authorization=Bearer <token>` 填写。

### 方式三：下载预编译二进制（Releases）

到 [Releases](https://github.com/jintilm/PRAETOR/releases) 下载对应平台的 zip，解压后得到 `praetor` + `start.sh`（Windows 为 `start.bat`）+ `skills/` + `config.example.json`：

```bash
cp config.example.json config.json   # 填好 database 连接
./start.sh                           # → http://localhost:8787
```

> 请用 `start.sh` / `start.bat` 启动，而不是直接跑 `./praetor`。它是个守护脚本：程序退出后按退出码决定是否重新拉起，**页面上的[一键更新](#方式一页面一键更新推荐)靠它完成换装**。直接运行 `./praetor` 时更新完就不会被拉起了。
> 后台常驻：`nohup ./start.sh >praetor.log 2>&1 &`。

### 方式四：从源码编译单二进制

```bash
# 1) 前端静态导出（build:static 是跨平台的：内部用 Node 设 NEXT_EXPORT 再拉起 next，
#    Windows 上也能直接跑，不需要手写 NEXT_EXPORT=1 前缀）
cd web && npm ci && npm run build:static && cd ..
# 2) 拷进内嵌目录
cp -r web/out server/webui/dist
# 3) 编译（-tags embedui 才内嵌前端）
CGO_ENABLED=0 go build -tags embedui -o praetor ./cmd/praetor
./start.sh
```

> 只需要后端、前端另跑 `npm run dev` 时，跳过 1~2 步并去掉 `-tags embedui`。
> 注意不带 `embedui` 编出来的二进制**没有 UI**（页面返回 404 提示语），别拿去部署。
> Windows 把输出名改成 `-o praetor.exe` 并用 `start.bat` 启动（`./install.sh` 选项 2 会自动按平台选名字）；Git Bash 里 `start.sh` 也能识别带 `.exe` 的产物。

### 方式五：构建跨平台 Release 压缩包

`build.sh` 会先构建并嵌入前端，再使用 Go linker 去除调试信息，并将发布文件压缩为 zip。Release 模式默认生成 Linux amd64/arm64、macOS amd64/arm64 和 Windows amd64 的 zip 包：

```bash
./build.sh --release
# 产物：dist/praetor-0.3.3-*.zip
```

UPX 自解压二进制可能与部分 Linux 内核、虚拟化环境或安全策略不兼容，因此默认不启用。可用 `PRAETOR_TARGETS` 自定义目标；确认目标运行环境兼容时，可显式传入 `--upx` 进一步缩小二进制：

```bash
PRAETOR_TARGETS=linux/amd64,windows/amd64 ./build.sh --release
./build.sh --target linux/amd64 --upx
```

### 方式六：环境变量配置（本地运行要重点看这里）

**二进制不会自动读 `.env`**（它只读 `config.json` 和进程环境变量），`docker compose` 才会自动读 `.env`。本地直接跑二进制时：

- **推荐**用 `./start.sh` / `start.bat`：脚本把 `.env` 里的 `PRAETOR_*` / `POSTGRES_*` 搬进环境，并从 `POSTGRES_PASSWORD` + `PRAETOR_PG_PORT` 自动组装 `PRAETOR_PG_DSN`。
- **手动配置**：`set -a; . ./.env; set +a` 只能带进 `.env` 里**已有的键**，而 `.env` 默认把 `PRAETOR_PG_DSN` 注释掉了 —— 所以还得自己 `export PRAETOR_PG_DSN=...`（或写好 `config.json`），否则仍会连不上库。
- 不确定读到了什么：先跑 `./praetor -check-config`，见上方「配置读不到时怎么自查」。

宿主机直接跑单二进制的最小配置：

```bash
# 1) 库：用 compose 里的 praetor-pg（宿主 55433），或任意 PostgreSQL
docker compose up -d postgres

# 2) 环境变量
export PRAETOR_PG_DSN='postgres://praetor:<POSTGRES_PASSWORD>@127.0.0.1:55433/praetor?sslmode=disable'
export PRAETOR_SANDBOX=required                  # 没有 Docker 时改 optional/off
export PRAETOR_SANDBOX_IMAGE=praetor/sandbox:latest
export PRAETOR_SANDBOX_WORK_ROOT="$PWD/data/work"   # 建议绝对路径
export ANTHROPIC_API_KEY='sk-...'                 # 或 OPENAI_API_KEY / 留空到 UI 里配

# 3) 启动（前端已内嵌）
./praetor -addr :8797
```

常用变量：

| 变量 | 作用 | 缺省 |
|---|---|---|
| `PRAETOR_PG_DSN` | 数据库连接串（优先于 `config.json`） | 读 `config.json` |
| `POSTGRES_USER/PASSWORD/DB` | compose 里 postgres 的账号与库名 | `praetor` / 必填 / `praetor` |
| `PRAETOR_HTTP_PORT` | 容器映射到宿主的 HTTP 端口 | `8797` |
| `PRAETOR_MCP_PORT` | 容器映射到宿主的 MCP 端口 | `8798` |
| `PRAETOR_DATA_DIR` | 宿主数据目录（jwt.key、工作区），必须是 bind mount 宿主目录而非命名卷名 | `./data` |
| `PRAETOR_SANDBOX_WORK_HOST_ROOT` | 覆盖自动推导的 `docker -v` 宿主源；仅远程 daemon 等非常规布局需要 | 空（自动推导） |
| `PRAETOR_SANDBOX_WORK_ROOT` | 仅宿主二进制部署：应用进程内的工作区根。compose 部署固定为 `/app/data/work`，忽略此值 | `<data>/work` |
| `PRAETOR_IMAGE` | 用外部镜像而不是源码构建 | 空（构建 `praetor/praetor:<tag>`） |
| `PRAETOR_TAG` | 本地构建的镜像 tag | `latest` |
| `PRAETOR_GOPROXY` | 构建时 Go 模块代理 | `https://proxy.golang.org,direct` |
| `PRAETOR_NPM_REGISTRY` | 构建时 npm 源 | `https://registry.npmjs.org` |
| `PRAETOR_MOUNT_DOCKER_SOCKET` | `1` = compose 带上 socket 覆盖层 | 由 `install.sh` 询问 |
| `PRAETOR_SANDBOX` | `required` / `optional` / `off` | `required` |
| `PRAETOR_SANDBOX_ISOLATION` | `per-task`（一任务一容器）/ `shared` | `per-task` |
| `PRAETOR_SANDBOX_IMAGE` | 沙箱容器镜像 | `praetor/sandbox:latest` |
| `PRAETOR_SANDBOX_NETWORK` | 打靶机时要接入的 docker 网络 | 空（默认 bridge） |
| `PRAETOR_LLM_PROVIDER/MODEL/BASE_URL/PROXY` | 覆盖 LLM 提供方、模型、网关、代理 | 空 |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` | 模型 API Key（也可在 UI 里配） | 空 |
| `PRAETOR_DOMAINS` | 启用的域，逗号分隔 | `pentest` |
| `PRAETOR_SUBAGENTS` | 允许派生 subagent 的域（`ctf,reverse` 或 `all`） | 关 |
| `PRAETOR_SAMPLE_KEY` | 逆向样本库密钥（64 位 hex，缺则报错，不降级明文） | 空 |
| `PRAETOR_HEXSTRIKE_DIR` | hexstrike MCP 目录 | 空（不注册） |

Windows 上不要写 `.env` 的 POSIX 语法到 `cmd`；`dev.sh` 与 `start.sh` 是 bash 脚本，
请用 Git Bash / WSL 执行。

---

## 更新升级

> 升级只换程序、不动数据：Postgres 数据卷 `pgdata`、`./data`（jwt.key / SQLite 等）、`./skills` 都会保留。**数据库迁移无需手动执行**——`praetor` 每次启动会幂等重跑 `schema.sql`（含 `ADD COLUMN` / `CREATE INDEX IF NOT EXISTS`），即“重启即迁移”。升级前仍建议先备份 `./data` 与数据库。

### 方式一：页面一键更新（推荐）

在 **系统配置** 页（侧边栏「系统配置」→ `/system/settings`）的**版本与更新**卡片里，可以直接检查并安装新版本，无需登录服务器。

点「更新」后：下载当前平台的发布包 → 比对 Release 的 `SHA256SUMS` → 用 `-h` 冒烟测试新二进制 → 暂存为 `praetor.new` → 程序退出，由 `start.sh` / `start.bat` 重新拉起并完成换装。页面会自动等到新版本上线后刷新。

- **失败不会留下坏程序**：校验或冒烟不通过就丢弃暂存件、继续跑当前版本；换装后的新版若连续 3 次启动失败，会自动回滚到 `praetor.old`（失败的那个留作 `praetor.failed` 供排查）。
- **随时可回退**：上一版本保留为 `praetor.old`，卡片上有「回滚到上一版本」。注意数据库结构不会回退。
- **更新会中断正在运行的任务**——更新即重启，请在空闲时进行。
- **开发构建不给更新**：版本号是 `dev` 或 `git describe` 带后缀时禁用，避免正式版覆盖掉本地调试的二进制。
- **Docker 下只换程序、不换镜像**：镜像里的 playwright / nmap 等工具链不会跟着升级，且 `docker compose up -d` 重建容器后会退回镜像自带的版本。要连镜像一起升级，用源码构建的部署执行 `docker compose build --pull praetor && docker compose up -d praetor`；用外部镜像的部署执行 `docker compose pull praetor && docker compose up -d praetor`。
- 访问 GitHub 需要代理时，在同一页面配置**全局代理**即可，更新链路会走它。更新只从 GitHub 域名下载并强制 HTTPS。

### 方式二：一键更新脚本

```bash
cd PRAETOR
./update.sh
```

脚本先可选 `git pull` 拉取最新代码，再让你选 **① Docker 更新** 或 **② 本地编译更新**（与 `install.sh` 对应）：

- **① Docker**：`git pull` 后**按当前代码重建镜像**（`docker compose build --pull`）再 `up -d`，重启即自动迁移；`.env` 设了 `PRAETOR_IMAGE` 时改为拉取该镜像。
- **② 本地**：重建前端静态产物 → 重新编译 `./praetor`（完成后重启进程生效）。

### 方式三：Docker Compose（手动）

```bash
cd PRAETOR
git pull                          # 更新 compose / 脚本 / 源码
docker compose build --pull praetor   # 按当前代码重建镜像（改了代码就走这一句）
docker compose up -d praetor          # 换新镜像重启 → 自动迁移 schema
docker image prune -f                 # 清理旧镜像（可选）
```

用的是外部镜像（`.env` 设了 `PRAETOR_IMAGE`）时，第 2 步换成：

```bash
docker compose pull praetor
```

### 方式四：预编译二进制（Releases）

到 [Releases](https://github.com/jintilm/PRAETOR/releases) 下载新版本 zip，停掉旧进程后覆盖 `praetor` 与 `skills/`（保留你的 `config.json` 与 `data/`），重启即可：

```bash
cp -r <解压目录>/skills ./ && cp <解压目录>/praetor ./
./start.sh
```

### 方式五：从源码编译

```bash
git pull
cd web && npm ci && npm run build:static && cd ..
cp -r web/out server/webui/dist
CGO_ENABLED=0 go build -tags embedui -o praetor ./cmd/praetor
# 重启 ./start.sh
```

---

## 卸载与清理

`./uninstall.sh` 是 `install.sh` 的逆操作，**默认只停服务、不删任何数据**：

| 档位 | 做什么 | 数据 |
|---|---|---|
| `1` 仅停止（默认） | `docker compose down --remove-orphans` | 全部保留 |
| `2` 清构建产物 | 停服务 + 归档二进制、`web/out`、`web/node_modules`、`server/webui/dist`、`dist/`、升级暂存件 | 全部保留 |
| `3` 彻底卸载 | 备份 + `pg_dump` → `compose down -v` → 删本栈镜像 → 归档本地状态 | **数据卷删除，靠备份恢复** |
| `4` 仅备份 | 复制配置 / 密钥 / `data/` + 导出数据库 | 不删任何东西 |
| `0` 取消 | 无操作 | — |

```bash
./uninstall.sh                    # 交互菜单，直接回车 = 档位 1
./uninstall.sh --dry-run --mode=3  # 只打印档位 3 会动什么，零改动
./uninstall.sh --mode=4            # 升级 / 迁移前先做一份备份
./uninstall.sh --backup-dir=/path/to/backups
```

档位 3 会先列出**每一个将被移动的文件路径**和要删的 Docker 资源，要求输入 `DELETE`
确认；若 `pg_dump` 失败，还要再输入 `I-UNDERSTAND` 才继续。取消不会留下任何改动。

**备份目录**默认 `./backups/uninstall-<时间戳>-<pid>/`（已加进 `.gitignore`，权限 700）：

```text
MANIFEST.txt         # 备份内容、恢复命令、未清理项清单
praetor-pg.sql       # pg_dump --clean --if-exists（数据库容器在跑时才生成）
pg_dump.err          # 导出失败时的错误
state/               # 档位 4 的副本，原件不动
removed/             # 档位 2/3 移出的文件，按原相对路径存放
```

本地文件一律**移动**到 `removed/` 而不是 `rm`，按原路径移回即可回滚，例如
`mv backups/uninstall-*/removed/.env ./.env`。数据库卷 `praetor-pgdata` 由 Docker 删除，
只能靠 `MANIFEST.txt` 里的 `psql < praetor-pg.sql` 恢复。

**脚本刻意不碰**（避免误伤其它部署）：靶场网络 `praetor-ctf` / `chal-*`、
`docker:27-cli` 等构建镜像、`.workbuddy/`、`docs/`、`skills/`、`.tok`、
`.playwright-mcp/`，以及宿主机上正在运行的 `praetor` / `praetor.exe` 进程。
它也不执行任何 `docker prune` 通配删除；只处理 compose 项目 `praetor`、
`praetor-task-*` 任务容器、`praetor-pgdata` / `praetor-pg` 卷和
`praetor/praetor:*` / `praetor/sandbox:*` 镜像。

> 用 `./start.sh` / `praetor.exe` 在宿主机跑二进制的部署，卸载前请先自行停止进程；
> 脚本不会 kill 进程，避免误杀同名进程。

---

## 配置

**数据库**（`config.json`，或用环境变量 `PRAETOR_PG_DSN` 覆盖）：

```json
{
  "database": {
    "host": "127.0.0.1", "port": 5432,
    "user": "praetor", "password": "yourpass",
    "dbname": "praetor", "sslmode": "disable"
  }
}
```

**LLM**：`export ANTHROPIC_API_KEY=sk-...`（或 `OPENAI_API_KEY`），也可在 UI 的「LLM 配置」页填写。
可选：`PRAETOR_LLM_PROVIDER` / `PRAETOR_LLM_MODEL` / `PRAETOR_LLM_BASE_URL` / `PRAETOR_LLM_PROXY`。

### 修改已部署实例的数据库密码

> ⚠️ 数据卷 `praetor-pgdata` 一旦初始化，postgres 官方镜像**只在首次初始化时读** `POSTGRES_PASSWORD`。只改 `.env` 不会改库里的密码，重启后应用会报密码认证失败 —— 别被「改完重启生效」这种说法带偏。

两步，顺序不能反：

```bash
# 1) 先改库内密码（容器在跑）
docker exec -it praetor-pg psql -U praetor -d praetor \
  -c "ALTER USER praetor WITH PASSWORD '新密码';"

# 2) 再同步 .env，并只重建应用容器（postgres 不必重建）
grep -v '^POSTGRES_PASSWORD=' .env > .env.tmp
printf 'POSTGRES_PASSWORD=%s\n' '新密码' >> .env.tmp && mv .env.tmp .env
docker compose up -d --force-recreate praetor
```

新密码同样只允许字母数字与 `. _ - ~`。若还没有任何数据（`down -v` 后重装），直接改 `.env` 再 `up -d` 即可。



**扩展能力**（均可选，缺省关闭；完整清单见 [.env.example](.env.example)）：

| 变量 | 作用 |
| --- | --- |
| `PRAETOR_SUBAGENTS` | 子 agent 派生灰度（`ctf,reverse` 域列表 / `all` / 空=关） |
| `PRAETOR_SANDBOX` / `PRAETOR_SANDBOX_NETWORK` 等 | 每任务容器沙箱与靶机网络 |
| `PRAETOR_SAMPLE_DIR` / `PRAETOR_SAMPLE_KEY` | 逆向样本库目录与加密密钥（64 位 hex） |
| `PRAETOR_CALDERA_URL` / `PRAETOR_CALDERA_KEY` | 红队 Caldera 编排（`caldera_operation`：列 ability / 下发 / 回收） |
| `PRAETOR_RE_DYNAMIC` | 动态执行总闸：`trace` 配方会真的运行样本，默认拒绝 |

**并发**：每个任务的 work agent 数在「系统设置」里配置（默认 3）。

**常用参数**：`./start.sh -addr :8787 -proxy :8788`（`-addr` 前端+API，`-proxy` 流量录制代理）。启动脚本会把参数原样透传给 `praetor`。

> ⚠️ 监听地址是 `-addr` **参数**，不是 `.env` 里的端口变量。用 `-addr :8797` 启动就必须访问 `:8797`；默认是 `:8787`。

### Windows 上的 Bash（需要 POSIX shell）

工具名虽然叫 `Bash`，但它要的是 **POSIX shell**。Linux/macOS 上 `/bin/sh` 就是，不用管；**Windows 上必须装 Git for Windows 或 MSYS2**，否则 `Bash` 会退化成 PowerShell，`2>/dev/null`、`$?`、`&&`、heredoc 这些语法一条都跑不了。

不需要手工配路径——启动时按这个顺序自动找，找到即用：

1. `PRAETOR_HOST_SHELL`（显式指定，优先级最高）
2. `PATH` 上的 `bash.exe`
3. 由 `PATH` 上的 `git.exe` 反推（向上两三层找 `bin\bash.exe` / `usr\bin\bash.exe`，覆盖 Git for Windows、PortableGit、MSYS2 各种布局）
4. `PATH` 上的 `sh.exe`
5. 固定安装点：`%ProgramFiles%\Git`、`%ProgramW6432%\Git`、`%ProgramFiles(x86)%\Git`、`%LOCALAPPDATA%\Programs\Git`、`%SystemDrive%\msys64`

`C:\Windows\System32\bash.exe`（WSL）会被**主动拒绝**——它解析不了 `E:\...` 这类 Win32 路径，用它比用 PowerShell 更糟。

启动日志里有一行能直接看出选了谁、为什么：

```
[shell] 宿主 shell: C:\Program Files\Git\bin\bash.exe [-c] ← 固定安装点 %ProgramFiles%\Git
```

看到 `← 回退：未找到可用的 POSIX shell` 就说明没装 Git Bash，同一条日志下面会跟一条带修复动作的警告。改完重启即可，不用重建二进制。

### 反向代理部署（HTTPS / 只开放 443）

前端和 API/SSE 都由同一个后端端口（默认 `:8787`）提供，实时活动流默认走**同源**地址，因此**无需配置 `NEXT_PUBLIC_SSE_BASE`**，公网只开放 443、把 8787 留在内网即可。

SSE 是长连接 + 持续推送，反代**必须关闭缓冲**，否则浏览器能连上却收不到事件（表现为活动流一直转圈）。Nginx 示例：

```nginx
server {
    listen 443 ssl;
    server_name your.domain.com;
    # ssl_certificate / ssl_certificate_key ...

    location / {
        proxy_pass http://127.0.0.1:8787;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;

        # SSE 关键项：关缓冲、长超时、HTTP/1.1
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 3600s;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }
}
```

> 仅当 SSE 需要走与页面不同的来源（如独立子域）时，才在**构建期**设置 `NEXT_PUBLIC_SSE_BASE`（该变量在 `next build` 时固化进静态包，容器运行时再设无效）。

---



## 开发

### 手动漏洞复测

任务详情的「复测」页签可分页选择本任务的漏洞、查看历次结论和证据，并手动发起复测。启动后保留当前页签，显示转圈图标和「复测中」；确认修复后同步更新漏洞状态。

在漏洞列表每行操作区点击「复测」，或在漏洞详情的「漏洞复测」区域点击「发起复测」，填写可选的修复版本、测试条件或限制，系统会创建独立的复测 Agent 会话，启动后保留当前页面。列表的平铺、按任务分组和资产视图均支持该入口；复测运行时显示转圈图标和「复测中」，需要查看时点击进入对应会话，结束后恢复「复测」。复测无需重新启动原扫描任务，结论分为「仍可复现」「已修复」「无法确认」，每次的结论、证据和会话链接保存在漏洞详情中。

新版后端首次启动会预置可编辑的「漏洞复测」（`retester`）Agent，可在 Agent 管理中配置提示词、LLM、运行预算和工具。默认使用其绑定的 LLM，未绑定则使用全局激活配置。复测会话成功完成且结论为「已修复」时，系统自动将漏洞处置状态改为「已修复」；执行中、失败、停止或其他结论保留原状态。原始证据和报告始终保留。也可在状态下拉菜单中手动选择「已修复」。同一漏洞正在复测时复用已有会话，停止、失败或服务重启后可重新发起。

本版历史记录通过漏洞详情和会话查看，暂未纳入漏洞报告导出或任务归档包，也未自动关联流量包。演示模式只生成明确标注的模拟记录，不请求真实目标。

### 本地运行与测试

```bash
./dev.sh    # 后端(:8787) + 流量代理(:8788) + 前端 next dev(:5173) → http://localhost:5173
```

- 后端：`go run ./cmd/praetor`（不带 `-tags embedui` 则不内嵌前端）
- 前端：`cd web && npm run dev`（`/api` 反代到后端，带热更新）
- 测试：`./scripts/gate.sh`（带 DB 全量口径，输出通过/失败/跳过三数；`--db` 要求 DB 用例真跑）。**测试源码不随本仓库发布**（`*_test.go` 与 `agent/testdata/` 在 `.gitignore` 里，仅保留在开发者本机），所以克隆后 `go test ./...` 不会有任何用例。**注意别在 source 过 `.env` 的 shell 里跑 `go test ./server/`**——会真调模型并产生脏容器；`gate.sh` 用 grep 取值就是为了避开这个
- Mock 预览（无后端）：`cd web && NEXT_PUBLIC_MOCK=1 npm run dev`

---

## 系统技术架构

PRAETOR 是一套 **LLM 多 agent 驱动的自主渗透系统**：Go 单体后端（内嵌 Next.js 前端）+ PostgreSQL，agent 运行时引擎内联自 [`norma`](https://github.com/Autumn-27/norma) v0.4.3（Apache-2.0，源码在 `internal/norma/`，见其 `NOTICE.md`）（`agentcore` / `tool` / `permission` / `harness` / `memory` / `transcript`）。核心是**双图架构**，以及围绕它的两条自主性机制：**worker 间过程级信息交换**与 **planner 多轮共享 todolist 稳定攻击链路**。

### 总体分层

```mermaid
flowchart TB
  subgraph FE["前端 Next.js（go:embed 内嵌单二进制）"]
    UI["仪表盘 · 任务 · 资产 · 覆盖图 · 流量 · 工作空间 · 系统配置"]
  end
  subgraph SRV["server（Go net/http）"]
    API["REST /api/*　JWT 鉴权　SSE"]
    ENG["engine 调度循环"]
    MGR["Manager　任务/引擎/store 生命周期"]
  end
  subgraph AG["agent（norma SDK）"]
    GO["goals　目标分解 + 提取范围"]
    PL["planner　规划者（唯一意图生成者）"]
    WK["worker　执行者 ×N"]
    MA["mainagent　人在环路"]
  end
  subgraph DB["PostgreSQL"]
    AGRAPH["资产图　assets / companies / task_scope"]
    EGRAPH["探索图　exploration_nodes / anchors / activity"]
  end
  subgraph SUB["支撑子系统"]
    PROXY["流量记录代理　MITM + CA 留痕"]
    GUARD["guard / intercept　工具审批门"]
    ENR["enrich　DNS / HTTP 异步补全"]
    EXT["MCP · skills · memory · report"]
  end

  UI -->|HTTP| API
  API --> MGR --> ENG
  ENG --> PL
  ENG --> WK
  API --> MA
  API --> GO
  PL --> DB
  WK --> DB
  MA --> DB
  GO --> DB
  WK -->|"Bash / HTTP 全程留痕"| PROXY
  WK --> GUARD
  WK --> ENR
  PL -.-> EXT
  WK -.-> EXT
  MA -.-> EXT
```

| 层 | 职责 |
| --- | --- |
| **前端** | Next.js 静态导出，`go:embed` 内嵌进单二进制；可视化任务/资产/探索链路/覆盖图，人在环路对话 |
| **server** | `net/http` 路由 + JWT 鉴权 + SSE；`Manager` 托管任务、引擎、DB store 的生命周期 |
| **engine** | 每任务一个 `plannerLoop` + N 个 worker goroutine；意图领取、超时/暂停/drain |
| **agent** | goals / planner / worker / mainagent，`ToolSet` 把双图暴露成 LLM 工具；`agent/domain` 按任务领域（渗透/CTF/逆向/红队）注入专属工具、角色表与调度语义 |
| **db** | 双图的 Postgres 落地（pgx）；schema 随 `go:embed` 每次启动幂等建表 |
| **支撑** | 记录型 MITM 代理、审批门、异步补全、MCP/技能/记忆/报告 |

### 双图架构：探索图 + 资产图

系统把「**目标是什么**」和「**测到了什么程度**」拆成两张相互独立、又通过锚点相连的图：

- **资产图（Asset Graph，全局共享）**：跨任务同一份的资产真值库。节点为 `root_domain / subdomain / ip / service / app / endpoint`，归属公司；域名→子域→服务→端点的父子关系与去重 key 全部由程序计算，agent 只提交原始信息。
- **探索图（Exploration Graph，每任务独立）**：一次任务的“思考与推进”过程。节点为 `goal（目标）/ intent（意图）/ fact（事实）/ finding（漏洞）/ hint（提示）`，靠 `spawns / derived_from / yields / proves` 等边连成**血缘链**，回答“哪个方向派生自哪些事实、产出了什么”。
- **两图靠锚点相连**：`exploration_anchors(node_id, asset_id)` 把意图/事实/漏洞锚定到具体资产上——于是既能从“探索方向”看它打的是哪些资产，也能从“某个资产”反查它在本任务被哪些意图测过、得出过哪些事实。这也支撑了**资产测试覆盖度**与**资产覆盖图**（范围内资产 + 已测高亮）。

```mermaid
flowchart LR
  subgraph EG["探索图（每任务独立 · 推进链）"]
    direction TB
    G["goal 目标"]
    I1["intent 意图 A"]
    F1["fact 事实"]
    I2["intent 意图 B"]
    FD["finding 漏洞"]
    G -->|spawns| I1
    I1 -->|yields| F1
    F1 -->|derived_from| I2
    I2 -->|proves| FD
  end
  subgraph AG["资产图（全局共享 · 真值库）"]
    direction TB
    RD["root_domain"]
    SD["subdomain"]
    SV["service"]
    EP["endpoint"]
    RD --> SD --> SV --> EP
  end
  I1 -. anchor .-> SD
  F1 -. anchor .-> SV
  I2 -. anchor .-> EP
  FD -. anchor .-> EP
```

> 分工：**planner** 读探索图态势、判目标、只在有未覆盖的新方向时派**意图**进 frontier；**worker** 领**一条意图**、用真实工具执行、把新资产/事实/漏洞写回两图后即停。资产图是共享事实，探索图是每任务的推进链。

### 引擎与意图生命周期（一次探索的闭环）

引擎是**事件驱动**的闭环：图一变就唤醒 planner，planner 派意图，worker 领意图执行并写回，写回又触发下一轮——直到目标被证明（`prove_goal`）。

```mermaid
sequenceDiagram
  autonumber
  participant EV as 图变更 debounce
  participant P as planner
  participant FR as frontier 意图队列
  participant W as worker
  participant PX as 记录代理
  participant DB as 双图 + activity

  EV-->>P: 唤醒
  P->>DB: 读态势(graph_overview 预取 + coverage/scope)
  P->>FR: 派 0..N 个意图(带 asset_ids)
  Note over P,FR: 大多数唤醒派 0 个——无新方向即结束
  W->>FR: claimNext 领一条意图
  W->>DB: 取意图 asset_ids 的原始资产作为初始信息
  W->>PX: 真实工具执行(Kali / Bash / HTTP)
  PX-->>W: 响应(全程留痕 + CA 验证)
  W->>DB: 写回 fact / asset / finding + 每步 activity
  DB-->>EV: 图变更
  EV-->>P: 再次唤醒(闭环)
```

### worker 间的过程级信息交换

一次深入的探索里，很多有价值的观察（某个报错、某段响应、某个隐藏参数）出现在一个 worker 的**执行过程**中，却未必被写成正式 fact。为避免重复劳动、让链路上的 worker 能站在彼此的肩膀上，worker 具备**跨 work 检索过程**的能力：

- `search_all_worker_traces(q)`：在**本任务其他 work 的执行过程**里按关键字检索（自动排除自己这条意图的步骤），命中项带 `intent_id`；
- `list_worker_traces` / `get_worker_trace(intent_id, step_ids=[…])`：先看有哪些 work 跑过，再取某个 work 具体几步的完整内容做细节交换。

这样即便探索图上还没有对应的 fact，后续 worker 也能复用他人过程中的观察——**信息在 worker 之间以“执行过程”为粒度流动**，而边界不变（每个 worker 仍只做自己领到的那条意图）。

```mermaid
flowchart LR
  WA["worker A（意图 #12）"] -->|"每步 activity"| ACT[("探索图 · activity 过程库")]
  WB["worker B（意图 #34）"] -->|"每步 activity"| ACT
  WC["worker C（意图 #56）"] ==>|"1) search_all_worker_traces(q)"| ACT
  ACT ==>|"2) 命中 A/B 的步骤（排除自己）"| WC
  WC ==>|"3) get_worker_trace(id, step_ids)"| ACT
  ACT ==>|"4) 返回完整过程内容"| WC
```

### planner 多轮共享 todolist → 稳定的攻击链路

真实攻击链往往是**有前后依赖的多步序列**（如：发现注入点 → 拿到凭据 → 横向 → 提权），一次性把这些并行派下去只会乱套。planner 因此持有一份**按任务保留、跨唤醒共享的规划待办（todolist）**：

- planner 是事件驱动的——图一变就被唤醒，但**每次唤醒是全新会话**；共享的 todolist 让它把一条串行利用链**记录一次**、然后在后续多轮里**按依赖逐步派意图**，而不是把整条链在一轮里全部前置展开；
- 每轮只对「前置步骤已完成、其依赖的 fact 已存在」的下一步派意图，并随进展更新清单（把已被 fact 满足的步骤标完成）。

```mermaid
flowchart TB
  subgraph TODO["共享 todolist（按任务保留 · 跨唤醒常驻）"]
    direction LR
    T1["1 注入点　[已完成]"]
    T2["2 取凭据　[进行中]"]
    T3["3 横向　[待前置]"]
    T4["4 提权　[待前置]"]
    T1 -.前置满足.-> T2 -.-> T3 -.-> T4
  end
  R1["第 1 轮唤醒　派意图①"] --> T1
  R2["第 2 轮（①产出 fact）　派意图②"] --> T2
  R3["第 3 轮（②产出 fact）　派意图③"] --> T3
```

于是攻击链在“事件驱动 + 无状态会话”的环境下依然**稳定推进、不重复、不错序**——这是 PRAETOR 能自主走完多步利用链的关键。

---

### 任务领域与子 agent

`agent/domain` 把「平台机制」与「领域语义」分开：平台提供双图、调度循环、审批门、预算闸门；领域包只声明自己的工具面（≤3 个自研工具为设计纪律）、角色表（RoleSpec：提示词 + 工具白名单 + 预算）与调度器拓扑。新增一个领域不改引擎。

```mermaid
flowchart LR
  subgraph DOM["任务领域（tasks.domain）"]
    PE["pentest 渗透 · explore 并发"]
    CT["ctf 靶场 · race 延迟竞速"]
    RE["reverse 逆向 · evidence 串行"]
    RT["redteam 战役 · campaign 阶段闸门"]
  end
  ENG["engine 调度循环"] --> DOM
  CT -.->|Agent 工具| SV["solver-web/pwn/rev/... 独立上下文"]
  RE -.->|Agent 工具| AN["re-analyst 串行验证假设"]
  SV -->|record_fact / ctf_submit| EG2[("探索图")]
  AN -->|re_evidence| EG2
```

灰度开关 `PRAETOR_SUBAGENTS`（默认关）按域启用派生后，CTF 的 lead 可把题目派给按题型定制的 solver、逆向的 lead 把假设验证派给 analyst——每个子 agent 独立上下文，lead 不被单题/单假设的过程记录撑爆；产物经共享工具集归口回发起意图，过程镜像进 activity 流。渗透/红队刻意不接（planner/worker 与战役闸门已是既定秩序）。

---

## 交流群

扫码关注微信公众号 **SecSentry**，在公众号后台私信即可入群交流。

<div align="center">

<img src="screenshots/wx.png" alt="微信公众号 SecSentry" width="480" />

</div>

---
## 参考

https://github.com/oritera/Cairn


## 许可与免责声明

### 开源协议

本项目采用 **GNU Affero General Public License v3.0（AGPL-3.0）** 授权，完整条款见仓库根目录的 [LICENSE](LICENSE) 文件。

这意味着任何人都可以自由使用、修改和分发本项目，但**衍生作品必须同样以 AGPL-3.0 开源**；特别地，**若你修改本项目并通过网络（如部署为在线服务）向用户提供，也必须向这些用户公开对应的完整源码**。

> ⚠️ **重要提示**：开源协议本身不限制软件的使用用途。以下的「使用限制」与「免责声明」是作者对使用者的额外约定与郑重声明，请务必遵守。

**PRAETOR 仅供个人学习、代码研究与本地技术验证使用，不得用于对任何线上系统或网站发起实际测试。**

### 允许使用范围

- 仅可用于**阅读、学习与研究本项目源码**，以及在**本地隔离环境**中进行技术原理验证；
- 适用于个人学习、学术研究、代码审阅等非攻击性用途。

### 禁止事项

- **严禁使用本工具对任何网站、线上服务或联网系统发起扫描、探测、利用或攻击**（无论是否获得授权、是否为自有资产）；
- 严禁将本工具用于任何实际的渗透测试、攻防对抗或生产环境；
- 严禁将本工具用于非法入侵、数据窃取、勒索、拒绝服务或任何破坏性、犯罪性活动；
- 严禁利用本工具从事违反所在国家/地区法律法规的行为。

### 合规责任

使用者须自行遵守所在国家/地区关于网络安全、数据保护与计算机犯罪的全部法律法规（在中国大陆包括但不限于《网络安全法》《数据安全法》《个人信息保护法》及相关司法解释）。**因使用本工具产生的一切法律责任与后果，均由使用者自行承担。**

### 免责声明

本项目按“现状（AS IS）”提供，不附带任何明示或默示的担保。作者及贡献者不对使用本工具（无论使用方式是否得当）所导致的任何直接或间接损失、数据丢失、系统损坏或法律纠纷承担责任。**下载、安装或使用本项目，即表示你已阅读、理解并同意上述全部条款。**
