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

渗透与红队任务下发前必须有可解析的测试范围：目标 URL、域名、IP/CIDR，或已关联企业。范围缺失会直接返回 400；CTF 与逆向不受此限制。操作者不需要写命令级步骤，只需把授权边界、目标、成功标准和硬约束说清楚。

### 子 agent 派生（灰度开关）

CTF 与逆向域的 worker 即领域 lead，可通过 `Agent` 工具把「解一道题」「验证一条假设」派给**独立上下文**的子 agent（CTF：web/pwn/rev/crypto/forensics 五个 solver；逆向：re-analyst）。子 agent 继承父的沙箱视角（容器路径映射、写白名单）、任务级 guard 策略、输出目录与独立 sidechain transcript，产物经共享工具集归口回本意图；中间过程镜像进 activity 流（UI 可见，带 `agentType:` 前缀）。这些角色在 **Agent 管理**页可见为一等 agent（role=specialist）：提示词可编辑（DB 权威，代码默认兜底）、可单独绑定 LLM 配置（如逆向 analyst 走本地模型）。逆向域的结论经 `re_evidence` 以**证据节点**落探索图（claim/ref 硬校验），任务详情的探索链路图对 evidence 类型有专属渲染。默认关闭，`PRAETOR_SUBAGENTS=ctf,reverse` 按域灰度开启。

### 漏洞知识库

「功能 → 漏洞知识库」把**已验证 finding** 自动沉淀为候选漏洞模式。候选不会直接进入模型上下文，必须在 UI 中补齐测试步骤、预期信号和误报检查并审核启用；启用后 planner/worker 可通过只读 `search_vuln_knowledge` 工具按技术栈、漏洞类别或关键词检索最多 5 条。

- 只从 `verification_state=verified` 且不是误报/重复/忽略的 finding 生成候选。
- 知识条目保留来源 finding、任务、CWE、技术栈、置信度、版本和使用计数，不复制完整请求体、凭据或样本。
- 启动时会幂等补扫历史 verified findings；也可在页面点「补扫已验证漏洞」。
- 当前不导入 CVE/nuclei/第三方 exploit 仓库；后续导入也必须带许可证、来源、预期信号和误报检查。
- 候选、停用条目永远不会被 agent 检索。模型只能读取，不能修改或晋升全局知识。
- 评测或基准任务应设 `PRAETOR_VULN_KB=off`，避免历史知识抬高分数或形成跨题泄漏。

### 每任务沙箱

开启后每任务一个一次性 Docker 容器（`PRAETOR_SANDBOX=required` + 隔离档位）：

- **全量出口隐身**（配置全局出口代理后自动生效）：容器全部出站 TCP 在 IP 层重定向到出口代理（iptables + redsocks）——不依赖环境变量，Go 工具、nmap `-sT` 等不读代理变量的程序同样被覆盖；本地网段（RFC1918）直连以保证内网靶场可达；
- **任务级出口池（IP 隔离，可选）**：设置页可配多个上游（mihomo 多 listener / gost / 商业隧道均可），按任务稳定分配（hash，同一任务重建容器不换出口，会话不漂移），不同任务出口互相隔离；不配则回落全局出口代理；
- **隐身边界（如实说明）**：SYN 扫描（`-sS`/masscan）承载不了——代理只能传 TCP，隐身语义下用 `-sT`，需要真 SYN 扫描走自建 WireGuard 出口；DNS 默认经宿主解析（上游用 mihomo/Clash 时可把容器 DNS 指向其 DNS 监听解决）；
- Bash 在容器内执行；文件工具（Read/Write/LS/Glob/Grep）跑在宿主进程，内置**容器路径 → 宿主路径**翻译与**写白名单**（只有工作挂载可写，题面挂载只读，未挂载路径一律拒绝）；
- 边界校验在解析符号链接后用真实路径重比，越界按「路径不存在」处理（fail closed）；
- 启动时扫描并清理本部署上次遗留的任务容器（按挂载源归属判断，不误删别的部署）。

### 代理池（目标流量出口）

「系统 → 代理池」把目标流量出口从“单一全局代理”扩展成可自动维护的代理池，默认开启（`route_mode=pool`）。它只作用于**目标流量**（沙箱出口与流量代理上游），不接管 LLM 网关 `PRAETOR_LLM_PROXY`、模型侧 `web_search_proxy`，也不改写宿主进程的 `HTTP_PROXY/HTTPS_PROXY`。

- **路由优先级**：任务级 `egress_upstreams` > 代理池健康代理 > 系统代理（设置页全局出口）> 直连。任务级配置永远最高，不会被代理池覆盖。
- **三种路由模式**：`pool`（默认，池内有健康代理即走池）/ `system`（始终用系统代理）/ `direct`（始终直连）；池空时按 `fallback_mode` 回落 `system` 或 `direct`，不会“池空即断网”。
- **自动采集**：启动后首次延迟约 1 分钟，之后按 `collect_interval_minutes` 抓取内置公开来源（proxifly 全球与 **CN 分区**、TheSpeedX / monosans、`proxy.scdn.io` 全球与 **CN API**、Proxy5 JSON 快照）；UI 可增删来源、手动抓取或粘贴导入，支持 `http` / `https` / `socks5`。来源可直连抓取，也可勾选「来源经系统代理」以应对 GitHub 不可直连的网络。快代理页面来源已预置但默认关闭：它当前会对非浏览器请求返回 JavaScript 验证页。
- **自动健康检查**：按 `check_interval_minutes` 并发探测（默认 `https://api.ipify.org`，可改 `probe_url`），记录延迟、成功率与评分；连续失败达到 `failure_threshold` 自动隔离，恢复后自动回到可用。单条可手动检测。
- **容量与并发**：`max_entries` 控制池上限，`concurrency` 控制探测并发，`timeout_seconds` 控制单次探测超时。每次采集按启用来源数分配单来源导入配额，避免超大列表挤占其它来源；超限时只淘汰非健康条目，健康代理不会被容量清理删除。
- **热更新**：选中的健康代理通过 `reapplyEgressAgents` 同步到运行中的任务与流量代理，无需重启任务。
- **可观测**：UI 展示条目总数 / 启用 / 健康 / 隔离异常、最近采集与检测运行记录、当前选中代理与当前有效出口；API 为 `/api/proxy-pool*`，条目与来源 URL 均脱敏输出。
- **风险提示**：公开代理不可信，可能记录、篡改或注入流量；只用于授权测试中的出口隔离，不要承载凭据或敏感数据。生产场景优先自建出口（mihomo / gost / 商业隧道）。

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

> 端口不是笔误：容器内固定监听 8787，宿主映射由 `PRAETOR_HTTP_PORT` 决定（默认 **8797**）；直接跑二进制时监听 **8787**。

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

#### MCP 连接方式

「系统 → MCP」支持三种传输：

- `stdio`：配置命令和参数，由应用进程启动子进程。
- `http`：Streamable HTTP，适合远程 MCP 或带鉴权的网关。
- `sse`：旧版 SSE，先 `GET` 建立事件流，再通过服务返回的
  `?sessionId=...` 或 `/message` 端点发送 JSON-RPC。

远程服务需要鉴权时，把请求头写进 MCP 的 `env`，例如
`{"Authorization":"Bearer <token>"}`。全 Docker 部署不要把宿主机地址写成
`127.0.0.1`，那指向应用容器自身；使用 `host.docker.internal`。

Burp 官方 MCP 扩展当前使用 **legacy SSE 根路径**，不是 `/sse`。宿主机确认端口后，
在 MCP 页面配置：

```text
transport: sse
url:       http://host.docker.internal:9876/
env:       {"Host":"localhost:9876"}
```

Burp 会校验 Host 头；没有 `Host` 覆盖时可能需要 403。宿主机可先用
`curl -i http://127.0.0.1:9876/` 验证 SSE，再刷新 MCP 工具列表。

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
| `PRAETOR_LLM_LOCAL_ONLY` | 环境变量直连的模型是否为本地/私有部署；LocalOnly 领域只接受已标记配置 | `0` |
| `PRAETOR_VULN_KB` | 漏洞知识检索总开关；`0/off` 关闭（评测建议关闭） | `1` |
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

本地/私有部署的模型要在 UI 的 LLM 配置里勾选「本地部署 · LocalOnly」；环境变量直连时用 `PRAETOR_LLM_LOCAL_ONLY=1`。逆向域要求 LocalOnly 模型，绑定云配置会被拒绝，故障转移也不会切到云端。

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
| `PRAETOR_RE_DYNAMIC` | **只管逆向域 `trace` 配方**（gdb 真的运行二进制样本），默认拒绝；与 Android 真机授权互不替代，不能拿它当设备动态的总闸 |
| `PRAETOR_MOBILE_DEVICE_MODE` / `PRAETOR_TRAFFIC_ADDR` / `PRAETOR_TRAFFIC_BIND` | Android 真机接入三件套：显式设备模式 + 容器内代理监听 + 宿主端口绑定，默认全关/全回环 |
| `PRAETOR_MOBILE_ADB_HOST` / `PRAETOR_MOBILE_ADB_PORT` / `PRAETOR_MOBILE_DEVICE_EXCLUDE` | 宿主 adb server 落点与 egress 直连白名单（设备 IP / adb 5037 / frida 27042） |

**并发**：每个任务的 work agent 数在「系统设置」里配置（默认 3）。

**常用参数**：`./start.sh -addr :8787 -proxy :8798`（`-addr` 前端+API，`-proxy` 流量录制代理）。启动脚本会把参数原样透传给 `praetor`。

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



## 报告输出模板

创建任务时可在「新建任务」抽屉里选**报告输出模板**，选定后写入 `tasks.report_template`；报告页与发现页导出时也能临时切换（只影响本次请求，不落库）。优先级：`?template=` 显式覆盖 > 任务的 `report_template` > `praetor`。

| 模板 | 适用场景 | 标题规则 | 粒度 |
| --- | --- | --- | --- |
| `praetor`（默认） | 项目原有 Markdown 报告 | `# [SEV] 漏洞名` | 任务级汇总 / 单漏洞 |
| `butian` | 补天公益 SRC 事件型表单 | 「单位名称 + 存在 + 漏洞类型 + 漏洞」 | 一漏洞一提交 |
| `edusrc` | 教育漏洞报告平台 | **只填单位名称**；标题公开可见，禁止写系统名/漏洞名 | 一漏洞点一份 |

三套标题规则互不相同、补天与 edusrc 甚至相反，因此标题生成器按模板独立实现，不做统一。

### 字段来源与待补项

补天字段按提交页截图固化：厂商名称\*、域名或IP\*、漏洞类别（Web漏洞 / IOT漏洞）、漏洞标题、漏洞URL\*、漏洞类型（事件型 / 通用型）、细分类型联动下拉（XSS / 配置错误 / 弱口令 / 入侵事件 / 疑似被黑 / 文件上传 / 信息泄露 / 存在后门 / 逻辑漏洞 / 代码执行 / 命令执行 / SQL注入 / 解析漏洞）、漏洞等级、参与活动/任务、简要描述\*、详细填写\*、附件、修复方案、行业所属（国民经济行业门类）、所属地区（省 / 市 / 区三级）。edusrc 按官方 10 字段输出：标题 / 分类 / 等级 / 漏洞单位 / 开发方 / 资产所在网段 / 是否需要账号认证 / 漏洞URL / 内容 / 附件。

模板只做「字段映射 + 章节布局 + 待补项清单」，不编造数据。项目已有的：名称、类别、等级、描述、证据、单位名（`tasks.company_ids → companies.name`）、资产主域名、漏洞 URL、截图附件；从 `report` 自由文本里按标题切出复现步骤 / 影响 / PoC / 修复建议。平台要求但项目不自动生成或自动判定的：归属证明截图、首页截图、复现视频、开发方、资产网段、行业所属、省市区、复测账号、平台分类/权重/活动 —— 仍输出「待补充」占位，不自动代选下拉项。`md-zip` 会额外附一份 `_提交清单.md`，逐份列待补项。补天「简要描述」有表单硬约束「请勿在此填写漏洞URL等其他漏洞信息」，模板会主动剔除摘要里的 URL。

### 漏洞截图附件

漏洞详情页的「证据附件」支持上传 PNG / JPEG，并按 finding 持久化：

- 单张上限 20 MiB，单个 finding 总量上限 100 MiB。
- 可标记为「页面截图」或「Burp 截图」，填写用途（正常对照 / 漏洞证明 / 补充验证 / 辅助证据）和说明。
- 支持缩略图、原图预览、下载、排序、编辑和删除；继承出来的 finding 只读。
- Agent 可通过 `attach_finding_attachment` 绑定当前任务工作区中的截图。
- Playwright MCP 返回的图片内容会落到任务 `evidence/`，只把路径交给模型，不把 base64 塞进上下文。

导出行为：

- `md-zip`：图片写入 `evidence/<finding-id>/attachments/`，报告中的图片链接使用包内相对路径。
- `md-single`：图片内嵌为 data URI，适合单文件交付；附件总量超过 32 MiB 时请改用 `md-zip`。
- 截图附件随 finding 持久化，并纳入证据 GC 和任务归档 / 恢复。

Burp GUI 截图仍需在宿主机截屏后上传。Burp MCP 当前没有截图工具；请求/响应证据继续通过「关联流量」绑定，不要用截图替代可验证的原始报文。

### 两项明确决策

1. **允许账号输出，报告不做证据脱敏**。edusrc / 补天的复测账号与密码按原文输出，便于审核员复现；Cookie / Token / 完整 HTTP 报文不自动内联，需要时从证据包单独导出。此前对照外部验收标准时给出的「敏感证据脱敏后入报告」结论作废；项目内三处与报告无关的脱敏逻辑（CTF 题面脱敏视图、通知渠道凭据掩码、DSN 日志掩码）保持不变。
2. **edusrc 不打包**。官方规范要求「同单位同系统多漏洞点打包一个」，本项目按决策一漏洞点一份，单位/系统只作为分组提示，模板不会自动合并；提交时若平台要求合并，由提交人自行处理。

### 兼容性与影响范围

- `GET /api/report`、`md-single`、`md-zip` 支持截图附件；CSV 增加附件数量和文件名列，JSON 包含附件元数据，不包含图片正文。
- 存量任务 `report_template` 默认 `praetor`。全 praetor **且没有附件** 时继续调用原 `report.Markdown` / `FindingsMarkdown` / `SingleFindingMarkdown`，输出字节级不变；有附件时走附件感知的渲染器。
- 跨任务导出时每条 finding 按自己所属任务取模板，一份 zip 里可以混用不同平台版式；`?template=butian` 可强制本次导出统一用补天模板。
- 模板是内置常量（`report/template_butian.go` / `report/template_edusrc.go`），不提供用户自定义编辑器；平台改版时改选项常量并发版。
- 命名避让：项目已有 `task_templates`（任务描述预设），新功能一律用 `report_template` / `ReportTemplate`。
- 未知模板名在创建任务或导出时返回 400，不会静默回落；读旧库脏值时回落 `praetor`。

### 移动端任务的目标信息

移动端（APK / IPA / 真机）报告额外带一份**结构化移动端目标**，三套模板共用同一个 `report.View.Mobile`：平台、应用包名 / Bundle ID、版本、授权设备序列号、授权 APK SHA256、字段来源。设备序列号与 APK 指纹取自 `task_dynamic_grants`（撤销或过期后仍是事实，供溯源），包名 / 版本由发现正文正则解析，**可能为空** —— 缺的字段列进「待补充」，不编造，也不会平白改掉 Web 任务的版式。

判定刻意保守：只认明确的 Android / iOS 特征词，不因为正文里出现 "app" 就把 Web 漏洞误判成移动端。补天沿用平台已有的「IOT漏洞」类别，不新增类别与细分类型联动下拉；edusrc 在「内容」里用三级小节避免标题跳级，并在归档提示里附一行移动端目标。非移动端任务不输出这一段，存量 praetor 报告**字节不变**。

报告页在模板控件下展示同一份数据（`GET /api/tasks/{id}/mobile-meta`），与导出共用同一个后端取数函数，避免「页面显示一份、提交材料写另一份」。

## 移动端静态分析（P0 / P2 扩展）

静态侧覆盖 **APK 与 IPA**，都不涉及模拟器、真机、动态运行或联网。真机接入的授权链与沙箱接线见 P1，真机动态工具面与证据落盘见 P2。

### 安装

「系统设置 → 可选组件」应用 **`mobile-static`** 预置，或手动勾选 `apktool`。这份预置只装 1 项（约 60MB），因为静态规则是纯 Go 读解包产物，不需要 androguard / MobSF 之类的服务与重依赖。`mobile-static` 是**独立预置**，不会像 `ctf-*` 增量预置那样并上 CTF 基础层。

组件面板把后端预置渲染成「一键预置」按钮：后端返回的是 `PresetItems` **展开后**的完整 ID 集合（含增量预置的 `Base`），所以点 `ctf-crypto` 不会漏掉 CTF 基础层；按钮只负责勾选，仍需点「应用」才真正构建镜像，当前勾选与某预置完全一致时按钮高亮。分组新增「移动端 / App 安全」。

`jadx` 故意不进组件清单：它需要下载 release 并做版本校验，且只影响「Java 源码还是 smali」的可读性。缺了它 `mobile` 配方会明确退回 smali，不阻断分析；需要 Java 源码时自行安装并加入 PATH。

### 配方

在逆向域的 `re_recipe` 里选：

| 配方 | 作用 | 依赖 |
| --- | --- | --- |
| `mobile` | 解包摘要：包名 / 入口 Activity / 权限 / 组件 / 类名清单；`select=类名` 取该类 Java 或 smali 源码 | `apktool`（`jadx` 可选） |
| `mobile_scan` | 静态规则扫描，按文件形态自动分流（APK 走 apktool，IPA 走纯 Go zip），一行一条命中带「文件:行 + 依据」，按行分页且全文落盘 | `apktool`（仅 APK）；IPA 无外部依赖 |

`mobile_scan` 覆盖两组规则，输出格式完全一致（首行标 `mobile_scan` / `ipa_scan`）：

- **APK**：导出组件无权限保护、可调试、备份未关闭、明文流量（`usesCleartextTraffic` / `networkSecurityConfig` / 旧 `targetSdk`）、信任用户 CA、证书绑定配置、敏感权限面、自定义 scheme、WebView JS 桥与远程调试、自定义 TrustManager、硬编码凭据线索。
- **IPA**：`Info.plist` 的 ATS 明文开关（`NSAllowsArbitraryLoads` / 域名例外）、文件共享（`UIFileSharingEnabled` / `LSSupportsOpeningDocumentsInPlace`）、自定义 URL scheme、敏感权限用途、最低系统版本、Mach-O 主二进制魔数、`embedded.mobileprovision` 里的 `get-task-allow` 调试 entitlement、明文 `http://` 端点与硬编码凭据线索。

扫描上限 400 个文件 / 单文件 2MB / 每类 8 条，超出会在头行标 `truncated=true`，不静默截断。IPA 走标准库 `archive/zip`，**不落盘解包**（只读文本条目 + 主二进制前 4 字节），并拒绝 `..` / 绝对路径的 zip slip 条目；遇到 binary plist 会明确提示需 `plutil -convert xml1` 后人工复核，不猜测内容。

**命中只是线索，不是漏洞结论**：每条都必须回到源码或流量上复核，再用 `re_evidence` 落证据链。不传 `select` 时不需要额外参数；缺 `apktool` 会明确报缺哪个及装法（指向 `mobile-static` 预置），不会静默降级。

### 边界

- 配方表已满 10 条（`TestReverseRecipeCatalogIsLean` 上限）。后续加移动端能力优先合并进 `mobile_scan` 的 `select` 子动作，不要扩表 —— iOS 就是按文件形态分流进同一条配方，没有另占一条。
- iOS **只做静态解析**，动态需 macOS + 越狱真机，平台不承诺自动化；APK / IPA 的动态运行都不在这条配方里。真机接入见 P1，Android 动态工具面见 P2。
- 与模板选择无关：移动端目标信息由 server 从授权记录 + 发现正文补充，`report_template` 只决定用哪套版式渲染它；三套模板取的是同一份数据，报告页也读同一处。

## Android 真机动态授权与接入（P1）

本期落地的是**执行链**：任务级授权、短时令牌、设备独占锁、只读探测、沙箱接线。它保证「没授权就一次动态操作都做不了」；设备工具面、frida 脚本库、证据落盘与收尾清理在下一章（P2）补齐。`mobile-dynamic` 预置只提供 adb / frida-tools **客户端**，设备本身与 CA 始终由签发人自备。

### 三条不可让步的边界

1. **授权由人签发，不由任务产生**。创建任务时显式勾选书面授权并填写授权编号、设备序列号、APK SHA256、允许操作集、有效期、签发人，服务端校验后与任务**同一事务**写入 `task_dynamic_grants`。「任务存在」≠「已授权」；没有这条记录，所有动态工具调用一律 fail-closed 降级静态。
2. **一次人工签发 → N 次机器校验**。签发后平台生成短时 HMAC 令牌（绑定 taskID / 设备 / APK / ops / 过期时间），令牌**只走 Go 侧 hook 旁路，不进 LLM 上下文**，模型看不到、伪造不了、也写不进日志。每次工具调用由执行层自动校验，agent 全程无需逐次人工确认。
3. **授权不能被改写或扩大**。没有「创建授权 / 修改授权 / 续期」接口，工具面也不存在 `grant` 类工具；授权只能撤销。令牌续签仍受数据库 `valid_until` 与撤销状态约束，撤销接口会立刻清掉内存缓存。

### 校验链（挂在哪儿）

`guard.PreToolUse` 是与「取证边界」并列的 code-owned 硬约束，不依赖提示词，也不放在用户可编辑的 DB 拦截规则里。每个 Task 装配时都会挂上 `dynamicGrantGate`（包括没签发授权的），因此「没有闸」和「没有授权」不是同一件事。每次调用先由 `dynamicOpsForCall` 识别是否属于动态作业 —— 既认 P2 的 `mobile_*` 工具名，也认 `Bash` / `shell_*` 里直敲的 `adb`、`frida`、`objection`、`mitmdump`，避免模型随手写一条命令绕过整条链。

判定顺序：授权存在 → 书面授权已勾 → 未撤销 → 在有效期内 → 每个 op 都在签发白名单 → 令牌签名与绑定字段有效 → 设备独占锁可获取 → 放行并写审计。任一环节失败都会 block、留痕，并返回「改走静态分析路线」的明确引导（不会让任务空转烧预算）。`PRAETOR_EGRESS_EXCLUDE` 之外的真机 IP / `adb :5037` / `frida :27042` 已加入透明出口层直连白名单，否则全量出口重定向会把设备链路一起劫走。

### 部署真机（默认全关，不接手机时零影响）

1. 宿主起 adb server，USB 边界留在宿主，平台只连 TCP：`adb kill-server && adb -a -P 5037 nodaemon server`，用 `adb devices` 确认状态为 `device`。
2. 测试机用**独立 WiFi + 独立账号**，禁止连生产；Android 7+ 需自行装系统 CA 或逐包重打包 `networkSecurityConfig`，证书绑定另需 frida 脚本。系统 CA 只装在这台设备上。
3. 在 `.env` 里**同时**设置（缺一项就会回落并告警）：

   ```dotenv
   PRAETOR_MOBILE_DEVICE_MODE=1
   PRAETOR_TRAFFIC_ADDR=0.0.0.0:8798
   PRAETOR_TRAFFIC_BIND=0.0.0.0
   PRAETOR_MOBILE_ADB_HOST=host.docker.internal   # 宿主二进制部署改 127.0.0.1
   PRAETOR_MOBILE_DEVICE_EXCLUDE=192.168.1.50,host.docker.internal:5037,host.docker.internal:27042
   ```

   真机 WiFi 代理指向 `http://<宿主局域网 IP>:8798`（`PRAETOR_MCP_PORT`）。抓包复用项目已有的 `traffic` 录制代理与 `mitmproxy-ca-cert.pem`，请求自动进入现有流量库、证据链与三套报告模板，**没有新起一套 mitmproxy**。
4. `docker compose up -d` 后可用 `./praetor -check-config` 核对「代理监听 / 设备模式 / adb 落点 / egress 旁路」四项。默认 `PRAETOR_TRAFFIC_ADDR` 只绑回环，只把它改成 `0.0.0.0` 而没开设备模式会被强制回落 —— 避免把一个 MITM 代理无意中对整个局域网开放。

### 任务侧

新建任务抽屉的「Android 真机动态授权（可选）」默认折叠且未启用。展开后可先点「探测设备」做只读自查。探测只报能从平台侧机读的事实：adb server 可达、设备在线、adb 已授权；`root` / `frida-server` 作为 advisory（无 root 仍可装包/启动/看日志），而**锁屏状态、系统 CA 安装、真机到代理的连通性一律标 `manual` 交签发人确认**，不假装「六项全绿」。探测失败会明确给出降级原因，不静默跳过。

表单里的「目标 APK SHA256」可用「选 APK 自动算」在浏览器本地用 Web Crypto 计算（只在 https / localhost 可用，超过 300MB 会提示改用 `sha256sum`）：**只登记指纹，不上传文件**；APK 本体仍需放进工作空间 `/work` 由 `mobile_install` 按路径安装，安装前会再比一次哈希。允许操作集、有效期上下限与默认值都取自 `GET /api/dynamic-ops`，前端不再写死清单；后端新增 op 而前端未发版时，选项自动回落到后端描述，不会出现「勾不到」。该接口同时返回 `device_mode` / `adb_addr` / `traffic_addr` 三个只读运行时前置 —— 设备模式没开时表单直接黄色告警「签发授权也不会注入 `mobile_*` 工具」，不再让任务静默降级后无从排查。

签发字段与 API：

| 动作 | 接口 |
| --- | --- |
| 随任务创建签发（唯一入口） | `POST /api/tasks` 的 `dynamic_grant` |
| 允许操作闭集 | `GET /api/dynamic-ops` |
| 只读设备探测 | `GET /api/mobile/devices?serial=<serial>` |
| 查看授权与状态 | `GET /api/tasks/{id}/dynamic-grant`（`none/active/revoked/expired`） |
| 查看调用审计 | `GET /api/tasks/{id}/dynamic-grant/audits` |
| 撤销 | `POST /api/tasks/{id}/dynamic-grant/revoke`（`reason`、`operator`） |
| 报告页移动端目标 | `GET /api/tasks/{id}/mobile-meta` |

审计是 append-only，记录每次 allow / block 的 op、工具、设备、令牌摘要（只存 SHA256，不存可重放票据）与原因；签发与撤销也各留一条。设备锁用 `device_leases` 的**数据库唯一约束 + 租约**实现，跨进程有效，任务异常退出不会永久占住手机；撤销会主动释放，未释放的靠 15 分钟租约自然过期。

### 组件与边界

「系统设置 → 可选组件」应用 **`mobile-dynamic`** 预置 = `mobile-static` + `android-tools-adb` + `frida-tools`。frida-server、CA、设备本身都由测试机自备，不进镜像；`objection` 仍按「不引重依赖」纪律保持宿主侧可选。

**本期边界**：P1 只解决「能不能做」；`mobile_*` 设备工具、frida 脚本模板、动态证据落盘、任务收尾主动清理、前端授权状态面板与 iOS 静态解析都在 P2（下一章）。P1 的设备锁只靠 15 分钟租约兜底，P2 之后任务落终态会主动释放。

`PRAETOR_RE_DYNAMIC=1` 是逆向域 `trace` 配方（gdb 跑二进制样本）的开关，作用范围与真机动态**完全不同**，不能互相替代；真机动态一律以任务级签发为准。

## Android 真机动态工具面与证据（P2）

### 工具在哪里跑

真机操作**全部由应用容器里的 Go 代码通过 adb TCP 协议完成**（`server/mobile_adb.go`），不依赖沙箱容器里是否装了 adb 二进制，也不碰 USB：adb server 仍在宿主 `:5037`，平台只是按 AOSP 协议说话。安装 APK 用 `sync:` 通道推到 `/data/local/tmp/`，其余动作走 `host:transport:<serial>` + `shell:`。

9 个工具与 P1 的授权 op 一一对应（`mobile_install` / `mobile_launch` / `mobile_shell` / `mobile_frida` / `mobile_hook` / `mobile_proxy` / `mobile_logcat` / `mobile_pull_data` / `mobile_cleanup`），默认 seed 进工具目录并只绑 `worker`。三层纵深：

1. **注入层**：`mobileToolsFor(taskID)` 按当前 run 的 taskID 判定。设备模式未开、任务无生效授权、或调用方不是 worker → 这些工具**根本不出现在模型工具面里**。
2. **guard 层**：工具名命中 `dynamicOpsForCall`，走 P1 那套 op 白名单 / 短时令牌 / 设备独占锁硬闸。
3. **工具层**：再读一次 DB 授权，并做参数级约束 —— `mobile_install` 校验本地 APK 的 SHA256 与授权签发的哈希**完全一致**（换包直接拒绝）；`mobile_shell` 只接受只读自省命令白名单；设备侧路径限定 `/data/local/tmp/`；`mobile_hook` 只接受闭集模板名，不接受自定义 JS。

### frida 脚本库

`server/mobile_frida.go` 内置 5 份固定模板：`ssl_pinning_bypass`、`root_detection_bypass`、`crypto_trace`、`http_trace`、`storage_trace`。脚本只记录算法名 / URL / 路径 / 长度，**不打印 Cookie、Token、完整报文或密钥明文**；输出统一带 `[praetor]` 前缀，可用 `mobile_logcat` 过滤。

诚实边界：应用容器是 Go runtime 镜像，**不内置 frida**。`mobile_hook` 把模板写到 `/work/mobile/frida/<name>.js` 并返回可在沙箱容器执行的 `frida -U -l ...` 命令；实际注入由 agent 用 `Bash` 调用（那条 Bash 同样过 frida/hook 授权闸）。`mobile_frida action=ps` 在没有 `frida-ps` 时明确提示降级，不假装成功。

### 证据落盘与脱敏

所有动态输出脱敏后写到 `<workRoot>/<taskID>/mobile/` —— 宿主侧是 `data/work/<taskID>/mobile/`，容器内就是 `/work/mobile/`（同一 bind mount，容器销毁后文件仍在）。`_index.jsonl` 是 append-only 证据索引，记录路径、类型、字节数、脱敏后 SHA256 与一行摘要。工具只回前 4KB 内联预览 + 路径，全文用文件工具读。

脱敏规则与报告模板一致：**允许账号与口令保留**（平台提交材料常需复现账号），但 `Cookie` / `Set-Cookie` / `Authorization` / `X-*-Token` / Bearer、`token|secret|session_id` 长值、短信验证码一律替换成 `[REDACTED#<hash8>]` 或 `[REDACTED]`，完整 HTTP 报文块折叠为「见落盘证据文件」。二进制证据（`adb sync pull`）原样落盘但不进入模型上下文，只回路径 / 大小 / 摘要。

### 收尾

任务落到 `done` / `failed` / `timeout` 时，`Manager` 的终态回调触发 `onTaskTerminal`：立刻作废内存令牌 → 复位全局代理 → 清目标 App 数据 → 删 `/data/local/tmp/praetor-*.apk` → 释放 `device_leases` → 写 `cleanup` 审计。清理是**平台义务**，不受 ops 白名单约束（否则没勾 `cleanup` 的任务会把脏环境留给下一个任务），但只作用于授权签发的那台设备，单项失败不阻断后续项，租约仍作为兜底。也可在任务中途主动调 `mobile_cleanup`。frida-server 若是签发人手工启动的，平台只做可见性报告、不代杀进程。

### 前端

任务详情新增「**真机动态**」页签：展示授权状态（`none/active/revoked/expired`）、签发字段与 ops 闭集、设备探测结果（含 `manual` 项）、append-only 审计列表，并提供带原因与操作者的撤销对话框。未签发授权时明确说明工具不可用与「只能创建任务时签发一次」。ops 标签取自 `/api/dynamic-ops`；后端未开设备模式时，页签（含未授权态）给出与创建表单一致的黄色告警和 adb 落点。

「动态证据」卡片不再只写一段说明，而是列出**实际落盘的文件**（走工作空间只读接口，相对路径 `work/<taskID>/mobile`），可内联预览 / 下载，也可一键深链到工作空间对应目录；目录不存在时显示「暂无证据」而不是报错。容器内工具回写的路径仍是 `/work/mobile/<name>` —— per-task bind mount 把宿主 `data/work/<taskID>` 挂成容器内 `/work`，两种写法指向同一份文件，**不要写成 `/work/<taskID>/mobile/`**。

报告页在模板控件下展示「移动端目标」卡片，字段与三套导出模板同源（见「报告输出模板 → 移动端任务的目标信息」）。

### 仍不做的事

- iOS 动态（macOS + 越狱真机），只做 IPA 静态解析；
- 不内置模拟器、不提供 `--privileged` / `--device`；
- 不提供通用 adb 命令直通工具，不让 op 白名单退化；
- 不自动装系统 CA、不自动绕过证书绑定 —— 这些是设备侧前置，由签发人确认（探测里标 `manual`）。

---
## 开发

### 手动漏洞复测

任务详情的「复测」页签可分页选择本任务的漏洞、查看历次结论和证据，并手动发起复测。启动后保留当前页签，显示转圈图标和「复测中」；确认修复后同步更新漏洞状态。

在漏洞列表每行操作区点击「复测」，或在漏洞详情的「漏洞复测」区域点击「发起复测」，填写可选的修复版本、测试条件或限制，系统会创建独立的复测 Agent 会话，启动后保留当前页面。列表的平铺、按任务分组和资产视图均支持该入口；复测运行时显示转圈图标和「复测中」，需要查看时点击进入对应会话，结束后恢复「复测」。复测无需重新启动原扫描任务，结论分为「仍可复现」「已修复」「无法确认」，每次的结论、证据和会话链接保存在漏洞详情中。

新版后端首次启动会预置可编辑的「漏洞复测」（`retester`）Agent，可在 Agent 管理中配置提示词、LLM、运行预算和工具。默认使用其绑定的 LLM，未绑定则使用全局激活配置。复测会话成功完成且结论为「已修复」时，系统自动将漏洞处置状态改为「已修复」；执行中、失败、停止或其他结论保留原状态。原始证据和报告始终保留。也可在状态下拉菜单中手动选择「已修复」。同一漏洞正在复测时复用已有会话，停止、失败或服务重启后可重新发起。

本版历史记录通过漏洞详情和会话查看，暂未纳入漏洞报告导出或任务归档包，也未自动关联流量包。演示模式只生成明确标注的模拟记录，不请求真实目标。

### 本地运行与测试

```bash
./dev.sh    # 后端(:8787) + 流量代理(:8798) + 前端 next dev(:5173) → http://localhost:5173
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
  PL --> GUARD
  WK --> GUARD
  MA --> GUARD
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
