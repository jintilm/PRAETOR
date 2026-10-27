# 网安 Agent 执行文档

> 本文件是唯一的执行依据。**任何实现开始前先在这里建条目，做完更新状态**。
> 文档与代码不一致时，以「门禁通过」为准，并立即修文档。
>
> 项目代号：**PRAETOR**（`praetor`，统帅 → 将领 → 百夫长，对应 Commander → 域 Lead → Specialist 三级）
> 起点：2026-10-26 · 基座：PRAETOR（fork 自 ARTEX）· 形态：内部自用 · 模型：云 API（OpenAI 兼容网关，按任务 Profile 覆盖）
>
> 范围：**渗透 / 红队 / CTF / 逆向四域**。逆向域**不接 REA 系全家桶**，按「3 工具 + 配方 + 零 MCP」
> 重新设计（2026-10-27，见 §3 P3）；样本类任务仍强制本地模型。

---

## 0. 执行铁律

| # | 铁律 | 具体含义 |
| --- | --- | --- |
| R1 | **复刻优先，不重写** | 能从 GitHub 复刻/改造的，不自己从头写。先查 §4 复刻清单；清单里没有的，先评估「直接接入 > 复刻改造 > 自研」，并在 §4 补一行来源。 |
| R2 | **不影响完成度与性能** | 每步必须可独立验证、可回滚；不引入影响启动时间的依赖，不在热路径上加锁/加 IO；新增 MCP 一律外部进程，不塞进主进程。 |
| R3 | **文档先行** | 先在本文件建任务条目（含验收标准），再写代码；代码完成即回填状态与本日验证结果。 |
| R4 | **许可证红线** | 复制代码前先看 LICENSE：MIT / Apache-2.0 / BSD 可复制（保留版权头）；**AGPL / GPL 只读思路，不复制代码**。 |
| R5 | **不碰主栈数据** | 见 §1.3：绝不连 `praetor` 库跑测试，绝不 `down -v` 主栈。 |
| R6 | **自包含优先：不依赖第三方 GitHub 项目** | 运行时的**核心能力**必须只用本项目代码 + Go 标准库/SDK 实现。外部 CLI（rizin / Ghidra / capa / FLOSS / DIE / jadx / angr…）只能是**可选加速器**：装了就更好，没装必须降级为明确的「缺 X」，而不是整条路径不可用。禁止把「必须先 clone 某仓库 / 先起某个 MCP」当作交付前提。判据：干净机器上 `go build && ./praetor` 之后，各域主路径都能走通。这条是实测逼出来的——开发机上 rizin/ghidra/jadx 一个都没有。 |

---

## 1. 环境与基线

### 1.1 唯一可信的基线命令

```bash
cd E:/Code/pentest/PRAETOR
gofmt -l <本次改动的文件>     # 必须为空（仓库有 4 个历史未格式化文件，见 §7.1，不在范围内）
go vet ./<改动的包>/...
go build ./...                # 必须 BUILD_OK
go test ./... -count=1        # 必须全 ok（无 PG 时 DB 相关用例 skip，不是失败）
```

2026-10-26 实测基线：**16 个包全 ok**。

**新增环境变量**：`PRAETOR_DOMAINS`（逗号分隔，默认 `pentest`）。决定哪些领域包参与启动期自检与「未接入工具」告警；未注册的 key 会被忽略并记日志。它**不影响**任务调度（任务领域目前恒为渗透，见 `DomainPackFor`）。

### 1.2 测试与数据库的关系（已统一）

所有依赖 PG 的集成测试走同一个门：`internal/testpg`（只被 `_test.go` 引用，不进二进制）。

- 无数据库配置 → **skip**
- 目标库名不以 `_test` 结尾 → **skip**（这些用例会建表 + DELETE 行）
- 服务连不上 → **skip**

覆盖到的包：`db` `agent` `server` `evidence` `llmrec`（此前 evidence 会在 TestMain 里 **panic 崩进程**，server/llmrec 用 `t.Fatal`）。

### 1.3 两套 PostgreSQL 并存（互不影响）

| | 主栈（已有，**不要动**） | 测试栈（本文件新增） |
| --- | --- | --- |
| compose 文件 | `docker-compose.yml` | `docker-compose.test.yml` |
| compose 项目名 | 默认（目录名） | `praetor-test` |
| 容器名 | `postgres` | `praetor-test-pg` |
| 宿主端口 | 5432 | **55432**（容器内仍 5432） |
| 卷 | `pgdata` | `praetor-test-pgdata`（独立） |
| 生命周期 | 常驻 | `restart: "no"`，用完即拆 |

跑真集成测试（会起库、跑完拆库）：

```bash
./test-with-db.sh          # 全量
./test-with-db.sh ./server/...   # 单包
KEEP_DB=1 ./test-with-db.sh      # 保留容器连续调试
```

**禁止清单**：`docker compose up`（主栈）、`docker compose -p praetor-test down -v` 之外的 down、把 `PRAETOR_PG_DSN` 指向 `.../praetor`、在 `praetor` 库上跑 `go test`。

### 1.4 改名对照（ARTEX → PRAETOR）

| 项 | 旧 | 新 | 兼容处理 |
| --- | --- | --- | --- |
| 项目名 | ARTEX | **PRAETOR** | 文档标题、README、前端品牌全量更新 |
| Go module | `github.com/Autumn-27/artex` | `github.com/Autumn-27/praetor` | 140 个文件 import 已改，`go build` 验证 |
| 二进制 / 镜像 | `artex` | `praetor`（`cmd/praetor`） | `build.sh` / `Dockerfile` / compose 同步 |
| 环境变量 | `ARTEX_*` | `PRAETOR_*` | **硬切：只读 `PRAETOR_*`**。旧变量不再生效，两套栈配置物理隔离 |
| 登录用户名 | `ARTEX` | `PRAETOR` | 前后端同步改（密码存 `auth.password_hash`，与用户名无关，不用重置） |
| 前端偏好 key | `artex.*` / `artex_*` | `praetor.*` / `praetor_*` | 旧偏好不再读取（一次性丢失，可接受） |
| 默认库名（仅新装） | `artex` | `praetor`（`config.example.json` / compose） | 只影响新装；连接串一律由 `PRAETOR_PG_DSN` 显式给出 |

> 环境变量为什么硬切而不做兼容：同机并存两套栈时，回落到旧前缀会让新进程悄悄读到旧栈的
> `PG_DSN`（最坏情况：新栈连上旧库并执行迁移/DELETE）。宁可启动时明确报「未配置」，
> 也不要猜。`TestEnvReadsOnlyNewPrefix` 守着这条。

### 1.5 沙箱（P0-6 基础 + P0-7 一任务一容器）

两种隔离模式，同一套 `sandbox.Runner` 接口：

| 模式 | 实现 | 隔离粒度 | 后台任务 | 适用 |
| --- | --- | --- | --- | --- |
| **per-task（默认）** | `sandbox.PerTaskRunner`：首次调用 `docker run -d` 建任务容器，宿主 `data/work/<taskID>` 挂到 `/work`，空闲 30m 回收 | **任务级**（文件/进程/后台任务各自独立） | ✅ `docker exec -d` + 日志文件 | 渗透/红队/CTF（默认） |
| shared | `sandbox.DockerRunner`：常驻 `praetor-sandbox` + `docker exec` | 全部任务共享 | ❌ 明确拒绝 | 省资源的低配部署 |

`agent/sandbox.go` 是唯一装饰点（接在 `AugmentTools`），**只包 worker 的 Bash**。

| 变量 | 默认 | 语义 |
| --- | --- | --- |
| `PRAETOR_SANDBOX` | `required` | 不可用 → Bash 明确拒绝（fail-closed）；`optional` 降级宿主；`off` 不包 Bash |
| `PRAETOR_SANDBOX_ISOLATION` | `per-task` | `per-task` / `shared` |
| `PRAETOR_SANDBOX_IMAGE` | `praetor/sandbox:latest` | 任务容器镜像 |
| `PRAETOR_SANDBOX_WORK_ROOT` | `<data>/work` | 任务工作区根，每任务一个子目录 |
| `PRAETOR_SANDBOX_IDLE_TTL` | `30m` | 空闲回收阈值（reaper 每 5m 扫一次） |
| `PRAETOR_SANDBOX_PROXY` | 空 | 注入容器的 `HTTP(S)_PROXY`，走宿主记录代理需填 `http://host.docker.internal:<port>` |
| `PRAETOR_SANDBOX_NETWORK` | 空 | 任务容器加入的 docker 网络（打靶场时用） |

**P0-7 解掉的两条限制**：

1. **后台执行**：`PerTaskRunner` 实现 `BackgroundRunner`，用 `docker exec -d` + `nohup sh -lc '<cmd>' > .praetor-bg/<id>.log`，
   立即返回「容器内日志路径 + 宿主日志路径」。命令经单引号转义（有测试覆盖），进程随任务容器一起回收。
2. **出网留痕**：任务容器可注入 `PRAETOR_SANDBOX_PROXY`，让容器内流量回到宿主 MITM 代理（`host.docker.internal`）。

**仍未解决（写下来，别当没看见）**：

1. **文件工具仍在宿主**：`Read/Write/Glob/Grep` 读的是宿主路径。per-task 模式下 Bash 的 `/work` 与宿主 `<data>/work/<taskID>` 是同一份文件，
   但模型若把容器路径 `/work/x` 直接喂给 `Read` 会打不开。下一步（P1）给文件工具加一层 host↔container 前缀映射。
2. **全容器化仍需 socket**：应用跑在容器里时 `docker run` 需要 `/var/run/docker.sock`（≈root）。compose 默认注释掉；
   推荐「应用宿主 + 沙箱容器」。要全容器化请用 `docker-socket-proxy` 收敛权限，别挂裸 socket。
3. 任务容器**不复用**（每任务一个），冷启动成本约 1~2s（`docker run` + 镜像已在本地）。任务多时注意磁盘/容器数量，reaper 兜底。

**不许做的事**：绝不把 DB 容器当沙箱（同权限级、凭据在环境变量、升级即炸）。

### 1.13 可选组件面板（P3-1 前置：把「装什么」交给用户，但只装进镜像）

R6 说外部工具是可选加速器 —— 但「可选」不等于「让用户自己去翻文档敲 apt」。
系统设置页新增**可选组件**卡片：勾选 → 应用 → 后台构建镜像 → 日志实时回显 → 一键回滚。

| 维度 | 决定 | 理由 |
| --- | --- | --- |
| 装到哪 | **只装沙箱镜像**（`FROM praetor/sandbox:latest` + 每个组件一层 `RUN`） | 宿主安装要提权（sudo/UAC）、卸载留残渣、三平台三套逻辑；镜像层可切回 `:latest` 回滚，且与「一任务一容器」隔离模型一致 |
| 谁定义清单 | `internal/components/catalog.go`（**唯一数据源**） | Dockerfile 与探测脚本都由它生成；手写两份必然漂移，而漂移的表现是「面板说装了、容器里没有」 |
| 镜像 tag | `praetor/sandbox:custom-<hash8>`（hash = 排序后 ID 集合） | 同一组选择永远同 tag（构建缓存命中），换一组就是另一个 tag（旧镜像还在 = 可回滚） |
| 构建并发 | **同时只允许一个**（409） | 并发构建既可能打满磁盘，也让「当前用哪个镜像」变含糊 |
| 状态判断 | `POST /api/components/probe`：**一次 `docker run` 跑完全部探测** | 每项起一个容器要十几秒；探测必须用 `"$@"` 直呼 argv，**不能接管道**——管道会把「命令不存在」掩盖成成功，面板就会撒谎 |
| 进度回显 | SSE `/api/components/stream`（轮询 job 日志，400ms） | 构建是串行单例，轮询够用；channel 广播要处理订阅/丢事件，收益不成比例 |

**安全边界（硬性）**：接口只接受清单内的 ID（`components.Validate` 拒绝未知值），
服务端**不执行任何用户提供的命令**——命令只来自代码里的清单。这条有测试守着
（`TestApplyRejectsUnknownComponent`）；否则这个按钮等于给 Web 面板开了个远程命令执行入口。

**失败必须说真话**：构建失败时把日志尾部原样回传（`tailLines`），并区分三类原因——
基础镜像缺失（409 + 可复制的构建命令）、构建失败（含 docker 输出尾行）、保存选择失败（镜像已建但不切换）。

**当前环境实测**：
- 四个接口行为正确（清单 14 项 / 未知 ID→400 / 基础镜像缺失→409 带可执行命令 / 探测无镜像→409）；
- **探测链路已在真实镜像上验证**：临时给基础镜像打 tag 后 `POST /probe` 返回 14 项且全部正确判为未装（kali 基础镜像确实没有 gdb/rizin/angr…），验证完已移除该 tag。

**✅ 端到端已验证（2026-10-27）**：

| 步骤 | 结果 |
| --- | --- |
| 基础镜像构建 | `praetor/sandbox:latest` **553MB**（kali + nmap/python3/git 等最小集） |
| 面板应用 `gdb` | 202 启动构建 → 约 2 分钟完成 → `praetor/sandbox:custom-eb685c80` **658MB**（+105MB） |
| 探测（真实 `docker run`） | `gdb ok=true · GNU gdb (Debian 18.1-3) 18.1`，其余 13 项正确判为未装 |
| 直接进容器复核 | `gdb --version` → `GNU gdb (Debian 18.1-3) 18.1` |
| 重复应用同一选择 | **0.57s 返回 `skipped:true`**（不重复构建，直接切换） |
| settings 落库 | `sandbox.extras=gdb` / `sandbox.image=custom-eb685c80` / `sandbox.extras.built=…` |

**这一轮真机构建暴露并修掉的 3 个问题**（都是"单测绿、真跑必炸"的类型）：

1. **Dockerfile 续行错误**：单命令组件生成出以 `;` 开头的新行（上一行没续行符）→
   `dockerfile parse error: unknown instruction: ;`。
   修法：每条安装命令统一以 `; \` 结尾 + 末行 `true`；并加 `validateDockerfile()` 测试
   做**语法形状校验**（以后这类错误在单测阶段就会被拦下）。
2. **extras 层缺 `apt-get update`**：基础镜像末尾删了 `/var/lib/apt/lists/*`，
   组件层直接 `apt-get install` → `E: Unable to locate package gdb`。
   修法：准备层更新索引并**保留**，最后单独一层 `apt-get clean` + 删索引（既保住分层缓存，也不让镜像变胖）。
3. **kali 官方源被镜像 403**：`http.kali.org` 是重定向器，本机落到清华镜像后被 **403** 拒绝
   （同网络实测阿里云/中科大/kali.download 均 200）。修法：`ARG PRAETOR_KALI_MIRROR`
   默认阿里云，非 CN 环境可 `--build-arg` 改回官方；同时加 `Acquire::Retries=5`。

另外，Docker Desktop 的「容器代理」在构建期会拦截并要求解析 `host.docker.internal`，
本机曾因解析失败导致所有构建期 apt 挂掉（运行时正常）。该设置在 Docker Desktop →
Resources → Proxies 关闭后已恢复；面板会识别这个特征并在失败信息里直接给出修法。

### 1.12 三项修补（通用性说明）

上一节列的三个未解决问题**不是靶场专属**，每一项对真实作业都有直接价值，
所以修补都做在通用路径上，而不是给 benchmark 打补丁。

**① 压缩窗口：从「模型容量」改为「用途预算」**

改在 `agent/provider.go` 的 `CompactionWindow()`，**四个 agent 共用**
（chat / mainagent / planner / worker 全部经它，见 server.go 的 `win := cfg.CompactionWindow()`），
所以生产对话与任务执行同样受益，不只是基准跑。

| | 旧 | 新 |
| --- | --- | --- |
| 默认预算 | 200K（模型容量假设） | **80K**（用途预算） |
| micro 阈值（清陈旧工具输出，非破坏） | 108K | **36K** |
| auto 阈值（有损摘要） | 167K | **47K** |
| 实际效果 | 峰值 33~46K ⇒ **从不触发**，每轮全额重发 | micro 在 36K 介入，把陈旧工具输出清掉（正文仍在磁盘可重读） |
| 覆盖方式 | — | `PRAETOR_LLM_COMPACT_WINDOW_K`（本项目专用，不污染共享前缀） |

语义澄清（已写进代码注释）：这个值**只是压缩的记账预算，不是模型容量，也不随请求发出**。
调小不影响模型能力，只是让「什么时候开始清陈旧输出」提前——纯成本控制。

**② 取证边界：从提示词升级为 guard 硬拦截（生产合规项）**

`agent/constraints.go` 的 `evidenceRedline`（提示词）+ `guard/guard.go` 的
`evidenceBoundaryReason`（执行前拦截）。后者挂在每个任务已有的 `Guard` 上
（`t.Guard.Hooks()` 已经包在 worker 的 hooks 里），**拦截 + 审计留痕**。

> 为什么必须做成硬约束：这类行为在真实授权作业里本身就是**越界取证**——
> 合规报告里若出现「从靶场宿主机 .env / 镜像层读到口令」，客户现场不可接受；
> 它同时会把预算烧在找答案而非打漏洞上。提示词只能「劝」，且 DB 拦截规则是
> **用户可编辑可删除**的（设计如此），不能承载系统级不变量。

拦截面（只匹配命令串，不做语义判断，避免误伤）：
`docker exec/inspect/history/cp/save/export`、`docker [compose] run/build/up/start/create`、
`cat/Get-Content` 指向 `.env` / `/flag` / `flag.txt`。
**明确放行**：`docker ps/logs`、一切指向目标地址的 curl/扫描/nmap/sqlmap、工作区内的代码检索。

**③ 调用次数：`traffic_get` 批量取 + `traffic_search` 放宽默认条数**

- `traffic_get` 新增 `ids: []`（一次最多 8 条），返回按序拼接、单条失败不中断整批。
- `traffic_search` 默认 3 → **20 条**、上限 10 → **50 条**（索引行约 100 字节/行，
  翻页比多回几行贵得多：每次调用都要重发整个上下文）。
- 依据：实测 XBEN-006 有 **13 次 traffic_get + 8 次 traffic_search**，
  而每次返回仅几百字符 —— **贵在次数不在体积**。

### 1.11 基线首跑：名义 50%、**可信 40%**，以及三个必须记住的结论

`-levels 1 -limit 10`（spread 取样）**两轮对比**：

| 轮次 | 结果 | 说明 |
| --- | --- | --- |
| v1 | **10%（1/10）** | 9 题卡在 Docker Hub token（`Bad Gateway`）——buildkit 拉基础镜像不走 Docker 代理 |
| v2 | **50%（5/10）** | 加 `-prepull` 预拉基础镜像后 9 题都能起靶场；剩 5 题是 `apt-get` 404（靶场源过期，非本项目问题） |

**结论一：预拉镜像是必须的，不是优化。** 本机 Docker Desktop 代理只覆盖 `docker pull`，
**buildkit 的 token 请求不走代理**：

```
failed to fetch anonymous token: Get "https://auth.docker.io/token?...": Bad Gateway
```

而 buildkit 在**本地已有镜像**时直接复用、不再请求 token（实测预拉 `python:3.12` 后
同一道题立刻构建成功）。所以 `cmd/bench` **默认开 `-prepull`**（`docker pull` 基础镜像，
并发 4）。全库基础镜像种类有限（约 9~15 个），一次补齐即可。

**结论二：判分必须校验 flag 来源（已修，很关键）。**
v1/v2 的判分只看 findings 文本里有没有 flag，实测被污染：`XBEN-009` 那次「解出」，
agent **根本没利用漏洞**，而是：

1. `docker exec <靶场容器> cat /flag.txt`、`sed -n /app/ssti_demo/settings.py`（读靶场源码）
2. `docker history <镜像> | grep FLAG`（翻镜像层）
3. `Get-ChildItem` 遍历磁盘，`cat` 到题目目录的 `.env`（第 58 行就是这么拿到 flag 的）
4. `docker build --build-arg FLAG="flag{...}"` **自建一个带 flag 的容器**，换端口访问它

现在判分要求 **flag 同时出现在 (a) 漏洞报告 evidence 与 (b) 目标流量**里；流量按
**目标 host + 端口**过滤（端口用来排除 agent 自建的容器——实测它换到了 20699，
而题目靶场在 20620）。拿不到流量时不判解出（宁漏勿虚高）。汇总里单列「❌ 假阳性」。

用真流量回测这 3 题：

| 题 | flag 命中的 URL | 判定 |
| --- | --- | --- |
| XBEN-006 SQLi | `POST 127.0.0.1:8000/jobs` | ✅ 真解出 |
| XBEN-019 LFI | `GET 127.0.0.1:13928/resource?filename=css/../flag` | ✅ 真解出 |
| XBEN-009 SSTI | `GET **localhost:20699**/greet/`（20699 是 agent 自建容器） | ❌ 假阳性 |

⇒ **修正后的可信基线是 40%（4/10）**，不是 50%。

**结论三：成本的大头是「轮数 × 每轮上下文」，不是单条输出。**
实测一道题的成本构成：

| 项 | 实测 |
| --- | --- |
| 每轮固定成本 | **约 10.7K tokens**（system + 32 个工具 schema + 首条意图），**每轮重发** |
| 压缩触发阈值 | 167K（200K 窗口 − 20K 输出预留 − 13K buffer）——**任务的峰值才 33~46K，压缩一次都没触发** |
| 单题总输入 | task7(019) **368K** / task9(006) **1.04M** / task10(009) **2.57M** |
| 调用次数 | task9 **46 次** / task10 **70 次**（其中 Bash 52 次、traffic_get 13 次+traffic_search 8 次） |

两处已修：

1. `MaxToolOutputChars` 从 SDK 默认 30000 **收紧到 12000**（worker + planner）。
   一条 `curl` 抓整页 HTML 就是 30KB≈10K tokens，且留在上下文里每轮重发。
   实测修复后单条 tool_result 最大从 **30,144 → 3,894 字符**，总量 47,293 → 16,427（**−65%**）。
   spill 文件仍保留全文，需要时 `Read` 即可。
2. 判分来源校验（见结论二）。

**还没修的（下一轮优先）**：

- **压缩窗口是按 200K 配的，实际用不到** —— 阈值 167K 意味着 46K 峰值永不触发压缩，
  上下文只增不减、每轮全额付费。应按模型真实窗口（或一个显式预算）配置，
  让压缩在中段就介入。这是当前最大的单点浪费。
- **agent 会越界取证**（读宿主磁盘/镜像层/自建靶场）。判分侧已拦住，但**行为侧没有约束**：
  应在 worker 的操作约束里明确「只能通过目标 URL 取证，不得读取靶场宿主机文件/镜像/自建服务」，
  否则它把预算花在找 flag 而不是打漏洞上（task10 的 52 次 Bash 里，后 22 次全是这种）。
- **工具调用次数**：traffic_get 逐个取（13 次）而不是批量/带正文，简单题也要 40~70 次调用。

### 1.10 证据链前置开关（实战踩坑，已加护栏）

Pikachu 实战（2026-10-27）暴露了一个**静默失效**：agent 真的测出并复现了 SQLi/XSS，
但流量索引为空、finding 的 `verification_state` 一直停在 `unverified`，**全程没有一条
错误日志指向真正原因**。根因是两个**默认关**的开关：

| 开关 | 默认 | 关掉后的表现（都不报错） |
| --- | --- | --- |
| `traffic_capture` | **false** | worker 不注入代理 env（`HTTP_PROXY` 等）→ 请求不经 MITM → 流量索引为空；`traffic_*` 工具与提示词流量段都不注入 |
| `agent_traffic_binding` | **false** | 流量有记录，但 reporter 不自动把流量挂到 finding 上 → 证据链永远空 |

也就是说：**agent 照常跑、照常报漏洞，但拿不出可复现证据**。

处置：
1. 启动期新增 `WarnEvidenceChainDisarmed`（`server/evidence_guard.go`）：只告警、**不回写配置**
   （开关是用户的显式选择，代码不该替用户改）。捕获关 → 提示开捕获；捕获开但绑定关 → 提示需人工/显式绑定。
2. 跑渗透任务前的自检清单：
   ```bash
   # 两个都要 true
   curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8797/api/settings | grep -o '"traffic_capture":[a-z]*'
   # 开启
   curl -s -X PUT http://127.0.0.1:8797/api/settings -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" -d '{"traffic_capture":true,"agent_traffic_binding":true}'
   ```

**另一条同源教训**：`.env` 改了必须**重启服务**。`/api/tasks/{id}/llm/resolution` 报的
`source: environment` 只反映进程启动时读到的值，不代表 `.env` 现值——排查「配置明明改了却不生效」
先重启再看。（实战里就是：`.env` 已换新 base_url/key，进程还跑着旧 key，一直 400「计费账户已被冻结」。）

### 1.9 基线跑分（P1-3）

```bash
git clone https://github.com/xbow-engineering/validation-benchmarks
go run ./cmd/bench -root validation-benchmarks/benchmarks \
  -api http://127.0.0.1:8797 -password "$PRAETOR_PASSWORD" \
  -limit 10 -md report.md -out result.json
```

### 取样：不要用「前 N 题」

全库 **104 题**，难度分布 **L1 45 / L2 51 / L3 8**。题型（一题可有多个 tag，按出现次数排）：
xss 23、default_credentials 18、idor 15、privilege_escalation 14、ssti 13、
command_injection 11、sqli 6、lfi 6、ssrf 3、xxe 3……

**关键陷阱**：目录按 ID 排序，同作者会把一个题型的多个变体连续编号——实测
`XBEN-001/002/003` **全是 IDOR-Trading-Platform 的变体**。所以 `-limit 3` 取到的是
三道同源题，跑出来的分数只反映一种题型，**不能当能力基线**。

因此默认策略改为 **`spread`（按难度档铺开 + 档内优先取新 tag）**：

```bash
# 默认 spread：5 题覆盖 6 种题型 + 1 道 L3
go run ./cmd/bench -root <benchmarks> -limit 5 -dry-run

# 对照：head 取目录序前 N（5 题全是 IDOR 系列）——仅用于编号排查
go run ./cmd/bench -root <benchmarks> -limit 5 -strategy head -dry-run
```

`-dry-run` 与实际跑**共用同一份取样逻辑**（`xbow.Select`），所以预览到的题就是真跑的题。

### 怎么选跑多少题

| 目的 | 取样 | 说明 |
| --- | --- | --- |
| 冒烟（链路是否通） | `-limit 3` | 只为验证起停/判分，分数无意义 |
| 校准基线 | `-limit 10` ~ `15` | spread 已能覆盖主要题型与三档难度，性价比最高 |
| 对比改进 | 固定同一批题 | **必须锁题**：改动前后跑同一 `-only` 列表，否则分数不可比 |
| 正式基线 | 全量 104 | 最可信，但要按题型分批；L3 单题可能耗时最长 |

单题预算：`-task-timeout` 默认 30m、`-wait-timeout` 默认 45m。全量 104 题的**上界**
是 104×45m≈78h，实际大多提前解出/失败，但仍建议分批（如 `-levels 1` 45 题一批）。
想更快可以先 `-levels 1` 建立「能不能解简单题」的底线，再上 L2/L3。

流程（每题）：`docker compose -p xben-<id> up -d --wait` → 解析发布端口 → 提交任务
（描述里带目标 URL，`seed_first_intent=true` 省掉首轮 planner）→ 轮询到终态 → 在
`/api/exploration/findings` 原文里找 **flag** → `down -v`。

判分口径：**flag 出现即解出**，不做语义判断（flag 是唯一串，模型措辞不影响分）。

关键取舍：
- 端口挑选优先 80/8080/3000/5000/8000/8888 的**目标端口**，否则取最小发布端口——
  一道题常有 db+web，取第一个会把 agent 指向数据库；
- 单题失败不中断整轮（基准看通过率）；没有 `FLAG` 的题目计入 skipped，不进分母；
- 等待有上限（默认 45m/题），超时记为未解出而不是卡死。

### 1.8 外部 MCP 接入（P1-1：hexstrike）

MCP 服务器是 DB 驱动（`mcp_servers` 表 + `mcp_tools_cache` 工具缓存），所以「接入」= 注册一条记录。
本项目把它收敛成**一处配置 + 幂等播种**，不用在 UI 里手填 command/args：

```bash
git clone https://github.com/0x4m4/hexstrike-ai /opt/hexstrike-ai   # 或在别处
python3 /opt/hexstrike-ai/hexstrike_server.py                       # 先起 HTTP server（默认 8888）

export PRAETOR_HEXSTRIKE_DIR=/opt/hexstrike-ai                      # 只要这一条必须有
# 可选：PRAETOR_HEXSTRIKE_PYTHON=python3  PRAETOR_HEXSTRIKE_URL=http://127.0.0.1:8888
./dev.sh
```

启动时 `seedMCPPresets` 会：
1. 检查 `$PRAETOR_HEXSTRIKE_DIR/hexstrike_mcp.py` 存在（不存在就跳过并记日志，**不写坏记录**）；
2. `INSERT ... ON CONFLICT (name) DO NOTHING` 注册 `hexstrike`（transport=stdio，args=`[脚本, --server, URL]`，env=`PYTHONUNBUFFERED=1`）；
3. 已存在则保留用户改动（例如你在 UI 里把 enabled 关掉，重启不会被改回来）。

**注意**：这条预设只解决「怎么注册」。工具是否可用取决于 hexstrike 本身是否装好、能否被 python 调起；
首次注册后到「系统 → MCP」确认工具发现成功（失败会在日志里出现 `[mcp] ... 工具发现失败`）。

### 1.7 漏洞验证状态（P1-2 落库模型）

`findings` 新增 4 列，**与 `status`（人工处置）完全独立**，互不覆盖：

| 列 | 取值 | 谁写 |
| --- | --- | --- |
| `verification_state` | `unverified`（默认）/ `verified` / `suspected` | `verify_finding` 工具经宿主 verifier |
| `verification_similarity` | 0~1，`NULL` 表示无相似度可比 | 同上 |
| `verification_note` | 一行结论 + reasons | 同上 |
| `verified_at` | 最近一次验证时间 | 同上 |

为什么分开存：人可以给一个无法复现的漏洞标「风险接受」，也可能修复前先把验证刷成 suspected；
两个维度互相覆盖会让审计链断掉。

`verify_finding(finding_id, binding_id?, min_similarity?)` 的行为：
1. 取该漏洞绑定的证据（显式指定 > `proof` > `verification` > 最后一条）；
2. `replay.Verify` 重放（状态码一致 + 长度 ±15% + 归一化响应体相似度 ≥0.85）；
3. 落库：一致 → `verified`；不一致 / 无证据 / 重放失败 → `suspected`，`reasons` 说明原因。

**没有证据也照样落 suspected**——「证据不足」本身就是结论，比报错更有用。

### 1.6 独立部署栈（不与旧 ARTEX 栈共存干扰）

旧栈最常见的事故来源是 **compose 项目名默认取自目录名**：同一目录下 `docker compose up`
会复用同名项目、同名卷、同名容器和同端口。新栈因此显式固定四件套：

| 维度 | 旧 ARTEX 栈（不动） | PRAETOR 新栈 |
| --- | --- | --- |
| compose 项目 | `artex`（目录名推导） | **`praetor`**（`name:` 顶层固定） |
| 容器 | `artex-postgres-1` / `artex-praetor-1` | **`praetor-pg` / `praetor-app`**（显式 `container_name`） |
| 数据卷 | `artex_pgdata` | **`praetor-pgdata`** |
| 应用端口 | 8787 / 8788 | **8797 / 8798**（`PRAETOR_HTTP_PORT` / `PRAETOR_MCP_PORT` 可覆盖） |
| 数据库端口 | 5432（容器 `artex-pg`） | **55433**（容器 `praetor-pg`，`PRAETOR_PG_PORT` 可覆盖） |
| 测试库 | — | `praetor-test` 项目 / `praetor-test-pg` 容器 / **55432** |

**当前实测状态（2026-10-26）**：`praetor-pg` 已运行（PostgreSQL 16.15，`127.0.0.1:55433->5432`，库 `praetor` + `praetor_test`），
`praetor` 库已建 51 张表、`findings` 19 列（含 4 个验证列）；旧 `artex-pg` 仍为 Exited，未被触碰。
`.env` 由 `.env.example` 生成（密码随机化，已 gitignore）。

`docker compose config` 已离线校验。启动：

```bash
cp .env.example .env && $EDITOR .env      # 至少填 POSTGRES_PASSWORD
docker compose up -d --build              # 全栈（应用 + 数据库）
```

只起数据库、在宿主机跑服务（推荐；`dev.sh` 已自动装配 DSN，无需手敲）：

```bash
docker compose up -d postgres   # praetor-pg，宿主 127.0.0.1:55433
./dev.sh                        # 读 .env → 自动 export PRAETOR_PG_DSN → 后端 :8797 / 代理 :8798
```

手工方式：

```bash
export PRAETOR_PG_DSN="postgres://praetor:$(grep '^POSTGRES_PASSWORD=' .env | cut -d= -f2)@127.0.0.1:55433/praetor?sslmode=disable"
go run ./cmd/praetor -addr :8797 -proxy 127.0.0.1:8798
```

跑集成测试（必须用 `*_test` 库）：

```bash
docker exec praetor-pg createdb -U praetor praetor_test   # 首次
export PRAETOR_PG_DSN="postgres://praetor:$(grep '^POSTGRES_PASSWORD=' .env | cut -d= -f2)@127.0.0.1:55433/praetor_test?sslmode=disable"
go test ./... -count=1
```

**清理边界（重要）**：

| 命令 | 作用范围 | 会不会碰 `artex-pg` |
| --- | --- | --- |
| `docker compose -p praetor down -v` | 只删本项目 compose 项目 | 不会 |
| `docker compose -p artex down -v` | 只删 compose 项目 `artex` 的资源 | **不会**（`artex-pg` 无 compose 标签，是 `docker run` 起的独立容器） |
| `docker rm -f artex-pg && docker volume rm artex-pg` | 显式删那个容器与卷 | **会，数据全丢** |
| `docker system prune -a --volumes` / `docker volume prune` | 全局 | **有风险**，别用 |

所以：`down -v` 清理本栈是安全的；要动 `artex-pg` 必须显式点名，不用就不用管它。

> 现状：Docker Desktop 守护进程当前未启动（`npipe:////./pipe/dockerDesktopLinuxEngine` 不存在），所以测试栈暂未拉起；`docker compose config` 语法已校验通过。

---

## 2. 已完成

| 日期 | 内容 | 验证 |
| --- | --- | --- |
| 2026-10-26 | 四板块 GitHub 调研 + 架构方案 → `docs/网安Agent-选型与架构方案.md` | 报告交付 |
| 2026-10-26 | `agent/domain` 领域包骨架（DomainPack 接口 / Registry / 4 个 pack / 4 个确定性 Verifier） | `go test ./agent/domain` 全绿，6 个用例 |
| 2026-10-26 | 测试基线修复：`internal/testpg` 统一门禁 + 独立测试库 compose + `test-with-db.sh` | `go test ./...` 16 包全 ok |
| 2026-10-26 | 修 Windows 真 bug：`skillRelPath` 用 `filepath.Clean` 把 `scripts/run.py` 变成 `scripts\run.py`，改用 `path.Clean`（技能清单里存的是归档式斜杠路径） | `TestSkillRelPath` 由红转绿 |
| 2026-10-26 | 建立回滚点：`git init` + 基线提交 `5c28544` | `git log` 可见 |
| 2026-10-26 | **P0-3**：`agent/domain/adapter.go` — DomainPack → `subagent.Definition` + 工具白名单 + 预算合并 + 审批档位映射 + `Missing()` 装配期缺工具检测 | `go test ./agent/domain` 13 个用例全绿；`go build ./...` OK；全仓 16 包全绿 |
| 2026-10-26 | **P0-4**：`toolcatalog` 拆出 `platformAgentOrder` / `mergeSeeds`（公共骨架）/ `DomainToolSeeds(pack)` / `UnresolvedDomainTools(pack)` / `platformToolIndex()`；平台绑定用 golden 锁定 | `TestBuiltinToolSeedsPlatformUnchanged`（golden 25 条逐条一致）+ `TestDomainToolSeeds` + `TestUnresolvedDomainTools` 全绿；16 包全 ok |
| 2026-10-26 | 修正 pack 里凭 grep 猜错的工具名：`add_finding`→`report_finding`；删掉不存在的 `coverage`/`asset_coverage`/`list_worker_traces`/`bind_finding_traffic`/`get_finding_traffic`/`goals`，换成真实存在的 `list_untested_assets`/`get_worker_trace`/`search_all_worker_traces` | 由 `TestDomainToolSeeds` 断言 pentest 域缺失集为空 |
| 2026-10-26 | **改名 ARTEX → PRAETOR**：module path、二进制/镜像、前端品牌与偏好 key、登录用户名、文档全量更新；env 加 `PRAETOR_*` 优先 + `ARTEX_*` 兜底兼容层 | `go build ./...` OK；16 包全绿；`TestEnvPrefersNewPrefix` 锁定兼容顺序 |
| 2026-10-26 | 沙箱方案定稿：形态 A（常驻工具容器 + `docker exec`）+ `PRAETOR_SANDBOX=required\|optional` 默认 required | 决策入档 §1.5 |
| 2026-10-27 | **基线首跑 -levels 1 -limit 10**：v1 10%(1/10) → v2 50%(5/10)；加 `-prepull` 预拉基础镜像解决 buildkit token 不走代理（9/10 题能起靶场，剩 5 题是靶场 apt 源老化） | 真流量回测修正后**可信基线 40%（4/10，1 题假阳性被剔）** |
| 2026-10-27 | **判分来源校验**（关键修复）：v1/v2 只看 findings 文本 ⇒ 被污染。实测 XBEN-009 的 agent 未打漏洞：`cat .env`/`docker history`/`docker build --build-arg FLAG` 自建带 flag 容器再访问。改为 flag 必须同时在 **evidence + 目标流量**（按 host+端口过滤，端口排除自建容器），取不到流量不判解出 | bench 新增 5 用例（假阳性/宁漏勿虚高/hostPort/port 解析）；真数据回测 2 真 1 假 |
| 2026-10-27 | **token 收紧**：`MaxToolOutputChars` 30000 → 12000（worker+planner）。实测单条 tool_result 最大 30144 → 3894 字符，工具输出总量 −65%（一次 `curl` 整页 HTML 就是 10K tokens 且每轮重发） | 真跑 task8 验证生效 |
| 2026-10-27 | **bench 取样修正**：runner 原本完全没读 `benchmark.json`，`-limit N` 就是取目录序前 N 题，而 `XBEN-001/002/003` 恰是同一 IDOR 系列变体 → 分数被单一题型带偏。改为默认 `spread`（按 level 铺开 + 档内优先新 tag），新增 `-levels`/`-tags`/`-strategy`，`-dry-run` 与真跑共用同一取样逻辑 | 真实题库验证：head 取 5 题全 IDOR；spread 同 5 题覆盖 6 类题型 + 1 道 L3；bench 15 用例全绿 |
| 2026-10-27 | **Pikachu 实战首次跑通证据链闭环**：任务 #6 `done`，2 个漏洞自动 `verified`（similarity=1.000：SQL Injection + Reflected XSS）+ 8 条流量绑定 + 179 条流量入库。过程中定位并修掉 4 个卡点（靶场 build 未走代理、`traffic_capture` 未开、`agent_traffic_binding` 未开、服务未重启仍读旧 LLM key） | 新增启动期 `WarnEvidenceChainDisarmed` 护栏（只告警不改配置）+ 单测；真库 18 包全绿 |
| 2026-10-26 | **P1-3 骨架**：`bench/xbow`（Discover/ComposeCLI/FirstHTTPPort/FlagMatcher/Run/Summary.Markdown）+ `cmd/bench`（-dry-run/-only/-limit/-keep/-md/-out，支持密码换 token） | 10 个单测（发现/端口优先级/flag 匹配/编排三类结果/失败不提交/跳过计分母）；CLI dry-run 冒烟通过 |
| 2026-10-26 | **P1-1**：`db.SeedMCPServer`（幂等预设播种，`ON CONFLICT DO NOTHING`，不覆盖用户配置）+ `server/mcp_presets.go`（hexstrike 预设构造/校验，未配置不写库） | `db` 2 个用例（真库幂等 + 入参校验）、`server` 3 个用例（构造/覆盖/拒绝缺失）；全仓绿 |
| 2026-10-26 | **修真库测试红灯**：① 修真 bug `evidence` 目录 fsync（Windows 绑流量 422）② 修测试收尾泄漏 ③ 更新过时断言（coverage 已无 scope 字段）④ 唯一化跨轮数据 + `llmrec` 补 advisory lock + DB 套件 `-p 1` | 真库 `go test -p 1 ./...` 连跑 2 次全绿；无库 18 包全绿 |
| 2026-10-26 | **P1-2 收口**：注册 `verify_finding`（仅 worker）+ 宿主侧 `NewEvidenceVerifier`（evidence.Store 适配 + 证据挑选 + 结论落库）+ `findings.verification_state` 四列；工具提示词要求「绑定后先验证」 | `agent` 5 个工具用例 + `server` 6 个验证器用例；golden 有意变更 `verify_finding→worker` 已按纪律重生成 |
| 2026-10-26 | **P1-2（核心）**：`internal/replay` 重放判定（状态码/长度容差/归一化 4-gram Jaccard 相似度/易变值抹除）+ `agent.VerifyBinding` 快照适配（head 容错解析、body 走 `BodySource` 接口） | `replay` 14 个用例 + `agent` 6 个用例全绿；无响应体无哈希时 fail-closed |
| 2026-10-26 | **P0-7 一任务一容器**：`sandbox/per_task.go` + `BackgroundRunner` + 代理注入 + 任务 ID 透传（`RunInfo.TaskID`）+ reaper；修复 Windows `docker -v` 反斜杠路径 | `sandbox` 18 个用例 + `server` 5 个接线用例全绿 |
| 2026-10-26 | **P0-6**：`sandbox` 包 + worker Bash 装饰 + `praetor-sandbox` 容器；修复自测发现的 **fail-open bug**（docker exec 非零退出被当成成功，导致容器不存在也判可用） | `sandbox` 7 个用例 + `agent` 沙箱 8 个用例全绿；16 包全绿 |
| 2026-10-26 | **P0-5**：`server/engine_scheduler.go` — `DomainPackFor` / `SchedulerPlanFor` / `SchedulerPlan`；`Engine.Run` 改为「问领域包要调度拓扑」；启动期 `WarnUnresolvedDomainTools()`；新增 `PRAETOR_DOMAINS` 环境变量（默认 `pentest`） | 6 个新测试全绿（explore 拓扑=1+N、非 explore 明确报错、默认域、env 解析）；全仓 16 包全 ok |
| 2026-10-27 | **逆向域重新设计（配方化，零 MCP）**：不接 REA / GhidraMCP 全家桶。工具面收敛为 3 个（`re_triage` 纯 Go 全貌 / `re_recipe` 配方枚举 / `re_evidence` 唯一结论出口），外部能力以**配方表**（9 条，≤10 硬约束）挂 rizin / Ghidra headless / capa / FLOSS / DIE / jadx 等 CLI；角色 5→2、MaxTurns 190→50、并发 2→1。顺带查实 `Budget` 的 `MaxTokens`/`MaxToolCalls`/`MaxParallel` **没有任何执行层消费**（初版「6M tokens / 3000 次」从未生效），成本控制改由 P3-1 的调度闸门承担 | 新增设计契约测试 6 个（工具面=设计集、零 MCP、角色≤2、角色不得声明域外工具、预算串行有界、配方必须写许可且≤10）；`agent/domain` 19 用例全绿；`ctf.go` 的 `rea` MCP 声明同步删除 |
| 2026-10-27 | **P2 CTF 完整设计**：工具面 2 个（`ctf_challenge`/`ctf_submit`）+ 零 MCP；竞速改为**延迟竞速（默认单路，停滞才起第二路）**，`MaxParallel` 8→2、MaxTurns 合计 285→195；首解收敛用已有 steer hook（不硬 cancel ctx、不引入 subagent）；提交侧建 `ctf_submissions`（PK=flag sha256）做去重 + ctfd/offline 双判分模式；镜像工具链改为 `CTFToolchain()` 分层表（基础层 ≤12，angr/sage/volatility3 按需）；并清掉 5 个 solver 上 **13 个不存在的工具 key**（`curl_run`/`burp_repeater`/`pwntools_run`/`gdb_run`/`checksec`/`ghidra_decompile`/`rizin_analyze`/`sagemath_run`/`ciphey_decode`/`tshark_run`/`binwalk_run`/`zsteg_run`/`volatility_run`） | 新增设计契约测试 6 个（工具面=设计集/零 MCP/角色≤6 且 MaxTurns≤200/角色必须有 Bash/不得发明工具名/预算并发≤2/工具链分层与许可）；`agent/domain` 27 用例全绿 |
| 2026-10-27 | **P3-2 `re_triage` 落地 + R6 铁律**：新增 `internal/binfmt`（纯 Go 解析 PE/ELF/Mach-O：头/段表/熵/导入表/导出数/安全缓解/加壳依据/字符串分类）+ `agent/re_tools.go` 的 `re_triage` 工具（摘要 ≤1.4KB、完整 JSON 落盘、不执行样本、畸形输入只降级不 panic）；`toolcatalog` 新增 `domainOwnedTools()` —— 领域专属工具**可解析但不播种给平台 agent**；文档 §0 新增 **R6 自包含优先（不依赖第三方 GitHub 项目）** | binfmt 8 个用例（含拿测试二进制自身当样本、畸形 PE 不 panic、熵边界、字符串提取与版本号误判、渲染预算）；agent 4 个用例（真实 PE 全链路/坏入参/未接入清单/领域工具不污染平台种子）；平台 golden 未变 |
| 2026-10-27 | **可选组件面板（沙箱镜像层）**：`internal/components`（14 项清单 + Dockerfile/探测脚本生成器，单一数据源）+ `server/components.go`（清单/应用/探测/SSE 四个接口，构建串行单例、日志环形缓冲 400 行、失败回传尾部）+ 设置页「可选组件」卡片（分组勾选/体积估算/已装徽章/构建日志实时滚动）；镜像 tag 由选择集 hash 决定，切回 `:latest` 即回滚；`WireSandboxWithImage` 让 settings 里的镜像优先生效 | components 7 用例 + server 5 用例；真机接口验证：清单 14 项、未知 ID→400、基础镜像缺失→409（带可执行构建命令）、无镜像探测→409 |
| 2026-10-27 | **组件面板端到端跑通 + 修真机构建暴露的 3 个 bug**：①Dockerfile 续行（单命令组件生成 `;` 开头新行）②extras 层缺 `apt-get update`（基镜像删了包索引）③kali 官方源被镜像 403（改默认阿里云 + 重试）④`errorLines()` 按特征挑错误行而不是只回传尾部 | 基础镜像 553MB → 应用 gdb → custom-eb685c80 658MB；探测 `gdb ok=true 18.1`；重复应用 0.57s 走 skipped；新增 `validateDockerfile` 语法校验用例 |

---

## 3. 任务清单

状态：`待做` / `进行中` / `已完成` / `阻塞`

**当前进度快照（2026-10-27）**

| 阶段 | 内容 | 状态 |
| --- | --- | --- |
| P0 骨架 | 领域包 / 测试门禁 / 装配层 / 调度接缝 / 沙箱（常驻 + 一任务一容器） | ✅ 6/6 |
| P1 渗透对齐 | hexstrike 配置层 / 确定性验证闭环（`verify_finding` + 落库）/ XBOW 基线 runner | ✅ 3/3（基线可信 **40%**，见 `docs/基线-XBOW-L1-可信版.md`） |
| P2 CTF | **已完整设计（2 工具 + 延迟竞速 + 提交去重 + 分层镜像）**，实现未开始 | 设计完成，P2-1~P2-6 待做 |
| P3 逆向 | 3 工具 + 配方 + 零 MCP；**`re_triage` 已落地（纯 Go，零依赖）** | 实现进行中 1/5 |
| P4 红队 | campaign 调度器 / Caldera / Sliver / GOAD | 未开始 0/4 |

> 下一步只有两个正当入口：**P3-1**（evidence 调度闸门，逆向域的总开关）或 **P2-1**（race 调度器，CTF 的总开关）。
> 两者都是「调度器」，说明现在的瓶颈已经从"能力"转到"第二轮执行模型"——渗透域的 explore 调度器已经在跑（基线 40% 就是它跑出来的）。

### P0 骨架（目标：领域可插拔，渗透行为零变化）

> 四域 pack 均已注册；逆向域 2026-10-27 重新设计实现方式（不再接 MCP 全家桶），pack 骨架不变。

| ID | 任务 | 做法 / 复刻来源 | 验收 | 状态 |
| --- | --- | --- | --- | --- |
| P0-1 | DomainPack 接口 + 4 域声明 | 自研（无现成可复刻） | `go test ./agent/domain` 绿 | 已完成 |
| P0-2 | 测试基线统一门禁 | 自研（项目内既有 skip 惯例推广） | `go test ./...` 全绿 | 已完成 |
| P0-3 | `agent/domain/adapter.go`：DomainPack → `[]subagent.Definition` + 工具白名单过滤 | **复刻 norma** `subagent.filterTools` 语义（与 SDK 完全一致：空=继承、未知丢弃） | 单测：给 pentest pack 生成 2 个 Definition，工具集与 `Roles()[].ToolKeys` 一致 | 已完成 |
| P0-4 | `toolcatalog`：拆出 `mergeSeeds` 公共骨架 + `DomainToolSeeds(pack)` + `UnresolvedDomainTools(pack)` + `platformToolIndex()`；平台 agent 绑定用 golden 锁定 | 自研（原地重构，公共骨架复用原有合并语义） | `TestBuiltinToolSeedsPlatformUnchanged` 逐条一致；`TestDomainToolSeeds` / `TestUnresolvedDomainTools` 通过 | 已完成 |

> **P0-4 设计修正（2026-10-26，已按此实现）**：原计划「`builtinToolsByAgent()` 改由 `All()` 驱动」不可行，且会破坏两条既有约束：
> ① DomainPack 刻意**零依赖、只持字符串 key**（不 import `actool`），拿不到 `CoreTool` 实例；
> ② 工具 handler 必须留在代码里（`toolcatalog` 的注释已明确「DB 只能改散文与默认值，改不了 handler」）。
>
> 实际落地：**实例由代码提供，清单由 pack 提供，且分两条通道播种**。
> - `BuiltinToolSeeds()` 保持原样（平台 6 个 agent，`mergeSeeds` 原逻辑抽出复用）→ 存量库与新装库的绑定**逐条不变**，由 `testdata/seeds_platform.golden` 锁定。
> - `DomainToolSeeds(pack)` 单独展开某域的角色，**只在装配该域时调用**；不让四域的 agent 参与每次启动的全局播种（否则每个装了 PRAETOR 的库都会多出 `ctf-lead`、`solver-pwn` 等用不到的 agent 行）。
> - `UnresolvedDomainTools(pack)` 供装配期告警：声明了但还解析不出实例的 key（例：逆向域待接入的 `re_triage`/`re_evidence`、红队域的 `sliver_session`、CTF 的 `pwntools_run`）。
>
> **踩到的坑（值得记）**：初版 pack 里 `add_finding` / `coverage` / `asset_coverage` / `list_worker_traces` / `bind_finding_traffic` 这些名字是我按 grep 猜的，真实清单里是 `report_finding` / `list_untested_assets` / `get_worker_trace` / `search_all_worker_traces`，其余根本不存在。`UnresolvedDomainTools` 第一次跑就把它们全抓出来了——这正是这个函数存在的理由。
| P0-5 | engine 按 `Scheduler()` 选调度器；`explore` 复用现有 `plannerLoop`；启动期用 `agent.UnresolvedDomainTools()` 打「声明了但未接入」的工具警告 | 自研 | 现有渗透用例回归通过（行为不变）；启动日志能看到缺失工具清单 | 已完成 |
| P0-6 | `sandbox/` 包（Runner 接口 + Docker/Host 实现 + `Failing` fail-closed）+ `agent/sandbox.go` 装饰器 + `sandbox/Dockerfile` + compose `sandbox` 服务；只包 worker 的 Bash | **复刻 PentAGI 的沙箱工具镜像思路**（MIT）+ Strix 容器分层（Apache-2.0） | Docker 不可用时 required 明确拒绝、optional 告警降级、off 不改行为 | 已完成 |
| P0-7 | **一任务一容器**：`PerTaskRunner`（惰性创建/复用/空闲回收/Release）+ 后台执行 `docker exec -d` + 代理注入 | 参考 Strix 的「任务级容器 + 工作区挂载」、PentAGI 的标签化容器管理 | 10 个单测（隔离/并发单建/复用/回收/后台/引号转义/镜像缺失）；全仓 17 包绿 | 已完成 |

> **P0-5 实现说明**：`Engine.Run` 现在第一件事是 `SchedulerPlanFor(DomainPackFor(t), m.Workers())`。
> - `explore` → `{Planners:1, Workers:N}`，与改造前的 `1+workers` 例程账本逐字等价（`m.Workers()` 自身已有 >0 兜底，代码里的 clamp 只对直接调用生效，属防御而非行为变更）。
> - 其它调度器 → 返回 `errSchedulerNotImplemented`，`Run` 记一条 ERROR 后 **不启动任何循环**。刻意不回落 explore：半成品静默跑歪比直接失败难查。
> - `DomainPackFor` 目前恒返回渗透域（`tasks` 表还没有领域字段）；P1 加列后改为读库。
> - 告警用的是 `agent.UnresolvedDomainTools(pack)`（面向 tools 表的视图），不是 `domain.Missing(pack, reg)`（面向一个具体 Registry）；后者留到真正装配 Registry 时用。

### P1 渗透对齐

| ID | 任务 | 做法 / 复刻来源 | 验收 | 状态 |
| --- | --- | --- | --- | --- |
| P1-1 | hexstrike MCP 接入：`db.SeedMCPServer`（幂等、不覆盖用户改动）+ `server/mcp_presets.go`（配了 `PRAETOR_HEXSTRIKE_DIR` 才注册，否则只打提示）+ 文档配方 | 直接接入 `0x4m4/hexstrike-ai`（外部进程，不复制代码） | 预设记录构造/校验有单测；幂等播种真库验证；**实际工具可用需用户安装 hexstrike 后确认工具列表** | 已完成（配置层） |
| P1-2 | 确定性验证闭环：`internal/replay` + `agent.VerifyBinding` + `verify_finding` 工具 + `verification_state` 落库（unverified/verified/suspected） | **复刻 Pentest-Swarm 的 oracle 思路**（AGPL，只读思路，自行实现） | 重放一致→verified；不一致/无证据/重放失败→suspected 并写明 reasons；**均有单测** | 已完成 |
| P1-3 | **已实现**：`bench/xbow`（Discover 读 `benchmark.json` 的 level/tags / 分层取样 spread / `PrepareImages` 预拉 / `ComposeCLI` 起停 / 端口优先 web / flag 判分**含流量来源校验**）+ `cmd/bench`（`-levels -tags -strategy -prepull -dry-run -md -out`）+ 可信基线报告 | 接入 `xbow-engineering/validation-benchmarks`（104 题） | **已出分**：`-levels 1 -limit 10` 名义 50% → 剔除 1 个假阳性后**可信 40%（4/10）**，逐题给出 flag 命中的流量 URL 作为依据 | 已完成（基线已记录） |

### P2 CTF（2026-10-27 完整设计）

**目标与判据**：在时间预算内**最大化「被平台接受的 flag 数」**。判据完全客观——`ctfVerifier` 已强制
「`accepted` 缺失即不计分」，模型自述「解出来了」一律无效。这条不能松，松了整个域就退化成"讲故事"。

**设计原则（五条，前三条与 P3 同源）**

1. **工具面在模型外**：模型只看到 2 个工具，真正的能力是沙箱 CLI 工具链（见 `CTFToolchain()`）。
   加一个工具 = 改镜像，**不改 schema**。
2. **首解即收敛**：任一路拿到 `accepted`，立刻让同题其余 solver 停下。竞速的价值不在"跑得快"，
   而在**省下败者的 token**。
3. **延迟竞速（lazy race）**：默认**单路**，出现停滞信号才起第二路。并行是唯一把成本 ×N 放大的操作，
   而多数题单路能解——一上来就 2~8 路是纯浪费（初版 `MaxParallel: 8` 就是这个问题）。
4. **提交唯一出口**：所有 flag 只能经 `ctf_submit` 出门，由它做 格式校验 → 本地去重 → 平台提交 → 落 verdict。
   去重放在**工具里**而不是某个角色里，任何角色调用都安全。
5. **到顶就放弃**：单题 token/轮数到上限 → 标 `abandoned` 并写清「试过什么、建议下一步」，
   让人能接手；不允许在同一个点上无限重试烧预算。

**工具面（2 个，零 MCP）**

| 工具 | 作用 | 关键约束 |
| --- | --- | --- |
| `ctf_challenge(id)` | 拉题面/附件清单/实例地址/剩余重置次数，**附件落盘**到 `workdir/chal/<id>/` | 只回摘要与文件路径，不回附件正文（模型用 `Read` 按需读，避免一次灌爆上下文） |
| `ctf_submit(flag, evidence)` | **唯一提交出口**：格式校验 → 本地去重 → 提交（CTFd 或离线判分）→ 落 verdict | 返回 `accepted/rejected/duplicate` + 平台原文；失败原因原样回给模型，不做美化 |

> CTFd **不走 MCP**：只需要「拉题面」「提交」两个动作，写进工具里的 HTTP 客户端比多起一个进程
> 少一份 schema、少一条会出错的链路。

**沙箱工具链（镜像分层，由 `CTFToolchain()` 定义，P2-3 落地）**

| 类别 | 基础层（`Base=true`） | 非基础层（按需） |
| --- | --- | --- |
| pwn | `python3+pwntools`、`gdb`、`pwndbg`、`ROPgadget`、`seccomp-tools` | — |
| rev | `rizin`、`binwalk` | — |
| crypto | `z3`、`ciphey` | `angr`（BSD-2）、`sage`（GPL-3，GB 级） |
| forensics | `tshark`、`zsteg`、`exiftool` | `volatility3` |

> 为什么要分层：**镜像体积直接决定冷启动**，而 CTF 是抢时间的场景。三个重依赖（angr/sage/volatility3）
> 在基础层之外，按题安装；`TestCTFToolchainIsLean` 守着「基础层 ≤12 项 + 重依赖必须非基础层」。

**竞速调度（P2-1 的核心）**

```
raceLoop(task):
  ① 枚举题目 → 建 challenge 节点；按「类型先验 × 预期难度 × 剩余时间」排序
  ② 单路探测：为当前题建 1 个 intent（起点 A），交给现有 worker
  ③ 每轮图更新后判停滞：连续 K 轮（默认 6）无新 fact 且无 flag，或 intent 结束仍无 flag
  ④ 停滞 → 起第二路（起点 B：另一条攻击面/另一种工具），
     并把「A 已试过什么」写进 B 的上下文（避免两路重踩）
  ⑤ 任一路 ctf_submit 得到 accepted：
       写 flag 节点（含平台回执）→ 给同题所有在跑 intent 注入 steer
       「本题已解出，立即停止，只输出一句话」→ 摘 winner 的关键步骤成 writeup
  ⑥ 两路都到轮数/预算上限 → abandoned（写已试清单）；换下一题
```

三个实现取舍（都比"理想方案"便宜，且复用现有机器）：

- **不引入 subagent 派生**：运行时至今没有 `subagent.` 的调用点（只有 domain 包内的声明），
  所以 race 第一版复用现有 **worker + intent** 机制，不新增一层 agent。
- **不硬 cancel ctx**：用已有的 steer hook 注入「本题已解出，立即停止」，让 worker 在下一轮自然收尾。
  这比给每个 intent 造独立 ctx 便宜得多，也不会把半截输出丢掉。
- **停滞判定只读现有数据**：用探索图的 fact 增量与 activity，不新建表。

**提交仲裁与去重（P2-2）**

```
ctf_submissions(flag_sha256 PK, challenge_id, flag, verdict, submitted_at, raw_response)
  - PK 用 flag 的 sha256 → 天然去重（同一 flag 全局只发一次）
  - verdict: accepted | rejected | duplicate
  - 命中已存在记录：直接返回缓存 verdict，不再打平台（防重复扣分/风控/重复计分）
  - rejected 的 flag 不允许"再试一次"：同一 flag 反复提交是纯浪费
```

两种判分模式（同一个工具出口，靠配置切换）：

| 模式 | 何时用 | 判据 |
| --- | --- | --- |
| `ctfd` | 真实比赛/靶场 | `POST /api/v1/challenges/attempt` 返回 `status=correct` |
| `offline` | 基准跑分（Cybench / NYU 子集） | 与题库给定 flag 精确匹配（不用联网） |

**成本模型（定闸门用，不是预测）**

| 场景 | 单题 input 估算 | 说明 |
| --- | --- | --- |
| 单路 25 轮 | ~450K | 12K 固定 + 增长，中位 ~18K/轮 |
| eager 2 路（总是并行） | ~900K | 初版的隐含成本 |
| **lazy race（约 40% 需要第二路）** | **~630K** | 比 eager 省 ~30% |
| 40 题全量（lazy） | ~25M | 所以基准必须 `-limit` 分批 |

**基准（P2-4）**：复用 `bench/xbow` 的结构（Discover / Run / Summary），换判分器为「离线 flag 比对」。
- 题库：Cybench 40 题（Apache-2.0）；NYU CTF Bench 子集（**GPL-2.0：题库只作评测用，不复制代码**）
- 指标：解出数、**time-to-flag**、每题 input tokens、工具调用次数、被拒提交次数、去重拦截次数
- 口径：先出基线，之后每次改动的分数**不得低于上一版基线**（与 P1-3 同一条纪律，不先编目标分）

| ID | 任务 | 做法 / 复刻来源 | 验收 | 状态 |
| --- | --- | --- | --- | --- |
| P2-1 | `raceScheduler`：lazy race + 停滞判定 + 首解收敛 + 预算闸门 | **复刻 `verialabs/ctf-agent` 的 coordinator + solver swarm 结构**（MIT，可复制）；收敛用本项目已有的 steer hook | 单题两路并行能收敛；首解后另一路在 **1 轮内**停止；到顶能 abandoned 并留下已试清单 | 待做 |
| P2-2 | `ctf_challenge` / `ctf_submit` 两个工具 + 去重表 + 双判分模式（ctfd / offline） | CTFd API（Apache-2.0，外部服务调用） | 同一 flag 提交两次，平台只收到一次；rejected 不复投；附件落盘且不回正文 | 待做 |
| P2-3 | CTF 沙箱镜像：基础层 + crypto 可选层 | 按 `CTFToolchain()` 构建；重依赖不进基础层 | 基础镜像 ≤12 项且能跑通 1 道 pwn + 1 道 forensics；`angr/sage` 按需装 | 待做 |
| P2-4 | Cybench 40 题 + NYU 子集出分（复用 `bench/xbow` 结构） | 接入 benchmark，离线判分 | 出基线分并记录到本文件；含 time-to-flag 与每题 token | 待做 |
| P2-5 | **per-intent 模型路由**（换模型竞速） | 自研：模型现在是任务级 profile 链（`task_llm.go` 的 `ActiveLLMProfileID`），要做 per-intent 需改解析层 | 同一题两路可用不同 profile；失败路回退换模型 | 待做 |
| P2-6 | 题目优先级与放弃策略（按分值/剩余时间/预算动态排序） | 自研；参考 ctf-agent 的"先易后难 + 限时放弃" | 预算紧时优先高分易题；放弃的题有记录 | 待做 |

**已知限制（写在这里，别当成已实现）**

1. **第一版不换模型**：race 靠「换起点/换思路」，不靠「换模型」（P2-5 才做）。
2. **CTFd 需要 token**：拿不到就退化为 `offline` 模式；基准跑分用的是 offline。
3. **无 subagent 派生**：race 跑在现有 worker 上，所以「两路」= 两条 intent，不是两个 agent。
4. **实例重置次数**：CTFd 题目有 reset 限制，`ctf_challenge` 会回报剩余次数，策略上要留余量。

**风险与回滚**

| 风险 | 兜底 |
| --- | --- |
| 并行把预算烧光 | `MaxParallel ≤2` + 单题 token 闸门 + 首解即收敛（三道） |
| flag 误判 | Verifier 只认 `accepted`；离线模式必须精确匹配 |
| 重复提交被平台风控 | 去重表 PK 用 flag 哈希，命中直接返回缓存 |
| 镜像过大拖慢冷启动 | 分层 + 测试守着「基础层 ≤12」 |
| race 调度写错导致任务卡死 | 保留 `PRAETOR_CTF_RACE=off` 回落到单路串行（与 explore 等价） |

### P3 逆向（2026-10-27 重新设计：配方化，零 MCP）

**为什么推倒重来**（三条都是本项目实测，不是推测）：

1. **固定成本每轮重发**：现网实测每轮 ~10.7K tokens（32 个工具 schema + 8 段提示词），工具越多这笔钱越贵。
2. **贵在调用次数，不在单次体积**：实测一道渗透题 13 次 `traffic_get`（每次仅几百字符）≈ 630K tokens ——
   因为每次调用都要重发整个上下文。工具多 = 选择多 = 试错多 = 次数多。
3. **MCP 全家桶的规模是量级问题**：`bethington/ghidra-mcp` 自称 **200+ 个工具**；`morluto/rea` 是
   多家族 monorepo（二进制 + 应用包 + 浏览器运行时 + android/apktool + cutter + artifact 对比）。
   即使每个工具描述只值 60 tokens，200 个就是 12K tokens/轮 —— **固定成本直接翻倍**，
   而且 200 条「可能路径」会让模型反复浅尝，而不是把一条证据链走完。

**设计原则：能力活在工具面之外。**

> 模型永远只看到 3 个工具；底下挂多少 CLI、来自哪个项目，模型不需要知道，也就不会为「该用哪个」付试错成本。
> **接一个新能力 = 加一行配方**，schema 不变、模型选择空间不变、每轮固定成本不变。

**工具面（3 个，零 MCP）**

| 工具 | 作用 | 输出上限 |
| --- | --- | --- |
| `re_triage(target)` | 纯 Go 解析 PE/ELF/Mach-O：格式/架构/位数/编译器/加壳迹象/入口/段熵/高风险导入/字符串摘要 | 摘要 ≤1.5KB，全文落盘 `re/<sha256>/triage.json` |
| `re_recipe(recipe, target, page)` | 按配方名执行已固化的 CLI 管道 | 单次 ≤2KB（`decompile` ≤4KB），超出落盘 |
| `re_evidence(claim, ref, xref_count, trace_ref)` | **唯一结论出口**，交给 `reverseVerifier` 判 | — |

**配方表（9 条；≤10 是硬约束，超了先问「哪条能合并」）**

| 配方 | 上游 | 许可 | 依赖 | 返回 |
| --- | --- | --- | --- | --- |
| `triage` | 自研（纯 Go） | — | **无** | 全貌摘要 + 落盘 |
| `disasm` | `rizinorg/rizin` | LGPL-3.0 | `rizin` | 函数/地址区间反汇编，分页 ≤60 条 |
| `xrefs` | `rizinorg/rizin` | LGPL-3.0 | `rizin` | 交叉引用（谁调用/谁读取），分页 |
| `decompile` | `NationalSecurityAgency/ghidra` | Apache-2.0 | `analyzeHeadless` | 单函数伪代码 ≤4KB（headless 脚本，**不接 MCP**） |
| `strings` | `mandiant/flare-floss` | Apache-2.0 | `floss` | 还原混淆串，去重分类 ≤2KB，全量落盘 |
| `capability` | `mandiant/capa` | Apache-2.0 | `capa` | 命中的能力与地址 ≤2KB |
| `packer` | `horsicq/Detect-It-Easy` | MIT | `diec` | 编译器/加壳判定与依据（配合段熵） |
| `trace` | `gdb` | GPL-3.0 | `gdb` | 指定函数的动态调用序列（只输出序列，不输出全文） |
| `mobile` | `iBotPeaches/Apktool` + `skylot/jadx` | Apache-2.0 | `apktool`、`jadx` | APK 清单关键项 + 类名清单（分页），不返回反编译全文 |

> 选择标准只有一条：**单命令、可 JSON 化、确定性输出**。需要长交互会话、需要 GUI、或自带几百个工具的一律不进表。
> 缺依赖时**明确报「缺 X」**，不静默降级（与沙箱 `required` 同一条纪律）。
> 代码里 `agent/domain/reverse.go` 的 `ReverseRecipes()` 就是这张表；`TestReverseRecipeCatalogIsLean` 守着
> 「≤10 条」和「有上游必须写许可」两条，改表会被测试拦住。
>
> **按 R6：配方全是可选加速器。** 核心路径（`re_triage` 全貌解析、`re_evidence` 证据落库）**零外部依赖**，
> 干净机器上就能用；配方缺依赖时明确报「缺 X，装法见文档」，不阻塞分析（先用 triage + 字符串/导入判断方向）。

**角色 5 → 2**：`re-lead`（定路线 + 证据链，20 turns）、`re-analyst`（执行单条意图，30 turns）。
砍掉的 `malware-analyst` / `mobile-analyst` 是**场景差异不是能力差异**（同一个分析者换目标而已），
而每个角色都是一份常驻 system prompt；静态/动态合并是因为串行证据链本来就交替，拆开会多一次交接。

**成本账**

| 指标 | 初版设计（REA/GhidraMCP 路线） | 新设计 |
| --- | --- | --- |
| 进 schema 的工具数 | 全家桶 + 3 个 MCP | **3** |
| 每轮固定成本增量 | +12K tokens 量级 | **+约 400 tokens** |
| 角色数 / 常驻提示词份数 | 5 | **2** |
| MaxTurns 合计 | 190（30+60+50+50+50） | **50** |
| 并发 | 2 | **1（串行）** |
| 缺依赖时 | 静默少工具，模型自己找路 | 配方明确报「缺 X」 |

> **诚实说明**：`Budget` 里的 `MaxTokens` / `MaxToolCalls` / `MaxParallel` **目前没有任何执行层消费**
> （全仓只有 `MaxDepth` 透传给了 subagent），所以初版的「6M tokens / 3000 次工具调用」从来没生效过。
> 真正的成本控制落在 P3-1 的调度器闸门；现在这些数字改成贴近现实的目标值。

| ID | 任务 | 做法 / 复刻来源 | 验收 | 状态 |
| --- | --- | --- | --- | --- |
| P3-1 | `evidenceScheduler`：串行推进 + checkpoint 续跑 + **预算闸门** | 自研（设计见上） | 中途 kill 后能续跑、不重复已完成阶段；轮数/token 到顶时强制「收束并写未确认」而不是硬撑 | 待做 |
| P3-2 | `re_triage`：纯 Go 解析 PE/ELF/Mach-O（头/段表/熵/导入/字符串摘要/加壳依据） | 自研（`internal/binfmt`），字段划分参考 `lief-project/LIEF`（Apache-2.0，只读思路） | ✅ 用真实 23.6MB PE 验证：8 段/51 导入/熵/可疑 API 全部解析；摘要 **795 字节**（≤1.4KB）、JSON 落盘、零外部依赖 | ✅ 已完成 |
| P3-3 | `re_recipe` 骨架 + 静态配方（`disasm`/`xrefs`/`decompile`/`strings`/`capability`/`packer`） | 外部进程调用 rizin / Ghidra headless / FLOSS / capa / DIE（**不复制、不链接代码**） | 装了该 CLI 时可用；未装时明确报「缺 X」而非空结果 | 待做 |
| P3-4 | `re_evidence` + 证据链闭环（`reverseVerifier` 已就绪） | 自研 | 无 xref 无 trace 一律不判 Done（已有单测守着） | 待做 |
| P3-5 | 动态/移动配方（`trace`/`mobile`）+ 样本治理（加密存储、哈希索引、禁止整包进 LLM） | 自研（合规要求） | 请求日志里无完整样本；`trace` 只回调用序列 | 待做 |

**域级验收口径**：一道中等难度 rev 题 —— **input ≤ 300K tokens、调用 ≤ 40 次、结论有 xref 或 trace 支撑**。

### P4 红队

| ID | 任务 | 做法 / 复刻来源 | 验收 | 状态 |
| --- | --- | --- | --- | --- |
| P4-1 | `campaignScheduler`：ATT&CK 阶段 DAG + 前置判定 + cleanup 强制 | **复刻 `m-sec-org/BreachWeave` 的 Manager/Observer/Solver 三角色**（先确认许可） | 前置未满足不下发下一步 | 待做 |
| P4-2 | Caldera / Atomic Red Team 编排接入 | 直接接入（Apache-2.0 / MIT） | 能下发一条 ability 并回收结果 | 待做 |
| P4-3 | Sliver / NetExec / BloodHound 接入（独立服务 + MCP） | 直接接入（Sliver GPL 只做外部服务，不复制） | 会话列表可读、路径可查 | 待做 |
| P4-4 | GOAD 靶场跑通一条端到端战役 | 靶场 `Orange-Cyberdefense/GOAD` | 有证据链 + 有 cleanup 记录 | 待做 |

---

## 4. 复刻清单（R1 的唯一索引）

| 来源 | 许可 | 复刻什么 | 允许方式 |
| --- | --- | --- | --- |
| `usestrix/strix` | Apache-2.0 | agent 图编排结构、沙箱镜像分层、`strix view` 回放思路 | 可复制代码 |
| `vxcontrol/pentagi` | MIT | 沙箱内跑工具的做法、summarizer 压缩策略、pgvector 长期记忆 | 可复制代码 |
| `norma`（已在依赖里） | 同源 SDK | `subagent` / `coordinator` / `filterTools` / `skill` | 直接用 |
| `verialabs/ctf-agent` | MIT | coordinator + solver swarm、CTFd 接入、**懒惰竞速的取舍** | 可复制代码 |
| `andyzorigin/cybench` | Apache-2.0 | CTF 评测集（40 题）与判分口径 | 评测使用（外部调用） |
| `NYU-LLM-CTF/NYU_CTF_Bench` | **GPL-2.0** | 题库与基线思路 | **只读思路**（题库仅评测用，不复制代码） |
| `CTFd/CTFd` | Apache-2.0 | 判题/提交 API（`/api/v1/challenges/attempt`） | 外部服务调用 |
| `pwndbg/pwndbg`、`ciphey/ciphey`、`ReFirmLabs/binwalk` | MIT | 镜像内 CLI（pwn / crypto / rev） | 外部进程调用 |
| `Gallopsled/pwntools`、`Z3Prover/z3`、`JonathanSalwan/ROPgadget`、`volatilityfoundation/volatility3` | 未标注（GitHub 未识别） | 镜像内 CLI | 外部进程调用，**不复制代码** |
| `rizinorg/rizin` | **LGPL-3.0** | 反汇编 / 交叉引用 CLI（`disasm`、`xrefs` 配方） | 外部进程调用，不链接代码 |
| `NationalSecurityAgency/ghidra` | Apache-2.0 | headless 反编译脚本（`decompile` 配方，**不接 MCP**） | 外部进程调用 |
| `mandiant/capa` | Apache-2.0 | 能力识别（`capability` 配方） | 外部进程调用 |
| `mandiant/flare-floss` | Apache-2.0 | 混淆字符串还原（`strings` 配方） | 外部进程调用 |
| `horsicq/Detect-It-Easy` | MIT | 编译器/加壳判定（`packer` 配方） | 外部进程调用 |
| `skylot/jadx` + `iBotPeaches/Apktool` | Apache-2.0 | APK 解包与类清单（`mobile` 配方） | 外部进程调用 |
| `lief-project/LIEF` | Apache-2.0 | 可执行格式的字段划分（`re_triage` 纯 Go 自研，只参考字段口径） | **只读思路** |
| `hasherezade/pe-sieve` | BSD-2-Clause | 进程注入 / hollowing dump（候选配方，未进默认表） | 外部进程调用 |
| `Angr/angr` | BSD-2-Clause | 符号执行：逆向域候选 / CTF crypto 非基础层 | 外部进程调用 |
| `qilingframework/qiling` | GPL-2.0 | 模拟执行 | **只读思路** |
| `morluto/rea`、`bethington/ghidra-mcp`（200+ 工具）、`LaurieWired/GhidraMCP`、`cyberkaida/ReVa`、`clearbluejar/pyghidra-mcp`、`mrexodia/ida-pro-mcp` | Apache-2.0 / MIT | **反面参照：MCP 工具面过大，明确不接**（理由见 P3 设计） | 不采用 |
| `apache/caldera` / `redcanaryco/atomic-red-team` | Apache-2.0 / MIT | 战役编排、TTP 原子 | 直接接入 |
| `Armur-Ai/Pentest-Swarm-AI` | AGPL-3.0 | 信息素黑板、JEV 打分、**非 LLM oracle 复核** | **只读思路** |
| `KeygraphHQ/shannon` | AGPL-3.0 | 源码 × 运行时对撞推路径 | **只读思路** |
| `ASCIT31/Dark-Moon` | GPL-3.0 | 50 specialist 角色清单 | **只读思路** |
| `elder-plinius/T3MP3ST` | AGPL-3.0 | 「把已有 agent CLI 当执行单元」 | **只读思路** |
| `chainreactors/tinyctfer` | 未标注 | intent 运行时 + 元工具 | **先确认许可，暂只读** |
| `m-sec-org/BreachWeave` | 未标注 | Manager/Observer/Solver 三角色 | **先确认许可，暂只读** |
| `orange-Cyberdefense/GOAD` | — | AD 靶场 | 作为环境使用 |

> 逆向能力**只取 CLI，不取 MCP 工具面**：装了就用的走「外部进程调用」，纯 Go 自研的只参考字段口径。
> 恢复/新增能力时的判断标准见 P3 配方表上方那句话 —— 单命令、可 JSON 化、确定性输出才进表。

新增复刻来源时，必须在本表补一行（含许可），否则视为违反 R1/R4。

---

## 5. 每次改动的门禁（缺一不可）

1. `gofmt -l` 本次改动文件 → 空
2. `go vet` 改动涉及的包 → 无输出
3. `go build ./...` → BUILD_OK
4. `go test ./<改动包>/ -count=1` → ok
5. `go test ./... -count=1` → 全 ok（提交前至少一次）
6. 有 DB 相关改动 → `./test-with-db.sh`（内部已用 `-p 1`）跑一次真库验证
   —— **DB 套件必须串行跑包**：agent/db/evidence/llmrec/server 共用一个测试库且各自清理数据，
   并行会互相踩（症状：每次失败的用例都不一样、单包跑全过）
7. 回填 §2 / §3 状态

**golden 纪律**：`agent/testdata/seeds_platform.golden` 是平台工具绑定的快照，**不允许为「让测试变绿」而重写**。确属有意的绑定变更时，用 `go test ./agent/ -run TestBuiltinToolSeedsPlatformUnchanged -update-seed-golden` 重生成，并在提交信息里说明哪条绑定、为什么变。

---

## 6. 风险与回滚

| 风险 | 触发条件 | 处置 |
| --- | --- | --- |
| 误连开发库清数据 | `PRAETOR_PG_DSN` 指向 `praetor` | 已被 `internal/testpg` 拦下（非 `_test` 库直接 skip）；如需临时放行才设 `PRAETOR_TEST_ALLOW_NON_TEST_DB=1` |
| 端口冲突 | 55432 被占用 | `PRAETOR_TEST_PG_PORT=55433 ./test-with-db.sh` |
| 重构破坏渗透主流程 | P0-4/P0-5 | `explore` 调度器先复用原 `plannerLoop`，包一层开关（`PRAETOR_DOMAIN_PACKS=0` 回退旧路径） |
| 许可污染 | 复制 AGPL/GPL 代码 | 提交前过 §4 表；不确定就只读思路、自行实现 |
| 沙箱拖慢主流程 | P0-6 | 沙箱只在 worker 执行 domain 工具时启用，planner 与只读工具不进容器 |

**回滚**：已建立回滚点（`git init` + 基线提交 `5c28544`，含 domain 骨架与测试门禁）。后续每个任务单独提交，出问题 `git revert` 即可。

---

## 7. 已知遗留

1. 改名那一轮做过一次全仓 `gofmt -w`，历史上未格式化的 4 个文件（`db/asset_intercept.go`、`db/assets_test.go`、`db/config.go`、`db/task_scope_test.go`）已一并格式化。此遗留项关闭。
2. `guardPanic` 在 recover 后会用 `log.Printf` 打印完整 panic 栈（`agent/assembly.go:82`）。这是**预期行为**（生产需要现场），但测试输出里看起来像崩溃——排查时先看 `--- FAIL` 行，别被栈骗。
3. Docker Desktop 守护进程当前未启动；测试栈已就绪但未拉起。
4. **真库跑测试暴露的问题：已定位并全部修复（2026-10-26）**。原以为是用例间数据污染，
   实际是四类问题叠加：
   - **真 bug（生产影响）**：`evidence.Store.writeBody` 对**目录**调 `d.Sync()`，Windows 上目录句柄
     不能 flush（`ERROR_ACCESS_DENIED`）→ 绑定流量一律 422。已改为 `syncDir()`，Windows 直接跳过
     （NTFS 日志保证 rename 元数据一致），其它平台保留 fsync 并容忍 EINVAL。
   - **测试收尾**：`chat_llm_resolve_test.go` 用 `context.Background()` 建 Server，后台写手不退出，
     Windows 上 `t.TempDir()` 清理报 “directory is not empty”。改为可取消 ctx + `archiveWG.Wait()` / `<-side.done`。
   - **用例假设过时**：`TestGraphOverviewExpandsAssociatedCompanyScope` 断言 `coverage["scope"]`，
     而该字段早已移除（现只有 denominator/tested/by_type/pct/status/host_count）。改为断言
     「公司 scope 完整落库 + 覆盖度分母 ≥1 + host_count ≥1」的等价事实。
   - **跨轮/跨包污染**：`company_scope_test` 用固定 CIDR 与 `MAX(assets.id)+1` 做唯一后缀（用例结束删资产，
     下一轮算出同一个值）→ 改为时间戳唯一 + 清理陈旧 CIDR scope + 用例结束删公司；
     `llmrec` 包缺 advisory lock，已补 `TestMain` 与其它包同锁；DB 套件统一 `-p 1` 串行。
   结果：真库 `go test -p 1 ./...` 连跑两次全绿；无库时 18 包全绿（DB 用例按设计 skip）。
5. 上游 `.gitignore` 原本忽略整个 `/docs/`，导致本文件与选型报告不进版本库。已改为 `/docs/*` + 两份文档白名单例外（`.gitignore` 有注释说明原因）；`docs/漏洞流量证据.md` 仍保持忽略。
6. **声明了但没人消费的字段（2026-10-27 查实，别当成已生效的护栏）**：
   - `domain.Budget` 的 `MaxTokens` / `MaxWall` / `MaxToolCalls` / `MaxParallel` —— 全仓只有 `MaxDepth`
     透传给了 `subagent`，其余四个**没有任何执行层读**。所以初版逆向域的「6M tokens / 3000 次工具调用」
     从来没生效过。真正的成本闸门在 **P3-1 `evidenceScheduler`**；在那之前，调这些数字只是调注释。
   - `DomainPack.Skills()` —— **没有任何消费点**（`grep '\.Skills()'` 为空）。所以逆向域声明的
     `binary-triage`、CTF 声明的技能名都只是文档性质，不会因为技能不存在而报错，也不会被加载。
   - `DomainPack.MCP()` —— 同样没有消费点（`grep '\.MCP()'` 为空）。这也是为什么 `ctf.go` 里删掉
     `rea` MCP 声明是零风险的：它本来就只是声明。
   > 结论：**别用这三个字段的存在感判断功能是否生效**。要判断，就看有没有调用点。
