# 网安 Agent 执行文档

> 本文件是唯一的执行依据。**任何实现开始前先在这里建条目，做完更新状态**。
> 文档与代码不一致时，以「门禁通过」为准，并立即修文档。
>
> 项目代号：**PRAETOR**（`praetor`，统帅 → 将领 → 百夫长，对应 Commander → 域 Lead → Specialist 三级）
> 起点：2026-10-26 · 基座：PRAETOR（fork 自 ARTEX）· 形态：内部自用 · 模型：混合（逆向本地，其余云 API）

---

## 0. 执行铁律

| # | 铁律 | 具体含义 |
| --- | --- | --- |
| R1 | **复刻优先，不重写** | 能从 GitHub 复刻/改造的，不自己从头写。先查 §4 复刻清单；清单里没有的，先评估「直接接入 > 复刻改造 > 自研」，并在 §4 补一行来源。 |
| R2 | **不影响完成度与性能** | 每步必须可独立验证、可回滚；不引入影响启动时间的依赖，不在热路径上加锁/加 IO；新增 MCP 一律外部进程，不塞进主进程。 |
| R3 | **文档先行** | 先在本文件建任务条目（含验收标准），再写代码；代码完成即回填状态与本日验证结果。 |
| R4 | **许可证红线** | 复制代码前先看 LICENSE：MIT / Apache-2.0 / BSD 可复制（保留版权头）；**AGPL / GPL 只读思路，不复制代码**。 |
| R5 | **不碰主栈数据** | 见 §1.3：绝不连 `praetor` 库跑测试，绝不 `down -v` 主栈。 |

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

---

## 3. 任务清单

状态：`待做` / `进行中` / `已完成` / `阻塞`

### P0 骨架（目标：四域可插拔，渗透行为零变化）

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
> - `UnresolvedDomainTools(pack)` 供装配期告警：声明了但还解析不出实例的 key（待接入的 MCP 工具）。
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
| P1-3 | benchmark runner | 接入 `xbow-engineering/validation-benchmarks`（104 题）+ `auto-pen-bench` | 出基线分并记录到本文件 | 待做 |

### P2 CTF

| ID | 任务 | 做法 / 复刻来源 | 验收 | 状态 |
| --- | --- | --- | --- | --- |
| P2-1 | `raceScheduler`：同题多解并行、首解收敛、失败换模型 | **复刻 `verialabs/ctf-agent` 的 coordinator + solver swarm 结构**（MIT，可复制） | 单题可在 2 个 solver 并行下收敛 | 待做 |
| P2-2 | CTFd 答题 + flag 仲裁（去重，避免重复提交） | 同上（其 CTFd token 接入方式） | 重复 flag 只提交一次 | 待做 |
| P2-3 | CTF 沙箱工具链（pwntools/pwndbg/angr/z3） | 复刻 `chainreactors/tinyctfer` 的 sandbox 镜像构成（先确认许可） | 能跑通 1 道 pwn | 待做 |
| P2-4 | Cybench 40 题 + NYU CTF Bench 子集出分 | 接入 benchmark | 分数记录到本文件 | 待做 |

### P3 逆向

| ID | 任务 | 做法 / 复刻来源 | 验收 | 状态 |
| --- | --- | --- | --- | --- |
| P3-1 | 接 REA MCP（本地，LocalOnly） | 直接接入 `morluto/rea`（MIT） | `decompile/xrefs/strings` 可用 | 待做 |
| P3-2 | 接 headless Ghidra MCP | `clearbluejar/pyghidra-mcp` 或 `bethington/ghidra-mcp`（Apache-2.0） | 无 GUI 环境可批量分析 | 待做 |
| P3-3 | 证据链 schema + 可续跑 | **复刻 open-reverselab 的「输入信号→证据链」模型**（GPL-3，只读思路） | 结论缺 xref/trace 时 Verifier 拒绝判 Done | 待做 |
| P3-4 | 样本治理：加密存储 + 哈希索引 + 禁止整包进 LLM | 自研（合规要求） | 请求日志里无完整样本 | 待做 |

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
| `verialabs/ctf-agent` | MIT | coordinator + solver swarm、CTFd 接入 | 可复制代码 |
| `morluto/rea` | MIT | 逆向 MCP 工具面 | 直接接入 |
| `LaurieWired/GhidraMCP` / `bethington/ghidra-mcp` | Apache-2.0 | Ghidra 能力暴露 | 直接接入 |
| `apache/caldera` / `redcanaryco/atomic-red-team` | Apache-2.0 / MIT | 战役编排、TTP 原子 | 直接接入 |
| `Armur-Ai/Pentest-Swarm-AI` | AGPL-3.0 | 信息素黑板、JEV 打分、**非 LLM oracle 复核** | **只读思路** |
| `KeygraphHQ/shannon` | AGPL-3.0 | 源码 × 运行时对撞推路径 | **只读思路** |
| `LING71671/open-reverselab` | GPL-3.0 | 证据链工作流模型 | **只读思路** |
| `ASCIT31/Dark-Moon` | GPL-3.0 | 50 specialist 角色清单 | **只读思路** |
| `elder-plinius/T3MP3ST` | AGPL-3.0 | 「把已有 agent CLI 当执行单元」 | **只读思路** |
| `chainreactors/tinyctfer` | 未标注 | intent 运行时 + 元工具 | **先确认许可，暂只读** |
| `m-sec-org/BreachWeave` | 未标注 | Manager/Observer/Solver 三角色 | **先确认许可，暂只读** |
| `orange-Cyberdefense/GOAD` | — | AD 靶场 | 作为环境使用 |

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
