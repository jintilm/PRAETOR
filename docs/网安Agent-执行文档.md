# 网安 Agent 执行文档

> 本文件是唯一的执行依据。**任何实现开始前先在这里建条目，做完更新状态**。
> 文档与代码不一致时，以「门禁通过」为准，并立即修文档。
>
> 起点：2026-10-26 · 基座：ARTEX（fork 改造）· 形态：内部自用 · 模型：混合（逆向本地，其余云 API）

---

## 0. 执行铁律

| # | 铁律 | 具体含义 |
| --- | --- | --- |
| R1 | **复刻优先，不重写** | 能从 GitHub 复刻/改造的，不自己从头写。先查 §4 复刻清单；清单里没有的，先评估「直接接入 > 复刻改造 > 自研」，并在 §4 补一行来源。 |
| R2 | **不影响完成度与性能** | 每步必须可独立验证、可回滚；不引入影响启动时间的依赖，不在热路径上加锁/加 IO；新增 MCP 一律外部进程，不塞进主进程。 |
| R3 | **文档先行** | 先在本文件建任务条目（含验收标准），再写代码；代码完成即回填状态与本日验证结果。 |
| R4 | **许可证红线** | 复制代码前先看 LICENSE：MIT / Apache-2.0 / BSD 可复制（保留版权头）；**AGPL / GPL 只读思路，不复制代码**。 |
| R5 | **不碰主栈数据** | 见 §1.3：绝不连 `artex` 库跑测试，绝不 `down -v` 主栈。 |

---

## 1. 环境与基线

### 1.1 唯一可信的基线命令

```bash
cd E:/Code/pentest/ARTEX
gofmt -l <本次改动的文件>     # 必须为空（仓库有 4 个历史未格式化文件，见 §7.1，不在范围内）
go vet ./<改动的包>/...
go build ./...                # 必须 BUILD_OK
go test ./... -count=1        # 必须全 ok（无 PG 时 DB 相关用例 skip，不是失败）
```

2026-10-26 实测基线：**16 个包全 ok**。

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
| compose 项目名 | 默认（目录名） | `artex-test` |
| 容器名 | `postgres` | `artex-test-pg` |
| 宿主端口 | 5432 | **55432**（容器内仍 5432） |
| 卷 | `pgdata` | `artex-test-pgdata`（独立） |
| 生命周期 | 常驻 | `restart: "no"`，用完即拆 |

跑真集成测试（会起库、跑完拆库）：

```bash
./test-with-db.sh          # 全量
./test-with-db.sh ./server/...   # 单包
KEEP_DB=1 ./test-with-db.sh      # 保留容器连续调试
```

**禁止清单**：`docker compose up`（主栈）、`docker compose -p artex-test down -v` 之外的 down、把 `ARTEX_PG_DSN` 指向 `.../artex`、在 `artex` 库上跑 `go test`。

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
> - `DomainToolSeeds(pack)` 单独展开某域的角色，**只在装配该域时调用**；不让四域的 agent 参与每次启动的全局播种（否则每个装了 ARTEX 的库都会多出 `ctf-lead`、`solver-pwn` 等用不到的 agent 行）。
> - `UnresolvedDomainTools(pack)` 供装配期告警：声明了但还解析不出实例的 key（待接入的 MCP 工具）。
>
> **踩到的坑（值得记）**：初版 pack 里 `add_finding` / `coverage` / `asset_coverage` / `list_worker_traces` / `bind_finding_traffic` 这些名字是我按 grep 猜的，真实清单里是 `report_finding` / `list_untested_assets` / `get_worker_trace` / `search_all_worker_traces`，其余根本不存在。`UnresolvedDomainTools` 第一次跑就把它们全抓出来了——这正是这个函数存在的理由。
| P0-5 | engine 按 `Scheduler()` 选调度器；`explore` 复用现有 `plannerLoop`；装配期用 `domain.Missing()` 打「声明了但未接入」的工具警告 | 自研 | 现有渗透用例回归通过（行为不变）；启动日志能看到缺失工具清单 | 待做 |
| P0-6 | `sandbox/`：`Bash` 改容器 exec，出口走现有 MITM 代理 + `AllowEgress` | **复刻 PentAGI 的沙箱工具镜像思路**（MIT）+ Strix 容器分层（Apache-2.0） | 工具在容器内执行；出口流量仍被记录代理截获 | 待做 |

### P1 渗透对齐

| ID | 任务 | 做法 / 复刻来源 | 验收 | 状态 |
| --- | --- | --- | --- | --- |
| P1-1 | 接 hexstrike MCP 工具面（外部进程，不复制代码） | 直接接入 `0x4m4/hexstrike-ai` | 至少 3 个工具可被 worker 调用 | 待做 |
| P1-2 | 确定性验证器接流量重放（`bind_finding_traffic` → 重放 → 比对差异） | **复刻 Pentest-Swarm 的 oracle 思路**（AGPL，只读思路，自行实现） | 无流量证据的 finding 进「疑似」队列 | 待做 |
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
6. 有 DB 相关改动 → `./test-with-db.sh` 跑一次真库验证
7. 回填 §2 / §3 状态

**golden 纪律**：`agent/testdata/seeds_platform.golden` 是平台工具绑定的快照，**不允许为「让测试变绿」而重写**。确属有意的绑定变更时，用 `go test ./agent/ -run TestBuiltinToolSeedsPlatformUnchanged -update-seed-golden` 重生成，并在提交信息里说明哪条绑定、为什么变。

---

## 6. 风险与回滚

| 风险 | 触发条件 | 处置 |
| --- | --- | --- |
| 误连开发库清数据 | `ARTEX_PG_DSN` 指向 `artex` | 已被 `internal/testpg` 拦下（非 `_test` 库直接 skip）；如需临时放行才设 `ARTEX_TEST_ALLOW_NON_TEST_DB=1` |
| 端口冲突 | 55432 被占用 | `ARTEX_TEST_PG_PORT=55433 ./test-with-db.sh` |
| 重构破坏渗透主流程 | P0-4/P0-5 | `explore` 调度器先复用原 `plannerLoop`，包一层开关（`ARTEX_DOMAIN_PACKS=0` 回退旧路径） |
| 许可污染 | 复制 AGPL/GPL 代码 | 提交前过 §4 表；不确定就只读思路、自行实现 |
| 沙箱拖慢主流程 | P0-6 | 沙箱只在 worker 执行 domain 工具时启用，planner 与只读工具不进容器 |

**回滚**：已建立回滚点（`git init` + 基线提交 `5c28544`，含 domain 骨架与测试门禁）。后续每个任务单独提交，出问题 `git revert` 即可。

---

## 7. 已知遗留

1. 仓库有 4 个文件历史上未 `gofmt`：`db/asset_intercept.go`、`db/assets_test.go`、`db/config.go`、`db/task_scope_test.go`。**不在任何任务范围内**，改动它们会污染 diff；若某个任务必须改，只格式化改动块。
2. `guardPanic` 在 recover 后会用 `log.Printf` 打印完整 panic 栈（`agent/assembly.go:82`）。这是**预期行为**（生产需要现场），但测试输出里看起来像崩溃——排查时先看 `--- FAIL` 行，别被栈骗。
3. Docker Desktop 守护进程当前未启动；测试栈已就绪但未拉起。
4. 上游 `.gitignore` 原本忽略整个 `/docs/`，导致本文件与选型报告不进版本库。已改为 `/docs/*` + 两份文档白名单例外（`.gitignore` 有注释说明原因）；`docs/漏洞流量证据.md` 仍保持忽略。
