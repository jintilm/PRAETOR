# 网安 Agent 选型与架构方案

> 面向「渗透测试 / 红队 / CTF / 逆向」四大板块 + 子 Agent 协作
> 调研数据抓取日期：**2026-10-26**（GitHub REST/Search API + 各仓库 README 原文）
> 参考坐标：当前工作区 `E:/Code/pentest/PRAETOR`（Go + Next.js，AGPLv3）

---

## 0. 结论先行（TL;DR）

| 决策点 | 结论 | 理由 |
| --- | --- | --- |
| **要不要舍弃 PRAETOR（原 ARTEX）** | **不要舍弃，建议 fork 改造** | 已有 9.3 万行 Go + 5.6 万行 TS 的可用骨架：双图（资产图/探索图）、planner→worker 事件驱动闭环、工具审批门、MITM 全流量留痕、工具目录按 agent 绑定。这三样是**四个板块共用**的底座，重写成本远大于改造 |
| **执行内核** | 直接复用 `norma` SDK（PRAETOR 的依赖） | 它已内置 `subagent`（Agent 工具 + 递归深度保护）、`coordinator`（分解 + `RunParallel` 扇出）、`skill`（SKILL.md）、`mcp`、`permission`（四段式）、`hook`（8 个生命周期）、`compaction`。**子 Agent 协作不需要自研调度器** |
| **改造主线** | 把「单域渗透系统」升级为「**领域包（Domain Pack）插件化**的多域平台」 | 四域执行模型差异极大（渗透=探索、红队=战役 DAG、CTF=竞速抢旗、逆向=证据链），必须靠接口隔离，不能靠一套 prompt 硬扛 |
| **重点借鉴的 5 个项目** | Strix（图编排+沙箱）、PentAGI（分层记忆+沙箱工具镜像）、Pentest-Swarm（黑板+确定性验证器）、Veria ctf-agent（coordinator+solver 竞速）、REA / open-reverselab / GhidraMCP（逆向工具面） | 分别解决：多 agent 拓扑、记忆与隔离、降误报、CTF 并行、逆向接入 |
| **不要自研的红队件** | C2 / implant / AD 攻击链 全用开源成熟件（Sliver / Mythic / Caldera / Atomic Red Team / BloodHound / NetExec） | 自研 C2 既无必要也踩合规红线；Agent 只做「编排 + 决策 + 留证」 |
| **必须有的验收** | 从第一天就接 benchmark（XBOW validation-104 / AutoPenBench / Cybench / NYU CTF Bench / CyberGym） | 「好用」必须可量化，否则多 agent 只是堆 token |
| **许可证红线** | PRAETOR 自身是 **AGPLv3**；Shannon / T3MP3ST / Pentest-Swarm / Dark-Moon / open-reverselab 为 AGPL/GPL | 若要做**闭源商用或 SaaS**，这些代码只能「读思路」，不能复制粘贴；可安全吸收的是 MIT / Apache-2.0 项目（Strix、PentAGI、Veria ctf-agent、REA） |

---

## 1. 本地项目 PRAETOR 体检

### 1.1 现状盘点

| 能力 | PRAETOR 现状 | 四域可复用度 | 缺口 |
| --- | --- | --- | --- |
| **双图世界模型** | 资产图（root_domain→subdomain→service→endpoint，全局共享）+ 探索图（goal/intent/fact/finding/hint + 血缘边）+ anchors 锚定 | ★★★★★ 通用「黑板」 | 逆向/CTF 的节点类型缺失（binary/function/flag/patch） |
| **执行闭环** | engine 每任务 1 个 plannerLoop + N worker；图变→debounce→唤醒 planner→派意图→worker 领取→写回 | ★★★★★ 渗透域直接可用 | 红队战役的「阶段依赖 + 时序」；CTF 的「多题并行 + 抢旗仲裁」 |
| **信息交换** | `search_all_worker_traces` / `get_worker_trace`：跨 worker 按「执行过程」粒度检索 | ★★★★★ | 缺结构化 artifact（payload、脚本、样本、内存 dump）引用机制 |
| **审批门** | `guard` / `intercept`：工具级 allow/deny/ask + 人在环路对话 + 审批记录 | ★★★★★ **四域强制保留** | 需要「按目标 scope + 动作危险等级」的细粒度策略 |
| **留痕** | MITM 记录代理（CA 签发 + HTTPS 校验）+ 每步 activity | ★★★★☆ 渗透/CTF-Web 通用 | 逆向域需要「二进制证据链」（哈希/反编译片段/动态 trace） |
| **工具目录** | `toolcatalog` 把内置工具 seed 进 DB，可按 agent 绑定/改描述/schema | ★★★★★ **天然的子 Agent 能力路由** | 无第三方 MCP 池的统一注册与隔离 |
| **子 Agent** | 依赖的 `norma` 已有 `subagent` + `coordinator`，**但 PRAETOR 目前只用了 planner/worker 固定角色** | ★★★★★ | 缺「动态派生子 Agent」「子 Agent 生命周期/预算/回收」的产品层 |
| **沙箱** | 未见容器级隔离（Bash 直出） | ★★☆☆☆ | 四域都必须有容器沙箱 + 出口白名单 + 资源限额 |
| **评测** | 无 | ☆☆☆☆☆ | 无 benchmark 回归 = 无法迭代 |

### 1.2 判断

**不建议舍弃**，理由：

1. **骨架稀缺**：双图 + 审批 + 留痕这三件事，四域都要用。自己重写至少 2~3 个月，且做完才发现「跨 worker 过程检索」「planner 共享 todolist 稳定攻击链」这些细节坑已经踩过一遍。
2. **SDK 是对的**：`norma` 的抽象（Agent Harness）本来就不是「渗透专用」，README 明确说「不知道自己在驱动编码 agent、安全审计还是客服机器人」——这正好支撑「四域 + 子 Agent」。
3. **真正的缺口在「域」，不在「架」**：缺的是 CTF 竞赛模式、逆向工具面、红队战役编排、沙箱、评测。这些都是**加模块**，不是改架构。

**改造代价**：需要把 `agent/` 里写死的三角色（mainagent/planner/worker）抽象成「角色由 DomainPack 声明」，把 prompt/skill/工具集/审批策略/产出 schema 全部下沉为插件。这是**唯一一次结构性重构**，越早做越省事。

---

## 2. GitHub 项目盘点（按板块）

> Star 数为 2026-10-26 抓取值，AI 安全类项目一年内 star 通胀极严重（Strix 一个月 +19k），**请以「定位匹配度 + 可复用性 + 活跃度」为主判据，Star 仅作热度参考**。

### 2.1 通用基座 / 多 Agent 框架

| 项目 | Star | 语言 | 许可 | 定位 | 对我们的价值 |
| --- | --- | --- | --- | --- | --- |
| [usestrix/strix](https://github.com/usestrix/strix) | 72k | Python | Apache-2.0 | 开源 AI 黑客，**Graph of Agents** + Docker 沙箱 + Caido 代理 + Playwright + Python exploit 运行时 | **最值得抄架构**：agent 图编排、沙箱镜像分层、`strix view` 本地回放、MCP 客户端、把能力打成 skills |
| [vxcontrol/pentagi](https://github.com/vxcontrol/pentagi) | 32.4k | Go | MIT | 自托管多 agent 渗透；Docker 沙箱跑 20+ 工具；PG+pgvector 长期记忆；可选 Graphiti/Neo4j 知识图谱；summarizer 压缩 | **记忆分层范式**（向量召回 + 图谱关系 + 摘要压缩），以及「小模型靠 execution monitoring / task planning 补齐」的工程手段。注意：开源版**不含 MCP**（企业版才有） |
| [KeygraphHQ/shannon](https://github.com/KeygraphHQ/shannon) | 47.6k | TS | **AGPL-3.0** | 白盒（源码 + 运行时）Web/API 自主渗透 | 学「源码与运行时对撞推导攻击路径」；许可传染，勿抄码 |
| [GreyDGL/PentestGPT](https://github.com/GreyDGL/PentestGPT) | 16.1k | Python | — | 早期标杆：reasoning / execution / generation 三阶段解耦 | 学「推理与执行分离」，避免单 agent 上下文被工具输出淹没 |
| [0x4m4/hexstrike-ai](https://github.com/0x4m4/hexstrike-ai) | 13.1k | Python | — | MCP server 封装 150+ 安全工具 | **别自己包工具**：直接当工具面接进来（配合我们的 MCP 客户端） |
| [Armur-Ai/Pentest-Swarm-AI](https://github.com/Armur-Ai/Pentest-Swarm-AI) | 3.0k | Go | **AGPL-3.0** | 蜂群架构：信息素黑板去中心化协作 + JEV 打分 + **非 LLM oracle 复核** | 两个点非常关键：①黑板式协作；②**确定性验证器**（非 LLM）二次确认高危发现 → 直接降误报 |
| [ASCIT31/Dark-Moon](https://github.com/ASCIT31/Dark-Moon) | 1.1k | Python | GPL-3.0 | 50 个 specialist agent，覆盖 Web/云/AD/K8s，本地模型 + 隐私网关 | 「specialist 清单」可直接抄成我们的 role 目录；隐私网关思路适合本地模型场景 |
| [aliasrobotics/cai](https://github.com/aliasrobotics/cai) | 9.8k | Python | — | ⚠️ **已于 2026-08 归档**（18 篇论文、30+ CVE 的研究artifact） | 只作参考读物，**不要作为基座**（无维护） |
| [oritera/Cairn](https://github.com/oritera/Cairn) | 2.5k | Python | — | 通用状态空间搜索引擎做自主渗透 | PRAETOR README 已参考，思路同源 |
| [mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) | 32k | Markdown | — | 817 个结构化网络安全 skill，映射 MITRE ATT&CK / CIS / OWASP / NIST 等 6 框架 | **能力层白捡**：SKILL.md 格式与 `norma/skill` 兼容，直接当领域知识包 |
| [Yeti-791/Awesome-Offensive-AI-Agentic-Landscape](https://github.com/Yeti-791/Awesome-Offensive-AI-Agentic-Landscape) | 398 | — | — | 46 个开源 Agent + 11 个安全专用模型 + MCP/Skill/116 篇论文/13 个 benchmark 全景 | **持续跟踪的唯一入口**，建议每个迭代周期扫一次 |

### 2.2 渗透测试（Web / API / 内网）

优先级：**能力直接接 → Strix + HexStrike + PRAETOR 本体**；**架构借鉴 → PentAGI（记忆）+ Pentest-Swarm（验证器）**。
不建议把 Shannon / T3MP3ST 作为代码基座（AGPL）。

关键结论：**渗透域不需要新写执行内核**。PRAETOR 的 planner/worker 已经解决了「一条串行利用链在事件驱动 + 无状态会话下稳定推进」这个最难的工程问题（共享 todolist + 前置依赖判定）。

### 2.3 红队 / 对手模拟

| 项目 | Star | 语言 | 许可 | 定位 | 用法 |
| --- | --- | --- | --- | --- | --- |
| [BishopFox/sliver](https://github.com/BishopFox/sliver) | 12.2k | Go | GPL-3.0 | 现代 C2 / implant 框架 | **执行层**：作为独立服务部署，Agent 通过 gRPC 调用，不嵌入 |
| [its-a-feature/Mythic](https://github.com/its-a-feature/Mythic) | ~3k | Python | BSD-3 | 协作式 C2 平台（多 agent/payload） | 备选 C2；插件化更适合「Agent 编排」 |
| [apache/caldera](https://github.com/apache/caldera) | 7.5k | Python | Apache-2.0 | 自动化对手模拟（ATT&CK 编排） | **战役引擎首选**：能力（ability）→  adversary → operation，天然是「红队 DAG」 |
| [redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team) | ~11k | YAML | MIT | 原子化 TTP 测试库 | 把每条 atomic 变成「可执行战术原子」，给 Agent 当弹药 |
| [Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec) | 5.9k | Python | BSD | 网络执行/横向（SMB/WinRM/LDAP…） | 内网横向执行器 |
| [SpecterOps/BloodHound](https://github.com/SpecterOps/BloodHound) | ~11k | TS/Go | GPL-3.0 | AD 攻击路径图谱 | 「路径即计划」，直接喂给 planner 当 todolist |
| [Orange-Cyberdefense/GOAD](https://github.com/Orange-Cyberdefense/GOAD) | ~4k | — | — | 5 域大型 AD 靶场 | **红队评测环境**（必须有靶场才能回归） |
| [SpecterOps/Ghostwriter](https://github.com/SpecterOps/Ghostwriter) | ~2k | Python | BSD | 红队战役/报告管理 | 报告与战役元数据模型可借鉴 |
| [elder-plinius/T3MP3ST](https://github.com/elder-plinius/T3MP3ST) | 5.9k | TS | **AGPL-3.0** | 多 agent 红队元框架，把本机 coding agent 变 zeroday hunter | 借鉴「**把已有 Agent CLI 当执行单元**」这一招——我们正好可以让 Domain Lead 派生 `norma` subagent 当执行单元 |
| [m-sec-org/BreachWeave](https://github.com/m-sec-org/BreachWeave) | 525 | TS | — | Manager / Observer / Solver 三角色（腾讯云黑客松决赛第 1） | 三角色分工可直接映射到红队域 |
| [andreashappe/cochise](https://github.com/andreashappe/cochise) | 134 | Python | — | Assumed-breach AD 渗透（TOSEM 2025） | 学术级 AD 攻击策略参考 |

**红队域的核心判断**：Agent 不做「打」，做「**规划 + 编排 + 证据化**」。C2/横向/AD 全部外挂成熟工具，Agent 输出的是「ATT&CK 阶段化的战役 DAG + 每步证据 + 报告」。

### 2.4 CTF

| 项目 | Star | 语言 | 许可 | 定位 | 用法 |
| --- | --- | --- | --- | --- | --- |
| [verialabs/ctf-agent](https://github.com/verialabs/ctf-agent) | 757 | Python | MIT | **Coordinator + Solver Swarm 竞速**，CTFd 接入，BSidesSF 2026 **52/52 全胜** | ⭐ **CTF 域首选范式**：一个 coordinator 管全场，每道题起多个 solver（不同模型并行），先解出者胜；沙箱镜像自带工具链 |
| [chainreactors/tinyctfer](https://github.com/chainreactors/tinyctfer) | 174 | Python | — | 「intent 即一切」：antix 微型意图运行时 + 元工具 | 国内实战（腾讯云黑客松第 4）；**意图/元工具**设计与 PRAETOR 的 intent 模型同构，最易融合 |
| [NYU-LLM-CTF/nyuctf_agents](https://github.com/NYU-LLM-CTF/nyuctf_agents) | 161 | Python | — | D-CIPHER 多 agent（Commander / Planner / Solver） | 三角色分层与我们的三层架构同构，可直接对齐 |
| [andyzorigin/cybench](https://github.com/andyzorigin/cybench) | 317 | Python | — | 40 道专业 CTF（4 场大赛，17 子任务，Unguided/Subtask 双模式） | **CTF 能力验收基准** |
| [NYU-LLM-CTF/NYU_CTF_Bench](https://github.com/NYU-LLM-CTF/NYU_CTF_Bench) | 171 | Python | — | 200 题正式 + 55 开发集，Docker 化 | 大样本回归 |
| [ljagiello/ctf-skills](https://github.com/ljagiello/ctf-skills) | 3.2k | Markdown | — | CTF 全领域 skill 包（Web/Pwn/Crypto/Rev/Forensics/OSINT/Malware/AI-ML） | 直接当 `norma/skill` 技能包 |
| [CTFd/CTFd](https://github.com/CTFd/CTFd) | 6.9k | Python | Apache-2.0 | CTF 平台 | **验证答题用**：验证用；**评测靶场**：题目由该引擎提供 + flag 提交/计分 API |
| [Gallopsled/pwntools](https://github.com/Gallopsled/pwntools) | 13.8k | Python | — | pwn 框架 | 沙箱必备 |
| [pwndbg/pwndbg](https://github.com/pwndbg/pwndbg) / [hugsy/gef](https://github.com/hugsy/gef) | 11.1k / 8.4k | Python | — | GDB 增强（逆向/利用） | 动态调试工具面 |
| [bee-san/Ciphey](https://github.com/bee-san/Ciphey) | 21.7k | Python | — | 自动解密/解码 | Crypto 类题的确定性兜底工具 |
| [0ca/BoxPwnr](https://github.com/0ca/BoxPwnr) | 450 | Python | — | 15 个平台统一基准（HTB/THM/picoCTF/Cybench/XBOW） | **统一评测框架**，省掉自己写 harness |

**CTF 域的核心判断**：CTF 与渗透是**两种完全不同的执行模型**——渗透是「深度优先、单链推进」，CTF 是「广度优先、多题并发、抢旗仲裁」。PRAETOR 现在的 planner（唯一意图生成者、串行 todolist）**不适合直接跑 CTF**，必须新增一个「**竞速调度器**」（多解法并行 + 首个 flag 命中即收敛 + 失败题回退换模型）。

### 2.5 逆向工程

> **⚠️ 2026-10-27 设计变更：本节结论已作废，保留作调研记录。**
>
> 最终**没有接入 REA / GhidraMCP / open-reverselab 中的任何一个 MCP**。原因在表的规模一栏就能看出来：
> `open-reverselab` 自称 100+ 工具、`bethington/ghidra-mcp` 200+ 工具，而**工具 schema 每一轮都要随上下文重发**
> （本项目实测固定成本 ~10.7K tokens/轮）。接进来等于固定成本翻倍，还会制造大量「先试试这个」的浅尝路径 ——
> 而实测最贵的是**调用次数**，不是单次体积。
>
> 现在的做法：**只取 CLI 能力做配方**（rizin / Ghidra headless / capa / FLOSS / DIE / jadx+apktool / gdb），
> 模型侧工具面固定 3 个（`re_triage` / `re_recipe` / `re_evidence`）。
> 设计与理由见 `网安Agent-执行文档.md` §3「P3 逆向（2026-10-27 重新设计）」。
>
> 本表仍然可用的部分：各项目的**许可**（rizin LGPL-3、x64dbg GPL-3、bincat GPL-3 → 只读思路）
> 与单点能力定位（反编译引擎、调试器、格式解析）。

| 项目 | Star | 语言 | 许可 | 定位 | 用法 |
| --- | --- | --- | --- | --- | --- |
| [morluto/rea](https://github.com/morluto/rea) | 385k* | — | MIT | 「一个 MCP 搞定逆向」：二进制 / 应用 / 运行时行为统一分析入口 | ⭐ **逆向工具面首选**：接入成本最低，一个 MCP 顶掉一堆胶水（*Star 异常高，注意甄别热度） |
| [LING71671/open-reverselab](https://github.com/LING71671/open-reverselab) | 1.3k | — | **GPL-3.0** | 100+ MCP 工具，Ghidra/Frida/x64dbg/Rizin/PE/APK/恶意样本，证据链式工作流 | 「从输入信号到证据链，每一步可执行」——**证据链模型值得抄** |
| [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP) | 11.6k | Java/Py | Apache-2.0 | Ghidra MCP（函数/符号/反编译查询） | 最轻量，起步用它 |
| [bethington/ghidra-mcp](https://github.com/bethington/ghidra-mcp) | 5.9k | — | — | Ghidra MCP **200+ 工具**，GUI 插件形态 | 需要细粒度能力时替换 GhidraMCP |
| [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) | ~3k | Python | MIT | IDA Pro MCP | 有 IDA 授权时接入（本地环境已装 IDA 9.4） |
| [clearbluejar/pyghidra-mcp](https://github.com/clearbluejar/pyghidra-mcp) | 454 | Python | — | 无 GUI 的 headless Ghidra MCP | **批量/服务化**场景必选（无需开 Ghidra GUI） |
| [jtsylve/re-mcp](https://github.com/jtsylve/re-mcp) | 176 | — | — | headless IDA + Ghidra 双后端 | 同上 |
| [NationalSecurityAgency/ghidra](https://github.com/NationalSecurityAgency/ghidra) | 94.4k | Java | Apache-2.0 | 反汇编/反编译 | 引擎层 |
| [radareorg/radare2](https://github.com/radareorg/radare2) / [rizinorg/rizin](https://github.com/rizinorg/rizin) | 25.2k / ~3k | C | LGPL-3 | CLI 逆向框架 | 沙箱内脚本化分析 |
| [angr/angr](https://github.com/angr/angr) | ~8k | Python | BSD | 符号执行 | 求解 flag / 路径约束（CTF-pwn/rev 关键） |
| [x64dbg/x64dbg](https://github.com/x64dbg/x64dbg) | 50k | C++ | GPL-3 | Windows 调试器 | 动态调试（Windows 样本） |
| [WerWolv/ImHex](https://github.com/WerWolv/ImHex) | 55.6k | C++ | GPL-2 | 十六进制/结构化解析 | 文件格式逆向 |
| [iBotPeaches/Apktool](https://github.com/iBotPeaches/Apktool) | 26.7k | Java | Apache-2.0 | APK 反编译 | 移动端逆向 |
| [albertan017/LLM4Decompile](https://github.com/albertan017/LLM4Decompile) | ~1k | Python | MIT | 反编译专用 LLM（汇编→C） | 自建本地模型时的基座 |
| [airbus-seclab/bincat](https://github.com/airbus-seclab/bincat) | ~1.5k | Python | GPL-3 | 二进制相似性/补丁分析（IR） | 漏洞定位、补丁差分 |

**逆向域的核心判断**：逆向不是「一次对话」，是「**长时程、可验证的证据链**」。Agent 的产出必须落成结构化证据（函数签名、调用图、字符串、交叉引用、动态 trace、结论 + 置信度），否则人无法复核。这正好用 PRAETOR 的「探索图 + anchor」承载，但要新增 `binary / function / sample / evidence` 节点类型。

### 2.6 评测基准（务必从一开始就接）

| Benchmark | 覆盖 | 规模 | 用途 |
| --- | --- | --- | --- |
| [xbow-engineering/validation-benchmarks](https://github.com/xbow-engineering/validation-benchmarks) | Web 漏洞 | 104 | **渗透域主基准**（业界事实标准） |
| [lucagioacchini/auto-pen-bench](https://github.com/lucagioacchini/auto-pen-bench) | 渗透（含真实 CVE） | 33 | 快速回归 |
| [andyzorigin/cybench](https://github.com/andyzorigin/cybench) | CTF | 40 | CTF 主基准（对标学术） |
| [NYU_CTF_Bench](https://github.com/NYU-LLM-CTF/NYU_CTF_Bench) | CTF | 200+55 | CTF 大样本 |
| [sunblaze-ucb/cybergym](https://github.com/sunblaze-ucb/cybergym) | 真实漏洞分析/复现 | 1507（240GB） | **红队+逆向**的真实性基准 |
| [uiuc-kang-lab/cve-bench](https://github.com/uiuc-kang-lab/cve-bench) | 真实 CVE 利用 | 40 critical | 端到端利用验证 |
| [SEC-bench](https://github.com/SEC-bench/SEC-bench) | C/C++ CVE PoC+补丁 | 200 | 逆向 + 修复 |
| [meta-llama/PurpleLlama](https://github.com/meta-llama/PurpleLlama) (CyberSecEval 1-4) | 多任务安全能力 | — | 横向能力画像 |
| **TSecBench**（腾讯云鼎，闭卷） | 智能攻防 | — | 国内口径参考 |

---

## 3. 架构方案：三层角色 + 结构化黑板

### 3.1 总体拓扑

```
                      ┌──────────────────────────────────────────┐
   人（授权/审批/接管）─→ │  Commander  会话层                        │
                      │  · 澄清目标与 scope  · 预算（token/时长/请求）│
                      │  · 审批门 · 报告出口                      │
                      └───────────────┬──────────────────────────┘
                                      │  派发 DomainTask（含 scope/预算/验收器）
        ┌───────────────┬─────────────┼─────────────┬───────────────┐
        ▼               ▼             ▼             ▼               │
  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐        │
  │Pentest   │   │RedTeam   │   │CTF       │   │Reverse   │  ← Domain Lead（4 个，可并存）
  │Lead      │   │Lead      │   │Lead      │   │Lead      │        │
  │planner   │   │战役 DAG  │   │竞速仲裁  │   │证据链    │        │
  └────┬─────┘   └────┬─────┘   └────┬─────┘   └────┬─────┘        │
       │ 派生（norma/subagent，带独立上下文 + 预算 + 工具子集）      │
   ┌───┴───┐      ┌───┴───┐     ┌────┴────┐    ┌───┴────┐         │
   │worker │      │operator│    │solver ×N│    │analyst │  ← Specialist（并发）
   │ ×N    │      │ ×N     │    │(多模型) │    │ ×N     │         │
   └───┬───┘      └───┬───┘     └────┬────┘    └───┬────┘         │
       │              │              │             │               │
       └──────────────┴──────┬───────┴─────────────┘               │
                             ▼                                      │
        ┌────────────────────────────────────────────────┐         │
        │  共享黑板（Blackboard）                          │         │
        │  探索图(goal/intent/fact/finding) + 资产图       │←────────┘
        │  + artifact 存储(payload/脚本/样本/dump)         │
        │  + 证据库(evidence: 哈希/时间/来源/置信度)        │
        └───────────────────┬────────────────────────────┘
                            ▼
        ┌────────────────────────────────────────────────┐
        │  执行面（全部容器沙箱化，出口走记录代理 + 白名单）  │
        │  Kali工具 / MCP池(hexstrike,REA,GhidraMCP,Burp) │
        │  C2(Sliver|Mythic) / 战役(Caldera) / 靶场(GOAD) │
        └────────────────────────────────────────────────┘
```

### 3.2 四条铁律（避免多 agent 变成多倍幻觉）

1. **Agent 之间不自由对话，只读写黑板。**
   自由对话会导致 token 爆炸 + 幻觉互相污染。信息交换一律是**结构化条目**（fact/artifact/evidence + 来源 intent_id），需要定向沟通时用 mailbox（单条消息 + 明确 payload schema）。
   > PRAETOR 已有的 `search_all_worker_traces` / `get_worker_trace` 就是正确做法：**按需检索他人过程**，而不是广播。

2. **每个 Specialist = 独立上下文 + 独立预算 + 工具子集。**
   `norma/subagent` 天然隔离上下文。Domain Lead 派生 specialist 时必须带 `{scope, 预算上限, 允许工具白名单, 产出 schema, 终止条件}`，禁止继承全量工具。

3. **高危动作必须过门；高危发现必须过确定性校验。**
   沿用 PRAETOR `guard/intercept`；发现（finding）落库前先跑**非 LLM oracle**（重放 PoC、比对响应差异、CVSS 打分器），拿不到可复现证据的只能进「疑似」队列——这是 Pentest-Swarm 的思路，直接解决误报这个最大痛点。

4. **失败的收敛路径必须显式。**
   specialist 连续 N 次无新事实 → 上报 Lead；Lead 判定「方向穷尽」→ 换策略（换工具/换模型/降级为人工）；全局预算耗尽 → 强制 wrapup（PRAETOR 已有 `wrapup`、`terminalreason`）。

### 3.3 四域执行模型对照（这是必须插件化的根本原因）

| 维度 | 渗透 Pentest | 红队 RedTeam | CTF | 逆向 Reverse |
| --- | --- | --- | --- | --- |
| 目标 | 找并证明漏洞 | 达成战役目标（拿域控/数据） | 拿到 flag | 说清「这段二进制在干什么」 |
| 拓扑 | 深度优先，单链推进 | **阶段 DAG**（ATT&CK 顺序依赖） | **广度并发 + 竞速** | 长时程串行 + 分支递归 |
| 成功判据 | PoC 可复现 | 目标达成 + 痕迹可控 | flag 正确 | 结论可被证据支撑 |
| 主要工具面 | HTTP/Proxy/Nuclei/SQLMap | C2/横向/AD/免杀 | pwn/rev/crypto/forensic | 反汇编/调试/符号执行 |
| 时间尺度 | 分钟~小时 | 小时~天 | 分钟~小时 | 分钟~天（可中断续跑） |
| 关键风险 | 越界打生产 | 遗留后门/影响业务 | 无（隔离环境） | 样本外泄 |
| 特有机制 | 资产图覆盖度 | 战役回滚/清理（cleanup） | flag 仲裁/去重 | 证据链/可续跑 |

### 3.4 领域包接口（Go 骨架）

```go
// agent/domain/pack.go
package domain

// DomainPack 是一个板块的全部「可变部分」。engine 只认这个接口，
// 新增第五个板块 = 新增一个 pack，不动 engine。
type DomainPack interface {
    Key() string                                  // "pentest" | "redteam" | "ctf" | "reverse"
    Prompt() PromptBundle                         // 系统提示词片段 + 角色说明
    Roles() []RoleSpec                            // Lead / Specialist 的角色定义与派生规则
    Tools() []actool.CoreTool                     // 本域内置工具
    MCP() []MCPServerSpec                          // 本域 MCP 池（REA/GhidraMCP/hexstrike…）
    Skills() []string                             // SKILL.md 目录
    Policy() PolicySpec                           // 审批策略：动作 → allow/deny/ask
    Graph() GraphSpec                             // 本域新增的节点/边类型与 schema
    Artifacts() []ArtifactKind                     // 产出物类型（payload/样本/dump/flag…）
    Verifier() Verifier                            // 确定性验收（非 LLM）
    Scheduler() Scheduler                          // "explore" | "campaign" | "race" | "evidence"
}

// Scheduler 决定「意图怎么派、并发多少、何时收敛」——四域差异最大的地方。
type Scheduler interface {
    // Next 返回下一批可执行的 Work（红队按 DAG 前置判定，CTF 按题并行，渗透按 frontier 领取）
    Next(ctx context.Context, st Snapshot) ([]Work, error)
    // Verdict 判定某条产出是否达成该域的成功判据（渗透=PoC复现，CTF=flag命中，红队=目标达成，逆向=证据完备）
    Verdict(ctx context.Context, out Outcome) (done bool, reason string)
}
```

配套改动（在 PRAETOR 上）：

| 改动点 | 位置 | 说明 |
| --- | --- | --- |
| 角色插件化 | `agent/toolcatalog.go`、`agent/prompt*.go` | 把 `builtinToolsByAgent()` 的硬编码 map 换成 `pack.Roles()` 驱动；prompt 按 pack 拼接 |
| 子 Agent 落地 | 新增 `agent/subagent_runner.go` | 包一层 `norma/subagent` + `norma/coordinator.RunParallel`，带预算与回收 |
| 沙箱 | 新增 `sandbox/` | Docker 容器 per specialist；`Bash` 工具改为容器 exec；网络出口强制走现有 MITM 代理 + 目标白名单 |
| 黑板扩展 | `db/` migration | 新增 `binary/function/sample/evidence/flag` 节点 + `artifact` 表（对象存储指针） |
| 竞速调度 | `engine/` | 新增 `raceScheduler`（CTF）：多 solver 并行 + 首解收敛 + 失败换模型 |
| 战役调度 | `engine/` | 新增 `campaignScheduler`（红队）：DAG + 前置判定 + cleanup 保证 |
| 评测 | 新增 `bench/` | 统一 runner 适配 XBOW / Cybench / NYU / AutoPenBench |

---

## 4. 落地路线（建议 4 个迭代，每步都能独立验收）

| 阶段 | 内容 | 验收标准 |
| --- | --- | --- |
| **P0 骨架（1~2 周）** | DomainPack 接口 + 角色插件化 + `norma/subagent` 接入 + Docker 沙箱 + 预算/回收 | 现有 PRAETOR 渗透任务在新架构下 **行为不变**（回归通过）；能派生一个 specialist 并在限额内回收 |
| **P1 渗透对齐（2~3 周）** | 接 hexstrike MCP 工具面 + 确定性验证器（PoC 重放）+ bench runner | **XBOW validation-104** 跑出基线分；AutoPenBench ≥ 论文 baseline |
| **P2 CTF（2~3 周）** | raceScheduler + CTFd 答题 + pwn/rev/crypto 沙箱工具链 + ctf-skills 技能包 | **Cybench 40 题** & NYU CTF Bench 子集出分；对标 verialabs（52/52 为上限参考） |
| **P3 逆向（3 周）** | REA / open-reverselab / GhidraMCP 接入 + 证据链 schema + 可续跑 | 给定 3 个 CTF-rev 题 + 1 个开源样本，产出**可复核证据链**（人抽检通过率 ≥ 80%） |
| **P4 红队（3~4 周）** | Sliver/Mythic + Caldera + Atomic + NetExec + BloodHound + GOAD 靶场 | 在 **GOAD** 上完成一条端到端战役（初始访问→横向→域控），全程有证据 + 有 cleanup 记录 |

**排期建议**：P0 → P1 → P2 → P3 → P4 串行做骨架与渗透（确定地基对不对），P2/P3 可并行（互不依赖），P4 最后（依赖前三者产出的黑板与证据模型沉淀成熟）。

---

## 5. 合规与许可（必须前置决策）

1. **许可证传染**
   - PRAETOR 本体 **AGPL-3.0**：若对外提供网络服务（SaaS），AGPL 要求向使用者提供修改后的源码。**闭源商业化前必须先决策**：要么接受开源、要么 clean-room 重写受影响部分、要么仅内部使用。
   - 可直接吸收（MIT/Apache-2.0）：Strix、PentAGI、Veria ctf-agent、REA、GhidraMCP、Caldera、Atomic Red Team、IDAPython-MCP。
   - 只读思路（AGPL/GPL）：Shannon、T3MP3ST、Pentest-Swarm、Dark-Moon、open-reverselab、Sliver、BloodHound。

2. **授权与 scope 强制**
   - 目标必须在 scope 表内，否则工具层直接 fail-closed（PRAETOR `guard` 已有基础）。
   - 三层限速：单目标 QPS / 单任务总请求 / 全局并发；越界即熔断并记录。
   - 所有动作留痕（谁、何时、对哪个目标、什么 payload），与 7 天流量留痕配套，用于事后审计与免责举证。

3. **红队域的额外红线**
   - C2 只允许在隔离靶场（GOAD / 自建）内落地，禁止在真实目标上部署持久化 implant。
   - 战役必须内置 cleanup（清理上传物、关闭监听、删除账号），且 cleanup 结果进入报告。

4. **逆向域的样本治理**
   - 样本加密存储 + 哈希索引；禁止自动外传（含 LLM 请求中夹带完整样本）。
   - 大二进制先做「符号/函数级切片」再送模型，避免整包上传（合规 + 成本双赢）。

---

## 6. 一句话总结

> **底座用 PRAETOR（原 ARTEX，别丢），调度用 norma（别造），架构抄 Strix + PentAGI（图编排 + 分层记忆），降误报抄 Pentest-Swarm（确定性验证器），CTF 抄 Veria ctf-agent（协调者 + 求解器竞速），逆向靠 MCP（REA / GhidraMCP）而不是自己写反编译，红队只编排不自研 C2。**

---

## 附：参考链接

- 全景跟踪：https://github.com/Yeti-791/Awesome-Offensive-AI-Agentic-Landscape
- 技能包：https://github.com/mukul975/Anthropic-Cybersecurity-Skills ・ https://github.com/ljagiello/ctf-skills
- 工具面（MCP）：https://github.com/0x4m4/hexstrike-ai ・ https://github.com/morluto/rea ・ https://github.com/LaurieWired/GhidraMCP ・ https://github.com/portswigger/mcp-server ・ https://github.com/FuzzingLabs/mcp-security-hub
- 靶场：https://github.com/Orange-Cyberdefense/GOAD ・ https://github.com/CTFd/CTFd ・ https://github.com/0ca/BoxPwnr
- 本仓库：`github.com/jintilm/praetor` ・ SDK `github.com/Autumn-27/norma`（第三方，保留）

---

## 附录 A：P0 骨架已落地（2026-10-26）

已新增包 `agent/domain`（零业务依赖，**尚未接入 engine，不改变任何现有行为**）：

| 文件 | 内容 |
| --- | --- |
| `pack.go` | `DomainPack` 接口 + `Registry`（`Register`/`Get`/`All`）+ 装配期自检 `validate`（必须恰好 1 个 Lead、必须有 Verifier） |
| `verifier.go` | 四个「非 LLM 确定性验收器」最小实现：`pentest/poc-replay`、`redteam/objective-cleanup`、`ctf/flag-arbitration`、`reverse/evidence-chain` |
| `pentest.go` | 调度 `explore`；角色 planner(lead) / worker(specialist)，工具 key 全部指向现有 `toolcatalog` 真实工具 |
| `redteam.go` | 调度 `campaign`；`CleanupRequired=true`；6 个角色；C2/AD 全部走外部 MCP，不自研 |
| `ctf.go` | 调度 `race`；6 类 solver；判题走 CTFd API；`MaxDepth=1` 防竞速指数膨胀 |
| `reverse.go` | 调度 `evidence`；`LocalOnly=true` + 全部敏感 artifact 禁止外传；`MaxDepth=3` 允许函数级递归 |

设计取舍（三条，避免后面返工）：

1. **本包不 import 任何业务包**，工具/角色/MCP 全用字符串 key 声明 → `agent → domain` 单向依赖，永不产生 import cycle；engine 装配期把 key 解析成 `actool.CoreTool` / `subagent.Definition`。
2. **`Verifier` 是接口而非可选**：`validate()` 里 `Verifier()==nil` 直接 panic。理由：没有确定性验收的多 agent 一定退化成「多倍 token 换更多幻觉」。
3. **预算与模型进 DomainPack**：混合部署靠 `ModelPolicy.LocalOnly` 硬约束（逆向域），不是靠 prompt 提醒。

下一步装配（P0 剩余）：

- [ ] `agent/domain/adapter.go`：`DomainPack → []subagent.Definition` + `tool.Registry` 过滤（复用 `subagent.filterTools` 的白名单语义）
- [ ] `engine` 按 `Scheduler()` 选择调度器，`explore` 直接复用现有 `plannerLoop`（保证 P1 行为不变）
- [ ] `toolcatalog.builtinToolsByAgent()` 改为由 `All()` 驱动，删掉硬编码 map
- [ ] 容器沙箱：`sandbox/` 包，`Bash` 改容器 exec，出口强制走现有 MITM 代理 + `AllowEgress` 白名单
