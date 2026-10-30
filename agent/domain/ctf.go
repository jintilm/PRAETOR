package domain

import "time"

// CTF 域（**2026-10-27 重新设计**，与逆向域同一套纪律：**能力活在工具面之外**）。
//
// # 与渗透域的根本差异
//
//   - 判据客观：flag 是否被平台接受，没有「疑似」这一说。所以 Verifier 必须接平台判题，
//     模型自述「解出来了」一律不计分（ctfVerifier 已强制 `accepted` 缺失即拒）。
//   - 执行模型是竞速：多路并行、首解收敛。渗透是「一条链走到底」，CTF 是「谁先拿到算谁的」。
//   - 单题上下文更碎：附件大、要反复写脚本本地跑，所以工具输出必须落盘、只回摘要。
//
// # 设计原则（五条，前三条与逆向域同源）
//
//  1. **工具面在模型外**：模型只看到 2 个工具（ctf_challenge / ctf_submit），
//     真正的能力是沙箱里的 CLI 工具链（pwntools / gdb+pwndbg / rizin / z3 / tshark…）。
//     接一个新工具 = 改镜像，**不改 schema**。
//  2. **首解即收敛**：任一 solver 拿到 `accepted`，立刻 cancel 同题其余 solver。
//     竞速的价值不在「跑得快」，而在「省下败者的 token」。
//  3. **延迟竞速（lazy race）**：默认**单路**，出现停滞信号才起第二路。
//     并行是唯一会把成本 ×N 倍放大的操作，而实测多数题单路能解 —— 一上来就 2~8 路是纯浪费。
//  4. **提交唯一出口**：所有 flag 只能经 `ctf_submit` 出门，由它做格式校验 → 本地去重 → 平台提交 → 落 verdict。
//     去重放在工具里（不是放在某个角色里），任何角色调用都安全。
//  5. **预算到顶就放弃**：单题 token/轮数到上限 → 标 `abandoned` 并写清「试过什么」，
//     让人能接手；绝不允许模型在同一个点上无限重试把预算烧光。
//
// # 成本模型（用于定闸门，不是精确预测）
//
//	单轮固定成本实测 ~10.7K tokens（32 工具 + 8 段提示词）；
//	单路 25 轮、context 中位 ~18K  ⇒  ~450K/题
//	eager 2 路（总是并行）        ⇒  ~900K/题
//	lazy race（约 40% 需要第二路）⇒  ~630K/题（省 ~30%）
//	40 题全量                       ⇒  ~25M tokens（所以基准必须 -limit 分批）
//
// # 已知限制（写在这里，不要当成已实现）
//
//   - **第一版不换模型**：模型是**任务级** profile 链（`task_llm.go` 的 `ActiveLLMProfileID`），
//     没有 per-intent 模型。所以 race 第一版靠「换起点/换思路」，不靠「换模型」；
//     per-intent 模型路由是 P2-5，要动 `task_llm`。
//   - `ctf_submit` 需要 CTFd 的 API token（或 session + CSRF）；拿不到就退化为「离线判分模式」：
//     只与题目给定 flag 比对，不联网（基准跑分走这条路）。
//   - 运行时**还没有 subagent 派生能力**（`subagent.` 只在 domain 包内出现），
//     所以 race 第一版复用现有 worker + intent 机制，而不是派生子 agent。
func init() { Register(ctfPack{}) }

type ctfPack struct{}

func (ctfPack) Key() Key      { return CTF }
func (ctfPack) Title() string { return "CTF 竞赛" }

func (ctfPack) Prompt() []string {
	return []string{
		"你是 CTF 竞赛的协调者。首要目标是在时间预算内最大化解出的题目数，而不是把一道题做到完美。",
		"识别题目类型（web/pwn/rev/crypto/forensics/misc）后分派给对应 solver；同一题可并行多解法。",
		"任何结论都必须给出可验证的 flag 与完整利用/求解路径；不许猜 flag 硬凑格式。",
		// 新设计的行为约束：工具少是刻意的，别去「找一个更全的工具」。
		"工具只有 ctf_challenge / ctf_submit，其余全部在沙箱里用命令行做。不要因为「缺少某工具」而停下——" +
			"先看镜像里有什么；确实没有就换思路，并把「缺什么」写进记录。",
	}
}

// 子 agent 的单次派发墙钟。**必须小于 worker 的 run_seconds 减 30s 收尾余量**
// （subagent.dispatchSettleMargin），否则 run() 的派发前检查会一律拒绝 —— 子 agent 不是
// "跑得慢"，而是永远派不出去。默认 worker run_seconds = 1200s（agents 表列默认），于是：
//
//	lead   600s：25 轮规划/派发，够它读榜、派活、仲裁一次
//	solver 900s：1200 - 900 - 30 = 270s 留给 lead 派活与消费结果
//
// 为什么不是计划里写的 20/30/45 分钟：那三个数在 1200s 的父预算下**永远过不了检查**
// （父 agent 总共只有 20 分钟），上线即等于关掉子 agent。要更长的子任务，先把 worker 的
// run_seconds 调大（Agent 管理页），再改这两个常量；启动期有告警兜底这对值不匹配。
const (
	ctfLeadWall   = 10 * time.Minute
	ctfSolverWall = 15 * time.Minute
)

// Roles 保留 6 个（1 lead + 5 类 solver），但**工具全部收敛为 Bash/Read/Write(+Edit)**。
//
// 为什么这里不像逆向域那样砍角色：CTF 的 5 类是**能力差异**而不是场景差异 ——
// pwn 要 pwntools + 调试器，crypto 要 z3/sage，forensics 要 tshark/volatility，
// 提示词与工具链都不同，合并会写出又长又含糊的万能提示词。
//
// 但声明层面必须干净：原来每个 solver 都挂着 2~4 个**根本不存在的工具 key**（合计 13 个不同名字）
// （pwntools_run / checksec / z3_solve / tshark_run …）。它们解析不出实例，装配期会被过滤，
// 只留下「看起来声明了、实际什么都没有」的假象。现在统一改成：**Bash 是唯一的执行入口**，
// 具体工具由镜像提供（见 CTFToolchain），模型在 Bash 里直接调 CLI。
func (ctfPack) Roles() []RoleSpec {
	return []RoleSpec{
		{
			Key:         "ctf_lead",
			Kind:        RoleLead,
			Name:        "CTF 统筹",
			Description: "读题面与附件，判类型、分配预算、竞速仲裁、决定放弃哪题",
			PromptSection: "开局先调 ctf_board 拿排序（它按分值/难度/剩余预算算好了该先做哪道），" +
				"再按 recommend 派活——不要凭题面印象随手挑一道。" +
				"每题维护一份「已尝试思路」清单，避免第二个 solver 重踩。" +
				"某一题连续多轮没有新事实时：要么起第二路换起点，要么用 ctf_board 的 give_up 记下" +
				"「试过什么、卡在哪」后换题——**死磕一道做不出的题是最贵的浪费**。" +
				"看板说 exhausted 时就收工，不要挤预算。",
			// add_intent/add_hint 是真实存在的平台工具：lead 的"分派"就是靠它建意图；
			// 没有它 lead 只能空谈策略（race 调度器建初始意图，后续换起点仍由 lead 决定）。
			ToolKeys:    []string{"Read", "Bash", "ctf_challenge", "ctf_board", "ctf_submit", "add_intent", "add_hint"},
			MaxTurns:    25,
			MaxDuration: ctfLeadWall,
			Approval:    ApprovalAuto,
			Budget:      Budget{MaxParallel: 2}, // 延迟竞速：单路先跑，停滞才起第二路
		},
		{
			Key:         "solver_web",
			Kind:        RoleSpecialist,
			Name:        "CTF · Web 解题",
			Description: "Web 题：注入/SSRF/反序列化/模板/文件上传/JWT",
			ToolKeys: []string{"Bash", "Read", "Write", "ctf_submit",
				// Web 题的**客户端侧**只能靠浏览器：XSS 要执行 JS 看是否触发、
				// CSRF 要看表单与 cookie、DOM clobbering 要看渲染后的 DOM。
				// 只给 Bash 时这类题做不了（curl 拿到的是源码，不是执行后的页面）。
				//
				// 只给 6 个，不是全部 25 个：navigate（打开）、evaluate（执行 JS，XSS 验证的核心）、
				// snapshot（读渲染后的 DOM）、click / fill_form（交互）、network_requests（看请求）。
				// resize / emulate_media / tabs / file_upload 对 CTF 没有用，白白占 schema。
				"mcp__browser__browser_navigate", "mcp__browser__browser_evaluate",
				"mcp__browser__browser_snapshot", "mcp__browser__browser_click",
				"mcp__browser__browser_fill_form", "mcp__browser__browser_network_requests"},
			MaxTurns:    30,
			MaxDuration: ctfSolverWall,
			Approval:    ApprovalAuto,
			PromptSection: "先在容器内本地复现，再打远端实例；注意实例有重置次数限制。" +
				"拿到 flag 立刻提交（ctf_submit），不要等「完全确认后再报」——竞速里晚一步就白干。",
		},
		{
			Key:         "solver_pwn",
			Kind:        RoleSpecialist,
			Name:        "CTF · Pwn 解题",
			Description: "Pwn 题：栈/堆利用、格式化字符串、ROP、沙箱逃逸",
			ToolKeys:    []string{"Bash", "Read", "Write", "Edit", "ctf_submit"},
			MaxTurns:    40,
			MaxDuration: ctfSolverWall,
			Approval:    ApprovalAuto,
			PromptSection: "先 checksec 定性（镜像内有 pwntools/checksec），再用 pwndbg 定位；" +
				"exp 写到文件再跑，保留调试日志作为证据。偏移算错时先用本地实例验证，别直接打远端。" +
				// 下面这段来自 10-30 基准跑：task 194 的 solver 用 12 分钟发了 12 条
				// `printf ... | nc`，平均 60 秒/条，而其中大半是"同一轮泄漏换个格式再试"，
				// 完全可以在一个脚本里一次跑完。逐条手打 payload = 每条都付一次模型往返，
				// 这是盲打题最贵的浪费（也是 Bash 失败率里剩下那 9% 的主要来源：
				// 手写转义错、管道被截断、输出被 head 截掉）。
				"**不要逐条手打 payload**：每发一条命令都是一次完整往返（实测 30~90 秒），" +
				"盲打题（没有二进制附件）尤其吃亏。把「连一次 → 发一批 → 收输出 → 落文件」" +
				"写进一个 pwntools / socket 脚本，一次跑完一整轮：批量泄漏 `%p`、批量试偏移、" +
				"批量试写，结果写进文件再用 Read 读，不要在命令行里用 head/awk 截输出。" +
				"拿到栈布局或崩溃信息后，先写清「还缺什么」，再决定下一轮脚本，而不是边打边改。",
		},
		{
			Key:         "solver_rev",
			Kind:        RoleSpecialist,
			Name:        "CTF · 逆向解题",
			Description: "逆向题：静态反编译 + 动态调试，还原校验逻辑",
			ToolKeys:    []string{"Bash", "Read", "Write", "ctf_submit"},
			MaxTurns:    40,
			MaxDuration: ctfSolverWall,
			Approval:    ApprovalAuto,
			PromptSection: "优先动态验证假设（gdb/rizin），别在反编译结果里空想；" +
				"关键函数要留地址与伪代码片段。若逆向域已启用，可直接复用其配方（disasm/xrefs/decompile）。",
		},
		{
			Key:         "solver_crypto",
			Kind:        RoleSpecialist,
			Name:        "CTF · 密码解题",
			Description: "密码学题：古典密码、RSA/ECC 误用、格、PRNG 预测",
			ToolKeys:    []string{"Bash", "Write", "ctf_submit"},
			MaxTurns:    30,
			MaxDuration: ctfSolverWall,
			Approval:    ApprovalAuto,
			PromptSection: "先判断是「实现错误」还是「数学困难」：前者写脚本，后者先降维试小参数。" +
				"z3 在线性/位运算约束上比手推快；格问题再上 sage（镜像里按需装）。",
		},
		{
			Key:         "solver_forensics",
			Kind:        RoleSpecialist,
			Name:        "CTF · 取证解题",
			Description: "取证/流量/隐写/misc：pcap、内存镜像、文件格式、编码",
			ToolKeys:    []string{"Bash", "Read", "Write", "ctf_submit"},
			MaxTurns:    30,
			MaxDuration: ctfSolverWall,
			Approval:    ApprovalAuto,
			PromptSection: "先 file/binwalk 摸清格式，再决定深挖方向；保留每一步的命令与输出。" +
				"隐写先试常见顺序（exiftool → binwalk → zsteg → 字符串），别一上来就上重武器。",
		},
	}
}

// Tools 是域级声明的工具面：**3 个**。
//
// 与逆向域同理，这些 key 在接入前会被 `UnresolvedDomainTools` 报「声明了但未接入」，
// 由 `TestCTFDeclaredToolsAreDesignSet` 锁成已知清单。
//
// 为什么允许从 2 个加到 3 个（P2-6）：这两个协调工具解决的是**比赛里最贵的错误**——
// 死磕一道做不出的题直到预算烧光。它们不提供任何"解题能力"（能力仍在沙箱镜像里），
// 只是把"还有哪些题、各值多少分、我花了多少"摊开。仍然封顶 3：再加就得先进沙箱。
func (ctfPack) Tools() []string {
	return []string{"ctf_challenge", "ctf_board", "ctf_submit"}
}

// MCP 返回空：**刻意不接**，连 CTFd 也不走 MCP。
//
// 理由：CTFd 的 MCP/插件要额外起进程并暴露一堆工具，而我们只需要「拉题面」和「提交 flag」
// 两个动作 —— 直接写进 `ctf_challenge` / `ctf_submit` 的 HTTP 客户端更省：
// 少一个进程、少一份 schema、少一条会出错的链路。
func (ctfPack) MCP() []MCPRef { return nil }

func (ctfPack) Skills() []string { return []string{"ctf-skills"} }

func (ctfPack) Policy() PolicySpec {
	return PolicySpec{
		ScopeRequired: false, // CTF 目标由平台给定，天然隔离
		Rules: []PolicyRule{
			{Match: "Bash", Action: ActionAllow, Reason: "CTF 全部在隔离容器内，允许自由执行"},
			{Match: "ctf_submit", Action: ActionAllow, Reason: "提交 flag 由工具内统一去重后发出"},
			{Match: "artifact.exfil", Action: ActionDeny, Reason: "禁止把题目附件外传"},
		},
	}
}

func (ctfPack) Graph() GraphSpec {
	return GraphSpec{
		NodeKinds: []string{"challenge", "intent", "fact", "flag", "hint", "writeup"},
		EdgeKinds: []string{"solves", "derived_from", "yields", "duplicates"},
	}
}

func (ctfPack) Artifacts() []ArtifactKind {
	return []ArtifactKind{
		{Key: "challenge_file", Description: "题目附件/镜像", MaxBytes: 512 << 20},
		{Key: "exp_script", Description: "利用或求解脚本", MaxBytes: 4 << 20},
		{Key: "writeup", Description: "解题路径（含命令与输出）", MaxBytes: 2 << 20},
		{Key: "flag_proof", Description: "flag 与平台判题回执（提交原文）", MaxBytes: 64 << 10},
	}
}

// CTFToolchainItem 是沙箱镜像里应提供的 CLI（**不是**给模型的工具）。
//
// 这张表有双重用途：① P2-3 的镜像构建清单；② 让「缺什么」可被明确报告，
// 而不是让模型在 Bash 里逐个 `command -v` 试探（每次试探都是一次 LLM 调用）。
//
// 纪律（由 TestCTFToolchainIsLean 守着）：
//   - 每项必须写明类别与许可（R4）；未标注许可的一律按「外部进程调用，不复制代码」处理；
//   - `Base=true` 的项数必须受控（镜像体积决定冷启动时间）；
//   - 重依赖（angr / sagemath / volatility3）必须 `Base=false`，按需安装。
type CTFToolchainItem struct {
	Name     string // 可执行文件名（模型在 Bash 里直接敲的那个）
	Category string // pwn / rev / web / crypto / forensics
	Upstream string // 上游项目
	License  string // 许可；"未标注" = GitHub 未能识别，按外部调用处理
	Base     bool   // 是否进基础镜像
	Why      string // 解决什么问题（给 P2-3 构建镜像的人看）
	// Component 是「可选组件」清单（internal/components）里的 ID。
	//
	// 这是本表与镜像之间的**唯一切口**：声明写了什么，镜像就必须装什么。
	// 只写名字不写 ID 的话，两边会漂移，表现是「文档说镜像里有 pwntools、实际没有」——
	// `server/ctf_toolchain_test.go` 会拿它逐项核对清单。
	Component string
}

// CTFToolchain 返回沙箱镜像的 CLI 清单（有序，供镜像构建与文档共用）。
func CTFToolchain() []CTFToolchainItem {
	return []CTFToolchainItem{
		// pwn：交互 + 调试 + gadget
		// pwntools 走发行版包（python3-pwntools）：pip 版要现场编译原生依赖，
		// 而基础镜像的系统解释器是 Python 3.14。
		{Name: "pwntools", Category: "pwn", Upstream: "Gallopsled/pwntools", License: "未标注", Base: true, Why: "远程交互、打包解包、ELF 解析", Component: "pwntools"},
		{Name: "gdb", Category: "pwn", Upstream: "GNU binutils", License: "GPL-3.0", Base: true, Why: "动态调试基线", Component: "gdb"},
		// 原定 pwndbg：实测既不在 Kali 源、也不在内网 pip 源里，装不上；
		// GEF 提供同类的堆/栈/寄存器可视化，且是发行版包（可复现）。
		{Name: "gef", Category: "pwn", Upstream: "hugsy/gef", License: "MIT", Base: true, Why: "gdb 增强：堆可视化、栈回溯", Component: "gef"},
		{Name: "ROPgadget", Category: "pwn", Upstream: "JonathanSalwan/ROPgadget", License: "未标注", Base: true, Why: "gadget 搜索", Component: "ropgadget"},
		{Name: "seccomp-tools", Category: "pwn", Upstream: "david942j/seccomp-tools", License: "MIT", Base: true, Why: "沙箱规则分析（判断能否 execve）", Component: "seccomp-tools"},
		// rev：反汇编 + 固件/文件拆解
		{Name: "rizin", Category: "rev", Upstream: "rizinorg/rizin", License: "LGPL-3.0", Base: true, Why: "反汇编/交叉引用（脚本化）", Component: "rizin"},
		{Name: "binwalk", Category: "rev", Upstream: "ReFirmLabs/binwalk", License: "MIT", Base: true, Why: "固件/嵌套文件识别与提取", Component: "binwalk"},
		// crypto：约束求解 + 自动解码
		{Name: "z3", Category: "crypto", Upstream: "Z3Prover/z3", License: "未标注", Base: true, Why: "位运算/线性约束求解", Component: "z3"},
		{Name: "ciphey", Category: "crypto", Upstream: "ciphey/ciphey", License: "MIT", Base: true, Why: "常见编码/古典密码自动识别", Component: "ciphey"},
		{Name: "angr", Category: "crypto", Upstream: "Angr/angr", License: "BSD-2-Clause", Base: false, Why: "符号执行（体积大，按需装）", Component: "angr"},
		{Name: "sage", Category: "crypto", Upstream: "sagemath/sage", License: "GPL-3.0", Base: false, Why: "格/数论（体积数 GB，按需装）", Component: "sage"},
		// forensics：流量/隐写/内存
		{Name: "tshark", Category: "forensics", Upstream: "wireshark/wireshark", License: "GPL-2.0", Base: true, Why: "pcap 解析与字段提取", Component: "tshark"},
		{Name: "zsteg", Category: "forensics", Upstream: "zed-0xff/zsteg", License: "未标注", Base: true, Why: "PNG/BMP LSB 隐写", Component: "zsteg"},
		{Name: "exiftool", Category: "forensics", Upstream: "exiftool/exiftool", License: "未标注", Base: true, Why: "元数据（隐写第一顺位）", Component: "exiftool"},
		{Name: "volatility3", Category: "forensics", Upstream: "volatilityfoundation/volatility3", License: "未标注", Base: false, Why: "内存镜像分析（按需装）", Component: "volatility3"},
	}
}

func (ctfPack) Model() ModelPolicy {
	return ModelPolicy{
		Tier:        TierCloud,
		Reason:      "pwn/rev 对代码推理要求最高，用大模型；**第一版不换模型**（模型是任务级 profile 链，per-intent 路由见 P2-5）",
		PreferLarge: true,
	}
}

// Budget 从「拍脑袋的 4M / 2000 次 / 并发 8」收紧为可解释的目标值。
//
// 并发 8 是设计缺陷：8 路 × 40 轮 × ~18K ≈ 5.8M/challenge，而多数题单路就能解。
// 现在默认 **MaxParallel 2**（延迟竞速：1 路探测 + 1 路挑战），并靠「首解即 cancel」止损。
func (ctfPack) Budget() Budget {
	return Budget{
		MaxTokens:    3_000_000,
		MaxWall:      2 * time.Hour, // 单题上限；整场时长由任务 deadline 控制
		MaxToolCalls: 500,
		MaxDepth:     1, // solver 不再派生，避免竞速时指数膨胀
		MaxParallel:  2,
	}
}

func (ctfPack) Scheduler() SchedulerKind { return ScheduleRace }
func (ctfPack) Verifier() Verifier       { return ctfVerifier{} }

// WorkerIsLead：CTF 的 lead 就是 worker。race 调度器按题建意图，领到意图的 worker
// 同时负责选题判断、派 solver、仲裁结果 —— planner 在 CTF 域只做初始题目拆分。
func (ctfPack) WorkerIsLead() bool { return true }
