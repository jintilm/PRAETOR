package domain

import "time"

// 逆向域（**2026-10-27 重新设计**）。
//
// # 为什么重做
//
// 初版按「接 REA + Ghidra MCP」设计，工具面直接继承上游。实测下来这条路的成本结构不对：
//   - REA 是全家桶（二进制 + 应用包 + 浏览器运行时 + android/apktool + cutter + artifact 对比），
//     光是工具契约文件就 20KB/15KB/12KB/8KB 各一份。**这些 schema 每一轮都要随上下文重发**，
//     本项目的固定成本实测是 ~10.7K tokens/轮（32 个工具 + 8 段提示词），再叠一个全家桶就是纯亏。
//   - 工具越多，模型在「该用哪个」上的试错越多。而本项目最贵的是**调用次数**不是单次体积：
//     实测一道渗透题 13 次 traffic_get（每次返回仅几百字符）就吃掉约 630K tokens，
//     因为每次调用都要重发整个上下文。
//   - 多路径也让结论更难收敛：REA 的 decompile/disasm/xrefs/strings/imports… 各自都能"看一眼"，
//     模型倾向于反复浅尝，而不是把一条证据链走完。
//
// # 新设计：3 个工具 + 配方 + 零 MCP
//
// 核心判断：**能力应该活在工具面之外**。
//
//		模型看到的永远是 3 个工具（triage / recipe / evidence），
//		底下挂多少 CLI、来自哪个项目，模型完全不需要知道 —— 也就不会为「该用哪个」付试错成本。
//
//	 1. `re_triage(target)` —— **一次调用出全貌**：格式/架构/位数/编译器/加壳迹象/入口点/段表/
//	    高风险导入/字符串摘要。返回 ≤1.5KB 结构化摘要，完整报告落盘（`re/<sha256>/triage.json`）。
//	    纯 Go 解析 PE/ELF/Mach-O 头，**不依赖任何外部 CLI** —— 本机实测 rizin/ghidra/jadx 全都没有，
//	    objdump/readelf 只在 msys64 里；依赖外部工具的工具面在容器里就是废的。
//	 2. `re_recipe(recipe, target, page)` —— **一个 schema 覆盖全部外部能力**。
//	    配方（见 ReverseRecipes）是已固化的 CLI 管道：`disasm`→rizin、`decompile`→Ghidra headless、
//	    `capability`→capa、`strings`→FLOSS、`packer`→DIE、`mobile`→apktool+jadx…
//	    模型只在一个枚举字段里选配方名，参数不会漏、命令不会写错，**上游项目换来换去不影响 schema**。
//	    缺可执行文件时明确报「缺 X，装法见文档」，不静默降级（与沙箱 required 同一条纪律）。
//	 3. `re_evidence(claim, ref, xref_count, trace_ref)` —— **唯一的下结论出口**，
//	    直接把结论写成证据节点交给 reverseVerifier 判（无 xref 无 trace 一律不通过）。
//
// # 为什么不用 MCP（本轮核过许可证与规模，2026-10-27）
//
//	| 候选 | 形态 | 判断 |
//	|---|---|---|
//	| morluto/rea | 多家族 monorepo（二进制+应用包+浏览器运行时+android/apktool+cutter+artifact） | 工具面过宽，schema 每轮重发，且有大量同类能力让模型反复浅尝 |
//	| bethington/ghidra-mcp | **自称 200+ 个 MCP 工具** | 典型反面样本：光工具描述就能吃掉整个上下文预算 |
//	| LaurieWired/GhidraMCP、cyberkaida/ReVa、clearbluejar/pyghidra-mcp | Ghidra MCP | 能力重合，接一个就够；而我们要的「反编译单函数」用 headless 脚本更省 |
//	| mrexodia/ida-pro-mcp | IDA MCP（MIT） | 同上；IDA 授权场景另说 |
//
//	结论：**只取 CLI 能力，不取 MCP 工具面**。要更深的能力（符号执行 angr、模拟执行 qiling）
//	同样是"再加一个配方"，而不是"再加一百个工具"。
//
// # 预算纪律（重要）
//
// `Budget` 里的 MaxTokens/MaxToolCalls/MaxParallel **目前没有任何执行层消费它们**
// （全仓只有 MaxDepth 透传给了 subagent），所以初版的「6M tokens / 3000 次工具调用」
// 从来没生效过，纯装饰。真正管住成本的是 `ScheduleEvidence` 的闸门（P3-1），
// 这里的数字改成**贴近现实的目标值**，等闸门落地后才真正起作用。
//
// 三条硬约束（来自样本治理要求，未变）：
//  1. LocalOnly —— 样本与伪代码不出本机，模型也走本地；
//  2. 切片后再送模型 —— 大二进制先做函数级切片，不整包塞上下文；
//  3. 结论必须挂证据 —— 交叉引用或动态 trace，否则只能算「推测」。
func init() { Register(reversePack{}) }

type reversePack struct{}

func (reversePack) Key() Key      { return Reverse }
func (reversePack) Title() string { return "逆向工程" }

func (reversePack) Prompt() []string {
	return []string{
		"你是二进制分析者。目标不是「猜这段代码做什么」，而是产出一条别人能复核的证据链。",
		"每一步结论都要落到具体证据：函数地址、交叉引用、字符串、动态 trace、内存 dump。",
		"遇到无法确定的点，明确标注「未确认」并给出验证方法，禁止用看似合理的猜测填补空白。",
		// 新设计的核心行为约束：工具少是刻意的，不要试图用外部全家桶绕开。
		"工具面刻意很小（triage / recipe / evidence）。不要为了「再看看」反复换手段：一次 triage 定路线，" +
			"之后每次 recipe 都要指向一个待验证的假设，验证完立刻用 evidence 落结论。",
	}
}

// 子 agent 的单次派发墙钟。约束与取值理由同 ctf.go（必须小于 worker run_seconds
// 减 30s 收尾余量，否则派发前检查一律拒绝）。逆向域多给 analyst 一点：一条假设的
// 动态验证（起调试器、跑 trace、读输出）比一道 CTF 题的一个步骤更长。
const (
	reLeadWall    = 10 * time.Minute
	reAnalystWall = 15 * time.Minute
)

// Roles 从 5 个收敛到 2 个。
//
// 砍掉的 malware-analyst / mobile-analyst 不是能力差异，而是**场景差异**（同一个分析者换个目标而已）：
// 每个 specialist 都是独立 agent + 独立 system prompt（KB 级、每轮重发），
// 5 个角色意味着 5 份提示词常驻上下文，而收益只是措辞更贴题。
// 静态/动态也合并：串行证据链里本来就要交替（静态提假设 → 动态验证），拆成两个 agent 反而多一次交接。
func (reversePack) Roles() []RoleSpec {
	return []RoleSpec{
		{
			Key:         "re_lead",
			Kind:        RoleLead,
			Name:        "逆向 · 统筹",
			Description: "定路线、维护证据链、判定结论置信度",
			PromptSection: "先 triage 一次拿到全貌，再按「入口 → 关键分支 → 数据流」定 2~3 条待验证假设。" +
				"每条假设交给 analyst 验证后，必须用 re_evidence 落结论；证据不足就降级为「未确认」，不要含糊表述。" +
				"同一假设最多验证两轮，第二轮仍无进展就换假设或收束——不要在同一个点上反复试。",
			// re_triage 只给 lead：它是「定路线」的一次性动作，analyst 直接读落盘报告即可，
			// 两边都给会导致同一目标被 triage 两次（一次多余的 LLM 调用 + 一次重复输出）。
			ToolKeys:    []string{"Read", "Bash", "re_triage", "re_evidence"},
			MaxTurns:    20,
			MaxDuration: reLeadWall,
		},
		{
			Key:         "re_analyst",
			Kind:        RoleSpecialist,
			Name:        "逆向 · 分析",
			Description: "执行单条分析意图：静态定位（反汇编/交叉引用/字符串）与动态验证（调试/trace）",
			ToolKeys:    []string{"Read", "Write", "Bash", "re_recipe"},
			MaxTurns:    30,
			MaxDuration: reAnalystWall,
			PromptSection: "每次只回答一个具体问题（某个函数做什么 / 某个字符串被谁引用 / 某处校验能否绕过）。" +
				"re_recipe 一次只取一页，需要更多就带 page 续取，不要用超大 limit 一次灌满。" +
				"配方缺可执行文件时会明确报缺哪个，按提示记录「环境不具备」并换路线，不要自己拼命令绕过去。" +
				"结论写回时必须带地址或引用来源；动态验证保留命令与关键输出作为 trace。",
		},
	}
}

// Recipe 是一个**已固化的分析配方**：模型只说「要什么」，不关心底下是哪个项目、什么参数。
//
// 这是本轮设计的收敛点。接一个新能力 = 加一行配方，而不是给模型再塞一堆工具：
// 工具 schema 不变、模型的选择空间不变、每轮固定成本不变。
//
// 纪律（由 TestReverseRecipeCatalogIsLean 守着）：
//   - 每条必须写明上游与许可（R4：LGPL/GPL 只做外部进程调用，不复制、不链接代码）；
//   - 总条数 ≤ 10 —— 超过说明又在堆能力了，先问「哪条能合并」；
//   - Returns 必须一句话说清返回什么、多大，避免模型对大输出没有预期。
type Recipe struct {
	Name     string   // 配方名（re_recipe 的枚举值）
	Upstream string   // 复刻/依赖来源；空 = 自研
	License  string   // 上游许可；空 = 自研
	Needs    []string // 需要的可执行文件；空 = 纯 Go，无需外部依赖
	Returns  string   // 返回什么（会进工具描述，直接决定模型怎么用）
}

// ReverseRecipes 返回逆向域的全部配方（有序，供工具实现与文档共用）。
//
// 选择标准只有一条：**单命令、可 JSON 化、确定性输出**。凡是需要长交互会话、
// 需要 GUI、或自带几百个工具的，一律不进这张表。
func ReverseRecipes() []Recipe {
	return []Recipe{
		{Name: "triage", Returns: "全貌摘要 ≤1.5KB（格式/架构/加壳迹象/入口/段表/高风险导入/字符串摘要）；全文落盘"},
		{Name: "disasm", Upstream: "rizinorg/rizin", License: "LGPL-3.0", Needs: []string{"rizin"},
			Returns: "指定函数或地址区间的反汇编，分页（page 从 0 起，每页 ≤60 条）"},
		{Name: "xrefs", Upstream: "rizinorg/rizin", License: "LGPL-3.0", Needs: []string{"rizin"},
			Returns: "某个地址/字符串/导入的交叉引用列表（谁调用、谁读取），分页"},
		{Name: "decompile", Upstream: "NationalSecurityAgency/ghidra", License: "Apache-2.0", Needs: []string{"analyzeHeadless"},
			Returns: "单个函数的伪代码（≤4KB，超出落盘），附函数地址与签名"},
		{Name: "strings", Upstream: "mandiant/flare-floss", License: "Apache-2.0", Needs: []string{"floss"},
			Returns: "还原混淆后的字符串（栈串/解码串），去重分类后 ≤2KB，全量落盘"},
		{Name: "capability", Upstream: "mandiant/capa", License: "Apache-2.0", Needs: []string{"capa"},
			Returns: "命中的能力（如「创建进程」「注入」）与对应地址，≤2KB"},
		{Name: "packer", Upstream: "horsicq/Detect-It-Easy", License: "MIT", Needs: []string{"diec"},
			Returns: "编译器/加壳器判定与依据（配合段熵）；判定为壳时给出脱壳建议"},
		{Name: "trace", Upstream: "gdb", License: "GPL-3.0", Needs: []string{"gdb"},
			Returns: "指定函数的动态调用序列与关键寄存器/返回值（gdb batch，只输出序列不输出全文）"},
		// Needs 只写 apktool：jadx 只决定"Java 源码还是 smali"的可读性，
		// 不装也能拿到清单、类名与单类 smali。把可选增强写成硬依赖，
		// 等于让没装 200MB jadx 的机器整条配方不可用 —— 可读性问题不该变成阻断。
		{Name: "mobile", Upstream: "iBotPeaches/Apktool（jadx 可选）", License: "Apache-2.0", Needs: []string{"apktool"},
			Returns: "APK 解包摘要：清单关键项、入口 Activity、类名清单（分页，不返回反编译全文）；" +
				"select=类名时回该类的 Java（装了 jadx）或 smali 源码"},
		// 第 10 条，正好卡住 TestReverseRecipeCatalogIsLean 的上限。
		// 再加移动端能力时优先合并进这条（用 select 区分子动作），不要扩表。
		// Needs 里的 apktool 只对 APK 分支生效；IPA 分支是纯 Go zip，无外部依赖。
		{Name: "mobile_scan", Upstream: "iBotPeaches/Apktool（APK 解包）＋ Go archive/zip（IPA），规则自研", License: "Apache-2.0", Needs: []string{"apktool"},
			Returns: "静态规则扫描，按文件形态自动分流：APK → 导出组件 / 可调试 / 备份 / 明文流量 / 用户 CA / " +
				"证书绑定 / 危险权限 / WebView / 硬编码凭据；IPA → Info.plist（ATS / URL scheme / 权限用途）、" +
				"Mach-O 魔数、描述文件 entitlement、明文端点。一行一条带「文件:行 + 依据」，分页 ≤60 行，全文落盘"},
	}
}

// Tools 是域级声明的工具面：**3 个，全部自研，零 MCP**。
//
// 这 3 个 key 在 P3-2~P3-4 落地前会被 `UnresolvedDomainTools` 报「声明了但未接入」——
// 那是预期行为，且被 `TestReverseDeclaredToolsAreDesignSet` 锁成一份**已知清单**，
// 不是随机漂移。落地一个就从该测试里划掉一个。
func (reversePack) Tools() []string {
	return []string{"re_triage", "re_recipe", "re_evidence"}
}

// MCP 返回空：**刻意不接**。
//
// 初版声明了 rea / pyghidra / ida-pro 三个 stdio MCP。问题不在许可，在成本结构：
// MCP 的工具由外部进程自带，schema 全量进上下文（REA 是全家桶），且每个工具都是一条新的
// "可能路径"，模型会在其中反复试错。要能力就用 Bash 调 CLI（按需、不占 schema），
// 要确定性就用自研的 3 个窄工具。
//
// 如果将来确实要接，约束写在这里：**只接单一职责的 MCP**（例如只暴露 decompile 一个工具），
// 且必须实测 schema 增量 < 1.5K tokens 再决定。
func (reversePack) MCP() []MCPRef { return nil }

func (reversePack) Skills() []string { return []string{"binary-triage"} }

func (reversePack) Policy() PolicySpec {
	return PolicySpec{
		ScopeRequired: false,
		// 逆向不出网：只允许访问本地分析服务与本机文件。
		AllowEgress: []string{"127.0.0.1", "localhost"},
		Rules: []PolicyRule{
			{Match: "Bash", Action: ActionAsk, Reason: "任意命令需确认，防止样本逃逸到宿主"},
			{Match: "artifact.upload", Action: ActionDeny, Reason: "样本与伪代码禁止外传（含禁止整包进 LLM 请求）"},
			{Match: "net.outbound", Action: ActionDeny, Reason: "分析环境默认无外网；回连用黑洞地址接住"},
			{Match: "sample.decrypt", Action: ActionAsk, Reason: "解密样本库需授权"},
		},
	}
}

func (reversePack) Graph() GraphSpec {
	return GraphSpec{
		NodeKinds: []string{"sample", "binary", "function", "string", "xref", "evidence", "conclusion"},
		EdgeKinds: []string{"calls", "references", "derived_from", "supports", "contradicts"},
	}
}

func (reversePack) Artifacts() []ArtifactKind {
	return []ArtifactKind{
		{Key: "sample", Description: "原始样本（加密存储 + 哈希索引）", Sensitive: true, LocalOnly: true, MaxBytes: 256 << 20},
		{Key: "triage_report", Description: "一次 triage 的结构化全貌（摘要进上下文，全文落盘）", Sensitive: true, LocalOnly: true, MaxBytes: 4 << 20},
		{Key: "decompiled_slice", Description: "函数级伪代码切片", Sensitive: true, LocalOnly: true, MaxBytes: 4 << 20},
		{Key: "memory_dump", Description: "进程内存镜像", Sensitive: true, LocalOnly: true, MaxBytes: 1 << 30},
		{Key: "analysis_report", Description: "结论 + 证据链 + 置信度", MaxBytes: 4 << 20},
	}
}

func (reversePack) Model() ModelPolicy {
	return ModelPolicy{
		Tier:        TierLocal,
		Reason:      "样本与伪代码属最高敏感级，强制本地模型（LocalOnly），宁可牺牲部分推理能力",
		LocalOnly:   true,
		PreferLarge: true,
	}
}

// Budget 从「拍脑袋的大数」改为「贴近现实的目标值」。
//
// 初版 6M tokens / 12h / 3000 次工具调用 / MaxParallel 2：这些字段除了 MaxDepth 之外
// **根本没有执行层消费**，等于装饰。现在按「串行 + 每阶段落盘 + 收束优先」估算：
//   - 串行 2 角色、MaxTurns 20+30 = 最多 50 次 LLM 调用；
//   - context 按 ~12K 起步、随查询结果缓慢增长，中间值按 25K 估；
//   - 50 × 25K ≈ 1.25M，留 20% 余量 → 1.5M。
//
// MaxParallel 1 是设计选择而非保守：两条并行分析线会重复消耗同一份样本的理解成本，
// 而证据链本来就要求「一条假设验证完再下一条」。
func (reversePack) Budget() Budget {
	return Budget{
		MaxTokens:    1_500_000,
		MaxWall:      3 * time.Hour,
		MaxToolCalls: 150,
		MaxDepth:     2, // 只允许 Lead → Specialist 一层，禁止无限派生
		MaxParallel:  1,
	}
}

func (reversePack) Scheduler() SchedulerKind { return ScheduleEvidence }
func (reversePack) Verifier() Verifier       { return reverseVerifier{} }

// WorkerIsLead：逆向的 lead 是 worker。任务是「长时程串行 + 分支递归」，worker 领到的
// 是「验证一条假设」这类意图，它同时负责定路线、派 analyst、维护证据链 —— 与 CTF 同构，
// 而不是渗透那种 planner 派意图 / worker 只执行的分工。
func (reversePack) WorkerIsLead() bool { return true }
