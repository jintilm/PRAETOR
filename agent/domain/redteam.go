package domain

import "time"

// 红队域：与渗透的最大区别是【阶段 DAG + 必须清理】。
//
// 铁律：不自研 C2、不自研 implant。Agent 只做「编排 + 决策 + 留证」，
// 执行一律交给成熟开源件（Sliver / Mythic / Caldera / NetExec / BloodHound），
// 且只允许在隔离靶场（GOAD 类）内落地持久化行为。
func init() { Register(redTeamPack{}) }

type redTeamPack struct{}

func (redTeamPack) Key() Key      { return RedTeam }
func (redTeamPack) Title() string { return "红队 / 对手模拟" }

func (redTeamPack) Prompt() []string {
	return []string{
		"你是红队战役的规划者，不是打手。你的产出是「战役 DAG + 每步证据 + 清理记录」。",
		"阶段按 ATT&CK 战术顺序推进（侦察→初始访问→执行→持久化→提权→横向→收集→外传），前置未满足不得下发下一步。",
		"任何持久化/后门行为只允许在隔离靶场内进行；任务结束必须清理干净并留下清理证据。",
	}
}

func (redTeamPack) Roles() []RoleSpec {
	return []RoleSpec{
		{
			Key:         "campaign-lead",
			Kind:        RoleLead,
			Description: "编排 ATT&CK 阶段的战役 DAG，按前置依赖逐步下发，负责最终 cleanup 收尾",
			PromptSection: "先读 BloodHound 攻击路径与侦察事实，产出带前置依赖的 todolist；" +
				"每轮只下发「前置已完成」的下一步。战役结束前必须下发 cleanup 并核验结果。",
			ToolKeys: []string{
				"READ_GRAPH", "add_intent", "add_hint", "list_facts",
				"bloodhound_shortest_path", "caldera_operation_status",
			},
			MaxTurns: 20,
		},
		{
			Key:           "recon-operator",
			Kind:          RoleSpecialist,
			Description:   "资产与身份面侦察：存活、端口、服务、域内用户与信任关系",
			ToolKeys:      []string{"Bash", "nmap_scan", "netexec_smb", "netexec_ldap", "bloodhound_collect"},
			MaxTurns:      30,
			PromptSection: "只做侦察，不碰利用。产出事实要带来源（命令 + 输出摘要）。",
		},
		{
			Key:           "access-operator",
			Kind:          RoleSpecialist,
			Description:   "初始访问与凭据获取（钓鱼/弱口令/已知漏洞利用）",
			ToolKeys:      []string{"Bash", "metasploit_run", "netexec_spray", "hydra_run"},
			MaxTurns:      30,
			PromptSection: "优先低噪声路径；任何可能导致服务不可用的利用必须先停下请求审批。",
		},
		{
			Key:           "lateral-operator",
			Kind:          RoleSpecialist,
			Description:   "横向移动与提权（SMB/WinRM/WMI/委派/ACL 滥用）",
			ToolKeys:      []string{"Bash", "netexec_smb", "netexec_winrm", "netexec_wmi", "sliver_session"},
			MaxTurns:      30,
			PromptSection: "每步横向都要记录「从哪台到哪台、用什么凭据、留下什么痕迹」。",
		},
		{
			Key:           "c2-operator",
			Kind:          RoleSpecialist,
			Description:   "C2 会话管理与载荷投递（仅限隔离靶场）",
			ToolKeys:      []string{"sliver_session", "sliver_implant_build", "mythic_task"},
			MaxTurns:      20,
			PromptSection: "靶场以外一律拒绝下发载荷。每次投递都要登记 artifact（哈希 + 落地路径）。",
		},
		{
			Key:         "cleanup-operator",
			Kind:        RoleSpecialist,
			Description: "战役收尾：清理落地物、关闭监听、删除临时账号、核验无残留",
			ToolKeys:    []string{"Bash", "sliver_session", "netexec_smb"},
			MaxTurns:    20,
			PromptSection: "逐项核对战役期间创建的所有实体（文件/服务/账号/计划任务/监听），" +
				"清理后重新枚举一次证明无残留，输出 cleanup_done 与证据。",
		},
	}
}

func (redTeamPack) Tools() []string {
	return []string{"add_intent", "add_hint", "list_facts", "record_fact", "add_finding"}
}

func (redTeamPack) MCP() []MCPRef {
	return []MCPRef{
		{Name: "sliver", Transport: "http", URL: "https://127.0.0.1:31337", LocalOnly: true, Allowed: []string{"session", "implant", "job"}},
		{Name: "caldera", Transport: "http", URL: "http://127.0.0.1:8888", LocalOnly: true},
		{Name: "bloodhound", Transport: "stdio", Command: "bloodhound-mcp", LocalOnly: true},
		{Name: "netexec", Transport: "stdio", Command: "nxc-mcp", LocalOnly: true},
	}
}

func (redTeamPack) Skills() []string { return []string{"atomic-red-team", "ad-attack-paths"} }

func (redTeamPack) Policy() PolicySpec {
	return PolicySpec{
		ScopeRequired:   true,
		CleanupRequired: true,
		Rules: []PolicyRule{
			{Match: "sliver_implant_build", Action: ActionAsk, Reason: "载荷构建具有双用途风险"},
			{Match: "sliver_implant_deploy", Action: ActionAsk, Reason: "落地 implant 必须人工确认目标为靶场"},
			{Match: "persistence.*", Action: ActionAsk, Reason: "持久化会改变目标状态"},
			{Match: "artifact.exfil", Action: ActionDeny, Reason: "禁止把目标数据传出环境"},
			{Match: "msf_run", Action: ActionAsk, Reason: "利用模块可能打崩服务"},
		},
	}
}

func (redTeamPack) Graph() GraphSpec {
	return GraphSpec{
		NodeKinds: []string{"goal", "intent", "fact", "finding", "hint", "campaign", "phase", "objective"},
		EdgeKinds: []string{"spawns", "derived_from", "yields", "proves", "requires", "fulfills", "cleans_up"},
	}
}

func (redTeamPack) Artifacts() []ArtifactKind {
	return []ArtifactKind{
		{Key: "session_log", Description: "C2 会话与命令记录", Sensitive: true, LocalOnly: true, MaxBytes: 16 << 20},
		{Key: "implant", Description: "载荷样本（哈希索引，禁止外传）", Sensitive: true, LocalOnly: true, MaxBytes: 32 << 20},
		{Key: "cleanup_report", Description: "清理清单与无残留核验", MaxBytes: 1 << 20},
	}
}

func (redTeamPack) Model() ModelPolicy {
	return ModelPolicy{
		Tier:        TierCloud,
		Reason:      "战役规划依赖长程依赖推理与域知识，走云 API；涉密靶场数据先在本地脱敏",
		PreferLarge: true,
	}
}

func (redTeamPack) Budget() Budget {
	return Budget{
		MaxTokens:    5_000_000,
		MaxWall:      8 * time.Hour,
		MaxToolCalls: 1500,
		MaxDepth:     2,
		MaxParallel:  3, // 战役有依赖，并发天然低于渗透
	}
}

func (redTeamPack) Scheduler() SchedulerKind { return ScheduleCampaign }
func (redTeamPack) Verifier() Verifier       { return redTeamVerifier{} }
