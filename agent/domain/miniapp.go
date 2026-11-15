package domain

import "time"

// 已发布真实小程序的授权黑盒测试。
//
// 该领域刻意不做源码、wxapkg 解包和平台保护绕过。输入是真实微信小程序、
// 测试账号、授权后端域名与 Burp 已记录流量；输出必须能回指截图或 Burp 请求。
func init() { Register(miniappPack{}) }

type miniappPack struct{}

func (miniappPack) Key() Key      { return Miniapp }
func (miniappPack) Title() string { return "小程序黑盒" }

func (miniappPack) Prompt() []string {
	return []string{
		"你是已发布微信小程序的授权黑盒测试执行者。目标是验证真实业务漏洞，而不是扫描所有可解析域名。",
		"只处理任务 Scope 内的后端域名。登录、扫码、验证码和设备解锁由操作者完成，Agent 不绕过微信平台保护或风控。",
		"以 Burp Proxy History 为默认流量来源；先同步、聚类和建立接口清单，再对测试账号执行最小必要的重放验证。",
		"每个结论必须能回到 Burp 请求/响应与页面截图，静态猜测或未复现的业务推理不得标记为 confirmed。",
	}
}

func (miniappPack) Roles() []RoleSpec {
	return []RoleSpec{
		{
			Key:         "planner",
			Kind:        RoleLead,
			Description: "按页面、账号角色和 Burp 接口规划黑盒测试，不越出授权域名",
			PromptSection: "优先让 worker 调用 miniapp_status / burp_sync 建立页面与接口基线。" +
				"围绕未授权访问、IDOR、参数篡改和业务逻辑拆分意图；不要要求源码或解包能力。" +
				"访问控制、支付、删除、短信和外发类写操作必须按安全等级拆分，不能合并成批量探测。",
			ToolKeys: []string{
				"graph_overview", "list_untested_assets", "list_facts", "list_assets", "list_companies", "list_goals",
				"add_intent", "add_hint", "add_company_scope", "add_task_scope",
				"prove_goal", "kill_work", "steer_work", "expand_digest",
				"node_detail", "get_worker_output", "search_all_worker_traces", "report_finding",
			},
			MaxTurns: 12,
			Budget:   Budget{MaxParallel: 3},
		},
		{
			Key:         "worker",
			Kind:        RoleSpecialist,
			Description: "同步 Burp 流量、记录页面证据并在授权 Scope 内验证小程序业务漏洞",
			PromptSection: "先调用 miniapp_status 确认设备、Burp 和默认授权状态，再用 burp_sync 同步最近的授权域名流量。" +
				"调用 traffic_search/traffic_get 聚类接口；需要页面证据时调用 miniapp_screenshot。" +
				"任何主动重放都使用测试账号并限速；删除、支付、短信、邀请、文件上传等写操作先请求人工确认。" +
				"不使用微信开发者工具源码、wxapkg 解包、微信进程注入或证书绑定绕过。",
			ToolKeys: []string{
				"Bash", "Read", "Write", "Edit", "Grep", "Glob", "WebFetch",
				"record_fact", "report_finding", "verify_finding", "insert_assets", "list_assets", "list_findings",
				"node_detail", "search_all_worker_traces", "get_worker_trace", "get_worker_output",
			},
			MaxTurns: 40,
			Budget:   Budget{MaxToolCalls: 120},
		},
	}
}

func (miniappPack) Tools() []string {
	return []string{
		"report_finding", "list_findings", "insert_assets", "list_assets", "list_companies",
		"add_company_scope", "add_task_scope", "record_fact", "list_untested_assets",
	}
}

func (miniappPack) MCP() []MCPRef { return nil }

func (miniappPack) Skills() []string { return nil }

func (miniappPack) Policy() PolicySpec {
	return PolicySpec{
		ScopeRequired: true,
		Rules: []PolicyRule{
			{Match: "miniapp.platform_bypass", Action: ActionDeny, Reason: "禁止绕过微信客户端、平台风控或保护机制"},
			{Match: "miniapp.cache_extract", Action: ActionDeny, Reason: "默认黑盒模式不提取微信缓存或解包小程序"},
			{Match: "miniapp.write_action", Action: ActionAsk, Reason: "支付、删除、短信、邀请、上传等写操作需人工确认"},
			{Match: "miniapp.scope_expand", Action: ActionAsk, Reason: "扩大授权后端域名必须先确认"},
		},
		MaxReqPerTarget: 120,
		AllowEgress:     []string{"task-scope", "burp-history", "recording-proxy"},
	}
}

func (miniappPack) Graph() GraphSpec {
	return GraphSpec{
		NodeKinds: []string{"goal", "intent", "fact", "finding", "hint", "miniapp_page", "miniapp_endpoint"},
		EdgeKinds: []string{"spawns", "derived_from", "yields", "proves", "observed_on", "called_by"},
	}
}

func (miniappPack) Artifacts() []ArtifactKind {
	return []ArtifactKind{
		{Key: "burp_trace", Description: "Burp Proxy History 中的请求与响应", Sensitive: true, MaxBytes: 16 << 20},
		{Key: "miniapp_screenshot", Description: "真实设备上的小程序页面截图", Sensitive: true, MaxBytes: 8 << 20},
		{Key: "miniapp_flow", Description: "页面、账号状态与接口的关联记录", Sensitive: true, MaxBytes: 2 << 20},
		{Key: "finding_report", Description: "已验证漏洞结论与复现步骤", MaxBytes: 2 << 20},
	}
}

func (miniappPack) Model() ModelPolicy {
	return ModelPolicy{Tier: TierCloud, Reason: "黑盒业务逻辑验证需要较强 HTTP 语义推理；敏感证据仍按任务策略脱敏"}
}

func (miniappPack) Budget() Budget {
	return Budget{
		MaxTokens:    2_000_000,
		MaxWall:      75 * time.Minute,
		MaxToolCalls: 500,
		MaxDepth:     1,
		MaxParallel:  3,
	}
}

func (miniappPack) Scheduler() SchedulerKind { return ScheduleExplore }
func (miniappPack) Verifier() Verifier       { return miniappVerifier{} }
