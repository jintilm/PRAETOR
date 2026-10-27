package server

import (
	"log"

	"github.com/jintilm/praetor/db"
)

// WarnEvidenceChainDisarmed 在启动期检查「证据链前置开关」是否被关掉，
// 关掉时给出醒目告警。
//
// 为什么需要这个：traffic_capture 与 agent_traffic_binding 都是**默认关**，
// 但它们是很多能力的前置条件，关着的时候**不报任何错**，表现为：
//
//	worker 无代理 env（HTTP_PROXY 等不注入）→ 请求不经 MITM → 流量索引为空
//	worker 无 traffic_* 工具（提示词里的流量段也不注入）
//	reporter 不自动绑定流量 → finding 的证据链永远是空的
//
// 即「agent 照样跑、照样报漏洞，但拿不出可复现的证据」。2026-10-27 的实战
// 就卡在这里：agent 真的测出了 SQLi/XSS，但 flow 全空、verification_state
// 停在 unverified，全程无一条错误日志指向真正原因。
//
// 这里只告警、不改配置——开关是用户在 UI 上的显式选择，代码不该替用户改。
func WarnEvidenceChainDisarmed(pg *db.DB) {
	if pg == nil {
		return
	}
	capture := pg.GetBool(settingTrafficCapture, false)
	binding := pg.GetBool(settingAgentTrafficBinding, false)

	switch {
	case !capture:
		log.Printf("[evidence] ⚠️ 流量捕获未开启（traffic_capture=false）：worker 不会走记录代理，" +
			"traffic_* 工具与流量提示词都不会注入，finding 将无法绑定可复现证据。" +
			"跑渗透任务前请在「系统 → 设置」开启流量捕获。")
	case !binding:
		// 捕获开了但自动绑定关着：流量有记录，但没人把它挂到 finding 上。
		log.Printf("[evidence] ⚠️ 流量已捕获，但漏洞↔流量自动绑定未开启（agent_traffic_binding=false）：" +
			"finding 需要人工或显式调用 bind_finding_traffic 才有证据。")
	}
}
