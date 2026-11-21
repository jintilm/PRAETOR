package oracle

import "strings"

// IdentityDiff 判定越权（BOLA）：A 名下的对象，B 用自己身份能不能读到。
//
// 主判据是 canary——A 独有的资源标记（邮箱、订单号、私有字段值），而不是整页哈希：
// 页面只要有动态元素（时间戳、CSRF token、推荐位），哈希必然不等，拿哈希做主判据
// 会把真实越权判成"不确定"。
//
// 只有 canary 缺失时才退回哈希比整页，且必须配匿名对照把"公开资源"摘出去。
// 任何一条 Confirmed 都要求 A/B 两侧都有采集侧精确归属，否则无法作为证据。
func IdentityDiff(owner, peer, anonymous Observation, canary string, distinct bool) Verdict {
	if !distinct {
		return verdict(Inconclusive, "两次请求用的是同一份身份凭据，差分无意义")
	}
	if owner.Error != "" || peer.Error != "" || anonymous.Error != "" {
		return verdict(Inconclusive, "有请求失败，差分不完整")
	}
	if !owner.ok() {
		return verdict(Inconclusive, "拥有者基线不是成功响应，无法比对")
	}
	if peer.denied() {
		return verdict(Rejected, "另一身份被访问控制明确拒绝，不存在越权")
	}
	if !peer.ok() {
		return verdict(Inconclusive, "另一身份没有拿到可比较的成功响应")
	}

	confirm := func(why string) Verdict {
		if owner.TrafficID == "" || peer.TrafficID == "" {
			return verdict(Inconclusive, why+"；但缺少采集侧精确流量归属")
		}
		return verdict(Confirmed, why)
	}

	if c := strings.TrimSpace(canary); c != "" && strings.Contains(peer.Body, c) {
		if strings.Contains(owner.Body, c) {
			return confirm("另一身份读到了拥有者独有的标记：" + c)
		}
		return verdict(Inconclusive, "另一身份读到了标记，但拥有者基线里没有它，标记可能不唯一")
	}
	if owner.Hash != peer.Hash {
		return verdict(Inconclusive, "两边响应不同；给该对象一个拥有者独有标记（canary）再判")
	}
	// 两边字节相同：要么是真越权，要么是公开资源，靠匿名对照区分。
	if anonymous.ok() && anonymous.Hash == owner.Hash {
		return verdict(Rejected, "匿名也能拿到相同内容：这是公开资源")
	}
	if anonymous.denied() {
		return confirm("两个身份拿到相同内容，且匿名被拒绝")
	}
	return verdict(Inconclusive, "匿名对照既未成功也未拒绝，无法排除公开资源")
}
