// Package oracle 是漏洞判定的纯函数层：只吃观测结果，不下网络请求。
// 三态取值刻意保守——"没打通"不等于"不存在"，所以 Inconclusive 与 Rejected 必须分开。
package oracle

import "strings"

// State 是一次判定的结论。
type State string

const (
	Confirmed    State = "confirmed"    // 漏洞成立
	Rejected     State = "rejected"     // 明确不成立（有否定证据）
	Inconclusive State = "inconclusive" // 证据不足，!= 不成立
)

// Observation 是单个身份发一次请求后的观测。Body 只用于找 canary，可以截断。
type Observation struct {
	Status    int    `json:"status"`
	Hash      string `json:"hash"`
	Body      string `json:"body,omitempty"`
	TrafficID string `json:"traffic_id,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Verdict 带判定理由，理由会原样回给模型，便于它决定补哪一条证据。
type Verdict struct {
	State  State  `json:"state"`
	Reason string `json:"reason"`
}

func verdict(s State, why string) Verdict { return Verdict{State: s, Reason: why} }

// ok 判断观测是否为可比较的成功响应。
func (o Observation) ok() bool {
	return o.Error == "" && o.Status >= 200 && o.Status < 300 && strings.TrimSpace(o.Hash) != ""
}

func (o Observation) denied() bool { return o.Status == 401 || o.Status == 403 }
