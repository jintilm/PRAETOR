package domain

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// 本文件的四个 Verifier 是「非 LLM 确定性验收」的最小可用实现。
// 原则：拿不到可复核证据的结论一律不判 Done——宁可漏报，不可误报。
// 生产期各域应各自加强（渗透接流量重放、CTF 接 CTFd 判题 API、红队接目标状态断言）。

type pentestVerifier struct{}

func (pentestVerifier) Name() string { return "pentest/poc-replay" }

func (pentestVerifier) Verify(_ context.Context, ev Evidence) (Verdict, error) {
	if ev.SHA256 == "" {
		return Verdict{Reason: "缺少证据哈希，无法复核"}, nil
	}
	if !ev.Reproduced {
		return Verdict{Reason: "PoC 未经独立重放，暂记为疑似"}, nil
	}
	if tid, _ := ev.Meta["traffic_id"].(string); tid == "" {
		return Verdict{Reason: "未绑定流量记录（bind_finding_traffic），证据链不完整"}, nil
	}
	return Verdict{Done: true, Reason: "PoC 可重放且已绑定流量"}, nil
}

type redTeamVerifier struct{}

func (redTeamVerifier) Name() string { return "redteam/objective-cleanup" }

func (redTeamVerifier) Verify(_ context.Context, ev Evidence) (Verdict, error) {
	if met, _ := ev.Meta["objective_met"].(bool); !met {
		return Verdict{Reason: "战役目标未达成"}, nil
	}
	// 红队与渗透的关键区别：达成就行是错的，必须证明清理干净。
	if done, _ := ev.Meta["cleanup_done"].(bool); !done {
		return Verdict{Reason: "目标已达成但 cleanup 未完成，禁止判定收尾"}, nil
	}
	return Verdict{Done: true, Reason: "目标达成且清理完成"}, nil
}

var flagPattern = regexp.MustCompile(`^[A-Za-z0-9_]{2,32}\{[^\r\n{}]{1,256}\}$`)

type ctfVerifier struct{}

func (ctfVerifier) Name() string { return "ctf/flag-arbitration" }

func (ctfVerifier) Verify(_ context.Context, ev Evidence) (Verdict, error) {
	flag, _ := ev.Meta["flag"].(string)
	if !flagPattern.MatchString(strings.TrimSpace(flag)) {
		return Verdict{Reason: "flag 格式不合法"}, nil
	}
	if accepted, ok := ev.Meta["accepted"].(bool); ok && !accepted {
		return Verdict{Reason: "flag 被平台判为错误"}, nil
	}
	if _, ok := ev.Meta["accepted"]; !ok {
		return Verdict{Reason: "未经平台判题（accepted 缺失），不得计分"}, nil
	}
	return Verdict{Done: true, Reason: "flag 已通过平台判题"}, nil
}

type reverseVerifier struct{}

func (reverseVerifier) Name() string { return "reverse/evidence-chain" }

func (reverseVerifier) Verify(_ context.Context, ev Evidence) (Verdict, error) {
	if ev.SHA256 == "" || ev.Ref == "" {
		return Verdict{Reason: "缺少样本/产物引用或哈希，不可复核"}, nil
	}
	// 逆向结论必须至少有「静态交叉引用」或「动态 trace」之一作为支撑，
	// 否则就是模型看图说话。
	static, _ := ev.Meta["xref_count"].(int)
	dynamic, _ := ev.Meta["trace_ref"].(string)
	if static == 0 && dynamic == "" {
		return Verdict{Reason: "结论无交叉引用也无动态 trace 支撑"}, nil
	}
	return Verdict{Done: true, Reason: fmt.Sprintf("证据链完整（xref=%d, 有动态trace=%v）", static, dynamic != "")}, nil
}
