package server

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/jintilm/praetor/agent"
	"github.com/jintilm/praetor/db"
	"github.com/jintilm/praetor/evidence"
	"github.com/jintilm/praetor/internal/replay"
)

// findingEvidence 是验证器需要的最小证据能力（*evidence.Store 天然满足）。
// 抽成接口是为了让「无 PG、无磁盘」也能单测状态机与证据挑选逻辑。
type findingEvidence interface {
	GetFindingTraffic(ctx context.Context, findingID int64) (*db.FindingTraffic, error)
	OpenBody(snapshot db.TrafficEvidenceSnapshot, side string) (*os.File, int64, error)
	SetFindingVerification(ctx context.Context, findingID int64, state string, similarity float64, note string) (int64, error)
}

// replayVerifier 是 agent.FindingVerifier 的生产实现：重放绑定的证据并落库结论。
//
// rt 传 nil 表示直连目标；要保留复现流量的话传走记录代理的 Transport（后续接）。
type replayVerifier struct {
	ev findingEvidence
	rt http.RoundTripper
}

// NewReplayVerifier 构造验证器。
func NewReplayVerifier(ev findingEvidence, rt http.RoundTripper) agent.FindingVerifier {
	return &replayVerifier{ev: ev, rt: rt}
}

func (v *replayVerifier) VerifyFinding(ctx context.Context, findingID, bindingID int64, minSimilarity float64) (*agent.FindingVerifyResult, error) {
	if v == nil || v.ev == nil {
		return nil, fmt.Errorf("证据存储未就绪")
	}

	tr, err := v.ev.GetFindingTraffic(ctx, findingID)
	if err != nil {
		return nil, fmt.Errorf("读取漏洞证据失败: %w", err)
	}
	binding, why := pickBinding(tr, bindingID)
	if binding == nil {
		// 没有可重放的证据：落 suspected，而不是报错——「证据不足」本身就是结论。
		res := &agent.FindingVerifyResult{
			FindingID: findingID, State: db.VerificationSuspected,
			Reasons: []string{why},
		}
		if _, err := v.ev.SetFindingVerification(ctx, findingID, db.VerificationSuspected, -1, why); err != nil {
			return nil, fmt.Errorf("写入验证结论失败: %w", err)
		}
		return res, nil
	}

	verdict, verr := agent.VerifyBinding(ctx, v.ev, binding.Snapshot, v.rt, replay.Options{MinSimilarity: minSimilarity})
	if verr != nil {
		note := "重放失败：" + verr.Error()
		res := &agent.FindingVerifyResult{
			FindingID: findingID, BindingID: binding.ID, State: db.VerificationSuspected,
			Reasons: []string{note},
		}
		if _, err := v.ev.SetFindingVerification(ctx, findingID, db.VerificationSuspected, -1, note); err != nil {
			return nil, fmt.Errorf("写入验证结论失败: %w", err)
		}
		return res, nil
	}

	state := db.VerificationSuspected
	if verdict.Reproduced {
		state = db.VerificationVerified
	}
	res := &agent.FindingVerifyResult{
		FindingID: findingID, BindingID: binding.ID, State: state,
		Reproduced: verdict.Reproduced, Status: verdict.Status,
		Similarity: verdict.Similarity, LenRatio: verdict.LenRatio,
		Reasons: verdict.Reasons,
	}
	note := verdict.Explain()
	if _, err := v.ev.SetFindingVerification(ctx, findingID, state, verdict.Similarity, note); err != nil {
		return nil, fmt.Errorf("写入验证结论失败: %w", err)
	}
	return res, nil
}

// pickBinding 选择用于重放的那条证据。
//
// 优先级（明确 request 时直接用）：proof > verification > 最后一条。
// 之所以偏向 proof：baseline 是「正常请求」的对照，supporting 只是辅助，
// 拿它们重放得到的结论没有说服力。
func pickBinding(tr *db.FindingTraffic, wantID int64) (*db.FindingTrafficBinding, string) {
	if tr == nil || len(tr.Bindings) == 0 {
		return nil, "该漏洞没有绑定任何流量证据，无法做确定性验证"
	}
	list := tr.Bindings
	if wantID > 0 {
		for i := range list {
			if list[i].ID == wantID {
				return &list[i], ""
			}
		}
		return nil, fmt.Sprintf("指定的证据 %d 不属于该漏洞", wantID)
	}
	for _, role := range []string{"proof", "verification"} {
		for i := range list {
			if list[i].Role == role {
				return &list[i], ""
			}
		}
	}
	last := &list[len(list)-1]
	return last, ""
}

// 编译期断言：接口与实现对齐（避免改签名时静默漂移）。
var _ agent.FindingVerifier = (*replayVerifier)(nil)

// evidenceAdapter 把 *evidence.Store 适配成 findingEvidence。
//
// Store 的 DB 是具名字段（不是内嵌），所以 GetFindingTraffic / SetFindingVerification
// 不会被提升；这里显式转发，避免为「测试方便」去改 evidence 包的公开结构。
type evidenceAdapter struct{ s *evidence.Store }

func (a evidenceAdapter) GetFindingTraffic(ctx context.Context, findingID int64) (*db.FindingTraffic, error) {
	return a.s.DB.GetFindingTraffic(ctx, findingID)
}

func (a evidenceAdapter) OpenBody(snapshot db.TrafficEvidenceSnapshot, side string) (*os.File, int64, error) {
	return a.s.OpenBody(snapshot, side)
}

func (a evidenceAdapter) SetFindingVerification(ctx context.Context, findingID int64, state string, similarity float64, note string) (int64, error) {
	return a.s.DB.SetFindingVerification(ctx, findingID, state, similarity, note)
}

// NewEvidenceVerifier 用 evidence.Store 构造验证器（生产入口）。
func NewEvidenceVerifier(store *evidence.Store, rt http.RoundTripper) agent.FindingVerifier {
	if store == nil {
		return nil
	}
	return &replayVerifier{ev: evidenceAdapter{s: store}, rt: rt}
}
