package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/jintilm/praetor/agent"
	"github.com/jintilm/praetor/db"
	"github.com/jintilm/praetor/evidence"
	"github.com/jintilm/praetor/internal/replay"
	"github.com/jintilm/praetor/traffic"
)

// findingEvidence 是验证器需要的最小证据能力（*evidence.Store 天然满足）。
// 抽成接口是为了让「无 PG、无磁盘」也能单测状态机与证据挑选逻辑。
type findingEvidence interface {
	GetFindingTraffic(ctx context.Context, findingID int64) (*db.FindingTraffic, error)
	OpenBody(snapshot db.TrafficEvidenceSnapshot, side string) (*os.File, int64, error)
	// RecordFindingVerification 以「读取时的 evidence_version」做 CAS；stale=true 表示没落库。
	RecordFindingVerification(ctx context.Context, findingID, evidenceVersion int64, engine, state string, similarity float64, note string, bindingID int64) (bool, error)
}

type vulnKnowledgeIngestor interface {
	UpsertVulnKnowledgeFromFinding(ctx context.Context, findingID int64) (int64, error)
}

// replayVerifier 是 agent.FindingVerifier 的生产实现：重放绑定的证据并落库结论。
//
// rt 传 nil 表示直连目标；要保留复现流量的话传走记录代理的 Transport（后续接）。
type replayVerifier struct {
	ev    findingEvidence
	rt    http.RoundTripper
	scope ScopeFunc // nil = 不做范围校验（仅测试与兼容路径）
	// 重放产生的流量同样要归属到任务：取证链后续要用「本任务的流量」而不是猜 ID。
	traffic *traffic.Traffic
	store   *db.DB
	taskID  int64
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
		return v.persist(ctx, tr, &agent.FindingVerifyResult{
			FindingID: findingID, State: db.VerificationSuspected,
			Reasons: []string{why},
		}, db.VerificationSuspected, -1, why)
	}

	// 范围校验必须在发请求之前：重放的目标 URL 来自历史证据，
	// 而验证器走的是宿主进程的出网链路，不受 worker 那套 scope/审批门约束。
	if v.scope != nil {
		if serr := v.scope(binding.Snapshot.URL); serr != nil {
			note := "拒绝重放：" + serr.Error()
			log.Printf("[verify] finding %d 重放被范围校验拒绝: %v", findingID, serr)
			return v.persist(ctx, tr, &agent.FindingVerifyResult{
				FindingID: findingID, BindingID: binding.ID, State: db.VerificationSuspected,
				Reasons: []string{note},
			}, db.VerificationSuspected, -1, note)
		}
	}

	capture := &capturedTransport{traffic: v.traffic, base: v.rt}
	verdict, verr := agent.VerifyBinding(ctx, v.ev, binding.Snapshot, capture, replay.Options{MinSimilarity: minSimilarity})
	if verr != nil {
		note := "重放失败：" + verr.Error()
		return v.persist(ctx, tr, &agent.FindingVerifyResult{
			FindingID: findingID, BindingID: binding.ID, State: db.VerificationSuspected,
			Reasons: []string{note},
		}, db.VerificationSuspected, -1, note)
	}

	// 请求真的发出去了（verr==nil），就把这次重放记进任务流量归属。
	// 与结论无关：即使没复现成功，这条流量也是本任务产生的。
	v.recordTraffic(ctx, capture.meta)
	if capture.meta.ID == "" {
		verdict.Reasons = append(verdict.Reasons, "重放已完成，但未取得采集侧精确回执，重放流量暂未归属；原始绑定与验证记录仍保留")
	}

	state := db.VerificationSuspected
	if verdict.Reproduced {
		state = db.VerificationVerified
	}
	res, err := v.persist(ctx, tr, &agent.FindingVerifyResult{
		FindingID: findingID, BindingID: binding.ID, State: state,
		Reproduced: verdict.Reproduced, Status: verdict.Status,
		Similarity: verdict.Similarity, LenRatio: verdict.LenRatio,
		Reasons: verdict.Reasons,
	}, state, verdict.Similarity, verdict.Explain())
	if err != nil {
		return nil, err
	}
	// 只有真正落库成 verified 才沉淀知识；stale 时那次结论对应的是旧证据，不能拿去喂知识库。
	if state == db.VerificationVerified && res.State == db.VerificationVerified {
		if ing, ok := v.ev.(vulnKnowledgeIngestor); ok {
			if _, ingestErr := ing.UpsertVulnKnowledgeFromFinding(ctx, findingID); ingestErr != nil {
				// Verification is already persisted; knowledge extraction is best-effort
				// and must not turn a successful replay into a failed verification.
				log.Printf("[vuln-kb] finding %d 生成候选知识失败: %v", findingID, ingestErr)
			}
		}
	}
	return res, nil
}

// persist 用「读取时的证据版本」做 CAS 写入，并把 stale 折成结果态。
//
// 为什么必须有这一步：读证据 → 重放 → 写结论之间可能隔着几秒到几十秒，
// 期间用户完全可能改绑定（evidence_version +1）。不带版本的写入会把
// 「旧证据的结论」贴到「新证据」上，而 UI 会显示成 verified —— 那是最坏的一种假阳性。
func (v *replayVerifier) persist(ctx context.Context, tr *db.FindingTraffic, res *agent.FindingVerifyResult, state string, similarity float64, note string) (*agent.FindingVerifyResult, error) {
	var version int64
	if tr != nil {
		version = tr.Version
	}
	stale, err := v.ev.RecordFindingVerification(ctx, res.FindingID, version, "replay", state, similarity, note, res.BindingID)
	if err != nil {
		return nil, fmt.Errorf("写入验证结论失败: %w", err)
	}
	if stale {
		res.State = db.VerificationStale
		res.Reproduced = false
		res.Reasons = append(res.Reasons, fmt.Sprintf("验证期间证据已变更（本次基于 evidence_version=%d），结论未落库，请重跑 verify_finding", version))
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

func (a evidenceAdapter) RecordFindingVerification(ctx context.Context, findingID, evidenceVersion int64, engine, state string, similarity float64, note string, bindingID int64) (bool, error) {
	return a.s.DB.RecordFindingVerification(ctx, findingID, evidenceVersion, engine, state, similarity, note, bindingID)
}

func (a evidenceAdapter) UpsertVulnKnowledgeFromFinding(ctx context.Context, findingID int64) (int64, error) {
	return a.s.DB.UpsertVulnKnowledgeFromFinding(ctx, findingID)
}

// NewEvidenceVerifier 用 evidence.Store 构造验证器（生产入口）。
func NewEvidenceVerifier(store *evidence.Store, rt http.RoundTripper) agent.FindingVerifier {
	if store == nil {
		return nil
	}
	return &replayVerifier{ev: evidenceAdapter{s: store}, rt: rt}
}

// NewTaskEvidenceVerifier 是**任务级**生产入口：证据 + 记录代理 + 任务范围。
//
// 与 NewEvidenceVerifier 的区别只在两处，但这两处决定了「验证」是否能作为证据：
//   - rt 走记录代理：复现流量同样进流量库，UI 能看到、报告能贴；
//   - scope 校验：重放前确认目标仍在任务授权范围内。
func NewTaskEvidenceVerifier(store *evidence.Store, proxyAddr, caCertPath string, scope ScopeFunc, tr *traffic.Traffic, dbStore *db.DB, taskID int64) agent.FindingVerifier {
	if store == nil {
		return nil
	}
	return &replayVerifier{
		ev:      evidenceAdapter{s: store},
		rt:      replayTransport(proxyAddr, caCertPath),
		traffic: tr,
		store:   dbStore,
		taskID:  taskID,
		scope:   scope,
	}
}

// recordTraffic 把本次重放的请求记进 task_traffic（source=replay）。
//
// 与 http_probe 同一条规矩：只在流量索引里对上 id 才写；写失败只记日志——
// 归属是辅助信息，不能让它把一次已验证的重放变成失败。
func (v *replayVerifier) recordTraffic(ctx context.Context, meta traffic.ExchangeMeta) {
	if v == nil || v.store == nil || v.taskID <= 0 || meta.ID == "" {
		return
	}
	if err := v.store.RecordTaskTraffic(ctx, db.TaskTraffic{
		TaskID: v.taskID, TrafficID: meta.ID, Host: meta.Host, Method: meta.Method,
		URL: meta.URL, Status: meta.Status, Source: db.TaskTrafficReplay, AttributionKind: db.TaskTrafficCaptured,
	}); err != nil {
		log.Printf("[traffic] 记录任务 %d 的重放流量归属失败（%s）: %v", v.taskID, meta.ID, err)
	}
}
