package server

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/jintilm/praetor/agent"
	"github.com/jintilm/praetor/db"
)

// autoVerifyTimeout 是单次自动复验的墙钟上限。重放一条请求通常在秒级，
// 给到 90s 是为了容纳慢目标；再长就该由模型手动 verify_finding 了。
const autoVerifyTimeout = 90 * time.Second

// autoVerifyingRecorder 在漏洞落库后自动跑一次确定性复验。
//
// 为什么必须自动：verify_finding 是模型可选调用的工具，实测它经常在"漏洞已登记、
// 还有下一个方向"时直接跳过，于是证据链停在 unverified，验收时被判没证据。
// 复验本身是程序判定、不依赖模型，没有理由等单位模型想起来。
//
// 失败一律吞掉：自动化的附加动作不该把一次成功的上报变成失败。
type autoVerifyingRecorder struct {
	inner    agent.FindingRecorder
	verifier agent.FindingVerifier
	taskID   int64
	busy     *sync.Map // 每任务一个信号量，避免同任务并发复验刷爆目标
}

func newAutoVerifyingRecorder(inner agent.FindingRecorder, verifier agent.FindingVerifier, taskID int64, busy *sync.Map) agent.FindingRecorder {
	if inner == nil || verifier == nil || taskID <= 0 {
		return inner
	}
	return &autoVerifyingRecorder{inner: inner, verifier: verifier, taskID: taskID, busy: busy}
}

func (r *autoVerifyingRecorder) Record(ctx context.Context, in db.RecordFindingInput, refs []db.TrafficRef) (*db.RecordedFinding, error) {
	out, err := r.inner.Record(ctx, in, refs)
	if err != nil || out == nil {
		return out, err
	}
	// 没有绑定流量就没有可重放的东西，复验必然落 suspected，先不跑。
	if out.Traffic == nil || len(out.Traffic.Bindings) == 0 {
		return out, nil
	}
	r.schedule(out.FindingID)
	return out, nil
}

func (r *autoVerifyingRecorder) schedule(findingID int64) {
	if r.busy == nil {
		return
	}
	v, loaded := r.busy.LoadOrStore(r.taskID, make(chan struct{}, 1))
	sem := v.(chan struct{})
	_ = loaded
	select {
	case sem <- struct{}{}:
	default:
		log.Printf("[verify] finding %d 自动复验跳过：同任务已有复验在跑（手动 verify_finding 仍可用）", findingID)
		return
	}
	go func() {
		defer func() { <-sem }()
		// 与上报请求解绑：上报已经返回，worker 的 ctx 随时会被取消。
		ctx, cancel := context.WithTimeout(context.Background(), autoVerifyTimeout)
		defer cancel()
		res, err := r.verifier.VerifyFinding(ctx, findingID, 0, 0)
		if err != nil {
			log.Printf("[verify] finding %d 自动复验失败: %v", findingID, err)
			return
		}
		if res == nil {
			return
		}
		log.Printf("[verify] finding %d 自动复验结论: %s", findingID, res.State)
	}()
}
