package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jintilm/praetor/agent/domain"
	"github.com/jintilm/praetor/db"
	actool "github.com/jintilm/praetor/internal/norma/tool"
)

// reEvidence 是逆向域的**唯一结论出口**。
//
// 设计意图（执行文档 P3-4）：结论不是"写进正文就算"，必须落成证据节点，
// 并由领域自己的 `reverseVerifier` 判定"能不能复核"。判定规则是**代码**，不是提示词：
//
//	有 SHA256 + Ref（可复核）
//	且 至少有「交叉引用数 xref_count > 0」或「动态 trace 引用 trace_ref」
//	否则只能算推测。
//
// 为什么即使不通过也要落库：模型说过什么必须留痕（便于人复盘"它当时凭什么这么判断"），
// 但 state 会标成 inferred，且返回值明确告诉它"这条不计成果"。这样一来，
// 模型既不能靠措辞蒙混，也不会因为一次不合格就丢掉全部上下文。
func (t *ToolSet) reEvidence() actool.CoreTool {
	return t.writeExpTool("re_evidence",
		"提交一条**可复核的逆向结论**（这是逆向域唯一的下结论出口；只写正文不算数）。\n"+
			"必须给出：claim（结论）、ref（证据引用：样本/伪代码/trace 文件路径，或可复现的命令）、"+
			"以及**至少一项支撑**——xref_count（静态交叉引用数）或 trace_ref（动态 trace 的文件/命令）。\n"+
			"返回里 chain_ok 表示证据链是否成立：false 时 reason 会说明缺什么（例如「结论无交叉引用也无动态 trace 支撑」），"+
			"此时结论只按「推测」记录，**不计成果**。不要为了让它变 true 而编造 xref/trace——"+
			"那等于伪造证据，比不写更糟。\n"+
			"典型用法：验证完一个函数（有反汇编地址/调用方）或跑完一次动态跟踪后，把结论连同依据一起提交。",
		obj(map[string]any{
			"claim":      str("你要下的结论（一句话，可复核的事实，不要写推测性措辞）"),
			"ref":        str("证据引用：样本路径 / 伪代码文件 / trace 文件 / 可复现的具体命令"),
			"xref_count": intp("静态交叉引用数量（有几个调用方/引用方；没有就留 0）"),
			"trace_ref":  str("动态 trace 的引用（gdb 日志路径、strace 输出文件、或产生 trace 的命令）"),
			"confidence": str("observed（证据里直接看到）| inferred（据现象推断）。默认 observed"),
			"intent_id":  idp("产生本结论的意图 id（可选，建议填，便于把结论挂到探索链上）"),
		}, "claim", "ref"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Claim      string `json:"claim"`
				Ref        string `json:"ref"`
				XRefCount  int    `json:"xref_count"`
				TraceRef   string `json:"trace_ref"`
				Confidence string `json:"confidence"`
				IntentID   int64  `json:"intent_id"`
			}
			_ = json.Unmarshal(in, &a)

			in2, err := normalizeEvidenceInput(a.Claim, a.Ref)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}

			// 交叉引用数不能为负：负数一律当 0（宁可判推测，也不让脏数据过关）
			xref := a.XRefCount
			if xref < 0 {
				xref = 0
			}
			traceRef := strings.TrimSpace(a.TraceRef)

			sha, hashedFrom := hashEvidenceRef(in2.Ref)

			// 用**领域自己的判定器**，不在这里重写规则：规则只有一份，
			// 否则出现"工具说通过、Verifier 说不过"的分裂。
			pack, ok := domain.Get(domain.Reverse)
			if !ok {
				return actool.Errorf("逆向域未注册，无法判定证据链（这是装配问题，请检查 domain 注册）"), nil
			}
			ev := domain.Evidence{
				Kind:    "analysis_report",
				Summary: in2.Claim,
				Ref:     in2.Ref,
				SHA256:  sha,
				Meta:    map[string]any{"xref_count": xref, "trace_ref": traceRef},
			}
			verdict, err := pack.Verifier().Verify(ctx, ev)
			if err != nil {
				return actool.Errorf("证据链判定出错：" + err.Error()), nil
			}

			confidence := strings.ToLower(strings.TrimSpace(a.Confidence))
			if confidence == "" {
				confidence = "observed"
			}
			// 状态跟着判定走：判定不通过就不允许标 confirmed，避免图谱里出现"已确认的推测"。
			state := "inferred"
			if verdict.Done {
				state = "confirmed"
			}

			payload := map[string]any{
				"claim":         in2.Claim,
				"ref":           in2.Ref,
				"sha256":        sha,
				"sha256_source": hashedFrom,
				"xref_count":    xref,
				"trace_ref":     traceRef,
				"confidence":    confidence,
				"chain_ok":      verdict.Done,
				"reason":        verdict.Reason,
				"verifier":      pack.Verifier().Name(),
			}
			id, werr := t.ts.AddNode(db.KindEvidence, payload, 5, state, t.worker, nil)
			if werr != nil {
				return actool.Errorf("写入证据节点失败：" + werr.Error()), nil
			}
			if a.IntentID > 0 {
				_ = t.ts.Link(a.IntentID, db.RelYields, id)
			}
			t.writes.Evidence++

			out := map[string]any{
				"id":            id,
				"chain_ok":      verdict.Done,
				"reason":        verdict.Reason,
				"sha256":        sha,
				"sha256_source": hashedFrom,
				"state":         state,
			}
			if !verdict.Done {
				out["hint"] = "证据链未通过：结论已按「推测」记录，不计成果。补交叉引用或动态 trace 后重新提交。"
			}
			return jsonResult(out)
		})
}

// evidenceInput 是规范化后的输入。
type evidenceInput struct {
	Claim string
	Ref   string
}

// normalizeEvidenceInput 校验必填项。
//
// 抽成纯函数是为了可测：这两个字段是 Verifier 判定的前提（缺一直接拒），
// 而提示词写多清楚都不如工具里硬校验可靠。
func normalizeEvidenceInput(claim, ref string) (evidenceInput, error) {
	claim = strings.TrimSpace(claim)
	ref = strings.TrimSpace(ref)
	if claim == "" {
		return evidenceInput{}, fmt.Errorf("claim 必填：写你要下的结论（一句话）")
	}
	if len([]rune(claim)) > 500 {
		return evidenceInput{}, fmt.Errorf("claim 过长（%d 字）：结论要一句话，细节放 ref 指向的文件里", len([]rune(claim)))
	}
	if ref == "" {
		return evidenceInput{}, fmt.Errorf("ref 必填：给出证据引用（样本路径 / 伪代码文件 / trace 文件 / 可复现命令）")
	}
	return evidenceInput{Claim: claim, Ref: ref}, nil
}

// hashEvidenceRef 计算证据哈希。
//
// 优先对**文件内容**做哈希（可复核性最强）；ref 不是文件时退化为对 ref 字符串本身做哈希，
// 并通过返回值说明来源，避免把"命令字符串的哈希"误当成"样本哈希"。
func hashEvidenceRef(ref string) (sha, from string) {
	if fi, err := os.Stat(ref); err == nil && !fi.IsDir() && fi.Size() <= 512<<20 {
		f, err := os.Open(ref)
		if err == nil {
			defer f.Close()
			h := sha256.New()
			if _, err := io.Copy(h, f); err == nil {
				return hex.EncodeToString(h.Sum(nil)), "file_content"
			}
		}
	}
	sum := sha256.Sum256([]byte(ref))
	return hex.EncodeToString(sum[:]), "ref_string"
}
