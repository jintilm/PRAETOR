package agent

import (
	"context"
	"io"

	"github.com/jintilm/praetor/db"
)

// FindingRecorder is injected by the host; agents never synthesize or copy
// evidence bodies themselves. Its implementation owns the atomic write.
type FindingRecorder interface {
	Record(context.Context, db.RecordFindingInput, []db.TrafficRef) (*db.RecordedFinding, error)
}

// FindingAttachmentRecorder is the host-owned binary evidence boundary. Agent
// tools pass a verified local file here; the host writes the content-addressed
// blob and the finding_attachments row atomically.
type FindingAttachmentRecorder interface {
	AddAttachment(context.Context, db.FindingAttachmentInput, io.Reader) (*db.FindingAttachment, error)
}

// Tool-use guidance is appended without replacing the user's editable prompt.
// It does not require capture or claim that unavailable traffic tools exist.
const findingTrafficGuidance = "\n\n**漏洞流量证据（可选）**：调用 report_finding 上报漏洞时，如有已查看并确认支持漏洞结论的 HTTP 请求/响应，可用 traffic_refs 按复现顺序绑定真实 ID；域名和时间只作候选筛选，不推定关联。TCP 等非 HTTP 漏洞、未采集或无确切匹配时省略或传 []，在 evidence 保留命令输出、日志等其他可验证证据，建议说明未绑定原因。不要猜测 ID，也不要仅为补包重复探测。绑定成功后服务端会自动重放一次做确定性验证（不依赖模型判断），你也可以主动调 verify_finding 复查；结论为 suspected 时读 reasons 判断是已修复/被拦截还是证据过期，不要为让它变绿而反复重放同一请求。**报告只声明了漏洞存在，危害是另一件事**：随后用 record_impact 把从目标抠出来的东西（读到的库表行数 / 回显里的指纹 / 内网端点或回连源 IP / 受害者私有字段 / 落地 URL 的执行回显 / 被破坏的业务不变量）结构化落库；`record_impact` 返回的 gaps 会告诉你离 2 级还差什么。只有结论、没有提取物的漏洞，在审核环节会被判「危害不足」。**取证优先用 http_probe**：它走记录代理、发送前校验任务范围，采集成功时返回精确关联的 traffic_id（绑定并核对后作 artifact）；缺少关联时保留原始流量供人工复核，compare 给相似度与状态差异、timing 给耗时分布。curl 只在两处用：探索阶段探路，以及目标只能靠容器名/内网名解析时（宿主进程解析不到这类名字）。已经用 curl 发出的请求，用 traffic_search 按 host+path 找回本次请求的 ID 再绑定，不要靠猜。**越权类先做确定性差分**：用 register_identity 登记两个不同身份（A 要带私有 canary），再用 identity_diff 请求同一对象——三次请求由程序判 confirmed/rejected/inconclusive，别用「两边都能打开」当越权。"

func (t *ToolSet) SetFindingRecorder(r FindingRecorder)   { t.findingRecorder = r }
func (w *Worker) SetFindingRecorder(r FindingRecorder)    { w.findingRecorder = r }
func (p *Planner) SetFindingRecorder(r FindingRecorder)   { p.findingRecorder = r }
func (m *MainAgent) SetFindingRecorder(r FindingRecorder) { m.findingRecorder = r }

func (t *ToolSet) SetAttachmentRecorder(r FindingAttachmentRecorder) { t.attachmentRecorder = r }
func (w *Worker) SetAttachmentRecorder(r FindingAttachmentRecorder)  { w.attachmentRecorder = r }
func (p *Planner) SetAttachmentRecorder(r FindingAttachmentRecorder) { p.attachmentRecorder = r }
func (m *MainAgent) SetAttachmentRecorder(r FindingAttachmentRecorder) {
	m.attachmentRecorder = r
}
