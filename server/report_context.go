package server

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"time"

	"github.com/jintilm/praetor/db"
	"github.com/jintilm/praetor/report"
)

const maxInlineReportAttachmentBytes = int64(32 << 20)

// 报告模板的取数与优先级集中在这里，避免 getReport / findingsExport 各写一套。
//
// 优先级：?template= 显式覆盖（不落库） > 任务 report_template > praetor。
// 跨任务导出时每个 finding 按自己所属任务取模板，所以一份 md-zip 里可以
// 同时存在不同平台版式；只要有任何一份不是 praetor，md-single 就走模板层，
// 全 praetor 时继续调用原 FindingsMarkdown，保证存量输出字节级不变。

// resolveReportTemplate 返回 (模板, 是否显式覆盖, 错误)。
func resolveReportTemplate(q url.Values, t *Task) (report.Template, bool, error) {
	if raw := q.Get("template"); raw != "" {
		tpl, err := report.ParseTemplate(raw)
		if err != nil {
			return "", false, err
		}
		return tpl, true, nil
	}
	if t != nil {
		return report.NormalizeTemplate(t.ReportTemplate), false, nil
	}
	return report.TemplatePraetor, false, nil
}

// companyNameMap 一次查出全部企业名，避免逐条 finding 打一次库。
// 查失败返回空表即可：模板会把「厂商名称 / 漏洞单位」列进待补清单，不阻断导出。
func (s *Server) companyNameMap() map[int64]string {
	out := map[int64]string{}
	list, err := s.m.pg.Companies().ListCompanies()
	if err != nil {
		return out
	}
	for _, c := range list {
		if c == nil {
			continue
		}
		out[c.ID] = c.Name
	}
	return out
}

func companyNamesForTask(t *Task, names map[int64]string) []string {
	if t == nil {
		return nil
	}
	var out []string
	for _, id := range t.CompanyIDs {
		if name := names[id]; name != "" {
			out = append(out, name)
		}
	}
	return out
}

func (s *Server) taskByID(id *int64) *Task {
	if id == nil {
		return nil
	}
	t, ok := s.m.Task(strconv.FormatInt(*id, 10))
	if !ok {
		return nil
	}
	return t
}

func templateForTask(t *Task) report.Template {
	if t == nil {
		return report.TemplatePraetor
	}
	return report.NormalizeTemplate(t.ReportTemplate)
}

// reportViewsForFindings 把 findings 表行补上企业名、资产域名/IP 与实际模板。
// views 与 fs 同序，供 md-zip 按索引取用。
func (s *Server) reportViewsForFindings(fs []*db.DBFinding, now time.Time, override report.Template, hasOverride bool) []report.View {
	names := s.companyNameMap()
	assets := s.resolveFindingAssets(fs)
	// 授权记录按 taskID 缓存：跨任务批量导出时同任务的 finding 只查一次库。
	grants := map[int64]*db.DynamicGrant{}
	views := make([]report.View, 0, len(fs))
	for _, f := range fs {
		if f == nil {
			continue
		}
		v := report.ViewFromFinding(f, now)
		t := s.taskByID(f.TaskID)
		v = v.WithCompanies(companyNamesForTask(t, names))
		var hosts []string
		for _, aid := range f.AssetIDs {
			if a := assets[aid]; a != nil {
				hosts = append(hosts, a.RootDomain, a.Domain, a.IP, a.CSegment)
			}
		}
		v = v.WithHosts(hosts)
		id := viewTaskID(f, t)
		grant, ok := grants[id]
		if !ok {
			grant = s.grantFor(id)
			grants[id] = grant
		}
		v = v.WithMobile(s.mobileMetaWithGrant(grant, mobileMetaTexts(v)...))
		switch {
		case hasOverride:
			v.Template = override
		case t != nil:
			v.Template = templateForTask(t)
		default:
			// 归属任务已删除/归档：findings 表行仍可导出，但拿不到任务模板。
			v.Template = report.TemplatePraetor
		}
		views = append(views, v)
	}
	return views
}

// reportViewsForNodes 把任务报告 Tab 的探索图节点补成 View。
func (s *Server) reportViewsForNodes(nodes []*db.Node, t *Task, now time.Time, tpl report.Template) []report.View {
	names := s.companyNameMap()
	companies := companyNamesForTask(t, names)
	grant := s.grantFor(taskNumericID(t))
	nodeIDs := make([]int64, 0, len(nodes))
	for _, n := range nodes {
		if n != nil {
			nodeIDs = append(nodeIDs, n.ID)
		}
	}
	findingIDs, _ := s.m.pg.AttachmentFindingIDsByNodeIDs(context.Background(), nodeIDs)
	attachmentsByFinding := map[int64][]db.FindingAttachment{}
	for _, findingID := range findingIDs {
		items, err := s.m.pg.ListFindingAttachments(context.Background(), findingID)
		if err == nil {
			attachmentsByFinding[findingID] = items
		}
	}
	views := make([]report.View, 0, len(nodes))
	for _, n := range nodes {
		v := report.ViewFromNode(n, now)
		if n == nil {
			views = append(views, v)
			continue
		}
		if t != nil {
			v.TaskDescription = t.Description
		}
		v = v.WithCompanies(companies)
		v = v.WithMobile(s.mobileMetaWithGrant(grant, mobileMetaTexts(v)...))
		v.Template = tpl
		if findingID := findingIDs[n.ID]; findingID > 0 {
			for _, a := range attachmentsByFinding[findingID] {
				v.Attachments = append(v.Attachments, report.AttachmentView{
					ID: a.ID, Kind: a.Kind, Filename: a.Filename, MIMEType: a.MIMEType,
					Size: a.Size, SHA256: a.SHA256, Caption: a.Caption, Role: a.Role, Source: a.Source,
					Link: fmt.Sprintf("evidence/%d/attachments/%d-%s", findingID, a.ID, safeAttachmentZipName(a.Filename)),
				})
			}
		}
		views = append(views, v)
	}
	return views
}

func reportViewsHaveAttachments(views []report.View) bool {
	for _, v := range views {
		if len(v.Attachments) > 0 {
			return true
		}
	}
	return false
}

// inlineReportAttachments turns attachment blobs into data URIs for md-single.
// The cap is intentionally explicit: a single self-contained Markdown file must
// not silently balloon into hundreds of megabytes.
func (s *Server) inlineReportAttachments(ctx context.Context, views []report.View) error {
	var total int64
	for i := range views {
		for j := range views[i].Attachments {
			a := &views[i].Attachments[j]
			if a.SHA256 == "" {
				continue
			}
			total += a.Size
			if total > maxInlineReportAttachmentBytes {
				return errors.New("md-single 附件总量超过 32 MiB，请改用 md-zip")
			}
			f, _, err := s.evidenceStore().OpenAttachment(db.FindingAttachment{SHA256: a.SHA256, Size: a.Size})
			if err != nil {
				return err
			}
			data, readErr := io.ReadAll(io.LimitReader(f, a.Size+1))
			closeErr := f.Close()
			if err := errors.Join(readErr, closeErr); err != nil {
				return err
			}
			if int64(len(data)) != a.Size {
				return errors.New("附件正文长度不一致")
			}
			a.DataURI = "data:" + a.MIMEType + ";base64," + base64.StdEncoding.EncodeToString(data)
		}
	}
	return nil
}

func allPraetor(views []report.View, fallback report.Template) bool {
	if fallback != report.TemplatePraetor && fallback != "" {
		return false
	}
	for _, v := range views {
		if v.Template != "" && v.Template != report.TemplatePraetor {
			return false
		}
	}
	return true
}
