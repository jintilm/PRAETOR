package server

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jintilm/praetor/db"
	"github.com/jintilm/praetor/evidence"
	"github.com/jintilm/praetor/report"
)

func writeFindingsEvidenceZip(out io.Writer, findings []*db.DBFinding, stage string, now time.Time) error {
	return writeFindingsEvidenceZipWithTemplates(out, findings, nil, stage, now)
}

// writeFindingsEvidenceZipWithTemplates 是带报告模板的导出版本；views 为空时
// 行为与旧版完全一致（全 praetor 单条渲染，不生成提交清单）。
func writeFindingsEvidenceZipWithTemplates(out io.Writer, findings []*db.DBFinding, views []report.View, stage string, now time.Time) error {
	zw := zip.NewWriter(out)
	if err := writeFindingsZipEntriesWithTemplates(zw, findings, views, stage, now); err != nil {
		zw.Close()
		return err
	}
	return zw.Close()
}

func writeFindingsZipEntries(zw *zip.Writer, findings []*db.DBFinding, stage string, now time.Time) error {
	return writeFindingsZipEntriesWithTemplates(zw, findings, nil, stage, now)
}

func writeFindingsZipEntriesWithTemplates(zw *zip.Writer, findings []*db.DBFinding, views []report.View, stage string, now time.Time) error {
	store := evidence.New(nil, nil, stage) // private export copy; not subject to GC
	used := map[string]int{}
	platformSubmission := false
	for _, v := range views {
		if v.Template != "" && v.Template != report.TemplatePraetor {
			platformSubmission = true
			break
		}
	}
	for i, f := range findings {
		base := report.FindingFilename(f)
		name := base
		if n := used[base]; n > 0 {
			name = fmt.Sprintf("%s-%d.md", strings.TrimSuffix(base, ".md"), n+1)
		}
		used[base]++
		w, err := zw.Create(name)
		if err != nil {
			return err
		}
		// 一漏洞一文件：平台模板按各自表单版式渲染，praetor 沿用原函数。
		content := report.SingleFindingMarkdown(f, now)
		if i < len(views) && views[i].Template != "" && views[i].Template != report.TemplatePraetor {
			content = report.RenderFinding(views[i], views[i].Template)
		}
		if _, err = io.WriteString(w, content); err != nil {
			return err
		}
		for _, b := range f.TrafficBindings {
			prefix := fmt.Sprintf("evidence/%d/%d/", f.ID, b.ID)
			w, err := zw.Create(prefix + "manifest.json")
			if err != nil {
				return err
			}
			if err = json.NewEncoder(w).Encode(b); err != nil {
				return err
			}
			for _, side := range []string{"request", "response"} {
				if err := func() error {
					body, _, err := store.OpenBody(b.Snapshot, side)
					if err != nil {
						return err
					}
					defer body.Close()
					w, err := zw.Create(prefix + side + ".http")
					if err != nil {
						return err
					}
					head := b.Snapshot.ReqHead
					if side == "response" {
						head = b.Snapshot.RespHead
					}
					if _, err = io.WriteString(w, strings.TrimRight(head, "\r\n")+"\n\n"); err != nil {
						return err
					}
					if _, err = io.Copy(w, body); err != nil {
						return err
					}
					if _, err = body.Seek(0, io.SeekStart); err != nil {
						return err
					}
					w, err = zw.Create(prefix + side + ".bin")
					if err != nil {
						return err
					}
					_, err = io.Copy(w, body)
					return err
				}(); err != nil {
					return err
				}
			}
		}
		for _, a := range f.Attachments {
			blob, _, err := store.OpenAttachment(db.FindingAttachment{SHA256: a.SHA256, Size: a.Size})
			if err != nil {
				return err
			}
			name := fmt.Sprintf("evidence/%d/attachments/%d-%s", f.ID, a.ID, safeAttachmentZipName(a.Filename))
			w, err := zw.Create(name)
			if err != nil {
				blob.Close()
				return err
			}
			if _, err = io.Copy(w, blob); err != nil {
				blob.Close()
				return err
			}
			if err = blob.Close(); err != nil {
				return err
			}
		}
	}
	// 平台模板一漏洞一提交，附一份逐份待补项清单；纯 praetor 导出保持原有 zip 结构。
	if platformSubmission {
		cw, err := zw.Create("_提交清单.md")
		if err != nil {
			return err
		}
		if _, err = io.WriteString(cw, report.Checklist(views, "")); err != nil {
			return err
		}
	}
	return nil
}

func safeAttachmentZipName(name string) string {
	name = filepath.Base(strings.TrimSpace(name))
	name = strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == '\x00' || r == '\r' || r == '\n' {
			return '_'
		}
		return r
	}, name)
	if name == "" || name == "." || name == ".." {
		return "attachment"
	}
	return name
}

func buildFindingsEvidenceZip(path string, findings []*db.DBFinding, stage string, now time.Time) error {
	return buildFindingsEvidenceZipWithTemplates(path, findings, nil, stage, now)
}

func buildFindingsEvidenceZipWithTemplates(path string, findings []*db.DBFinding, views []report.View, stage string, now time.Time) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	writeErr := writeFindingsEvidenceZipWithTemplates(f, findings, views, stage, now)
	syncErr := f.Sync()
	closeErr := f.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	// Re-read every compressed entry to validate the finished ZIP, including CRCs,
	// before the caller starts an HTTP download response.
	archive, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer archive.Close()
	for _, entry := range archive.File {
		r, err := entry.Open()
		if err != nil {
			return err
		}
		_, readErr := io.Copy(io.Discard, r)
		if err := errors.Join(readErr, r.Close()); err != nil {
			return err
		}
	}
	return nil
}
