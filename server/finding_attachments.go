package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jintilm/praetor/db"
)

const (
	maxFindingAttachmentSize  = int64(20 << 20)
	maxFindingAttachmentTotal = int64(100 << 20)
)

type stagedFindingAttachment struct {
	path     string
	filename string
	mimeType string
	size     int64
	sha256   string
	width    int
	height   int
}

func (s *Server) loadFindingAttachments(ctx context.Context, findings []*db.DBFinding) ([]string, error) {
	var hashes []string
	seen := map[string]bool{}
	for _, f := range findings {
		items, err := s.m.pg.ListFindingAttachments(ctx, f.ID)
		if err != nil {
			return nil, err
		}
		f.Attachments = items
		f.AttachmentCount = len(items)
		for _, item := range items {
			if !seen[item.SHA256] {
				seen[item.SHA256] = true
				hashes = append(hashes, item.SHA256)
			}
		}
	}
	return hashes, nil
}

func (s *Server) registerFindingAttachments(mux *http.ServeMux) {
	base := "/api/exploration/findings/{id}/attachments"
	mux.HandleFunc("GET "+base, s.listFindingAttachments)
	mux.HandleFunc("POST "+base, s.uploadFindingAttachment)
	mux.HandleFunc("POST "+base+"/from-workspace", s.importFindingAttachmentFromWorkspace)
	mux.HandleFunc("GET "+base+"/{attachment_id}/content", s.getFindingAttachmentContent)
	mux.HandleFunc("PATCH "+base+"/{attachment_id}", s.updateFindingAttachment)
	mux.HandleFunc("DELETE "+base+"/{attachment_id}", s.deleteFindingAttachment)
	mux.HandleFunc("PUT "+base+"/order", s.reorderFindingAttachments)
}

func (s *Server) listFindingAttachments(w http.ResponseWriter, r *http.Request) {
	id, ok := s.findingTrafficAccess(w, r, false)
	if !ok {
		return
	}
	items, err := s.m.pg.ListFindingAttachments(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"attachments": items})
}

func (s *Server) uploadFindingAttachment(w http.ResponseWriter, r *http.Request) {
	id, ok := s.findingTrafficAccess(w, r, true)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFindingAttachmentSize+(1<<20))
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "解析附件失败或超出大小限制: "+err.Error())
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "缺少上传文件")
		return
	}
	defer file.Close()

	staged, err := s.stageFindingAttachment(file, maxFindingAttachmentSize)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	defer os.Remove(staged.path)
	if header != nil && strings.TrimSpace(header.Filename) != "" {
		staged.filename = sanitizeAttachmentFilename(header.Filename)
	}
	in := db.FindingAttachmentInput{
		FindingID: id,
		Kind:      r.FormValue("kind"),
		Source:    r.FormValue("source"),
		SourceRef: r.FormValue("source_ref"),
		Filename:  staged.filename,
		MIMEType:  staged.mimeType,
		Size:      staged.size,
		SHA256:    staged.sha256,
		Role:      r.FormValue("role"),
		Caption:   r.FormValue("caption"),
		Metadata:  attachmentMetadata(staged),
	}
	attachment, err := s.addStagedFindingAttachment(r.Context(), id, in, staged)
	if err != nil {
		evidenceError(w, err)
		return
	}
	writeJSON(w, 201, attachment)
}

func (s *Server) importFindingAttachmentFromWorkspace(w http.ResponseWriter, r *http.Request) {
	id, ok := s.findingTrafficAccess(w, r, true)
	if !ok {
		return
	}
	var body struct {
		Path      string `json:"path"`
		Kind      string `json:"kind"`
		Source    string `json:"source"`
		SourceRef string `json:"source_ref"`
		Role      string `json:"role"`
		Caption   string `json:"caption"`
		Filename  string `json:"filename"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "无效请求")
		return
	}
	abs, ok := s.wsResolve(body.Path)
	if !ok {
		writeErr(w, http.StatusBadRequest, "非法工作区路径")
		return
	}
	fi, err := os.Stat(abs)
	if err != nil || fi.IsDir() {
		writeErr(w, http.StatusNotFound, "工作区文件不存在")
		return
	}
	if fi.Size() > maxFindingAttachmentSize {
		writeErr(w, http.StatusRequestEntityTooLarge, "附件超过 20 MiB 限制")
		return
	}
	f, err := os.Open(abs)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	staged, err := s.stageFindingAttachment(f, maxFindingAttachmentSize)
	_ = f.Close()
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	defer os.Remove(staged.path)
	if strings.TrimSpace(body.Filename) != "" {
		staged.filename = sanitizeAttachmentFilename(body.Filename)
	}
	in := db.FindingAttachmentInput{
		FindingID: id,
		Kind:      body.Kind,
		Source:    "workspace",
		SourceRef: body.SourceRef,
		Filename:  staged.filename,
		MIMEType:  staged.mimeType,
		Size:      staged.size,
		SHA256:    staged.sha256,
		Role:      body.Role,
		Caption:   body.Caption,
		Metadata:  attachmentMetadata(staged),
	}
	attachment, err := s.addStagedFindingAttachment(r.Context(), id, in, staged)
	if err != nil {
		evidenceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, attachment)
}

func (s *Server) addStagedFindingAttachment(ctx context.Context, findingID int64, in db.FindingAttachmentInput, staged *stagedFindingAttachment) (*db.FindingAttachment, error) {
	existing, err := s.m.pg.ListFindingAttachments(ctx, findingID)
	if err != nil {
		return nil, err
	}
	duplicate := false
	var total int64
	for _, item := range existing {
		total += item.Size
		if item.SHA256 == in.SHA256 {
			duplicate = true
		}
	}
	if !duplicate && total+in.Size > maxFindingAttachmentTotal {
		return nil, fmt.Errorf("漏洞附件总量超过 %d MiB 限制", maxFindingAttachmentTotal>>20)
	}
	f, err := os.Open(staged.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return s.evidenceStore().AddAttachment(ctx, in, f)
}

func (s *Server) getFindingAttachmentContent(w http.ResponseWriter, r *http.Request) {
	findingID, ok := s.findingTrafficAccess(w, r, false)
	if !ok {
		return
	}
	attachmentID, err := strconv.ParseInt(r.PathValue("attachment_id"), 10, 64)
	if err != nil || attachmentID <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid attachment id")
		return
	}
	attachment, err := s.m.pg.GetFindingAttachment(r.Context(), findingID, attachmentID)
	if err != nil {
		evidenceError(w, err)
		return
	}
	f, size, err := s.evidenceStore().OpenAttachment(*attachment)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", attachment.MIMEType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "sandbox")
	disposition := "inline"
	if r.URL.Query().Get("download") == "1" {
		disposition = "attachment"
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("%s; filename*=UTF-8''%s", disposition, url.PathEscape(attachment.Filename)))
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	http.ServeContent(w, r, attachment.Filename, attachment.CreatedAt, f)
}

func (s *Server) updateFindingAttachment(w http.ResponseWriter, r *http.Request) {
	findingID, ok := s.findingTrafficAccess(w, r, true)
	if !ok {
		return
	}
	attachmentID, err := strconv.ParseInt(r.PathValue("attachment_id"), 10, 64)
	if err != nil || attachmentID <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid attachment id")
		return
	}
	var body struct {
		Version   *int64          `json:"version"`
		Kind      *string         `json:"kind"`
		Source    *string         `json:"source"`
		SourceRef *string         `json:"source_ref"`
		Filename  *string         `json:"filename"`
		Role      *string         `json:"role"`
		Caption   *string         `json:"caption"`
		Metadata  json.RawMessage `json:"metadata"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "无效请求")
		return
	}
	patch := db.FindingAttachmentPatch{
		Kind: body.Kind, Source: body.Source, SourceRef: body.SourceRef,
		Filename: body.Filename, Role: body.Role, Caption: body.Caption,
	}
	if body.Metadata != nil {
		patch.Metadata = &body.Metadata
	}
	attachment, err := s.m.pg.UpdateFindingAttachment(r.Context(), findingID, attachmentID, body.Version, patch)
	if err != nil {
		evidenceError(w, err)
		return
	}
	writeJSON(w, 200, attachment)
}

func (s *Server) deleteFindingAttachment(w http.ResponseWriter, r *http.Request) {
	findingID, ok := s.findingTrafficAccess(w, r, true)
	if !ok {
		return
	}
	attachmentID, err := strconv.ParseInt(r.PathValue("attachment_id"), 10, 64)
	if err != nil || attachmentID <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid attachment id")
		return
	}
	var body struct {
		Version *int64 `json:"version"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body)
	if err := s.m.pg.DeleteFindingAttachment(r.Context(), findingID, attachmentID, body.Version); err != nil {
		evidenceError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": true, "id": attachmentID})
}

func (s *Server) reorderFindingAttachments(w http.ResponseWriter, r *http.Request) {
	findingID, ok := s.findingTrafficAccess(w, r, true)
	if !ok {
		return
	}
	var body struct {
		Version       *int64  `json:"version"`
		AttachmentIDs []int64 `json:"attachment_ids"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "无效请求")
		return
	}
	if err := s.m.pg.ReorderFindingAttachments(r.Context(), findingID, body.Version, body.AttachmentIDs); err != nil {
		evidenceError(w, err)
		return
	}
	s.listFindingAttachments(w, r)
}

func (s *Server) stageFindingAttachment(r io.Reader, maxSize int64) (*stagedFindingAttachment, error) {
	stageDir := filepath.Join(s.m.dir, "evidence", ".staging")
	if err := os.MkdirAll(stageDir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(stageDir, "attachment-")
	if err != nil {
		return nil, err
	}
	path := f.Name()
	cleanup := func() {
		_ = f.Close()
		_ = os.Remove(path)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(r, maxSize+1))
	if err != nil {
		cleanup()
		return nil, err
	}
	if n > maxSize {
		cleanup()
		return nil, fmt.Errorf("附件超过 %d MiB 限制", maxSize>>20)
	}
	if err := f.Sync(); err != nil {
		cleanup()
		return nil, err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return nil, err
	}
	mimeType, width, height, err := inspectAttachmentFile(path)
	if err != nil {
		_ = os.Remove(path)
		return nil, err
	}
	return &stagedFindingAttachment{
		path: path, filename: "screenshot." + attachmentExtension(mimeType),
		mimeType: mimeType, size: n, sha256: hex.EncodeToString(h.Sum(nil)),
		width: width, height: height,
	}, nil
}

func inspectAttachmentFile(path string) (string, int, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, 0, err
	}
	defer f.Close()
	cfg, format, err := image.DecodeConfig(f)
	if err != nil {
		return "", 0, 0, errors.New("附件必须是有效的 PNG 或 JPEG 图片")
	}
	mimeType := ""
	switch format {
	case "png":
		mimeType = "image/png"
	case "jpeg":
		mimeType = "image/jpeg"
	default:
		return "", 0, 0, errors.New("附件只支持 PNG 或 JPEG 图片")
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width > 16384 || cfg.Height > 16384 ||
		int64(cfg.Width)*int64(cfg.Height) > 64_000_000 {
		return "", 0, 0, errors.New("图片尺寸超出限制")
	}
	return mimeType, cfg.Width, cfg.Height, nil
}

func attachmentExtension(mimeType string) string {
	if mimeType == "image/jpeg" {
		return "jpg"
	}
	return "png"
}

func attachmentMetadata(staged *stagedFindingAttachment) json.RawMessage {
	raw, _ := json.Marshal(map[string]any{
		"width": staged.width, "height": staged.height, "original_filename": staged.filename,
	})
	return raw
}

func sanitizeAttachmentFilename(name string) string {
	name = filepath.Base(strings.TrimSpace(name))
	name = strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == '\x00' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, name)
	if name == "" || name == "." || name == ".." {
		return "screenshot.png"
	}
	if len(name) > 180 {
		name = name[:180]
	}
	return name
}
