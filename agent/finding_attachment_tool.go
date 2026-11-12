package agent

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
	"os"
	"path/filepath"
	"strings"

	"github.com/jintilm/praetor/db"
	acperm "github.com/jintilm/praetor/internal/norma/permission"
	actool "github.com/jintilm/praetor/internal/norma/tool"
)

const maxAgentAttachmentSize = int64(20 << 20)

const findingAttachmentGuidance = "\n\n**截图证据附件（可选）**：确认漏洞并取得 finding_id 后，如果当前任务工作区已有目标页面截图，优先用 attach_finding_attachment(finding_id, path, kind=screenshot, source=browser_mcp, role=proof, caption=...) 登记。调用 browser_take_screenshot 时不要自行传 filename，二进制接收层会把图片保存到任务 evidence/ 并返回路径；不要把图片 base64 写进 evidence 或报告正文。Burp GUI 截图由操作者上传到漏洞详情页；Burp 请求/响应证据仍走流量绑定，不要伪造 Burp 截图。"

// addFindingAttachmentTool attaches an already captured workspace image to a
// finding. The model never sends binary data through the tool result; only the
// path and metadata are accepted.
func (t *ToolSet) addFindingAttachmentTool() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        "attach_finding_attachment",
		Description: "把当前任务工作区里的 PNG/JPEG 截图附加到已登记的漏洞。先调用 report_finding 获取 finding_id，再调用本工具；path 使用相对任务工作目录的 evidence/xxx.png，或 /work/... 视角。工具只登记证据，不把图片 base64 塞进上下文。" + findingAttachmentGuidance,
		Schema: obj(map[string]any{
			"finding_id": idp("report_finding 返回的独立 finding_id（不是 finding_node_id）"),
			"path":       str("工作区图片路径；相对路径按任务工作目录解析"),
			"kind":       str("screenshot | burp_screenshot | file，默认 screenshot"),
			"source":     str("browser_mcp | burp_mcp | workspace | host_capture | manual_upload，默认 workspace"),
			"role":       str("baseline | proof | verification | supporting，默认 supporting"),
			"caption":    str("截图说明，报告中使用"),
		}, "finding_id", "path"),
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision {
			return acperm.Allowed()
		},
		Run: func(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
			var a struct {
				FindingID json.RawMessage `json:"finding_id"`
				Path      string          `json:"path"`
				Kind      string          `json:"kind"`
				Source    string          `json:"source"`
				Role      string          `json:"role"`
				Caption   string          `json:"caption"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("invalid input: " + err.Error()), nil
			}
			findingID := pid(a.FindingID)
			if findingID <= 0 {
				return actool.Errorf("finding_id 必须是 report_finding 返回的独立 finding_id"), nil
			}
			if t.ts == nil || t.attachmentRecorder == nil {
				return actool.Errorf("附件存储不可用；当前没有任务上下文"), nil
			}
			abs, err := resolveAgentAttachmentPath(tc, a.Path)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			meta, err := inspectAgentAttachment(abs)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			kind := strings.TrimSpace(a.Kind)
			if kind == "" {
				kind = db.FindingAttachmentScreenshot
			}
			source := strings.TrimSpace(a.Source)
			if source == "" {
				source = "workspace"
			}
			role := strings.TrimSpace(a.Role)
			if role == "" {
				role = "supporting"
			}
			rawMeta, _ := json.Marshal(map[string]any{
				"width": meta.width, "height": meta.height, "original_filename": filepath.Base(abs),
			})
			f, err := os.Open(abs)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			defer f.Close()
			out, err := t.attachmentRecorder.AddAttachment(ctx, db.FindingAttachmentInput{
				FindingID: findingID,
				TaskID:    t.taskID,
				Kind:      kind,
				Source:    source,
				SourceRef: tcToolUseID(tc),
				Filename:  safeAgentAttachmentName(filepath.Base(abs)),
				MIMEType:  meta.mimeType,
				Size:      meta.size,
				SHA256:    meta.sha256,
				Role:      role,
				Caption:   strings.TrimSpace(a.Caption),
				Metadata:  rawMeta,
			}, f)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{
				"attachment_id": out.ID,
				"finding_id":    out.FindingID,
				"filename":      out.Filename,
				"mime_type":     out.MIMEType,
				"size":          out.Size,
				"caption":       out.Caption,
			})
		},
	})
}

type agentAttachmentMeta struct {
	mimeType string
	size     int64
	sha256   string
	width    int
	height   int
}

func resolveAgentAttachmentPath(tc *actool.ToolContext, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("path 不能为空")
	}
	if tc != nil && tc.SandboxPath != nil {
		if mapped, ok := tc.SandboxPath(raw); ok {
			raw = mapped
		}
	}
	if !filepath.IsAbs(raw) {
		if tc == nil || strings.TrimSpace(tc.WorkingDir) == "" {
			return "", errors.New("当前没有任务工作目录")
		}
		raw = filepath.Join(tc.WorkingDir, filepath.FromSlash(raw))
	}
	abs, err := filepath.Abs(filepath.Clean(raw))
	if err != nil {
		return "", err
	}
	if tc != nil && strings.TrimSpace(tc.WorkingDir) != "" {
		root, err := filepath.Abs(filepath.Clean(tc.WorkingDir))
		if err != nil {
			return "", err
		}
		rel, err := filepath.Rel(root, abs)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return "", errors.New("附件路径必须位于当前任务工作区内")
		}
	}
	fi, err := os.Lstat(abs)
	if err != nil {
		return "", fmt.Errorf("附件文件不存在: %w", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return "", errors.New("附件必须是普通文件，不能是符号链接或目录")
	}
	if fi.Size() <= 0 || fi.Size() > maxAgentAttachmentSize {
		return "", fmt.Errorf("附件大小必须在 1 字节到 %d MiB 之间", maxAgentAttachmentSize>>20)
	}
	return abs, nil
}

func inspectAgentAttachment(path string) (agentAttachmentMeta, error) {
	f, err := os.Open(path)
	if err != nil {
		return agentAttachmentMeta{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return agentAttachmentMeta{}, err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return agentAttachmentMeta{}, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return agentAttachmentMeta{}, err
	}
	cfg, format, err := image.DecodeConfig(f)
	if err != nil {
		return agentAttachmentMeta{}, errors.New("附件必须是有效的 PNG 或 JPEG 图片")
	}
	mimeType := ""
	switch format {
	case "png":
		mimeType = "image/png"
	case "jpeg":
		mimeType = "image/jpeg"
	default:
		return agentAttachmentMeta{}, errors.New("附件只支持 PNG 或 JPEG 图片")
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width > 16384 || cfg.Height > 16384 ||
		int64(cfg.Width)*int64(cfg.Height) > 64_000_000 {
		return agentAttachmentMeta{}, errors.New("图片尺寸超出限制")
	}
	return agentAttachmentMeta{
		mimeType: mimeType, size: info.Size(), sha256: hex.EncodeToString(h.Sum(nil)),
		width: cfg.Width, height: cfg.Height,
	}, nil
}

func tcToolUseID(tc *actool.ToolContext) string {
	if tc == nil {
		return ""
	}
	return tc.ToolUseID
}

func safeAgentAttachmentName(name string) string {
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

// saveAgentArtifact persists a binary MCP content block under the task's
// evidence directory. The model receives only the relative path, never base64.
func saveAgentArtifact(_ context.Context, tc *actool.ToolContext, name, mimeType string, data []byte) (string, error) {
	if tc == nil || strings.TrimSpace(tc.WorkingDir) == "" {
		return "", errors.New("artifact sink 缺少任务工作目录")
	}
	if len(data) == 0 || int64(len(data)) > maxAgentAttachmentSize {
		return "", errors.New("artifact 大小超出限制")
	}
	ext := ".bin"
	switch strings.ToLower(strings.TrimSpace(mimeType)) {
	case "image/png":
		ext = ".png"
	case "image/jpeg":
		ext = ".jpg"
	case "image/webp":
		ext = ".webp"
	}
	base := safeAgentAttachmentName(name)
	if base == "screenshot.png" || filepath.Ext(base) == "" {
		base = "artifact-" + safeAgentAttachmentName(tc.ToolUseID)
		if base == "artifact-" {
			base = "artifact"
		}
		base += ext
	}
	root, err := filepath.Abs(filepath.Clean(tc.WorkingDir))
	if err != nil {
		return "", err
	}
	dir := filepath.Join(root, "evidence")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	target := filepath.Join(dir, base)
	if err := os.WriteFile(target, data, 0o600); err != nil {
		return "", err
	}
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return "", err
	}
	return filepath.ToSlash(rel), nil
}
