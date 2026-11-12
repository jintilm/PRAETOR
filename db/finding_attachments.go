package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// FindingAttachment is a persisted piece of finding evidence. The binary lives
// in the content-addressed evidence store; this row only carries metadata and
// the SHA-256 handle.
type FindingAttachment struct {
	ID        int64           `json:"id"`
	FindingID int64           `json:"finding_id"`
	Kind      string          `json:"kind"`
	Source    string          `json:"source"`
	SourceRef string          `json:"source_ref,omitempty"`
	Filename  string          `json:"filename"`
	MIMEType  string          `json:"mime_type"`
	Size      int64           `json:"size"`
	SHA256    string          `json:"sha256"`
	Role      string          `json:"role"`
	Caption   string          `json:"caption"`
	Position  int             `json:"position"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}

// FindingAttachmentInput is the validated metadata written after the blob has
// been staged and hashed. SHA256 and Size are computed by the evidence store.
type FindingAttachmentInput struct {
	FindingID int64
	// TaskID, when non-zero, is the caller task authority. Agent tool calls set
	// it so a guessed finding id cannot attach evidence across task boundaries.
	TaskID    int64
	Kind      string
	Source    string
	SourceRef string
	Filename  string
	MIMEType  string
	Size      int64
	SHA256    string
	Role      string
	Caption   string
	Metadata  json.RawMessage
}

// FindingAttachmentPatch carries optional editable metadata. Nil means keep the
// existing value.
type FindingAttachmentPatch struct {
	Kind      *string
	Source    *string
	SourceRef *string
	Filename  *string
	Role      *string
	Caption   *string
	Metadata  *json.RawMessage
}

const (
	FindingAttachmentScreenshot     = "screenshot"
	FindingAttachmentBurpScreenshot = "burp_screenshot"
	FindingAttachmentHTTPCapture    = "http_capture"
	FindingAttachmentFile           = "file"
)

var FindingAttachmentKinds = map[string]bool{
	FindingAttachmentScreenshot:     true,
	FindingAttachmentBurpScreenshot: true,
	FindingAttachmentHTTPCapture:    true,
	FindingAttachmentFile:           true,
}

var FindingAttachmentSources = map[string]bool{
	"manual_upload": true,
	"browser_mcp":   true,
	"burp_mcp":      true,
	"host_capture":  true,
	"workspace":     true,
}

func validFindingAttachmentKind(kind string) bool {
	return FindingAttachmentKinds[kind]
}

func validFindingAttachmentSource(source string) bool {
	return FindingAttachmentSources[source]
}

func validFindingAttachmentRole(role string) bool {
	return ValidTrafficRole(role)
}

func normalizeFindingAttachmentInput(in FindingAttachmentInput) (FindingAttachmentInput, error) {
	in.Kind = strings.TrimSpace(in.Kind)
	in.Source = strings.TrimSpace(in.Source)
	in.SourceRef = strings.TrimSpace(in.SourceRef)
	in.Filename = strings.TrimSpace(in.Filename)
	in.MIMEType = strings.ToLower(strings.TrimSpace(in.MIMEType))
	in.SHA256 = strings.ToLower(strings.TrimSpace(in.SHA256))
	in.Role = strings.TrimSpace(in.Role)
	in.Caption = strings.TrimSpace(in.Caption)
	if in.Kind == "" {
		in.Kind = FindingAttachmentScreenshot
	}
	if in.Source == "" {
		in.Source = "manual_upload"
	}
	if in.Role == "" {
		in.Role = "supporting"
	}
	if in.Filename == "" {
		return in, errors.New("附件文件名不能为空")
	}
	if !validFindingAttachmentKind(in.Kind) {
		return in, fmt.Errorf("无效的附件类型 %q", in.Kind)
	}
	if !validFindingAttachmentSource(in.Source) {
		return in, fmt.Errorf("无效的附件来源 %q", in.Source)
	}
	if !validFindingAttachmentRole(in.Role) {
		return in, fmt.Errorf("无效的附件用途 %q", in.Role)
	}
	if in.Size <= 0 {
		return in, errors.New("附件大小必须大于 0")
	}
	if len(in.SHA256) != 64 {
		return in, errors.New("附件 SHA-256 无效")
	}
	if len(in.Metadata) == 0 || string(in.Metadata) == "null" {
		in.Metadata = json.RawMessage(`{}`)
	}
	return in, nil
}

const findingAttachmentSelect = `id,finding_id,kind,source,source_ref,filename,mime_type,size,sha256,role,caption,position,metadata,created_at`

func scanFindingAttachment(sc interface{ Scan(...any) error }) (*FindingAttachment, error) {
	var a FindingAttachment
	var metadata []byte
	if err := sc.Scan(&a.ID, &a.FindingID, &a.Kind, &a.Source, &a.SourceRef, &a.Filename,
		&a.MIMEType, &a.Size, &a.SHA256, &a.Role, &a.Caption, &a.Position, &metadata, &a.CreatedAt); err != nil {
		return nil, err
	}
	if len(metadata) == 0 {
		metadata = []byte(`{}`)
	}
	a.Metadata = json.RawMessage(metadata)
	return &a, nil
}

func (d *DB) AddFindingAttachment(ctx context.Context, in FindingAttachmentInput) (*FindingAttachment, error) {
	in, err := normalizeFindingAttachmentInput(in)
	if err != nil {
		return nil, err
	}
	out := &FindingAttachment{}
	err = d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if err := LockFindingEvidenceTx(tx, in.FindingID, nil); err != nil {
			return err
		}
		if in.TaskID > 0 {
			var taskID sql.NullInt64
			if err := tx.QueryRow(`SELECT task_id FROM findings WHERE id=$1`, in.FindingID).Scan(&taskID); err != nil {
				return err
			}
			if !taskID.Valid || taskID.Int64 != in.TaskID {
				return ErrFindingNotFound
			}
		}
		var position int
		if err := tx.QueryRow(`SELECT COALESCE(MAX(position)+1,0) FROM finding_attachments WHERE finding_id=$1`, in.FindingID).Scan(&position); err != nil {
			return err
		}
		var inserted bool
		err := tx.QueryRow(`
INSERT INTO finding_attachments(finding_id,kind,source,source_ref,filename,mime_type,size,sha256,role,caption,position,metadata)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
ON CONFLICT(finding_id,sha256) DO NOTHING
RETURNING `+findingAttachmentSelect,
			in.FindingID, in.Kind, in.Source, in.SourceRef, in.Filename, in.MIMEType, in.Size, in.SHA256,
			in.Role, in.Caption, position, string(in.Metadata)).Scan(
			&out.ID, &out.FindingID, &out.Kind, &out.Source, &out.SourceRef, &out.Filename,
			&out.MIMEType, &out.Size, &out.SHA256, &out.Role, &out.Caption, &out.Position, &out.Metadata, &out.CreatedAt)
		if errors.Is(err, sql.ErrNoRows) {
			out, err = scanFindingAttachment(tx.QueryRow(`SELECT `+findingAttachmentSelect+` FROM finding_attachments WHERE finding_id=$1 AND sha256=$2`, in.FindingID, in.SHA256))
			if err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else {
			inserted = true
		}
		if inserted {
			return bumpEvidenceVersionTx(tx, in.FindingID)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (d *DB) ListFindingAttachments(ctx context.Context, findingID int64) ([]FindingAttachment, error) {
	rows, err := d.QueryContext(ctx, `SELECT `+findingAttachmentSelect+`
FROM finding_attachments WHERE finding_id=$1 ORDER BY position,id`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanFindingAttachments(rows)
}

func scanFindingAttachments(rows *sql.Rows) ([]FindingAttachment, error) {
	out := []FindingAttachment{}
	for rows.Next() {
		a, err := scanFindingAttachment(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

func (d *DB) GetFindingAttachment(ctx context.Context, findingID, attachmentID int64) (*FindingAttachment, error) {
	a, err := scanFindingAttachment(d.QueryRowContext(ctx, `SELECT `+findingAttachmentSelect+`
FROM finding_attachments WHERE finding_id=$1 AND id=$2`, findingID, attachmentID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrEvidenceNotFound
	}
	return a, err
}

func (d *DB) DeleteFindingAttachment(ctx context.Context, findingID, attachmentID int64, version *int64) error {
	return d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if err := LockFindingEvidenceTx(tx, findingID, version); err != nil {
			return err
		}
		res, err := tx.Exec(`DELETE FROM finding_attachments WHERE finding_id=$1 AND id=$2`, findingID, attachmentID)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrEvidenceNotFound
		}
		return bumpEvidenceVersionTx(tx, findingID)
	})
}

func (d *DB) UpdateFindingAttachment(ctx context.Context, findingID, attachmentID int64, version *int64, patch FindingAttachmentPatch) (*FindingAttachment, error) {
	var out *FindingAttachment
	err := d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if err := LockFindingEvidenceTx(tx, findingID, version); err != nil {
			return err
		}
		set := []string{}
		args := []any{findingID, attachmentID}
		add := func(col string, value any) {
			args = append(args, value)
			set = append(set, fmt.Sprintf("%s=$%d", col, len(args)))
		}
		if patch.Kind != nil {
			if !validFindingAttachmentKind(strings.TrimSpace(*patch.Kind)) {
				return errors.New("无效的附件类型")
			}
			add("kind", strings.TrimSpace(*patch.Kind))
		}
		if patch.Source != nil {
			if !validFindingAttachmentSource(strings.TrimSpace(*patch.Source)) {
				return errors.New("无效的附件来源")
			}
			add("source", strings.TrimSpace(*patch.Source))
		}
		if patch.SourceRef != nil {
			add("source_ref", strings.TrimSpace(*patch.SourceRef))
		}
		if patch.Filename != nil {
			if strings.TrimSpace(*patch.Filename) == "" {
				return errors.New("附件文件名不能为空")
			}
			add("filename", strings.TrimSpace(*patch.Filename))
		}
		if patch.Role != nil {
			if !validFindingAttachmentRole(strings.TrimSpace(*patch.Role)) {
				return errors.New("无效的附件用途")
			}
			add("role", strings.TrimSpace(*patch.Role))
		}
		if patch.Caption != nil {
			add("caption", strings.TrimSpace(*patch.Caption))
		}
		if patch.Metadata != nil {
			raw := *patch.Metadata
			if len(raw) == 0 || string(raw) == "null" {
				raw = json.RawMessage(`{}`)
			}
			add("metadata", string(raw))
		}
		if len(set) == 0 {
			return errors.New("没有可更新的附件字段")
		}
		res, err := tx.Exec(`UPDATE finding_attachments SET `+strings.Join(set, ",")+` WHERE finding_id=$1 AND id=$2`, args...)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrEvidenceNotFound
		}
		if err := bumpEvidenceVersionTx(tx, findingID); err != nil {
			return err
		}
		out, err = scanFindingAttachment(tx.QueryRow(`SELECT `+findingAttachmentSelect+` FROM finding_attachments WHERE finding_id=$1 AND id=$2`, findingID, attachmentID))
		return err
	})
	return out, err
}

func (d *DB) ReorderFindingAttachments(ctx context.Context, findingID int64, version *int64, order []int64) error {
	return d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if err := LockFindingEvidenceTx(tx, findingID, version); err != nil {
			return err
		}
		var count int
		if err := tx.QueryRow(`SELECT count(*) FROM finding_attachments WHERE finding_id=$1`, findingID).Scan(&count); err != nil {
			return err
		}
		if len(order) != count {
			return ErrEvidenceConflict
		}
		seen := map[int64]bool{}
		for position, id := range order {
			if id <= 0 || seen[id] {
				return ErrEvidenceConflict
			}
			seen[id] = true
			res, err := tx.Exec(`UPDATE finding_attachments SET position=$1 WHERE finding_id=$2 AND id=$3`, position, findingID, id)
			if err != nil {
				return err
			}
			n, err := res.RowsAffected()
			if err != nil {
				return err
			}
			if n == 0 {
				return ErrEvidenceConflict
			}
		}
		return bumpEvidenceVersionTx(tx, findingID)
	})
}

// FindingAttachmentHashes returns every distinct blob hash referenced by one
// task. It is used by task archive and evidence GC.
func (d *DB) FindingAttachmentHashes(ctx context.Context, taskID int64) ([]string, error) {
	rows, err := d.QueryContext(ctx, `SELECT DISTINCT a.sha256
FROM finding_attachments a JOIN findings f ON f.id=a.finding_id
WHERE f.task_id=$1 ORDER BY a.sha256`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			return nil, err
		}
		out = append(out, hash)
	}
	return out, rows.Err()
}

// FindingAttachmentsByNodeIDs maps exploration finding-node IDs to their
// standalone finding IDs and attachments. Task reports use this to add the same
// evidence exported by the global findings page.
func (d *DB) FindingAttachmentsByNodeIDs(ctx context.Context, nodeIDs []int64) (map[int64][]FindingAttachment, error) {
	out := map[int64][]FindingAttachment{}
	if len(nodeIDs) == 0 {
		return out, nil
	}
	ph := make([]string, len(nodeIDs))
	args := make([]any, len(nodeIDs))
	for i, id := range nodeIDs {
		ph[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}
	rows, err := d.QueryContext(ctx, `SELECT `+findingAttachmentSelect+`
FROM finding_attachments WHERE finding_id IN (SELECT id FROM findings WHERE node_id IN (`+strings.Join(ph, ",")+`))
ORDER BY finding_id,position,id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		a, err := scanFindingAttachment(rows)
		if err != nil {
			return nil, err
		}
		out[a.FindingID] = append(out[a.FindingID], *a)
	}
	return out, rows.Err()
}

// AttachmentFindingIDsByNodeIDs returns the standalone finding ID for each
// visible exploration node. Missing rows are simply omitted.
func (d *DB) AttachmentFindingIDsByNodeIDs(ctx context.Context, nodeIDs []int64) (map[int64]int64, error) {
	out := map[int64]int64{}
	if len(nodeIDs) == 0 {
		return out, nil
	}
	ph := make([]string, len(nodeIDs))
	args := make([]any, len(nodeIDs))
	for i, id := range nodeIDs {
		ph[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}
	rows, err := d.QueryContext(ctx, `SELECT node_id,id FROM findings WHERE node_id IN (`+strings.Join(ph, ",")+`)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var nodeID, findingID int64
		if err := rows.Scan(&nodeID, &findingID); err != nil {
			return nil, err
		}
		out[nodeID] = findingID
	}
	return out, rows.Err()
}

// ArchiveAttachmentHashes extracts the distinct blob handles from an archive
// manifest table. Older archives omit the table and therefore return nil.
func ArchiveAttachmentHashes(snapshot *TaskArchiveSnapshot) ([]string, error) {
	if snapshot == nil {
		return nil, nil
	}
	raw := snapshot.Tables["finding_attachments"]
	if len(raw) == 0 {
		return nil, nil
	}
	var rows []struct {
		SHA256 string `json:"sha256"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, row := range rows {
		hash := strings.ToLower(strings.TrimSpace(row.SHA256))
		if hash == "" || seen[hash] {
			continue
		}
		if len(hash) != 64 {
			return nil, errors.New("归档附件 SHA-256 无效")
		}
		seen[hash] = true
		out = append(out, hash)
	}
	return out, nil
}
