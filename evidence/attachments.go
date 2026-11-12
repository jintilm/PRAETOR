package evidence

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/jintilm/praetor/db"
)

// AddAttachment durably writes the blob first, then persists its metadata. A
// failed metadata commit leaves an unreferenced blob for the normal evidence GC.
func (s *Store) AddAttachment(ctx context.Context, in db.FindingAttachmentInput, r io.Reader) (*db.FindingAttachment, error) {
	if s == nil || s.DB == nil {
		return nil, errors.New("attachment store unavailable")
	}
	if _, err := s.writeBody(r, in.Size, in.SHA256); err != nil {
		return nil, err
	}
	return s.DB.AddFindingAttachment(ctx, in)
}

// OpenAttachment verifies and opens an attachment blob. It intentionally does
// not hold the evidence advisory lock while the caller streams the body.
func (s *Store) OpenAttachment(a db.FindingAttachment) (*os.File, int64, error) {
	path, err := hashPath(s.Dir, a.SHA256)
	if err != nil {
		return nil, 0, err
	}
	if err := verifyFile(path, a.SHA256, a.Size); err != nil {
		return nil, 0, err
	}
	f, err := os.Open(path)
	return f, a.Size, err
}

// CopyAttachmentHashes copies task attachment blobs into a private export or
// archive staging tree, preserving the existing content-addressed layout.
func (s *Store) CopyAttachmentHashes(hashes []string, dest string) error {
	for _, hash := range hashes {
		if err := s.copyBlob(hash, dest); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) copyBlob(hash, dest string) error {
	src, err := hashPath(s.Dir, hash)
	if err != nil {
		return err
	}
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	target, err := hashPath(dest, hash)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return err
	}
	out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if os.IsExist(err) {
		return verifyFile(target, hash, info.Size())
	}
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, f)
	syncErr := out.Sync()
	closeErr := out.Close()
	return errors.Join(copyErr, syncErr, closeErr)
}

// InstallAttachmentHashes copies blobs from a verified archive package into the
// live evidence store before metadata restoration commits.
func (s *Store) InstallAttachmentHashes(ctx context.Context, hashes []string, source string) error {
	for _, hash := range hashes {
		path, err := hashPath(source, hash)
		if err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		info, err := f.Stat()
		if err != nil {
			f.Close()
			return err
		}
		_, writeErr := s.writeBody(f, info.Size(), hash)
		closeErr := f.Close()
		if err := errors.Join(writeErr, closeErr); err != nil {
			return err
		}
	}
	return nil
}
