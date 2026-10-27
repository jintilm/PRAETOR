// Package samplestore 是逆向域的样本库：**加密落盘 + 哈希索引**，并且是唯一允许
// 长期持有原始样本的地方。
//
// 三条规矩（P3-5 的合规要求，不是可选优化）：
//  1. 磁盘上不出现明文样本：AES-256-GCM 加密，密钥只从环境变量取，缺了直接报错 ——
//     没有"密钥不对就先不加密"这种降级，那等于把样本库变成明文目录。
//  2. 索引用 sha256 做键：同一份样本重复入库只留一份，分析结论（re_triage / re_recipe
//     的落盘文件）也能稳定对应到样本。
//  3. 工具拿不到"整包内容"：只给 **解密后的临时文件路径**，用完即删；样本字节永远
//     不进 LLM 上下文（那既贵又把样本外传了）。
package samplestore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// KeyEnv 是样本库密钥的环境变量名（64 位 hex = 32 字节）。
const KeyEnv = "PRAETOR_SAMPLE_KEY"

// Entry 是索引里的一条记录。**不含样本内容**，只有元数据。
type Entry struct {
	SHA256  string    `json:"sha256"`
	Size    int64     `json:"size"`
	Name    string    `json:"name"`
	AddedAt time.Time `json:"added_at"`
}

// Store 是一个样本库目录。
type Store struct {
	root string
	aead cipher.AEAD
}

// Open 打开（或创建）样本库；密钥缺失或不合法时返回错误。
//
// 为什么不让调用方传密钥：密钥只有一个来源（环境变量），传参会让"忘记配置"变成
// "用了个默认值"，而默认值意味着明文。
func Open(root string) (*Store, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("样本库路径为空")
	}
	raw := strings.TrimSpace(os.Getenv(KeyEnv))
	if raw == "" {
		return nil, fmt.Errorf("未配置 %s：样本库必须加密，不提供明文降级。"+
			"生成方式：`openssl rand -hex 32`", KeyEnv)
	}
	key, err := hex.DecodeString(raw)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("%s 必须是 64 位 hex（32 字节），当前长度 %d", KeyEnv, len(raw))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	return &Store{root: root, aead: aead}, nil
}

// Put 把一个文件加密入库，返回索引条目（已存在则直接返回旧条目）。
func (s *Store) Put(src, name string) (Entry, error) {
	sum, size, err := hashFile(src)
	if err != nil {
		return Entry{}, err
	}
	if name == "" {
		name = filepath.Base(src)
	}
	ent := Entry{SHA256: sum, Size: size, Name: name, AddedAt: time.Now().UTC()}

	idx, err := s.loadIndex()
	if err != nil {
		return Entry{}, err
	}
	if old, ok := idx[sum]; ok {
		return old, nil // 同一份样本只留一份，元数据以首次入库为准
	}

	dst, err := s.pathFor(sum)
	if err != nil {
		return Entry{}, err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return Entry{}, err
	}
	if err := encryptFile(s.aead, src, dst); err != nil {
		return Entry{}, err
	}
	idx[sum] = ent
	if err := s.saveIndex(idx); err != nil {
		return Entry{}, err
	}
	return ent, nil
}

// List 返回全部条目（按入库时间倒序），供人工核对，不进模型上下文。
func (s *Store) List() ([]Entry, error) {
	idx, err := s.loadIndex()
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(idx))
	for _, e := range idx {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AddedAt.After(out[j].AddedAt) })
	return out, nil
}

// Materialize 把样本解密到临时文件，返回路径与清理函数。
//
// 调用方**必须** defer cleanup()：样本在磁盘上的明文窗口越短越好。
func (s *Store) Materialize(sha string) (string, func(), error) {
	sha = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(sha, "sha256:")))
	if len(sha) != 64 {
		return "", nil, fmt.Errorf("不是合法的 sha256：%q", sha)
	}
	src, err := s.pathFor(sha)
	if err != nil {
		return "", nil, err
	}
	if _, err := os.Stat(src); err != nil {
		return "", nil, fmt.Errorf("样本库里没有 %s", sha[:12])
	}
	tmp, err := os.CreateTemp("", "praetor-sample-*")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() {
		tmp.Close()
		os.Remove(tmp.Name())
	}
	if err := decryptFile(s.aead, src, tmp); err != nil {
		cleanup()
		return "", nil, err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return "", nil, err
	}
	return tmp.Name(), cleanup, nil
}

func (s *Store) pathFor(sha string) (string, error) {
	if len(sha) < 2 {
		return "", fmt.Errorf("不是合法的 sha256：%q", sha)
	}
	return filepath.Join(s.root, sha[:2], sha+".enc"), nil
}

func (s *Store) indexPath() string { return filepath.Join(s.root, "index.json") }

func (s *Store) loadIndex() (map[string]Entry, error) {
	body, err := os.ReadFile(s.indexPath())
	if errors.Is(err, os.ErrNotExist) {
		return map[string]Entry{}, nil
	}
	if err != nil {
		return nil, err
	}
	idx := map[string]Entry{}
	if err := json.Unmarshal(body, &idx); err != nil {
		return nil, fmt.Errorf("索引损坏：%w", err)
	}
	return idx, nil
}

func (s *Store) saveIndex(idx map[string]Entry) error {
	body, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	// 先写临时文件再改名：半截索引会让整个样本库不可读。
	tmp := s.indexPath() + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.indexPath())
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// encryptFile 是 AES-256-GCM：nonce 写在密文前面，认证标签由 GCM 自己追加。
//
// 用 GCM 而不是"异或 + 哈希"：样本库要能发现被篡改（认证），否则一份被替换的样本
// 会静默产出错误结论。
func encryptFile(aead cipher.AEAD, src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	if _, err := out.Write(nonce); err != nil {
		return err
	}
	buf := make([]byte, 1<<20)
	for {
		n, err := in.Read(buf)
		if n > 0 {
			if _, werr := out.Write(aead.Seal(nil, nonce, buf[:n], nil)); werr != nil {
				return werr
			}
			// nonce 递增：GCM 下同一 key 复用 nonce 是灾难性的，分块加密必须换 nonce。
			increment(nonce)
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func decryptFile(aead cipher.AEAD, src string, dst io.Writer) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(in, nonce); err != nil {
		return err
	}
	buf := make([]byte, 1<<20)
	for {
		n, err := in.Read(buf)
		if n > 0 {
			plain, derr := aead.Open(nil, nonce, buf[:n], nil)
			if derr != nil {
				return fmt.Errorf("解密失败（密钥不对或文件被改过）")
			}
			if _, werr := dst.Write(plain); werr != nil {
				return werr
			}
			increment(nonce)
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// increment 把 nonce 当大端计数器 +1。
func increment(nonce []byte) {
	for i := len(nonce) - 1; i >= 0; i-- {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
}
