package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jintilm/praetor/agent"
	"github.com/jintilm/praetor/config"
)

// CTF 题面来源（P2-2b）：离线目录 或 CTFd。
//
// 两种来源都在"把附件放到本地"这一步收口——因为工具只回路径、不回正文：
// 模型需要内容时用 Read 自己读，这样上下文里只付一次摘要的钱。

const (
	envCTFChallengeDir = "CTF_CHALLENGE_DIR"
	// 离线题面目录里这几个文件承载元信息，不进附件列表。
	chalNameFile    = "name.txt"
	chalDescFiles   = "README.md" // 也接受 description.md / description.txt
	chalConnFile    = "connection.txt"
	chalMaxDownload = 256 << 20
)

// offlineChallengeSource 从本地目录读题面。
//
// 目录约定（写在文档里，别再发明第二套）：
//
//	<dir>/name.txt          可选，题目名（缺省用目录名）
//	<dir>/README.md         可选，题面正文（也接受 description.md / description.txt）
//	<dir>/connection.txt    可选，实例地址/连接方式
//	<dir>/*                 其余文件都当附件（递归）
type offlineChallengeSource struct {
	root string
	// guestRoot 非空时，返回的 Dir 与 Files[].Path 会映射到容器内的该挂载点
	// （见 sandbox_mounts.go 的长注释：这是"Serve 给模型的路径必须是模型能打开的路径"）。
	guestRoot string
}

func (s offlineChallengeSource) Fetch(_ context.Context, challengeID string) (*agent.CTFChallenge, error) {
	dir := s.root
	if challengeID != "" {
		// 只在目标子目录**确实是一道题**时才切过去；否则留在 root。
		//
		// 与 List 的判定同源：单题目录下的 `files/` 是附件容器，若照 id 切进去，
		// 模型会拿到一个没有题面的目录。留 root 至少拿到的还是本题。
		if nested := filepath.Join(s.root, challengeID); dirExists(nested) && hasChallengeMeta(nested) {
			dir = nested
		}
	}
	if !dirExists(dir) {
		return nil, fmt.Errorf("题面目录不存在：%s", dir)
	}
	ch := &agent.CTFChallenge{
		// ID 以**实际落到的目录**为准：请求的 id 没切过去时（见上面的注释），
		// 回一个 "files" 会让模型以为自己在解另一道题。
		ID:     filepath.Base(dir),
		Name:   filepath.Base(dir),
		Dir:    dir,
		Resets: -1, // 离线目录不提供重置次数
		Source: "offline",
	}
	if v := readSmallFile(filepath.Join(dir, chalNameFile)); v != "" {
		ch.Name = v
	}
	for _, cand := range []string{chalDescFiles, "description.md", "description.txt"} {
		if v := readSmallFile(filepath.Join(dir, cand)); v != "" {
			ch.Description = v
			break
		}
	}
	ch.ConnInfo = readSmallFile(filepath.Join(dir, chalConnFile))

	// 复用同一份跳过表（而不是在这里再写一遍）：早期版本在这里硬编码了一份，
	// 于是 offlineMetaFiles 后来加的过滤（比如答案文件）对这里不生效 ——
	// 实测就是附件列表里出现了 /chal/flag.txt。
	if files, err := listChallengeFiles(dir, offlineMetaFiles()); err == nil {
		ch.Files = files
	}
	// 路径映射放在最后统一做：中途任何一步都还在用宿主路径（读文件、列目录），
	// 只有"要交给模型"的那一刻才切换视角。
	if s.guestRoot != "" {
		ch.Dir = guestChallengePath(s.root, dir)
		for i := range ch.Files {
			ch.Files[i].Path = guestChallengePath(s.root, ch.Files[i].Path)
		}
	}
	return ch, nil
}

// ctfdChallengeSource 从 CTFd 拉题面并下载附件。
type ctfdChallengeSource struct {
	base  string
	token string
	// workDir 是落盘根目录（<data>/chal/<taskID>）。
	workDir string
	hc      *http.Client
}

func (s ctfdChallengeSource) Fetch(ctx context.Context, challengeID string) (*agent.CTFChallenge, error) {
	id := strings.TrimSpace(challengeID)
	if id == "" {
		return nil, fmt.Errorf("CTFd 模式必须给题目 id")
	}
	body, err := s.get(ctx, "/api/v1/challenges/"+url.PathEscape(id))
	if err != nil {
		return nil, err
	}
	var resp struct {
		Data struct {
			Name           string   `json:"name"`
			Category       string   `json:"category"`
			Description    string   `json:"description"`
			ConnectionInfo string   `json:"connection_info"`
			Files          []string `json:"files"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("CTFd 响应解析失败：%w", err)
	}
	ch := &agent.CTFChallenge{
		ID: id, Name: resp.Data.Name, Category: resp.Data.Category,
		Description: stripTags(resp.Data.Description),
		ConnInfo:    resp.Data.ConnectionInfo,
		Resets:      -1, // CTFd 标准 API 不暴露重置次数，不编数字
		Source:      "ctfd",
	}
	dir := filepath.Join(s.workDir, sanitizePath(id))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("创建附件目录失败：%w", err)
	}
	ch.Dir = dir
	for _, p := range resp.Data.Files {
		name := filepath.Base(p)
		if name == "" || name == "." || name == "/" {
			continue
		}
		dst := filepath.Join(dir, sanitizePath(name))
		if err := s.download(ctx, p, dst); err != nil {
			// 单个附件失败不该让整个题面拉取失败：记进 Files 的空路径由调用方忽略，
			// 但这里选择直接跳过并继续，避免"一个 404 附件毁掉整道题"。
			continue
		}
		fi, err := os.Stat(dst)
		if err != nil {
			continue
		}
		ch.Files = append(ch.Files, agent.CTFChallengeFile{Name: name, Path: dst, Bytes: fi.Size()})
	}
	return ch, nil
}

func (s ctfdChallengeSource) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.base+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Token "+s.token)
	resp, err := s.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CTFd 返回 HTTP %d：%s", resp.StatusCode, snippetBytes(body))
	}
	return body, nil
}

func (s ctfdChallengeSource) download(ctx context.Context, path, dst string) error {
	u := path
	if !strings.HasPrefix(u, "http") {
		u = s.base + "/" + strings.TrimPrefix(path, "/")
	}
	// CTFd 的附件常需要 token 才能下（/files/... 端点）
	sep := "?"
	if strings.Contains(u, "?") {
		sep = "&"
	}
	full := u + sep + "token=" + url.QueryEscape(s.token)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Token "+s.token)
	resp, err := s.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("附件下载 HTTP %d", resp.StatusCode)
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, io.LimitReader(resp.Body, chalMaxDownload))
	return err
}

// ctfChallengeSourceFor 按任务解析题面来源；都没有则返回 nil（工具明确报不可用）。
func (s *Server) ctfChallengeSourceFor(t *Task) agent.CTFChallengeSource {
	if t == nil || t.Domain != "ctf" {
		return nil
	}
	// 离线目录优先：它不需要网络，测试与基准都靠它。
	//
	// guestRoot 只在"Bash 真的跑在任务容器里"时才设：这时题面目录会被只读挂到
	// /chal（见 taskMountsFor），交给模型的路径必须跟着换视角。
	// 宿主执行模式（sandbox=off / optional 降级）下宿主路径本来就是可用的，映射反而会错。
	if root := s.taskChallengeDir(t); root != "" {
		guest := ""
		if SandboxPerTaskActive() {
			guest = challengeMountTarget
		}
		return offlineChallengeSource{root: root, guestRoot: guest}
	}
	// 再尝试 CTFd（复用判题那边的 URL/Token 配置）
	base := settingOr(s.m.pg, "ctf.ctfd_url", "")
	if base == "" {
		base = config.Env(envCTFCTFdURL)
	}
	token := settingOr(s.m.pg, "ctf.ctfd_token", "")
	if token == "" {
		token = config.Env(envCTFCTFdToken)
	}
	if base != "" && token != "" {
		return ctfdChallengeSource{
			base:    strings.TrimRight(base, "/"),
			token:   token,
			workDir: filepath.Join(s.m.dir, "chal", t.ID),
			hc:      &http.Client{Timeout: 30 * time.Second},
		}
	}
	return nil
}

// ---- 小工具 ----

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// readSmallFile 读一个小文本文件（元信息用）；读不到返回空串。
func readSmallFile(p string) string {
	fi, err := os.Stat(p)
	if err != nil || fi.IsDir() || fi.Size() > 1<<20 {
		return ""
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// listChallengeFiles 递归列出附件（跳过元信息文件），只回路径与大小。
func listChallengeFiles(dir string, skip map[string]bool) ([]agent.CTFChallengeFile, error) {
	var out []agent.CTFChallengeFile
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // 单个文件不可读就跳过，不影响其余附件
		}
		if d.IsDir() {
			return nil
		}
		if skip[d.Name()] {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		out = append(out, agent.CTFChallengeFile{Name: d.Name(), Path: p, Bytes: fi.Size()})
		return nil
	})
	return out, err
}

// stripTags 去掉题面里的 HTML 标签（CTFd 的 description 是 HTML）。
// 不做完整解析：只需要让模型读得下去，正文结构由它自己判断。
func stripTags(s string) string {
	var b strings.Builder
	depth := 0
	for _, r := range s {
		switch r {
		case '<':
			depth++
		case '>':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 {
				b.WriteRune(r)
			}
		}
	}
	out := strings.TrimSpace(b.String())
	// HTML 里的 <br>/<p> 被抹掉后会粘成一行，这里把连续空白收一下
	out = strings.Join(strings.Fields(out), " ")
	return out
}

// sanitizePath 只保留安全字符，防止附件名带 ../ 写穿目录。
func sanitizePath(s string) string {
	s = filepath.Base(strings.ReplaceAll(s, "\\", "/"))
	repl := func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '.' || r == '-' || r == '_':
			return r
		}
		return '_'
	}
	out := strings.Map(repl, s)
	if out == "" || out == "." || out == ".." {
		return "file"
	}
	return out
}
