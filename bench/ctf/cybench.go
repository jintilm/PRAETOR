package ctf

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// 本文件把 **Cybench**（Apache-2.0）的题目目录转成跑分器认的离线约定。
//
// 为什么需要转换而不是直接读 Cybench：跑分器只认一件事——每题目录里有 `flag.txt`。
// Cybench 没有这个文件：它在 `metadata/metadata.json` 里用 subtasks 描述答案，
// 最后一问的 answer 才是完整 flag。判分口径必须落在我们这边，不能"读题库猜答案"。
//
// 纪律：
//  1. **flag 只进 flag.txt，绝不进 prompt**：Cybench 的 easy_prompt/hard_prompt 里没有 flag，
//     但导入时仍然显式剥一遍 subtask 的 answer —— 题库换版本时不该把泄题风险带进来；
//  2. 目标地址为空 = 离线题（挂 attachments）；不为空 = 需要起靶场的题，
//     导入时只记端口，不猜地址（起法见 runner 的 compose 逻辑）；
//  3. 导入是**幂等**的：同一个题库目录重复导入结果一致（可用来刷新）。
type cybenchMeta struct {
	Categories []string `json:"categories"`
	Difficulty string   `json:"difficulty"`
	EasyPrompt string   `json:"easy_prompt"`
	HardPrompt string   `json:"hard_prompt"`
	TargetHost string   `json:"target_host"`
	Subtasks   []struct {
		Subtask string `json:"subtask"`
		Answer  string `json:"answer"`
	} `json:"subtasks"`
}

// ImportCybench 把 src 下的全部题目导入 dst（每题一个子目录）。
//
// src 是 clone 出来的仓库根（含 `benchmark/`）。返回导入的题目 ID 列表（有序）。
func ImportCybench(src, dst string) ([]string, error) {
	root := filepath.Join(src, "benchmark")
	if st, err := os.Stat(root); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("不是 Cybench 仓库根（缺 benchmark/ 目录）：%s", src)
	}
	var metas []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // 单个目录读不了不该让整轮导入失败
		}
		if info.IsDir() || info.Name() != "metadata.json" {
			return nil
		}
		// 只认 `<challenge>/metadata/metadata.json`：仓库里另有同名文件（模板/测试），
		// 按形状挑比按路径白名单稳。
		if filepath.Base(filepath.Dir(path)) == "metadata" {
			metas = append(metas, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(metas) == 0 {
		return nil, fmt.Errorf("没找到任何 <challenge>/metadata/metadata.json：题库目录不对？")
	}
	sort.Strings(metas)

	var done []string
	for _, mp := range metas {
		chalDir := filepath.Dir(filepath.Dir(mp))
		id, err := importOne(chalDir, mp, dst)
		if err != nil {
			// 一道题导入失败不该拖死整轮：记下来，继续下一题。
			fmt.Fprintf(os.Stderr, "跳过 %s：%v\n", filepath.Base(chalDir), err)
			continue
		}
		done = append(done, id)
	}
	return done, nil
}

var unsafeSlug = regexp.MustCompile(`[^a-z0-9]+`)

// slug 生成稳定的题目 ID：`<赛事>-<分类>-<题目>`，全小写。
//
// 为什么不用路径原文：路径里有空格、方括号、大写，进 URL/报告表格都要转义；
// 而 ID 是判分记录（ctf_submissions.challenge_id）的一部分，越稳越好。
func slug(chalDir, root string) string {
	rel, err := filepath.Rel(root, chalDir)
	if err != nil {
		rel = filepath.Base(chalDir)
	}
	rel = strings.ToLower(filepath.ToSlash(rel))
	return strings.Trim(unsafeSlug.ReplaceAllString(rel, "-"), "-")
}

func importOne(chalDir, metaPath, dst string) (string, error) {
	raw, err := os.ReadFile(metaPath)
	if err != nil {
		return "", err
	}
	var m cybenchMeta
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", fmt.Errorf("metadata.json 解析失败：%w", err)
	}
	flag := pickFlag(m)
	if flag == "" {
		return "", fmt.Errorf("metadata 里找不到 flag（subtasks 全空）")
	}
	root := filepath.Dir(filepath.Dir(filepath.Dir(metaPath))) // <src>/benchmark
	id := slug(chalDir, root)
	out := filepath.Join(dst, id)
	if err := os.MkdirAll(out, 0o755); err != nil {
		return "", err
	}

	// flag.txt：判分的唯一依据
	if err := os.WriteFile(filepath.Join(out, "flag.txt"), []byte(flag+"\n"), 0o644); err != nil {
		return "", err
	}

	// name.txt：题目原名（报告里给人看）
	name := filepath.Base(chalDir)
	if err := os.WriteFile(filepath.Join(out, "name.txt"), []byte(name+"\n"), 0o644); err != nil {
		return "", err
	}

	// README.md：题面。硬提示优先（Cybench 的 hard_prompt 是"不给过程提示"的版本，
	// 更接近真实比赛题面）。**绝不写 subtask answer**。
	prompt := strings.TrimSpace(m.HardPrompt)
	if prompt == "" {
		prompt = strings.TrimSpace(m.EasyPrompt)
	}
	prompt = stripAnswers(prompt, m)
	// 题面里说的"parent directory"在我们的约定里是 files/ 子目录：
	// 不写清楚，模型会在工作目录里瞎找，或者干脆以为没给附件。
	if prompt != "" {
		prompt = "附件在 `files/` 目录下（若有）。\n\n" + prompt
	}
	if prompt != "" {
		if err := os.WriteFile(filepath.Join(out, "README.md"), []byte(prompt+"\n"), 0o644); err != nil {
			return "", err
		}
	}

	// connection.txt：有靶场的题才写
	if th := strings.TrimSpace(m.TargetHost); th != "" {
		if err := os.WriteFile(filepath.Join(out, "connection.txt"), []byte(th+"\n"), 0o644); err != nil {
			return "", err
		}
	}

	// meta.json：只影响排序（分值/难度），不影响判分
	diff, _ := parseDifficulty(m.Difficulty)
	meta := map[string]any{
		"category":   firstNonEmpty(m.Categories),
		"points":     difficultyPoints(diff),
		"difficulty": diff,
		"source":     "cybench",
	}
	if b, err := json.MarshalIndent(meta, "", "  "); err == nil {
		_ = os.WriteFile(filepath.Join(out, "meta.json"), append(b, '\n'), 0o644)
	}

	// 附件：challenge/ 与 release/ 复制到 files/（题面里说的"parent directory"）。
	// 复制而不是软链：跑分时题目目录会被拷进沙箱工作目录，软链会断。
	//
	// 两个来源都要：HTB 系列把可下发的东西放在 release/*.zip，而纯本地题放在 challenge/。
	// 少了任一个，模型拿到的题面就会指向一个不存在的文件。
	for _, sub := range []string{"challenge", "release"} {
		if err := copyDir(filepath.Join(chalDir, sub), filepath.Join(out, "files", sub)); err != nil {
			return "", fmt.Errorf("复制附件失败：%w", err)
		}
	}
	// 少数题把靶场起法放在题目根上（docker-compose.yml / init_script.sh）
	for _, f := range []string{"docker-compose.yml", "compose.yml", "init_script.sh", "requirements.sh"} {
		if err := copyFile(filepath.Join(chalDir, f), filepath.Join(out, f)); err != nil {
			return "", err
		}
	}
	return id, nil
}

// pickFlag 取**最后一个** subtask 的 answer：Cybench 用 subtasks 表示解题步骤，
// 最后一问是"拿到完整 flag"。靠形状而不是"有没有 flag 字段"——
// 实测 metadata 里没有 flag 字段，全是 subtasks。
func pickFlag(m cybenchMeta) string {
	for i := len(m.Subtasks) - 1; i >= 0; i-- {
		a := strings.TrimSpace(m.Subtasks[i].Answer)
		// 只要长得像 flag 的（xx{...}）：有的题最后一步答案是"yes"或一串数字
		if strings.Contains(a, "{") && strings.HasSuffix(a, "}") {
			return a
		}
	}
	return ""
}

// stripAnswers 把题面里可能出现的答案串抹掉。
//
// 理论上 prompt 里不该有答案，但题库是外部数据：上一版就出现过把 answer 拼进 prompt 的写法。
// 泄漏一次，那道题的分数就永久不可信，所以这里宁可多花一次替换。
func stripAnswers(prompt string, m cybenchMeta) string {
	for _, st := range m.Subtasks {
		a := strings.TrimSpace(st.Answer)
		if len(a) < 6 {
			continue
		}
		prompt = strings.ReplaceAll(prompt, a, "<redacted>")
	}
	return prompt
}

// parseDifficulty 把 Cybench 的难度串转成 0..3（0=Very Easy）。
func parseDifficulty(s string) (int, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "0", "very easy", "veryeasy":
		return 0, true
	case "1", "easy":
		return 1, true
	case "2", "medium":
		return 2, true
	case "3", "hard", "very hard":
		return 3, true
	}
	return 0, false
}

// difficultyPoints 给排序用的分值。Cybench 没有真实分数，所以只表达相对难度：
// 拿分多少不影响判分，只影响 ctfplan 的"先做哪道"。
func difficultyPoints(d int) int {
	switch d {
	case 0:
		return 100
	case 1:
		return 200
	case 2:
		return 300
	default:
		return 500
	}
}

func firstNonEmpty(ss []string) string {
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

// isFlagArtifact 判断是不是"expected flag"的文件。
//
// **必须跳过**：HTB 系列的 challenge/ 目录里就放着一份 flag.txt（给本地自测用的），
// 原样复制进 attachments 等于把答案塞给模型 —— 那样这题的分永远不可信。
func isFlagArtifact(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	return base == "flag.txt" || base == "flag"
}

func copyDir(src, dst string) error {
	st, err := os.Stat(src)
	if err != nil || !st.IsDir() {
		return nil // 没有附件目录是正常的（纯网络题）
	}
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && isFlagArtifact(path) {
			return nil
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		return copyFile(path, target)
	})
}

func copyFile(src, dst string) error {
	st, err := os.Stat(src)
	if err != nil || st.IsDir() {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, st.Mode().Perm())
}
