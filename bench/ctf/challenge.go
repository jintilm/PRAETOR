// Package ctf 是 CTF 域的基准跑分器（P2-4）。
//
// 判分口径只有一条：**平台判对过没有**（`ctf_submissions.verdict=accepted`）。
// 不看任务状态、不看模型自述、不看报告里有没有 flag 字样——那些都能自欺。
//
// 与 xbow 跑分器的区别：CTF 题通常自带靶场（compose）或本身就是静态/离线题，
// 所以这里不猜端口、不做流量来源校验；题目目录用离线约定（见执行文档 §1.18）：
//
//	<dir>/flag.txt        **必需**，期望 flag（没有就没法判分，直接跳过）
//	<dir>/name.txt        可选，题目名
//	<dir>/README.md       可选，题面
//	<dir>/connection.txt  可选，目标地址（起完靶场后模型要打的地方）
//	<dir>/meta.json       可选，分值/解出人数/预估成本（P2-6 排序用；缺省也能跑）
//	<dir>/*               其余当附件
package ctf

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Challenge 是一道可判分的题。
type Challenge struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Dir        string `json:"dir"`
	Flag       string `json:"-"` // 期望 flag：不落盘、不进报告
	HasCompose bool   `json:"has_compose"`
	// 以下三项来自可选的 meta.json，只影响**排序**（先做哪题），不影响判分。
	Category  string `json:"category,omitempty"`
	Points    int    `json:"points,omitempty"`
	Solves    int    `json:"solves,omitempty"`     // -1/0 = 未知
	EstTokens int64  `json:"est_tokens,omitempty"` // 0 = 用分类基线
}

// ErrNoFlag 表示该目录不是一道可判分的题（缺 flag.txt）。
var ErrNoFlag = errors.New("缺少 flag.txt")

// Discover 扫描 root 下的一级子目录，挑出可判分的题（有 flag.txt）。
//
// 为什么跳过没有 flag 的目录而不是报错：题库里常混着题解、脚本、模板目录，
// 一遇到就失败会让跑分没法用。但"有题却判不了"必须显式记入 skipped，不能静默丢。
func Discover(root string) ([]Challenge, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("读题目录失败：%w", err)
	}
	var out []Challenge
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(root, e.Name())
		flag := readTrim(filepath.Join(dir, "flag.txt"))
		if flag == "" {
			continue
		}
		c := Challenge{ID: e.Name(), Dir: dir, Flag: flag}
		c.Name = readTrim(filepath.Join(dir, "name.txt"))
		if c.Name == "" {
			c.Name = firstHeading(filepath.Join(dir, "README.md"))
		}
		if c.Name == "" {
			c.Name = e.Name()
		}
		if fileExists(filepath.Join(dir, "docker-compose.yml")) || fileExists(filepath.Join(dir, "compose.yml")) {
			c.HasCompose = true
		}
		applyMeta(&c, filepath.Join(dir, "meta.json"))
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// applyMeta 读可选的 meta.json（分值/解出人数/预估成本）。
//
// 读坏了就当没有：题库元信息只影响排序策略，不该让整轮跑分失败。
func applyMeta(c *Challenge, path string) {
	raw := readTrim(path)
	if raw == "" {
		return
	}
	var m struct {
		Category  string `json:"category"`
		Points    int    `json:"points"`
		Solves    int    `json:"solves"`
		EstTokens int64  `json:"est_tokens"`
	}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return
	}
	if m.Category != "" {
		c.Category = m.Category
	}
	c.Points = m.Points
	c.Solves = m.Solves
	c.EstTokens = m.EstTokens
}

func readTrim(p string) string {
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

// firstHeading 取 README 的一级标题（没有就用第一行非空文本）。
func firstHeading(p string) string {
	fi, err := os.Stat(p)
	if err != nil || fi.IsDir() || fi.Size() > 1<<20 {
		return ""
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		return strings.TrimSpace(strings.TrimLeft(line, "#"))
	}
	return ""
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// composeFile 返回题目目录里的 compose 文件名。
func composeFile(dir string) string {
	for _, name := range []string{"docker-compose.yml", "compose.yml"} {
		if fileExists(filepath.Join(dir, name)) {
			return filepath.Join(dir, name)
		}
	}
	return ""
}
