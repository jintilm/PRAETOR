package ctf

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Options 控制一次跑分。
type Options struct {
	Root        string
	Only        []string
	Limit       int
	TaskTimeout time.Duration // 单题任务超时（传给 PRAETOR）
	WaitTimeout time.Duration // 本机等待上限（防止任务卡住时跑分挂死）
	Poll        time.Duration
	Compose     bool // 是否起/停题目自带的 docker compose
	Keep        bool // 保留靶场（排查用）
	Client      Client
	Logf        func(format string, args ...any)
}

// Item 是一道题的跑分结果。
type Item struct {
	ID      string        `json:"id"`
	Name    string        `json:"name"`
	Solved  bool          `json:"solved"`
	TaskID  int64         `json:"task_id,omitempty"`
	Elapsed time.Duration `json:"elapsed_ns"`
	// 成本要和分数一起记：只报分数会让人做出"多路全开"这种账算不过来的优化。
	InputTokens  int64  `json:"input_tokens"`
	OutputTokens int64  `json:"output_tokens"`
	Err          string `json:"err,omitempty"`
	Skipped      bool   `json:"skipped,omitempty"`
	SkipWhy      string `json:"skip_why,omitempty"`
}

// Summary 是一轮跑分的汇总。
type Summary struct {
	Total       int           `json:"total"`
	Solved      int           `json:"solved"`
	Skipped     int           `json:"skipped"`
	InputTokens int64         `json:"input_tokens"`
	OutputToken int64         `json:"output_tokens"`
	Items       []Item        `json:"items"`
	Elapsed     time.Duration `json:"elapsed_ns"`
}

// Score 返回解出率（分母剔除跳过的题）。
func (s *Summary) Score() float64 {
	denom := s.Total - s.Skipped
	if denom <= 0 {
		return 0
	}
	return float64(s.Solved) / float64(denom) * 100
}

// Run 跑一轮基准。
func Run(ctx context.Context, opt Options) (*Summary, error) {
	if opt.Client == nil {
		return nil, fmt.Errorf("缺少 API 客户端")
	}
	if opt.TaskTimeout <= 0 {
		opt.TaskTimeout = 30 * time.Minute
	}
	if opt.WaitTimeout <= 0 {
		opt.WaitTimeout = opt.TaskTimeout + 5*time.Minute
	}
	if opt.Poll <= 0 {
		opt.Poll = 15 * time.Second
	}
	if opt.Logf == nil {
		opt.Logf = func(string, ...any) {}
	}

	all, err := Discover(opt.Root)
	if err != nil {
		return nil, err
	}
	chosen := filter(all, opt.Only, opt.Limit)
	if len(chosen) == 0 {
		return nil, fmt.Errorf("没有可跑的题（root=%s，需要子目录里有 flag.txt）", opt.Root)
	}

	sum := &Summary{Total: len(chosen)}
	start := time.Now()
	for _, ch := range chosen {
		it := runOne(ctx, opt, ch)
		if it.Skipped {
			sum.Skipped++
		}
		if it.Solved {
			sum.Solved++
		}
		sum.InputTokens += it.InputTokens
		sum.OutputToken += it.OutputTokens
		sum.Items = append(sum.Items, it)
		opt.Logf("[%s] solved=%v task=%d elapsed=%s in=%dK %s",
			ch.ID, it.Solved, it.TaskID, it.Elapsed.Round(time.Second), it.InputTokens/1000, it.Err)
	}
	sum.Elapsed = time.Since(start)
	return sum, nil
}

func runOne(ctx context.Context, opt Options, ch Challenge) (it Item) {
	start := time.Now()
	it = Item{ID: ch.ID, Name: ch.Name}
	defer func() { it.Elapsed = time.Since(start) }()

	// 靶场：起得来才继续；起不来不提交任务（省 LLM 调用）
	if opt.Compose && ch.HasCompose {
		if err := composeUp(ctx, ch); err != nil {
			it.Err = "起靶场失败：" + err.Error()
			return it
		}
		if !opt.Keep {
			defer func() { _ = composeDown(context.Background(), ch) }()
		}
	}

	desc, goal := buildPrompt(ch)
	taskID, err := opt.Client.CreateTask(ctx, desc, goal, int(opt.TaskTimeout.Seconds()))
	if err != nil {
		it.Err = "建任务失败：" + err.Error()
		return it
	}
	it.TaskID = taskID
	if err := opt.Client.ConfigureCTF(ctx, taskID, ch.Flag, ch.Dir); err != nil {
		it.Err = "配置判分失败：" + err.Error()
		return it
	}
	opt.Logf("[%s] 任务 #%d 已提交，等待结束…", ch.ID, taskID)

	// 等终态；超时不判解出（但**仍然查一次是否已判对**——模型可能刚好在超时前提交）
	deadline := time.Now().Add(opt.WaitTimeout)
	for {
		done, err := opt.Client.Done(ctx, taskID)
		if err == nil && done {
			break
		}
		if time.Now().After(deadline) {
			it.Err = "等待超时（任务未进终态）"
			break
		}
		select {
		case <-ctx.Done():
			it.Err = "被取消"
			return it
		case <-time.After(opt.Poll):
		}
	}

	// 判分只看平台是否判对——这是唯一口径
	solved, serr := opt.Client.Solved(ctx, taskID)
	if serr != nil {
		if it.Err == "" {
			it.Err = "查询判分失败：" + serr.Error()
		}
		return it
	}
	it.Solved = solved
	// token 用量是"附加信息"：取不到不影响判分，所以失败只丢成本、不改结论。
	if tk, terr := opt.Client.Stats(ctx, taskID); terr == nil {
		it.InputTokens, it.OutputTokens = tk.Input, tk.Output
	}
	if !solved && it.Err == "" {
		it.Err = "未解出"
	}
	return it
}

// buildPrompt 构造任务描述。
//
// 关键：**绝不能把期望 flag 写进提示词**——那等于把答案给模型。
// 题面/附件通过 ctf_challenge 读（工具会落盘并返回路径）。
func buildPrompt(ch Challenge) (desc, goal string) {
	var b strings.Builder
	fmt.Fprintf(&b, "CTF 题目：%s（id=%s）。\n", ch.Name, ch.ID)
	fmt.Fprintf(&b, "题面与附件在本地目录 %s，用 ctf_challenge（id=%s）读取。\n", ch.Dir, ch.ID)
	if conn := readTrim(filepath.Join(ch.Dir, "connection.txt")); conn != "" {
		fmt.Fprintf(&b, "目标地址：%s\n", conn)
	}
	b.WriteString("要求：分析题目并使用工具真实操作目标；拿到 flag 立刻用 ctf_submit 提交（只提交你真实拿到的串）。")
	goal = "解出这道 CTF 题并提交 flag"
	return b.String(), goal
}

func filter(all []Challenge, only []string, limit int) []Challenge {
	if len(only) > 0 {
		want := map[string]bool{}
		for _, id := range only {
			want[id] = true
		}
		var out []Challenge
		for _, ch := range all {
			if want[ch.ID] {
				out = append(out, ch)
			}
		}
		all = out
	}
	if limit > 0 && len(all) > limit {
		all = all[:limit]
	}
	return all
}

// composeUp 起靶场（项目名带前缀，避免与手工栈撞名）。
func composeUp(ctx context.Context, ch Challenge) error {
	file := composeFile(ch.Dir)
	if file == "" {
		return fmt.Errorf("找不到 compose 文件")
	}
	cmd := exec.CommandContext(ctx, "docker", "compose", "-f", file, "-p", "ctfbench-"+strings.ToLower(ch.ID), "up", "-d", "--wait")
	cmd.Dir = ch.Dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, truncate(strings.TrimSpace(string(out)), 400))
	}
	return nil
}

func composeDown(ctx context.Context, ch Challenge) error {
	file := composeFile(ch.Dir)
	cmd := exec.CommandContext(ctx, "docker", "compose", "-f", file, "-p", "ctfbench-"+strings.ToLower(ch.ID), "down", "-v")
	cmd.Dir = ch.Dir
	return cmd.Run()
}

// Markdown 渲染跑分报告。
func (s *Summary) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "## CTF 基线：%.1f%%（%d/%d 解出，跳过 %d）\n\n", s.Score(), s.Solved, s.Total-s.Skipped, s.Skipped)
	fmt.Fprintf(&b, "- 总耗时：%s\n- 总 token：input %.2fM / output %.0fK\n- 判分口径：平台判对（`ctf_submissions.verdict=accepted`），不看任务状态\n\n",
		s.Elapsed.Round(time.Second), float64(s.InputTokens)/1e6, float64(s.OutputToken)/1e3)
	b.WriteString("| 题目 | 结果 | 任务 | 耗时 | input | 备注 |\n| --- | --- | --- | --- | --- | --- |\n")
	for _, it := range s.Items {
		state := "未解出"
		switch {
		case it.Skipped:
			state = "跳过"
		case it.Solved:
			state = "✅ 解出"
		case it.Err != "":
			state = "⚠️ " + it.Err
		}
		task := "-"
		if it.TaskID > 0 {
			task = fmt.Sprintf("#%d", it.TaskID)
		}
		tok := "-"
		if it.InputTokens > 0 {
			tok = fmt.Sprintf("%.2fM", float64(it.InputTokens)/1e6)
		}
		fmt.Fprintf(&b, "| %s %s | %s | %s | %s | %s | %s |\n",
			it.ID, escapeCell(it.Name), state, task, it.Elapsed.Round(time.Second), tok, escapeCell(it.SkipWhy))
	}
	return b.String()
}

func escapeCell(s string) string {
	return strings.ReplaceAll(strings.TrimSpace(s), "|", "\\|")
}

// WriteReport 落盘（Markdown + 可选 JSON 由调用方处理）。
func WriteReport(path, content string) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	return os.WriteFile(path, []byte(content), 0o644)
}
