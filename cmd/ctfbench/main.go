// ctfbench 是 CTF 域的基准跑分 CLI（P2-4）。
//
// 用法：
//
//	go run ./cmd/ctfbench -root /path/to/challenges -password "$PRAETOR_PASSWORD" -limit 5 -md report.md
//
// 题目目录约定见 bench/ctf 包注释：每个子目录至少要有 flag.txt（期望 flag），
// 没有的目录不会进分母（避免"判不了的题"把分数拉低）。
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jintilm/praetor/bench/ctf"
)

func main() {
	var (
		root     = flag.String("root", "", "题目根目录（每个子目录一道题）")
		api      = flag.String("api", "http://127.0.0.1:8797", "PRAETOR API 地址")
		token    = flag.String("token", "", "直接给 JWT（优先于 -password）")
		password = flag.String("password", "", "登录密码（用固定用户名 PRAETOR 换 JWT）")
		only     = flag.String("only", "", "只跑这些题目 ID，逗号分隔")
		limit    = flag.Int("limit", 0, "只跑前 N 题（0=全部）")
		taskTO   = flag.Duration("task-timeout", 30*time.Minute, "单题任务超时")
		waitTO   = flag.Duration("wait-timeout", 35*time.Minute, "本机等待上限")
		poll     = flag.Duration("poll", 15*time.Second, "轮询间隔")
		// 默认开：题目自带 compose 却没起，靶场就是死的，模型再强也解不出——
		// 那种"未解出"是跑分器的错，不是模型的分。题目目录没有 compose 文件时此项无影响。
		compose    = flag.Bool("compose", true, "起/停题目自带的 docker compose")
		keep       = flag.Bool("keep", false, "保留靶场（排查用）")
		order      = flag.String("order", "auto", "排序策略：auto（按预算紧松自动）/ easy-first / value-first / asis（目录顺序，对照组）")
		budget     = flag.Int64("budget", 0, "整轮 token 预算（0=不限）；装不下的题会跳过并写明原因")
		mdPath     = flag.String("md", "", "Markdown 报告输出路径")
		jsonPath   = flag.String("out", "", "JSON 结果输出路径")
		dryRun     = flag.Bool("dry-run", false, "只列题，不跑")
		importFrom = flag.String("import", "", "从 Cybench 仓库根导入题目到 -root 后退出（题目目录约定见 bench/ctf）")
	)
	flag.Parse()

	if strings.TrimSpace(*root) == "" {
		fatal(fmt.Errorf("-root 必填（题目根目录）"))
	}

	// 导入是准备步骤：做完了就退出，不要顺手开始烧 token。
	// 题库不进仓库（来源与许可见文档），所以"先导入"是跑分的第一步。
	if src := strings.TrimSpace(*importFrom); src != "" {
		ids, err := ctf.ImportCybench(src, *root)
		if err != nil {
			fatal(err)
		}
		fmt.Printf("导入 %d 道题 → %s\n", len(ids), *root)
		for _, id := range ids {
			fmt.Printf("  %s\n", id)
		}
		return
	}

	challenges, err := ctf.Discover(*root)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("发现 %d 道可判分的题（子目录含 flag.txt）\n", len(challenges))
	if *dryRun {
		for _, c := range challenges {
			note := ""
			if c.HasCompose {
				note = " [compose]"
			}
			fmt.Printf("  %-24s %s%s\n", c.ID, c.Name, note)
		}
		return
	}
	if len(challenges) == 0 {
		fatal(fmt.Errorf("没有可跑的题：每个题目录里需要有 flag.txt"))
	}

	tk := strings.TrimSpace(*token)
	if tk == "" {
		if strings.TrimSpace(*password) == "" {
			fatal(fmt.Errorf("需要 -token 或 -password（用于登录换 JWT）"))
		}
		tk, err = ctf.Login(context.Background(), *api, *password)
		if err != nil {
			fatal(err)
		}
	}

	var ids []string
	if s := strings.TrimSpace(*only); s != "" {
		for _, part := range strings.Split(s, ",") {
			if p := strings.TrimSpace(part); p != "" {
				ids = append(ids, p)
			}
		}
	}

	client := ctf.NewHTTPClient(*api, tk)
	sum, err := ctf.Run(context.Background(), ctf.Options{
		Root: *root, Only: ids, Limit: *limit,
		TaskTimeout: *taskTO, WaitTimeout: *waitTO, Poll: *poll,
		Compose: *compose, Keep: *keep, Client: client,
		Order: *order, TokenBudget: *budget,
		Logf: func(f string, a ...any) { fmt.Printf("  "+f+"\n", a...) },
	})
	if err != nil {
		fatal(err)
	}

	md := sum.Markdown()
	fmt.Println()
	fmt.Println(md)
	if err := ctf.WriteReport(*mdPath, md); err != nil {
		fatal(err)
	}
	if strings.TrimSpace(*jsonPath) != "" {
		b, _ := json.MarshalIndent(sum, "", "  ")
		if err := os.WriteFile(*jsonPath, b, 0o644); err != nil {
			fatal(err)
		}
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "错误:", err)
	os.Exit(1)
}
