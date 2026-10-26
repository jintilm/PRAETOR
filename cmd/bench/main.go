// Command bench 跑 XBOW validation-benchmarks 并输出基线分。
//
// 用法：
//
//	go run ./cmd/bench -root /path/to/validation-benchmarks/benchmarks \
//	    -api http://127.0.0.1:8797 -password "$PRAETOR_PASSWORD" -limit 5
//
// 需要：Docker 可用（起靶场）、PRAETOR 已启动且配置了可用的 LLM 配置。
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Autumn-27/praetor/bench/xbow"
)

func main() {
	var (
		root     = flag.String("root", "", "基准库根目录（含 XBEN-* 子目录）")
		api      = flag.String("api", "http://127.0.0.1:8797", "PRAETOR API 基地址")
		token    = flag.String("token", os.Getenv("PRAETOR_BENCH_TOKEN"), "JWT（留空则用 -password 登录获取）")
		password = flag.String("password", os.Getenv("PRAETOR_BENCH_PASSWORD"), "登录密码（仅用于换 token）")
		only     = flag.String("only", "", "只跑这些题目 ID，逗号分隔")
		limit    = flag.Int("limit", 0, "只跑前 N 题（0=全部）")
		taskTO   = flag.Duration("task-timeout", 30*time.Minute, "单题任务超时")
		waitTO   = flag.Duration("wait-timeout", 45*time.Minute, "单题最长等待")
		poll     = flag.Duration("poll", 10*time.Second, "任务状态轮询间隔")
		keep     = flag.Bool("keep", false, "跑完保留靶场容器（排查用）")
		out      = flag.String("out", "", "结果 JSON 输出路径（留空则不写）")
		mdOut    = flag.String("md", "", "Markdown 汇总输出路径（留空则只打印）")
		dryRun   = flag.Bool("dry-run", false, "只列题目，不起靶场")
	)
	flag.Parse()

	if strings.TrimSpace(*root) == "" {
		fmt.Fprintln(os.Stderr, "缺少 -root（基准库 benchmarks 目录）")
		os.Exit(2)
	}

	challenges, err := xbow.Discover(*root)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("发现 %d 道题\n", len(challenges))
	if *dryRun {
		for _, c := range challenges {
			fmt.Printf("  %-16s %s\n", c.ID, c.Name)
		}
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	client := xbow.NewHTTPClient(*api, *token)
	if *token == "" {
		if *password == "" {
			fatal(fmt.Errorf("需要 -token 或 -password（也可用环境变量 PRAETOR_BENCH_TOKEN/PASSWORD）"))
		}
		tk, err := login(ctx, *api, *password)
		if err != nil {
			fatal(fmt.Errorf("登录失败: %w", err))
		}
		client.Token = tk
	}

	var ids []string
	if s := strings.TrimSpace(*only); s != "" {
		ids = strings.Split(s, ",")
		for i := range ids {
			ids[i] = strings.TrimSpace(ids[i])
		}
	}

	sum, err := xbow.Run(ctx, xbow.Options{
		Root:        *root,
		Only:        ids,
		Limit:       *limit,
		TaskTimeout: *taskTO,
		WaitTimeout: *waitTO,
		Poll:        *poll,
		Keep:        *keep,
		Client:      client,
		Logf:        func(f string, a ...any) { fmt.Printf("  "+f+"\n", a...) },
	})
	if err != nil {
		fatal(err)
	}

	md := sum.Markdown()
	fmt.Println()
	fmt.Println(md)

	if *mdOut != "" {
		if err := os.WriteFile(*mdOut, []byte(md), 0o644); err != nil {
			fatal(err)
		}
		fmt.Printf("Markdown 已写入 %s\n", *mdOut)
	}
	if *out != "" {
		b, _ := json.MarshalIndent(sum, "", "  ")
		if err := os.WriteFile(*out, b, 0o644); err != nil {
			fatal(err)
		}
		fmt.Printf("结果 JSON 已写入 %s\n", *out)
	}
}

// login 走单用户登录换 JWT（用户名是固定的 PRAETOR）。
func login(ctx context.Context, api, password string) (string, error) {
	body, _ := json.Marshal(map[string]string{"username": "PRAETOR", "password": password})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(api, "/")+"/api/auth/login", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", err
	}
	if out.Token == "" {
		return "", fmt.Errorf("登录响应没有 token: %s", strings.TrimSpace(string(raw)))
	}
	return out.Token, nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "错误:", err)
	os.Exit(1)
}
