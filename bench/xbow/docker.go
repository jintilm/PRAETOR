package xbow

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// Docker 负责靶场起停。抽成接口是为了让 Run 的编排逻辑能在无 Docker 环境单测。
type Docker interface {
	// Up 起靶场并返回可访问的基地址（如 http://127.0.0.1:32768）。project 用作 compose 项目名。
	Up(ctx context.Context, ch Challenge, project string) (baseURL string, err error)
	// Down 停掉并清理（含卷），保证题间不串数据。
	Down(ctx context.Context, ch Challenge, project string) error
}

// ComposeCLI 用本机 docker 命令起停靶场。
type ComposeCLI struct {
	// Run 是可注入的命令执行缝（参数为 docker 之后的参数），默认走 exec.CommandContext。
	Run func(ctx context.Context, args ...string) (stdout, stderr string, code int, err error)
}

func (c *ComposeCLI) run(ctx context.Context, args ...string) (string, string, int, error) {
	if c != nil && c.Run != nil {
		return c.Run(ctx, args...)
	}
	cmd := exec.CommandContext(ctx, "docker", args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
			return out.String(), errb.String(), code, nil
		}
		return out.String(), errb.String(), -1, err
	}
	return out.String(), errb.String(), code, nil
}

// Up 执行 `docker compose -p <project> up -d --wait`，再从 ps 里解析发布端口。
func (c *ComposeCLI) Up(ctx context.Context, ch Challenge, project string) (string, error) {
	file := composeFile(ch.Dir)
	stdout, stderr, code, err := c.run(ctx, "compose", "-p", project, "-f", file, "up", "-d", "--wait")
	if err != nil {
		return "", fmt.Errorf("compose up 失败: %w (%s)", err, strings.TrimSpace(stderr))
	}
	if code != 0 {
		return "", fmt.Errorf("compose up 退出码 %d: %s", code, trimErr(stderr, stdout))
	}
	psOut, psErr, psCode, perr := c.run(ctx, "compose", "-p", project, "-f", file, "ps", "--format", "json")
	if perr != nil || psCode != 0 {
		return "", fmt.Errorf("compose ps 失败: %v %s", perr, strings.TrimSpace(psErr))
	}
	port, err := FirstHTTPPort([]byte(psOut))
	if err != nil {
		return "", err
	}
	return "http://127.0.0.1:" + strconv.Itoa(port), nil
}

// Down 执行 `down -v`（连卷一起删）。失败只记错误、不阻断后续题目。
func (c *ComposeCLI) Down(ctx context.Context, ch Challenge, project string) error {
	stdout, stderr, code, err := c.run(ctx, "compose", "-p", project, "-f", composeFile(ch.Dir), "down", "-v", "--remove-orphans")
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("compose down 退出码 %d: %s", code, trimErr(stderr, stdout))
	}
	return nil
}

func composeFile(dir string) string {
	if p := filepath.Join(dir, "docker-compose.yml"); fileExists(p) {
		return p
	}
	return filepath.Join(dir, "compose.yml")
}

func trimErr(stderr, stdout string) string {
	s := strings.TrimSpace(stderr)
	if s == "" {
		s = strings.TrimSpace(stdout)
	}
	// 截尾不截头：compose/docker 的失败原因几乎总在最后几行（前面是构建进度）。
	if len(s) > 600 {
		s = "…" + s[len(s)-600:]
	}
	return s
}

// portRecord 兼容 `docker compose ps --format json` 的两种输出：
// 单行 JSON 数组（compose v2.20+）与逐行 JSON 对象（旧版）。
type portRecord struct {
	Service    string `json:"Service"`
	State      string `json:"State"`
	Publishers []struct {
		URL           string `json:"URL"`
		TargetPort    int    `json:"TargetPort"`
		PublishedPort int    `json:"PublishedPort"`
		Protocol      string `json:"Protocol"`
	} `json:"Publishers"`
}

// FirstHTTPPort 从 compose ps 输出里挑一个宿主端口。
//
// 优先级：目标端口是常见 web 端口（80/8080/3000/5000/8000/8888）的；其次取最小的发布端口。
// 之所以挑而不是「取第一个」：一道题常有 db + web 两个服务，取错端口会把 agent 指向数据库。
func FirstHTTPPort(psJSON []byte) (int, error) {
	records, err := parsePS(psJSON)
	if err != nil {
		return 0, err
	}
	preferred := map[int]bool{80: true, 8080: true, 3000: true, 5000: true, 8000: true, 8888: true}
	best, fallback := 0, 0
	for _, r := range records {
		for _, p := range r.Publishers {
			if p.PublishedPort <= 0 || (p.Protocol != "" && p.Protocol != "tcp") {
				continue
			}
			if preferred[p.TargetPort] {
				if best == 0 || p.PublishedPort < best {
					best = p.PublishedPort
				}
				continue
			}
			if fallback == 0 || p.PublishedPort < fallback {
				fallback = p.PublishedPort
			}
		}
	}
	if best > 0 {
		return best, nil
	}
	if fallback > 0 {
		return fallback, nil
	}
	return 0, fmt.Errorf("靶场没有发布任何 TCP 端口（检查 docker-compose.yml 的 ports）")
}

func parsePS(b []byte) ([]portRecord, error) {
	t := strings.TrimSpace(string(b))
	if t == "" {
		return nil, fmt.Errorf("compose ps 输出为空")
	}
	if strings.HasPrefix(t, "[") {
		var arr []portRecord
		if err := json.Unmarshal([]byte(t), &arr); err != nil {
			return nil, fmt.Errorf("解析 compose ps: %w", err)
		}
		return arr, nil
	}
	var out []portRecord
	for _, line := range strings.Split(t, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var r portRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return nil, fmt.Errorf("解析 compose ps 行: %w", err)
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("compose ps 没有返回服务")
	}
	return out, nil
}
