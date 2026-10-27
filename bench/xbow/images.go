package xbow

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// fromRe 抓 Dockerfile 里的 FROM 指令（取第一个字段后的镜像名，去掉 --platform / AS 别名）。
var fromRe = regexp.MustCompile(`(?im)^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)`)

// PrepareImages 预拉题目依赖的基础镜像。
//
// 为什么需要它（实测踩到的坑）：本机 Docker Desktop 代理只覆盖 `docker pull`，
// **buildkit 拉取基础镜像时的 token 请求不走代理**，于是这类报错会出现在 9/10 道题上：
//
//	failed to fetch anonymous token: Get "https://auth.docker.io/token?...": Bad Gateway
//
// 而 buildkit 在**本地已有该镜像**时直接复用，不会再请求 token（实测：预拉
// python:3.12 后同一道题的 build 立刻成功）。所以「先 pull 基础镜像、再 build」
// 是绕开这条网络限制的最省事办法，且不改变题目本身。
//
// 返回成功预拉的数量与失败明细；失败不阻断——题目可能本来就只需本地镜像。
func PrepareImages(ctx context.Context, chs []Challenge, logf func(string, ...any)) (int, []string) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	imgs := map[string]bool{}
	for _, ch := range chs {
		for _, img := range challengeImages(ch.Dir) {
			imgs[img] = true
		}
	}
	if len(imgs) == 0 {
		return 0, nil
	}
	var (
		mu     sync.Mutex
		ok     int
		failed []string
		wg     sync.WaitGroup
		sem    = make(chan struct{}, 4) // 并发 4：别把代理/带宽打满
	)
	for img := range imgs {
		wg.Add(1)
		go func(img string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			logf("预拉镜像 %s…", img)
			out, err := exec.CommandContext(ctx, "docker", "pull", img).CombinedOutput()
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				msg := strings.TrimSpace(string(out))
				if len(msg) > 200 {
					msg = msg[len(msg)-200:]
				}
				failed = append(failed, fmt.Sprintf("%s: %s", img, msg))
				logf("  拉取失败 %s（继续）", img)
				return
			}
			ok++
		}(img)
	}
	wg.Wait()
	return ok, failed
}

// challengeImages 解析一道题里所有 Dockerfile 的 FROM 基础镜像（去重）。
//
// 遍历范围为「题干目录 + 一级子目录」（app/ mysql/ web/ …）——题库的布局就是
// 每个 service 一个子目录。不递归太深是为了不误抓题目自带的示例/文档里的
// Dockerfile 片段。
func challengeImages(dir string) []string {
	var files []string
	// 题干目录自身
	if p := filepath.Join(dir, "Dockerfile"); fileExists(p) {
		files = append(files, p)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if p := filepath.Join(dir, e.Name(), "Dockerfile"); fileExists(p) {
			files = append(files, p)
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			m := fromRe.FindStringSubmatch(sc.Text())
			if len(m) != 2 {
				continue
			}
			img := m[1]
			// 跳过 build 阶段引用（FROM base AS builder 的第二段已由 m[1] 排除；
			// 但 `FROM builder` 这种多阶段引用会指向本地阶段名，pull 会失败）。
			if !strings.Contains(img, "/") && !strings.Contains(img, ":") {
				continue
			}
			if img == "scratch" || seen[img] {
				continue
			}
			seen[img] = true
			out = append(out, img)
		}
		_ = fh.Close()
	}
	return out
}
