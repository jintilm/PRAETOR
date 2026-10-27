// Command sandboximg 把「可选组件预置」构建成沙箱镜像。
//
// 面板里点一次也会走同一份清单（internal/components），这个 CLI 存在的理由是**没有面板也能构建**：
// CI、远程机器、以及"我只想先看看 Dockerfile 长什么样"的时候。
//
// 与面板的区别只有一处：面板会把结果写进 settings（决定后续任务用哪个镜像），
// CLI 只构建、不改变任何运行时配置 —— 改配置是有副作用的动作，不该藏在构建命令里。
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/jintilm/praetor/internal/components"
)

func main() {
	var (
		presetID = flag.String("preset", "", "预置 ID（见 -list）")
		ids      = flag.String("ids", "", "直接给组件 ID（逗号分隔），与 -preset 二选一")
		out      = flag.String("out", "", "把 Dockerfile 写到该路径（默认打印到 stdout）")
		build    = flag.Bool("build", false, "真的执行 docker build")
		list     = flag.Bool("list", false, "列出预置与组件后退出")
		tag      = flag.String("tag", "", "覆盖镜像 tag（默认按组件集合算稳定 tag）")
	)
	flag.Parse()

	if *list {
		for _, p := range components.Presets() {
			items, err := components.PresetItems(p.ID)
			if err != nil {
				fmt.Printf("%-14s 展开失败：%v\n", p.ID, err)
				continue
			}
			mb := 0
			for _, it := range items {
				mb += it.SizeMB
			}
			fmt.Printf("%-14s %-40s %d 项 ≈ %dMB\n    %s\n", p.ID, p.Title, len(items), mb, p.Why)
		}
		return
	}

	items, err := resolve(*presetID, *ids)
	if err != nil {
		fatal(err.Error())
	}
	imageTag := components.ImageTag(items)
	if strings.TrimSpace(*tag) != "" {
		imageTag = strings.TrimSpace(*tag)
	}

	df := components.RenderDockerfile(items)
	if *out != "" {
		if err := os.WriteFile(*out, []byte(df), 0o644); err != nil {
			fatal("写 Dockerfile 失败：" + err.Error())
		}
		fmt.Printf("Dockerfile → %s\n", *out)
	} else if !*build {
		fmt.Print(df)
		return
	}

	if !*build {
		fmt.Printf("镜像 tag：%s（加 -build 才会真的构建）\n", imageTag)
		return
	}
	if err := runBuild(df, imageTag); err != nil {
		fatal(err.Error())
	}
}

// resolve 取组件：预置优先，其次显式 ID。两者都为空时明确报错而不是构建一个空镜像。
func resolve(presetID, ids string) ([]components.Item, error) {
	switch {
	case strings.TrimSpace(presetID) != "":
		return components.PresetItems(presetID)
	case strings.TrimSpace(ids) != "":
		var list []string
		for _, s := range strings.Split(ids, ",") {
			if s = strings.TrimSpace(s); s != "" {
				list = append(list, s)
			}
		}
		return components.Validate(list)
	default:
		return nil, fmt.Errorf("必须给 -preset 或 -ids（用 -list 看可选项）")
	}
}

// runBuild 在标准输入里喂 Dockerfile，避免往仓库里落一个临时文件。
func runBuild(dockerfile, tag string) error {
	cmd := exec.Command("docker", "build", "-t", tag, "-f", "-", ".")
	cmd.Stdin = strings.NewReader(dockerfile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	fmt.Printf("构建 %s（%d 行 Dockerfile）…\n", tag, strings.Count(dockerfile, "\n"))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker build 失败：%w", err)
	}
	fmt.Printf("完成：%s\n", tag)
	return nil
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}
