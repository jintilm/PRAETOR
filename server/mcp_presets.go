package server

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/Autumn-27/praetor/config"
	"github.com/Autumn-27/praetor/db"
)

// MCP 预设：把「装好一个外部 MCP server」的过程收敛成一次配置，而不是让用户
// 在 UI 里手填 command/args/env（容易填错，且不同机器路径不同）。
//
// 目前只有一个预设：hexstrike（150+ 安全工具的 MCP 封装）。
// 设计原则：**没配置就什么都不写**——绝不往库里塞一条指向不存在路径的记录，
// 那会让 MCP 工具发现阶段反复报错，比没有更糟。

// hexstrikeEnvPrefix 是预设读取的环境变量前缀（config.Env 会补 PRAETOR_）。
const (
	envHexstrikeDir    = "HEXSTRIKE_DIR"    // 含 hexstrike_mcp.py 的目录
	envHexstrikePython = "HEXSTRIKE_PYTHON" // python 可执行文件，默认 python3
	envHexstrikeURL    = "HEXSTRIKE_URL"    // hexstrike_server 地址，默认 http://127.0.0.1:8888
)

const hexstrikeDefaultURL = "http://127.0.0.1:8888"

// hexstrikePreset 构造 hexstrike 的 MCP 服务器记录（纯函数，便于单测）。
//
// hexstrike 的运行方式是「先起一个 HTTP server，再用 stdio 的 MCP 桥接脚本连过去」，
// 所以 transport 用 stdio，args 指向桥接脚本并把 server 地址作为参数传进去。
func hexstrikePreset(dir, python, url string) (*db.MCPServer, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, fmt.Errorf("hexstrike 目录为空")
	}
	if strings.TrimSpace(python) == "" {
		python = "python3"
	}
	if strings.TrimSpace(url) == "" {
		url = hexstrikeDefaultURL
	}
	script := filepath.Join(dir, "hexstrike_mcp.py")
	if st, err := os.Stat(script); err != nil {
		return nil, fmt.Errorf("找不到 %s: %w", script, err)
	} else if st.IsDir() {
		return nil, fmt.Errorf("%s 是目录，不是脚本", script)
	}

	args, _ := json.Marshal([]string{script, "--server", url})
	// 显式给 PYTHONUNBUFFERED，避免 Python 缓冲导致 MCP 握手卡住（stdio 场景常见坑）。
	env, _ := json.Marshal(map[string]string{"PYTHONUNBUFFERED": "1"})

	return &db.MCPServer{
		Name:      "hexstrike",
		Transport: "stdio",
		Command:   python,
		Args:      args,
		Env:       env,
		Enabled:   true,
	}, nil
}

// seedMCPPresets 在启动期播种已配置的 MCP 预设。未配置时只提示一次，不写库。
func seedMCPPresets(pg *db.DB) {
	if pg == nil {
		return
	}
	dir := config.Env(envHexstrikeDir)
	if strings.TrimSpace(dir) == "" {
		log.Printf("[mcp] 未配置 %s，跳过 hexstrike 预设（需要时设该变量指向 hexstrike 仓库目录后重启）",
			"PRAETOR_"+envHexstrikeDir)
		return
	}

	preset, err := hexstrikePreset(dir, config.Env(envHexstrikePython), config.Env(envHexstrikeURL))
	if err != nil {
		log.Printf("[mcp] hexstrike 预设未启用: %v", err)
		return
	}
	inserted, err := pg.SeedMCPServer(preset)
	if err != nil {
		log.Printf("[mcp] hexstrike 预设写入失败: %v", err)
		return
	}
	if inserted {
		log.Printf("[mcp] 已注册 hexstrike MCP 预设（首次需在「系统 → MCP」里确认工具列表）")
	} else {
		log.Printf("[mcp] hexstrike 预设已存在，保留现有配置")
	}
}
