package db

import (
	"encoding/json"
	"errors"
	"strings"
)

// SeedMCPServer 幂等注册一条 MCP 服务器预设。
//
// 语义与工具表播种一致：**只在不存在时插入**，不覆盖用户在 UI 里的修改
// （enabled/args/url 都可能被手工调过，播种不该把它们改回去）。
// 返回 inserted=true 表示本次确实新增了一条。
func (d *DB) SeedMCPServer(m *MCPServer) (inserted bool, err error) {
	if m == nil {
		return false, errors.New("nil mcp server")
	}
	name := strings.TrimSpace(m.Name)
	if name == "" {
		return false, errors.New("mcp server name is required")
	}
	transport := strings.TrimSpace(m.Transport)
	switch transport {
	case "stdio", "http", "sse":
	default:
		return false, errors.New("invalid mcp transport: " + transport)
	}
	args, env := string(m.Args), string(m.Env)
	if strings.TrimSpace(args) == "" {
		args = "[]"
	}
	if strings.TrimSpace(env) == "" {
		env = "{}"
	}
	if !json.Valid([]byte(args)) || !json.Valid([]byte(env)) {
		return false, errors.New("mcp args/env must be valid JSON")
	}

	res, err := d.Exec(`
INSERT INTO mcp_servers(name, transport, command, args, env, url, enabled, insecure)
VALUES ($1,$2,NULLIF($3,''),$4,$5,NULLIF($6,''),$7,$8)
ON CONFLICT (name) DO NOTHING`,
		name, transport, m.Command, args, env, m.URL, m.Enabled, m.Insecure)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}
