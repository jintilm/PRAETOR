---
name: scopesentry
description: 通过 ScopeSentry MCP 管理安全扫描平台（项目、任务、模板、资产、节点）。在用户提到 ScopeSentry、MCP、API Key、扫描任务、资产查询时使用。
mcps:
  - ScopeSentry
---

# ScopeSentry MCP 使用指南

面向**已部署 ScopeSentry 实例**的用户。通过 MCP 客户端连接平台，无需本地源码。

## 1. 准备工作

### 1.1 确认服务可访问

- 默认 Web 界面：`http://<主机>`
- MCP 端点：`http://<主机>/mcp`（若前面有反向代理或前端代理，以实际 `/mcp` 地址为准）

### 1.2 创建 API Key

1. 浏览器登录 ScopeSentry Web 界面
2. 进入 **API Key** 管理页创建密钥（或通过管理员提供的接口创建）
3. 保存返回的 `ssk_...` 字符串（**仅显示一次**）

### 1.3 配置 MCP

平台「系统 → MCP」里添加 ScopeSentry 服务器（transport=http，url 指向 `<主机>/mcp`，按需填 API Key 头），或在其他 MCP 客户端中配置：

```json
{
  "mcpServers": {
    "scopesentry": {
      "url": "http://<你的主机>:8082/mcp",
      "headers": { "Authorization": "Bearer ssk_..." }
    }
  }
}
```

## 2. 常用流程

- **资产查询**：先列项目 → 选定项目列任务 → 按任务拉资产/漏洞结果
- **下发扫描**：确认目标在授权范围内 → 选模板 → 创建任务 → 轮询状态
- **数据同步**：平台「数据同步」页可把 ScopeSentry 资产导入本地资产图（sync/scopesentry）

## 3. 注意事项

- 只对**授权范围内**的目标操作；API Key 等同账号凭据，不要写进代码仓库
- MCP 名单见平台「系统 → MCP」；本 skill 关联 `ScopeSentry`，未配置时先完成 1.3
