# devspace-wrapper-mcp

一个无认证的本地 MCP 工作区服务，作用类似“轻量 DevSpace / Playwright 风格中间层”：

```text
ChatGPT
  ↓ GPT Secure MCP Tunnel
127.0.0.1:8931/mcp  devspace-wrapper-mcp，无 OAuth
  ↓
本地允许目录：读文件 / 写文件 / 精准替换 / 搜索 / 列目录 / 执行 bash
```

它不是 DevSpace 的 OAuth 代理，也不需要 Cloudflare/ngrok。它直接暴露一组 DevSpace 常用能力，适合只通过 GPT 隧道访问。

## 安装

```bash
git clone https://github.com/freeluyishisan/test.git
cd test/devspace-wrapper-mcp
npm install
```

## 启动

只允许一个项目目录：

```bash
HOST=127.0.0.1 \
PORT=8931 \
WRAPPER_ALLOWED_ROOTS="/home/test/Desktop/mitmproxy-MCP" \
npm start
```

允许多个目录，用英文逗号分隔：

```bash
WRAPPER_ALLOWED_ROOTS="/home/test/Desktop/mitmproxy-MCP,/home/test/Desktop/hermes" npm start
```

健康检查：

```bash
curl -s http://127.0.0.1:8931/healthz | jq
```

`GET /mcp` 会返回说明 JSON；真正 MCP 客户端使用 `POST /mcp`。

## GPT 隧道配置

```bash
./tunnel-client init \
  --profile devspace-wrapper \
  --tunnel-id tunnel_你的id \
  --mcp-server-url http://127.0.0.1:8931/mcp

./tunnel-client run --profile devspace-wrapper
```

ChatGPT 创建连接器时：

```text
Connection: Tunnel
Auth: None / No authentication
MCP URL: http://127.0.0.1:8931/mcp 由 tunnel-client 转发
```

## 工具列表

| 工具 | 作用 |
| --- | --- |
| `open_workspace` | 打开允许目录内的项目，返回 `workspaceId` |
| `read` | 读取 UTF-8 文本文件，支持 `offset` / `limit` |
| `write` | 创建或覆盖文件 |
| `edit` | 用 `oldText` 精准替换为 `newText` |
| `ls` | 列目录 |
| `grep` | 搜索文本文件 |
| `bash` | 在 workspace 内执行 bash 命令 |

使用顺序：先调用 `open_workspace`，后续所有工具带上返回的 `workspaceId`。

## 设计边界

- 默认监听 `127.0.0.1`，不要直接监听公网。
- 默认无 OAuth，必须只放在可信 tunnel 后面。
- 所有路径都会限制在 `WRAPPER_ALLOWED_ROOTS` 内。
- `bash` 很强，等于给模型本地命令执行能力；不要把 allowed roots 设置成 `/`、`/home`、`/root`。

## 环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `HOST` / `WRAPPER_HOST` | `127.0.0.1` | 监听地址 |
| `PORT` / `WRAPPER_PORT` | `8931` | 监听端口 |
| `WRAPPER_ALLOWED_ROOTS` | 当前目录 | 允许打开的根目录，逗号分隔 |
| `WRAPPER_MAX_OUTPUT_BYTES` | `200000` | 工具输出截断上限 |
| `WRAPPER_MAX_READ_BYTES` | `1500000` | 单次无 limit 读取文件上限 |
| `WRAPPER_DEFAULT_TIMEOUT_SECONDS` | `30` | bash 默认超时 |
| `WRAPPER_MAX_TIMEOUT_SECONDS` | `300` | bash 最大超时 |
| `WRAPPER_SHELL` | `/bin/bash` | 执行 shell |

## 本地 MCP 初始化测试

```bash
curl -s http://127.0.0.1:8931/mcp \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}' | jq
```

列工具：

```bash
curl -s http://127.0.0.1:8931/mcp \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' | jq
```
