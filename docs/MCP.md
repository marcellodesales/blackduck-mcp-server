# Black Duck MCP — MCP Reference

This document focuses on the MCP-facing HTTP surface (endpoints + auth) for the Black Duck MCP server.
For tool usage and curl examples, see `docs/TOOLS.md`.

## HTTP endpoints

### Health + index
- `GET /health`
  - Returns a small JSON health payload.
- `GET /`
  - Returns plain-text `blackduck-mcp`.

### MCP transport
- `POST /mcp`
  - Streamable HTTP MCP endpoint (JSON-RPC: `tools/list`, `tools/call`, etc.).
  - Note: the handler runs in stateless mode, so `GET /mcp` (standalone SSE stream) is not supported.

### MCP + OAuth metadata
- `GET /.well-known/mcp/server-card.json`
- `GET /.well-known/oauth-authorization-server`
- `GET /.well-known/oauth-protected-resource/mcp`

### OAuth endpoints (MCP client compatibility)
- `POST /register`
- `GET /authorize`
- `POST /token`

### Hosted login UI
- `GET/POST /blackduck/login`
  - Intended to be reached via `/authorize`.

## Authentication modes

### Recommended: OAuth bearer access token
Most MCP clients will:
1) Discover metadata under `/.well-known/*`
2) Use `/register` + `/authorize` + `/token`
3) Call MCP tools with:
- `Authorization: Bearer <MCP_ACCESS_TOKEN>`

Note: this is the MCP server's access token, not a Black Duck bearer token.

### Smoke tests (secondary): direct API token to `/mcp` via Basic auth
For quick validation without an OAuth-capable MCP client, `/mcp` also accepts:
- `Authorization: Basic <base64(user:BLACKDUCK_API_TOKEN)>`

## Minimal validation checklist
- `tools/list` returns Black Duck tools.
- `blackduck_current_user` works.
- `blackduck_current_version` works.
- `blackduck_projects_list` works.