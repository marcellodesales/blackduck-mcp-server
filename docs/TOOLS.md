# Black Duck MCP — Tools and Usage

This document describes what the Black Duck MCP server does and how to use it from MCP clients (or via `curl` for smoke tests).

## What this server does
- Exposes Black Duck read operations as MCP tools.
- Exposes a limited set of write operations as MCP tools (currently: update users via `PUT /api/users/{userId}`).
  - Note: Black Duck does not support permanent user deletion; to "delete" a user, set `active=false` (deactivate). Inactive users do not count against licensing limits and cannot log in.
- Provides an OAuth2-compatible authentication flow for MCP clients.
- Remains stateless: encrypted bearer tokens carry the upstream API token (no DB).

## Transport
- MCP endpoint (Streamable HTTP): `POST /mcp`
- Server card: `GET /.well-known/mcp/server-card.json`

Note: this server runs the MCP handler in stateless mode, so `GET /mcp` (standalone SSE stream) is not supported and will return **405**.

### Local authentication (quick notes)
- `/mcp` is a Streamable HTTP **JSON-RPC** endpoint. Authenticate via headers and call it via `POST /mcp` (`tools/list`, `tools/call`).
- The browser login experience starts at `/authorize`, which redirects to `/blackduck/login?auth_state=...`.
  - `/blackduck/login` can’t be opened directly; it requires the `auth_state` minted by `/authorize`.
- For smoke tests, you can skip OAuth and send **Basic auth** directly to `/mcp` where the password is the Black Duck API token:
  - `Authorization: Basic <base64(user:BLACKDUCK_API_TOKEN)>`

OAuth is recommended for real MCP clients.

## Tool catalog

### Sanity + identity
- `blackduck_ping`
  - Sanity check (no upstream call).
- `blackduck_current_version`
  - Fetch system version (GET `/api/current-version`).
- `blackduck_current_user`
  - Fetch current user (GET `/api/current-user`).

### Projects
- `blackduck_projects_list`
- `blackduck_projects_get`
- `blackduck_project_versions_list`
- `blackduck_project_versions_get`

### Project groups
- `blackduck_project_groups_list`
- `blackduck_project_groups_get`

### Bill of Materials (BOM)
- `blackduck_bom_status_get`
- `blackduck_bom_components_list`
- `blackduck_bom_component_get`
- `blackduck_bom_component_version_get`
- `blackduck_bom_component_policy_status_get`
- `blackduck_bom_component_policy_rules_list`
- `blackduck_vulnerable_bom_components_list`

### Components
- `blackduck_components_search` (requires `q`)
- `blackduck_components_get`
- `blackduck_component_versions_list`
- `blackduck_component_versions_get`
- `blackduck_component_version_origins_list`

### Copyrights
- `blackduck_copyrights_list`

### Vulnerabilities
- `blackduck_component_vulnerabilities_list`
- `blackduck_component_version_vulnerabilities_list`
- `blackduck_vulnerabilities_get`
- `blackduck_project_version_vulnerability_matches_list`

### Scans
- `blackduck_codelocation_scan_summaries_list`
- `blackduck_codelocation_latest_scan_summary_get`
- `blackduck_scan_summaries_get`

### Users + user groups
- `blackduck_users_list`
- `blackduck_users_get`
- `blackduck_dormant_users_list`
- `blackduck_users_update`
- `blackduck_user_usergroups_list`
- `blackduck_usergroups_list`
- `blackduck_usergroups_get`

## Prompt catalog
- `blackduck-quick-verify`

## Local usage

### Run with Docker
See `docker-compose.yaml` for a step-by-step local test flow.

Optional:
- `MCP_AUTH_SECRET` (base64url-encoded 32-byte key, no padding)
  - Recommended if you want OAuth sessions/tokens to remain valid across restarts.
  - If unset, the server auto-generates an ephemeral secret at startup.

Then:
- `docker compose up --build`

Note: the compose file maps host port **9290** → container port **9090**.

### Configure an MCP client
Configure your MCP client with Streamable HTTP:
- Docker compose: `http://localhost:9290/mcp`
- Running directly (no Docker): `http://localhost:9090/mcp`

The client should discover OAuth metadata under `/.well-known/*` and open:
- `/authorize` → `/blackduck/login`

## Smoke tests with curl (Basic auth)

These are useful for quick verification without a full OAuth client.

Required headers for Streamable HTTP POST:
- `Content-Type: application/json`
- `Accept: application/json, text/event-stream`
- `Mcp-Protocol-Version: 2025-06-18` (recommended)

Tip: for easier `curl | jq` debugging, set `MCP_JSON_RESPONSE=true` when running the server.

### List tools
```bash
curl -sS -u 'user:<BLACKDUCK_API_TOKEN>' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'Mcp-Protocol-Version: 2025-06-18' \
  http://localhost:9290/mcp \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | jq .
```

### Call `blackduck_ping`
```bash
curl -sS -u 'user:<BLACKDUCK_API_TOKEN>' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'Mcp-Protocol-Version: 2025-06-18' \
  http://localhost:9290/mcp \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"blackduck_ping","arguments":{}}}' | jq .
```

### Fetch current version
```bash
curl -sS -u 'user:<BLACKDUCK_API_TOKEN>' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'Mcp-Protocol-Version: 2025-06-18' \
  http://localhost:9290/mcp \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"blackduck_current_version","arguments":{}}}' | jq .
```

### List projects (first 10)
```bash
curl -sS -u 'user:<BLACKDUCK_API_TOKEN>' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'Mcp-Protocol-Version: 2025-06-18' \
  http://localhost:9290/mcp \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"blackduck_projects_list","arguments":{"limit":10}}}' | jq .
```

### List project versions (example)
```bash
# First, get a project_id from blackduck_projects_list, then:
curl -sS -u 'user:<BLACKDUCK_API_TOKEN>' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'Mcp-Protocol-Version: 2025-06-18' \
  http://localhost:9290/mcp \
  -d '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"blackduck_project_versions_list","arguments":{"project_id":"<PROJECT_ID>","limit":10}}}' | jq .
```

### Re-activate (enable) a user by ID (example)
```bash
# First, obtain a user_id (for example via blackduck_users_list or blackduck_users_get), then:
curl -sS -u 'user:<BLACKDUCK_API_TOKEN>' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'Mcp-Protocol-Version: 2025-06-18' \
  http://localhost:9290/mcp \
  -d '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"blackduck_users_update","arguments":{"user_id":"<USER_ID>","updates":{"active":true}}}}' | jq .
```

Tip: this tool fetches the current user and sends the full required payload, applying only the requested `updates` fields.

### Deactivate a user by ID (set active=false)
```bash
# Deactivation is the supported "delete user" behavior in Black Duck.
# Inactive users do not count against licensing limits and cannot log in.
curl -sS -u 'user:<BLACKDUCK_API_TOKEN>' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'Mcp-Protocol-Version: 2025-06-18' \
  http://localhost:9290/mcp \
  -d '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"blackduck_users_update","arguments":{"user_id":"<USER_ID>","updates":{"active":false}}}}' | jq .
```
### List dormant users (example)
```bash
# List users considered dormant (for example: no login in the last 90 days).
# You can then match locally on userName/externalUserName/email depending on the response shape.
curl -sS -u 'user:<BLACKDUCK_API_TOKEN>' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'Mcp-Protocol-Version: 2025-06-18' \
  http://localhost:9290/mcp \
  -d '{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"blackduck_dormant_users_list","arguments":{"since_days":90,"limit":999}}}' | jq .
```
