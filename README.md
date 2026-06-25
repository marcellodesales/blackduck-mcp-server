# Black Duck MCP Server

Remote Streamable HTTP MCP server for querying Black Duck via MCP tools.

This server is **stateless**:
- OAuth client registration, auth state, auth codes, and access tokens are all encrypted into tokens.
- No DB or server-side session store is required.

## What it supports
Read endpoints are exposed as MCP tools for:
- Projects + project versions
- Project groups
- Bill of Materials (BOM): status, components, vulnerable BOM components
- Components: search, versions, origins
- Copyrights
- Vulnerabilities
- Scans (scan summaries)
- Users + user groups
- Policy rules for BOM component versions

A limited set of write endpoints are also exposed:
- Users: update basic properties (including `active`) via `PUT /api/users/{userId}`

## Authentication

### Upstream (Black Duck)
Black Duck uses an API token that must be exchanged for a short-lived bearer token:
- `POST /api/tokens/authenticate` with `Authorization: token <API_TOKEN>`
- subsequent requests use `Authorization: Bearer <BEARER_TOKEN>`

The MCP server performs this exchange on demand.

### MCP server (OAuth2-compatible)
This is a remote Streamable HTTP MCP server. MCP clients should:
1) Discover metadata under `/.well-known/*`
2) Use `/register` + `/authorize` + `/token`
3) Authenticate to `/mcp` using `Authorization: Bearer <MCP_ACCESS_TOKEN>`

Hosted login UI:
- `GET/POST /blackduck/login` (intended to be reached via `/authorize`)

### Smoke tests (secondary)
For quick local testing, `/mcp` also accepts **Basic auth** where the password is treated as the Black Duck API token:
- `Authorization: Basic <base64(user:BLACKDUCK_API_TOKEN)>`

OAuth is recommended for real MCP clients.

## Configuration
Environment variables:
- `PORT` (default `9090`)
- `MCP_SERVER_URL` (default `http://localhost:$PORT`)
- `BLACKDUCK_BASE_URL` (default `https://blackduck.infosec.viasat.io`)

Upstream TLS / CA handling (often required for internal Viasat HTTPS services):
- `VIASAT_IO_CACERT_FILE` + `VIASAT_IO_CACERT_URL`
  - when both set, the server fetches the Viasat CA bundle at startup and writes it to the file
- `BLACKDUCK_CA_CERT_FILE` (optional override)
- `BLACKDUCK_CA_CERT_BASE64` (optional additional PEM bundle)
- `BLACKDUCK_TLS_INSECURE_SKIP_VERIFY` (optional/unsafe): when true, disables upstream TLS verification

Auth and server behavior:
- `MCP_AUTH_SECRET` (optional): base64url-encoded 32-byte key (no padding)
  - If unset, the server auto-generates an ephemeral secret at startup (OAuth sessions/tokens become invalid after restart).
  - For deployments, set a stable value so sessions can survive restarts.
- `MCP_JSON_RESPONSE` (default `false`): when true, `/mcp` responses are JSON (easier for curl)

## Local run (Docker)
See `docker-compose.yaml` for step-by-step local smoke tests.

Optional:
- export `MCP_AUTH_SECRET` if you want OAuth sessions/tokens to remain valid across restarts
  - If unset, the server auto-generates an ephemeral secret at startup.

Then:
- `docker compose up --build`

## Docs
- `docs/API.md` — upstream API mapping + auth flow + version notes
- `docs/TOOLS.md` — tool catalog + curl examples
- `docs/MCP.md` — HTTP endpoints + auth modes
