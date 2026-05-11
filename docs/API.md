# Black Duck MCP — API Reference

This document closes the loop between:
- the upstream Black Duck REST API
- the API documentation source used during implementation
- the MCP tools implemented by this server

## Upstream API

### Base URL
The upstream Black Duck API base URL is configured via:
- `BLACKDUCK_BASE_URL` (default: `https://blackduck.infosec.viasat.io`)

Docs landing page:
- `https://blackduck.infosec.viasat.io/api-doc/public.html`

TLS notes:
- The upstream Black Duck endpoint uses HTTPS and may be signed by the Viasat private PKI.
- For Dockerized local development, configure CA roots using:
  - `VIASAT_IO_CACERT_FILE` + `VIASAT_IO_CACERT_URL` (bootstrap bundle at startup)
  - `BLACKDUCK_CA_CERT_FILE` / `BLACKDUCK_CA_CERT_BASE64` (additional roots)
  - `BLACKDUCK_TLS_INSECURE_SKIP_VERIFY=true` (last resort)

### Target system version (declared by the running Black Duck instance)
The upstream Black Duck instance exposes its version via:
- `GET /api/current-version`
- Accept: `application/vnd.blackducksoftware.status-4+json`

Recorded from the target instance:
- Version: `TBD` (run the `blackduck_current_version` tool to capture this)

### OpenAPI / Swagger
At the time of implementation, the public docs site did not expose an OpenAPI/Swagger document URL that could be pinned (for example `/swagger.json` or `/openapi.json`).

This MCP server was implemented via direct HTTP calls based on the docs.

If an OpenAPI snapshot becomes available later:
- pin it under `api/`
- record its `openapi/swagger` and `info.version` fields here (per the `from-openapi-to-mcp` skill guidance)

## Authentication

### Upstream authentication (Black Duck)
Black Duck uses an API token exchange flow:

1) Exchange API token for bearer token:
- `POST /api/tokens/authenticate`
- header: `Authorization: token <API_TOKEN>`
- header: `Accept: application/vnd.blackducksoftware.user-4+json`
- response JSON includes: `bearerToken`, `expiresInMilliseconds`

2) Call API endpoints with:
- header: `Authorization: Bearer <BEARER_TOKEN>`
- header: `Accept: <endpoint-specific vendor media type>`

This MCP server performs the exchange on demand for each tool call.

### MCP server authentication (OAuth2-compatible)
This is a remote Streamable HTTP MCP server.

It exposes OAuth discovery metadata under `/.well-known/*` and supports the common MCP client flow:
- `POST /register`
- `GET /authorize` (starts auth and redirects to hosted login)
- `GET/POST /blackduck/login` (hosted login UI)
- `POST /token` (auth code → bearer access token)

Stateless by design:
- all auth/session state (`client_id`, `auth_state`, `auth_code`, `access_token`) is encrypted into tokens
- no DB or server-side session store is required

Token encryption key:
- `MCP_AUTH_SECRET` (required): base64url-encoded 32-byte key (no padding)

### Direct Basic auth to `/mcp` (secondary)
For quick local smoke tests, `/mcp` also accepts upstream API tokens directly via:
- `Authorization: Basic <base64(user:BLACKDUCK_API_TOKEN)>`

OAuth is recommended for real MCP clients.

## Upstream endpoints used by current MCP tools

### System / identity
- `GET /api/current-version` (Accept: status-4)
  - Used by: `blackduck_current_version`
- `GET /api/current-user` (Accept: user-4)
  - Used by: `blackduck_current_user`
  - Also used for credential validation during `/blackduck/login`

### Projects
- `GET /api/projects` (Accept: project-detail-7)
  - Used by: `blackduck_projects_list`
- `GET /api/projects/{projectId}` (Accept: project-detail-7)
  - Used by: `blackduck_projects_get`
- `GET /api/projects/{projectId}/versions` (Accept: project-detail-5)
  - Used by: `blackduck_project_versions_list`
- `GET /api/projects/{projectId}/versions/{projectVersionId}` (Accept: project-detail-5)
  - Used by: `blackduck_project_versions_get`

### Project groups
- `GET /api/project-groups` (Accept: project-detail-5)
  - Used by: `blackduck_project_groups_list`
- `GET /api/project-groups/{projectGroupId}` (Accept: project-detail-5)
  - Used by: `blackduck_project_groups_get`

### Bill of Materials (BOM)
- `GET /api/projects/{projectId}/versions/{projectVersionId}/bom-status` (Accept: bill-of-materials-6)
  - Used by: `blackduck_bom_status_get`
- `GET /api/projects/{projectId}/versions/{projectVersionId}/components` (Accept: bill-of-materials-6)
  - Used by: `blackduck_bom_components_list`
- `GET /api/projects/{projectId}/versions/{projectVersionId}/components/{componentId}` (Accept: bill-of-materials-6)
  - Used by: `blackduck_bom_component_get`
- `GET /api/projects/{projectId}/versions/{projectVersionId}/components/{componentId}/versions/{componentVersionId}` (Accept: bill-of-materials-6)
  - Used by: `blackduck_bom_component_version_get`
- `GET /api/projects/{projectId}/versions/{projectVersionId}/components/{componentId}/versions/{componentVersionId}/policy-status` (Accept: bill-of-materials-7)
  - Used by: `blackduck_bom_component_policy_status_get`
- `GET /api/projects/{projectId}/versions/{projectVersionId}/components/{componentId}/versions/{componentVersionId}/policy-rules` (Accept: bill-of-materials-7)
  - Used by: `blackduck_bom_component_policy_rules_list`
- `GET /api/projects/{projectId}/versions/{projectVersionId}/vulnerable-bom-components` (Accept: bill-of-materials-8)
  - Used by: `blackduck_vulnerable_bom_components_list`

### Components
- `GET /api/components` (Accept: component-detail-4; requires `q`)
  - Used by: `blackduck_components_search`
- `GET /api/components/{componentId}` (Accept: component-detail-4)
  - Used by: `blackduck_components_get`
- `GET /api/components/{componentId}/versions` (Accept: component-detail-5)
  - Used by: `blackduck_component_versions_list`
- `GET /api/components/{componentId}/versions/{componentVersionId}` (Accept: component-detail-5)
  - Used by: `blackduck_component_versions_get`
- `GET /api/components/{componentId}/versions/{componentVersionId}/origins` (Accept: component-detail-5)
  - Used by: `blackduck_component_version_origins_list`

### Copyrights
- `GET /api/components/{componentId}/versions/{componentVersionId}/origins/{componentVersionOriginId}/copyrights` (Accept: copyright-4)
  - Used by: `blackduck_copyrights_list`

### Vulnerabilities
- `GET /api/components/{componentId}/vulnerabilities` (Accept: vulnerability-4)
  - Used by: `blackduck_component_vulnerabilities_list`
- `GET /api/components/{componentId}/versions/{componentVersionId}/vulnerabilities` (Accept: vulnerability-4)
  - Used by: `blackduck_component_version_vulnerabilities_list`
- `GET /api/vulnerabilities/{vulnerabilityId}` (Accept: vulnerability-4)
  - Used by: `blackduck_vulnerabilities_get`
- `GET /api/projects/{projectId}/versions/{projectVersionId}/vulnerabilities/{vulnerabilityId}/vulnerability-matches` (Accept: vulnerability-4)
  - Used by: `blackduck_project_version_vulnerability_matches_list`

### Scans
- `GET /api/codelocations/{codeLocationId}/scan-summaries` (Accept: scan-6)
  - Used by: `blackduck_codelocation_scan_summaries_list`
- `GET /api/codelocations/{codeLocationId}/latest-scan-summary` (Accept: scan-6)
  - Used by: `blackduck_codelocation_latest_scan_summary_get`
- `GET /api/scan-summaries/{scanId}` (Accept: scan-6)
  - Used by: `blackduck_scan_summaries_get`

### Users + user groups
- `GET /api/users` (Accept: user-4)
  - Used by: `blackduck_users_list`
- `GET /api/users/{userId}` (Accept: user-4)
  - Used by: `blackduck_users_get`
- `GET /api/users/{userId}/usergroups` (Accept: user-4)
  - Used by: `blackduck_user_usergroups_list`
- `GET /api/usergroups` (Accept: user-4)
  - Used by: `blackduck_usergroups_list`
- `GET /api/usergroups/{userGroupId}` (Accept: user-4)
  - Used by: `blackduck_usergroups_get`

## Implementation map (where to look in code)
- HTTP routes + OAuth/login UI:
  - `internal/interfaces/httpserver/`
- MCP Streamable HTTP handler + tool registration:
  - `internal/interfaces/mcp/`
- Stateless token mint/parse:
  - `internal/platform/mcpauth/` + `internal/platform/securetoken/`
- Thin upstream adapter:
  - `internal/infra/blackduck/`

## Security notes
- Never log or print API tokens.
- Treat MCP bearer tokens as sensitive: they contain encrypted upstream API tokens.
- Prefer least-privilege Black Duck API tokens.