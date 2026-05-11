---
name: blackduck-customer-service
description: "Use when supporting Cybersecurity customer-service workflows with Black Duck via the blackduck-mcp server. Captures preferred prompt flows for resolving users by Viasat LDAP username, checking dormant status, re-activating users, and managing user groups/project-group access. Triggers on: Black Duck, blackduck, dormant users, activate user, user groups, project groups."
license: "Viasat internal"
compatibility: "Requires network access to the Viasat Black Duck instance and a running blackduck-mcp server (remote Streamable HTTP MCP). Some admin flows below require additional MCP write tools (planned)."
metadata:
  version: "0.1.0"
allowed-tools:
  - "Read"
  - "Write"
  - "Glob"
  - "Grep"
  - "Bash(*)"
---

# Black Duck Customer Service (blackduck-mcp)

## Preferred input (Viasat identity)
When asked about a user, prefer accepting a single identifier from Viasat’s network:
- `<LDAP_USERNAME>` (example: `mdesales`)

In Black Duck, this typically maps to one of:
- `userName` (often the same as LDAP)
- `externalUserName` (often the same as LDAP)

## Non-negotiable preference: NEVER enumerate all users
Do NOT page through the entire `/api/users` collection.

Always resolve users via **search**, using `blackduck_users_list` with a narrow query and a small limit.

Recommended search strategy:
1) Try `q: "userName:<LDAP_USERNAME>"` with `limit: 1`
2) If not found, try `q: "externalUserName:<LDAP_USERNAME>"` with `limit: 1`

## Verified prompt flows (read-only)
These flows work with the tools currently available in the blackduck MCP server.

### 1) Resolve a user by LDAP username
Prompt:
- "Find the Black Duck user for LDAP username '<LDAP_USERNAME>' and return their key properties."

Expected tool flow:
1) `blackduck_users_list` with `q: "userName:<LDAP_USERNAME>"`, `limit: 1`
2) Extract `userId` from the returned user `_meta.href` (or re-run with a larger limit if needed)
3) `blackduck_users_get` for that `user_id`

Return (typical properties):
- `userName`, `externalUserName`, `email`, `active`, `type`, `mfaConfigured`

### 2) List the user groups a user belongs to
Prompt:
- "For Black Duck user '<LDAP_USERNAME>', list the user groups they are a member of."

Expected tool flow:
1) Resolve the user to a `user_id` using the flow above
2) `blackduck_user_usergroups_list` with that `user_id`
3) Return the group `name` values

## Dormant status (planned)
"Dormant" is NOT the same as `active=false`.
- `active` typically means the account is enabled/disabled.
- "dormant" typically means *inactive usage / last login* within a policy window.

Preferred dormant check behavior:
- Query the dedicated dormant-users endpoint and filter by the specific username.
- Do NOT enumerate all users.

Planned MCP tool:
- `blackduck_dormant_users_list` → `GET /api/dormant-users`
  - Should accept paging + `q` + `sort` + `filter` (same conventions as other list endpoints)
  - Example filters (seen in practice): `filter=active:true`

Prompt:
- "Check if Black Duck user '<LDAP_USERNAME>' is dormant. If dormant, show the dormant-user record." 

Expected tool flow (once implemented):
1) `blackduck_dormant_users_list` with:
   - `q: "userName:<LDAP_USERNAME>"` (or `externalUserName:<LDAP_USERNAME>`)
   - `limit: 10`
2) If user is present in `items[]` → treat as dormant

## Reactivating a user (planned write)
If a user account is disabled, it will typically show as:
- `active: false` in `blackduck_users_get`

Planned MCP tool:
- `blackduck_users_update` → `PUT /api/users/{userId}`
  - Goal: set `active=true` (and preserve required fields)

Prompt:
- "Re-activate Black Duck user '<LDAP_USERNAME>' (set active=true)."

Expected tool flow (once implemented):
1) Resolve user → `user_id`
2) `blackduck_users_get` (fetch current record)
3) `blackduck_users_update` with:
   - `user_id: <USER_ID>`
   - payload: same user fields, but `active: true`
4) `blackduck_users_get` again to confirm

Safety recommendation:
- Consider adding a prepare/commit pattern for writes (similar to Invicti) to reduce accidental changes.

## Adding a user to a project group (planned write)
Goal:
- Grant a user access to a specific Black Duck project group.

High-level expected flow:
1) Resolve `<LDAP_USERNAME>` → `user_id`
2) Resolve `<PROJECT_GROUP_NAME>` → `project_group_id` via `blackduck_project_groups_list`
3) Add membership / access via the relevant relation endpoint

Planned MCP tool (name TBD after validating the exact upstream write shape):
- `blackduck_user_project_groups_add`
  - likely uses one of:
    - `POST /api/users/{userId}/project-groups`
    - `POST /api/project-groups/{projectGroupId}/users`

Implementation preference:
- Use the `_meta.links` relations returned by `blackduck_users_get` and `blackduck_project_groups_get` to select the correct upstream URL and method, rather than hard-coding paths blindly.

Prompt:
- "Add Black Duck user '<LDAP_USERNAME>' to project group '<PROJECT_GROUP_NAME>'."

Expected tool flow (once implemented):
1) `blackduck_users_list` (search) → get `user_id`
2) `blackduck_project_groups_list` (search) → get `project_group_id`
3) `blackduck_user_project_groups_add` (perform the write)
4) Re-list user’s project groups (requires a companion read tool) to confirm
