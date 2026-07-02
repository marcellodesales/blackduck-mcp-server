---
name: blackduck-customer-service
description: "Use when supporting Cybersecurity customer-service workflows with Black Duck via the blackduck-viasat MCP server. For user re-activation, require a Viasat email (@viasat.com) or LDAP username, confirm the identity via the viasat-vice MCP server, look up the account starting from /api/dormant-users (then fall back to /api/users if needed), and if active=false update the user via HTTP PUT to set active=true using blackduck_users_update. For offboarding cleanup, if a user is dormant for >1 year and is NOT found in the VICE directory, suggest deactivation (active=false); after the operator confirms via a manual Slack search, deactivate the Black Duck user via blackduck_users_update. Triggers on: Black Duck, blackduck, dormant users, activate user, reactivate user, enable user, deactivate user, disable user, delete user, remove user, offboarding, user groups, project groups."
license: "Viasat internal"
compatibility: "Requires network access to the Viasat Black Duck instance and the centrally hosted viasat-vice MCP server. Write operations (e.g., blackduck_users_update and blackduck_project_delete_*) are only available when the MCP bearer token was authorized with access_mode=read_write; otherwise write tools are not registered."
metadata:
  version: "0.2.5"
allowed-tools:
  - "Read"
  - "Write"
  - "Glob"
  - "Grep"
  - "Bash(*)"
---

# Black Duck Customer Service (blackduck-mcp)

## Connectivity preflight (VPN / viasat.io)
Black Duck's upstream APIs (and this MCP server) live on `viasat.io` infrastructure. **Before** invoking any tool below, confirm the network path is available.

Symptoms of missing connectivity (treat as VPN-not-connected first, not as a server bug):
- `request canceled (Client.Timeout exceeded while awaiting headers)`
- `TLS handshake timeout`
- `dial tcp: lookup ... no such host`
- `context deadline exceeded`

Recommended preflight:
1. Call `blackduck_ping` (or `blackduck_current_user`) — a successful response confirms connectivity.
2. If it fails with a timeout/TLS error, stop and ask the operator to verify VPN before retrying any other tool.
3. Retry **once** after the operator confirms the VPN is connected; do not loop.

## Required input (Viasat identity)
For enable/reactivation and other standard support requests, require **one** of:
- `<EMAIL>` ending in `@viasat.com` (case-insensitive)
- `<LDAP_USERNAME>` (example: `mdesales`)

For offboarding cleanup (deactivating long-dormant accounts), you may start from the Black Duck record (dormant list or a `user_id`) and then check VICE using the identity fields on the Black Duck user.

For enable/reactivation: do not proceed to Black Duck until the identity is confirmed in VICE.

## Step 1 — Confirm the identity in VICE (required for enable/reactivation)
Use the `viasat-vice` MCP server as the source of truth:
- If the operator provides `<EMAIL>`: call `vice_get_user_by_email` with `email: "<EMAIL>"`
- If the operator provides `<LDAP_USERNAME>`: call `vice_get_user` with `username: "<LDAP_USERNAME>"`

If no user is found:
- For enable/reactivation: stop and ask the operator to double-check the email/username.
- For offboarding cleanup: continue — VICE not-found is part of the removal decision (see "Offboarding cleanup" below).

If a VICE user is found, capture the canonical values:
- `ldap_username` (VICE `username`)
- `email` (VICE `email`, normalize to lowercase)

## Step 2 — Black Duck user lookup (start from dormant users)
Prefer the dormant-users endpoint first (it includes last login context), and only fall back to full enumeration if the user is not returned as dormant.

### 2A) Preferred — Lookup via dormant-users (bounded)
Expected tool call:
- `blackduck_dormant_users_list` with `since_days: 90`, `limit: 999`

Selection rules (in priority order):
1) If the dormant record includes `email`, match it (case-insensitive) against the known email (VICE if available; otherwise the operator-provided `<EMAIL>`).
2) Match `externalUserName` / `userName` / `username` (case-insensitive) against the known username (VICE `ldap_username` if available; otherwise the operator-provided `<LDAP_USERNAME>`).

Typical dormant-user fields (may vary by Black Duck version):
- `externalUserName`, `userName` / `username`, `firstName`, `lastName`, `email`, `type`, `active`, `href` / `_meta.href`, `lastLogin`

How to get `user_id` from a dormant record:
- Use the record `_meta.href` (commonly `.../api/users/<USER_ID>/last-login`) and strip the trailing `/last-login`, then take the `<USER_ID>` segment.

If there are 0 matches or multiple matches, proceed to the fallback enumeration (2B) or ask the operator to choose.

### 2B) Fallback — Full enumeration (no pagination)
Use `blackduck_users_list` to list **all** users in a single call (no pagination) and then select the matching record locally.

Expected tool call:
- `blackduck_users_list` with `limit: 1000`, `offset: 0`

Notes:
- Black Duck rejects excessively large `limit` values with `{core.rest.excessive_request}`. Do not raise `limit` above 1000.
- Verify `response.totalCount <= limit` to ensure the single call returned the full user list. If `totalCount > limit`, stop and ask the operator how to proceed (pagination would violate this skill’s no-pagination requirement).
- The current `blackduck_users_list` MCP tool does not reliably apply `q` / `filter` server-side — do not rely on them.

Selection rules (in priority order):
1) Match the `email` field (case-insensitive) against the known email (VICE if available; otherwise the operator-provided `<EMAIL>`).
2) If no email match, match `userName` or `externalUserName` (case-insensitive) against the known username (VICE `ldap_username` if available; otherwise the operator-provided `<LDAP_USERNAME>`).

If there are 0 matches or multiple matches, stop and ask the operator which record to use (show `userName`, `externalUserName`, `email`, `active` for each candidate).

## Verified prompt flows
These flows work with the tools currently available in the Black Duck MCP server.

### 1) Resolve a user by Viasat email or LDAP username
Prompt:
- "Find the Black Duck user for '<EMAIL>' (or '<LDAP_USERNAME>') and return their key properties."

Expected tool flow:
1) Confirm identity in VICE (Step 1 above) → get `{ldap_username, email}`
2) Try `blackduck_dormant_users_list` (`since_days: 90`, `limit: 999`) and attempt to select the matching dormant record (Step 2A)
3) If not found as dormant, fall back to `blackduck_users_list` (`limit: 1000`, `offset: 0`) and select the matching user record (Step 2B)
4) Extract `user_id` from the selected record `_meta.href`
5) `blackduck_users_get` for that `user_id`

Return (typical properties):
- `userName`, `externalUserName`, `email`, `active`, `type`, `mfaConfigured`

### 2) List the user groups a user belongs to
Prompt:
- "For Black Duck user '<EMAIL>' (or '<LDAP_USERNAME>'), list the user groups they are a member of."

Expected tool flow:
1) Resolve the user to a `user_id` using the flow above
2) `blackduck_user_usergroups_list` with that `user_id`
3) Return the group `name` values

## Project cleanup — deleting a Black Duck project (prepare/commit)
This is a destructive operation. It is only available with a READ-WRITE token and uses a prepare/commit safety gate.

Required input:
- `project_id` (Black Duck project identifier)

Verified tool flow:
1) (Optional) `blackduck_projects_get` to confirm you have the correct project
2) `blackduck_project_delete_prepare { project_id }`
3) After explicit operator confirmation, `blackduck_project_delete_commit { approval_token }`

Notes:
- This maps to `DELETE /api/projects/{projectId}`. Ensure the Scorecard/CodeDx mapping is correct before committing.

## Dormant status
"Dormant" is NOT the same as `active=false`.
- `active` means the account is enabled/disabled.
- "dormant" means *inactive usage / last login* within a policy window.
- A dormant user can still log in if `active: true`.
- Inactive (`active: false`) users do not count against licensing limits and cannot log in.

Prompt:
- "Check if Black Duck user '<EMAIL>' (or '<LDAP_USERNAME>') is dormant. If dormant, show the dormant-user record." 

Expected tool flow:
1) Confirm identity in VICE → `{ldap_username, email}`
2) `blackduck_dormant_users_list` with:
   - `since_days: 90`
   - `limit: 999`
3) Select the matching dormant record using:
   - `email` match (if present), otherwise `externalUserName` / `userName` / `username` match
4) If a matching record is present in `items[]` → treat as dormant and return:
   - `lastLogin` (if present)
   - the record `href` / `_meta.href` (used to derive `/api/users/{userId}`)

Notes:
- If the user is not present, they may not be dormant for the chosen `since_days` window.
- Response shapes can vary by Black Duck version; treat the record as authoritative and match on whatever identity fields are present.

## Offboarding cleanup — deactivating long-dormant users not found in VICE
Sometimes dormant Black Duck accounts belong to employees/contractors who have left the company. If the account has been dormant for **more than 1 year** and the user is **not found in VICE**, suggest disabling the account (set `active=false`).

Important:
- Black Duck does not support permanent user deletion; "delete user" should be interpreted as **deactivate user**.
- Inactive (`active=false`) users do not count against licensing limits and cannot log in to the Black Duck UI.

Scope guardrails:
- Do NOT deactivate users just because VICE is unreachable (network/auth errors) — only proceed when VICE tools are functioning.
- Do NOT deactivate system/service users (examples: `anonymous`, `default-authenticated-user`, `sysadmin`).
- If the dormant record lacks `lastLogin`, treat the dormancy duration as **unknown** and do not recommend deactivation solely from that record.

### Step A — Find candidates (> 1 year)
1) Use `blackduck_dormant_users_list` with:
   - `since_days: 365`
   - `limit: 999`
   - `sort: "lastLogin asc"` (oldest first; ignore records missing `lastLogin`)
2) Select the specific user record the operator is asking about (match on email/username as in Step 2A).
3) Derive `user_id` from `href` / `_meta.href` and fetch `blackduck_users_get` for that ID.

### Step B — Verify the user is NOT in VICE
Attempt all applicable VICE lookups:
- If you have an email: `vice_get_user_by_email` using the Black Duck email.
- If you have a username: `vice_get_user` using the Black Duck `userName` / `externalUserName`.

If any VICE lookup returns a user, stop — do **not** suggest deactivation.

If no VICE record is found:
- Suggest deactivation due to the possibility the user has left the company.

### Step C — Manual confirmation via Slack (required)
VICE not-found is not sufficient by itself.
Ask the operator to manually search for the user in Slack (not available via MCP) and confirm the person/account is deactivated/offboarded.

### Step D — Deactivate the Black Duck user (set active=false)
Only after explicit operator confirmation:
1) Re-state what will be changed (include `user_id`, `userName`, `externalUserName`, `email`, `lastLogin`, current `active`).
2) If the user is already `active: false`, stop (nothing to do).
3) Otherwise, call `blackduck_users_update` with:
   - `user_id: <USER_ID>`
   - `updates: {"active": false}`
4) Re-fetch `blackduck_users_get` to confirm `active: false`.
## Reactivating a user (inactive → active)
If a user account is disabled, it will show as `active: false` in the user record.

Required operations:
1) Confirm identity in VICE (Step 1)
2) Look up the user (Step 2) — start with `blackduck_dormant_users_list`, fall back to `blackduck_users_list`
3) `blackduck_users_get` (fetch current record)
4) If `active: true` → stop (already enabled)
5) If `active: false` → set the account to active by updating **only** the `active` field via HTTP PUT

MCP tool:
- `blackduck_users_update` → `PUT /api/users/{userId}`
  - Input is a patch-like `updates` object; the tool fetches the current user and sends the full required payload.

User fields that can be updated via `blackduck_users_update` (supported `updates` keys):
- `active`
- `firstName`, `lastName`
- `email`
- `userName`, `externalUserName`, `type` (supported, but generally avoid changing unless explicitly requested)

Read-only / informational fields (do not attempt to update):
- `lastLogin`, `href`, `_meta`, and other server-managed fields

Prompt:
- "Re-activate Black Duck user '<EMAIL>' (or '<LDAP_USERNAME>') — set active=true."

Expected tool flow:
1) Confirm identity in VICE → `{ldap_username, email}`
2) Try dormant-users first:
   - `blackduck_dormant_users_list` (`since_days: 90`, `limit: 999`) → select dormant record → extract `user_id` from its `href` / `_meta.href`
   - If not found, fall back to `blackduck_users_list` (`limit: 1000`, `offset: 0`) → select user → extract `user_id`
3) `blackduck_users_get` (fetch current record)
4) `blackduck_users_update` with:
   - `user_id: <USER_ID>`
   - `updates: {"active": true}`
5) `blackduck_users_get` again to confirm `active: true`

Safety recommendation:
- Consider adding a prepare/commit pattern for writes to reduce accidental changes.

## Adding a user to a project group (planned write)
Goal:
- Grant a user access to a specific Black Duck project group.

High-level expected flow:
1) Confirm identity in VICE (Step 1) → `{ldap_username, email}`
2) Enumerate Black Duck users (Step 2) → select the matching record → `user_id`
3) List project groups via `blackduck_project_groups_list` (enumerate with a high `limit`) → select `project_group_id`
4) Add membership / access via the relevant relation endpoint

Planned MCP tool (name TBD after validating the exact upstream write shape):
- `blackduck_user_project_groups_add`
  - likely uses one of:
    - `POST /api/users/{userId}/project-groups`
    - `POST /api/project-groups/{projectGroupId}/users`

Implementation preference:
- Use the `_meta.links` relations returned by `blackduck_users_get` and `blackduck_project_groups_get` to select the correct upstream URL and method, rather than hard-coding paths blindly.

Prompt:
- "Add Black Duck user '<EMAIL>' (or '<LDAP_USERNAME>') to project group '<PROJECT_GROUP_NAME>'."

Expected tool flow (once implemented):
1) Confirm identity in VICE → `{ldap_username, email}`
2) `blackduck_users_list` (`limit: 1000`, `offset: 0`) → select user → extract `user_id`
3) `blackduck_project_groups_list` with a high `limit` (enumerate) → select `project_group_id`
4) `blackduck_user_project_groups_add` (perform the write)
5) Re-list user’s project groups (requires a companion read tool) to confirm
