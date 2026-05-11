package mcpserver

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Black Duck MCP Prompts — reusable prompt templates for common Black Duck operations.
func registerBlackduckPrompts(server *mcp.Server) {
	server.AddPrompt(&mcp.Prompt{
		Name:        "blackduck-quick-verify",
		Title:       "Black Duck: quick verify (ping, current user, current version, projects)",
		Description: "Sanity-check connectivity and credentials using a small set of read-only tools.",
	}, promptBlackduckQuickVerify)
}

func promptBlackduckQuickVerify(_ context.Context, _ *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	today := time.Now().UTC().Format("2006-01-02")
	text := fmt.Sprintf(
		"Generate a quick, human-readable verification report for this Black Duck MCP server.\n\n"+
			"Do not describe your plan or narrate intermediate steps. Fetch data and output only the final report.\n\n"+
			"## Data to fetch (in parallel)\n"+
			"1) blackduck_ping\n"+
			"2) blackduck_current_version\n"+
			"3) blackduck_current_user\n"+
			"4) blackduck_projects_list with limit=10\n\n"+
			"## Output requirements\n"+
			"- Output markdown only.\n"+
			"- Do NOT paste full raw JSON responses.\n"+
			"- Redact any tokens/secrets if present.\n\n"+
			"## Output format (today is %s)\n"+
			"## Black Duck MCP — Quick Verify\n"+
			"**Date:** %s\n\n"+
			"### Connectivity\n"+
			"- Ping: <pong or error>\n\n"+
			"### Black Duck Version (GET /api/current-version)\n"+
			"- Version: ...\n\n"+
			"### Current User (GET /api/current-user)\n"+
			"- Principal/UserName: ...\n"+
			"- Top-level keys (if unsure): ...\n\n"+
			"### Projects (first 10)\n"+
			"- Count returned: N\n"+
			"- Example projects: <name/id pairs>\n",
		today,
		today,
	)

	return &mcp.GetPromptResult{
		Description: "Quick verification report for Black Duck MCP connectivity, credentials, and basic read access.",
		Messages:    []*mcp.PromptMessage{{Role: "user", Content: &mcp.TextContent{Text: text}}},
	}, nil
}
