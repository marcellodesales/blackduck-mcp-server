package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"git.viasat.com/seceng-devsecops-platform/blackduck-mcp/internal/infra/blackduck"
	"git.viasat.com/seceng-devsecops-platform/blackduck-mcp/internal/platform/config"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type PingInput struct{}

type PingOutput struct {
	Message string `json:"message" jsonschema:"Human-readable ping response."`
}

type RawResponseOutput struct {
	BaseURL  string         `json:"base_url" jsonschema:"Black Duck base URL used by this server."`
	Response map[string]any `json:"response" jsonschema:"Raw JSON response from Black Duck."`
}

type OffsetLimitSortQuery struct {
	Offset *int32  `json:"offset,omitempty" jsonschema:"Pagination offset."`
	Limit  *int32  `json:"limit,omitempty" jsonschema:"Pagination limit."`
	Sort   *string `json:"sort,omitempty" jsonschema:"Sort specification."`
}

type OffsetLimitSortQFilterQuery struct {
	Offset *int32  `json:"offset,omitempty" jsonschema:"Pagination offset."`
	Limit  *int32  `json:"limit,omitempty" jsonschema:"Pagination limit."`
	Sort   *string `json:"sort,omitempty" jsonschema:"Sort specification."`
	Q      *string `json:"q,omitempty" jsonschema:"Search query."`
	Filter *string `json:"filter,omitempty" jsonschema:"Filter expression."`
}

func registerBlackduckTools(server *mcp.Server, cfg config.Config, client *blackduck.Client, creds upstreamCreds) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "blackduck_ping",
		Description: "Sanity-check tool: returns a static response to confirm the MCP server is reachable.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ PingInput) (*mcp.CallToolResult, PingOutput, error) {
		return nil, PingOutput{Message: "pong"}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "blackduck_current_user",
		Description: "Return the current Black Duck user (GET /api/current-user).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, RawResponseOutput, error) {
		ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()

		resp, err := client.CurrentUser(ctx, creds.apiToken)
		if err != nil {
			return nil, RawResponseOutput{}, blackduckToolError(err)
		}
		return nil, RawResponseOutput{BaseURL: cfg.BlackduckBaseURL, Response: resp}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "blackduck_current_version",
		Description: "Return the current Black Duck system version (GET /api/current-version).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, RawResponseOutput, error) {
		ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()

		resp, err := client.CurrentVersion(ctx, creds.apiToken)
		if err != nil {
			return nil, RawResponseOutput{}, blackduckToolError(err)
		}
		return nil, RawResponseOutput{BaseURL: cfg.BlackduckBaseURL, Response: resp}, nil
	})

	registerProjectTools(server, cfg, client, creds)
	registerProjectGroupTools(server, cfg, client, creds)
	registerBOMTools(server, cfg, client, creds)
	registerComponentTools(server, cfg, client, creds)
	registerCopyrightTools(server, cfg, client, creds)
	registerVulnerabilityTools(server, cfg, client, creds)
	registerScanTools(server, cfg, client, creds)
	registerUserTools(server, cfg, client, creds)
	registerUserGroupTools(server, cfg, client, creds)
}

func blackduckToolError(err error) error {
	if errors.Is(err, blackduck.ErrUnauthorized) || errors.Is(err, blackduck.ErrForbidden) {
		return fmt.Errorf("blackduck authentication failed: %w", err)
	}
	return err
}

func setOptInt32(q url.Values, key string, v *int32) {
	if v == nil {
		return
	}
	q.Set(key, strconv.FormatInt(int64(*v), 10))
}

func setOptString(q url.Values, key string, v *string) {
	if v == nil {
		return
	}
	if *v == "" {
		return
	}
	q.Set(key, *v)
}

type ProjectsListInput struct {
	Offset *int32  `json:"offset,omitempty" jsonschema:"Pagination offset."`
	Limit  *int32  `json:"limit,omitempty" jsonschema:"Pagination limit."`
	Sort   *string `json:"sort,omitempty" jsonschema:"Sort specification."`
	Q      *string `json:"q,omitempty" jsonschema:"Search query."`
	Filter *string `json:"filter,omitempty" jsonschema:"Filter expression."`
}

type ProjectGetInput struct {
	ProjectID string `json:"project_id" jsonschema:"Black Duck project identifier."`
}

type ProjectVersionsListInput struct {
	ProjectID string  `json:"project_id" jsonschema:"Black Duck project identifier."`
	Offset    *int32  `json:"offset,omitempty" jsonschema:"Pagination offset."`
	Limit     *int32  `json:"limit,omitempty" jsonschema:"Pagination limit."`
	Sort      *string `json:"sort,omitempty" jsonschema:"Sort specification."`
	Q         *string `json:"q,omitempty" jsonschema:"Search query."`
	Filter    *string `json:"filter,omitempty" jsonschema:"Filter expression."`
}

type ProjectVersionGetInput struct {
	ProjectID        string `json:"project_id" jsonschema:"Black Duck project identifier."`
	ProjectVersionID string `json:"project_version_id" jsonschema:"Black Duck project version identifier."`
}

func registerProjectTools(server *mcp.Server, cfg config.Config, client *blackduck.Client, creds upstreamCreds) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "blackduck_projects_list",
		Description: "List projects (GET /api/projects).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ProjectsListInput) (*mcp.CallToolResult, RawResponseOutput, error) {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		q := url.Values{}
		setOptInt32(q, "offset", in.Offset)
		setOptInt32(q, "limit", in.Limit)
		setOptString(q, "sort", in.Sort)
		setOptString(q, "q", in.Q)
		setOptString(q, "filter", in.Filter)

		resp, err := client.GetJSON(ctx, creds.apiToken, "/api/projects", blackduck.MediaTypeProjectDetailV7, q)
		if err != nil {
			return nil, RawResponseOutput{}, blackduckToolError(err)
		}
		return nil, RawResponseOutput{BaseURL: cfg.BlackduckBaseURL, Response: resp}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "blackduck_projects_get",
		Description: "Get a project by ID (GET /api/projects/{projectId}).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ProjectGetInput) (*mcp.CallToolResult, RawResponseOutput, error) {
		if in.ProjectID == "" {
			return nil, RawResponseOutput{}, fmt.Errorf("project_id is required")
		}
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		path := "/api/projects/" + url.PathEscape(in.ProjectID)
		resp, err := client.GetJSON(ctx, creds.apiToken, path, blackduck.MediaTypeProjectDetailV7, nil)
		if err != nil {
			return nil, RawResponseOutput{}, blackduckToolError(err)
		}
		return nil, RawResponseOutput{BaseURL: cfg.BlackduckBaseURL, Response: resp}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "blackduck_project_versions_list",
		Description: "List project versions (GET /api/projects/{projectId}/versions).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ProjectVersionsListInput) (*mcp.CallToolResult, RawResponseOutput, error) {
		if in.ProjectID == "" {
			return nil, RawResponseOutput{}, fmt.Errorf("project_id is required")
		}
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		q := url.Values{}
		setOptInt32(q, "offset", in.Offset)
		setOptInt32(q, "limit", in.Limit)
		setOptString(q, "sort", in.Sort)
		setOptString(q, "q", in.Q)
		setOptString(q, "filter", in.Filter)

		path := "/api/projects/" + url.PathEscape(in.ProjectID) + "/versions"
		resp, err := client.GetJSON(ctx, creds.apiToken, path, blackduck.MediaTypeProjectDetailV5, q)
		if err != nil {
			return nil, RawResponseOutput{}, blackduckToolError(err)
		}
		return nil, RawResponseOutput{BaseURL: cfg.BlackduckBaseURL, Response: resp}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "blackduck_project_versions_get",
		Description: "Get a project version (GET /api/projects/{projectId}/versions/{projectVersionId}).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ProjectVersionGetInput) (*mcp.CallToolResult, RawResponseOutput, error) {
		if in.ProjectID == "" || in.ProjectVersionID == "" {
			return nil, RawResponseOutput{}, fmt.Errorf("project_id and project_version_id are required")
		}
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		path := "/api/projects/" + url.PathEscape(in.ProjectID) + "/versions/" + url.PathEscape(in.ProjectVersionID)
		resp, err := client.GetJSON(ctx, creds.apiToken, path, blackduck.MediaTypeProjectDetailV5, nil)
		if err != nil {
			return nil, RawResponseOutput{}, blackduckToolError(err)
		}
		return nil, RawResponseOutput{BaseURL: cfg.BlackduckBaseURL, Response: resp}, nil
	})
}

type ProjectGroupsListInput struct {
	Offset *int32  `json:"offset,omitempty" jsonschema:"Pagination offset."`
	Limit  *int32  `json:"limit,omitempty" jsonschema:"Pagination limit."`
	Sort   *string `json:"sort,omitempty" jsonschema:"Sort specification."`
	Q      *string `json:"q,omitempty" jsonschema:"Search query."`
	Filter *string `json:"filter,omitempty" jsonschema:"Filter expression."`
}

type ProjectGroupGetInput struct {
	ProjectGroupID string `json:"project_group_id" jsonschema:"Black Duck project group identifier."`
}

func registerProjectGroupTools(server *mcp.Server, cfg config.Config, client *blackduck.Client, creds upstreamCreds) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "blackduck_project_groups_list",
		Description: "List project groups (GET /api/project-groups).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ProjectGroupsListInput) (*mcp.CallToolResult, RawResponseOutput, error) {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		q := url.Values{}
		setOptInt32(q, "offset", in.Offset)
		setOptInt32(q, "limit", in.Limit)
		setOptString(q, "sort", in.Sort)
		setOptString(q, "q", in.Q)
		setOptString(q, "filter", in.Filter)

		resp, err := client.GetJSON(ctx, creds.apiToken, "/api/project-groups", blackduck.MediaTypeProjectDetailV5, q)
		if err != nil {
			return nil, RawResponseOutput{}, blackduckToolError(err)
		}
		return nil, RawResponseOutput{BaseURL: cfg.BlackduckBaseURL, Response: resp}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "blackduck_project_groups_get",
		Description: "Get a project group (GET /api/project-groups/{projectGroupId}).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ProjectGroupGetInput) (*mcp.CallToolResult, RawResponseOutput, error) {
		if in.ProjectGroupID == "" {
			return nil, RawResponseOutput{}, fmt.Errorf("project_group_id is required")
		}
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		path := "/api/project-groups/" + url.PathEscape(in.ProjectGroupID)
		resp, err := client.GetJSON(ctx, creds.apiToken, path, blackduck.MediaTypeProjectDetailV5, nil)
		if err != nil {
			return nil, RawResponseOutput{}, blackduckToolError(err)
		}
		return nil, RawResponseOutput{BaseURL: cfg.BlackduckBaseURL, Response: resp}, nil
	})
}

type ProjectVersionRef struct {
	ProjectID        string `json:"project_id" jsonschema:"Black Duck project identifier."`
	ProjectVersionID string `json:"project_version_id" jsonschema:"Black Duck project version identifier."`
}

type BOMStatusGetInput struct {
	ProjectID        string `json:"project_id"`
	ProjectVersionID string `json:"project_version_id"`
}

type BOMComponentsListInput struct {
	ProjectID        string  `json:"project_id"`
	ProjectVersionID string  `json:"project_version_id"`
	Offset           *int32  `json:"offset,omitempty"`
	Limit            *int32  `json:"limit,omitempty"`
	Sort             *string `json:"sort,omitempty"`
	Q                *string `json:"q,omitempty"`
	Filter           *string `json:"filter,omitempty"`
}

type BOMComponentGetInput struct {
	ProjectID        string `json:"project_id"`
	ProjectVersionID string `json:"project_version_id"`
	ComponentID      string `json:"component_id"`
}

type BOMComponentVersionGetInput struct {
	ProjectID          string `json:"project_id"`
	ProjectVersionID   string `json:"project_version_id"`
	ComponentID        string `json:"component_id"`
	ComponentVersionID string `json:"component_version_id"`
}

type BOMComponentPolicyStatusGetInput struct {
	ProjectID          string `json:"project_id"`
	ProjectVersionID   string `json:"project_version_id"`
	ComponentID        string `json:"component_id"`
	ComponentVersionID string `json:"component_version_id"`
}

type BOMComponentPolicyRulesListInput struct {
	ProjectID          string  `json:"project_id"`
	ProjectVersionID   string  `json:"project_version_id"`
	ComponentID        string  `json:"component_id"`
	ComponentVersionID string  `json:"component_version_id"`
	Offset             *int32  `json:"offset,omitempty"`
	Limit              *int32  `json:"limit,omitempty"`
	Sort               *string `json:"sort,omitempty"`
}

type VulnerableBOMComponentsListInput struct {
	ProjectID        string  `json:"project_id"`
	ProjectVersionID string  `json:"project_version_id"`
	Offset           *int32  `json:"offset,omitempty"`
	Limit            *int32  `json:"limit,omitempty"`
	Sort             *string `json:"sort,omitempty"`
}

func registerBOMTools(server *mcp.Server, cfg config.Config, client *blackduck.Client, creds upstreamCreds) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "blackduck_bom_status_get",
		Description: "Get BOM status for a project version (GET /api/projects/{projectId}/versions/{projectVersionId}/bom-status).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in BOMStatusGetInput) (*mcp.CallToolResult, RawResponseOutput, error) {
		if in.ProjectID == "" || in.ProjectVersionID == "" {
			return nil, RawResponseOutput{}, fmt.Errorf("project_id and project_version_id are required")
		}
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		path := "/api/projects/" + url.PathEscape(in.ProjectID) + "/versions/" + url.PathEscape(in.ProjectVersionID) + "/bom-status"
		resp, err := client.GetJSON(ctx, creds.apiToken, path, blackduck.MediaTypeBOMV6, nil)
		if err != nil {
			return nil, RawResponseOutput{}, blackduckToolError(err)
		}
		return nil, RawResponseOutput{BaseURL: cfg.BlackduckBaseURL, Response: resp}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "blackduck_bom_components_list",
		Description: "List BOM components for a project version (GET /api/projects/{projectId}/versions/{projectVersionId}/components).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in BOMComponentsListInput) (*mcp.CallToolResult, RawResponseOutput, error) {
		if in.ProjectID == "" || in.ProjectVersionID == "" {
			return nil, RawResponseOutput{}, fmt.Errorf("project_id and project_version_id are required")
		}
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		q := url.Values{}
		setOptInt32(q, "offset", in.Offset)
		setOptInt32(q, "limit", in.Limit)
		setOptString(q, "sort", in.Sort)
		setOptString(q, "q", in.Q)
		setOptString(q, "filter", in.Filter)

		path := "/api/projects/" + url.PathEscape(in.ProjectID) + "/versions/" + url.PathEscape(in.ProjectVersionID) + "/components"
		resp, err := client.GetJSON(ctx, creds.apiToken, path, blackduck.MediaTypeBOMV6, q)
		if err != nil {
			return nil, RawResponseOutput{}, blackduckToolError(err)
		}
		return nil, RawResponseOutput{BaseURL: cfg.BlackduckBaseURL, Response: resp}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "blackduck_bom_component_get",
		Description: "Read a BOM component entry (GET /api/projects/{projectId}/versions/{projectVersionId}/components/{componentId}).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in BOMComponentGetInput) (*mcp.CallToolResult, RawResponseOutput, error) {
		if in.ProjectID == "" || in.ProjectVersionID == "" || in.ComponentID == "" {
			return nil, RawResponseOutput{}, fmt.Errorf("project_id, project_version_id, and component_id are required")
		}
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		path := "/api/projects/" + url.PathEscape(in.ProjectID) + "/versions/" + url.PathEscape(in.ProjectVersionID) + "/components/" + url.PathEscape(in.ComponentID)
		resp, err := client.GetJSON(ctx, creds.apiToken, path, blackduck.MediaTypeBOMV6, nil)
		if err != nil {
			return nil, RawResponseOutput{}, blackduckToolError(err)
		}
		return nil, RawResponseOutput{BaseURL: cfg.BlackduckBaseURL, Response: resp}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "blackduck_bom_component_version_get",
		Description: "Read a BOM component version entry (GET /api/projects/{projectId}/versions/{projectVersionId}/components/{componentId}/versions/{componentVersionId}).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in BOMComponentVersionGetInput) (*mcp.CallToolResult, RawResponseOutput, error) {
		if in.ProjectID == "" || in.ProjectVersionID == "" || in.ComponentID == "" || in.ComponentVersionID == "" {
			return nil, RawResponseOutput{}, fmt.Errorf("project_id, project_version_id, component_id, and component_version_id are required")
		}
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		path := "/api/projects/" + url.PathEscape(in.ProjectID) + "/versions/" + url.PathEscape(in.ProjectVersionID) + "/components/" + url.PathEscape(in.ComponentID) + "/versions/" + url.PathEscape(in.ComponentVersionID)
		resp, err := client.GetJSON(ctx, creds.apiToken, path, blackduck.MediaTypeBOMV6, nil)
		if err != nil {
			return nil, RawResponseOutput{}, blackduckToolError(err)
		}
		return nil, RawResponseOutput{BaseURL: cfg.BlackduckBaseURL, Response: resp}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "blackduck_bom_component_policy_status_get",
		Description: "Get policy status for a BOM component version (GET .../policy-status).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in BOMComponentPolicyStatusGetInput) (*mcp.CallToolResult, RawResponseOutput, error) {
		if in.ProjectID == "" || in.ProjectVersionID == "" || in.ComponentID == "" || in.ComponentVersionID == "" {
			return nil, RawResponseOutput{}, fmt.Errorf("project_id, project_version_id, component_id, and component_version_id are required")
		}
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		path := "/api/projects/" + url.PathEscape(in.ProjectID) + "/versions/" + url.PathEscape(in.ProjectVersionID) + "/components/" + url.PathEscape(in.ComponentID) + "/versions/" + url.PathEscape(in.ComponentVersionID) + "/policy-status"
		resp, err := client.GetJSON(ctx, creds.apiToken, path, blackduck.MediaTypeBOMV7, nil)
		if err != nil {
			return nil, RawResponseOutput{}, blackduckToolError(err)
		}
		return nil, RawResponseOutput{BaseURL: cfg.BlackduckBaseURL, Response: resp}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "blackduck_bom_component_policy_rules_list",
		Description: "List policy rules for a BOM component version (GET .../policy-rules).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in BOMComponentPolicyRulesListInput) (*mcp.CallToolResult, RawResponseOutput, error) {
		if in.ProjectID == "" || in.ProjectVersionID == "" || in.ComponentID == "" || in.ComponentVersionID == "" {
			return nil, RawResponseOutput{}, fmt.Errorf("project_id, project_version_id, component_id, and component_version_id are required")
		}
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		q := url.Values{}
		setOptInt32(q, "offset", in.Offset)
		setOptInt32(q, "limit", in.Limit)
		setOptString(q, "sort", in.Sort)

		path := "/api/projects/" + url.PathEscape(in.ProjectID) + "/versions/" + url.PathEscape(in.ProjectVersionID) + "/components/" + url.PathEscape(in.ComponentID) + "/versions/" + url.PathEscape(in.ComponentVersionID) + "/policy-rules"
		resp, err := client.GetJSON(ctx, creds.apiToken, path, blackduck.MediaTypeBOMV7, q)
		if err != nil {
			return nil, RawResponseOutput{}, blackduckToolError(err)
		}
		return nil, RawResponseOutput{BaseURL: cfg.BlackduckBaseURL, Response: resp}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "blackduck_vulnerable_bom_components_list",
		Description: "List vulnerable BOM components for a project version (GET /api/projects/{projectId}/versions/{projectVersionId}/vulnerable-bom-components).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in VulnerableBOMComponentsListInput) (*mcp.CallToolResult, RawResponseOutput, error) {
		if in.ProjectID == "" || in.ProjectVersionID == "" {
			return nil, RawResponseOutput{}, fmt.Errorf("project_id and project_version_id are required")
		}
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		q := url.Values{}
		setOptInt32(q, "offset", in.Offset)
		setOptInt32(q, "limit", in.Limit)
		setOptString(q, "sort", in.Sort)

		path := "/api/projects/" + url.PathEscape(in.ProjectID) + "/versions/" + url.PathEscape(in.ProjectVersionID) + "/vulnerable-bom-components"
		resp, err := client.GetJSON(ctx, creds.apiToken, path, blackduck.MediaTypeBOMV8, q)
		if err != nil {
			return nil, RawResponseOutput{}, blackduckToolError(err)
		}
		return nil, RawResponseOutput{BaseURL: cfg.BlackduckBaseURL, Response: resp}, nil
	})
}

type ComponentsSearchInput struct {
	Q      string  `json:"q" jsonschema:"Component search query (required by Black Duck)."`
	Offset *int32  `json:"offset,omitempty"`
	Limit  *int32  `json:"limit,omitempty"`
	Sort   *string `json:"sort,omitempty"`
}

type ComponentGetInput struct {
	ComponentID string `json:"component_id" jsonschema:"Black Duck component identifier."`
}

type ComponentVersionsListInput struct {
	ComponentID string  `json:"component_id"`
	Offset      *int32  `json:"offset,omitempty"`
	Limit       *int32  `json:"limit,omitempty"`
	Sort        *string `json:"sort,omitempty"`
	Q           *string `json:"q,omitempty"`
	Filter      *string `json:"filter,omitempty"`
}

type ComponentVersionGetInput struct {
	ComponentID        string `json:"component_id"`
	ComponentVersionID string `json:"component_version_id"`
}

type ComponentVersionOriginsListInput struct {
	ComponentID        string  `json:"component_id"`
	ComponentVersionID string  `json:"component_version_id"`
	Offset             *int32  `json:"offset,omitempty"`
	Limit              *int32  `json:"limit,omitempty"`
	Sort               *string `json:"sort,omitempty"`
}

func registerComponentTools(server *mcp.Server, cfg config.Config, client *blackduck.Client, creds upstreamCreds) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "blackduck_components_search",
		Description: "Search components (GET /api/components). Note: Black Duck requires the q parameter.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ComponentsSearchInput) (*mcp.CallToolResult, RawResponseOutput, error) {
		if in.Q == "" {
			return nil, RawResponseOutput{}, fmt.Errorf("q is required")
		}
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		q := url.Values{}
		q.Set("q", in.Q)
		setOptInt32(q, "offset", in.Offset)
		setOptInt32(q, "limit", in.Limit)
		setOptString(q, "sort", in.Sort)

		resp, err := client.GetJSON(ctx, creds.apiToken, "/api/components", blackduck.MediaTypeComponentDetailV4, q)
		if err != nil {
			return nil, RawResponseOutput{}, blackduckToolError(err)
		}
		return nil, RawResponseOutput{BaseURL: cfg.BlackduckBaseURL, Response: resp}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "blackduck_components_get",
		Description: "Get a component by ID (GET /api/components/{componentId}).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ComponentGetInput) (*mcp.CallToolResult, RawResponseOutput, error) {
		if in.ComponentID == "" {
			return nil, RawResponseOutput{}, fmt.Errorf("component_id is required")
		}
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		path := "/api/components/" + url.PathEscape(in.ComponentID)
		resp, err := client.GetJSON(ctx, creds.apiToken, path, blackduck.MediaTypeComponentDetailV4, nil)
		if err != nil {
			return nil, RawResponseOutput{}, blackduckToolError(err)
		}
		return nil, RawResponseOutput{BaseURL: cfg.BlackduckBaseURL, Response: resp}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "blackduck_component_versions_list",
		Description: "List component versions (GET /api/components/{componentId}/versions).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ComponentVersionsListInput) (*mcp.CallToolResult, RawResponseOutput, error) {
		if in.ComponentID == "" {
			return nil, RawResponseOutput{}, fmt.Errorf("component_id is required")
		}
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		q := url.Values{}
		setOptInt32(q, "offset", in.Offset)
		setOptInt32(q, "limit", in.Limit)
		setOptString(q, "sort", in.Sort)
		setOptString(q, "q", in.Q)
		setOptString(q, "filter", in.Filter)

		path := "/api/components/" + url.PathEscape(in.ComponentID) + "/versions"
		resp, err := client.GetJSON(ctx, creds.apiToken, path, blackduck.MediaTypeComponentDetailV5, q)
		if err != nil {
			return nil, RawResponseOutput{}, blackduckToolError(err)
		}
		return nil, RawResponseOutput{BaseURL: cfg.BlackduckBaseURL, Response: resp}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "blackduck_component_versions_get",
		Description: "Get a component version (GET /api/components/{componentId}/versions/{componentVersionId}).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ComponentVersionGetInput) (*mcp.CallToolResult, RawResponseOutput, error) {
		if in.ComponentID == "" || in.ComponentVersionID == "" {
			return nil, RawResponseOutput{}, fmt.Errorf("component_id and component_version_id are required")
		}
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		path := "/api/components/" + url.PathEscape(in.ComponentID) + "/versions/" + url.PathEscape(in.ComponentVersionID)
		resp, err := client.GetJSON(ctx, creds.apiToken, path, blackduck.MediaTypeComponentDetailV5, nil)
		if err != nil {
			return nil, RawResponseOutput{}, blackduckToolError(err)
		}
		return nil, RawResponseOutput{BaseURL: cfg.BlackduckBaseURL, Response: resp}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "blackduck_component_version_origins_list",
		Description: "List origins for a component version (GET /api/components/{componentId}/versions/{componentVersionId}/origins).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ComponentVersionOriginsListInput) (*mcp.CallToolResult, RawResponseOutput, error) {
		if in.ComponentID == "" || in.ComponentVersionID == "" {
			return nil, RawResponseOutput{}, fmt.Errorf("component_id and component_version_id are required")
		}
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		q := url.Values{}
		setOptInt32(q, "offset", in.Offset)
		setOptInt32(q, "limit", in.Limit)
		setOptString(q, "sort", in.Sort)

		path := "/api/components/" + url.PathEscape(in.ComponentID) + "/versions/" + url.PathEscape(in.ComponentVersionID) + "/origins"
		resp, err := client.GetJSON(ctx, creds.apiToken, path, blackduck.MediaTypeComponentDetailV5, q)
		if err != nil {
			return nil, RawResponseOutput{}, blackduckToolError(err)
		}
		return nil, RawResponseOutput{BaseURL: cfg.BlackduckBaseURL, Response: resp}, nil
	})
}

type CopyrightsListInput struct {
	ComponentID              string  `json:"component_id"`
	ComponentVersionID       string  `json:"component_version_id"`
	ComponentVersionOriginID string  `json:"component_version_origin_id"`
	Offset                   *int32  `json:"offset,omitempty"`
	Limit                    *int32  `json:"limit,omitempty"`
	Sort                     *string `json:"sort,omitempty"`
}

func registerCopyrightTools(server *mcp.Server, cfg config.Config, client *blackduck.Client, creds upstreamCreds) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "blackduck_copyrights_list",
		Description: "List copyrights for a component version origin (GET /api/components/{componentId}/versions/{componentVersionId}/origins/{componentVersionOriginId}/copyrights).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in CopyrightsListInput) (*mcp.CallToolResult, RawResponseOutput, error) {
		if in.ComponentID == "" || in.ComponentVersionID == "" || in.ComponentVersionOriginID == "" {
			return nil, RawResponseOutput{}, fmt.Errorf("component_id, component_version_id, and component_version_origin_id are required")
		}
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		q := url.Values{}
		setOptInt32(q, "offset", in.Offset)
		setOptInt32(q, "limit", in.Limit)
		setOptString(q, "sort", in.Sort)

		path := "/api/components/" + url.PathEscape(in.ComponentID) + "/versions/" + url.PathEscape(in.ComponentVersionID) + "/origins/" + url.PathEscape(in.ComponentVersionOriginID) + "/copyrights"
		resp, err := client.GetJSON(ctx, creds.apiToken, path, blackduck.MediaTypeCopyrightV4, q)
		if err != nil {
			return nil, RawResponseOutput{}, blackduckToolError(err)
		}
		return nil, RawResponseOutput{BaseURL: cfg.BlackduckBaseURL, Response: resp}, nil
	})
}

type ComponentVulnerabilitiesListInput struct {
	ComponentID string  `json:"component_id"`
	Offset      *int32  `json:"offset,omitempty"`
	Limit       *int32  `json:"limit,omitempty"`
	Sort        *string `json:"sort,omitempty"`
}

type ComponentVersionVulnerabilitiesListInput struct {
	ComponentID        string  `json:"component_id"`
	ComponentVersionID string  `json:"component_version_id"`
	Offset             *int32  `json:"offset,omitempty"`
	Limit              *int32  `json:"limit,omitempty"`
	Sort               *string `json:"sort,omitempty"`
}

type VulnerabilityGetInput struct {
	VulnerabilityID string `json:"vulnerability_id"`
}

type ProjectVersionVulnerabilityMatchesListInput struct {
	ProjectID        string  `json:"project_id"`
	ProjectVersionID string  `json:"project_version_id"`
	VulnerabilityID  string  `json:"vulnerability_id"`
	Offset           *int32  `json:"offset,omitempty"`
	Limit            *int32  `json:"limit,omitempty"`
	Sort             *string `json:"sort,omitempty"`
}

func registerVulnerabilityTools(server *mcp.Server, cfg config.Config, client *blackduck.Client, creds upstreamCreds) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "blackduck_component_vulnerabilities_list",
		Description: "List vulnerabilities for a component (GET /api/components/{componentId}/vulnerabilities).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ComponentVulnerabilitiesListInput) (*mcp.CallToolResult, RawResponseOutput, error) {
		if in.ComponentID == "" {
			return nil, RawResponseOutput{}, fmt.Errorf("component_id is required")
		}
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		q := url.Values{}
		setOptInt32(q, "offset", in.Offset)
		setOptInt32(q, "limit", in.Limit)
		setOptString(q, "sort", in.Sort)

		path := "/api/components/" + url.PathEscape(in.ComponentID) + "/vulnerabilities"
		resp, err := client.GetJSON(ctx, creds.apiToken, path, blackduck.MediaTypeVulnerabilityV4, q)
		if err != nil {
			return nil, RawResponseOutput{}, blackduckToolError(err)
		}
		return nil, RawResponseOutput{BaseURL: cfg.BlackduckBaseURL, Response: resp}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "blackduck_component_version_vulnerabilities_list",
		Description: "List vulnerabilities for a component version (GET /api/components/{componentId}/versions/{componentVersionId}/vulnerabilities).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ComponentVersionVulnerabilitiesListInput) (*mcp.CallToolResult, RawResponseOutput, error) {
		if in.ComponentID == "" || in.ComponentVersionID == "" {
			return nil, RawResponseOutput{}, fmt.Errorf("component_id and component_version_id are required")
		}
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		q := url.Values{}
		setOptInt32(q, "offset", in.Offset)
		setOptInt32(q, "limit", in.Limit)
		setOptString(q, "sort", in.Sort)

		path := "/api/components/" + url.PathEscape(in.ComponentID) + "/versions/" + url.PathEscape(in.ComponentVersionID) + "/vulnerabilities"
		resp, err := client.GetJSON(ctx, creds.apiToken, path, blackduck.MediaTypeVulnerabilityV4, q)
		if err != nil {
			return nil, RawResponseOutput{}, blackduckToolError(err)
		}
		return nil, RawResponseOutput{BaseURL: cfg.BlackduckBaseURL, Response: resp}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "blackduck_vulnerabilities_get",
		Description: "Get a vulnerability by ID (GET /api/vulnerabilities/{vulnerabilityId}).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in VulnerabilityGetInput) (*mcp.CallToolResult, RawResponseOutput, error) {
		if in.VulnerabilityID == "" {
			return nil, RawResponseOutput{}, fmt.Errorf("vulnerability_id is required")
		}
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		path := "/api/vulnerabilities/" + url.PathEscape(in.VulnerabilityID)
		resp, err := client.GetJSON(ctx, creds.apiToken, path, blackduck.MediaTypeVulnerabilityV4, nil)
		if err != nil {
			return nil, RawResponseOutput{}, blackduckToolError(err)
		}
		return nil, RawResponseOutput{BaseURL: cfg.BlackduckBaseURL, Response: resp}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "blackduck_project_version_vulnerability_matches_list",
		Description: "List vulnerability matches for a project version (GET /api/projects/{projectId}/versions/{projectVersionId}/vulnerabilities/{vulnerabilityId}/vulnerability-matches).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ProjectVersionVulnerabilityMatchesListInput) (*mcp.CallToolResult, RawResponseOutput, error) {
		if in.ProjectID == "" || in.ProjectVersionID == "" || in.VulnerabilityID == "" {
			return nil, RawResponseOutput{}, fmt.Errorf("project_id, project_version_id, and vulnerability_id are required")
		}
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		q := url.Values{}
		setOptInt32(q, "offset", in.Offset)
		setOptInt32(q, "limit", in.Limit)
		setOptString(q, "sort", in.Sort)

		path := "/api/projects/" + url.PathEscape(in.ProjectID) + "/versions/" + url.PathEscape(in.ProjectVersionID) + "/vulnerabilities/" + url.PathEscape(in.VulnerabilityID) + "/vulnerability-matches"
		resp, err := client.GetJSON(ctx, creds.apiToken, path, blackduck.MediaTypeVulnerabilityV4, q)
		if err != nil {
			return nil, RawResponseOutput{}, blackduckToolError(err)
		}
		return nil, RawResponseOutput{BaseURL: cfg.BlackduckBaseURL, Response: resp}, nil
	})
}

type CodeLocationScanSummariesListInput struct {
	CodeLocationID string  `json:"code_location_id"`
	Offset         *int32  `json:"offset,omitempty"`
	Limit          *int32  `json:"limit,omitempty"`
	Sort           *string `json:"sort,omitempty"`
}

type CodeLocationLatestScanSummaryGetInput struct {
	CodeLocationID string `json:"code_location_id"`
}

type ScanSummaryGetInput struct {
	ScanID string `json:"scan_id"`
}

func registerScanTools(server *mcp.Server, cfg config.Config, client *blackduck.Client, creds upstreamCreds) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "blackduck_codelocation_scan_summaries_list",
		Description: "List scan summaries for a code location (GET /api/codelocations/{codeLocationId}/scan-summaries).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in CodeLocationScanSummariesListInput) (*mcp.CallToolResult, RawResponseOutput, error) {
		if in.CodeLocationID == "" {
			return nil, RawResponseOutput{}, fmt.Errorf("code_location_id is required")
		}
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		q := url.Values{}
		setOptInt32(q, "offset", in.Offset)
		setOptInt32(q, "limit", in.Limit)
		setOptString(q, "sort", in.Sort)

		path := "/api/codelocations/" + url.PathEscape(in.CodeLocationID) + "/scan-summaries"
		resp, err := client.GetJSON(ctx, creds.apiToken, path, blackduck.MediaTypeScanV6, q)
		if err != nil {
			return nil, RawResponseOutput{}, blackduckToolError(err)
		}
		return nil, RawResponseOutput{BaseURL: cfg.BlackduckBaseURL, Response: resp}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "blackduck_codelocation_latest_scan_summary_get",
		Description: "Get the latest scan summary for a code location (GET /api/codelocations/{codeLocationId}/latest-scan-summary).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in CodeLocationLatestScanSummaryGetInput) (*mcp.CallToolResult, RawResponseOutput, error) {
		if in.CodeLocationID == "" {
			return nil, RawResponseOutput{}, fmt.Errorf("code_location_id is required")
		}
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		path := "/api/codelocations/" + url.PathEscape(in.CodeLocationID) + "/latest-scan-summary"
		resp, err := client.GetJSON(ctx, creds.apiToken, path, blackduck.MediaTypeScanV6, nil)
		if err != nil {
			return nil, RawResponseOutput{}, blackduckToolError(err)
		}
		return nil, RawResponseOutput{BaseURL: cfg.BlackduckBaseURL, Response: resp}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "blackduck_scan_summaries_get",
		Description: "Get a scan summary by ID (GET /api/scan-summaries/{scanId}).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ScanSummaryGetInput) (*mcp.CallToolResult, RawResponseOutput, error) {
		if in.ScanID == "" {
			return nil, RawResponseOutput{}, fmt.Errorf("scan_id is required")
		}
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		path := "/api/scan-summaries/" + url.PathEscape(in.ScanID)
		resp, err := client.GetJSON(ctx, creds.apiToken, path, blackduck.MediaTypeScanV6, nil)
		if err != nil {
			return nil, RawResponseOutput{}, blackduckToolError(err)
		}
		return nil, RawResponseOutput{BaseURL: cfg.BlackduckBaseURL, Response: resp}, nil
	})
}

type UsersListInput struct {
	Offset *int32  `json:"offset,omitempty"`
	Limit  *int32  `json:"limit,omitempty"`
	Sort   *string `json:"sort,omitempty"`
	Q      *string `json:"q,omitempty"`
	Filter *string `json:"filter,omitempty"`
}

type DormantUsersListInput struct {
	SinceDays *int32  `json:"since_days,omitempty" jsonschema:"Number of days since last login to consider a user dormant (mapped to sinceDays query param)."`
	Offset    *int32  `json:"offset,omitempty" jsonschema:"Pagination offset."`
	Limit     *int32  `json:"limit,omitempty" jsonschema:"Pagination limit."`
	Sort      *string `json:"sort,omitempty" jsonschema:"Sort specification."`
	Q         *string `json:"q,omitempty" jsonschema:"Search query (if supported by the endpoint)."`
	Filter    *string `json:"filter,omitempty" jsonschema:"Filter expression (if supported by the endpoint)."`
}

type UserGetInput struct {
	UserID string `json:"user_id"`
}

type UserUpdateInput struct {
	UserID  string         `json:"user_id" jsonschema:"Black Duck user identifier."`
	Updates map[string]any `json:"updates" jsonschema:"Fields to update. Supported keys: active, userName, externalUserName, firstName, lastName, email, type."`
}

type UserUserGroupsListInput struct {
	UserID string  `json:"user_id"`
	Offset *int32  `json:"offset,omitempty"`
	Limit  *int32  `json:"limit,omitempty"`
	Sort   *string `json:"sort,omitempty"`
	Q      *string `json:"q,omitempty"`
	Filter *string `json:"filter,omitempty"`
}

func registerUserTools(server *mcp.Server, cfg config.Config, client *blackduck.Client, creds upstreamCreds) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "blackduck_users_list",
		Description: "List users (GET /api/users).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in UsersListInput) (*mcp.CallToolResult, RawResponseOutput, error) {
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		q := url.Values{}
		setOptInt32(q, "offset", in.Offset)
		setOptInt32(q, "limit", in.Limit)
		setOptString(q, "sort", in.Sort)
		setOptString(q, "q", in.Q)
		setOptString(q, "filter", in.Filter)

		resp, err := client.GetJSON(ctx, creds.apiToken, "/api/users", blackduck.MediaTypeUserV4, q)
		if err != nil {
			return nil, RawResponseOutput{}, blackduckToolError(err)
		}
		return nil, RawResponseOutput{BaseURL: cfg.BlackduckBaseURL, Response: resp}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "blackduck_users_get",
		Description: "Get a user by ID (GET /api/users/{userId}).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in UserGetInput) (*mcp.CallToolResult, RawResponseOutput, error) {
		if in.UserID == "" {
			return nil, RawResponseOutput{}, fmt.Errorf("user_id is required")
		}
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		path := "/api/users/" + url.PathEscape(in.UserID)
		resp, err := client.GetJSON(ctx, creds.apiToken, path, blackduck.MediaTypeUserV4, nil)
		if err != nil {
			return nil, RawResponseOutput{}, blackduckToolError(err)
		}
		return nil, RawResponseOutput{BaseURL: cfg.BlackduckBaseURL, Response: resp}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "blackduck_dormant_users_list",
		Description: "List dormant users (GET /api/dormant-users).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in DormantUsersListInput) (*mcp.CallToolResult, RawResponseOutput, error) {
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		q := url.Values{}
		setOptInt32(q, "sinceDays", in.SinceDays)
		setOptInt32(q, "offset", in.Offset)
		setOptInt32(q, "limit", in.Limit)
		setOptString(q, "sort", in.Sort)
		setOptString(q, "q", in.Q)
		setOptString(q, "filter", in.Filter)

		resp, err := client.GetJSON(ctx, creds.apiToken, "/api/dormant-users", blackduck.MediaTypeUserV4, q)
		if err != nil {
			return nil, RawResponseOutput{}, blackduckToolError(err)
		}
		return nil, RawResponseOutput{BaseURL: cfg.BlackduckBaseURL, Response: resp}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "blackduck_users_update",
		Description: "Update a user by ID (PUT /api/users/{userId}). This endpoint requires a full user payload; this tool fetches the current user and applies the requested field updates.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in UserUpdateInput) (*mcp.CallToolResult, RawResponseOutput, error) {
		if in.UserID == "" {
			return nil, RawResponseOutput{}, fmt.Errorf("user_id is required")
		}
		if len(in.Updates) == 0 {
			return nil, RawResponseOutput{}, fmt.Errorf("updates is required")
		}
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		path := "/api/users/" + url.PathEscape(in.UserID)
		current, err := client.GetJSON(ctx, creds.apiToken, path, blackduck.MediaTypeUserV4, nil)
		if err != nil {
			return nil, RawResponseOutput{}, blackduckToolError(err)
		}

		body, err := buildUserUpdateBody(current, in.Updates)
		if err != nil {
			return nil, RawResponseOutput{}, err
		}

		resp, err := client.PutJSON(ctx, creds.apiToken, path, blackduck.MediaTypeUserV4, blackduck.MediaTypeUserV4, body)
		if err != nil {
			return nil, RawResponseOutput{}, blackduckToolError(err)
		}
		return nil, RawResponseOutput{BaseURL: cfg.BlackduckBaseURL, Response: resp}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "blackduck_user_usergroups_list",
		Description: "List user groups for a user (GET /api/users/{userId}/usergroups).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in UserUserGroupsListInput) (*mcp.CallToolResult, RawResponseOutput, error) {
		if in.UserID == "" {
			return nil, RawResponseOutput{}, fmt.Errorf("user_id is required")
		}
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		q := url.Values{}
		setOptInt32(q, "offset", in.Offset)
		setOptInt32(q, "limit", in.Limit)
		setOptString(q, "sort", in.Sort)
		setOptString(q, "q", in.Q)
		setOptString(q, "filter", in.Filter)

		path := "/api/users/" + url.PathEscape(in.UserID) + "/usergroups"
		resp, err := client.GetJSON(ctx, creds.apiToken, path, blackduck.MediaTypeUserV4, q)
		if err != nil {
			return nil, RawResponseOutput{}, blackduckToolError(err)
		}
		return nil, RawResponseOutput{BaseURL: cfg.BlackduckBaseURL, Response: resp}, nil
	})
}

func buildUserUpdateBody(current map[string]any, updates map[string]any) (map[string]any, error) {
	allowed := map[string]struct{}{
		"active":           {},
		"userName":         {},
		"externalUserName": {},
		"firstName":        {},
		"lastName":         {},
		"email":            {},
		"type":             {},
	}
	for k := range updates {
		if _, ok := allowed[k]; !ok {
			return nil, fmt.Errorf("unsupported update field %q (allowed: active, userName, externalUserName, firstName, lastName, email, type)", k)
		}
	}

	userName, ok := current["userName"].(string)
	if !ok || userName == "" {
		return nil, fmt.Errorf("unexpected user payload: missing userName")
	}
	firstName, ok := current["firstName"].(string)
	if !ok || firstName == "" {
		return nil, fmt.Errorf("unexpected user payload: missing firstName")
	}
	lastName, ok := current["lastName"].(string)
	if !ok || lastName == "" {
		return nil, fmt.Errorf("unexpected user payload: missing lastName")
	}
	email, ok := current["email"].(string)
	if !ok || email == "" {
		return nil, fmt.Errorf("unexpected user payload: missing email")
	}
	typeStr, ok := current["type"].(string)
	if !ok || typeStr == "" {
		return nil, fmt.Errorf("unexpected user payload: missing type")
	}
	active, ok := current["active"].(bool)
	if !ok {
		return nil, fmt.Errorf("unexpected user payload: missing active")
	}
	externalUserName, _ := current["externalUserName"].(string)

	if v, ok := updates["userName"]; ok {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("updates.userName must be a string")
		}
		userName = s
	}
	if v, ok := updates["externalUserName"]; ok {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("updates.externalUserName must be a string")
		}
		externalUserName = s
	}
	if v, ok := updates["firstName"]; ok {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("updates.firstName must be a string")
		}
		firstName = s
	}
	if v, ok := updates["lastName"]; ok {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("updates.lastName must be a string")
		}
		lastName = s
	}
	if v, ok := updates["email"]; ok {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("updates.email must be a string")
		}
		email = s
	}
	if v, ok := updates["type"]; ok {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("updates.type must be a string")
		}
		typeStr = s
	}
	if v, ok := updates["active"]; ok {
		b, ok := v.(bool)
		if !ok {
			return nil, fmt.Errorf("updates.active must be a boolean")
		}
		active = b
	}

	if _, ok := updates["externalUserName"]; !ok && externalUserName == "" {
		externalUserName = userName
	}
	if typeStr == "EXTERNAL" && externalUserName == "" {
		return nil, fmt.Errorf("externalUserName is required for EXTERNAL users")
	}

	return map[string]any{
		"userName":         userName,
		"externalUserName": externalUserName,
		"firstName":        firstName,
		"lastName":         lastName,
		"email":            email,
		"type":             typeStr,
		"active":           active,
	}, nil
}

type UserGroupsListInput struct {
	Offset *int32  `json:"offset,omitempty"`
	Limit  *int32  `json:"limit,omitempty"`
	Sort   *string `json:"sort,omitempty"`
	Q      *string `json:"q,omitempty"`
	Filter *string `json:"filter,omitempty"`
}

type UserGroupGetInput struct {
	UserGroupID string `json:"user_group_id"`
}

func registerUserGroupTools(server *mcp.Server, cfg config.Config, client *blackduck.Client, creds upstreamCreds) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "blackduck_usergroups_list",
		Description: "List user groups (GET /api/usergroups).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in UserGroupsListInput) (*mcp.CallToolResult, RawResponseOutput, error) {
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		q := url.Values{}
		setOptInt32(q, "offset", in.Offset)
		setOptInt32(q, "limit", in.Limit)
		setOptString(q, "sort", in.Sort)
		setOptString(q, "q", in.Q)
		setOptString(q, "filter", in.Filter)

		resp, err := client.GetJSON(ctx, creds.apiToken, "/api/usergroups", blackduck.MediaTypeUserV4, q)
		if err != nil {
			return nil, RawResponseOutput{}, blackduckToolError(err)
		}
		return nil, RawResponseOutput{BaseURL: cfg.BlackduckBaseURL, Response: resp}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "blackduck_usergroups_get",
		Description: "Get a user group by ID (GET /api/usergroups/{userGroupId}).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in UserGroupGetInput) (*mcp.CallToolResult, RawResponseOutput, error) {
		if in.UserGroupID == "" {
			return nil, RawResponseOutput{}, fmt.Errorf("user_group_id is required")
		}
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		path := "/api/usergroups/" + url.PathEscape(in.UserGroupID)
		resp, err := client.GetJSON(ctx, creds.apiToken, path, blackduck.MediaTypeUserV4, nil)
		if err != nil {
			return nil, RawResponseOutput{}, blackduckToolError(err)
		}
		return nil, RawResponseOutput{BaseURL: cfg.BlackduckBaseURL, Response: resp}, nil
	})
}
