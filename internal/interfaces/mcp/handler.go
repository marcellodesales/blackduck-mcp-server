package mcpserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/marcellodesales/blackduck-mcp-server/internal/infra/blackduck"
	"github.com/marcellodesales/blackduck-mcp-server/internal/platform/config"
	"github.com/marcellodesales/blackduck-mcp-server/internal/platform/mcpauth"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Handler is a distinct interface type (separate from net/http.Handler) so DI can
// distinguish the MCP transport handler from the root HTTP handler.
//
// It intentionally matches http.Handler's method set.
type Handler interface {
	ServeHTTP(http.ResponseWriter, *http.Request)
}

type credsKey struct{}

type accessModeKey struct{}

type upstreamCreds struct {
	principal string
	apiToken  string
}

func withCreds(ctx context.Context, c upstreamCreds) context.Context {
	return context.WithValue(ctx, credsKey{}, c)
}

func credsFromContext(ctx context.Context) (upstreamCreds, bool) {
	v := ctx.Value(credsKey{})
	if v == nil {
		return upstreamCreds{}, false
	}
	c, ok := v.(upstreamCreds)
	return c, ok
}

func withAccessMode(ctx context.Context, m mcpauth.AccessMode) context.Context {
	return context.WithValue(ctx, accessModeKey{}, m)
}

func accessModeFromContext(ctx context.Context) mcpauth.AccessMode {
	v := ctx.Value(accessModeKey{})
	if v == nil {
		return mcpauth.AccessModeReadOnly
	}
	m, ok := v.(mcpauth.AccessMode)
	if !ok || strings.TrimSpace(string(m)) == "" {
		return mcpauth.AccessModeReadOnly
	}
	if m != mcpauth.AccessModeReadWrite {
		return mcpauth.AccessModeReadOnly
	}
	return m
}

func requireWriteAccess(ctx context.Context) error {
	if accessModeFromContext(ctx) != mcpauth.AccessModeReadWrite {
		return fmt.Errorf("write operations are disabled for this access token; re-authorize with READ-WRITE")
	}
	return nil
}

// publicMCPMethods are JSON-RPC methods a client may call WITHOUT authentication
// so registries, catalogs, and agents can DISCOVER the toolset. Tool execution
// (tools/call) and everything else still require a valid bearer / Basic credential.
var publicMCPMethods = map[string]bool{
	"initialize":                true,
	"notifications/initialized": true,
	"tools/list":                true,
	"prompts/list":              true,
	"resources/list":            true,
	"resources/templates/list":  true,
	"ping":                      true,
}

// isPublicMCPRequest reports whether the POST body is a JSON-RPC discovery method
// that may proceed unauthenticated. It reads and RESTORES the body so the
// downstream MCP handler still sees it.
func isPublicMCPRequest(req *http.Request) bool {
	if req.Method != http.MethodPost || req.Body == nil {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, 1<<20))
	if err != nil {
		return false
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	var rpc struct {
		Method string `json:"method"`
	}
	if err := json.Unmarshal(body, &rpc); err != nil {
		return false
	}
	return publicMCPMethods[rpc.Method]
}

func NewHandler(cfg config.Config, logger *slog.Logger, tokenSvc *mcpauth.Service, blackduckClient *blackduck.Client) (Handler, error) {
	streamable := mcp.NewStreamableHTTPHandler(func(req *http.Request) *mcp.Server {
		c, ok := credsFromContext(req.Context())
		if !ok {
			return nil
		}

		writeEnabled := accessModeFromContext(req.Context()) == mcpauth.AccessModeReadWrite

		server := mcp.NewServer(&mcp.Implementation{Name: "blackduck-mcp", Version: "0.1.0"}, nil)

		registerBlackduckTools(server, cfg, tokenSvc, blackduckClient, c, writeEnabled)
		registerBlackduckPrompts(server)

		return server
	}, &mcp.StreamableHTTPOptions{
		Stateless:    true,
		JSONResponse: cfg.JSONResponse,
		Logger:       logger,
	})

	resourceMetadataURL := cfg.ServerURL + "/.well-known/oauth-protected-resource/mcp"

	verifier := func(ctx context.Context, token string, req *http.Request) (*auth.TokenInfo, error) {
		var at mcpauth.AccessTokenData
		meta, err := tokenSvc.Parse(string(mcpauth.TokenTypeAccessToken), token, &at)
		if err != nil {
			if errors.Is(err, mcpauth.ErrTokenExpired) {
				return nil, fmt.Errorf("%w: token expired", auth.ErrInvalidToken)
			}
			return nil, fmt.Errorf("%w: invalid token", auth.ErrInvalidToken)
		}
		return &auth.TokenInfo{UserID: at.Principal, Expiration: meta.ExpiresAt}, nil
	}

	bearerOnly := auth.RequireBearerToken(verifier, &auth.RequireBearerTokenOptions{ResourceMetadataURL: resourceMetadataURL})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verified bearer token; decrypt again to get upstream API token.
		fields := strings.Fields(r.Header.Get("Authorization"))
		if len(fields) != 2 {
			http.Error(w, "no bearer token", http.StatusUnauthorized)
			return
		}
		var at mcpauth.AccessTokenData
		if _, err := tokenSvc.Parse(string(mcpauth.TokenTypeAccessToken), fields[1], &at); err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		accessMode := at.AccessMode
		if accessMode != mcpauth.AccessModeReadWrite {
			accessMode = mcpauth.AccessModeReadOnly
		}
		ctx := withCreds(r.Context(), upstreamCreds{principal: at.Principal, apiToken: at.APIToken})
		ctx = withAccessMode(ctx, accessMode)
		streamable.ServeHTTP(w, r.WithContext(ctx))
	}))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		if strings.HasPrefix(strings.ToLower(authz), "basic ") {
			// For convenience, accept Basic auth where the password is treated as the Black Duck API token.
			// The username is treated as an optional principal label.
			user, pass, ok := parseBasicAuth(authz)
			if !ok {
				http.Error(w, "invalid basic auth", http.StatusUnauthorized)
				return
			}
			ctx := withCreds(r.Context(), upstreamCreds{principal: user, apiToken: pass})
			// Default direct Basic auth to read-only to avoid accidental writes.
			ctx = withAccessMode(ctx, mcpauth.AccessModeReadOnly)
			streamable.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// Discovery methods (initialize, tools/list, …) sent WITHOUT credentials
		// proceed unauthenticated so registries, catalogs, and agents can enumerate
		// the toolset per the MCP protocol. Tool execution (tools/call) and every
		// other method still fall through to bearerOnly and require a valid token.
		// A default (empty-credential) read-only context is injected so the server
		// factory can register the tool schemas for tools/list.
		if strings.TrimSpace(authz) == "" && isPublicMCPRequest(r) {
			ctx := withCreds(r.Context(), upstreamCreds{})
			ctx = withAccessMode(ctx, mcpauth.AccessModeReadOnly)
			streamable.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		bearerOnly.ServeHTTP(w, r)
	}), nil
}

func parseBasicAuth(header string) (user string, pass string, ok bool) {
	fields := strings.Fields(header)
	if len(fields) != 2 || strings.ToLower(fields[0]) != "basic" {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return "", "", false
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}
