package httpserver

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"git.viasat.com/seceng-devsecops-platform/blackduck-mcp/internal/infra/blackduck"
	"git.viasat.com/seceng-devsecops-platform/blackduck-mcp/internal/interfaces/mcp"
	"git.viasat.com/seceng-devsecops-platform/blackduck-mcp/internal/platform/config"
	"git.viasat.com/seceng-devsecops-platform/blackduck-mcp/internal/platform/mcpauth"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
)

type Router struct {
	cfg        config.Config
	logger     *slog.Logger
	mcpHandler mcpserver.Handler

	tokenSvc  *mcpauth.Service
	blackduck *blackduck.Client
}

func NewRouter(cfg config.Config, logger *slog.Logger, mcpHandler mcpserver.Handler, tokenSvc *mcpauth.Service, blackduckClient *blackduck.Client) *Router {
	return &Router{cfg: cfg, logger: logger, mcpHandler: mcpHandler, tokenSvc: tokenSvc, blackduck: blackduckClient}
}

func (r *Router) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "ok",
			"service": "blackduck-mcp",
		})
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("blackduck-mcp\n"))
	})

	// OAuth + MCP metadata endpoints.
	mux.HandleFunc("/.well-known/mcp/server-card.json", r.serverCard)
	mux.HandleFunc("/.well-known/oauth-authorization-server", r.authorizationServerMetadata)
	mux.Handle(
		"/.well-known/oauth-protected-resource/mcp",
		auth.ProtectedResourceMetadataHandler(&oauthex.ProtectedResourceMetadata{
			Resource:               r.cfg.ServerURL + "/mcp",
			AuthorizationServers:   []string{r.cfg.ServerURL},
			ScopesSupported:        nil,
			BearerMethodsSupported: nil,
		}),
	)

	// OAuth endpoints.
	mux.HandleFunc("/register", r.registerClient)
	mux.HandleFunc("/authorize", r.authorize)
	mux.HandleFunc("/token", r.token)

	// Login UI.
	mux.HandleFunc("/blackduck/login", r.blackduckLogin)

	// MCP endpoint (support both /mcp and /mcp/).
	mux.Handle("/mcp", r.mcpHandler)
	mux.Handle("/mcp/", r.mcpHandler)

	return mux
}
