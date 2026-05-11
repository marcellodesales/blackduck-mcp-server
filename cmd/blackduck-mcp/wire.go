//go:build wireinject

package main

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/google/wire"

	"git.viasat.com/seceng-devsecops-platform/blackduck-mcp/internal/infra/blackduck"
	"git.viasat.com/seceng-devsecops-platform/blackduck-mcp/internal/interfaces/httpserver"
	"git.viasat.com/seceng-devsecops-platform/blackduck-mcp/internal/interfaces/mcp"
	"git.viasat.com/seceng-devsecops-platform/blackduck-mcp/internal/platform/app"
	"git.viasat.com/seceng-devsecops-platform/blackduck-mcp/internal/platform/config"
	"git.viasat.com/seceng-devsecops-platform/blackduck-mcp/internal/platform/logging"
	"git.viasat.com/seceng-devsecops-platform/blackduck-mcp/internal/platform/viasatca"
	"git.viasat.com/seceng-devsecops-platform/blackduck-mcp/internal/platform/wiring"
)

func InitializeApp() (*app.App, error) {
	wire.Build(
		config.Load,
		logging.New,
		wiring.ProvideSealer,
		wiring.ProvideAuthService,
		wiring.ProvideViasatCABootstrapper,
		wiring.ProvideHTTPClient,
		blackduck.ProvideClient,
		mcpserver.NewHandler,
		httpserver.NewRouter,
		httpserver.ProvideHandler,
		httpserver.NewServer,
		newApp,
	)
	return nil, nil
}

func newApp(logger *slog.Logger, srv *http.Server, viasatCABootstrapper *viasatca.Bootstrapper) *app.App {
	return &app.App{
		Logger:               logger,
		HTTPServer:           srv,
		ShutdownTimeout:      10 * time.Second,
		ViasatCABootstrapper: viasatCABootstrapper,
	}
}
