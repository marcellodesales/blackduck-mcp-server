//go:build wireinject

package main

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/google/wire"

	"github.com/marcellodesales/blackduck-mcp-server/internal/infra/blackduck"
	"github.com/marcellodesales/blackduck-mcp-server/internal/interfaces/httpserver"
	"github.com/marcellodesales/blackduck-mcp-server/internal/interfaces/mcp"
	"github.com/marcellodesales/blackduck-mcp-server/internal/platform/app"
	"github.com/marcellodesales/blackduck-mcp-server/internal/platform/config"
	"github.com/marcellodesales/blackduck-mcp-server/internal/platform/logging"
	"github.com/marcellodesales/blackduck-mcp-server/internal/platform/privateca"
	"github.com/marcellodesales/blackduck-mcp-server/internal/platform/wiring"
)

func InitializeApp() (*app.App, error) {
	wire.Build(
		config.Load,
		logging.New,
		wiring.ProvideSealer,
		wiring.ProvideAuthService,
		wiring.ProvidePrivateCABootstrapper,
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

func newApp(logger *slog.Logger, srv *http.Server, privateCABootstrapper *privateca.Bootstrapper) *app.App {
	return &app.App{
		Logger:                logger,
		HTTPServer:            srv,
		ShutdownTimeout:       10 * time.Second,
		PrivateCABootstrapper: privateCABootstrapper,
	}
}
