package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"git.viasat.com/seceng-devsecops-platform/blackduck-mcp/internal/platform/viasatca"
)

type App struct {
	Logger               *slog.Logger
	HTTPServer           *http.Server
	ShutdownTimeout      time.Duration
	ViasatCABootstrapper *viasatca.Bootstrapper
}

func (a *App) Run(ctx context.Context) error {
	if err := a.handlePrerequirements(ctx); err != nil {
		return err
	}

	errCh := make(chan error, 1)
	go func() {
		a.Logger.Info("http server starting", "addr", a.HTTPServer.Addr)
		errCh <- a.HTTPServer.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), a.ShutdownTimeout)
		defer cancel()

		a.Logger.Info("http server shutting down")
		if err := a.HTTPServer.Shutdown(shutdownCtx); err != nil {
			return err
		}
		return nil
	case err := <-errCh:
		if err == nil {
			return nil
		}
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (a *App) handlePrerequirements(ctx context.Context) error {
	if err := a.ensurePrivateCARoot(ctx); err != nil {
		return fmt.Errorf("handle startup prerequisites: %w", err)
	}
	return nil
}

// ensurePrivateCARoot reuses the Viasat private CA bundle already present on
// disk and only fetches it from ViasatIOCACertURL when it is missing. This
// keeps container restarts cheap and avoids hard-coupling startup to network
// reachability of `cacerts.viasat.io` when the bundle has already been
// primed (e.g. via the `./data/certs:/viasat/certs` docker-compose volume).
func (a *App) ensurePrivateCARoot(ctx context.Context) error {
	if a.ViasatCABootstrapper == nil {
		return nil
	}

	status, err := a.ViasatCABootstrapper.EnsurePrivateCARoot(ctx)
	if err != nil {
		return fmt.Errorf("ensure private ca root: %w", err)
	}
	if a.Logger != nil && status.Enabled && status.Exists {
		a.Logger.Info(
			"private ca root ready",
			"path", status.ViasatIOCACertFile,
			"size_bytes", status.SizeBytes,
			"updated_at", status.UpdatedAt,
			"refetched", status.LastFetchedAt != "",
		)
	}
	return nil
}
