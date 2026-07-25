package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/marcellodesales/blackduck-mcp-server/internal/platform/privateca"
)

type App struct {
	Logger                *slog.Logger
	HTTPServer            *http.Server
	ShutdownTimeout       time.Duration
	PrivateCABootstrapper *privateca.Bootstrapper
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

// ensurePrivateCARoot reuses the private CA bundle already present on
// disk and only fetches it from PrivateCACertURL when it is missing. This
// keeps container restarts cheap and avoids hard-coupling startup to network
// reachability of `the private CA endpoint` when the bundle has already been
// primed (e.g. via the `./data/certs:/certs` docker-compose volume).
func (a *App) ensurePrivateCARoot(ctx context.Context) error {
	if a.PrivateCABootstrapper == nil {
		return nil
	}

	status, err := a.PrivateCABootstrapper.EnsurePrivateCARoot(ctx)
	if err != nil {
		return fmt.Errorf("ensure private ca root: %w", err)
	}
	if a.Logger != nil && status.Enabled && status.Exists {
		a.Logger.Info(
			"private ca root ready",
			"path", status.PrivateCACertFile,
			"size_bytes", status.SizeBytes,
			"updated_at", status.UpdatedAt,
			"refetched", status.LastFetchedAt != "",
		)
	}
	return nil
}
