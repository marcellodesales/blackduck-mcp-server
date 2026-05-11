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
	if err := a.fetchPrivateCARoot(ctx); err != nil {
		return fmt.Errorf("handle startup prerequisites: %w", err)
	}
	return nil
}

func (a *App) fetchPrivateCARoot(ctx context.Context) error {
	if a.ViasatCABootstrapper == nil {
		return nil
	}

	if _, err := a.ViasatCABootstrapper.FetchPrivateCARoot(ctx); err != nil {
		return fmt.Errorf("fetch private ca root: %w", err)
	}
	return nil
}
