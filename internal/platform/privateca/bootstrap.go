package privateca

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/marcellodesales/blackduck-mcp-server/internal/platform/config"
)

type Status struct {
	Enabled           bool   `json:"enabled"`
	PrivateCACertFile string `json:"private_cacert_file,omitempty"`
	PrivateCACertURL  string `json:"private_cacert_url,omitempty"`
	Exists            bool   `json:"exists"`
	SizeBytes         int64  `json:"size_bytes,omitempty"`
	UpdatedAt         string `json:"updated_at,omitempty"`
	LastFetchedAt     string `json:"last_fetched_at,omitempty"`
}

type Bootstrapper struct {
	cfg    config.Config
	logger *slog.Logger
	client *http.Client

	mu            sync.RWMutex
	lastFetchedAt time.Time
}

func NewBootstrapper(cfg config.Config, logger *slog.Logger) *Bootstrapper {
	return &Bootstrapper{
		cfg:    cfg,
		logger: logger,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// FetchPrivateCARoot forces a fresh download of the private CA bundle
// from PrivateCACertURL, replacing any cached file on disk. Prefer
// EnsurePrivateCARoot for normal startup.
func (b *Bootstrapper) FetchPrivateCARoot(ctx context.Context) (Status, error) {
	return b.Ensure(ctx, true)
}

// EnsurePrivateCARoot guarantees that the private CA bundle is
// available on disk at PrivateCACertFile. If the file already exists, it is
// reused as-is (no network call). Only when the file is missing does this
// fetch PrivateCACertURL. This is the preferred startup behaviour so that:
//   - container restarts do not require connectivity to the private CA endpoint;
//   - operators can prime the bundle by mounting a host directory at
//     /certs (e.g. via docker-compose `volumes:`).
func (b *Bootstrapper) EnsurePrivateCARoot(ctx context.Context) (Status, error) {
	return b.Ensure(ctx, false)
}

func (b *Bootstrapper) Ensure(ctx context.Context, force bool) (Status, error) {
	if !b.cfg.IsPrivateCACertBootstrapEnabled() {
		return b.Status(), nil
	}

	if !force {
		status := b.Status()
		if status.Exists {
			return status, nil
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.cfg.PrivateCACertURL, nil)
	if err != nil {
		return Status{}, fmt.Errorf("build private CA request: %w", err)
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return b.fallbackStatus(fmt.Errorf("fetch private CA bundle: %w", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return b.fallbackStatus(fmt.Errorf("fetch private CA bundle: unexpected status %s", resp.Status))
	}

	pemBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return b.fallbackStatus(fmt.Errorf("read private CA bundle: %w", err))
	}

	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(pemBytes); !ok {
		return b.fallbackStatus(fmt.Errorf("private CA bundle at %s did not contain PEM certificates", b.cfg.PrivateCACertURL))
	}

	if err := os.MkdirAll(filepath.Dir(b.cfg.PrivateCACertFile), 0o755); err != nil {
		return b.fallbackStatus(fmt.Errorf("create private CA directory: %w", err))
	}

	tempFile, err := os.CreateTemp(filepath.Dir(b.cfg.PrivateCACertFile), "private-ca-*.pem")
	if err != nil {
		return b.fallbackStatus(fmt.Errorf("create temp private CA file: %w", err))
	}
	tempPath := tempFile.Name()
	cleanup := true
	defer func() {
		_ = tempFile.Close()
		if cleanup {
			_ = os.Remove(tempPath)
		}
	}()

	if _, err := tempFile.Write(pemBytes); err != nil {
		return b.fallbackStatus(fmt.Errorf("write private CA bundle: %w", err))
	}
	if err := tempFile.Chmod(0o644); err != nil {
		return b.fallbackStatus(fmt.Errorf("chmod private CA bundle: %w", err))
	}
	if err := tempFile.Close(); err != nil {
		return b.fallbackStatus(fmt.Errorf("close private CA bundle: %w", err))
	}
	if err := os.Rename(tempPath, b.cfg.PrivateCACertFile); err != nil {
		return b.fallbackStatus(fmt.Errorf("install private CA bundle: %w", err))
	}
	cleanup = false

	now := time.Now().UTC()
	b.mu.Lock()
	b.lastFetchedAt = now
	b.mu.Unlock()

	status := b.Status()
	if b.logger != nil {
		b.logger.Info(
			"private ca root fetched",
			"path", b.cfg.PrivateCACertFile,
			"url", b.cfg.PrivateCACertURL,
			"size_bytes", status.SizeBytes,
			"fetched_at", status.LastFetchedAt,
		)
	}
	return status, nil
}

func (b *Bootstrapper) Status() Status {
	status := Status{
		Enabled:           b.cfg.IsPrivateCACertBootstrapEnabled(),
		PrivateCACertFile: b.cfg.PrivateCACertFile,
		PrivateCACertURL:  b.cfg.PrivateCACertURL,
	}

	if b.cfg.PrivateCACertFile != "" {
		if info, err := os.Stat(b.cfg.PrivateCACertFile); err == nil {
			status.Exists = true
			status.SizeBytes = info.Size()
			status.UpdatedAt = info.ModTime().UTC().Format(time.RFC3339)
		}
	}

	b.mu.RLock()
	lastFetchedAt := b.lastFetchedAt
	b.mu.RUnlock()
	if !lastFetchedAt.IsZero() {
		status.LastFetchedAt = lastFetchedAt.Format(time.RFC3339)
	}

	return status
}

func (b *Bootstrapper) fallbackStatus(err error) (Status, error) {
	status := b.Status()
	if status.Exists {
		if b.logger != nil {
			b.logger.Warn(
				"failed to refresh private CA bundle; using existing file",
				"path", status.PrivateCACertFile,
				"error", err,
			)
		}
		return status, nil
	}
	return status, err
}
