package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/marcellodesales/blackduck-mcp-server/internal/platform/securetoken"
)

type Config struct {
	Port int

	// Public URL of this server (used in OAuth metadata and redirects).
	ServerURL string

	// Base URL for Black Duck.
	BlackduckBaseURL string

	// Shared private CA bundle bootstrap settings (optional). When configured, the
	// server can fetch the bundle during startup and store it at runtime.
	PrivateCACertFile string
	PrivateCACertURL  string

	// Optional extra PEM-encoded CA certificate sources used when connecting to
	// Black Duck. Useful for Dockerized local development against a
	// private PKI.
	BlackduckCACertFile   string
	BlackduckCACertBase64 string

	// If true, disables TLS certificate verification for upstream Black Duck calls.
	// Prefer configuring CA roots via *_CA_CERT_* vars instead.
	BlackduckTLSInsecureSkipVerify bool

	// Symmetric key used to encrypt all stateless tokens.
	// Expected format: base64url (no padding) encoded 32-byte key.
	AuthSecret string

	AuthCodeTTL    time.Duration
	AccessTokenTTL time.Duration
	ApprovalTTL    time.Duration

	// StreamableHTTP options.
	JSONResponse bool
}

func Load() (Config, error) {
	cfg := Config{
		Port:                           9090,
		ServerURL:                      "",
		BlackduckBaseURL:               "https://blackduck.example.com",
		PrivateCACertFile:              strings.TrimSpace(os.Getenv("PRIVATE_CACERT_FILE")),
		PrivateCACertURL:               strings.TrimSpace(os.Getenv("PRIVATE_CACERT_URL")),
		BlackduckCACertFile:            strings.TrimSpace(os.Getenv("BLACKDUCK_CA_CERT_FILE")),
		BlackduckCACertBase64:          strings.TrimSpace(os.Getenv("BLACKDUCK_CA_CERT_BASE64")),
		BlackduckTLSInsecureSkipVerify: false,
		AuthSecret:                     strings.TrimSpace(os.Getenv("MCP_AUTH_SECRET")),
		// Token lifetimes are env-overridable so deployments can tune them without a
		// rebuild, matching the prismacloud, kubernetes, and vault MCP servers. The
		// access-token default is 10h (the standard across our MCP servers);
		// compose/.env set it explicitly via MCP_AUTH_ACCESS_TTL.
		AuthCodeTTL:    durationEnv("MCP_AUTH_CODE_TTL", 5*time.Minute),
		AccessTokenTTL: durationEnv("MCP_AUTH_ACCESS_TTL", 10*time.Hour),
		ApprovalTTL:    durationEnv("MCP_APPROVAL_TTL", 5*time.Minute),
		JSONResponse:   false,
	}

	if v := strings.TrimSpace(os.Getenv("BLACKDUCK_TLS_INSECURE_SKIP_VERIFY")); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, fmt.Errorf("invalid BLACKDUCK_TLS_INSECURE_SKIP_VERIFY: %q", v)
		}
		cfg.BlackduckTLSInsecureSkipVerify = b
	}

	if v := os.Getenv("PORT"); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p <= 0 || p > 65535 {
			return Config{}, fmt.Errorf("invalid PORT: %q", v)
		}
		cfg.Port = p
	}

	if v := os.Getenv("MCP_SERVER_URL"); v != "" {
		cfg.ServerURL = v
	} else {
		cfg.ServerURL = fmt.Sprintf("http://localhost:%d", cfg.Port)
	}

	if _, err := url.Parse(cfg.ServerURL); err != nil {
		return Config{}, fmt.Errorf("invalid MCP_SERVER_URL: %w", err)
	}

	if v := os.Getenv("BLACKDUCK_BASE_URL"); v != "" {
		cfg.BlackduckBaseURL = strings.TrimSpace(v)
	}
	if _, err := url.Parse(cfg.BlackduckBaseURL); err != nil {
		return Config{}, fmt.Errorf("invalid BLACKDUCK_BASE_URL: %w", err)
	}

	if v := os.Getenv("MCP_JSON_RESPONSE"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, fmt.Errorf("invalid MCP_JSON_RESPONSE: %q", v)
		}
		cfg.JSONResponse = b
	}

	// MCP_AUTH_SECRET is optional. When unset, generate an ephemeral secret so the
	// server can run locally without extra setup.
	//
	// Note: Any OAuth/MCP access tokens issued with an auto-generated secret will
	// become invalid after the server restarts.
	if cfg.AuthSecret == "" {
		key := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return Config{}, fmt.Errorf("generate MCP_AUTH_SECRET: %w", err)
		}
		cfg.AuthSecret = base64.RawURLEncoding.EncodeToString(key)
	}
	if err := securetoken.ValidateKey(cfg.AuthSecret); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

// durationEnv reads a Go duration (e.g. "10h", "5m") from the environment,
// falling back to the provided default when the variable is unset or invalid.
// Mirrors the helper used by the prismacloud, kubernetes, and vault MCP servers
// so token-TTL configuration is consistent across all of our MCP servers.
func durationEnv(key string, fallback time.Duration) time.Duration {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}

func (c Config) EffectiveBlackduckCACertFile() string {
	if c.BlackduckCACertFile != "" {
		return c.BlackduckCACertFile
	}
	return c.PrivateCACertFile
}

func (c Config) IsPrivateCACertBootstrapEnabled() bool {
	return c.PrivateCACertFile != "" && c.PrivateCACertURL != ""
}
