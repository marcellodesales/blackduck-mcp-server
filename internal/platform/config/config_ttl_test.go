package config

import (
	"testing"
	"time"
)

// TestAccessTokenTTLFromEnv verifies the access-token lifetime is env-driven with
// a 10h default (the standard across our MCP servers), honors a valid override,
// and falls back to the default on an invalid value.
func TestAccessTokenTTLFromEnv(t *testing.T) {
	// Default when unset -> 10h.
	t.Setenv("MCP_AUTH_ACCESS_TTL", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AccessTokenTTL != 10*time.Hour {
		t.Errorf("default AccessTokenTTL = %s, want 10h", cfg.AccessTokenTTL)
	}

	// Valid override honored.
	t.Setenv("MCP_AUTH_ACCESS_TTL", "6h")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AccessTokenTTL != 6*time.Hour {
		t.Errorf("override AccessTokenTTL = %s, want 6h", cfg.AccessTokenTTL)
	}

	// Invalid value falls back to the 10h default.
	t.Setenv("MCP_AUTH_ACCESS_TTL", "not-a-duration")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AccessTokenTTL != 10*time.Hour {
		t.Errorf("invalid AccessTokenTTL = %s, want fallback 10h", cfg.AccessTokenTTL)
	}
}
