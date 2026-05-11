package mcpauth

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"git.viasat.com/seceng-devsecops-platform/blackduck-mcp/internal/platform/securetoken"
)

type payload struct {
	A string `json:"a"`
}

func TestService_MintParse(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	sealer, err := securetoken.NewSealer(base64.RawURLEncoding.EncodeToString(key))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}

	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	svc := NewService(sealer, func() time.Time { return fixed })

	tok, _, err := svc.Mint("t1", 10*time.Second, payload{A: "x"})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	var out payload
	_, err = svc.Parse("t1", tok, &out)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if out.A != "x" {
		t.Fatalf("data mismatch: got %q", out.A)
	}
}

func TestService_TypeMismatch(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	sealer, _ := securetoken.NewSealer(base64.RawURLEncoding.EncodeToString(key))
	svc := NewService(sealer, time.Now)

	tok, _, err := svc.Mint("t1", 10*time.Second, payload{A: "x"})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	var out payload
	_, err = svc.Parse("t2", tok, &out)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestService_Expired(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	sealer, _ := securetoken.NewSealer(base64.RawURLEncoding.EncodeToString(key))

	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := start
	svc := NewService(sealer, func() time.Time { return now })

	tok, _, err := svc.Mint("t1", 1*time.Second, payload{A: "x"})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	now = start.Add(2 * time.Second)
	var out payload
	_, err = svc.Parse("t1", tok, &out)
	if err == nil {
		t.Fatalf("expected error")
	}
	if err != ErrTokenExpired {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}
