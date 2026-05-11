package securetoken

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestSealer_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	keyB64 := base64.RawURLEncoding.EncodeToString(key)

	s, err := NewSealer(keyB64)
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}

	plaintext := []byte("hello")
	tok, err := s.Seal(plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	got, err := s.Open(tok)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("roundtrip mismatch: got %q want %q", got, plaintext)
	}
}

func TestSealer_WrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	_, _ = rand.Read(key1)
	_, _ = rand.Read(key2)

	s1, err := NewSealer(base64.RawURLEncoding.EncodeToString(key1))
	if err != nil {
		t.Fatalf("NewSealer(1): %v", err)
	}
	s2, err := NewSealer(base64.RawURLEncoding.EncodeToString(key2))
	if err != nil {
		t.Fatalf("NewSealer(2): %v", err)
	}

	tok, err := s1.Seal([]byte("secret"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	_, err = s2.Open(tok)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestSealer_InvalidToken(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	s, err := NewSealer(base64.RawURLEncoding.EncodeToString(key))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}

	_, err = s.Open("not-base64")
	if err == nil {
		t.Fatalf("expected error")
	}
}
