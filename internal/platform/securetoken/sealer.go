package securetoken

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

const (
	nonceSize   = 12
	tokenV1Byte = byte(1)
)

var (
	ErrInvalidToken = errors.New("invalid token")
)

type Sealer struct {
	aead cipher.AEAD
}

// NewSealer creates an AES-256-GCM token sealer.
//
// keyB64 must be base64url (raw, no padding) encoding of 32 random bytes.
func NewSealer(keyB64 string) (*Sealer, error) {
	key, err := decodeKey(keyB64)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}

	return &Sealer{aead: aead}, nil
}

func decodeKey(keyB64 string) ([]byte, error) {
	key, err := base64.RawURLEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf("decode MCP_AUTH_SECRET: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("decode MCP_AUTH_SECRET: expected 32 bytes, got %d", len(key))
	}
	return key, nil
}

func ValidateKey(keyB64 string) error {
	_, err := decodeKey(keyB64)
	return err
}

// Seal encrypts plaintext into a compact base64url token.
//
// Format: base64url( version(1) || nonce(12) || ciphertext+tag )
func (s *Sealer) Seal(plaintext []byte) (string, error) {
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("read nonce: %w", err)
	}

	ciphertext := s.aead.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, 1+nonceSize+len(ciphertext))
	out = append(out, tokenV1Byte)
	out = append(out, nonce...)
	out = append(out, ciphertext...)

	return base64.RawURLEncoding.EncodeToString(out), nil
}

// Open decrypts a token produced by Seal.
func (s *Sealer) Open(token string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("%w: base64 decode", ErrInvalidToken)
	}
	if len(raw) < 1+nonceSize+1 {
		return nil, fmt.Errorf("%w: too short", ErrInvalidToken)
	}
	if raw[0] != tokenV1Byte {
		return nil, fmt.Errorf("%w: unsupported version", ErrInvalidToken)
	}

	nonce := raw[1 : 1+nonceSize]
	ciphertext := raw[1+nonceSize:]

	plaintext, err := s.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: decrypt", ErrInvalidToken)
	}
	return plaintext, nil
}
