package mcpauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/marcellodesales/blackduck-mcp-server/internal/platform/securetoken"
)

var (
	ErrTokenExpired      = errors.New("token expired")
	ErrTokenTypeMismatch = errors.New("token type mismatch")
	ErrTokenInvalid      = errors.New("token invalid")
)

type Clock func() time.Time

type Service struct {
	sealer *securetoken.Sealer
	now    Clock
}

func NewService(sealer *securetoken.Sealer, now Clock) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{sealer: sealer, now: now}
}

type Envelope struct {
	Typ  string          `json:"typ"`
	Iat  int64           `json:"iat"`
	Exp  int64           `json:"exp"`
	Data json.RawMessage `json:"data"`
}

type Meta struct {
	IssuedAt  time.Time
	ExpiresAt time.Time
}

func (s *Service) Mint(typ string, ttl time.Duration, data any) (string, Meta, error) {
	now := s.now().UTC()
	exp := now.Add(ttl)

	payload, err := json.Marshal(data)
	if err != nil {
		return "", Meta{}, fmt.Errorf("marshal token payload: %w", err)
	}

	env := Envelope{
		Typ:  typ,
		Iat:  now.Unix(),
		Exp:  exp.Unix(),
		Data: payload,
	}
	b, err := json.Marshal(env)
	if err != nil {
		return "", Meta{}, fmt.Errorf("marshal token envelope: %w", err)
	}
	tok, err := s.sealer.Seal(b)
	if err != nil {
		return "", Meta{}, fmt.Errorf("seal token: %w", err)
	}
	return tok, Meta{IssuedAt: now, ExpiresAt: exp}, nil
}

func (s *Service) ParseEnvelope(token string) (Envelope, Meta, error) {
	b, err := s.sealer.Open(token)
	if err != nil {
		return Envelope{}, Meta{}, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}

	var env Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		return Envelope{}, Meta{}, fmt.Errorf("%w: unmarshal", ErrTokenInvalid)
	}

	now := s.now().UTC().Unix()
	if now >= env.Exp {
		return Envelope{}, Meta{}, ErrTokenExpired
	}

	meta := Meta{
		IssuedAt:  time.Unix(env.Iat, 0).UTC(),
		ExpiresAt: time.Unix(env.Exp, 0).UTC(),
	}
	return env, meta, nil
}

func (s *Service) Parse(expectedType string, token string, out any) (Meta, error) {
	env, meta, err := s.ParseEnvelope(token)
	if err != nil {
		return Meta{}, err
	}

	if env.Typ != expectedType {
		return Meta{}, fmt.Errorf("%w: got %q want %q", ErrTokenTypeMismatch, env.Typ, expectedType)
	}

	if out == nil {
		return meta, nil
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return Meta{}, fmt.Errorf("%w: unmarshal payload", ErrTokenInvalid)
	}
	return meta, nil
}
