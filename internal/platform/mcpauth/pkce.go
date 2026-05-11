package mcpauth

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

func CodeChallengeS256(codeVerifier string) string {
	sum := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func VerifyCodeChallengeS256(codeVerifier string, expectedChallenge string) bool {
	got := CodeChallengeS256(codeVerifier)
	return strings.EqualFold(got, expectedChallenge)
}
