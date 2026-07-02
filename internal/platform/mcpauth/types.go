package mcpauth

import "encoding/json"

type TokenType string

type AccessMode string

const (
	TokenTypeClientID     TokenType = "client_id"
	TokenTypeAuthState    TokenType = "auth_state"
	TokenTypeAuthCode     TokenType = "auth_code"
	TokenTypeAccessToken  TokenType = "access_token"
	TokenTypeApproval     TokenType = "approval"
	TokenTypeSessionState TokenType = "session_state"

	AccessModeReadOnly  AccessMode = "read_only"
	AccessModeReadWrite AccessMode = "read_write"
)

// ClientRegistrationData is encrypted into the OAuth client_id.
// It exists only to validate redirect URIs and other registration metadata.
type ClientRegistrationData struct {
	ClientIDIssuedAt int64    `json:"client_id_issued_at"`
	RedirectURIs     []string `json:"redirect_uris"`

	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`

	ClientName string `json:"client_name,omitempty"`
	Scope      string `json:"scope,omitempty"`
}

// AuthState is encrypted into a short-lived blob passed to the login page.
type AuthState struct {
	RedirectURI          string   `json:"redirect_uri"`
	CodeChallenge        string   `json:"code_challenge"`
	CodeChallengeMethod  string   `json:"code_challenge_method"`
	State                string   `json:"state,omitempty"`
	Scopes               []string `json:"scopes,omitempty"`
	ClientID             string   `json:"client_id"`
	CreatedAtUnixSeconds int64    `json:"created_at"`
}

// AuthCodeData is encrypted into the OAuth authorization code.
// It contains upstream API token data so it can be exchanged for an access token.
type AuthCodeData struct {
	Principal string `json:"principal"`
	APIToken  string `json:"api_token"`

	AccessMode AccessMode `json:"access_mode,omitempty"`

	RedirectURI          string   `json:"redirect_uri"`
	CodeChallenge        string   `json:"code_challenge"`
	CodeChallengeMethod  string   `json:"code_challenge_method"`
	State                string   `json:"state,omitempty"`
	Scopes               []string `json:"scopes,omitempty"`
	ClientID             string   `json:"client_id"`
	CreatedAtUnixSeconds int64    `json:"created_at"`
}

// AccessTokenData is encrypted into the OAuth bearer access token.
type AccessTokenData struct {
	Principal string `json:"principal"`
	APIToken  string `json:"api_token"`

	AccessMode AccessMode `json:"access_mode,omitempty"`

	CreatedAtUnixSeconds int64 `json:"created_at"`
}

// ApprovalData is encrypted into a short-lived token returned by "prepare" tools.
// It enables a stateless prepare/commit workflow for write operations.
type ApprovalData struct {
	Operation string          `json:"operation"`
	Request   json.RawMessage `json:"request"`
}
