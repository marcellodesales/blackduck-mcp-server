package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"git.viasat.com/seceng-devsecops-platform/blackduck-mcp/internal/infra/blackduck"
	"git.viasat.com/seceng-devsecops-platform/blackduck-mcp/internal/platform/mcpauth"
)

type authServerMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
}

type clientRegistrationRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
}

type clientRegistrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

func (r *Router) serverCard(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"name":        "com.viasat.blackduck-mcp",
		"title":       "Black Duck MCP Server",
		"version":     "0.1.0",
		"description": "Query Black Duck projects, BOMs, components, vulnerabilities, scans, users, and policy rules via MCP tools.",
		"homepage":    r.cfg.ServerURL,
		"transports": []map[string]any{
			{"type": "streamable-http", "url": r.cfg.ServerURL + "/mcp"},
		},
		"auth": map[string]any{
			"type":                   "oauth2",
			"authorizationServerUrl": r.cfg.ServerURL,
		},
		"capabilities": map[string]any{
			"tools":   map[string]any{"listChanged": false},
			"prompts": map[string]any{"listChanged": false},
		},
		"tools": "dynamic",
		"tags":  []string{"blackduck", "supply-chain", "sbom", "security"},
	})
}

func (r *Router) authorizationServerMetadata(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	meta := authServerMetadata{
		Issuer:                            r.cfg.ServerURL,
		AuthorizationEndpoint:             r.cfg.ServerURL + "/authorize",
		TokenEndpoint:                     r.cfg.ServerURL + "/token",
		RegistrationEndpoint:              r.cfg.ServerURL + "/register",
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		TokenEndpointAuthMethodsSupported: []string{"none"},
	}
	_ = json.NewEncoder(w).Encode(meta)
}

func (r *Router) registerClient(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	defer req.Body.Close()

	var in clientRegistrationRequest
	if err := json.NewDecoder(req.Body).Decode(&in); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	if len(in.RedirectURIs) == 0 {
		http.Error(w, "redirect_uris is required", http.StatusBadRequest)
		return
	}

	for _, ru := range in.RedirectURIs {
		u, err := url.Parse(ru)
		if err != nil || u.Scheme == "" || u.Host == "" {
			http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
			return
		}
	}

	method := in.TokenEndpointAuthMethod
	if method == "" {
		method = "none"
	}

	data := mcpauth.ClientRegistrationData{
		ClientIDIssuedAt:        time.Now().UTC().Unix(),
		RedirectURIs:            in.RedirectURIs,
		TokenEndpointAuthMethod: method,
		GrantTypes:              in.GrantTypes,
		ResponseTypes:           in.ResponseTypes,
		ClientName:              in.ClientName,
		Scope:                   in.Scope,
	}

	clientID, _, err := r.tokenSvc.Mint(string(mcpauth.TokenTypeClientID), 3650*24*time.Hour, data)
	if err != nil {
		http.Error(w, "failed to register client", http.StatusInternalServerError)
		return
	}

	out := clientRegistrationResponse{
		ClientID:                clientID,
		ClientIDIssuedAt:        data.ClientIDIssuedAt,
		RedirectURIs:            data.RedirectURIs,
		TokenEndpointAuthMethod: data.TokenEndpointAuthMethod,
		GrantTypes:              data.GrantTypes,
		ResponseTypes:           data.ResponseTypes,
		ClientName:              data.ClientName,
		Scope:                   data.Scope,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (r *Router) authorize(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	q := req.URL.Query()
	responseType := q.Get("response_type")
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")
	state := q.Get("state")
	scope := q.Get("scope")

	if responseType != "code" {
		http.Error(w, "unsupported response_type", http.StatusBadRequest)
		return
	}
	if clientID == "" || redirectURI == "" || codeChallenge == "" {
		http.Error(w, "missing required parameters", http.StatusBadRequest)
		return
	}
	if codeChallengeMethod == "" {
		codeChallengeMethod = "S256"
	}
	if codeChallengeMethod != "S256" {
		http.Error(w, "unsupported code_challenge_method", http.StatusBadRequest)
		return
	}

	var reg mcpauth.ClientRegistrationData
	if _, err := r.tokenSvc.Parse(string(mcpauth.TokenTypeClientID), clientID, &reg); err != nil {
		http.Error(w, "invalid client_id", http.StatusBadRequest)
		return
	}
	if !contains(reg.RedirectURIs, redirectURI) {
		http.Error(w, "redirect_uri not registered", http.StatusBadRequest)
		return
	}

	scopes := splitScopes(scope)
	authState := mcpauth.AuthState{
		RedirectURI:          redirectURI,
		CodeChallenge:        codeChallenge,
		CodeChallengeMethod:  codeChallengeMethod,
		State:                state,
		Scopes:               scopes,
		ClientID:             clientID,
		CreatedAtUnixSeconds: time.Now().UTC().Unix(),
	}
	encState, _, err := r.tokenSvc.Mint(string(mcpauth.TokenTypeAuthState), r.cfg.AuthCodeTTL, authState)
	if err != nil {
		http.Error(w, "failed to start auth", http.StatusInternalServerError)
		return
	}

	loginURL := r.cfg.ServerURL + "/blackduck/login?" + url.Values{"auth_state": []string{encState}}.Encode()
	http.Redirect(w, req, loginURL, http.StatusFound)
}

var loginTemplate = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Black Duck MCP — Sign In</title>
  {{if .RedirectURL}}<meta http-equiv="refresh" content="1;url={{.RedirectURL}}" />{{end}}
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, sans-serif; background:#f5f5f5; margin:0; padding:0; }
    .card { max-width:460px; margin:10vh auto; background:#fff; padding:24px; border-radius:12px; box-shadow:0 4px 20px rgba(0,0,0,0.08); }
    h1 { margin:0 0 8px 0; font-size:20px; }
    p { margin:0 0 16px 0; color:#555; font-size:14px; line-height:1.4; }
    label { display:block; font-weight:600; font-size:13px; margin:12px 0 6px; }
    input { width:100%; padding:10px 12px; border:1px solid #ddd; border-radius:8px; font-size:14px; }
    button { width:100%; margin-top:16px; padding:10px 12px; border:0; border-radius:8px; background:#006978; color:#fff; font-weight:700; font-size:14px; cursor:pointer; }
    .err { background:#fdecea; border:1px solid #f5c6cb; color:#7a1c1c; padding:10px 12px; border-radius:8px; margin-bottom:12px; font-size:13px; }
    .success { background:#e7f7ed; border:1px solid #b7ebc6; color:#0f5132; padding:10px 12px; border-radius:8px; margin-bottom:12px; font-size:13px; }
    .info { background:#eef4ff; border:1px solid #cfe0ff; color:#1f3b7a; padding:10px 12px; border-radius:8px; margin-top:12px; font-size:13px; }
    .note { background:#fff8e1; border-left:4px solid #ff8f00; padding:10px 12px; border-radius:8px; margin-top:12px; font-size:13px; color:#555; }
    code { background:#f1f1f1; padding:1px 4px; border-radius:4px; }
    a { color:#006978; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Black Duck MCP Server</h1>

    {{if .RedirectURL}}
      <div class="success">Authentication succeeded. Redirecting…</div>
      <p>Redirecting you back to your MCP client…</p>
      <p>If you are not redirected, <a href="{{.RedirectURL}}">continue</a>.</p>
      <div class="info">
        It is safe to close this tab — your MCP client now has an encrypted access token. Nothing is stored server-side.
      </div>
    {{else}}
      <p>Sign in using a Black Duck <strong>API token</strong>. This server exchanges it for a short-lived OAuth bearer token using <code>/api/tokens/authenticate</code> and validates it via <code>/api/current-user</code>.</p>
      <div class="note">
        Create an API token in the Black Duck UI under user management. Prefer a <strong>read-only</strong> token unless you need write operations.
      </div>
      {{if .Error}}<div class="err">{{.Error}}</div>{{end}}
      {{if .Success}}<div class="success">{{.Success}}</div>{{end}}

      <form method="POST" action="/blackduck/login">
        <label for="api_token">API Token</label>
        <input id="api_token" name="api_token" type="password" autocomplete="current-password" required />
        <input type="hidden" name="auth_state" value="{{.AuthState}}" />
        <button type="submit">Sign in</button>
      </form>

      <div class="note">
        The API token is encrypted into your MCP bearer token. Treat it as sensitive.
      </div>
    {{end}}
  </div>
</body>
</html>`))

type loginPageData struct {
	AuthState   string
	Error       string
	Success     string
	RedirectURL string
}

func (r *Router) blackduckLogin(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		r.renderBlackduckLogin(w, req)
	case http.MethodPost:
		r.handleBlackduckLoginSubmit(w, req)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (r *Router) renderBlackduckLogin(w http.ResponseWriter, req *http.Request) {
	authState := req.URL.Query().Get("auth_state")
	if authState == "" {
		http.Error(w, "missing auth_state", http.StatusBadRequest)
		return
	}
	data := loginPageData{
		AuthState: authState,
		Error:     req.URL.Query().Get("error"),
		Success:   req.URL.Query().Get("success"),
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = loginTemplate.Execute(w, data)
}

func (r *Router) handleBlackduckLoginSubmit(w http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	apiToken := strings.TrimSpace(req.FormValue("api_token"))
	encState := req.FormValue("auth_state")

	if apiToken == "" || encState == "" {
		http.Error(w, "missing required fields", http.StatusBadRequest)
		return
	}

	var st mcpauth.AuthState
	if _, err := r.tokenSvc.Parse(string(mcpauth.TokenTypeAuthState), encState, &st); err != nil {
		http.Error(w, "invalid auth_state", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(req.Context(), 15*time.Second)
	defer cancel()
	user, err := r.blackduck.CurrentUser(ctx, apiToken)
	if err != nil {
		msg := "authentication failed"
		if errors.Is(err, blackduck.ErrUnauthorized) || errors.Is(err, blackduck.ErrForbidden) {
			msg = "invalid API token or insufficient permissions"
		} else {
			errText := strings.ReplaceAll(err.Error(), "\n", " ")
			if len(errText) > 240 {
				errText = errText[:240] + "…"
			}
			if strings.Contains(errText, "x509:") || strings.Contains(errText, "certificate verify failed") {
				msg = "upstream TLS verification failed (certificate not trusted). Configure VIASAT_IO_CACERT_* or BLACKDUCK_CA_CERT_* (or set BLACKDUCK_TLS_INSECURE_SKIP_VERIFY=true). " + errText
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_ = loginTemplate.Execute(w, loginPageData{AuthState: encState, Error: msg})
		return
	}

	principal := extractPrincipal(user)
	if principal == "" {
		principal = "blackduck"
	}

	codeData := mcpauth.AuthCodeData{
		Principal:            principal,
		APIToken:             apiToken,
		RedirectURI:          st.RedirectURI,
		CodeChallenge:        st.CodeChallenge,
		CodeChallengeMethod:  st.CodeChallengeMethod,
		State:                st.State,
		Scopes:               st.Scopes,
		ClientID:             st.ClientID,
		CreatedAtUnixSeconds: time.Now().UTC().Unix(),
	}
	code, _, err := r.tokenSvc.Mint(string(mcpauth.TokenTypeAuthCode), r.cfg.AuthCodeTTL, codeData)
	if err != nil {
		http.Error(w, "failed to issue auth code", http.StatusInternalServerError)
		return
	}

	cb, err := url.Parse(st.RedirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	q := cb.Query()
	q.Set("code", code)
	if st.State != "" {
		q.Set("state", st.State)
	}
	cb.RawQuery = q.Encode()

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = loginTemplate.Execute(w, loginPageData{AuthState: encState, Success: "Authentication succeeded. Redirecting…", RedirectURL: cb.String()})
}

func extractPrincipal(user map[string]any) string {
	for _, k := range []string{"userName", "username", "email", "id"} {
		if v, ok := user[k]; ok {
			if s, ok := v.(string); ok {
				s = strings.TrimSpace(s)
				if s != "" {
					return s
				}
			}
		}
	}
	return ""
}

func (r *Router) token(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := req.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	grantType := req.FormValue("grant_type")
	code := req.FormValue("code")
	codeVerifier := req.FormValue("code_verifier")
	clientID := req.FormValue("client_id")
	redirectURI := req.FormValue("redirect_uri")

	if grantType != "authorization_code" {
		http.Error(w, "unsupported grant_type", http.StatusBadRequest)
		return
	}
	if code == "" || codeVerifier == "" || clientID == "" || redirectURI == "" {
		http.Error(w, "missing required parameters", http.StatusBadRequest)
		return
	}

	var cd mcpauth.AuthCodeData
	if _, err := r.tokenSvc.Parse(string(mcpauth.TokenTypeAuthCode), code, &cd); err != nil {
		http.Error(w, "invalid code", http.StatusBadRequest)
		return
	}
	if cd.ClientID != clientID {
		http.Error(w, "client_id mismatch", http.StatusBadRequest)
		return
	}
	if cd.RedirectURI != redirectURI {
		http.Error(w, "redirect_uri mismatch", http.StatusBadRequest)
		return
	}
	if cd.CodeChallengeMethod != "S256" {
		http.Error(w, "unsupported code_challenge_method", http.StatusBadRequest)
		return
	}
	if !mcpauth.VerifyCodeChallengeS256(codeVerifier, cd.CodeChallenge) {
		http.Error(w, "invalid code_verifier", http.StatusBadRequest)
		return
	}

	at := mcpauth.AccessTokenData{
		Principal:            cd.Principal,
		APIToken:             cd.APIToken,
		CreatedAtUnixSeconds: time.Now().UTC().Unix(),
	}
	accessToken, meta, err := r.tokenSvc.Mint(string(mcpauth.TokenTypeAccessToken), r.cfg.AccessTokenTTL, at)
	if err != nil {
		http.Error(w, "failed to issue token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(tokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(meta.ExpiresAt.Sub(time.Now().UTC()).Seconds()),
		Scope:       strings.Join(cd.Scopes, " "),
	})
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func splitScopes(scope string) []string {
	fields := strings.Fields(strings.TrimSpace(scope))
	if len(fields) == 0 {
		return nil
	}
	out := make([]string, 0, len(fields))
	seen := make(map[string]struct{}, len(fields))
	for _, f := range fields {
		if f == "" {
			continue
		}
		if _, ok := seen[f]; ok {
			continue
		}
		seen[f] = struct{}{}
		out = append(out, f)
	}
	return out
}
