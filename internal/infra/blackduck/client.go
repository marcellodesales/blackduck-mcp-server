package blackduck

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden")
)

const (
	MediaTypeStatusV4          = "application/vnd.blackducksoftware.status-4+json"
	MediaTypeUserV4            = "application/vnd.blackducksoftware.user-4+json"
	MediaTypeProjectDetailV7   = "application/vnd.blackducksoftware.project-detail-7+json"
	MediaTypeProjectDetailV5   = "application/vnd.blackducksoftware.project-detail-5+json"
	MediaTypeBOMV6             = "application/vnd.blackducksoftware.bill-of-materials-6+json"
	MediaTypeBOMV7             = "application/vnd.blackducksoftware.bill-of-materials-7+json"
	MediaTypeBOMV8             = "application/vnd.blackducksoftware.bill-of-materials-8+json"
	MediaTypeComponentDetailV4 = "application/vnd.blackducksoftware.component-detail-4+json"
	MediaTypeComponentDetailV5 = "application/vnd.blackducksoftware.component-detail-5+json"
	MediaTypeCopyrightV4       = "application/vnd.blackducksoftware.copyright-4+json"
	MediaTypeVulnerabilityV4   = "application/vnd.blackducksoftware.vulnerability-4+json"
	MediaTypeScanV6            = "application/vnd.blackducksoftware.scan-6+json"
)

type Client struct {
	baseURL *url.URL
	http    *http.Client

	mu          sync.Mutex
	bearerCache map[[32]byte]cachedBearer
}

type cachedBearer struct {
	token     string
	expiresAt time.Time
}

func NewClient(baseURL string, httpClient *http.Client) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(baseURL), "/"))
	if err != nil {
		return nil, fmt.Errorf("parse base url: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid base url: %q", baseURL)
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &Client{baseURL: u, http: httpClient}, nil
}

type tokenAuthResponse struct {
	BearerToken           string `json:"bearerToken"`
	ExpiresInMilliseconds int64  `json:"expiresInMilliseconds"`
}

// Authenticate exchanges a long-lived API token for a short-lived OAuth2 bearer token.
//
// Docs: POST /api/tokens/authenticate with header Authorization: token <API token>
func (c *Client) Authenticate(ctx context.Context, apiToken string) (bearerToken string, expires time.Duration, _ error) {
	return c.authenticate(ctx, apiToken, false)
}

func (c *Client) authenticate(ctx context.Context, apiToken string, force bool) (bearerToken string, expires time.Duration, _ error) {
	apiToken = strings.TrimSpace(apiToken)
	if apiToken == "" {
		return "", 0, ErrUnauthorized
	}

	key := sha256.Sum256([]byte(apiToken))
	now := time.Now().UTC()

	if !force {
		c.mu.Lock()
		cached, ok := c.bearerCache[key]
		c.mu.Unlock()

		// Refresh a little early to avoid edge expiry.
		if ok && cached.token != "" && now.Before(cached.expiresAt.Add(-30*time.Second)) {
			return cached.token, time.Until(cached.expiresAt), nil
		}
	}

	endpoint := c.baseURL.JoinPath("/api/tokens/authenticate")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), nil)
	if err != nil {
		return "", 0, fmt.Errorf("new request: %w", err)
	}

	req.Header.Set("Accept", MediaTypeUserV4)
	req.Header.Set("Authorization", "token "+apiToken)

	resp, err := c.http.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, fmt.Errorf("read body: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		var out tokenAuthResponse
		if err := json.Unmarshal(body, &out); err != nil {
			return "", 0, fmt.Errorf("decode response: %w", err)
		}
		if strings.TrimSpace(out.BearerToken) == "" {
			return "", 0, fmt.Errorf("blackduck authenticate: empty bearerToken")
		}

		expires = time.Duration(out.ExpiresInMilliseconds) * time.Millisecond
		expiresAt := now.Add(expires)

		c.mu.Lock()
		if c.bearerCache == nil {
			c.bearerCache = make(map[[32]byte]cachedBearer)
		}
		c.bearerCache[key] = cachedBearer{token: out.BearerToken, expiresAt: expiresAt}
		c.mu.Unlock()

		return out.BearerToken, expires, nil
	case http.StatusUnauthorized:
		c.mu.Lock()
		delete(c.bearerCache, key)
		c.mu.Unlock()
		return "", 0, ErrUnauthorized
	case http.StatusForbidden:
		c.mu.Lock()
		delete(c.bearerCache, key)
		c.mu.Unlock()
		return "", 0, ErrForbidden
	default:
		msg := strings.TrimSpace(string(body))
		if len(msg) > 500 {
			msg = msg[:500]
		}
		return "", 0, fmt.Errorf("blackduck authenticate error: status=%d body=%q", resp.StatusCode, msg)
	}
}

func (c *Client) GetJSON(ctx context.Context, apiToken, path, accept string, query url.Values) (map[string]any, error) {
	bearer, _, err := c.authenticate(ctx, apiToken, false)
	if err != nil {
		return nil, err
	}

	out, err := c.getJSONWithBearer(ctx, bearer, path, accept, query)
	if err == nil {
		return out, nil
	}

	// If the cached bearer token expired (or was revoked), refresh once and retry.
	if errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrForbidden) {
		bearer, _, authErr := c.authenticate(ctx, apiToken, true)
		if authErr != nil {
			return nil, authErr
		}
		return c.getJSONWithBearer(ctx, bearer, path, accept, query)
	}

	return nil, err
}

func (c *Client) getJSONWithBearer(ctx context.Context, bearer, path, accept string, query url.Values) (map[string]any, error) {
	endpoint := c.baseURL.JoinPath(strings.TrimPrefix(path, "/"))
	u := endpoint
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		// fallthrough
	case http.StatusCreated:
		// fallthrough
	case http.StatusAccepted:
		// ok
	default:
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			return nil, ErrUnauthorized
		case http.StatusForbidden:
			return nil, ErrForbidden
		}
		msg := strings.TrimSpace(string(body))
		if len(msg) > 500 {
			msg = msg[:500]
		}
		return nil, fmt.Errorf("blackduck api error: status=%d body=%q", resp.StatusCode, msg)
	}

	ct := strings.ToLower(strings.TrimSpace(strings.SplitN(resp.Header.Get("Content-Type"), ";", 2)[0]))
	if ct != "" && !strings.Contains(ct, "json") {
		// Return the raw body in a JSON wrapper.
		return map[string]any{
			"content_type": ct,
			"body":         string(body),
		}, nil
	}

	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return out, nil
}

func (c *Client) CurrentUser(ctx context.Context, apiToken string) (map[string]any, error) {
	return c.GetJSON(ctx, apiToken, "/api/current-user", MediaTypeUserV4, nil)
}

func (c *Client) CurrentVersion(ctx context.Context, apiToken string) (map[string]any, error) {
	return c.GetJSON(ctx, apiToken, "/api/current-version", MediaTypeStatusV4, nil)
}
