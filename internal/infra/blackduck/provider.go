package blackduck

import (
	"net/http"

	"git.viasat.com/seceng-devsecops-platform/blackduck-mcp/internal/platform/config"
)

func ProvideClient(cfg config.Config, httpClient *http.Client) (*Client, error) {
	return NewClient(cfg.BlackduckBaseURL, httpClient)
}
