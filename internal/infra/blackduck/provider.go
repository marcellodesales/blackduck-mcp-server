package blackduck

import (
	"net/http"

	"github.com/marcellodesales/blackduck-mcp-server/internal/platform/config"
)

func ProvideClient(cfg config.Config, httpClient *http.Client) (*Client, error) {
	return NewClient(cfg.BlackduckBaseURL, httpClient)
}
