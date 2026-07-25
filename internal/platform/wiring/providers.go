package wiring

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/marcellodesales/blackduck-mcp-server/internal/platform/config"
	"github.com/marcellodesales/blackduck-mcp-server/internal/platform/mcpauth"
	"github.com/marcellodesales/blackduck-mcp-server/internal/platform/privateca"
	"github.com/marcellodesales/blackduck-mcp-server/internal/platform/securetoken"
)

func ProvideSealer(cfg config.Config) (*securetoken.Sealer, error) {
	return securetoken.NewSealer(cfg.AuthSecret)
}

func ProvideAuthService(sealer *securetoken.Sealer) *mcpauth.Service {
	return mcpauth.NewService(sealer, nil)
}

func ProvidePrivateCABootstrapper(cfg config.Config, logger *slog.Logger) *privateca.Bootstrapper {
	return privateca.NewBootstrapper(cfg, logger)
}

func ProvideHTTPClient(cfg config.Config) (*http.Client, error) {
	client := &http.Client{Timeout: 15 * time.Second}

	if cfg.BlackduckTLSInsecureSkipVerify {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		client.Transport = transport
		return client, nil
	}

	effectiveCACertFile := cfg.EffectiveBlackduckCACertFile()
	if effectiveCACertFile == "" && cfg.BlackduckCACertBase64 == "" {
		return client, nil
	}

	client.Transport = &lazyCACertTransport{cfg: cfg}
	return client, nil
}

type lazyCACertTransport struct {
	cfg config.Config

	mu        sync.Mutex
	transport *http.Transport
}

func (t *lazyCACertTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	transport, err := t.getTransport()
	if err != nil {
		return nil, err
	}
	return transport.RoundTrip(req)
}

func (t *lazyCACertTransport) getTransport() (*http.Transport, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.transport != nil {
		return t.transport, nil
	}

	tlsConfig, err := loadTLSConfig(t.cfg)
	if err != nil {
		return nil, err
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	t.transport = transport
	return transport, nil
}

func loadTLSConfig(cfg config.Config) (*tls.Config, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("load system cert pool: %w", err)
	}
	if pool == nil {
		pool = x509.NewCertPool()
	}

	effectiveCACertFile := cfg.EffectiveBlackduckCACertFile()
	if effectiveCACertFile != "" {
		pemBytes, err := os.ReadFile(effectiveCACertFile)
		if err != nil {
			return nil, fmt.Errorf("read effective Black Duck CA cert file %q: %w", effectiveCACertFile, err)
		}
		if ok := pool.AppendCertsFromPEM(pemBytes); !ok {
			return nil, fmt.Errorf("effective Black Duck CA cert file %q did not contain any PEM certificates", effectiveCACertFile)
		}
	}

	if cfg.BlackduckCACertBase64 != "" {
		pemBytes, err := base64.StdEncoding.DecodeString(cfg.BlackduckCACertBase64)
		if err != nil {
			return nil, fmt.Errorf("decode BLACKDUCK_CA_CERT_BASE64: %w", err)
		}
		if ok := pool.AppendCertsFromPEM(pemBytes); !ok {
			return nil, fmt.Errorf("BLACKDUCK_CA_CERT_BASE64 did not decode to any PEM certificates")
		}
	}

	return &tls.Config{RootCAs: pool}, nil
}
