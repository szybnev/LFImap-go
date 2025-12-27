package http

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

// ClientConfig holds HTTP client configuration
type ClientConfig struct {
	Timeout         time.Duration
	ProxyURL        string
	FollowRedirects bool
	InsecureSkipTLS bool
}

// NewClient creates a new HTTP client with the given configuration
func NewClient(cfg ClientConfig) (*http.Client, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.InsecureSkipTLS,
		},
		DialContext: (&net.Dialer{
			Timeout:   cfg.Timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// Configure proxy if specified
	if cfg.ProxyURL != "" {
		proxyURL, err := url.Parse(cfg.ProxyURL)
		if err != nil {
			return nil, err
		}

		// Check if it's a SOCKS proxy
		if proxyURL.Scheme == "socks5" || proxyURL.Scheme == "socks5h" {
			auth := &proxy.Auth{}
			if proxyURL.User != nil {
				auth.User = proxyURL.User.Username()
				auth.Password, _ = proxyURL.User.Password()
			} else {
				auth = nil
			}

			dialer, err := proxy.SOCKS5("tcp", proxyURL.Host, auth, proxy.Direct)
			if err != nil {
				return nil, err
			}

			transport.DialContext = nil
			transport.Dial = dialer.Dial
		} else {
			// HTTP/HTTPS proxy
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
	}

	// Configure redirect handling
	if !cfg.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return client, nil
}

// DefaultClient creates a client with default settings
func DefaultClient() *http.Client {
	client, _ := NewClient(ClientConfig{
		Timeout:         5 * time.Second,
		InsecureSkipTLS: true,
		FollowRedirects: true,
	})
	return client
}
