package http

import (
	"math/rand"
	"net/http"
	"strings"
	"time"
)

// UserAgents contains common user agent strings
var UserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
	"Mozilla/5.0 (X11; Linux i686; rv:127.0) Gecko/20100101 Firefox/127.0",
	"Mozilla/5.0 (X11; U; Linux 2.4.2-2 i586; en-US; m18) Gecko/20010131 Netscape6/6.01",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/1.0.154.36 Safari/525.19",
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

// RandomUserAgent returns a random user agent string
func RandomUserAgent() string {
	return UserAgents[rand.Intn(len(UserAgents))]
}

// InitHeaders initializes default HTTP headers
func InitHeaders(userAgent, referer, cookie string) http.Header {
	headers := make(http.Header)

	// Set User-Agent
	if userAgent != "" {
		headers.Set("User-Agent", userAgent)
	} else {
		headers.Set("User-Agent", RandomUserAgent())
	}

	// Set Accept
	headers.Set("Accept", "*/*")

	// Set Connection
	headers.Set("Connection", "close")

	// Set Referer if provided
	if referer != "" {
		headers.Set("Referer", referer)
	}

	// Set Cookie if provided
	if cookie != "" {
		headers.Set("Cookie", cookie)
	}

	return headers
}

// AddHeader adds a header to the headers map
func AddHeader(headers http.Header, key, value string) {
	headers.Set(key, value)
}

// DelHeader removes a header from the headers map
func DelHeader(headers http.Header, key string) {
	headers.Del(key)
}

// ParseHeaderString parses a header string in format "Key: Value"
func ParseHeaderString(headerStr string) (string, string, bool) {
	idx := strings.Index(headerStr, ":")
	if idx < 0 {
		return "", "", false
	}

	key := strings.TrimSpace(headerStr[:idx])
	value := strings.TrimSpace(headerStr[idx+1:])

	return key, value, true
}

// MergeHeaders merges additional headers into existing headers
func MergeHeaders(base http.Header, additional []string) http.Header {
	for _, h := range additional {
		key, value, ok := ParseHeaderString(h)
		if ok {
			base.Set(key, value)
		}
	}
	return base
}

// CloneHeaders creates a deep copy of headers
func CloneHeaders(headers http.Header) http.Header {
	clone := make(http.Header)
	for k, v := range headers {
		clone[k] = append([]string{}, v...)
	}
	return clone
}

// HeadersToMap converts http.Header to map[string]string
func HeadersToMap(headers http.Header) map[string]string {
	m := make(map[string]string)
	for k, v := range headers {
		if len(v) > 0 {
			m[k] = v[0]
		}
	}
	return m
}

// MapToHeaders converts map[string]string to http.Header
func MapToHeaders(m map[string]string) http.Header {
	headers := make(http.Header)
	for k, v := range m {
		headers.Set(k, v)
	}
	return headers
}
