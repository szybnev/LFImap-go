package http

import (
	"io"
	"net/http"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/hansmach1ne/lfimap/internal/config"
)

// CheckPayload checks if the payload was executed based on response keywords
func CheckPayload(resp *http.Response, body string) bool {
	if resp == nil || body == "" {
		return false
	}

	for _, word := range config.KeyWords {
		if strings.Contains(body, word) {
			// Special case: avoid false positive for base64-encoded PHP data wrapper
			if word == "PD9w" && strings.Contains(body, "PD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4K") {
				return false
			}
			return true
		}
	}
	return false
}

// ExtractInputFields extracts input field names and values from HTML
func ExtractInputFields(htmlContent string) map[string]string {
	fields := make(map[string]string)

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlContent))
	if err != nil {
		return fields
	}

	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		name, nameExists := s.Attr("name")
		if nameExists {
			value, _ := s.Attr("value")
			fields[name] = value
		}
	})

	return fields
}

// ExtractAllParameters extracts parameters from URL and form data
func ExtractAllParameters(rawURL, formData string) map[string]string {
	params := make(map[string]string)

	// Extract URL parameters
	if idx := strings.Index(rawURL, "?"); idx != -1 {
		query := rawURL[idx+1:]
		for _, param := range strings.Split(query, "&") {
			parts := strings.SplitN(param, "=", 2)
			if len(parts) == 2 {
				params[parts[0]] = parts[1]
			} else if len(parts) == 1 {
				params[parts[0]] = ""
			}
		}
	}

	// Extract form data parameters
	if formData != "" {
		for _, param := range strings.Split(formData, "&") {
			parts := strings.SplitN(param, "=", 2)
			if len(parts) == 2 {
				params[parts[0]] = parts[1]
			} else if len(parts) == 1 {
				params[parts[0]] = ""
			}
		}
	}

	return params
}

// DetectOS detects the target OS based on response content
func DetectOS(url, postData, responseBody string) string {
	combined := strings.ToLower(url + postData + responseBody)

	if strings.Contains(combined, "ipconfig") ||
		strings.Contains(combined, "windows ip configuration") ||
		strings.Contains(combined, "windows\\system32") {
		return "windows"
	}
	return "linux"
}

// ReadResponseBody reads and returns the response body as string
func ReadResponseBody(resp *http.Response) (string, error) {
	if resp == nil || resp.Body == nil {
		return "", nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// IsValidStatusCode checks if the status code is in the valid list
func IsValidStatusCode(code int, validCodes []int) bool {
	for _, valid := range validCodes {
		if code == valid {
			return true
		}
	}
	return false
}
