package util

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// IsValidURL checks if the provided URL is valid
func IsValidURL(rawURL string) bool {
	if rawURL == "" {
		return false
	}

	urlRegex := regexp.MustCompile(
		`^(?:http)s?://` + // http://, https://
			`(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*?[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?|` + // domain
			`localhost|` + // localhost
			`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}` + // IP address
			`(?::\d+)?` + // optional port
			`(?:/?|[/?]\S*)?$`, // optional trailing slash or path
	)

	return urlRegex.MatchString(rawURL)
}

// IsValidJSON checks if the provided string is valid JSON
func IsValidJSON(data string) bool {
	var js json.RawMessage
	return json.Unmarshal([]byte(data), &js) == nil
}

// IsFileEndingWithNewline checks if there is a blank line after headers in request file
func IsFileEndingWithNewline(filePath string) bool {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return false
	}

	idx := strings.Index(string(content), "\n\n")
	if idx != -1 && idx < len(content)-1 {
		return true
	}
	return false
}

// ConvertFormDataToJSON converts HTTP form data to JSON string
func ConvertFormDataToJSON(formData string) (string, error) {
	if formData == "" {
		return "{}", nil
	}

	params := make(map[string]string)
	items := strings.Split(formData, "&")

	for _, item := range items {
		parts := strings.SplitN(item, "=", 2)
		key := parts[0]
		value := ""
		if len(parts) > 1 {
			value = parts[1]
		}
		params[key] = value
	}

	jsonBytes, err := json.Marshal(params)
	if err != nil {
		return "", err
	}
	return string(jsonBytes), nil
}

// ParseHTTPRequestFile parses an HTTP request file and returns method, headers, and form data
func ParseHTTPRequestFile(filePath string, placeholder string) (string, map[string]string, []string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", nil, nil, fmt.Errorf("file not found: %s", filePath)
	}

	parts := strings.SplitN(string(content), "\n\n", 2)
	if len(parts) < 2 {
		return "", nil, nil, fmt.Errorf("invalid request file format: missing blank line after headers")
	}

	headerSection := parts[0]
	postData := strings.TrimSpace(parts[1])

	lines := strings.Split(headerSection, "\n")
	if len(lines) == 0 {
		return "", nil, nil, fmt.Errorf("empty request file")
	}

	// Parse first line: METHOD ENDPOINT PROTOCOL
	firstLine := strings.Fields(lines[0])
	if len(firstLine) < 2 {
		return "", nil, nil, fmt.Errorf("invalid request line")
	}
	method := firstLine[0]

	// Parse headers
	headers := make(map[string]string)
	for _, line := range lines[1:] {
		idx := strings.Index(line, ":")
		if idx > 0 {
			key := strings.TrimSpace(line[:idx])
			value := strings.TrimSpace(line[idx+1:])
			headers[key] = value
		}
	}

	// Parse form data
	formData := ParseFormDataLine(postData, placeholder)

	return method, headers, formData, nil
}

// ParseURLFromRequestFile parses URL from HTTP request file
func ParseURLFromRequestFile(filePath string, forceSSL bool) (string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("file not found: %s", filePath)
	}

	lines := strings.Split(string(content), "\n")
	if len(lines) == 0 {
		return "", fmt.Errorf("empty request file")
	}

	// Parse first line
	firstLine := strings.Fields(lines[0])
	if len(firstLine) < 2 {
		return "", fmt.Errorf("invalid request line")
	}
	endpoint := firstLine[1]

	// Find Host header
	var host string
	for _, line := range lines[1:] {
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			host = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
			break
		}
	}
	if host == "" {
		return "", fmt.Errorf("host header not found")
	}

	// Build URL
	scheme := "http"
	if forceSSL {
		scheme = "https"
	}

	return fmt.Sprintf("%s://%s%s", scheme, host, endpoint), nil
}

// GetAllParams returns all query parameters from a URL
func GetAllParams(rawURL string) map[string][]string {
	params := make(map[string][]string)

	u, err := url.Parse(rawURL)
	if err != nil {
		return params
	}

	query := u.RawQuery
	if query == "" {
		return params
	}

	for _, param := range strings.Split(query, "&") {
		if param == "" {
			continue
		}
		parts := strings.SplitN(param, "=", 2)
		key := parts[0]
		value := ""
		if len(parts) > 1 {
			value = parts[1]
		}
		params[key] = append(params[key], value)
	}

	return params
}

// ParseGet parses a URL and returns a list of test URLs with placeholder
func ParseGet(rawURL string, placeholder string) []string {
	var testURLs []string

	params := GetAllParams(rawURL)
	if len(params) == 0 {
		return []string{rawURL}
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return []string{rawURL}
	}

	baseURL := fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, u.Path)

	// For each parameter, create a test URL
	for testParam := range params {
		if testParam == "" {
			testURLs = append(testURLs, baseURL)
			continue
		}

		recreated := baseURL
		first := true

		for key, values := range params {
			if first {
				recreated += "?"
				first = false
			} else {
				recreated += "&"
			}

			recreated += key + "="

			if key == testParam {
				recreated += placeholder
			} else {
				// Handle array parameters
				if len(values) <= 1 {
					recreated += strings.Join(values, "")
				} else {
					for i, v := range values {
						if i > 0 {
							recreated += "&" + key + "="
						}
						recreated += v
					}
				}
			}
		}

		testURLs = append(testURLs, recreated)
	}

	return testURLs
}

// ParseFormDataLine parses form data and returns a list of testable parameters
func ParseFormDataLine(postData string, placeholder string) []string {
	if postData == "" {
		return []string{}
	}

	parameters := strings.Split(postData, "&")
	numParams := len(parameters)
	testParams := make([]string, 0, numParams)

	for i := 0; i < numParams; i++ {
		var tempParams []string

		for idx, parameter := range parameters {
			parts := strings.SplitN(parameter, "=", 2)
			name := parts[0]
			var value string

			if idx == i {
				value = placeholder
			} else if len(parts) > 1 {
				value = parts[1]
			}

			tempParams = append(tempParams, fmt.Sprintf("%s=%s", name, value))
		}

		testParams = append(testParams, strings.Join(tempParams, "&"))
	}

	return testParams
}

// GetParamsWithPlaceholder returns parameter names that contain the placeholder
func GetParamsWithPlaceholder(rawURL string, placeholder string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	values, _ := url.ParseQuery(u.RawQuery)
	var matching []string

	for key, vals := range values {
		for _, v := range vals {
			if strings.Contains(v, placeholder) {
				matching = append(matching, key)
				break
			}
		}
	}

	return strings.Join(matching, ", ")
}

// PostParamsWithPlaceholder returns POST parameter names that contain the placeholder
func PostParamsWithPlaceholder(postData string, placeholder string) string {
	if postData == "" {
		return ""
	}

	var matching []string
	params := strings.Split(postData, "&")

	for _, param := range params {
		parts := strings.SplitN(param, "=", 2)
		if len(parts) == 2 && strings.Contains(parts[1], placeholder) {
			matching = append(matching, parts[0])
		}
	}

	return strings.Join(matching, ", ")
}

// GetHeadersToTest returns header names that contain the placeholder
func GetHeadersToTest(headers map[string]string, placeholder string) string {
	var matching []string
	placeholderLower := strings.ToLower(placeholder)

	for key, value := range headers {
		if strings.Contains(strings.ToLower(value), placeholderLower) {
			matching = append(matching, key)
		}
	}

	return strings.Join(matching, ", ")
}

// ParseURLParameters returns comma-separated parameter names from URL
func ParseURLParameters(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	values, _ := url.ParseQuery(u.RawQuery)
	var names []string

	for key := range values {
		names = append(names, key)
	}

	return strings.Join(names, ", ")
}

// IsStringInDict checks if string exists in map keys or values
func IsStringInDict(s string, m map[string]string) bool {
	for k, v := range m {
		if strings.Contains(k, s) || strings.Contains(v, s) {
			return true
		}
	}
	return false
}

// ReadLines reads a file and returns lines as a slice
func ReadLines(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	return lines, scanner.Err()
}
