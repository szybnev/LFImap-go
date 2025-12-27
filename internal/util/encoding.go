package util

import (
	"encoding/base64"
	"net/url"
)

// Base64Encode encodes a string to base64
func Base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// URLEncode encodes a string for use in URLs
func URLEncode(s string) string {
	return url.QueryEscape(s)
}

// Encode applies the specified encodings to the payload
// Encodings can be "B" for Base64 or "U" for URL encoding
// Multiple encodings are applied in order
func Encode(payload string, encodings []string) string {
	if len(encodings) == 0 {
		return payload
	}

	result := payload
	for _, enc := range encodings {
		switch enc {
		case "B":
			result = Base64Encode(result)
		case "U":
			result = URLEncode(result)
		}
	}
	return result
}
