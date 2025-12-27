package resources

import (
	"embed"
	"strings"
)

//go:embed wordlists/short.txt
//go:embed wordlists/long.txt
//go:embed wordlists/http_access_log.txt
var Wordlists embed.FS

//go:embed exploits/*
var Exploits embed.FS

// ReadWordlist reads lines from an embedded wordlist
func ReadWordlist(name string) ([]string, error) {
	content, err := Wordlists.ReadFile("wordlists/" + name)
	if err != nil {
		return nil, err
	}
	return strings.Split(string(content), "\n"), nil
}

// GetShortWordlist returns the short truncation wordlist
func GetShortWordlist() ([]string, error) {
	return ReadWordlist("short.txt")
}

// GetLongWordlist returns the long truncation wordlist
func GetLongWordlist() ([]string, error) {
	return ReadWordlist("long.txt")
}

// GetHTTPLogPaths returns the HTTP access log paths wordlist
func GetHTTPLogPaths() ([]string, error) {
	return ReadWordlist("http_access_log.txt")
}
