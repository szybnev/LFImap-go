package attacks

import (
	"fmt"
	"math/rand"
	"net/url"
	"regexp"
	"strings"

	lfihttp "github.com/hansmach1ne/lfimap/internal/http"
)

// HeuristicsAttack implements heuristic-based vulnerability testing
type HeuristicsAttack struct{}

// Name returns the attack name
func (a *HeuristicsAttack) Name() string {
	return "heuristics"
}

// Test executes heuristic tests (XSS, CRLF, info disclosure, open redirect)
func (a *HeuristicsAttack) Test(ctx *AttackContext, targetURL, postData string) bool {
	if ctx.Verbose {
		fmt.Printf("%s Testing with heuristics...\n", ctx.Colors.Blue("[i]"))
	}

	placeholder := ctx.Config.Args.Placeholder
	headers := lfihttp.HeadersToMap(lfihttp.InitHeaders(
		ctx.Config.Args.UserAgent,
		ctx.Config.Args.Referer,
		ctx.Config.Args.Cookie,
	))

	found := false

	// XSS Testing
	if a.testXSS(ctx, targetURL, postData, placeholder, headers) {
		found = true
		if ctx.Quick {
			return true
		}
	}

	// CRLF Testing
	if a.testCRLF(ctx, targetURL, postData, placeholder, headers) {
		found = true
		if ctx.Quick {
			return true
		}
	}

	// Error-based info disclosure
	if a.testInfoDisclosure(ctx, targetURL, postData, placeholder, headers) {
		found = true
		if ctx.Quick {
			return true
		}
	}

	// Open Redirect Testing
	if a.testOpenRedirect(ctx, targetURL, postData, placeholder, headers) {
		found = true
	}

	return found
}

// testXSS tests for XSS vulnerabilities
func (a *HeuristicsAttack) testXSS(ctx *AttackContext, targetURL, postData, placeholder string, headers map[string]string) bool {
	// Generate random XSS polyglot
	protocol := randomString(3)
	num1 := rand.Intn(100)
	num2 := rand.Intn(100)
	letter1 := string(byte('a' + rand.Intn(26)))
	letter2 := string(byte('a' + rand.Intn(26)))
	letters3 := randomString(2)
	letters4 := randomString(2)

	// XSS polyglot: {protocol}:{num1}{letter1}>{letter2}<{letters3};{num2}"'{letters4}
	xssPayload := fmt.Sprintf("%s:%d%s>%s<%s;%d\"'%s",
		protocol, num1, letter1, letter2, letters3, num2, letters4)

	u, reqHeaders, postTest := lfihttp.PrepareRequest(placeholder, url.QueryEscape(xssPayload), targetURL, postData, headers, ctx.Encodings)
	result := lfihttp.Request(ctx.HTTPCtx, u, reqHeaders, postTest, "XSS", "HEUR", false, false, false)

	if result.Error != nil {
		return false
	}

	// Check for XSS reflection
	body := result.Body

	// Check HREF attribute reflection
	hrefPattern := regexp.MustCompile(fmt.Sprintf(`href\s*=\s*["']%s:`, protocol))
	if hrefPattern.MatchString(body) {
		fmt.Printf("%s Possible XSS (HREF attribute reflection) -> '%s'\n", ctx.Colors.Green("[+]"), u)
		ctx.Stats.IncrementVulns()
		return true
	}

	// Check full reflection
	if strings.Contains(body, xssPayload) {
		fmt.Printf("%s Possible XSS (full reflection) -> '%s'\n", ctx.Colors.Green("[+]"), u)
		ctx.Stats.IncrementVulns()
		return true
	}

	return false
}

// testCRLF tests for CRLF injection
func (a *HeuristicsAttack) testCRLF(ctx *AttackContext, targetURL, postData, placeholder string, headers map[string]string) bool {
	// CRLF payloads with various encodings
	crlfPayload := "%0d%0aLfi:13CRLF37%250d%250aLfi%3A13CRLF37%25%30D%25%30ALfi%3A13CRLF37"

	u, reqHeaders, postTest := lfihttp.PrepareRequest(placeholder, crlfPayload, targetURL, postData, headers, ctx.Encodings)
	result := lfihttp.Request(ctx.HTTPCtx, u, reqHeaders, postTest, "CRLF", "HEUR", false, false, false)

	if result.Error != nil || result.Response == nil {
		return false
	}

	// Check response headers for CRLF injection
	for key, values := range result.Response.Header {
		keyLower := strings.ToLower(key)
		for _, value := range values {
			if strings.Contains(keyLower, "lfi") || strings.Contains(value, "13CRLF37") {
				fmt.Printf("%s CRLF Injection found -> '%s'\n", ctx.Colors.Green("[+]"), u)
				ctx.Stats.IncrementVulns()
				return true
			}
		}
	}

	return false
}

// testInfoDisclosure tests for error-based information disclosure
func (a *HeuristicsAttack) testInfoDisclosure(ctx *AttackContext, targetURL, postData, placeholder string, headers map[string]string) bool {
	// Send a malformed payload to trigger errors
	u, reqHeaders, postTest := lfihttp.PrepareRequest(placeholder, "../../../../etc/passwd'\"", targetURL, postData, headers, ctx.Encodings)
	result := lfihttp.Request(ctx.HTTPCtx, u, reqHeaders, postTest, "INFO", "HEUR", false, false, false)

	if result.Error != nil {
		return false
	}

	body := strings.ToLower(result.Body)

	// File inclusion error indicators
	fiErrors := []string{
		"warning",
		"include(",
		"require(",
		"fopen(",
		"fpassthru(",
		"readfile(",
		"fread(",
		"fgets(",
	}

	// SQL error indicators
	sqlErrors := []string{
		"you have an error in your sql syntax",
		"unclosed quotation mark after the character string",
		"mysql_query(",
		"mysql_fetch_array(",
		"mysql_fetch_assoc(",
		"mysql_prepare(",
		"mysql_stmt_execute(",
	}

	for _, errStr := range fiErrors {
		if strings.Contains(body, errStr) {
			fmt.Printf("%s File Inclusion error disclosure found -> '%s' (contains '%s')\n",
				ctx.Colors.Green("[+]"), u, errStr)
			ctx.Stats.IncrementVulns()
			return true
		}
	}

	for _, errStr := range sqlErrors {
		if strings.Contains(body, errStr) {
			fmt.Printf("%s SQL error disclosure found -> '%s' (contains '%s')\n",
				ctx.Colors.Green("[+]"), u, errStr)
			ctx.Stats.IncrementVulns()
			return true
		}
	}

	return false
}

// testOpenRedirect tests for open redirect vulnerabilities
func (a *HeuristicsAttack) testOpenRedirect(ctx *AttackContext, targetURL, postData, placeholder string, headers map[string]string) bool {
	redirectPayload := "/lfi/a/../"

	u, reqHeaders, postTest := lfihttp.PrepareRequest(placeholder, url.QueryEscape(redirectPayload), targetURL, postData, headers, ctx.Encodings)

	// Don't follow redirects for this test
	result := lfihttp.Request(ctx.HTTPCtx, u, reqHeaders, postTest, "REDIRECT", "HEUR", false, false, false)

	if result.Error != nil || result.Response == nil {
		return false
	}

	// Check Location header
	location := result.Response.Header.Get("Location")
	if location == "" {
		return false
	}

	// Check for redirect patterns
	patterns := []string{
		"/lfi/a/../",
		"http:///lfi/a/../",
		"https:///lfi/a/../",
		"//lfi/a/../",
		"///lfi/a/../",
	}

	for _, pattern := range patterns {
		if strings.Contains(location, pattern) {
			fmt.Printf("%s Open Redirect found -> '%s' (Location: %s)\n",
				ctx.Colors.Green("[+]"), u, location)
			ctx.Stats.IncrementVulns()
			return true
		}
	}

	return false
}

// randomString generates a random string of given length
func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
