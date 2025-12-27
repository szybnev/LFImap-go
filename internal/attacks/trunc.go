package attacks

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	lfihttp "github.com/hansmach1ne/lfimap/internal/http"
	"github.com/hansmach1ne/lfimap/resources"
)

// TruncAttack implements path truncation attack
type TruncAttack struct{}

// Name returns the attack name
func (a *TruncAttack) Name() string {
	return "trunc"
}

// Test executes the path truncation attack
func (a *TruncAttack) Test(ctx *AttackContext, targetURL, postData string) bool {
	if ctx.Verbose {
		fmt.Printf("%s Testing with path truncation...\n", ctx.Colors.Blue("[i]"))
	}

	var lines []string
	var err error

	// Determine wordlist source
	wordlistPath := ctx.Config.Args.TruncWordlist
	if wordlistPath != "" {
		// Custom wordlist from filesystem
		lines, err = readWordlistFile(wordlistPath)
	} else if ctx.Config.Args.UseLong {
		// Embedded long wordlist
		lines, err = resources.GetLongWordlist()
	} else {
		// Embedded short wordlist (default)
		lines, err = resources.GetShortWordlist()
	}

	if err != nil {
		fmt.Printf("%s Could not read wordlist: %v\n", ctx.Colors.Red("[-]"), err)
		return false
	}

	placeholder := ctx.Config.Args.Placeholder
	headers := lfihttp.HeadersToMap(lfihttp.InitHeaders(
		ctx.Config.Args.UserAgent,
		ctx.Config.Args.Referer,
		ctx.Config.Args.Cookie,
	))

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		u, reqHeaders, postTest := lfihttp.PrepareRequest(placeholder, line, targetURL, postData, headers, ctx.Encodings)
		result := lfihttp.Request(ctx.HTTPCtx, u, reqHeaders, postTest, "LFI", "TRUNC", false, false, false)

		if !result.DoContinue {
			return true
		}

		if i == 1 && ctx.Quick {
			return false
		}
	}

	return false
}

// readWordlistFile reads lines from a wordlist file on the filesystem
func readWordlistFile(path string) ([]string, error) {
	file, err := os.Open(path)
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
