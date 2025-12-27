package http

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hansmach1ne/lfimap/internal/config"
	"github.com/hansmach1ne/lfimap/internal/util"
)

// RequestContext holds all context for making requests
type RequestContext struct {
	Config  *config.Config
	Client  *http.Client
	Stats   *util.Stats
	Colors  *util.Colors
	WebDir  string
	Verbose bool
}

// RequestResult holds the result of a request
type RequestResult struct {
	Response     *http.Response
	Body         string
	DoContinue   bool
	Exploit      *config.Exploit
	Error        error
}

// PrepareRequest prepares a request by replacing placeholder with payload
func PrepareRequest(parameter, payload, url, postData string, headers map[string]string, encodings []string) (string, map[string]string, string) {
	encodedPayload := util.Encode(payload, encodings)

	// Prepare URL
	reqURL := url
	if strings.Contains(url, parameter) {
		reqURL = strings.Replace(url, parameter, encodedPayload, -1)
	}

	// Prepare POST data
	reqData := ""
	if postData != "" {
		reqData = strings.TrimLeft(strings.Replace(postData, parameter, encodedPayload, -1), " ")
	}

	// Prepare headers
	reqHeaders := make(map[string]string)
	paramInHeaders := false
	for _, v := range headers {
		if strings.Contains(v, parameter) {
			paramInHeaders = true
			break
		}
	}

	if paramInHeaders {
		for k, v := range headers {
			if strings.Contains(v, parameter) {
				reqHeaders[k] = strings.Replace(v, parameter, encodedPayload, -1)
			} else {
				reqHeaders[k] = v
			}
		}
	} else {
		for k, v := range headers {
			reqHeaders[k] = v
		}
	}

	return reqURL, reqHeaders, reqData
}

// Request sends an HTTP request and processes the response
func Request(ctx *RequestContext, url string, headers map[string]string, postData string,
	exploitType, exploitMethod string, exploit, followRedirect, isCsrfRequest bool) *RequestResult {

	args := ctx.Config.Args
	result := &RequestResult{DoContinue: true}

	if postData == "" {
		postData = ""
	}

	// Increment request counter
	ctx.Stats.IncrementRequests()

	// Calculate timeout
	var timeout time.Duration
	if exploitMethod == "RFI" {
		timeout = 15 * time.Second
	} else if args.MaxTimeout > 0 {
		timeout = time.Duration(args.MaxTimeout) * time.Second
	} else if args.Proxy != "" {
		timeout = 15 * time.Second
	} else {
		timeout = 5 * time.Second
	}

	// Determine HTTP method
	method := "GET"
	if isCsrfRequest && args.CSRFMethod != "" {
		method = args.CSRFMethod
	} else if args.Method != "" {
		method = args.Method
	}

	// Handle CSRF URL
	if args.CSRFURL != "" && isCsrfRequest {
		url = args.CSRFURL
	}

	// Handle CSRF data
	if args.CSRFData != "" && isCsrfRequest {
		postData = args.CSRFData
	}

	// Create request context with timeout
	reqCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Create request
	var body io.Reader
	if postData != "" {
		body = bytes.NewBufferString(postData)
	}

	req, err := http.NewRequestWithContext(reqCtx, method, url, body)
	if err != nil {
		result.Error = err
		result.DoContinue = !args.NoStop
		return result
	}

	// Set headers
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// Set Content-Type for POST
	if postData != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	// Send request
	resp, err := ctx.Client.Do(req)
	if err != nil {
		handleRequestError(ctx, err, exploitMethod, args)
		result.Error = err
		result.DoContinue = !args.NoStop
		return result
	}
	defer resp.Body.Close()

	// Read response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Error = err
		result.DoContinue = true
		return result
	}
	bodyStr := string(bodyBytes)

	result.Response = resp
	result.Body = bodyStr

	// Check for second-order vulnerability
	if args.SecondURL != "" && !isCsrfRequest {
		secondMethod := "GET"
		if args.SecondMethod != "" {
			secondMethod = args.SecondMethod
		}

		var secondBody io.Reader
		if args.SecondData != "" {
			secondBody = bytes.NewBufferString(args.SecondData)
		}

		secondReq, err := http.NewRequestWithContext(reqCtx, secondMethod, args.SecondURL, secondBody)
		if err == nil {
			for k, v := range headers {
				secondReq.Header.Set(k, v)
			}
			secondResp, err := ctx.Client.Do(secondReq)
			if err == nil {
				defer secondResp.Body.Close()
				secondBodyBytes, _ := io.ReadAll(secondResp.Body)
				result.Response = secondResp
				result.Body = string(secondBodyBytes)
			}
		}
	}

	// Check if payload executed
	if !exploit {
		if initExploit(ctx, result.Response, result.Body, exploitType, url, postData, headers, exploitMethod) {
			result.DoContinue = false
		}
	}

	// Log request/response if enabled
	if args.Log != "" {
		logRequest(args.Log, req, resp, postData, bodyStr)
	}

	// Apply delay if specified
	if args.Delay > 0 {
		time.Sleep(time.Duration(args.Delay) * time.Millisecond)
	}

	return result
}

// initExploit checks if exploit succeeded and records it
func initExploit(ctx *RequestContext, resp *http.Response, body, exploitType, url, postData string,
	headers map[string]string, attackMethod string) bool {

	args := ctx.Config.Args

	// Add script name variants to replace list
	toReplace := append([]string{}, config.ToReplace...)
	if ctx.Config.ScriptName != "" {
		toReplace = append(toReplace, ctx.Config.ScriptName)
		toReplace = append(toReplace, ctx.Config.ScriptName+".php")
		toReplace = append(toReplace, ctx.Config.ScriptName+"%00")
	}

	if !CheckPayload(resp, body) {
		return false
	}

	for _, replace := range toReplace {
		if strings.Contains(url, replace) || strings.Contains(url, "?c="+replace) || strings.Contains(postData, replace) {
			// Detect OS
			os := DetectOS(url, postData, body)

			// Replace with temp arg
			u := strings.Replace(url, replace, ctx.Config.TempArg, -1)
			p := ""
			if strings.Contains(postData, replace) {
				p = strings.Replace(postData, replace, ctx.Config.TempArg, -1)
			}

			// Create exploit record
			exploit := config.Exploit{
				RequestType:  "GET",
				ExploitType:  exploitType,
				GetVal:       u,
				PostVal:      p,
				Headers:      resp.Header,
				AttackMethod: attackMethod,
				OS:           os,
			}
			ctx.Config.AddExploit(exploit)

			// Print finding
			if postData == "" && exploitType != "" {
				fmt.Printf("%s %s -> '%s'\n", ctx.Colors.Green("[+]"), exploitType, url)
			} else if exploitType != "" {
				fmt.Printf("%s %s -> '%s' -> HTTP POST -> '%s'\n", ctx.Colors.Green("[+]"), exploitType, url, postData)
			}
			ctx.Stats.IncrementVulns()

			if !args.NoStop {
				return true
			}
			return false
		}
	}

	return false
}

// handleRequestError handles various HTTP request errors
func handleRequestError(ctx *RequestContext, err error, exploitMethod string, args *config.Arguments) {
	errStr := err.Error()

	if strings.Contains(errStr, "context deadline exceeded") || strings.Contains(errStr, "timeout") {
		if exploitMethod == "RFI" && args.Callback == "" && args.LHost == "" {
			fmt.Printf("%s Socket timeout. This could be an indication for RFI vulnerability. Try specifying '--lhost' or '--callback' to confirm...\n",
				ctx.Colors.Yellow("[?]"))
		} else {
			fmt.Printf("%s Request timeout. Try specifying bigger '--delay' or '--max-timeout'. Skipping...\n",
				ctx.Colors.Red("[-]"))
		}
	} else if strings.Contains(errStr, "connection refused") {
		fmt.Printf("%s Connection refused. Try proxying requests to see what happened...\n",
			ctx.Colors.Red("[-]"))
	} else if strings.Contains(errStr, "no such host") {
		fmt.Printf("%s Host not found. Check the URL and try again...\n",
			ctx.Colors.Red("[-]"))
	} else {
		if args.Verbose {
			fmt.Printf("%s Request error: %v\n", ctx.Colors.Red("[-]"), err)
		}
	}
}

// logRequest logs request and response to file
func logRequest(logFile string, req *http.Request, resp *http.Response, postData, body string) {
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	// Log request
	f.WriteString(fmt.Sprintf("%s %s HTTP/1.1\n", req.Method, req.URL.RequestURI()))
	f.WriteString(fmt.Sprintf("Host: %s\n", req.URL.Host))
	for k, v := range req.Header {
		f.WriteString(fmt.Sprintf("%s: %s\n", k, strings.Join(v, ", ")))
	}
	if postData != "" {
		f.WriteString("\n\n")
		f.WriteString(postData)
	}
	f.WriteString("\n\n\n")

	// Log response
	if resp != nil {
		f.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\n", resp.StatusCode, resp.Status))
		for k, v := range resp.Header {
			f.WriteString(fmt.Sprintf("%s: %s\n", k, strings.Join(v, ", ")))
		}
		f.WriteString("\n\n")
		f.WriteString(body)
		f.WriteString("\n--\n\n\n")
	}
}
