package cli

import (
	"fmt"
	"os"

	"github.com/hansmach1ne/lfimap/internal/config"
	"github.com/spf13/cobra"
)

var (
	args    *config.Arguments
	rootCmd *cobra.Command
)

// ParseArgs parses command line arguments and returns the configuration
func ParseArgs() (*config.Arguments, error) {
	args = &config.Arguments{
		Placeholder: "PWN",
		HTTPValid:   []int{200, 204, 301, 302, 303},
		MaxTimeout:  5,
	}

	rootCmd = &cobra.Command{
		Use:   "lfimap",
		Short: "LFImap - Local File Inclusion discovery and exploitation tool",
		Long:  "LFImap, Local File Inclusion discovery and exploitation tool",
		Run: func(cmd *cobra.Command, cmdArgs []string) {
			// Main execution happens in main.go after parsing
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// Target options
	rootCmd.Flags().StringVarP(&args.URL, "url", "U", "", "Single URL to test")
	rootCmd.Flags().StringVarP(&args.URLFile, "file", "F", "", "Load multiple URLs to test from a file")
	rootCmd.Flags().StringVarP(&args.RequestFile, "request", "R", "", "Load single request to test from a file")

	// Request options
	rootCmd.Flags().StringVarP(&args.Cookie, "cookie", "C", "", "HTTP session Cookie header")
	rootCmd.Flags().StringVarP(&args.PostData, "data", "D", "", "HTTP request FORM-data")
	rootCmd.Flags().StringArrayVarP(&args.Header, "header", "H", nil, "Additional HTTP header(s)")
	rootCmd.Flags().StringVarP(&args.Method, "method", "M", "", "Request method to use for testing")
	rootCmd.Flags().StringVarP(&args.Proxy, "proxy", "P", "", "Use a proxy to connect to the target endpoint")
	rootCmd.Flags().StringVar(&args.UserAgent, "useragent", "", "HTTP user-agent header value")
	rootCmd.Flags().StringVar(&args.Referer, "referer", "", "HTTP referer header value")
	rootCmd.Flags().StringVar(&args.Placeholder, "placeholder", "PWN", "Custom testing placeholder name")
	rootCmd.Flags().IntVar(&args.Delay, "delay", 0, "Delay in milliseconds after each request")
	rootCmd.Flags().IntVar(&args.MaxTimeout, "max-timeout", 5, "Number of seconds after giving up on a response")
	rootCmd.Flags().IntSliceVar(&args.HTTPValid, "http-ok", []int{200, 204, 301, 302, 303}, "HTTP response code(s) to treat as valid")

	// CSRF options
	rootCmd.Flags().StringVar(&args.CSRFParam, "csrf-param", "", "Parameter used to hold anti-CSRF token")
	rootCmd.Flags().StringVar(&args.CSRFMethod, "csrf-method", "", "HTTP method to use during anti-CSRF token page visit")
	rootCmd.Flags().StringVar(&args.CSRFURL, "csrf-url", "", "URL address to visit for extraction of anti-CSRF token")
	rootCmd.Flags().StringVar(&args.CSRFData, "csrf-data", "", "POST data to send during anti-CSRF token page visit")

	// Second-order options
	rootCmd.Flags().StringVar(&args.SecondMethod, "second-method", "", "Specify method for second order request")
	rootCmd.Flags().StringVar(&args.SecondURL, "second-url", "", "URL for second order request")
	rootCmd.Flags().StringVar(&args.SecondData, "second-data", "", "FORM-line data for second-order request")

	// Flags
	rootCmd.Flags().BoolVar(&args.ForceSSL, "force-ssl", false, "Force usage of HTTPS/SSL if otherwise not specified")
	rootCmd.Flags().BoolVar(&args.NoStop, "no-stop", false, "Don't stop using the same testing technique upon findings")
	rootCmd.Flags().BoolVar(&args.NoRedirect, "no-redirect", false, "Don't follow HTTP redirects")

	// Attack technique options
	rootCmd.Flags().BoolVarP(&args.TestFilter, "filter", "f", false, "Attack using filter wrapper")
	rootCmd.Flags().BoolVarP(&args.TestInput, "input", "i", false, "Attack using input wrapper")
	rootCmd.Flags().BoolVarP(&args.TestData, "php-data", "d", false, "Attack using data wrapper")
	rootCmd.Flags().BoolVarP(&args.TestExpect, "expect", "e", false, "Attack using expect wrapper")
	rootCmd.Flags().BoolVarP(&args.TestTrunc, "trunc", "t", false, "Attack using path traversal with wordlist")
	rootCmd.Flags().BoolVarP(&args.TestRFI, "rfi", "r", false, "Attack using remote file inclusion")
	rootCmd.Flags().BoolVarP(&args.TestCMD, "cmd", "c", false, "Attack using command injection")
	rootCmd.Flags().BoolVar(&args.TestFile, "file-wrapper", false, "Attack using file wrapper")
	rootCmd.Flags().BoolVar(&args.TestHeur, "heuristics", false, "Test for miscellaneous issues using heuristics")
	rootCmd.Flags().BoolVarP(&args.TestAll, "all", "a", false, "Use all supported attack methods")

	// Payload options
	rootCmd.Flags().IntVarP(&args.Encode, "encode", "n", 0, "URL-encode payloads N times")
	rootCmd.Flags().BoolVarP(&args.Quick, "quick", "q", false, "Perform quick testing with fewer payloads")
	rootCmd.Flags().BoolVarP(&args.RevShell, "exploit", "x", false, "Exploit and achieve reverse shell if RCE is available")
	rootCmd.Flags().StringVar(&args.LHost, "lhost", "", "Local IP address for reverse connection")
	rootCmd.Flags().IntVar(&args.LPort, "lport", 0, "Local port number for reverse connection")
	rootCmd.Flags().StringVar(&args.Callback, "callback", "", "Callback location for out of band detection")

	// Wordlist options
	rootCmd.Flags().StringVar(&args.TruncWordlist, "wordlist", "", "Path to wordlist for path traversal modality")
	rootCmd.Flags().BoolVar(&args.UseLong, "use-long", false, "Use long.txt wordlist for path traversal modality")

	// Output options
	rootCmd.Flags().StringVar(&args.Log, "log", "", "Output all requests and responses to specified file")

	// Other options
	rootCmd.Flags().BoolVar(&args.NoColor, "no-color", false, "Disables colored output for STDOUT")
	rootCmd.Flags().BoolVarP(&args.Verbose, "verbose", "v", false, "Print more detailed output when performing attacks")

	// Mark exclusive flags
	rootCmd.MarkFlagsMutuallyExclusive("url", "file", "request")

	if err := rootCmd.Execute(); err != nil {
		return nil, err
	}

	return args, nil
}

// ValidateArgs validates the parsed arguments
func ValidateArgs(args *config.Arguments) error {
	// Check that at least one target is specified
	if args.URL == "" && args.URLFile == "" && args.RequestFile == "" {
		return fmt.Errorf("at least one target option is required (-U, -F, or -R)")
	}

	// Validate reverse shell options
	if args.RevShell {
		if args.LHost == "" || args.LPort == 0 {
			return fmt.Errorf("--lhost and --lport are required when using --exploit")
		}
		if args.LPort < 1 || args.LPort > 65534 {
			return fmt.Errorf("--lport must be between 1 and 65534")
		}
	}

	// Validate URL file exists
	if args.URLFile != "" {
		if _, err := os.Stat(args.URLFile); os.IsNotExist(err) {
			return fmt.Errorf("URL file not found: %s", args.URLFile)
		}
	}

	// Validate request file exists
	if args.RequestFile != "" {
		if _, err := os.Stat(args.RequestFile); os.IsNotExist(err) {
			return fmt.Errorf("request file not found: %s", args.RequestFile)
		}
	}

	// Validate wordlist exists if specified
	if args.TruncWordlist != "" {
		if _, err := os.Stat(args.TruncWordlist); os.IsNotExist(err) {
			return fmt.Errorf("wordlist file not found: %s", args.TruncWordlist)
		}
	}

	return nil
}

