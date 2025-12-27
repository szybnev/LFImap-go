package scanner

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hansmach1ne/lfimap/internal/attacks"
	"github.com/hansmach1ne/lfimap/internal/config"
	lfihttp "github.com/hansmach1ne/lfimap/internal/http"
	"github.com/hansmach1ne/lfimap/internal/servers"
	"github.com/hansmach1ne/lfimap/internal/util"
)

// Scanner is the main vulnerability scanner
type Scanner struct {
	Config     *config.Config
	HTTPCtx    *lfihttp.RequestContext
	Colors     *util.Colors
	Stats      *util.Stats
	HTTPServer *servers.HTTPServer
	attacks    []attacks.Attack
	encodings  []string
}

// NewScanner creates a new scanner instance
func NewScanner(cfg *config.Config) (*Scanner, error) {
	// Initialize colors
	colors := util.NewColors(!cfg.Args.NoColor)

	// Initialize HTTP client
	clientCfg := lfihttp.ClientConfig{
		Timeout:         time.Duration(cfg.Args.MaxTimeout) * time.Second,
		ProxyURL:        cfg.Args.Proxy,
		FollowRedirects: !cfg.Args.NoRedirect,
		InsecureSkipTLS: cfg.Args.ForceSSL,
	}

	client, err := lfihttp.NewClient(clientCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// Initialize stats
	stats := util.NewStats()

	httpCtx := &lfihttp.RequestContext{
		Client:  client,
		Config:  cfg,
		Verbose: cfg.Args.Verbose,
		Colors:  colors,
		Stats:   stats,
	}

	// Build encodings list
	var encodings []string
	if cfg.Args.Encode > 0 {
		for i := 0; i < cfg.Args.Encode; i++ {
			encodings = append(encodings, "url")
		}
	}

	scanner := &Scanner{
		Config:    cfg,
		HTTPCtx:   httpCtx,
		Colors:    colors,
		Stats:     stats,
		encodings: encodings,
	}

	// Register attacks based on flags
	scanner.registerAttacks()

	return scanner, nil
}

// registerAttacks registers attack modules based on CLI flags
func (s *Scanner) registerAttacks() {
	args := s.Config.Args

	// If -a flag is set, enable all attacks
	if args.TestAll {
		args.TestFilter = true
		args.TestInput = true
		args.TestData = true
		args.TestExpect = true
		args.TestTrunc = true
		args.TestRFI = true
		args.TestCMD = true
		args.TestFile = true
		args.TestHeur = true
	}

	// Register individual attacks
	if args.TestFilter {
		s.attacks = append(s.attacks, &attacks.FilterAttack{})
	}
	if args.TestInput {
		s.attacks = append(s.attacks, &attacks.InputAttack{})
	}
	if args.TestData {
		s.attacks = append(s.attacks, &attacks.DataAttack{})
	}
	if args.TestExpect {
		s.attacks = append(s.attacks, &attacks.ExpectAttack{})
	}
	if args.TestFile {
		s.attacks = append(s.attacks, &attacks.FileAttack{})
	}
	if args.TestTrunc {
		s.attacks = append(s.attacks, &attacks.TruncAttack{})
	}
	if args.TestRFI {
		s.attacks = append(s.attacks, &attacks.RFIAttack{})
	}
	if args.TestCMD {
		s.attacks = append(s.attacks, &attacks.CMDIAttack{})
	}
	if args.TestHeur {
		s.attacks = append(s.attacks, &attacks.HeuristicsAttack{})
	}

	// If no attacks selected, default to filter
	if len(s.attacks) == 0 {
		s.attacks = append(s.attacks, &attacks.FilterAttack{})
	}
}

// Run starts the scanning process
func (s *Scanner) Run() error {
	fmt.Printf("%s Starting LFImap scanner...\n", s.Colors.LightBlue("[i]"))

	// Start HTTP server for RFI testing if needed
	if s.Config.Args.TestRFI && s.Config.Args.LHost != "" {
		s.HTTPServer = servers.NewHTTPServer(s.Config.RFITestPort, s.Colors)
		if err := s.HTTPServer.Start(); err != nil {
			fmt.Printf("%s Warning: Could not start HTTP server for RFI: %v\n", s.Colors.Yellow("[!]"), err)
		}
		defer s.HTTPServer.Stop()
	}

	// Get targets
	targets, err := s.getTargets()
	if err != nil {
		return err
	}

	if len(targets) == 0 {
		return fmt.Errorf("no valid targets found")
	}

	fmt.Printf("%s Loaded %d target(s) and %d attack module(s)\n",
		s.Colors.LightBlue("[i]"), len(targets), len(s.attacks))

	// Process each target
	for _, target := range targets {
		s.processTarget(target)
	}

	// Print summary
	s.printSummary()

	return nil
}

// getTargets collects all targets from various sources
func (s *Scanner) getTargets() ([]string, error) {
	var targets []string
	args := s.Config.Args

	// Single URL
	if args.URL != "" {
		targets = append(targets, args.URL)
	}

	// URL list file
	if args.URLFile != "" {
		urls, err := s.readURLFile(args.URLFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read URL file: %w", err)
		}
		targets = append(targets, urls...)
	}

	// Request file (raw HTTP request)
	if args.RequestFile != "" {
		url, err := s.parseRequestFile(args.RequestFile)
		if err != nil {
			return nil, fmt.Errorf("failed to parse request file: %w", err)
		}
		targets = append(targets, url)
	}

	// Validate and deduplicate
	seen := make(map[string]bool)
	var validTargets []string

	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}

		// Ensure HTTPS if force-ssl is set
		if args.ForceSSL && strings.HasPrefix(target, "http://") {
			target = "https://" + target[7:]
		}

		// Validate URL
		if !util.IsValidURL(target) {
			fmt.Printf("%s Invalid URL skipped: %s\n", s.Colors.Yellow("[!]"), target)
			continue
		}

		if !seen[target] {
			seen[target] = true
			validTargets = append(validTargets, target)
		}
	}

	return validTargets, nil
}

// readURLFile reads URLs from a file
func (s *Scanner) readURLFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			urls = append(urls, line)
		}
	}

	return urls, scanner.Err()
}

// parseRequestFile parses a raw HTTP request file
func (s *Scanner) parseRequestFile(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(content), "\n")
	if len(lines) == 0 {
		return "", fmt.Errorf("empty request file")
	}

	// Parse first line: METHOD /path HTTP/1.1
	parts := strings.Fields(lines[0])
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid request line")
	}

	method := parts[0]
	reqPath := parts[1]

	// Find Host header
	var host string
	var headerLines []string
	var postData string
	inBody := false

	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])

		if line == "" && !inBody {
			inBody = true
			continue
		}

		if inBody {
			postData += lines[i]
			continue
		}

		headerLines = append(headerLines, line)

		if strings.HasPrefix(strings.ToLower(line), "host:") {
			host = strings.TrimSpace(line[5:])
		}
	}

	if host == "" {
		return "", fmt.Errorf("no Host header found")
	}

	// Build URL
	scheme := "http"
	if s.Config.Args.ForceSSL {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s%s", scheme, host, reqPath)

	// Store method and post data in config
	s.Config.Args.Method = method
	if postData != "" {
		s.Config.Args.PostData = strings.TrimSpace(postData)
	}

	// Store headers
	for _, header := range headerLines {
		if strings.Contains(header, ":") {
			s.Config.Args.Header = append(s.Config.Args.Header, header)
		}
	}

	return url, nil
}

// processTarget scans a single target URL
func (s *Scanner) processTarget(targetURL string) {
	s.Stats.IncrementURLs()

	args := s.Config.Args
	postData := args.PostData

	// Check if placeholder exists in URL or POST data
	placeholder := args.Placeholder
	hasPlaceholder := strings.Contains(targetURL, placeholder) ||
		strings.Contains(postData, placeholder)

	if !hasPlaceholder {
		fmt.Printf("%s No placeholder '%s' found in target, skipping: %s\n",
			s.Colors.Yellow("[!]"), placeholder, targetURL)
		return
	}

	fmt.Printf("\n%s Testing: %s\n", s.Colors.Purple("[*]"), targetURL)

	// Add delay if specified
	if args.Delay > 0 {
		time.Sleep(time.Duration(args.Delay) * time.Millisecond)
	}

	// Create attack context
	attackCtx := &attacks.AttackContext{
		Config:    s.Config,
		HTTPCtx:   s.HTTPCtx,
		Colors:    s.Colors,
		Stats:     s.Stats,
		Verbose:   args.Verbose,
		Quick:     args.Quick,
		Encodings: s.encodings,
	}

	// Run each attack
	var wg sync.WaitGroup
	foundVuln := false
	var foundMutex sync.Mutex

	for _, attack := range s.attacks {
		if args.NoStop && foundVuln {
			continue
		}

		attack := attack // capture for goroutine
		wg.Add(1)

		go func() {
			defer wg.Done()

			if attack.Test(attackCtx, targetURL, postData) {
				foundMutex.Lock()
				foundVuln = true
				foundMutex.Unlock()
			}
		}()

		// If not parallel, wait for each attack to complete
		if !args.NoStop {
			wg.Wait()
			if foundVuln {
				break
			}
		}
	}

	wg.Wait()
}

// printSummary prints the scan summary
func (s *Scanner) printSummary() {
	fmt.Printf("\n%s Scan completed\n", s.Colors.LightBlue("[i]"))
	fmt.Printf("%s URLs tested: %d\n", s.Colors.LightBlue("[i]"), s.Stats.GetURLs())
	fmt.Printf("%s Requests made: %d (GET: %d, POST: %d)\n",
		s.Colors.LightBlue("[i]"),
		s.Stats.GetTotalRequests(),
		s.Stats.GetGetRequestCount(),
		s.Stats.GetPostRequestCount())

	vulns := s.Stats.GetVulns()
	if vulns > 0 {
		fmt.Printf("%s Vulnerabilities found: %d\n", s.Colors.Green("[+]"), vulns)
	} else {
		fmt.Printf("%s No vulnerabilities found\n", s.Colors.Yellow("[!]"))
	}

	// Print exploits if any
	exploits := s.Config.GetExploits()
	if len(exploits) > 0 {
		fmt.Printf("\n%s Exploitable vulnerabilities:\n", s.Colors.Green("[+]"))
		for i, exp := range exploits {
			fmt.Printf("  %d. [%s] %s - %s\n", i+1, exp.AttackMethod, exp.ExploitType, exp.GetVal)
		}
	}
}

// Cleanup performs cleanup operations
func (s *Scanner) Cleanup() {
	if s.HTTPServer != nil {
		s.HTTPServer.Stop()
	}
}
