package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/hansmach1ne/lfimap/internal/cli"
	"github.com/hansmach1ne/lfimap/internal/config"
	"github.com/hansmach1ne/lfimap/internal/exploit"
	"github.com/hansmach1ne/lfimap/internal/scanner"
	"github.com/hansmach1ne/lfimap/internal/util"
)

func main() {
	// Parse arguments
	args, err := cli.ParseArgs()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Initialize colors
	colors := util.NewColors(!args.NoColor)

	// Print banner
	cli.PrintBanner()

	// Validate arguments
	if err := cli.ValidateArgs(args); err != nil {
		fmt.Printf("%s %v\n", colors.Red("[-]"), err)
		os.Exit(1)
	}

	// Create config
	cfg := config.NewConfig(args)

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Create scanner
	s, err := scanner.NewScanner(cfg)
	if err != nil {
		fmt.Printf("%s Failed to create scanner: %v\n", colors.Red("[-]"), err)
		os.Exit(1)
	}

	// Handle cleanup on interrupt
	go func() {
		<-sigChan
		fmt.Printf("\n%s Interrupt received, cleaning up...\n", colors.Yellow("[!]"))
		s.Cleanup()
		os.Exit(0)
	}()

	// Run scanner
	if err := s.Run(); err != nil {
		fmt.Printf("%s Scanner error: %v\n", colors.Red("[-]"), err)
		s.Cleanup()
		os.Exit(1)
	}

	// Check for exploitation
	exploits := cfg.GetExploits()
	if len(exploits) > 0 && args.LHost != "" && args.LPort > 0 {
		fmt.Printf("\n%s Exploitation available. Attempting to get shell...\n", colors.Green("[+]"))

		exploitCtx := &exploit.ExploitContext{
			Config:    cfg,
			HTTPCtx:   s.HTTPCtx,
			Colors:    colors,
			Stats:     s.Stats,
			Encodings: []string{},
		}

		// Try to exploit the first suitable vulnerability
		for _, exp := range exploits {
			if exp.AttackMethod == "INPUT" || exp.AttackMethod == "DATA" ||
				exp.AttackMethod == "EXPECT" || exp.AttackMethod == "CMD" ||
				exp.AttackMethod == "TRUNC" || exp.AttackMethod == "RFI" {
				exploit.Pwn(exploitCtx, exp)
				break
			}
		}
	}

	// Cleanup
	s.Cleanup()

	// Exit with appropriate code
	if s.Stats.GetVulns() > 0 {
		os.Exit(0)
	} else {
		os.Exit(1)
	}
}
