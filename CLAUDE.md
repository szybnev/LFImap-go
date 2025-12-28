# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

LFImap is a Go-based security testing tool for discovering and exploiting Local File Inclusion (LFI) vulnerabilities in web applications.

## Build and Development Commands

```bash
# Build the binary
go build ./cmd/lfimap

# Run directly without building
go run ./cmd/lfimap -h

# Run tests
go test ./...

# Run a specific package's tests
go test ./internal/attacks -v

# Install globally
go install ./cmd/lfimap
```

## Architecture

### Entry Point
- `cmd/lfimap/main.go` - CLI entry point that parses args, creates scanner, and runs attacks

### Core Flow
1. `cli.ParseArgs()` parses CLI arguments using Cobra
2. `cli.ValidateArgs()` validates the parsed arguments
3. `config.NewConfig()` creates configuration from arguments
4. `scanner.NewScanner()` creates the scanner with HTTP client and attack modules
5. `scanner.Run()` loads targets and runs registered attacks
6. `exploit.Pwn()` attempts exploitation if vulnerabilities found with --exploit flag

### Key Packages

**cmd/lfimap/** - Entry point
- `main.go` - CLI orchestration, signal handling, scanner invocation

**internal/config/** - Configuration
- `config.go` - Config struct, Arguments, KeyWords for detection, ToReplace for payload signatures

**internal/cli/** - CLI handling
- `arguments.go` - Cobra-based argument parsing (40+ flags)
- `banner.go` - ASCII banner display

**internal/http/** - HTTP handling
- `client.go` - HTTP client with proxy support (HTTP/HTTPS/SOCKS5)
- `headers.go` - User-Agent rotation, header management
- `request.go` - Core request/response handling, CSRF support, logging
- `response.go` - Payload detection via KeyWords matching

**internal/attacks/** - Attack modules
- `attack.go` - Attack interface definition
- `filter.go` - PHP filter wrapper (11 payloads)
- `input.go` - PHP input wrapper (POST/GET modes)
- `data.go` - PHP data wrapper with base64
- `expect.go` - PHP expect wrapper (Linux/Windows)
- `file.go` - File wrapper (4 payloads with null byte)
- `trunc.go` - Path truncation with wordlist
- `rfi.go` - Remote file inclusion (local/internet/callback modes)
- `cmdi.go` - Command injection with IFS bypass
- `heuristics.go` - XSS, CRLF, info disclosure, open redirect

**internal/exploit/** - Exploitation
- `pwn.go` - Reverse shell orchestration (bash, nc, PHP, Perl, PowerShell)

**internal/servers/** - Supporting servers
- `httpserver.go` - HTTP server for RFI payload hosting
- `listener.go` - TCP listener for reverse shell connections

**internal/scanner/** - Scanner orchestration
- `scanner.go` - Target loading, attack registration and execution

**internal/util/** - Utilities
- `colors.go` - Terminal color output with ANSI codes
- `encoding.go` - Base64 and URL encoding utilities
- `parseurl.go` - URL parsing and parameter injection
- `stats.go` - Thread-safe statistics tracking
- `cleanup.go` - Resource cleanup utilities

**resources/** - Embedded resources
- `embed.go` - go:embed directives for wordlists and exploits
- `wordlists/` - Path traversal wordlists (short.txt, long.txt)
- `exploits/` - RFI payload files

### Testing Pattern
Tests use `go test` with the standard testing package. Mock HTTP servers can be created using `net/http/httptest`.

### Key Patterns

- **Context-based configuration**: Config passed through RequestContext instead of globals
- **Thread safety**: sync.RWMutex for statistics and exploit tracking
- **Embedded resources**: go:embed for wordlists and exploit files
- **Attack interface**: All attacks implement the Attack interface with Test() method
- **Placeholder injection**: Default "PWN" marker replaced with payloads
- **Payload detection**: 30+ keywords in KeyWords slice for success detection
- **Quick mode** (`-q`): Returns after first successful test per attack type
- **NoStop mode** (`--no-stop`): Continues testing same technique after findings
