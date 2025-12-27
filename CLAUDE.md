# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

LFImap is a Python-based security testing tool for discovering and exploiting Local File Inclusion (LFI) vulnerabilities in web applications. Despite the repository name containing "go", this is a pure Python project.

**Status:** Pre-alpha (v0.1.4), major release 1.0 planned

## Build and Development Commands

```bash
# Install for development
pip install -e .

# Run directly without installation
python3 lfimap/lfimap.py -h

# Run tests
pytest lfimap/src/tests/test_tests.py -v

# Run a single test
pytest lfimap/src/tests/test_tests.py::test_test_rfi -v
```

## Architecture

### Entry Point
- `lfimap/lfimap.py::main()` - CLI orchestrator that validates args, loads URLs, and runs attack modules

### Core Flow
1. `checkArgs()` validates CLI parameters
2. `init_args()` initializes argument dictionary (cached globally in `src.utils.arguments.args`)
3. URLs loaded from `-U`, `-F`, or `-R` flags
4. `prepareRequest()` injects payloads at parameter locations (default marker: `PWN`)
5. Attack modules execute via `REQUEST()` function
6. `checkPayload()` validates successful exploitation

### Key Modules

**Attack Modules** (`lfimap/src/attacks/`):
- Each follows pattern: `test_[type](url, post_data)` returns when exploitation found
- `filter.py`, `input.py`, `data.py`, `expect.py` - PHP wrapper attacks
- `file.py` - File wrapper attacks
- `trunc.py` - Path traversal with wordlists
- `rfi.py` - Remote File Inclusion
- `cmdi.py` - Command injection
- `heur.py` - Heuristic tests (XSS, CRLF, open redirect)
- `pwn.py` - Response validation for successful exploitation

**HTTP Handling** (`lfimap/src/httpreqs/`):
- `request.py` - Core request/response logic, `prepareRequest()`, `REQUEST()`
- `get.py`, `post.py` - Method-specific handling

**Configuration** (`lfimap/src/configs/config.py`):
- Global state: `checkedHosts`, `exploits`, `proxies`
- `KEY_WORDS` - Indicators of successful exploitation (e.g., `root:x:0:0`)
- `csrf_params` - Common CSRF token parameter names

**Utilities** (`lfimap/src/utils/`):
- `arguments.py` - CLI argument parsing with argparse
- `stats.py` - Global statistics tracking (`requests`, `vulns`, `urls`)
- `colors.py` - Terminal colored output prefixes: `[i]` info, `[+]` success, `[-]` failure

### Testing Pattern
Tests spawn a mock HTTP server on 127.0.0.1:8080 with marker-based responses. Test files use `custom_init_args()` to configure the argument dictionary directly.

### Payloads
- Stored URL-encoded in attack modules
- Additional encoding via `-n U` (URL) or `-n B` (Base64)
- RFI markers: `ysvznc.php`, `ysvznc.jsp`, etc. in `src/exploits/`
- Wordlists in `src/wordlists/` (short.txt default, long.txt extended)

## Important Patterns

- Global argument caching: `init_args()` stores in `src.utils.arguments.args`
- Quick mode (`-q`): Returns after first successful test per attack type
- `--no-stop`: Continues testing same technique after findings
- Default attacks (no flags): filter, input, data, expect, file, RFI, truncation (not cmd/heuristics)
