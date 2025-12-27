package config

import (
	"net/http"
	"sync"
	"time"
)

// Exploit represents a discovered vulnerability
type Exploit struct {
	RequestType  string
	ExploitType  string
	GetVal       string
	PostVal      string
	Headers      http.Header
	AttackMethod string
	OS           string
}

// Config holds the global configuration state
type Config struct {
	mu sync.RWMutex

	// Runtime state
	CheckedHosts   []string
	Exploits       []Exploit
	Proxies        map[string]string
	RFITestPort    int
	Timeout        time.Duration
	InitialReqTime time.Time
	ScriptName     string
	TempArg        string
	WebDir         string
	SkipSQLi       bool
	PreviousPrint  string
	URLs           []string
	ParsedURLs     []string
	MaxTimeout     time.Duration
	FollowRedirect bool
	PostReq        string
	URL            string

	// Arguments (set from CLI)
	Args *Arguments
}

// Arguments holds all CLI arguments
type Arguments struct {
	// Target options
	URL         string
	URLFile     string
	RequestFile string

	// Request options
	Cookie      string
	PostData    string
	Header      []string
	Method      string
	Proxy       string
	UserAgent   string
	Referer     string
	Placeholder string
	Delay       int
	MaxTimeout  int
	HTTPValid   []int

	// CSRF options
	CSRFParam  string
	CSRFMethod string
	CSRFURL    string
	CSRFData   string

	// Second-order options
	SecondMethod string
	SecondURL    string
	SecondData   string

	// Flags
	ForceSSL   bool
	NoStop     bool
	NoRedirect bool

	// Attack options
	TestFilter bool
	TestInput  bool
	TestData   bool
	TestExpect bool
	TestTrunc  bool
	TestRFI    bool
	TestCMD    bool
	TestFile   bool
	TestHeur   bool
	TestAll    bool

	// Payload options
	Encode   int
	Quick    bool
	RevShell bool
	LHost    string
	LPort    int
	Callback string

	// Wordlist options
	TruncWordlist string
	UseLong       bool

	// Output options
	Log     string
	Verbose bool
	NoColor bool

	// Internal
	ScriptDirectory     string
	UpdateCSRFToken     bool
	PreviousCSRF        string
	PreviousRes         *http.Response
	IsTestedParamPost   bool
	ParsedHeaders       map[string]string
	PostReq             []string
	HTTPHeaders         map[string]string
}

// NewConfig creates a new configuration with defaults
func NewConfig(args *Arguments) *Config {
	if args == nil {
		args = &Arguments{
			Placeholder: "PWN",
			HTTPValid:   []int{200, 204, 301, 302, 303},
		}
	}
	return &Config{
		RFITestPort: 8000,
		Proxies:     make(map[string]string),
		Args:        args,
		TempArg:     args.Placeholder,
	}
}

// NewDefaultConfig creates a config with default arguments
func NewDefaultConfig() *Config {
	return NewConfig(nil)
}

// AddExploit safely adds an exploit to the list
func (c *Config) AddExploit(e Exploit) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Exploits = append(c.Exploits, e)
}

// GetExploits safely returns all exploits
func (c *Config) GetExploits() []Exploit {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]Exploit{}, c.Exploits...)
}

// CSRFParams contains common CSRF parameter names
var CSRFParams = []string{
	"csrf",
	"xsrf",
	"csrfmiddlewaretoken",
	"RequestVerificationToken",
	"_RequestVerificationToken",
	"antiForgeryToken",
	"authenticity_token",
	"csrf_token",
	"_csrf",
	"_xsrf",
	"_csrf_token",
	"_xsrf_token",
}

// ToReplace contains payload signatures for success detection (ordered by complexity)
var ToReplace = []string{
	"Windows/System32/drivers/etc/hosts",
	"C%3A%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts",
	"file://C:\\Windows\\System32\\drivers\\etc\\hosts",
	"%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts",
	"C:\\Windows\\System32\\drivers\\etc\\hosts",
	"Windows\\System32\\drivers\\etc\\hosts",
	"%windir%\\System32\\drivers\\etc\\hosts",
	"file%3A%2F%2F%2Fetc%2Fpasswd%2500",
	"file%3A%2F%2F%2Fetc%2Fpasswd",
	"cat%24%7BIFS%7D%2Fetc%2Fpasswd",
	"cat%24IFS%2Fetc%2Fpasswd",
	"cat${IFS%??}/etc/passwd",
	"/sbin/cat%20/etc/passwd",
	"/sbin/cat /etc/passwd",
	"cat%20%2Fetc%2Fpasswd",
	"cat${IFS}/etc/passwd",
	"cat /etc/passwd",
	"%2Fetc%2Fpasswd",
	"/etc/passwd",
	"ysvznc",
	"ipconfig",
}

// KeyWords contains indicators of successful exploitation
var KeyWords = []string{
	"root:x:0:0",
	"<IMG sRC=X onerror=jaVaScRipT:alert`xss`>",
	"<img src=x onerror=javascript:alert`xss`>",
	"cm9vdDp4OjA",
	"Ond3dy1kYX",
	"ebbg:k:0:0",
	"d3d3LWRhdG",
	`aahgpz"ptz>e<atzf`,
	"jjj-qngn:k",
	"daemon:x:1:",
	"r o o t : x : 0 : 0",
	"ZGFlbW9uOng6",
	"; for 16-bit app support",
	"sample HOSTS file used by Microsoft",
	"iBvIG8gdCA6IHggOiA",
	"OyBmb3IgMTYtYml0IGFwcCBzdXBw",
	"c2FtcGxlIEhPU1RTIGZpbGUgIHVzZWQgYnkgTWljcm9zb2",
	"Windows IP Configuration",
	"OyBmb3IgMT",
	"; sbe 16-ovg ncc fhccbeg",
	"fnzcyr UBFGF svyr hfrq ol Zvpebfbsg",
	";  f o r  1 6 - b i t  a p p",
	"c2FtcGxlIEhPU1RT",
	"=1943785348b45",
	"www-data:x",
	"PD9w",
	"961bb08a95dbc34397248d92352da799",
	"PCFET0NUWVBFIGh0b",
	"PCFET0N",
	"PGh0b",
}

// TempArgCandidates for finding unused placeholder
var TempArgCandidates = []string{"CMD", "TEMP", "LFIMAP", "LFI"}
