package util

import (
	"fmt"
	"runtime"
)

// Colors provides colored terminal output
type Colors struct {
	NoColors bool
}

// NewColors creates a new Colors instance
func NewColors(noColors bool) *Colors {
	return &Colors{NoColors: noColors}
}

const (
	reset     = "\033[0m"
	green     = "\033[92m"
	red       = "\033[91m"
	blue      = "\033[94m"
	yellow    = "\033[93m"
	purple    = "\033[95m"
	lightBlue = "\033[1;36m"
)

func init() {
	// Enable ANSI on Windows
	if runtime.GOOS == "windows" {
		// Windows 10+ supports ANSI by default
	}
}

// Green returns text in green color
func (c *Colors) Green(text string) string {
	if c.NoColors {
		return text
	}
	return green + text + reset
}

// Red returns text in red color
func (c *Colors) Red(text string) string {
	if c.NoColors {
		return text
	}
	return red + text + reset
}

// Blue returns text in blue color
func (c *Colors) Blue(text string) string {
	if c.NoColors {
		return text
	}
	return blue + text + reset
}

// Yellow returns text in yellow color
func (c *Colors) Yellow(text string) string {
	if c.NoColors {
		return text
	}
	return yellow + text + reset
}

// Purple returns text in purple color
func (c *Colors) Purple(text string) string {
	if c.NoColors {
		return text
	}
	return purple + text + reset
}

// LightBlue returns text in light blue color
func (c *Colors) LightBlue(text string) string {
	if c.NoColors {
		return text
	}
	return lightBlue + text + reset
}

// Info prints an info message with [i] prefix
func (c *Colors) Info(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s %s\n", c.LightBlue("[i]"), msg)
}

// Success prints a success message with [+] prefix
func (c *Colors) Success(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s %s\n", c.Green("[+]"), msg)
}

// Error prints an error message with [-] prefix
func (c *Colors) Error(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s %s\n", c.Red("[-]"), msg)
}

// Warning prints a warning message with [!] prefix
func (c *Colors) Warning(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s %s\n", c.Yellow("[!]"), msg)
}

// Question prints a question message with [?] prefix
func (c *Colors) Question(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s %s\n", c.Purple("[?]"), msg)
}

// Status prints a status message with [.] prefix
func (c *Colors) Status(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s %s\n", c.Green("[.]"), msg)
}
