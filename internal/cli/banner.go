package cli

import "fmt"

// Banner returns the ASCII art banner
func Banner() string {
	return `
  _      ______ _____
 | |    |  ____|_   _|
 | |    | |__    | |  _ __ ___   __ _ _ __
 | |    |  __|   | | | '_ ` + "`" + ` _ \ / _` + "`" + ` | '_ \
 | |____| |     _| |_| | | | | | (_| | |_) |
 |______|_|    |_____|_| |_| |_|\__,_| .__/
                                     | |
                                     |_|

                                - by @h4nsmach1ne
`
}

// PrintBanner prints the banner
func PrintBanner() {
	fmt.Println(Banner())
}
