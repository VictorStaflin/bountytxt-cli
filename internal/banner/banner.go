package banner

import (
	"fmt"
	"runtime"
)

// ANSI color codes
const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Purple = "\033[35m"
	Cyan   = "\033[36m"
	White  = "\033[37m"
	Bold   = "\033[1m"
	Dim    = "\033[2m"
)

// Version information
const (
	Version = "1.0.0"
	Build   = "Prod"
)

// ASCII art banner
const asciiArt = `
    ██████╗ ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗████████╗██╗  ██╗████████╗
    ██╔══██╗██╔══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝╚══██╔══╝╚██╗██╔╝╚══██╔══╝
    ██████╔╝██████╔╝██║   ██║██╔██╗ ██║   ██║    ╚████╔╝    ██║    ╚███╔╝    ██║
    ██╔══██╗██╔══██╗██║   ██║██║╚██╗██║   ██║     ╚██╔╝     ██║    ██╔██╗    ██║
    ██████╔╝██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║      ██║   ██╔╝ ██╗   ██║
    ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝      ╚═╝   ╚═╝  ╚═╝   ╚═╝

         ██████╗██╗     ██╗    ████████╗ ██████╗  ██████╗ ██╗
        ██╔════╝██║     ██║    ╚══██╔══╝██╔═══██╗██╔═══██╗██║
        ██║     ██║     ██║       ██║   ██║   ██║██║   ██║██║
        ██║     ██║     ██║       ██║   ██║   ██║██║   ██║██║
        ╚██████╗███████╗██║       ██║   ╚██████╔╝╚██████╔╝███████╗
         ╚═════╝╚══════╝╚═╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
`

// GetBanner returns the complete colored banner
func GetBanner() string {
	if !supportsColor() {
		return getPlainBanner()
	}
	return getColoredBanner()
}

// GetPlainBanner returns the banner without colors (for non-color terminals)
func getPlainBanner() string {
	return fmt.Sprintf(`%s

    +-----------------------------------------------------------------+
    |  RFC 9116 Security.txt Validator & Discovery Tool               |
    |  Secure by Design • Validate • Discover • Analyze               |
    +-----------------------------------------------------------------+

    Version: %s | Build: %s | Go: %s
    
    Use --help for available commands and options.
    
`, asciiArt, Version, Build, runtime.Version())
}

// GetColoredBanner returns the banner with full colors
func getColoredBanner() string {
	coloredArt := Cyan + Bold + asciiArt + Reset

	versionInfo := fmt.Sprintf("%s%sVersion:%s %s%s | %sBuild:%s %s%s | %sGo:%s %s",
		Dim, White, Reset, Green, Version,
		Dim, White, Reset, Yellow, Build,
		Dim, runtime.Version())

	tagline := fmt.Sprintf("%s%sRFC 9116 Security.txt Validator & Discovery Tool%s",
		Bold, Green, Reset)

	subtitle := fmt.Sprintf("%s%sSecure by Design - Validate - Discover - Analyze%s",
		Bold, Cyan, Reset)

	helpText := fmt.Sprintf("%s%sUse --help for available commands and options.%s",
		Dim, White, Reset)

	border := fmt.Sprintf("%s%s┌─────────────────────────────────────────────────────────────────────┐%s",
		Dim, Purple, Reset)
	borderBottom := fmt.Sprintf("%s%s└─────────────────────────────────────────────────────────────────────┘%s",
		Dim, Purple, Reset)

	return fmt.Sprintf(`%s

%s
    │  %s        │
    │  %s        │
%s

    %s
    
    %s
    
`, coloredArt, border, tagline, subtitle, borderBottom, versionInfo, helpText)
}

// supportsColor checks if the terminal supports color output
func supportsColor() bool {
	// On Windows, check if we're in a modern terminal
	if runtime.GOOS == "windows" {
		// Modern Windows terminals support ANSI colors
		return true
	}
	return true
}

// PrintBanner prints the banner to stdout
func PrintBanner() {
	fmt.Print(GetBanner())
}
