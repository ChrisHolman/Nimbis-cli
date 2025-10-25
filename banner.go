package main

import (
	"fmt"
	"math/rand"
	"time"
)

// ANSI color codes
const (
	Reset       = "\033[0m"
	Bold        = "\033[1m"
	Dim         = "\033[2m"
	
	Red         = "\033[31m"
	Green       = "\033[32m"
	Yellow      = "\033[33m"
	Blue        = "\033[34m"
	Magenta     = "\033[35m"
	Cyan        = "\033[36m"
	White       = "\033[37m"
	
	BrightRed     = "\033[91m"
	BrightGreen   = "\033[92m"
	BrightYellow  = "\033[93m"
	BrightBlue    = "\033[94m"
	BrightMagenta = "\033[95m"
	BrightCyan    = "\033[96m"
	BrightWhite   = "\033[97m"
	
	BgBlack   = "\033[40m"
	BgRed     = "\033[41m"
	BgGreen   = "\033[42m"
	BgYellow  = "\033[43m"
	BgBlue    = "\033[44m"
	BgMagenta = "\033[45m"
	BgCyan    = "\033[46m"
	BgWhite   = "\033[47m"
)

var bannerVariants = []string{
	// Variant 1 - Big block letters
	`
    ███╗   ██╗██╗███╗   ███╗██████╗ ██╗███████╗
    ████╗  ██║██║████╗ ████║██╔══██╗██║██╔════╝
    ██╔██╗ ██║██║██╔████╔██║██████╔╝██║███████╗
    ██║╚██╗██║██║██║╚██╔╝██║██╔══██╗██║╚════██║
    ██║ ╚████║██║██║ ╚═╝ ██║██████╔╝██║███████║
    ╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝╚═════╝ ╚═╝╚══════╝
`,
	// Variant 2 - Sleek modern
	`
    ███╗   ██╗ ██╗ ███╗   ███╗ ██████╗  ██╗ ███████╗
    ████╗  ██║ ██║ ████╗ ████║ ██╔══██╗ ██║ ██╔════╝
    ██╔██╗ ██║ ██║ ██╔████╔██║ ██████╔╝ ██║ ███████╗
    ██║╚██╗██║ ██║ ██║╚██╔╝██║ ██╔══██╗ ██║ ╚════██║
    ██║ ╚████║ ██║ ██║ ╚═╝ ██║ ██████╔╝ ██║ ███████║
    ╚═╝  ╚═══╝ ╚═╝ ╚═╝     ╚═╝ ╚═════╝  ╚═╝ ╚══════╝
`,
	// Variant 3 - Simple bold
	`
    ███    ██ ██ ███    ███ ██████  ██ ███████ 
    ████   ██ ██ ████  ████ ██   ██ ██ ██      
    ██ ██  ██ ██ ██ ████ ██ ██████  ██ ███████ 
    ██  ██ ██ ██ ██  ██  ██ ██   ██ ██      ██ 
    ██   ████ ██ ██      ██ ██████  ██ ███████ 
`,
}

var taglines = []string{
	"Security Scanning in the Cloud",
	"Comprehensive Code Security Analysis",
	"IaC • Secrets • SAST • SCA • SBOM",
	"Your Security Copilot",
	"Nimble Security at Scale",
	"Scan Fast, Sleep Well",
	"Zero-Trust Security Scanning",
}

// PrintBanner displays the animated banner
func PrintBanner() {
	// Clear screen
	fmt.Print("\033[2J\033[H")
	
	// Select random banner variant
	banner := bannerVariants[rand.Intn(len(bannerVariants))]
	tagline := taglines[rand.Intn(len(taglines))]
	
	// Print banner with gradient effect
	lines := splitLines(banner)
	colors := []string{BrightCyan, Cyan, BrightBlue, Blue, Magenta}
	
	for i, line := range lines {
		color := colors[i%len(colors)]
		fmt.Printf("%s%s%s\n", color, line, Reset)
		time.Sleep(30 * time.Millisecond)
	}
	
	// Print version and tagline
	fmt.Printf("\n%s%s                    v%s%s\n", Dim, White, version, Reset)
	fmt.Printf("%s%s        %s%s\n\n", Bold, BrightWhite, tagline, Reset)
	
	// Loading animation
	printLoadingAnimation()
}

// PrintCompactBanner shows a smaller banner for quiet mode
func PrintCompactBanner() {
	fmt.Printf("\n%s%s╔═══════════════════════════════════════╗%s\n", Bold, BrightCyan, Reset)
	fmt.Printf("%s%s║   NIMBIS v%-6s Security Scanner   ║%s\n", Bold, BrightCyan, version, Reset)
	fmt.Printf("%s%s╚═══════════════════════════════════════╝%s\n\n", Bold, BrightCyan, Reset)
}

// printLoadingAnimation shows a brief loading animation
func printLoadingAnimation() {
	spinners := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	messages := []string{
		"Initializing security engines",
		"Loading threat intelligence",
		"Preparing scan environment",
	}
	
	for _, msg := range messages {
		for i := 0; i < 8; i++ {
			spinner := spinners[i%len(spinners)]
			fmt.Printf("\r%s%s%s %s%s", BrightCyan, spinner, Reset, Dim, msg)
			time.Sleep(50 * time.Millisecond)
		}
		fmt.Printf("\r%s✓%s %s\n", BrightGreen, Reset, msg)
	}
	
	fmt.Println()
}

// PrintScanStart prints the scan start header
func PrintScanStart(target string) {
	fmt.Printf("%s%s┌─────────────────────────────────────────────────────────┐%s\n", Bold, BrightCyan, Reset)
	fmt.Printf("%s%s│  SCAN INITIATED%s                                          │\n", Bold, BrightCyan, Reset)
	fmt.Printf("%s%s├─────────────────────────────────────────────────────────┤%s\n", Bold, BrightCyan, Reset)
	fmt.Printf("%s%s│%s  Target:  %s%-44s%s %s│%s\n", Bold, BrightCyan, Reset, BrightWhite, truncateBanner(target, 44), Reset, BrightCyan, Reset)
	fmt.Printf("%s%s│%s  Time:    %s%-44s%s %s│%s\n", Bold, BrightCyan, Reset, BrightWhite, time.Now().Format("2006-01-02 15:04:05"), Reset, BrightCyan, Reset)
	fmt.Printf("%s%s└─────────────────────────────────────────────────────────┘%s\n\n", Bold, BrightCyan, Reset)
}

// PrintScanProgress prints scanner progress with styling
func PrintScanProgress(scannerName string, status string, findings int) {
	var statusColor, statusIcon string
	
	switch status {
	case "running":
		statusColor = BrightYellow
		statusIcon = "▶"
	case "completed":
		statusColor = BrightGreen
		statusIcon = "✓"
	case "failed":
		statusColor = BrightRed
		statusIcon = "✗"
	case "skipped":
		statusColor = Yellow
		statusIcon = "⊘"
	default:
		statusColor = White
		statusIcon = "•"
	}
	
	findingsStr := ""
	if status == "completed" && findings > 0 {
		findingsStr = fmt.Sprintf(" %s(%d findings)%s", Dim, findings, Reset)
	}
	
	fmt.Printf("  %s%s%s %s%-30s%s%s\n", statusColor, statusIcon, Reset, scannerName, findingsStr, Reset, "")
}

// PrintSectionHeader prints a section header
func PrintSectionHeader(title string) {
	fmt.Printf("\n%s%s┌─ %s ──────────────────────────────────────────────────┐%s\n", Bold, BrightCyan, title, Reset)
}

// PrintSectionFooter prints a section footer
func PrintSectionFooter() {
	fmt.Printf("%s%s└───────────────────────────────────────────────────────────┘%s\n", Bold, BrightCyan, Reset)
}

// PrintFinding prints a formatted finding
func PrintFinding(severity, title, location, remediation string) {
	// Severity emoji and color
	var severityColor, emoji string
	switch severity {
	case SeverityCritical:
		severityColor = BrightRed
		emoji = "🔴"
	case SeverityHigh:
		severityColor = Red
		emoji = "🟠"
	case SeverityMedium:
		severityColor = Yellow
		emoji = "🟡"
	case SeverityLow:
		severityColor = Green
		emoji = "🟢"
	default:
		severityColor = White
		emoji = "⚪"
	}
	
	fmt.Printf("\n   %s %s%s%-8s%s %s%s%s\n", emoji, Bold, severityColor, severity, Reset, BrightWhite, title, Reset)
	
	if location != "" {
		fmt.Printf("      %s📍 %s%s\n", Dim, location, Reset)
	}
	
	if remediation != "" {
		fmt.Printf("      %s💡 %s%s\n", Dim, remediation, Reset)
	}
}

// PrintSummaryBox prints a styled summary box
func PrintSummaryBox(title string, stats map[string]interface{}) {
	fmt.Printf("\n%s%s╔════════════════════════════════════════════════════════╗%s\n", Bold, BrightCyan, Reset)
	fmt.Printf("%s%s║  %s%-50s%s  ║%s\n", Bold, BrightCyan, title, "", BrightCyan, Reset)
	fmt.Printf("%s%s╠════════════════════════════════════════════════════════╣%s\n", Bold, BrightCyan, Reset)
	
	for key, value := range stats {
		fmt.Printf("%s%s║%s  %-25s %s%-25v%s  %s║%s\n", Bold, BrightCyan, Reset, key+":", BrightWhite, value, Reset, BrightCyan, Reset)
	}
	
	fmt.Printf("%s%s╚════════════════════════════════════════════════════════╝%s\n", Bold, BrightCyan, Reset)
}

// PrintSuccess prints a success message
func PrintSuccess(message string) {
	fmt.Printf("\n%s%s✓%s %s\n", Bold, BrightGreen, Reset, message)
}

// PrintWarning prints a warning message
func PrintWarning(message string) {
	fmt.Printf("\n%s%s⚠%s %s\n", Bold, BrightYellow, Reset, message)
}

// PrintError prints an error message
func PrintError(message string) {
	fmt.Printf("\n%s%s✗%s %s\n", Bold, BrightRed, Reset, message)
}

// PrintInfo prints an info message
func PrintInfo(message string) {
	fmt.Printf("%s%sℹ%s %s\n", Bold, BrightBlue, Reset, message)
}

// splitLines splits a string into lines
func splitLines(s string) []string {
	lines := []string{}
	current := ""
	
	for _, ch := range s {
		if ch == '\n' {
			if current != "" {
				lines = append(lines, current)
			}
			current = ""
		} else {
			current += string(ch)
		}
	}
	
	if current != "" {
		lines = append(lines, current)
	}
	
	return lines
}

// ColorSeverity returns colored severity text
func ColorSeverity(severity string) string {
	switch severity {
	case SeverityCritical:
		return fmt.Sprintf("%s%s%s%s", Bold, BrightRed, severity, Reset)
	case SeverityHigh:
		return fmt.Sprintf("%s%s%s%s", Bold, Red, severity, Reset)
	case SeverityMedium:
		return fmt.Sprintf("%s%s%s%s", Bold, Yellow, severity, Reset)
	case SeverityLow:
		return fmt.Sprintf("%s%s%s%s", Bold, Green, severity, Reset)
	default:
		return severity
	}
}

// truncateBanner truncates a string for banner display
func truncateBanner(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
