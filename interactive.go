package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// RunInteractiveMode starts the interactive Metasploit-style interface
func RunInteractiveMode() error {
	PrintBanner()
	PrintWelcomeMessage()

	reader := bufio.NewReader(os.Stdin)

	for {
		// Main prompt
		fmt.Printf("\n%s%snimbis%s%s>%s ", Bold, BrightCyan, Reset, BrightGreen, Reset)

		input, err := reader.ReadString('\n')
		if err != nil {
			return err
		}

		input = strings.TrimSpace(input)

		// Handle commands
		switch strings.ToLower(input) {
		case "scan", "s":
			if err := runInteractiveScan(reader); err != nil {
				PrintError(fmt.Sprintf("Scan failed: %v", err))
			}
		case "help", "h", "?":
			printInteractiveHelp()
		case "exit", "quit", "q":
			fmt.Printf("\n%s%s[*]%s Exiting Nimbis. Stay secure!\n\n", Bold, BrightCyan, Reset)
			return nil
		case "":
			continue
		default:
			PrintWarning(fmt.Sprintf("Unknown command: %s (type 'help' for available commands)", input))
		}
	}
}

// PrintWelcomeMessage displays the welcome message
func PrintWelcomeMessage() {
	fmt.Printf("%s%s╔═══════════════════════════════════════════════════════════════╗%s\n", Bold, BrightCyan, Reset)
	fmt.Printf("%s%s║%s  Welcome to Nimbis - Nimble Security at Scale               %s║%s\n", Bold, BrightCyan, Reset, BrightCyan, Reset)
	fmt.Printf("%s%s║%s  Multi-Scanner Security Orchestration Platform               %s║%s\n", Bold, BrightCyan, Reset, BrightCyan, Reset)
	fmt.Printf("%s%s╠═══════════════════════════════════════════════════════════════╣%s\n", Bold, BrightCyan, Reset)
	fmt.Printf("%s%s║%s  Type 'scan' to start a security scan                        %s║%s\n", Bold, BrightCyan, Reset, BrightCyan, Reset)
	fmt.Printf("%s%s║%s  Type 'help' for available commands                          %s║%s\n", Bold, BrightCyan, Reset, BrightCyan, Reset)
	fmt.Printf("%s%s║%s  Type 'exit' to quit                                          %s║%s\n", Bold, BrightCyan, Reset, BrightCyan, Reset)
	fmt.Printf("%s%s╚═══════════════════════════════════════════════════════════════╝%s\n", Bold, BrightCyan, Reset)
}

// printInteractiveHelp displays available commands
func printInteractiveHelp() {
	fmt.Printf("\n%s%sAvailable Commands:%s\n", Bold, BrightWhite, Reset)
	fmt.Printf("  %sscan%s, %ss%s       - Start a new security scan\n", BrightCyan, Reset, BrightCyan, Reset)
	fmt.Printf("  %shelp%s, %sh%s, %s?%s   - Show this help message\n", BrightCyan, Reset, BrightCyan, Reset, BrightCyan, Reset)
	fmt.Printf("  %sexit%s, %squit%s, %sq%s - Exit Nimbis\n", BrightCyan, Reset, BrightCyan, Reset, BrightCyan, Reset)
}

// runInteractiveScan runs an interactive scan workflow
func runInteractiveScan(reader *bufio.Reader) error {
	fmt.Printf("\n%s%s[*]%s Starting interactive scan setup...\n", Bold, BrightCyan, Reset)

	// Step 1: Get target
	target := promptForTarget(reader)
	if target == "" {
		PrintWarning("Scan cancelled")
		return nil
	}

	// Step 2: Get scan types
	scanTypes := promptForScanTypes(reader)
	if scanTypes == nil {
		PrintWarning("Scan cancelled")
		return nil
	}

	// Step 3: Get severity
	severity := promptForSeverity(reader)
	if severity == "" {
		PrintWarning("Scan cancelled")
		return nil
	}

	// Step 4: Additional options
	outputFile := promptForOutputFile(reader)

	// Step 5: Confirm and run
	fmt.Printf("\n%s%s╔═══════════════════════════════════════════════════════════════╗%s\n", Bold, BrightYellow, Reset)
	fmt.Printf("%s%s║%s  SCAN CONFIGURATION                                           %s║%s\n", Bold, BrightYellow, Reset, BrightYellow, Reset)
	fmt.Printf("%s%s╠═══════════════════════════════════════════════════════════════╣%s\n", Bold, BrightYellow, Reset)
	fmt.Printf("%s%s║%s  Target:         %-45s%s║%s\n", Bold, BrightYellow, Reset, truncateBanner(target, 45), BrightYellow, Reset)
	fmt.Printf("%s%s║%s  Scan Types:     %-45s%s║%s\n", Bold, BrightYellow, Reset, formatScanTypes(scanTypes), BrightYellow, Reset)
	fmt.Printf("%s%s║%s  Min Severity:   %-45s%s║%s\n", Bold, BrightYellow, Reset, severity, BrightYellow, Reset)
	if outputFile != "" {
		fmt.Printf("%s%s║%s  Output File:    %-45s%s║%s\n", Bold, BrightYellow, Reset, truncateBanner(outputFile, 45), BrightYellow, Reset)
	}
	fmt.Printf("%s%s╚═══════════════════════════════════════════════════════════════╝%s\n", Bold, BrightYellow, Reset)

	fmt.Printf("\n%s%s[?]%s Proceed with scan? (Y/n): ", Bold, BrightYellow, Reset)
	confirm, _ := reader.ReadString('\n')
	confirm = strings.TrimSpace(strings.ToLower(confirm))

	if confirm != "" && confirm != "y" && confirm != "yes" {
		PrintWarning("Scan cancelled")
		return nil
	}

	// Create config and run scan
	config := &ScanConfig{
		TargetPath:     target,
		OutputFormat:   "json",
		OutputFile:     outputFile,
		MinSeverity:    severity,
		FailOnSeverity: "CRITICAL",
		Parallel:       true,
		Verbose:        false,
		AutoInstall:    false,
		Quiet:          false,
		ScanTypes:      *scanTypes,
	}

	fmt.Printf("\n%s%s[*]%s Initiating scan...\n", Bold, BrightGreen, Reset)

	scanner := NewScanner(config)
	if err := scanner.Run(); err != nil {
		// Don't return error, just display it
		fmt.Printf("\n%s%s[!]%s %v\n", Bold, BrightRed, Reset, err)
	}

	fmt.Printf("\n%s%s[*]%s Scan complete!\n", Bold, BrightGreen, Reset)

	return nil
}

// promptForTarget prompts user for scan target
func promptForTarget(reader *bufio.Reader) string {
	fmt.Printf("\n%s%s╔═══════════════════════════════════════════════════════════════╗%s\n", Bold, BrightCyan, Reset)
	fmt.Printf("%s%s║%s  STEP 1: TARGET SELECTION                                     %s║%s\n", Bold, BrightCyan, Reset, BrightCyan, Reset)
	fmt.Printf("%s%s╚═══════════════════════════════════════════════════════════════╝%s\n", Bold, BrightCyan, Reset)

	fmt.Printf("\n%sExamples:%s\n", Bold, Reset)
	fmt.Printf("  • Current directory:  %s.%s\n", BrightCyan, Reset)
	fmt.Printf("  • Specific path:      %s/path/to/project%s\n", BrightCyan, Reset)
	fmt.Printf("  • Container image:    %snginx:latest%s\n", BrightCyan, Reset)
	fmt.Printf("  • Dockerfile:         %sDockerfile%s\n", BrightCyan, Reset)

	fmt.Printf("\n%s%s[?]%s Enter target path or image (or 'cancel'): ", Bold, BrightYellow, Reset)

	input, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}

	input = strings.TrimSpace(input)

	if strings.ToLower(input) == "cancel" || input == "" {
		return ""
	}

	return input
}

// promptForScanTypes prompts user for scan types
func promptForScanTypes(reader *bufio.Reader) *ScanTypes {
	fmt.Printf("\n%s%s╔═══════════════════════════════════════════════════════════════╗%s\n", Bold, BrightCyan, Reset)
	fmt.Printf("%s%s║%s  STEP 2: SCAN TYPE SELECTION                                  %s║%s\n", Bold, BrightCyan, Reset, BrightCyan, Reset)
	fmt.Printf("%s%s╚═══════════════════════════════════════════════════════════════╝%s\n", Bold, BrightCyan, Reset)

	fmt.Printf("\n%sAvailable Scan Types:%s\n", Bold, Reset)
	fmt.Printf("  %s1)%s All Scans          - Run all security scanners\n", BrightCyan, Reset)
	fmt.Printf("  %s2)%s IaC                - Infrastructure as Code misconfigurations\n", BrightCyan, Reset)
	fmt.Printf("  %s3)%s Secrets            - Hardcoded credentials and API keys\n", BrightCyan, Reset)
	fmt.Printf("  %s4)%s SAST               - Static Application Security Testing\n", BrightCyan, Reset)
	fmt.Printf("  %s5)%s SCA                - Software Composition Analysis (dependencies)\n", BrightCyan, Reset)
	fmt.Printf("  %s6)%s Container          - Container images and Dockerfiles\n", BrightCyan, Reset)
	fmt.Printf("  %s7)%s SBOM               - Software Bill of Materials generation\n", BrightCyan, Reset)
	fmt.Printf("  %s8)%s Custom             - Select specific scan types\n", BrightCyan, Reset)

	fmt.Printf("\n%s%s[?]%s Select scan type [1-8] (or 'cancel'): ", Bold, BrightYellow, Reset)

	input, err := reader.ReadString('\n')
	if err != nil {
		return nil
	}

	input = strings.TrimSpace(input)

	if strings.ToLower(input) == "cancel" {
		return nil
	}

	scanTypes := &ScanTypes{}

	switch input {
	case "1":
		scanTypes.IaC = true
		scanTypes.Secrets = true
		scanTypes.SAST = true
		scanTypes.SCA = true
		scanTypes.Container = true
		scanTypes.SBOM = true
	case "2":
		scanTypes.IaC = true
	case "3":
		scanTypes.Secrets = true
	case "4":
		scanTypes.SAST = true
	case "5":
		scanTypes.SCA = true
	case "6":
		scanTypes.Container = true
	case "7":
		scanTypes.SBOM = true
	case "8":
		return promptForCustomScanTypes(reader)
	default:
		PrintWarning("Invalid selection, defaulting to 'All Scans'")
		scanTypes.IaC = true
		scanTypes.Secrets = true
		scanTypes.SAST = true
		scanTypes.SCA = true
		scanTypes.Container = true
		scanTypes.SBOM = true
	}

	return scanTypes
}

// promptForCustomScanTypes allows user to select multiple scan types
func promptForCustomScanTypes(reader *bufio.Reader) *ScanTypes {
	fmt.Printf("\n%sSelect scan types (comma-separated, e.g., '2,3,5'):%s\n", Bold, Reset)
	fmt.Printf("  %s2)%s IaC  %s3)%s Secrets  %s4)%s SAST  %s5)%s SCA  %s6)%s Container  %s7)%s SBOM\n",
		BrightCyan, Reset, BrightCyan, Reset, BrightCyan, Reset, BrightCyan, Reset, BrightCyan, Reset, BrightCyan, Reset)

	fmt.Printf("\n%s%s[?]%s Enter selections: ", Bold, BrightYellow, Reset)

	input, err := reader.ReadString('\n')
	if err != nil {
		return nil
	}

	input = strings.TrimSpace(input)
	selections := strings.Split(input, ",")

	scanTypes := &ScanTypes{}

	for _, sel := range selections {
		sel = strings.TrimSpace(sel)
		switch sel {
		case "2":
			scanTypes.IaC = true
		case "3":
			scanTypes.Secrets = true
		case "4":
			scanTypes.SAST = true
		case "5":
			scanTypes.SCA = true
		case "6":
			scanTypes.Container = true
		case "7":
			scanTypes.SBOM = true
		}
	}

	return scanTypes
}

// promptForSeverity prompts user for minimum severity
func promptForSeverity(reader *bufio.Reader) string {
	fmt.Printf("\n%s%s╔═══════════════════════════════════════════════════════════════╗%s\n", Bold, BrightCyan, Reset)
	fmt.Printf("%s%s║%s  STEP 3: SEVERITY LEVEL                                       %s║%s\n", Bold, BrightCyan, Reset, BrightCyan, Reset)
	fmt.Printf("%s%s╚═══════════════════════════════════════════════════════════════╝%s\n", Bold, BrightCyan, Reset)

	fmt.Printf("\n%sMinimum Severity to Report:%s\n", Bold, Reset)
	fmt.Printf("  %s1)%s LOW       - Report all issues\n", BrightCyan, Reset)
	fmt.Printf("  %s2)%s MEDIUM    - Report medium, high, and critical issues\n", BrightCyan, Reset)
	fmt.Printf("  %s3)%s HIGH      - Report only high and critical issues\n", BrightCyan, Reset)
	fmt.Printf("  %s4)%s CRITICAL  - Report only critical issues\n", BrightCyan, Reset)

	fmt.Printf("\n%s%s[?]%s Select severity level [1-4] (default: 1): ", Bold, BrightYellow, Reset)

	input, err := reader.ReadString('\n')
	if err != nil {
		return "LOW"
	}

	input = strings.TrimSpace(input)

	if strings.ToLower(input) == "cancel" {
		return ""
	}

	switch input {
	case "1", "":
		return "LOW"
	case "2":
		return "MEDIUM"
	case "3":
		return "HIGH"
	case "4":
		return "CRITICAL"
	default:
		PrintWarning("Invalid selection, defaulting to LOW")
		return "LOW"
	}
}

// promptForOutputFile prompts user for output file
func promptForOutputFile(reader *bufio.Reader) string {
	fmt.Printf("\n%s%s╔═══════════════════════════════════════════════════════════════╗%s\n", Bold, BrightCyan, Reset)
	fmt.Printf("%s%s║%s  STEP 4: OUTPUT OPTIONS (Optional)                            %s║%s\n", Bold, BrightCyan, Reset, BrightCyan, Reset)
	fmt.Printf("%s%s╚═══════════════════════════════════════════════════════════════╝%s\n", Bold, BrightCyan, Reset)

	fmt.Printf("\n%s%s[?]%s Save results to file? (Enter filename or press Enter to skip): ", Bold, BrightYellow, Reset)

	input, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}

	input = strings.TrimSpace(input)

	return input
}

// formatScanTypes formats scan types for display
func formatScanTypes(st *ScanTypes) string {
	types := []string{}

	if st.IaC {
		types = append(types, "IaC")
	}
	if st.Secrets {
		types = append(types, "Secrets")
	}
	if st.SAST {
		types = append(types, "SAST")
	}
	if st.SCA {
		types = append(types, "SCA")
	}
	if st.Container {
		types = append(types, "Container")
	}
	if st.SBOM {
		types = append(types, "SBOM")
	}

	if len(types) == 0 {
		return "None"
	}

	if len(types) == 6 {
		return "All"
	}

	result := strings.Join(types, ", ")
	if len(result) > 45 {
		return result[:42] + "..."
	}
	return result
}
