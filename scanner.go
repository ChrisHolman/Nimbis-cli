package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Scanner orchestrates multiple security scanners
type Scanner struct {
	config   *ScanConfig
	scanners map[string]ScannerInterface
	results  *ScanResult
}

// NewScanner creates a new scanner orchestrator
func NewScanner(config *ScanConfig) *Scanner {
	s := &Scanner{
		config: config,
		results: &ScanResult{
			Summary: Summary{
				FindingsBySeverity: make(map[string]int),
				FindingsByType:     make(map[string]int),
			},
			Metadata: Metadata{
				ToolName:    "Nimbis",
				ToolVersion: version,
				TargetPath:  config.TargetPath,
				StartTime:   time.Now(),
			},
		},
	}

	// Initialize scanners based on config
	s.scanners = make(map[string]ScannerInterface)
	
	if config.ScanTypes.IaC {
		s.scanners["trivy-iac"] = NewTrivyIaCScanner()
		s.scanners["checkov"] = NewCheckovScanner()
	}
	
	if config.ScanTypes.Secrets {
		s.scanners["trufflehog"] = NewTruffleHogScanner()
		s.scanners["trivy-secret"] = NewTrivySecretScanner()
	}
	
	if config.ScanTypes.SAST {
		s.scanners["opengrep"] = NewOpenGrepScanner()
	}
	
	if config.ScanTypes.SCA {
		s.scanners["trivy-vuln"] = NewTrivyVulnScanner()
		s.scanners["grype"] = NewGrypeScanner()
	}
	
	if config.ScanTypes.SBOM {
		s.scanners["syft"] = NewSyftScanner()
	}

	return s
}

// Run executes all configured scanners
func (s *Scanner) Run() error {
	// Print banner (skip if quiet mode)
	if !s.config.Quiet {
		PrintBanner()
	} else {
		PrintCompactBanner()
	}
	
	PrintScanStart(s.config.TargetPath)

	// Check scanner availability
	s.checkScannerAvailability()

	// Run scanners
	if s.config.Parallel {
		s.runParallel()
	} else {
		s.runSequential()
	}

	s.results.Metadata.EndTime = time.Now()
	s.results.Summary.ScanDuration = s.results.Metadata.EndTime.Sub(s.results.Metadata.StartTime).String()

	// Calculate summary
	s.calculateSummary()

	// Output results
	return s.outputResults()
}

// checkScannerAvailability checks which scanners are available
func (s *Scanner) checkScannerAvailability() {
	fmt.Println("🔧 Checking scanner availability...")
	availableScanners := []string{}
	
	for name, scanner := range s.scanners {
		if scanner.IsAvailable() {
			availableScanners = append(availableScanners, name)
			if s.config.Verbose {
				fmt.Printf("  ✓ %s\n", scanner.Name())
			}
		} else {
			fmt.Printf("  ⚠ %s not available (skipping)\n", scanner.Name())
			delete(s.scanners, name)
		}
	}
	
	s.results.Metadata.Scanners = availableScanners
	fmt.Printf("  Found %d available scanner(s)\n\n", len(availableScanners))
	
	if len(availableScanners) == 0 {
		// Offer to auto-install
		fmt.Println("❌ No scanners available.")
		
		shouldInstall := s.config.AutoInstall
		if !shouldInstall {
			fmt.Println("\nWould you like to auto-install scanners? (y/n)")
			fmt.Print("> ")
			
			var response string
			fmt.Scanln(&response)
			shouldInstall = strings.ToLower(strings.TrimSpace(response)) == "y"
		}
		
		if shouldInstall {
			installer, err := NewScannerInstaller()
			if err != nil {
				fmt.Printf("Failed to create installer: %v\n", err)
				os.Exit(1)
			}
			
			if err := installer.InstallAll(); err != nil {
				fmt.Printf("Installation failed: %v\n", err)
				os.Exit(1)
			}
			
			installer.AddToPath()
			
			// Re-check availability after installation
			fmt.Println("🔧 Re-checking scanner availability...")
			s.scanners = make(map[string]ScannerInterface)
			
			if s.config.ScanTypes.IaC {
				s.scanners["trivy-iac"] = NewTrivyIaCScanner()
				s.scanners["checkov"] = NewCheckovScanner()
			}
			
			if s.config.ScanTypes.Secrets {
				s.scanners["trufflehog"] = NewTruffleHogScanner()
				s.scanners["trivy-secret"] = NewTrivySecretScanner()
			}
			
			if s.config.ScanTypes.SAST {
				s.scanners["opengrep"] = NewOpenGrepScanner()
			}
			
			if s.config.ScanTypes.SCA {
				s.scanners["trivy-vuln"] = NewTrivyVulnScanner()
				s.scanners["grype"] = NewGrypeScanner()
			}
			
			if s.config.ScanTypes.SBOM {
				s.scanners["syft"] = NewSyftScanner()
			}
			
			availableScanners = []string{}
			for name, scanner := range s.scanners {
				if scanner.IsAvailable() {
					availableScanners = append(availableScanners, name)
					fmt.Printf("  ✓ %s\n", scanner.Name())
				} else {
					delete(s.scanners, name)
				}
			}
			
			if len(availableScanners) == 0 {
				fmt.Println("\n❌ Installation completed but scanners still not available.")
				fmt.Println("Please check your system PATH or install manually.")
				os.Exit(1)
			}
			
			s.results.Metadata.Scanners = availableScanners
			fmt.Printf("\n✅ Ready to scan with %d scanner(s)\n\n", len(availableScanners))
			return
		}
		
		fmt.Println("\nManual installation instructions:")
		fmt.Println("  • Trivy: https://aquasecurity.github.io/trivy/latest/getting-started/installation/")
		fmt.Println("  • TruffleHog: https://github.com/trufflesecurity/trufflehog")
		fmt.Println("  • Checkov: pip install checkov")
		fmt.Println("  • Grype: https://github.com/anchore/grype")
		fmt.Println("  • Syft: https://github.com/anchore/syft")
		os.Exit(1)
	}
}

// runParallel runs all scanners in parallel
func (s *Scanner) runParallel() {
	var wg sync.WaitGroup
	var mu sync.Mutex
	
	for name, scanner := range s.scanners {
		wg.Add(1)
		go func(n string, sc ScannerInterface) {
			defer wg.Done()
			
			if s.config.Verbose {
				fmt.Printf("▶ Starting %s...\n", sc.Name())
			}
			
			findings, err := sc.Scan(s.config)
			if err != nil {
				fmt.Printf("  ⚠ %s failed: %v\n", sc.Name(), err)
				return
			}
			
			mu.Lock()
			s.appendFindings(findings)
			mu.Unlock()
			
			fmt.Printf("  ✓ %s completed (%d findings)\n", sc.Name(), len(findings))
		}(name, scanner)
	}
	
	wg.Wait()
}

// runSequential runs all scanners sequentially
func (s *Scanner) runSequential() {
	for _, scanner := range s.scanners {
		fmt.Printf("▶ Running %s...\n", scanner.Name())
		
		findings, err := scanner.Scan(s.config)
		if err != nil {
			fmt.Printf("  ⚠ %s failed: %v\n", scanner.Name(), err)
			continue
		}
		
		s.appendFindings(findings)
		fmt.Printf("  ✓ %s completed (%d findings)\n", scanner.Name(), len(findings))
	}
}

// appendFindings adds findings to the appropriate result category
func (s *Scanner) appendFindings(findings []Finding) {
	for _, f := range findings {
		switch f.Type {
		case ScanTypeIaC:
			s.results.IaCResults = append(s.results.IaCResults, f)
		case ScanTypeSecret:
			s.results.SecretResults = append(s.results.SecretResults, f)
		case ScanTypeSAST:
			s.results.SASTResults = append(s.results.SASTResults, f)
		case ScanTypeSCA:
			s.results.SCAResults = append(s.results.SCAResults, f)
		}
	}
}

// calculateSummary calculates summary statistics
func (s *Scanner) calculateSummary() {
	allFindings := append(s.results.IaCResults, s.results.SecretResults...)
	allFindings = append(allFindings, s.results.SASTResults...)
	allFindings = append(allFindings, s.results.SCAResults...)
	
	s.results.Summary.TotalFindings = len(allFindings)
	
	for _, f := range allFindings {
		s.results.Summary.FindingsBySeverity[f.Severity]++
		s.results.Summary.FindingsByType[f.Type]++
	}
}

// outputResults outputs the scan results
func (s *Scanner) outputResults() error {
	// Always save full results to file if in quiet mode
	if s.config.Quiet && s.config.OutputFile == "" {
		s.config.OutputFile = "nimbis-results.json"
		s.config.OutputFormat = "json"
	}
	
	// Generate formatted output for file
	if s.config.OutputFile != "" {
		formatter := NewFormatter(s.config.OutputFormat, s.results)
		output, err := formatter.Format()
		if err != nil {
			return fmt.Errorf("failed to format output: %w", err)
		}
		
		if err := os.WriteFile(s.config.OutputFile, []byte(output), 0644); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		
		if !s.config.Quiet {
			fmt.Printf("\n📄 Full results saved to: %s\n", s.config.OutputFile)
		}
	}
	
	// Print summary (always shown unless quiet mode with no findings)
	if !s.config.Quiet || s.results.Summary.TotalFindings > 0 {
		s.printSummary()
		
		// Print brief findings overview
		if s.results.Summary.TotalFindings > 0 {
			s.printBriefFindings()
		}
	}
	
	// Check if we should fail based on severity
	return s.checkFailCondition()
}

// printBriefFindings prints a brief overview of findings
func (s *Scanner) printBriefFindings() {
	allFindings := append(s.results.IaCResults, s.results.SecretResults...)
	allFindings = append(allFindings, s.results.SASTResults...)
	allFindings = append(allFindings, s.results.SCAResults...)
	
	if len(allFindings) == 0 {
		return
	}
	
	fmt.Println("\n" + strings.Repeat("─", 60))
	fmt.Println("📋 FINDINGS OVERVIEW")
	fmt.Println(strings.Repeat("─", 60))
	
	// Group by severity
	severityGroups := map[string][]Finding{
		SeverityCritical: {},
		SeverityHigh:     {},
		SeverityMedium:   {},
		SeverityLow:      {},
	}
	
	for _, f := range allFindings {
		severityGroups[f.Severity] = append(severityGroups[f.Severity], f)
	}
	
	// Print each severity group
	for _, sev := range []string{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow} {
		findings := severityGroups[sev]
		if len(findings) == 0 {
			continue
		}
		
		emoji := getSeverityEmoji(sev)
		fmt.Printf("\n%s %s (%d issues)\n", emoji, sev, len(findings))
		fmt.Println(strings.Repeat("─", 60))
		
		for i, f := range findings {
			// Limit to 5 per severity level for readability
			if i >= 5 {
				fmt.Printf("   ... and %d more %s issues\n", len(findings)-5, sev)
				break
			}
			
			// Print brief finding
			location := ""
			if f.File != "" {
				location = fmt.Sprintf(" in %s", truncateMiddle(f.File, 35))
				if f.Line > 0 {
					location += fmt.Sprintf(":%d", f.Line)
				}
			}
			
			fmt.Printf("\n   %s%s\n", truncate(f.Title, 55), location)
			
			if f.Remediation != "" {
				fmt.Printf("   💡 %s\n", truncate(f.Remediation, 55))
			}
		}
	}
	
	if s.config.OutputFile != "" {
		fmt.Printf("\n💾 Full details available in: %s\n", s.config.OutputFile)
	} else {
		fmt.Println("\n💾 Run with -o results.json to save full details")
	}
	
	fmt.Println(strings.Repeat("─", 60))
}

// printSummary prints a human-readable summary
func (s *Scanner) printSummary() {
	fmt.Println("\n" + strings.Repeat("═", 60))
	fmt.Println("📊 SCAN SUMMARY")
	fmt.Println(strings.Repeat("═", 60))
	fmt.Printf("Total Findings: %d\n", s.results.Summary.TotalFindings)
	fmt.Printf("Scan Duration: %s\n", s.results.Summary.ScanDuration)
	
	if len(s.results.Summary.FindingsBySeverity) > 0 {
		fmt.Println("\nFindings by Severity:")
		for _, sev := range []string{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow} {
			if count, ok := s.results.Summary.FindingsBySeverity[sev]; ok && count > 0 {
				emoji := getSeverityEmoji(sev)
				fmt.Printf("  %s %s: %d\n", emoji, sev, count)
			}
		}
	}
	
	if len(s.results.Summary.FindingsByType) > 0 {
		fmt.Println("\nFindings by Type:")
		for scanType, count := range s.results.Summary.FindingsByType {
			fmt.Printf("  • %s: %d\n", scanType, count)
		}
	}
	
	fmt.Println(strings.Repeat("═", 60))
}

// checkFailCondition checks if the scan should fail based on severity threshold
func (s *Scanner) checkFailCondition() error {
	severityOrder := map[string]int{
		SeverityLow:      1,
		SeverityMedium:   2,
		SeverityHigh:     3,
		SeverityCritical: 4,
	}
	
	failThreshold := severityOrder[s.config.FailOnSeverity]
	
	for sev, count := range s.results.Summary.FindingsBySeverity {
		if count > 0 && severityOrder[sev] >= failThreshold {
			return fmt.Errorf("scan failed: found %d issue(s) at or above %s severity", count, s.config.FailOnSeverity)
		}
	}
	
	return nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func truncateMiddle(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	
	// Keep start and end, replace middle with ...
	keepLen := (maxLen - 3) / 2
	return s[:keepLen] + "..." + s[len(s)-keepLen:]
}

// getSeverityEmoji returns an emoji for the severity level
func getSeverityEmoji(severity string) string {
	switch severity {
	case SeverityCritical:
		return "🔴"
	case SeverityHigh:
		return "🟠"
	case SeverityMedium:
		return "🟡"
	case SeverityLow:
		return "🟢"
	default:
		return "⚪"
	}
}
