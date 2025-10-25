package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var (
	version = "0.1.0"
	
	// Global flags
	targetPath     string
	outputFormat   string
	outputFile     string
	severity       string
	failOnSeverity string
	parallel       bool
	verbose        bool
	autoInstall    bool
	quiet          bool
	
	// Scan type flags
	scanAll       bool
	scanIaC       bool
	scanSecrets   bool
	scanSAST      bool
	scanSCA       bool
	scanContainer bool
	generateSBOM  bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "nimbis",
		Short: "A comprehensive security scanning tool for code, containers, and infrastructure",
		Long: `Nimbis is a unified CLI tool that orchestrates multiple open-source security scanners
to identify IaC misconfigurations, secrets, SAST issues, SCA vulnerabilities, and generate SBOMs.`,
		Version: version,
		RunE:    runScan,
	}

	// Global flags
	rootCmd.PersistentFlags().StringVarP(&targetPath, "target", "t", ".", "Target path to scan (directory, file, or container image)")
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "format", "f", "json", "Output format (json, sarif, html, table)")
	rootCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "", "Output file path (default: stdout)")
	rootCmd.PersistentFlags().StringVarP(&severity, "severity", "s", "LOW", "Minimum severity to report (LOW, MEDIUM, HIGH, CRITICAL)")
	rootCmd.PersistentFlags().StringVar(&failOnSeverity, "fail-on", "CRITICAL", "Exit with error if issues of this severity or higher are found")
	rootCmd.PersistentFlags().BoolVarP(&parallel, "parallel", "p", true, "Run scanners in parallel")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().BoolVar(&autoInstall, "auto-install", false, "Automatically install missing scanners")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "Minimal output - only show summary (saves full results to file)")

	// Scan type flags
	rootCmd.Flags().BoolVar(&scanAll, "all", false, "Run all scan types")
	rootCmd.Flags().BoolVar(&scanIaC, "iac", false, "Scan for IaC misconfigurations")
	rootCmd.Flags().BoolVar(&scanSecrets, "secrets", false, "Scan for secrets and credentials")
	rootCmd.Flags().BoolVar(&scanSAST, "sast", false, "Perform static application security testing")
	rootCmd.Flags().BoolVar(&scanSCA, "sca", false, "Scan for vulnerable dependencies")
	rootCmd.Flags().BoolVar(&scanContainer, "container", false, "Scan container image")
	rootCmd.Flags().BoolVar(&generateSBOM, "sbom", false, "Generate Software Bill of Materials")

	// Add explain command
	explainCmd := &cobra.Command{
		Use:   "explain",
		Short: "Get AI-powered explanations for security findings",
		Long: `Use AI to explain security findings in plain language with actionable fix suggestions.
Supports OpenAI, Anthropic Claude, and local Ollama models.`,
		RunE: runExplain,
	}
	rootCmd.AddCommand(explainCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) error {
	// If no specific scan type is selected, default to --all
	if !scanAll && !scanIaC && !scanSecrets && !scanSAST && !scanSCA && !scanContainer && !generateSBOM {
		scanAll = true
	}

	config := &ScanConfig{
		TargetPath:     targetPath,
		OutputFormat:   outputFormat,
		OutputFile:     outputFile,
		MinSeverity:    severity,
		FailOnSeverity: failOnSeverity,
		Parallel:       parallel,
		Verbose:        verbose,
		AutoInstall:    autoInstall,
		Quiet:          quiet,
		ScanTypes: ScanTypes{
			IaC:       scanAll || scanIaC,
			Secrets:   scanAll || scanSecrets,
			SAST:      scanAll || scanSAST,
			SCA:       scanAll || scanSCA,
			Container: scanAll || scanContainer,
			SBOM:      scanAll || generateSBOM,
		},
	}

	scanner := NewScanner(config)
	return scanner.Run()
}

func runExplain(cmd *cobra.Command, args []string) error {
	// First, run a scan to get findings
	if outputFile == "" {
		outputFile = "nimbis-results.json"
	}
	
	// Run scan quietly
	fmt.Println("🔍 Scanning for vulnerabilities...")
	config := &ScanConfig{
		TargetPath:     targetPath,
		OutputFormat:   "json",
		OutputFile:     outputFile,
		MinSeverity:    severity,
		FailOnSeverity: failOnSeverity,
		Parallel:       parallel,
		Verbose:        false,
		AutoInstall:    autoInstall,
		Quiet:          true,
		ScanTypes: ScanTypes{
			IaC:       true,
			Secrets:   true,
			SAST:      true,
			SCA:       true,
			Container: false,
			SBOM:      false,
		},
	}
	
	scanner := NewScanner(config)
	if err := scanner.Run(); err != nil {
		return err
	}
	
	// Get findings
	results := scanner.results
	allFindings := append(results.IaCResults, results.SecretResults...)
	allFindings = append(allFindings, results.SASTResults...)
	allFindings = append(allFindings, results.SCAResults...)
	
	if len(allFindings) == 0 {
		PrintSuccess("No security findings to explain! 🎉")
		return nil
	}
	
	// Show interactive menu
	fmt.Println()
	fmt.Printf("%sFound %d security findings%s\n\n", Bold, len(allFindings), Reset)
	
	// Group by severity and show top issues
	criticalFindings := []Finding{}
	highFindings := []Finding{}
	
	for _, f := range allFindings {
		if strings.ToUpper(f.Severity) == "CRITICAL" {
			criticalFindings = append(criticalFindings, f)
		} else if strings.ToUpper(f.Severity) == "HIGH" {
			highFindings = append(highFindings, f)
		}
	}
	
	// Explain the most critical finding automatically
	var findingToExplain Finding
	if len(criticalFindings) > 0 {
		findingToExplain = criticalFindings[0]
		fmt.Printf("Explaining most critical finding:\n\n")
	} else if len(highFindings) > 0 {
		findingToExplain = highFindings[0]
		fmt.Printf("Explaining highest severity finding:\n\n")
	} else {
		findingToExplain = allFindings[0]
		fmt.Printf("Explaining finding:\n\n")
	}
	
	// Explain the finding
	return ExplainFinding(findingToExplain)
}
