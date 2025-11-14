package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
)

// cleanJSONOutput removes non-JSON content from scanner output
func cleanJSONOutput(output []byte) []byte {
	// Find the first '{' or '['
	start := bytes.IndexAny(output, "{[")
	if start == -1 {
		return output
	}
	
	// Find the last '}' or ']'
	end := bytes.LastIndexAny(output, "}]")
	if end == -1 {
		return output
	}
	
	return output[start : end+1]
}

// TrivyIaCScanner implements IaC scanning using Trivy
type TrivyIaCScanner struct{}

func NewTrivyIaCScanner() *TrivyIaCScanner {
	return &TrivyIaCScanner{}
}

func (t *TrivyIaCScanner) Name() string {
	return "Trivy IaC Scanner"
}

func (t *TrivyIaCScanner) IsAvailable() bool {
	_, err := exec.LookPath("trivy")
	return err == nil
}

func (t *TrivyIaCScanner) Scan(config *ScanConfig) ([]Finding, error) {
	args := []string{
		"config",
		"--format", "json",
		"--severity", "LOW,MEDIUM,HIGH,CRITICAL",
		"--quiet",
		config.TargetPath,
	}

	cmd := exec.Command("trivy", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Trivy returns non-zero exit code when findings are present
		if len(output) == 0 {
			return nil, fmt.Errorf("trivy failed: %w", err)
		}
	}

	return t.parseResults(output)
}

func (t *TrivyIaCScanner) parseResults(output []byte) ([]Finding, error) {
	output = cleanJSONOutput(output)
	
	var trivyResults TrivyConfigResults
	if err := json.Unmarshal(output, &trivyResults); err != nil {
		return nil, fmt.Errorf("failed to parse trivy output: %w", err)
	}

	var findings []Finding
	for _, result := range trivyResults.Results {
		for _, misconfig := range result.Misconfigurations {
			file := ""
			if misconfig.CauseMetadata.StartLine > 0 {
				file = result.Target
			}
			
			finding := Finding{
				Type:        ScanTypeIaC,
				Scanner:     "trivy",
				Severity:    misconfig.Severity,
				Title:       misconfig.Title,
				Description: misconfig.Description,
				File:        file,
				Line:        misconfig.CauseMetadata.StartLine,
				RuleID:      misconfig.ID,
				References:  misconfig.References,
				Remediation: misconfig.Resolution,
			}
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// TrivySecretScanner implements secret scanning using Trivy
type TrivySecretScanner struct{}

func NewTrivySecretScanner() *TrivySecretScanner {
	return &TrivySecretScanner{}
}

func (t *TrivySecretScanner) Name() string {
	return "Trivy Secret Scanner"
}

func (t *TrivySecretScanner) IsAvailable() bool {
	_, err := exec.LookPath("trivy")
	return err == nil
}

func (t *TrivySecretScanner) Scan(config *ScanConfig) ([]Finding, error) {
	args := []string{
		"fs",
		"--scanners", "secret",
		"--format", "json",
		"--quiet",
		config.TargetPath,
	}

	cmd := exec.Command("trivy", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if len(output) == 0 {
			return nil, fmt.Errorf("trivy secret scan failed: %w", err)
		}
	}

	return t.parseSecretResults(output)
}

func (t *TrivySecretScanner) parseSecretResults(output []byte) ([]Finding, error) {
	output = cleanJSONOutput(output)
	
	var trivyResults TrivySecretResults
	if err := json.Unmarshal(output, &trivyResults); err != nil {
		return nil, fmt.Errorf("failed to parse trivy secret output: %w", err)
	}

	var findings []Finding
	for _, result := range trivyResults.Results {
		for _, secret := range result.Secrets {
			finding := Finding{
				Type:        ScanTypeSecret,
				Scanner:     "trivy",
				Severity:    secret.Severity,
				Title:       secret.Title,
				Description: fmt.Sprintf("Secret detected: %s", secret.RuleID),
				File:        result.Target,
				Line:        secret.StartLine,
				RuleID:      secret.RuleID,
			}
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// TrivyVulnScanner implements vulnerability scanning using Trivy
type TrivyVulnScanner struct{}

func NewTrivyVulnScanner() *TrivyVulnScanner {
	return &TrivyVulnScanner{}
}

func (t *TrivyVulnScanner) Name() string {
	return "Trivy Vulnerability Scanner"
}

func (t *TrivyVulnScanner) IsAvailable() bool {
	_, err := exec.LookPath("trivy")
	return err == nil
}

func (t *TrivyVulnScanner) Scan(config *ScanConfig) ([]Finding, error) {
	args := []string{
		"fs",
		"--scanners", "vuln",
		"--format", "json",
		"--severity", "LOW,MEDIUM,HIGH,CRITICAL",
		"--quiet",
		config.TargetPath,
	}

	cmd := exec.Command("trivy", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if len(output) == 0 {
			return nil, fmt.Errorf("trivy vuln scan failed: %w", err)
		}
	}

	return t.parseVulnResults(output)
}

func (t *TrivyVulnScanner) parseVulnResults(output []byte) ([]Finding, error) {
	output = cleanJSONOutput(output)
	
	var trivyResults TrivyVulnResults
	if err := json.Unmarshal(output, &trivyResults); err != nil {
		return nil, fmt.Errorf("failed to parse trivy vuln output: %w", err)
	}

	var findings []Finding
	for _, result := range trivyResults.Results {
		for _, vuln := range result.Vulnerabilities {
			cvss := 0.0
			if vuln.CVSS != nil {
				for _, v := range vuln.CVSS {
					if v.V3Score > cvss {
						cvss = v.V3Score
					}
				}
			}

			title := vuln.VulnerabilityID
			if vuln.Title != "" {
				title = vuln.Title
			}

			finding := Finding{
				Type:        ScanTypeSCA,
				Scanner:     "trivy",
				Severity:    vuln.Severity,
				Title:       title,
				Description: vuln.Description,
				File:        result.Target, // Add the manifest file
				CVE:         vuln.VulnerabilityID,
				CVSS:        cvss,
				References:  vuln.References,
				Extra: map[string]string{
					"package":           vuln.PkgName,
					"installed_version": vuln.InstalledVersion,
					"fixed_version":     vuln.FixedVersion,
				},
			}
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// Trivy JSON result structures
type TrivyConfigResults struct {
	Results []TrivyConfigResult `json:"Results"`
}

type TrivyConfigResult struct {
	Target            string                `json:"Target"`
	Misconfigurations []TrivyMisconfig      `json:"Misconfigurations"`
}

type TrivyMisconfig struct {
	ID            string              `json:"ID"`
	Title         string              `json:"Title"`
	Description   string              `json:"Description"`
	Severity      string              `json:"Severity"`
	Resolution    string              `json:"Resolution"`
	References    []string            `json:"References"`
	CauseMetadata TrivyCauseMetadata  `json:"CauseMetadata"`
}

type TrivyCauseMetadata struct {
	StartLine int `json:"StartLine"`
	EndLine   int `json:"EndLine"`
}

type TrivySecretResults struct {
	Results []TrivySecretResult `json:"Results"`
}

type TrivySecretResult struct {
	Target  string         `json:"Target"`
	Secrets []TrivySecret  `json:"Secrets"`
}

type TrivySecret struct {
	RuleID    string `json:"RuleID"`
	Title     string `json:"Title"`
	Severity  string `json:"Severity"`
	StartLine int    `json:"StartLine"`
	EndLine   int    `json:"EndLine"`
}

type TrivyVulnResults struct {
	Results []TrivyVulnResult `json:"Results"`
}

type TrivyVulnResult struct {
	Target          string              `json:"Target"`
	Vulnerabilities []TrivyVulnerability `json:"Vulnerabilities"`
}

type TrivyVulnerability struct {
	VulnerabilityID  string                 `json:"VulnerabilityID"`
	PkgName          string                 `json:"PkgName"`
	InstalledVersion string                 `json:"InstalledVersion"`
	FixedVersion     string                 `json:"FixedVersion"`
	Severity         string                 `json:"Severity"`
	Title            string                 `json:"Title"`
	Description      string                 `json:"Description"`
	References       []string               `json:"References"`
	CVSS             map[string]TrivyCVSS   `json:"CVSS"`
}

type TrivyCVSS struct {
	V3Score float64 `json:"V3Score"`
}

// TrivyContainerScanner implements container image and Dockerfile scanning using Trivy
type TrivyContainerScanner struct{}

func NewTrivyContainerScanner() *TrivyContainerScanner {
	return &TrivyContainerScanner{}
}

func (t *TrivyContainerScanner) Name() string {
	return "Trivy Container Scanner"
}

func (t *TrivyContainerScanner) IsAvailable() bool {
	_, err := exec.LookPath("trivy")
	return err == nil
}

func (t *TrivyContainerScanner) Scan(config *ScanConfig) ([]Finding, error) {
	// Determine if we're scanning an image or a Dockerfile
	var args []string

	// Check if target is a Dockerfile or a directory containing one
	if isDockerfileOrImage(config.TargetPath) {
		// Scan container image or Dockerfile
		args = []string{
			"image",
			"--format", "json",
			"--severity", "LOW,MEDIUM,HIGH,CRITICAL",
			"--quiet",
			config.TargetPath,
		}
	} else {
		// Scan filesystem for Dockerfiles
		args = []string{
			"config",
			"--format", "json",
			"--severity", "LOW,MEDIUM,HIGH,CRITICAL",
			"--quiet",
			"--file-patterns", "Dockerfile,Dockerfile.*,*.dockerfile",
			config.TargetPath,
		}
	}

	cmd := exec.Command("trivy", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Trivy returns non-zero exit code when findings are present
		if len(output) == 0 {
			return nil, fmt.Errorf("trivy container scan failed: %w", err)
		}
	}

	return t.parseContainerResults(output)
}

func (t *TrivyContainerScanner) parseContainerResults(output []byte) ([]Finding, error) {
	output = cleanJSONOutput(output)

	// Try parsing as vulnerability results first
	var trivyVulnResults TrivyVulnResults
	if err := json.Unmarshal(output, &trivyVulnResults); err == nil && len(trivyVulnResults.Results) > 0 {
		var findings []Finding
		for _, result := range trivyVulnResults.Results {
			for _, vuln := range result.Vulnerabilities {
				cvss := 0.0
				if vuln.CVSS != nil {
					for _, v := range vuln.CVSS {
						if v.V3Score > cvss {
							cvss = v.V3Score
						}
					}
				}

				title := vuln.VulnerabilityID
				if vuln.Title != "" {
					title = vuln.Title
				}

				finding := Finding{
					Type:        ScanTypeContainer,
					Scanner:     "trivy",
					Severity:    vuln.Severity,
					Title:       title,
					Description: vuln.Description,
					File:        result.Target,
					CVE:         vuln.VulnerabilityID,
					CVSS:        cvss,
					References:  vuln.References,
					Extra: map[string]string{
						"package":           vuln.PkgName,
						"installed_version": vuln.InstalledVersion,
						"fixed_version":     vuln.FixedVersion,
					},
				}
				findings = append(findings, finding)
			}
		}

		// Also check for misconfigurations in the same scan
		var trivyConfigResults TrivyConfigResults
		if err := json.Unmarshal(output, &trivyConfigResults); err == nil {
			for _, result := range trivyConfigResults.Results {
				for _, misconfig := range result.Misconfigurations {
					file := ""
					if misconfig.CauseMetadata.StartLine > 0 {
						file = result.Target
					}

					finding := Finding{
						Type:        ScanTypeContainer,
						Scanner:     "trivy",
						Severity:    misconfig.Severity,
						Title:       misconfig.Title,
						Description: misconfig.Description,
						File:        file,
						Line:        misconfig.CauseMetadata.StartLine,
						RuleID:      misconfig.ID,
						References:  misconfig.References,
						Remediation: misconfig.Resolution,
					}
					findings = append(findings, finding)
				}
			}
		}

		return findings, nil
	}

	// Try parsing as config results (Dockerfile misconfigurations)
	var trivyConfigResults TrivyConfigResults
	if err := json.Unmarshal(output, &trivyConfigResults); err == nil {
		var findings []Finding
		for _, result := range trivyConfigResults.Results {
			for _, misconfig := range result.Misconfigurations {
				file := ""
				if misconfig.CauseMetadata.StartLine > 0 {
					file = result.Target
				}

				finding := Finding{
					Type:        ScanTypeContainer,
					Scanner:     "trivy",
					Severity:    misconfig.Severity,
					Title:       misconfig.Title,
					Description: misconfig.Description,
					File:        file,
					Line:        misconfig.CauseMetadata.StartLine,
					RuleID:      misconfig.ID,
					References:  misconfig.References,
					Remediation: misconfig.Resolution,
				}
				findings = append(findings, finding)
			}
		}
		return findings, nil
	}

	return nil, fmt.Errorf("failed to parse trivy container output")
}

// isDockerfileOrImage checks if the target is a Dockerfile or container image
func isDockerfileOrImage(target string) bool {
	// Check if it's a container image reference (contains : or @)
	if bytes.Contains([]byte(target), []byte(":")) || bytes.Contains([]byte(target), []byte("@")) {
		return true
	}

	// Check if it's a Dockerfile
	if bytes.Contains([]byte(target), []byte("Dockerfile")) || bytes.Contains([]byte(target), []byte(".dockerfile")) {
		return true
	}

	return false
}
