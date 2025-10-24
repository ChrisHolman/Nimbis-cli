package main

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// CheckovScanner implements IaC scanning using Checkov
type CheckovScanner struct{}

func NewCheckovScanner() *CheckovScanner {
	return &CheckovScanner{}
}

func (c *CheckovScanner) Name() string {
	return "Checkov"
}

func (c *CheckovScanner) IsAvailable() bool {
	_, err := exec.LookPath("checkov")
	return err == nil
}

func (c *CheckovScanner) Scan(config *ScanConfig) ([]Finding, error) {
	args := []string{
		"-d", config.TargetPath,
		"--output", "json",
		"--quiet",
	}

	cmd := exec.Command("checkov", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Checkov returns non-zero when findings exist
		if len(output) == 0 {
			return nil, fmt.Errorf("checkov failed: %w", err)
		}
	}

	return c.parseResults(output)
}

func (c *CheckovScanner) parseResults(output []byte) ([]Finding, error) {
	var checkovResults CheckovResults
	if err := json.Unmarshal(output, &checkovResults); err != nil {
		return nil, fmt.Errorf("failed to parse checkov output: %w", err)
	}

	var findings []Finding
	for _, result := range checkovResults.Results.FailedChecks {
		severity := c.mapSeverity(result.CheckClass)
		
		finding := Finding{
			Type:        ScanTypeIaC,
			Scanner:     "checkov",
			Severity:    severity,
			Title:       result.CheckName,
			Description: result.CheckName,
			File:        result.FilePath,
			Line:        result.FileLineRange[0],
			RuleID:      result.CheckID,
			Remediation: result.Guideline,
		}
		findings = append(findings, finding)
	}

	return findings, nil
}

func (c *CheckovScanner) mapSeverity(checkClass string) string {
	// Checkov doesn't always provide severity, so we use check class or default
	switch strings.ToUpper(checkClass) {
	case "CRITICAL":
		return SeverityCritical
	case "HIGH":
		return SeverityHigh
	case "MEDIUM":
		return SeverityMedium
	default:
		return SeverityLow
	}
}

// TruffleHogScanner implements secret scanning using TruffleHog
type TruffleHogScanner struct{}

func NewTruffleHogScanner() *TruffleHogScanner {
	return &TruffleHogScanner{}
}

func (t *TruffleHogScanner) Name() string {
	return "TruffleHog"
}

func (t *TruffleHogScanner) IsAvailable() bool {
	_, err := exec.LookPath("trufflehog")
	return err == nil
}

func (t *TruffleHogScanner) Scan(config *ScanConfig) ([]Finding, error) {
	args := []string{
		"filesystem",
		config.TargetPath,
		"--json",
		"--no-update",
	}

	cmd := exec.Command("trufflehog", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if len(output) == 0 {
			return nil, fmt.Errorf("trufflehog failed: %w", err)
		}
	}

	return t.parseResults(output)
}

func (t *TruffleHogScanner) parseResults(output []byte) ([]Finding, error) {
	lines := strings.Split(string(output), "\n")
	var findings []Finding

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		var result TruffleHogResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			continue // Skip malformed lines
		}

		if result.Verified {
			finding := Finding{
				Type:        ScanTypeSecret,
				Scanner:     "trufflehog",
				Severity:    SeverityCritical, // Verified secrets are critical
				Title:       fmt.Sprintf("%s secret detected", result.DetectorName),
				Description: fmt.Sprintf("Verified %s credential found", result.DetectorName),
				File:        result.SourceMetadata.Data.Filesystem.File,
				Line:        result.SourceMetadata.Data.Filesystem.Line,
				Extra: map[string]string{
					"detector": result.DetectorName,
					"verified": "true",
				},
			}
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// OpenGrepScanner implements SAST using OpenGrep
type OpenGrepScanner struct{}

func NewOpenGrepScanner() *OpenGrepScanner {
	return &OpenGrepScanner{}
}

func (o *OpenGrepScanner) Name() string {
	return "OpenGrep"
}

func (o *OpenGrepScanner) IsAvailable() bool {
	_, err := exec.LookPath("opengrep")
	return err == nil
}

func (o *OpenGrepScanner) Scan(config *ScanConfig) ([]Finding, error) {
	args := []string{
		"scan",
		"--config", "auto",
		"--json",
		config.TargetPath,
	}

	cmd := exec.Command("opengrep", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if len(output) == 0 {
			return nil, fmt.Errorf("opengrep failed: %w", err)
		}
	}

	return o.parseResults(output)
}

func (o *OpenGrepScanner) parseResults(output []byte) ([]Finding, error) {
	var openGrepResults OpenGrepResults
	if err := json.Unmarshal(output, &openGrepResults); err != nil {
		return nil, fmt.Errorf("failed to parse opengrep output: %w", err)
	}

	var findings []Finding
	for _, result := range openGrepResults.Results {
		finding := Finding{
			Type:        ScanTypeSAST,
			Scanner:     "opengrep",
			Severity:    o.mapSeverity(result.Extra.Severity),
			Title:       result.CheckID,
			Description: result.Extra.Message,
			File:        result.Path,
			Line:        result.Start.Line,
			Column:      result.Start.Col,
			RuleID:      result.CheckID,
			References:  result.Extra.Metadata.References,
		}

		if len(result.Extra.Metadata.CWE) > 0 {
			finding.CWE = result.Extra.Metadata.CWE
		}

		findings = append(findings, finding)
	}

	return findings, nil
}

func (o *OpenGrepScanner) mapSeverity(severity string) string {
	switch strings.ToUpper(severity) {
	case "ERROR":
		return SeverityHigh
	case "WARNING":
		return SeverityMedium
	default:
		return SeverityLow
	}
}

// GrypeScanner implements vulnerability scanning using Grype
type GrypeScanner struct{}

func NewGrypeScanner() *GrypeScanner {
	return &GrypeScanner{}
}

func (g *GrypeScanner) Name() string {
	return "Grype"
}

func (g *GrypeScanner) IsAvailable() bool {
	_, err := exec.LookPath("grype")
	return err == nil
}

func (g *GrypeScanner) Scan(config *ScanConfig) ([]Finding, error) {
	args := []string{
		"dir:" + config.TargetPath,
		"-o", "json",
		"--quiet",
	}

	cmd := exec.Command("grype", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if len(output) == 0 {
			return nil, fmt.Errorf("grype failed: %w", err)
		}
	}

	return g.parseResults(output)
}

func (g *GrypeScanner) parseResults(output []byte) ([]Finding, error) {
	var grypeResults GrypeResults
	if err := json.Unmarshal(output, &grypeResults); err != nil {
		return nil, fmt.Errorf("failed to parse grype output: %w", err)
	}

	var findings []Finding
	for _, match := range grypeResults.Matches {
		cvss := 0.0
		if len(match.Vulnerability.Cvss) > 0 {
			for _, c := range match.Vulnerability.Cvss {
				if score := c.Metrics.BaseScore; score > cvss {
					cvss = score
				}
			}
		}

		fixedVersion := ""
		if len(match.Vulnerability.Fix.Versions) > 0 {
			fixedVersion = match.Vulnerability.Fix.Versions[0]
		}

		finding := Finding{
			Type:        ScanTypeSCA,
			Scanner:     "grype",
			Severity:    match.Vulnerability.Severity,
			Title:       match.Vulnerability.ID,
			Description: match.Vulnerability.Description,
			CVE:         match.Vulnerability.ID,
			CVSS:        cvss,
			References:  match.Vulnerability.URLs,
			Extra: map[string]string{
				"package":           match.Artifact.Name,
				"installed_version": match.Artifact.Version,
				"fixed_version":     fixedVersion,
			},
		}
		findings = append(findings, finding)
	}

	return findings, nil
}

// SyftScanner implements SBOM generation using Syft
type SyftScanner struct{}

func NewSyftScanner() *SyftScanner {
	return &SyftScanner{}
}

func (s *SyftScanner) Name() string {
	return "Syft SBOM Generator"
}

func (s *SyftScanner) IsAvailable() bool {
	_, err := exec.LookPath("syft")
	return err == nil
}

func (s *SyftScanner) Scan(config *ScanConfig) ([]Finding, error) {
	// Syft generates SBOM, not findings
	// We'll handle SBOM generation separately
	return nil, nil
}

// GenerateSBOM generates an SBOM using Syft
func (s *SyftScanner) GenerateSBOM(targetPath string) (*SBOMData, error) {
	args := []string{
		"scan",
		"dir:" + targetPath,
		"-o", "json",
		"--quiet",
	}

	cmd := exec.Command("syft", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("syft failed: %w", err)
	}

	var syftOutput SyftOutput
	if err := json.Unmarshal(output, &syftOutput); err != nil {
		return nil, fmt.Errorf("failed to parse syft output: %w", err)
	}

	sbom := &SBOMData{
		Format:     "CycloneDX",
		Components: []Component{},
	}

	for _, artifact := range syftOutput.Artifacts {
		component := Component{
			Name:    artifact.Name,
			Version: artifact.Version,
			Type:    artifact.Type,
		}
		
		if len(artifact.Licenses) > 0 {
			component.License = artifact.Licenses[0].Value
		}
		
		sbom.Components = append(sbom.Components, component)
	}

	return sbom, nil
}

// Scanner output structures
type CheckovResults struct {
	Results struct {
		FailedChecks []CheckovFailedCheck `json:"failed_checks"`
	} `json:"results"`
}

type CheckovFailedCheck struct {
	CheckID       string `json:"check_id"`
	CheckName     string `json:"check_name"`
	CheckClass    string `json:"check_class"`
	FilePath      string `json:"file_path"`
	FileLineRange []int  `json:"file_line_range"`
	Guideline     string `json:"guideline"`
}

type TruffleHogResult struct {
	DetectorName   string `json:"DetectorName"`
	Verified       bool   `json:"Verified"`
	SourceMetadata struct {
		Data struct {
			Filesystem struct {
				File string `json:"file"`
				Line int    `json:"line"`
			} `json:"Filesystem"`
		} `json:"Data"`
	} `json:"SourceMetadata"`
}

type OpenGrepResults struct {
	Results []OpenGrepResult `json:"results"`
}

type OpenGrepResult struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line int `json:"line"`
		Col  int `json:"col"`
	} `json:"start"`
	Extra struct {
		Message  string `json:"message"`
		Severity string `json:"severity"`
		Metadata struct {
			CWE        []string `json:"cwe"`
			References []string `json:"references"`
		} `json:"metadata"`
	} `json:"extra"`
}

type GrypeResults struct {
	Matches []GrypeMatch `json:"matches"`
}

type GrypeMatch struct {
	Vulnerability GrypeVulnerability `json:"vulnerability"`
	Artifact      GrypeArtifact      `json:"artifact"`
}

type GrypeVulnerability struct {
	ID          string   `json:"id"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	URLs        []string `json:"urls"`
	Cvss        []struct {
		Metrics struct {
			BaseScore float64 `json:"baseScore"`
		} `json:"metrics"`
	} `json:"cvss"`
	Fix struct {
		Versions []string `json:"versions"`
	} `json:"fix"`
}

type GrypeArtifact struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type SyftOutput struct {
	Artifacts []SyftArtifact `json:"artifacts"`
}

type SyftArtifact struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Type     string `json:"type"`
	Licenses []struct {
		Value string `json:"value"`
	} `json:"licenses"`
}
