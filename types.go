package main

import (
	"time"
)

// ScanConfig holds the configuration for a scan
type ScanConfig struct {
	TargetPath     string
	OutputFormat   string
	OutputFile     string
	MinSeverity    string
	FailOnSeverity string
	Parallel       bool
	Verbose        bool
	ScanTypes      ScanTypes
}

// ScanTypes indicates which scan types to perform
type ScanTypes struct {
	IaC       bool
	Secrets   bool
	SAST      bool
	SCA       bool
	Container bool
	SBOM      bool
}

// ScanResult represents the aggregated results from all scanners
type ScanResult struct {
	Summary       Summary                  `json:"summary"`
	IaCResults    []Finding                `json:"iac_results,omitempty"`
	SecretResults []Finding                `json:"secret_results,omitempty"`
	SASTResults   []Finding                `json:"sast_results,omitempty"`
	SCAResults    []Finding                `json:"sca_results,omitempty"`
	SBOM          *SBOMData                `json:"sbom,omitempty"`
	Metadata      Metadata                 `json:"metadata"`
}

// Summary provides high-level statistics
type Summary struct {
	TotalFindings      int            `json:"total_findings"`
	FindingsBySeverity map[string]int `json:"findings_by_severity"`
	FindingsByType     map[string]int `json:"findings_by_type"`
	ScanDuration       string         `json:"scan_duration"`
}

// Finding represents a single security finding
type Finding struct {
	Type        string            `json:"type"`        // IaC, Secret, SAST, SCA
	Scanner     string            `json:"scanner"`     // Tool that found it
	Severity    string            `json:"severity"`    // CRITICAL, HIGH, MEDIUM, LOW
	Title       string            `json:"title"`
	Description string            `json:"description"`
	File        string            `json:"file,omitempty"`
	Line        int               `json:"line,omitempty"`
	Column      int               `json:"column,omitempty"`
	Code        string            `json:"code,omitempty"`
	RuleID      string            `json:"rule_id,omitempty"`
	CWE         []string          `json:"cwe,omitempty"`
	CVE         string            `json:"cve,omitempty"`
	CVSS        float64           `json:"cvss,omitempty"`
	References  []string          `json:"references,omitempty"`
	Remediation string            `json:"remediation,omitempty"`
	Extra       map[string]string `json:"extra,omitempty"`
}

// SBOMData represents SBOM information
type SBOMData struct {
	Format     string      `json:"format"`
	Components []Component `json:"components"`
	Path       string      `json:"path,omitempty"` // If saved to file
}

// Component represents a software component in the SBOM
type Component struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
	License string `json:"license,omitempty"`
}

// Metadata about the scan
type Metadata struct {
	ToolName    string    `json:"tool_name"`
	ToolVersion string    `json:"tool_version"`
	TargetPath  string    `json:"target_path"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
	Scanners    []string  `json:"scanners_used"`
}

// SeverityLevel enum
const (
	SeverityLow      = "LOW"
	SeverityMedium   = "MEDIUM"
	SeverityHigh     = "HIGH"
	SeverityCritical = "CRITICAL"
)

// ScanType enum
const (
	ScanTypeIaC     = "IaC"
	ScanTypeSecret  = "Secret"
	ScanTypeSAST    = "SAST"
	ScanTypeSCA     = "SCA"
)

// Scanner interface that all scanner implementations must fulfill
type ScannerInterface interface {
	Name() string
	IsAvailable() bool
	Scan(config *ScanConfig) ([]Finding, error)
}
