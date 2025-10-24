package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"
	"bytes"
)

// Formatter handles different output formats
type Formatter struct {
	format  string
	results *ScanResult
}

// NewFormatter creates a new formatter
func NewFormatter(format string, results *ScanResult) *Formatter {
	return &Formatter{
		format:  format,
		results: results,
	}
}

// Format formats the results according to the specified format
func (f *Formatter) Format() (string, error) {
	switch strings.ToLower(f.format) {
	case "json":
		return f.formatJSON()
	case "sarif":
		return f.formatSARIF()
	case "table":
		return f.formatTable()
	case "html":
		return f.formatHTML()
	default:
		return "", fmt.Errorf("unsupported format: %s", f.format)
	}
}

// formatJSON formats results as JSON
func (f *Formatter) formatJSON() (string, error) {
	data, err := json.MarshalIndent(f.results, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// formatSARIF formats results as SARIF 2.1.0
func (f *Formatter) formatSARIF() (string, error) {
	sarif := SARIFReport{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs:    []SARIFRun{},
	}

	// Group findings by scanner
	scannerFindings := make(map[string][]Finding)
	allFindings := append(f.results.IaCResults, f.results.SecretResults...)
	allFindings = append(allFindings, f.results.SASTResults...)
	allFindings = append(allFindings, f.results.SCAResults...)

	for _, finding := range allFindings {
		scannerFindings[finding.Scanner] = append(scannerFindings[finding.Scanner], finding)
	}

	// Create a run for each scanner
	for scanner, findings := range scannerFindings {
		run := SARIFRun{
			Tool: SARIFTool{
				Driver: SARIFDriver{
					Name:    scanner,
					Version: "1.0.0",
					Rules:   []SARIFRule{},
				},
			},
			Results: []SARIFResult{},
		}

		// Create rules and results
		ruleMap := make(map[string]bool)
		for _, finding := range findings {
			// Add rule if not already present
			if !ruleMap[finding.RuleID] && finding.RuleID != "" {
				rule := SARIFRule{
					ID:               finding.RuleID,
					ShortDescription: SARIFMessage{Text: finding.Title},
					FullDescription:  SARIFMessage{Text: finding.Description},
					Help:             SARIFMessage{Text: finding.Remediation},
					Properties: map[string]interface{}{
						"security-severity": f.severityToScore(finding.Severity),
					},
				}
				run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, rule)
				ruleMap[finding.RuleID] = true
			}

			// Add result
			result := SARIFResult{
				RuleID:  finding.RuleID,
				Level:   f.severityToSARIFLevel(finding.Severity),
				Message: SARIFMessage{Text: finding.Description},
			}

			if finding.File != "" {
				result.Locations = []SARIFLocation{
					{
						PhysicalLocation: SARIFPhysicalLocation{
							ArtifactLocation: SARIFArtifactLocation{
								URI: finding.File,
							},
							Region: SARIFRegion{
								StartLine:   finding.Line,
								StartColumn: finding.Column,
							},
						},
					},
				}
			}

			run.Results = append(run.Results, result)
		}

		sarif.Runs = append(sarif.Runs, run)
	}

	data, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// formatTable formats results as a human-readable table
func (f *Formatter) formatTable() (string, error) {
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)

	allFindings := append(f.results.IaCResults, f.results.SecretResults...)
	allFindings = append(allFindings, f.results.SASTResults...)
	allFindings = append(allFindings, f.results.SCAResults...)

	if len(allFindings) == 0 {
		return "No findings detected.\n", nil
	}

	// Header
	_, _ = fmt.Fprintln(w, "TYPE\tSEVERITY\tSCANNER\tFILE\tLINE\tTITLE")
	_, _ = fmt.Fprintln(w, "----\t--------\t-------\t----\t----\t-----")

	// Findings
	for _, finding := range allFindings {
		line := "-"
		if finding.Line > 0 {
			line = fmt.Sprintf("%d", finding.Line)
		}

		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			finding.Type,
			finding.Severity,
			finding.Scanner,
			truncate(finding.File, 40),
			line,
			truncate(finding.Title, 60),
		)
	}

	_ = w.Flush()
	return buf.String(), nil
}

// formatHTML formats results as HTML
func (f *Formatter) formatHTML() (string, error) {
	html := `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>SecureScan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .summary-card { background: #f9f9f9; padding: 15px; border-radius: 5px; border-left: 4px solid #4CAF50; }
        .summary-card h3 { margin: 0 0 10px 0; color: #666; font-size: 14px; }
        .summary-card .value { font-size: 32px; font-weight: bold; color: #333; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th { background: #4CAF50; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background: #f5f5f5; }
        .severity { padding: 4px 8px; border-radius: 3px; font-weight: bold; font-size: 12px; }
        .severity.CRITICAL { background: #f44336; color: white; }
        .severity.HIGH { background: #ff9800; color: white; }
        .severity.MEDIUM { background: #ffc107; color: black; }
        .severity.LOW { background: #8bc34a; color: white; }
        .type-badge { padding: 4px 8px; border-radius: 3px; background: #2196F3; color: white; font-size: 12px; }
        .metadata { background: #f9f9f9; padding: 15px; margin: 20px 0; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Nimbis Security Report</h1>
        
        <div class="metadata">
            <strong>Target:</strong> %s<br>
            <strong>Scan Duration:</strong> %s<br>
            <strong>Generated:</strong> %s
        </div>

        <div class="summary">
            <div class="summary-card">
                <h3>Total Findings</h3>
                <div class="value">%d</div>
            </div>
            <div class="summary-card" style="border-left-color: #f44336;">
                <h3>Critical</h3>
                <div class="value">%d</div>
            </div>
            <div class="summary-card" style="border-left-color: #ff9800;">
                <h3>High</h3>
                <div class="value">%d</div>
            </div>
            <div class="summary-card" style="border-left-color: #ffc107;">
                <h3>Medium</h3>
                <div class="value">%d</div>
            </div>
            <div class="summary-card" style="border-left-color: #8bc34a;">
                <h3>Low</h3>
                <div class="value">%d</div>
            </div>
        </div>

        <h2>Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>Scanner</th>
                    <th>Title</th>
                    <th>File</th>
                    <th>Line</th>
                </tr>
            </thead>
            <tbody>
%s
            </tbody>
        </table>
    </div>
</body>
</html>`

	allFindings := append(f.results.IaCResults, f.results.SecretResults...)
	allFindings = append(allFindings, f.results.SASTResults...)
	allFindings = append(allFindings, f.results.SCAResults...)

	rows := ""
	for _, finding := range allFindings {
		line := "-"
		if finding.Line > 0 {
			line = fmt.Sprintf("%d", finding.Line)
		}

		rows += fmt.Sprintf(`
                <tr>
                    <td><span class="type-badge">%s</span></td>
                    <td><span class="severity %s">%s</span></td>
                    <td>%s</td>
                    <td>%s</td>
                    <td>%s</td>
                    <td>%s</td>
                </tr>`,
			finding.Type,
			finding.Severity,
			finding.Severity,
			finding.Scanner,
			finding.Title,
			finding.File,
			line,
		)
	}

	return fmt.Sprintf(html,
		f.results.Metadata.TargetPath,
		f.results.Summary.ScanDuration,
		f.results.Metadata.EndTime.Format("2006-01-02 15:04:05"),
		f.results.Summary.TotalFindings,
		f.results.Summary.FindingsBySeverity[SeverityCritical],
		f.results.Summary.FindingsBySeverity[SeverityHigh],
		f.results.Summary.FindingsBySeverity[SeverityMedium],
		f.results.Summary.FindingsBySeverity[SeverityLow],
		rows,
	), nil
}

// Helper functions
func (f *Formatter) severityToSARIFLevel(severity string) string {
	switch severity {
	case SeverityCritical, SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func (f *Formatter) severityToScore(severity string) string {
	switch severity {
	case SeverityCritical:
		return "9.0"
	case SeverityHigh:
		return "7.0"
	case SeverityMedium:
		return "4.0"
	default:
		return "2.0"
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// SARIF structures
type SARIFReport struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID               string                 `json:"id"`
	ShortDescription SARIFMessage           `json:"shortDescription"`
	FullDescription  SARIFMessage           `json:"fullDescription"`
	Help             SARIFMessage           `json:"help"`
	Properties       map[string]interface{} `json:"properties"`
}

type SARIFResult struct {
	RuleID    string           `json:"ruleId"`
	Level     string           `json:"level"`
	Message   SARIFMessage     `json:"message"`
	Locations []SARIFLocation  `json:"locations,omitempty"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
}
