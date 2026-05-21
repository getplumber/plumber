package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/getplumber/plumber/control"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

// reportFilePath normalizes a finding's file path for security-report
// consumers (SARIF Code Scanning, GitLab SAST), which expect paths relative
// to the repository root. The GitHub collector records absolute paths; when
// the scan runs from the repo root (as in CI) we strip that prefix. Relative
// paths (the GitLab path already produces these) are passed through. Always
// forward-slashed.
func reportFilePath(file string) string {
	file = strings.TrimPrefix(file, "./")
	if file == "" {
		return ""
	}
	if filepath.IsAbs(file) {
		if wd, err := os.Getwd(); err == nil {
			if rel, err := filepath.Rel(wd, file); err == nil && !strings.HasPrefix(rel, "..") {
				return filepath.ToSlash(rel)
			}
		}
	}
	return filepath.ToSlash(file)
}

// SARIF 2.1.0 output. Surfaces Plumber findings in GitHub Code Scanning
// (Security tab) and GitLab's SARIF upload path. Only the minimal subset
// of the spec that those consumers use is emitted.
//
// Severity mapping:
//   - SARIF `level`: critical/high -> error, medium -> warning, low -> note.
//   - `security-severity` (0-10, drives GitHub's Critical/High/Medium/Low
//     bucketing in the Security tab): critical 9.5, high 8.0, medium 5.0,
//     low 2.0.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name,omitempty"`
	ShortDescription     sarifText      `json:"shortDescription"`
	FullDescription      *sarifText     `json:"fullDescription,omitempty"`
	Help                 *sarifText     `json:"help,omitempty"`
	HelpURI              string         `json:"helpUri,omitempty"`
	DefaultConfiguration sarifConfig    `json:"defaultConfiguration"`
	Properties           map[string]any `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func sarifLevel(sev string) string {
	switch control.IssueSeverity(sev) {
	case control.SeverityCritical, control.SeverityHigh:
		return "error"
	case control.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func sarifSecuritySeverity(sev string) string {
	switch control.IssueSeverity(sev) {
	case control.SeverityCritical:
		return "9.5"
	case control.SeverityHigh:
		return "8.0"
	case control.SeverityMedium:
		return "5.0"
	default:
		return "2.0"
	}
}

// buildSARIF converts the flat finding list into a SARIF 2.1.0 document.
// Rules are emitted once per distinct issue code (with metadata from the
// codes registry); results carry a file/line location when the finding
// has one.
func buildSARIF(findings []opaengine.Finding) sarifLog {
	rulesByID := map[string]sarifRule{}
	results := make([]sarifResult, 0, len(findings))

	for _, f := range findings {
		if f.Code == "" {
			continue
		}

		// The codes registry is the source of truth for a code's severity
		// (it drives the score, the terminal output, and the GitLab SAST
		// report). Use it for both the rule and the result so the SARIF is
		// internally consistent and agrees with the other outputs; fall back
		// to the finding's own severity only for codes not in the registry.
		info := control.LookupCode(control.ErrorCode(f.Code))
		severity := f.Severity
		if info != nil {
			severity = string(info.Severity)
		}

		if _, seen := rulesByID[f.Code]; !seen {
			rule := sarifRule{
				ID:                   f.Code,
				ShortDescription:     sarifText{Text: f.Code},
				DefaultConfiguration: sarifConfig{Level: sarifLevel(severity)},
				Properties:           map[string]any{"security-severity": sarifSecuritySeverity(severity)},
			}
			if info != nil {
				rule.Name = info.Title
				rule.ShortDescription = sarifText{Text: info.Title}
				if info.Description != "" {
					rule.FullDescription = &sarifText{Text: info.Description}
				}
				if info.Remediation != "" {
					rule.Help = &sarifText{Text: info.Remediation}
				}
				rule.HelpURI = info.DocURL
			}
			rulesByID[f.Code] = rule
		}

		res := sarifResult{
			RuleID:  f.Code,
			Level:   sarifLevel(severity),
			Message: sarifText{Text: f.Message},
		}
		if uri := reportFilePath(f.File); uri != "" {
			phys := sarifPhysical{ArtifactLocation: sarifArtifact{URI: uri}}
			if f.Line > 0 {
				phys.Region = &sarifRegion{StartLine: f.Line}
			}
			res.Locations = []sarifLocation{{PhysicalLocation: phys}}
		}
		results = append(results, res)
	}

	ids := make([]string, 0, len(rulesByID))
	for id := range rulesByID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rules := make([]sarifRule, 0, len(ids))
	for _, id := range ids {
		rules = append(rules, rulesByID[id])
	}

	return sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "Plumber",
				InformationURI: "https://getplumber.io",
				Version:        strings.TrimPrefix(Version, "v"),
				Rules:          rules,
			}},
			Results: results,
		}},
	}
}

// writeSARIFToFile renders the analysis findings as SARIF 2.1.0 and writes
// them to filePath. A clean run produces a valid empty-results document so
// downstream Code Scanning clears any previously-reported alerts.
func writeSARIFToFile(result *control.AnalysisResult, filePath string) error {
	data, err := json.MarshalIndent(buildSARIF(result.Findings), "", "  ")
	if err != nil {
		return fmt.Errorf("marshal sarif: %w", err)
	}
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("write sarif file: %w", err)
	}
	return nil
}
