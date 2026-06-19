package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/getplumber/plumber/control"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

// GitLab SAST report output (gl-sast-report.json), schema v15.0.4. Lets
// GitLab ingest Plumber findings into the Security Dashboard and the
// merge-request security widget via `artifacts:reports:sast`.
//
// Schema constraints honoured here (security-report-schemas v15.0.4):
//   - top level requires scan + version + vulnerabilities
//   - scan requires scanner + analyzer (each id/name/version/vendor.name),
//     type, start_time, end_time, status (success|failure)
//   - each vulnerability requires id + identifiers + location
//   - per-vulnerability `category` is NOT a known property and is omitted
//   - severity is one of Info|Unknown|Low|Medium|High|Critical

const glsastSchemaVersion = "15.0.4"

type glsastReport struct {
	Schema          string       `json:"schema,omitempty"`
	Version         string       `json:"version"`
	Scan            glsastScan   `json:"scan"`
	Vulnerabilities []glsastVuln `json:"vulnerabilities"`
}

type glsastScan struct {
	Scanner   glsastScanner   `json:"scanner"`
	Analyzer  glsastScanner   `json:"analyzer"`
	Type      string          `json:"type"`
	StartTime string          `json:"start_time"`
	EndTime   string          `json:"end_time"`
	Status    string          `json:"status"`
	Messages  []glsastMessage `json:"messages,omitempty"`
}

// glsastMessage carries a scan-level note (not a vulnerability) through the
// GitLab schema's scan.messages array. Used for "could not verify"
// warnings so a degraded check shows in the pipeline output instead of
// passing silently (ISSUE-228). level is one of info|warn|fatal.
type glsastMessage struct {
	Level string `json:"level"`
	Value string `json:"value"`
}

type glsastScanner struct {
	ID      string       `json:"id"`
	Name    string       `json:"name"`
	Version string       `json:"version"`
	Vendor  glsastVendor `json:"vendor"`
	URL     string       `json:"url,omitempty"`
}

type glsastVendor struct {
	Name string `json:"name"`
}

type glsastVuln struct {
	ID          string             `json:"id"`
	Name        string             `json:"name,omitempty"`
	Message     string             `json:"message,omitempty"`
	Description string             `json:"description,omitempty"`
	Severity    string             `json:"severity,omitempty"`
	Solution    string             `json:"solution,omitempty"`
	Scanner     glsastVulnScanner  `json:"scanner"`
	Identifiers []glsastIdentifier `json:"identifiers"`
	Location    glsastLocation     `json:"location"`
	Links       []glsastLink       `json:"links,omitempty"`
}

// glsastLink is a schema-supported pointer that GitLab renders as a
// clickable link in the Vulnerability detail panel (and surfaces in
// MR security widget tooltips). Used here to carry the per-finding
// source-file URL — either a forge blob URL when running in CI / on a
// remote project, or an absolute path locally.
type glsastLink struct {
	Name string `json:"name,omitempty"`
	URL  string `json:"url"`
}

type glsastVulnScanner struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type glsastIdentifier struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	URL   string `json:"url,omitempty"`
}

type glsastLocation struct {
	File      string `json:"file,omitempty"`
	StartLine int    `json:"start_line,omitempty"`
}

func glsastSeverity(sev string) string {
	switch control.IssueSeverity(sev) {
	case control.SeverityCritical:
		return "Critical"
	case control.SeverityHigh:
		return "High"
	case control.SeverityMedium:
		return "Medium"
	case control.SeverityLow:
		return "Low"
	}
	return "Unknown"
}

// glsastID derives a stable UUID-shaped id from the finding so GitLab can
// track the same vulnerability across runs (id is recommended to be a UUID).
func glsastID(f opaengine.Finding) string {
	sum := sha256.Sum256([]byte(f.Code + "|" + f.File + "|" + fmt.Sprint(f.Line) + "|" + f.Message))
	h := hex.EncodeToString(sum[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])
}

// buildGLSAST converts the flat finding list into a GitLab SAST report.
func buildGLSAST(findings []opaengine.Finding, provider string) glsastReport {
	now := time.Now().UTC().Format("2006-01-02T15:04:05")
	toolVersion := strings.TrimPrefix(Version, "v")
	if toolVersion == "" {
		toolVersion = "0.0.0"
	}
	scanner := glsastScanner{
		ID:      "plumber",
		Name:    "Plumber",
		Version: toolVersion,
		Vendor:  glsastVendor{Name: "Plumber"},
		URL:     "https://getplumber.io",
	}

	vulns := make([]glsastVuln, 0, len(findings))
	for _, f := range findings {
		if f.Code == "" {
			continue
		}
		severity := f.Severity
		if info := control.LookupCode(control.ErrorCode(f.Code)); info != nil {
			severity = string(info.Severity)
		}
		v := glsastVuln{
			ID:          glsastID(f),
			Name:        f.Code,
			Message:     f.Message,
			Severity:    glsastSeverity(severity),
			Scanner:     glsastVulnScanner{ID: "plumber", Name: "Plumber"},
			Identifiers: []glsastIdentifier{{Type: "plumber", Name: "Plumber " + f.Code, Value: f.Code}},
			Location:    glsastLocation{File: reportFilePath(f.File), StartLine: f.Line},
		}
		// Surface the clickable source pointer through the schema's
		// `links` array. We only emit links with an http(s) scheme —
		// the GitLab UI tries to navigate to whatever it sees, and a
		// local filesystem path renders as a broken link in the
		// Security Dashboard.
		if strings.HasPrefix(f.URL, "http://") || strings.HasPrefix(f.URL, "https://") {
			v.Links = append(v.Links, glsastLink{Name: "Source", URL: f.URL})
		}
		if info := control.LookupCode(control.ErrorCode(f.Code)); info != nil {
			title := info.TitleFor(provider)
			v.Name = title
			v.Description = info.DescriptionFor(provider)
			v.Solution = info.Remediation
			v.Identifiers[0].Name = "Plumber " + f.Code + ": " + title
			v.Identifiers[0].URL = info.DocURL
		}
		// GitLab's Vulnerability Report UI does not render the deprecated
		// `message` field, so fold the per-finding detail into `description`
		// where it actually shows up. Keep `message` populated too for
		// downstream consumers that still read it.
		if f.Message != "" {
			if v.Description != "" {
				v.Description = v.Description + "\n\nFinding: " + f.Message
			} else {
				v.Description = f.Message
			}
		}
		vulns = append(vulns, v)
	}

	return glsastReport{
		Schema:  "https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/v" + glsastSchemaVersion + "/dist/sast-report-format.json",
		Version: glsastSchemaVersion,
		Scan: glsastScan{
			Scanner:   scanner,
			Analyzer:  scanner,
			Type:      "sast",
			StartTime: now,
			EndTime:   now,
			Status:    "success",
		},
		Vulnerabilities: vulns,
	}
}

// writeGLSASTToFile renders the analysis findings as a GitLab SAST report
// and writes them to filePath. A clean run writes an empty vulnerabilities
// array so GitLab clears any previously-reported findings.
func writeGLSASTToFile(result *control.AnalysisResult, filePath, provider string) error {
	report := buildGLSAST(result.Findings, provider)
	// On a data-collection-degraded run mark the scan failed (#220), so the
	// GitLab Security Dashboard treats this partial report as a failed scan
	// rather than ingesting its empty/partial findings as authoritative.
	if result.DataCollectionDegraded {
		report.Scan.Status = "failure"
		for _, r := range result.DegradedReasons {
			report.Scan.Messages = append(report.Scan.Messages, glsastMessage{Level: "warn", Value: "data collection incomplete: " + r})
		}
	}
	for _, w := range result.Warnings {
		report.Scan.Messages = append(report.Scan.Messages, glsastMessage{Level: "warn", Value: w})
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal gitlab sast report: %w", err)
	}
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("write gitlab sast report file: %w", err)
	}
	return nil
}
