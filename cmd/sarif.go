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
	Tool        sarifTool         `json:"tool"`
	Results     []sarifResult     `json:"results"`
	Invocations []sarifInvocation `json:"invocations,omitempty"`
}

// sarifInvocation carries tool-level (not finding-level) messages. We use
// it two ways. For "could not verify" warnings (a known-CVE check skipped
// because an action's pinned commit could not be resolved to a version,
// ISSUE-228) executionSuccessful stays true: the run completed, some data
// was just unavailable. For a data-collection-degraded run (#220) we set
// executionSuccessful=false and emit error-level notifications, so a Code
// Scanning ingester treats the upload as a failed run and does not clear
// previously-reported alerts off this partial report.
type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

type sarifNotification struct {
	Level   string    `json:"level"`
	Message sarifText `json:"message"`
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

// sarifText is a multiformatMessageString (SARIF §3.12). Markdown is optional
// and only meaningful on a rule's `help`: GitHub Code Scanning renders
// help.markdown in place of help.text when present, which is the only place a
// clickable link reaches an inline PR comment (helpUri is not among the
// properties Code Scanning surfaces there).
type sarifText struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID string `json:"ruleId"`
	// PartialFingerprints carries a stable, line-independent identifier per
	// finding (opaengine.StampFingerprints), so an alert keeps its identity
	// across runs and a maintainer's dismissal survives.
	//
	// The key matters: Code Scanning reads ONLY `primaryLocationLineHash` and
	// ignores every other entry, so that is the one that makes dismissals
	// stick. Despite the name it is just an opaque tool-provided value, and a
	// semantic identity is exactly what belongs there: GitHub's own fallback
	// (rule + file + region + surrounding source) is what breaks on line drift.
	// The plumber/v1 entry carries the same value under a self-describing name
	// for consumers that are not Code Scanning.
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	// Kind categorizes the result's evaluation state (SARIF §3.27.9):
	// "fail" for findings (the spec default when absent), "pass" /
	// "notApplicable" / "open" for the synthetic per-control status
	// results — evaluated-clean, skipped-by-config, and
	// could-not-fully-evaluate respectively. When Kind is anything
	// other than "fail" the spec requires Level to be "none".
	Kind       string          `json:"kind,omitempty"`
	Level      string          `json:"level"`
	Message    sarifText       `json:"message"`
	Locations  []sarifLocation `json:"locations,omitempty"`
	Properties map[string]any  `json:"properties,omitempty"`
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
//
// GitHub Code Scanning rejects any result without at least one location
// ("expected at least one location") and the location's URI must resolve to
// a committed file. Repository-level findings (branch protection and other
// settings controls) have no source file, so they are anchored to
// fallbackURI — the effective .plumber.yaml, the file where those controls
// are enabled and which is always committed for a run to happen. When
// fallbackURI is itself empty the result is emitted location-less (still
// valid SARIF; only Code Scanning is that strict).

// sarifRuleFor builds the rules[] entry for an issue code from the codes
// registry (nil info falls back to the bare code). Shared by the finding
// results and the synthetic per-control status results so a rule renders
// identically whether the control fired or passed.
func sarifRuleFor(code, severity, provider string, info *control.ErrorCodeInfo) sarifRule {
	rule := sarifRule{
		ID:                   code,
		ShortDescription:     sarifText{Text: code},
		DefaultConfiguration: sarifConfig{Level: sarifLevel(severity)},
		Properties:           map[string]any{"security-severity": sarifSecuritySeverity(severity)},
	}
	if info != nil {
		title := info.TitleFor(provider)
		description := info.DescriptionFor(provider)
		rule.Name = title
		rule.ShortDescription = sarifText{Text: title}
		if description != "" {
			rule.FullDescription = &sarifText{Text: description}
		}
		rule.Help = sarifHelp(code, info)
		rule.HelpURI = info.DocURL
		rule.Properties["controlName"] = info.ControlName
	}
	return rule
}

// sarifHelp builds the rule's help block. Code Scanning renders help.markdown
// next to the alert (and in place of help.text), and it is the only route by
// which the issue code and a clickable documentation link reach an inline PR
// comment: helpUri is not among the properties Code Scanning surfaces there,
// and ruleId is not shown prominently. text mirrors the same content for
// consumers that do not render Markdown.
func sarifHelp(code string, info *control.ErrorCodeInfo) *sarifText {
	if info == nil {
		return nil
	}
	docURL := info.DocURL
	if docURL == "" {
		docURL = "https://getplumber.io/docs/cli/issues/" + code
	}

	var md, txt strings.Builder
	md.WriteString("**" + code + "**")
	txt.WriteString(code)
	if title := info.Title; title != "" {
		md.WriteString(" — " + title)
		txt.WriteString(" - " + title)
	}
	md.WriteString("\n\n")
	txt.WriteString("\n\n")

	if info.Remediation != "" {
		md.WriteString(info.Remediation + "\n\n")
		txt.WriteString(info.Remediation + "\n\n")
	}
	md.WriteString("[View the " + code + " documentation](" + docURL + ")")
	txt.WriteString(docURL)

	return &sarifText{Text: txt.String(), Markdown: md.String()}
}

// sarifLinkEscaper escapes the three characters SARIF reserves inside a
// message string that carries an embedded link (§3.11.6). Finding detail
// quotes job names and script lines, which can contain brackets of their
// own; unescaped, a strict reader would try to parse them as link syntax.
var sarifLinkEscaper = strings.NewReplacer(`\`, `\\`, `[`, `\[`, `]`, `\]`)

// sarifMessage renders the text Code Scanning shows in an inline PR comment.
// That comment contains only the rule title, this message, and GitHub's own
// "Show more details" link to the Security-tab alert, which 404s for a reader
// without security-events access. So both facts a reader needs have to be in
// the message itself: the issue code (ruleId is not surfaced there) and the
// documentation URL (helpUri is not surfaced, and rule help renders on the
// alert page, which is gated behind the same access).
//
// The URL rides on the issue code as a SARIF embedded link (§3.11.6), which
// is plain-text message syntax and not Markdown, so it does not depend on
// message.markdown — a field Code Scanning ignores.
func sarifMessage(f opaengine.Finding, info *control.ErrorCodeInfo) string {
	if f.Code == "" {
		return f.Message
	}
	docURL := ""
	if info != nil {
		docURL = info.DocURL
	}
	if docURL == "" {
		docURL = "https://getplumber.io/docs/cli/issues/" + f.Code
	}
	msg := "[" + f.Code + "](" + docURL + ")"
	if f.Message != "" {
		msg += ": " + sarifLinkEscaper.Replace(sarifCodeSpanJob(f))
	}
	return msg
}

// sarifCodeSpanJob re-quotes the job name inside a finding message as a
// Markdown code span, so an inline PR comment renders it as code rather than
// as prose in quotes. It runs here and not in the rule that wrote the message
// for two reasons. The message is shared by every output — terminal, JSON,
// CSV, GitLab SAST — where a backtick is literal noise, not formatting. And
// a rule that emits no structured subject key falls back to its message for
// the fingerprint (finding/identity.SubjectKeys), so rewording it in Rego re-files
// the alert and drops any dismissal; rendering here leaves the fingerprint
// input untouched.
//
// The job name is matched exactly, from Finding.Job, rather than guessed from
// the prose, so a message that quotes something else is left alone.
//
// A job name carrying a character the span cannot hold keeps the rule's own
// quoting instead. A backtick would close the span; `[`, `]` and `\` are the
// characters sarifLinkEscaper escapes immediately after this runs (§3.11.6),
// and a code span renders its contents verbatim, so those backslashes would
// be shown rather than applied: `ci\[nightly\]/build` instead of the name.
// Escaping first and spanning after would fix the display by emitting stray
// unescaped brackets inside a message that carries an embedded link, which
// the spec does not allow. Left as quoted prose the escapes render correctly,
// because Markdown does apply them outside a code span.
//
// Both providers can produce such a name. A GitHub job is namespaced by the
// workflow FILE base name, so `.github/workflows/ci[nightly].yml` yields
// "ci[nightly]/build" (the job id itself cannot hold brackets, the filename
// can). A GitLab job name is the raw YAML key from .gitlab-ci.yml, which is
// free-form apart from the reserved keywords.
func sarifCodeSpanJob(f opaengine.Finding) string {
	if f.Job == "" || strings.ContainsAny(f.Job, "`[]\\") {
		return f.Message
	}
	span := "`" + f.Job + "`"
	msg := strings.ReplaceAll(f.Message, `"`+f.Job+`"`, span)
	return strings.ReplaceAll(msg, `'`+f.Job+`'`, span)
}

func buildSARIF(findings []opaengine.Finding, fallbackURI, provider string) sarifLog {
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
			rulesByID[f.Code] = sarifRuleFor(f.Code, severity, provider, info)
		}

		res := sarifResult{
			RuleID:  f.Code,
			Kind:    "fail",
			Level:   sarifLevel(severity),
			Message: sarifText{Text: sarifMessage(f, info)},
		}
		if f.Fingerprint != "" {
			res.PartialFingerprints = map[string]string{
				// The only key Code Scanning reads; without it GitHub falls
				// back to hashing the surrounding source, which changes when
				// an unrelated edit shifts the line and resurrects dismissals.
				"primaryLocationLineHash": f.Fingerprint,
				"plumber/v1":              f.Fingerprint,
			}
		}
		// SARIF's `artifactLocation.uri` must stay repo-relative so
		// GitHub Code Scanning can map the alert to a file in the
		// commit. The clickable forge URL goes into a property bag,
		// where editors and uploaders that look for it (e.g. the
		// VS Code SARIF viewer) can surface it without breaking the
		// Code Scanning ingestion contract.
		if f.URL != "" {
			res.Properties = map[string]any{"url": f.URL}
		}
		if uri := reportFilePath(f.File); uri != "" {
			phys := sarifPhysical{ArtifactLocation: sarifArtifact{URI: uri}}
			if f.Line > 0 {
				phys.Region = &sarifRegion{StartLine: f.Line}
			}
			res.Locations = []sarifLocation{{PhysicalLocation: phys}}
		} else if fallbackURI != "" {
			// Repo-level finding with no source file: anchor it to the config
			// file (no region) so Code Scanning accepts the result.
			res.Locations = []sarifLocation{{PhysicalLocation: sarifPhysical{
				ArtifactLocation: sarifArtifact{URI: fallbackURI},
			}}}
		}
		results = append(results, res)
	}

	// Per-control status (passed / skipped / error) is deliberately NOT
	// emitted into SARIF, even though the spec's `kind` field (pass /
	// notApplicable / open) models it exactly. Verified 2026-07-31:
	// GitHub Code Scanning — the primary consumer of this file, uploaded
	// by default by the GitHub Action — ignores `result.kind` entirely
	// and opens a normal alert for EVERY result (kind is absent from the
	// supported-properties table in GitHub's SARIF support docs;
	// github.com/orgs/community/discussions/65477 has staff
	// acknowledgment and re-confirmations through Aug 2025). Synthetic
	// kind:pass results would therefore flood the Security tab with one
	// junk alert per passing control on every scan. The JSON report's
	// per-block `status` field is the status feed; findings here carry an
	// explicit kind:fail (the spec default, harmless to state) and
	// nothing else.

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
func writeSARIFToFile(result *control.AnalysisResult, filePath, provider string) error {
	// Anchor repo-level (file-less) findings to the effective config file so
	// every result has a location that resolves to a committed file, which
	// GitHub Code Scanning requires. configFile holds the effective config
	// path (its own --config flag / PLUMBER_ANALYZE_CONFIG, default
	// .plumber.yaml). Only anchor to it when it actually exists on disk: a
	// zero-config run loads the embedded default and never writes a
	// .plumber.yaml, so anchoring to that phantom path would emit a URI that
	// maps to no committed file — Code Scanning silently drops or mis-maps it.
	// When there is no real config file we drop the fallback location instead;
	// a locationless result is valid SARIF, a phantom-path one is not.
	// provider routes per-provider Title/Description overrides from the codes
	// registry into the rendered SARIF document.
	fallbackURI := ""
	if _, statErr := os.Stat(configFile); statErr == nil {
		fallbackURI = reportFilePath(configFile)
	}
	log := buildSARIF(result.Findings, fallbackURI, provider)
	if len(log.Runs) > 0 {
		notifs := make([]sarifNotification, 0, len(result.DegradedReasons)+len(result.Warnings))
		// Error-level notifications for incomplete collection (#220), so the
		// run reads as failed; warning-level for could-not-verify (#228).
		for _, r := range result.DegradedReasons {
			notifs = append(notifs, sarifNotification{Level: "error", Message: sarifText{Text: "data collection incomplete: " + r}})
		}
		for _, w := range result.Warnings {
			notifs = append(notifs, sarifNotification{Level: "warning", Message: sarifText{Text: w}})
		}
		if len(notifs) > 0 || result.DataCollectionDegraded {
			log.Runs[0].Invocations = []sarifInvocation{{
				ExecutionSuccessful:        !result.DataCollectionDegraded,
				ToolExecutionNotifications: notifs,
			}}
		}
	}
	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal sarif: %w", err)
	}
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("write sarif file: %w", err)
	}
	return nil
}
