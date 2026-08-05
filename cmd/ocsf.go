package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/provider"
)

// OCSF Compliance Finding constants (class 2003, category 2 = Findings).
// activity_id 1 = Create; type_uid = class_uid*100 + activity_id.
const (
	ocsfClassUID    = 2003
	ocsfCategoryUID = 2
	ocsfActivityID  = 1
	ocsfTypeUID     = 200301
	// ocsfTypeUID = ocsfClassUID * 100 + ocsfActivityID
	ocsfSchemaVer = "1.8.0"
	// ocsfStatusNew is the top-level finding lifecycle status (New). The
	// authoritative pass/fail signal is compliance.status_id, not this.
	ocsfStatusNew = 1
)

// ocsfFindingTypes tags every event's finding_info.types. It is an open
// string array (advisory metadata for consumer filtering/grouping), not an
// OCSF enum. "Compliance" is intentionally omitted: class_uid 2003 already
// conveys that these are compliance findings, and consumers prefer the
// CI/CD security vocabulary.
var ocsfFindingTypes = []string{"CI/CD Security", "Supply Chain", "Security"}

type ocsfComplianceFinding struct {
	ActivityID  int              `json:"activity_id"`
	CategoryUID int              `json:"category_uid"`
	ClassUID    int              `json:"class_uid"`
	TypeUID     int              `json:"type_uid"`
	Time        int64            `json:"time"`
	SeverityID  int              `json:"severity_id"`
	StatusID    int              `json:"status_id"`
	Message     string           `json:"message"`
	Metadata    ocsfMetadata     `json:"metadata"`
	Compliance  ocsfCompliance   `json:"compliance"`
	FindingInfo ocsfFindingInfo  `json:"finding_info"`
	Remediation *ocsfRemediation `json:"remediation,omitempty"`
	Unmapped    map[string]any   `json:"unmapped,omitempty"`
}

type ocsfMetadata struct {
	Version        string      `json:"version"`
	Product        ocsfProduct `json:"product"`
	CorrelationUID string      `json:"correlation_uid,omitempty"`
}

type ocsfProduct struct {
	Name       string `json:"name"`
	VendorName string `json:"vendor_name"`
	Version    string `json:"version"`
	URL        string `json:"url_string,omitempty"`
}

type ocsfCompliance struct {
	Control       string   `json:"control,omitempty"`
	Standards     []string `json:"standards"`
	Requirements  []string `json:"requirements,omitempty"`
	Status        string   `json:"status"`
	StatusID      int      `json:"status_id"`
	StatusDetails []string `json:"status_details,omitempty"`
}

type ocsfFindingInfo struct {
	UID    string   `json:"uid"`
	Title  string   `json:"title,omitempty"`
	Desc   string   `json:"desc,omitempty"`
	Types  []string `json:"types,omitempty"`
	SrcURL string   `json:"src_url,omitempty"`
}

type ocsfRemediation struct {
	Desc string `json:"desc"`
}

// ocsfComplianceStatus maps a control.StatusFor verdict onto OCSF's
// compliance.status_id enum (0 Unknown / 1 Pass / 2 Warning / 3 Fail /
// 99 Other). error → Warning is the explicit "could not verify" state that
// keeps a degraded run from reading as a pass.
func ocsfComplianceStatus(status string) (string, int) {
	switch status {
	case control.StatusFailed:
		return "Fail", 3
	case control.StatusPassed:
		return "Pass", 1
	case control.StatusError:
		return "Warning", 2
	case control.StatusSkipped:
		// status_id 99 (Other) is OCSF's bucket for a state that is not one of
		// Pass/Warning/Fail. Per OCSF convention the sibling caption string for
		// 99 carries the original source value, not the literal "Other", so the
		// consumer sees the real state and the validator does not warn.
		return "Skipped", 99
	default:
		return "Unknown", 0
	}
}

// ocsfSeverityID maps a Plumber issue severity onto OCSF severity_id.
func ocsfSeverityID(sev control.IssueSeverity) int {
	switch sev {
	case control.SeverityCritical:
		return 5
	case control.SeverityHigh:
		return 4
	case control.SeverityMedium:
		return 3
	case control.SeverityLow:
		return 2
	default:
		return 1 // Informational
	}
}

// ocsfProductVersion returns the Plumber build version without the leading
// "v", mirroring buildGLSAST; "0.0.0" when unset.
func ocsfProductVersion() string {
	v := strings.TrimPrefix(Version, "v")
	if v == "" {
		v = "0.0.0"
	}
	return v
}

// buildOCSF projects each catalog control onto one OCSF Compliance Finding
// event. It reuses control.StatusFor (the same verdict the --output JSON
// stamps), so an empty findings list is never silently a pass: a control that
// could not be verified is Warning, an intentionally skipped one is Other. now
// and correlationUID are injected so tests are deterministic.
func buildOCSF(entries []control.ControlEntry, result *control.AnalysisResult, providerName string, now int64, correlationUID string) []ocsfComplianceFinding {
	byControl := control.FindingsByControl(result.Findings)
	product := ocsfProduct{Name: "Plumber", VendorName: "getplumber", Version: ocsfProductVersion(), URL: "https://getplumber.io"}

	events := make([]ocsfComplianceFinding, 0, len(entries))
	for _, e := range entries {
		findings := byControl[e.ControlName]
		status := control.StatusFor(e, result, len(findings))
		statusLabel, statusID := ocsfComplianceStatus(status)

		codes := control.CodesForControl(e.ControlName)
		requirements := make([]string, 0, len(codes))
		for _, c := range codes {
			requirements = append(requirements, string(c))
		}

		ev := ocsfComplianceFinding{
			ActivityID:  ocsfActivityID,
			CategoryUID: ocsfCategoryUID,
			ClassUID:    ocsfClassUID,
			TypeUID:     ocsfTypeUID,
			Time:        now,
			SeverityID:  1,
			StatusID:    ocsfStatusNew,
			Message:     ocsfControlMessage(e.DisplayName, status, len(findings)),
			Metadata: ocsfMetadata{
				Version:        ocsfSchemaVer,
				Product:        product,
				CorrelationUID: correlationUID,
			},
			Compliance: ocsfCompliance{
				Control:       e.ControlName,
				Standards:     []string{"Plumber"},
				Requirements:  requirements,
				Status:        statusLabel,
				StatusID:      statusID,
				StatusDetails: ocsfStatusDetails(status, e, findings, result),
			},
			FindingInfo: ocsfFindingInfo{
				UID:    correlationUID + ":" + e.ControlName,
				Title:  e.DisplayName,
				Desc:   ocsfControlDesc(codes, providerName),
				Types:  ocsfFindingTypes,
				SrcURL: ocsfControlDocURL(codes),
			},
		}

		if status == control.StatusFailed {
			ev.SeverityID = ocsfMaxSeverityID(findings)
			ev.Remediation = &ocsfRemediation{Desc: ocsfRemediationText(codes)}
			ev.Unmapped = ocsfFailUnmapped(findings)
		}

		events = append(events, ev)
	}
	return events
}

func ocsfControlMessage(displayName, status string, n int) string {
	switch status {
	case control.StatusFailed:
		return fmt.Sprintf("Control %q failed: %d issue(s).", displayName, n)
	case control.StatusPassed:
		return fmt.Sprintf("Control %q passed.", displayName)
	case control.StatusError:
		return fmt.Sprintf("Control %q could not be verified.", displayName)
	case control.StatusSkipped:
		return fmt.Sprintf("Control %q was skipped.", displayName)
	default:
		return fmt.Sprintf("Control %q: status unknown.", displayName)
	}
}

func ocsfStatusDetails(status string, e control.ControlEntry, findings []opaengine.Finding, result *control.AnalysisResult) []string {
	switch status {
	case control.StatusFailed:
		details := make([]string, 0, len(findings))
		for _, f := range findings {
			if f.Message != "" {
				details = append(details, f.Message)
			}
		}
		return details
	case control.StatusSkipped:
		reason := e.SkipReason
		if reason == "" {
			reason = "disabled in configuration"
		}
		return []string{"skipped: " + reason}
	case control.StatusError:
		if result != nil && len(result.DegradedReasons) > 0 {
			return []string{"could not verify: " + strings.Join(result.DegradedReasons, "; ")}
		}
		return []string{"could not verify: control did not fully evaluate"}
	default:
		return nil
	}
}

func ocsfControlDesc(codes []control.ErrorCode, providerName string) string {
	if len(codes) == 0 {
		return ""
	}
	if info := control.LookupCode(codes[0]); info != nil {
		return info.DescriptionFor(providerName)
	}
	return ""
}

func ocsfControlDocURL(codes []control.ErrorCode) string {
	if len(codes) == 0 {
		return ""
	}
	if info := control.LookupCode(codes[0]); info != nil && info.DocURL != "" {
		return info.DocURL
	}
	return "https://getplumber.io/docs/cli/issues/" + string(codes[0])
}

func ocsfRemediationText(codes []control.ErrorCode) string {
	seen := map[string]bool{}
	var parts []string
	for _, c := range codes {
		info := control.LookupCode(c)
		if info == nil || info.Remediation == "" || seen[info.Remediation] {
			continue
		}
		seen[info.Remediation] = true
		parts = append(parts, info.Remediation)
	}
	return strings.Join(parts, " ")
}

func ocsfMaxSeverityID(findings []opaengine.Finding) int {
	maxID := 1
	for _, f := range findings {
		if info := control.LookupCode(control.ErrorCode(f.Code)); info != nil {
			if id := ocsfSeverityID(info.Severity); id > maxID {
				maxID = id
			}
		}
	}
	return maxID
}

func ocsfFailUnmapped(findings []opaengine.Finding) map[string]any {
	records := make([]map[string]any, 0, len(findings))
	codes := make([]control.ErrorCode, 0, len(findings))
	for _, f := range findings {
		rec := map[string]any{
			"issue_code": f.Code,
			"message":    f.Message,
		}
		if f.Fingerprint != "" {
			rec["fingerprint"] = f.Fingerprint
		}
		if f.File != "" {
			rec["file"] = reportFilePath(f.File)
		}
		if f.Line != 0 {
			rec["line"] = f.Line
		}
		if f.Job != "" {
			rec["job"] = f.Job
		}
		if step, ok := f.Data["step"].(string); ok && step != "" {
			rec["step"] = step
		}
		if f.URL != "" {
			rec["src_url"] = f.URL
		}
		records = append(records, rec)
		codes = append(codes, control.ErrorCode(f.Code))
	}
	return map[string]any{
		"plumber_findings":        records,
		"plumber_severity_counts": control.SeverityCountsFromIssueCodes(codes),
	}
}

// writeOCSFEvents marshals events as an indented JSON array and writes it to
// filePath.
func writeOCSFEvents(events []ocsfComplianceFinding, filePath string) error {
	data, err := json.MarshalIndent(events, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal ocsf events: %w", err)
	}
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("write ocsf file: %w", err)
	}
	return nil
}

// ocsfScanUID builds a per-scan correlation id from the analyzed project and
// scan time. Deterministic given its inputs, so no random dependency is added.
func ocsfScanUID(result *control.AnalysisResult, now int64) string {
	ref := result.HeadCommitSha
	if ref == "" {
		ref = result.AnalyzeBranch
	}
	return fmt.Sprintf("plumber:%s:%s:%d", result.ProjectPath, ref, now)
}

// writeOCSFToFile walks the provider's control catalog, projects each control's
// evaluation status onto an OCSF Compliance Finding, and writes the JSON array
// to filePath. Provider-agnostic: every control is listed with an explicit
// status, so the file is never empty and absence never reads as a pass.
func writeOCSFToFile(p provider.Provider, result *control.AnalysisResult, conf *configuration.Configuration, filePath string) error {
	entries := p.Controls(conf.PlumberConfig)
	control.MarkSkippedByFilter(entries, conf.ControlsFilter, conf.SkipControlsFilter)
	now := time.Now().UTC().UnixMilli()
	events := buildOCSF(entries, result, p.Name(), now, ocsfScanUID(result, now))
	return writeOCSFEvents(events, filePath)
}
