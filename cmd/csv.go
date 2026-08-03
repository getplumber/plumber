package cmd

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/provider"
)

// buildCSV renders the full per-control posture, not just findings. It walks the
// control catalog and emits, for every control, its evaluation status
// (control.StatusFor: passed / failed / skipped / error), so a clean run is no
// longer an empty file and a consumer can build a per-control history by
// grouping on controlName and reading status. This is the same posture the
// JSON --output status feed carries, flattened to a table.
//
// Row model:
//   - passed / skipped / error control -> one summary row. The finding columns
//     (code, fingerprint, severity, context, file, line, url, docUrl) are empty
//     and message carries the skip/error reason so the row is not opaque.
//   - failed control -> one row per code-bearing finding, with status "failed"
//     and the full finding detail. A control with N findings occupies N rows;
//     that repetition is the natural shape of a flat findings table.
//
// The fingerprint column is a stable, line-independent identifier per finding
// (opaengine.StampFingerprints), so a consumer can follow one specific finding
// across runs even when the same control has many findings of the same code.
//
// Ordering: non-failing controls (passed / error / skipped) come first, then the
// failing controls with their findings, so the clean posture reads at the top
// and the problems are grouped at the bottom. Catalog order is preserved within
// each group.
//
// The "context" column is Finding.Job as-is (a CI job name for job-scoped
// findings, but some rules put a branch / include path / file there instead), so
// the header avoids the false claim "job" would make when the value isn't a job.
func buildCSV(entries []control.ControlEntry, result *control.AnalysisResult) [][]string {
	header := []string{"code", "fingerprint", "controlName", "status", "severity", "message", "context", "file", "line", "url", "docUrl"}
	byControl := control.FindingsByControl(result.Findings)

	var nonFailing [][]string // passed / error / skipped: one row per control, at the top
	var failing [][]string    // failed: one row per finding, at the bottom

	for _, e := range entries {
		findings := byControl[e.ControlName]
		status := control.StatusFor(e, result, len(findings))

		if status != control.StatusFailed {
			nonFailing = append(nonFailing, []string{
				"",                                 // code
				"",                                 // fingerprint (no finding)
				e.ControlName,                      // controlName
				status,                             // status
				"",                                 // severity
				csvStatusReason(status, e, result), // message = reason (skipped/error) or empty
				"",                                 // context
				"",                                 // file
				"",                                 // line
				"",                                 // url
				"",                                 // docUrl
			})
			continue
		}

		for _, f := range findings {
			if f.Code == "" {
				continue // codeless findings have no stable identifier to report against
			}

			// The codes registry is the source of truth for severity, matching
			// how buildGLSAST and buildSARIF resolve it, so the CSV agrees with
			// the other exports.
			severity := f.Severity
			if info := control.LookupCode(control.ErrorCode(f.Code)); info != nil {
				severity = string(info.Severity)
			}

			line := ""
			if f.Line != 0 {
				line = strconv.Itoa(f.Line)
			}

			failing = append(failing, []string{
				f.Code,
				f.Fingerprint,
				e.ControlName,
				status,
				severity,
				f.Message,
				f.Job,
				reportFilePath(f.File),
				line,
				f.URL,
				"https://getplumber.io/docs/cli/issues/" + f.Code,
			})
		}
	}

	records := make([][]string, 0, 1+len(nonFailing)+len(failing))
	records = append(records, header)
	records = append(records, nonFailing...)
	records = append(records, failing...)
	return records
}

// csvStatusReason returns the human explanation for a non-failing control's row:
// the skip reason for a skipped control, the degraded reason for an error
// control, and empty for a pass (nothing to explain).
func csvStatusReason(status string, e control.ControlEntry, result *control.AnalysisResult) string {
	switch status {
	case control.StatusSkipped:
		if e.SkipReason != "" {
			return e.SkipReason
		}
		return "disabled in configuration"
	case control.StatusError:
		if result != nil && len(result.DegradedReasons) > 0 {
			return "could not verify: " + strings.Join(result.DegradedReasons, "; ")
		}
		return "could not verify"
	default:
		return ""
	}
}

// writeCSVToFile walks the provider's control catalog and writes the per-control
// CSV posture to filePath.
func writeCSVToFile(p provider.Provider, result *control.AnalysisResult, conf *configuration.Configuration, filePath string) error {
	entries := p.Controls(conf.PlumberConfig)
	control.MarkSkippedByFilter(entries, conf.ControlsFilter, conf.SkipControlsFilter)
	records := buildCSV(entries, result)

	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.WriteAll(records); err != nil {
		return fmt.Errorf("write csv records: %w", err)
	}
	if err := os.WriteFile(filePath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("write csv file: %w", err)
	}
	return nil
}
