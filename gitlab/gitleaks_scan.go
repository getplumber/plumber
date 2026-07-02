// gitleaks_scan.go integrates the gitleaks secret scanner. Plumber
// does not embed gitleaks (license + binary-bloat trade-off): we
// shell out to a user-installed `gitleaks` binary, parse its JSON
// report, redact matches, and write GitleaksHit entries onto the
// pipeline IR. The rego rule policies/leaked_secrets.rego turns those
// IR entries into ISSUE-301 findings.
//
// The raw secret value never leaves this file: redactPreview replaces
// it with first-4 + "***" + last-4 (or "***" only for short matches)
// before the entry is appended to pipeline.GitleaksHits. The rego
// rule and every downstream output (terminal, JSON, SARIF, GitLab
// SAST, MR comment) see only the redacted form.
package gitlab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/sirupsen/logrus"
)

// gitleaksTimeout caps the gitleaks subprocess. A resolved pipeline
// YAML scans in milliseconds; the timeout exists to catch pathological
// inputs (a wedged binary, an enormous included file pulled by
// mistake) rather than as part of normal flow.
const gitleaksTimeout = 30 * time.Second

// defaultGitleaksBinary is the name plumber looks up on $PATH when
// the user has not set gitleaksPath explicitly.
const defaultGitleaksBinary = "gitleaks"

// gitleaksReportEntry mirrors the JSON shape from
// `gitleaks detect --report-format=json --report-path=-`. Only fields
// plumber actually surfaces are decoded; gitleaks's Author / Commit /
// Date / Email / Fingerprint / etc. are ignored.
type gitleaksReportEntry struct {
	RuleID      string `json:"RuleID"`
	Description string `json:"Description"`
	Secret      string `json:"Secret"`
	StartLine   int    `json:"StartLine"`
	File        string `json:"File"`
}

// ScanGitleaksForGitlab runs gitleaks against the resolved GitLab
// pipeline configuration carried on origin.ConfString and appends any
// hits to pipeline.GitleaksHits as redacted GitleaksHit entries. The
// raw secret value never leaves this function.
//
// No-op (returns nil, pipeline untouched) in any of:
//   - pipeline or origin is nil
//   - control is missing from .plumber.yaml or `enabled: false`
//   - origin.ConfString is empty (nothing to scan)
//   - gitleaks binary is not resolvable
//
// When gitleaks itself fails (exec error, timeout, non-1 exit) the
// failure is logged at warn level and nil is returned so the rest of
// the analyze flow continues. Matches the degraded-but-not-fatal
// contract every optional integration in plumber follows.
func ScanGitleaksForGitlab(
	l *logrus.Entry,
	conf *configuration.Configuration,
	origin *GitlabPipelineOriginData,
	pipeline *ir.NormalizedPipeline,
) error {
	if pipeline == nil || origin == nil || origin.ConfString == "" {
		return nil
	}
	cfg := conf.PlumberConfig.GetPipelineMustNotLeakSecretsInConfigConfig("gitlab")
	if cfg == nil || !cfg.IsEnabled() {
		return nil
	}
	binary, err := resolveGitleaksBinary(cfg)
	if err != nil {
		l.WithError(err).Warn("gitleaks not available; ISSUE-301 will not fire")
		pipeline.GitleaksAbstainReason = "gitleaks binary not available: " + err.Error()
		return nil
	}

	tmp, err := os.MkdirTemp("", "plumber-gitleaks-*")
	if err != nil {
		return fmt.Errorf("create gitleaks tempdir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	const logicalName = "merged-gitlab-ci.yml"
	srcPath := filepath.Join(tmp, logicalName)
	if err := os.WriteFile(srcPath, []byte(origin.ConfString), 0o600); err != nil {
		return fmt.Errorf("write gitleaks source: %w", err)
	}

	entries, err := execGitleaks(binary, cfg, tmp)
	if err != nil {
		l.WithError(err).Warn("gitleaks scan failed; ISSUE-301 will not fire")
		pipeline.GitleaksAbstainReason = "gitleaks scan failed: " + err.Error()
		return nil
	}
	for _, e := range entries {
		pipeline.GitleaksHits = append(pipeline.GitleaksHits, ir.GitleaksHit{
			RuleID:      e.RuleID,
			Description: e.Description,
			Preview:     redactPreview(e.Secret),
			File:        logicalName,
			Line:        e.StartLine,
		})
	}
	return nil
}

// ScanGitleaksForGitHub runs gitleaks against the workflow files
// under workflowsDir (typically <rootDir>/.github/workflows). Hits
// are appended to pipeline.GitleaksHits in the same redacted form as
// the GitLab path. logicalPrefix is prepended to each finding's File
// so output reads ".github/workflows/release.yml" rather than the
// absolute clone path.
func ScanGitleaksForGitHub(
	l *logrus.Entry,
	conf *configuration.Configuration,
	workflowsDir, logicalPrefix string,
	pipeline *ir.NormalizedPipeline,
) error {
	if pipeline == nil || workflowsDir == "" {
		return nil
	}
	cfg := conf.PlumberConfig.GetPipelineMustNotLeakSecretsInConfigConfig("github")
	if cfg == nil || !cfg.IsEnabled() {
		return nil
	}
	info, err := os.Stat(workflowsDir)
	if err != nil || !info.IsDir() {
		l.WithField("workflowsDir", workflowsDir).WithError(err).Warn("gitleaks: workflows dir not found; ISSUE-301 will not fire")
		pipeline.GitleaksAbstainReason = "workflows directory not found at " + workflowsDir
		return nil
	}
	binary, err := resolveGitleaksBinary(cfg)
	if err != nil {
		l.WithError(err).Warn("gitleaks not available; ISSUE-301 will not fire")
		pipeline.GitleaksAbstainReason = "gitleaks binary not available: " + err.Error()
		return nil
	}
	l.WithFields(logrus.Fields{"workflowsDir": workflowsDir, "binary": binary}).Info("gitleaks: scanning GitHub workflows")
	entries, err := execGitleaks(binary, cfg, workflowsDir)
	if err != nil {
		l.WithError(err).Warn("gitleaks scan failed; ISSUE-301 will not fire")
		pipeline.GitleaksAbstainReason = "gitleaks scan failed: " + err.Error()
		return nil
	}
	l.WithField("hitCount", len(entries)).Info("gitleaks: scan complete")
	for _, e := range entries {
		// Rewrite gitleaks's absolute File path to a repo-relative form so
		// the operator sees ".github/workflows/release.yml" rather than a
		// scratch clone path that may live anywhere on disk.
		logical := e.File
		if rel, relErr := filepath.Rel(workflowsDir, e.File); relErr == nil {
			logical = filepath.ToSlash(filepath.Join(logicalPrefix, rel))
		}
		pipeline.GitleaksHits = append(pipeline.GitleaksHits, ir.GitleaksHit{
			RuleID:      e.RuleID,
			Description: e.Description,
			Preview:     redactPreview(e.Secret),
			File:        logical,
			Line:        e.StartLine,
		})
	}
	return nil
}

// execGitleaks runs `gitleaks detect --no-git --source=<dir>` and
// returns the parsed report. gitleaks exits 1 when it finds secrets:
// that's our success case, not an error.
//
// gitleaks writes its report through Go's file I/O which on macOS
// rejects "/dev/stdout" with EACCES, so we materialise a temp file
// for --report-path and read it back. Cleanup is deferred.
func execGitleaks(binary string, cfg *configuration.SecretDetectionControlConfig, dir string) ([]gitleaksReportEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), gitleaksTimeout)
	defer cancel()

	reportFile, err := os.CreateTemp("", "plumber-gitleaks-report-*.json")
	if err != nil {
		return nil, fmt.Errorf("create gitleaks report tempfile: %w", err)
	}
	reportPath := reportFile.Name()
	_ = reportFile.Close()
	defer func() { _ = os.Remove(reportPath) }()

	args := []string{
		"detect",
		"--no-git",
		"--source", dir,
		"--report-format", "json",
		"--report-path", reportPath,
	}
	if cfg != nil && cfg.GitleaksConfigPath != "" {
		args = append(args, "--config", cfg.GitleaksConfigPath)
	}
	// binary is validated by ensureBinaryOutsideWorkspace: it is either a
	// $PATH lookup or an absolute path outside the checked-out repository,
	// never an attacker-planted file inside the analyzed workspace.
	cmd := exec.CommandContext(ctx, binary, args...) //nolint:gosec // path validated: resolved outside the analyzed workspace
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return nil, fmt.Errorf("gitleaks timed out after %s", gitleaksTimeout)
			}
			return nil, fmt.Errorf("gitleaks: %w: %s", err, strings.TrimSpace(stderr.String()))
		}
	}

	report, err := os.Open(reportPath)
	if err != nil {
		return nil, fmt.Errorf("open gitleaks report: %w", err)
	}
	defer func() { _ = report.Close() }()
	return parseGitleaksReport(report)
}

// resolveGitleaksBinary returns the path plumber should exec.
//
//   - cfg.GitleaksPath set → that path is the override. Resolvable →
//     use it; unresolvable → error. We never fall back to $PATH when
//     the user explicitly named a binary — that would silently mask a
//     misconfigured sealed-CI deploy and run a different gitleaks than
//     the operator asked for.
//   - cfg.GitleaksPath unset → look up `gitleaks` on $PATH.
//
// Returns an error when the chosen path doesn't resolve; the caller
// logs and abstains rather than failing the whole run.
func resolveGitleaksBinary(cfg *configuration.SecretDetectionControlConfig) (string, error) {
	if cfg != nil && cfg.GitleaksPath != "" {
		path, err := exec.LookPath(cfg.GitleaksPath)
		if err != nil {
			return "", fmt.Errorf("gitleaks not found at configured gitleaksPath %q: %w", cfg.GitleaksPath, err)
		}
		if err := ensureBinaryOutsideWorkspace(path); err != nil {
			return "", err
		}
		return path, nil
	}
	path, err := exec.LookPath(defaultGitleaksBinary)
	if err != nil {
		return "", fmt.Errorf("gitleaks not found on PATH: %w", err)
	}
	if err := ensureBinaryOutsideWorkspace(path); err != nil {
		return "", err
	}
	return path, nil
}

// ensureBinaryOutsideWorkspace refuses to run a gitleaks binary that resolves
// inside the analyzed workspace (the current working directory — the
// checked-out repository).
//
// SECURITY (arbitrary code execution): gitleaksPath is read from the repo's
// own .plumber.yaml. When plumber scans an untrusted branch — the canonical
// case being a fork merge-request / pull-request pipeline — that file is
// attacker-controlled, and so is anything committed to the checkout. Without
// this guard an attacker sets `gitleaksPath: ./x` (or any in-repo path),
// commits an executable `x`, and plumber runs it with the CI job's privileges
// and secrets. Executing a binary the attacker planted in the workspace is
// remote code execution, so we reject it and abstain from the scan.
//
// Legitimate configurations are unaffected: a bare command name resolved via
// $PATH, or an absolute path to a system-installed binary, both live outside
// the workspace. The analyzed repository cannot influence $PATH.
func ensureBinaryOutsideWorkspace(resolved string) error {
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("determine workspace root to validate gitleaks binary: %w", err)
	}
	absBin, err := filepath.Abs(resolved)
	if err != nil {
		return fmt.Errorf("resolve gitleaks binary path %q: %w", resolved, err)
	}
	// Resolve symlinks on both sides so a symlink planted in the checkout
	// cannot disguise an in-workspace target as an outside path.
	if real, rerr := filepath.EvalSymlinks(absBin); rerr == nil {
		absBin = real
	}
	if real, rerr := filepath.EvalSymlinks(wd); rerr == nil {
		wd = real
	}
	if pathWithin(wd, absBin) {
		return fmt.Errorf("refusing to execute gitleaks binary %q inside the analyzed workspace %q: "+
			"a repository-controlled .plumber.yaml must not select the binary plumber runs "+
			"(install gitleaks on $PATH, or set gitleaksPath to an absolute path outside the repository)", absBin, wd)
	}
	return nil
}

// pathWithin reports whether target is root itself or lies beneath it.
func pathWithin(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}

// parseGitleaksReport decodes gitleaks's JSON report. gitleaks writes
// a JSON array of entries, or nothing at all when no matches are
// found. Trailing whitespace and an empty body are valid.
func parseGitleaksReport(r io.Reader) ([]gitleaksReportEntry, error) {
	body, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read gitleaks stdout: %w", err)
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}
	var out []gitleaksReportEntry
	if err := json.Unmarshal(trimmed, &out); err != nil {
		return nil, fmt.Errorf("decode gitleaks report: %w", err)
	}
	return out, nil
}

// redactPreview replaces a raw secret string with a redacted preview.
// For matches >= 8 characters the form is "first4***last4" so an
// operator can confirm which secret matched without seeing the value.
// For shorter matches we return "***" only — even partial reveal of a
// short token is enough to recover it.
func redactPreview(secret string) string {
	if len(secret) < 8 {
		return "***"
	}
	return secret[:4] + "***" + secret[len(secret)-4:]
}
