package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/getplumber/plumber/collector"
	"github.com/getplumber/plumber/configuration"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/sirupsen/logrus"
)

const secretDetectionTimeout = 30 * time.Second

type gitleaksReport struct {
	Description string `json:"Description"`
	RuleID      string `json:"RuleID"`
	Match       string `json:"Match"`
	Line        int    `json:"StartLine"`
	File        string `json:"File"`
}

// runSecretDetection executes gitleaks against the resolved pipeline YAML and
// returns ISSUE-309 findings. When gitleaks is not available or the control is
// disabled, an empty slice is returned.
func runSecretDetection(
	l *logrus.Entry,
	conf *configuration.Configuration,
	originData *collector.GitlabPipelineOriginData,
) []opaengine.Finding {
	cfg := conf.PlumberConfig.GetPipelineMustNotLeakSecretsInConfigConfig()
	if cfg == nil || !cfg.IsEnabled() {
		return nil
	}
	if originData == nil || originData.ConfString == "" {
		return nil
	}

	gitleaksPath := "gitleaks"
	if cfg.GitleaksPath != "" {
		gitleaksPath = cfg.GitleaksPath
	}

	tmp, err := os.CreateTemp("", "plumber-ci-*.yml")
	if err != nil {
		l.WithError(err).Warn("secret-detection: failed to create temp file")
		return nil
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.WriteString(originData.ConfString); err != nil {
		l.WithError(err).Warn("secret-detection: failed to write temp file")
		return nil
	}
	tmp.Close()

	args := []string{"detect", "--no-git", "--report-format=json", "--report-path=-", "--source", tmp.Name()}
	if cfg.GitleaksConfigPath != "" {
		args = append(args, "--config", cfg.GitleaksConfigPath)
	}

	ctx, cancel := context.WithTimeout(context.Background(), secretDetectionTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, gitleaksPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// gitleaks exits 1 when it finds secrets, not on error.
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
		} else if ctx.Err() != nil {
			l.Warn("secret-detection: gitleaks timed out")
			return nil
		} else {
			l.WithFields(logrus.Fields{
				"stderr": stderr.String(),
			}).Warn("secret-detection: gitleaks not available or failed, skipping")
			return nil
		}
	}

	var reports []gitleaksReport
	if err := json.Unmarshal(stdout.Bytes(), &reports); err != nil {
		l.WithError(err).Warn("secret-detection: failed to parse gitleaks output")
		return nil
	}

	findings := make([]opaengine.Finding, 0, len(reports))
	for _, r := range reports {
		findings = append(findings, opaengine.Finding{
			Code:     string(CodePipelineLeaksSecrets),
			Severity: string(SeverityCritical),
			Message:  fmt.Sprintf("hardcoded secret detected (%s): %s", r.RuleID, r.Description),
			Line:     r.Line,
			Data: map[string]any{
				"ruleId": r.RuleID,
				"match":  r.Match,
			},
		})
	}
	return findings
}
