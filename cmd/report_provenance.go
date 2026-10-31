package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"

	"github.com/getplumber/plumber/configuration"
)

// configFileSha256 hashes the exact bytes of the loaded config file
// (pc.FileBytes), never pc.Raw: in overlay mode (extends: plumber:default)
// Raw holds the resolved (merged) YAML, which would not match sha256sum of
// the committed file. The embedded default has no file, so it hashes to ""
// rather than to the default's bytes: the service must never mistake a
// default run for a file. builtinDefaultConfigSource ("built-in default")
// is the real sentinel loadEmbeddedDefaultConfig stamps on
// PlumberConfig.Source for that path.
func configFileSha256(pc *configuration.PlumberConfig) string {
	if pc == nil || len(pc.FileBytes) == 0 || pc.Source == builtinDefaultConfigSource {
		return ""
	}
	sum := sha256.Sum256(pc.FileBytes)
	return hex.EncodeToString(sum[:])
}

// actionsRunInfo names the GitHub Actions run from the runner environment.
// Strings, not numbers: the service compares them with certificate fields.
func actionsRunInfo() (map[string]string, bool) {
	if !strings.EqualFold(os.Getenv("GITHUB_ACTIONS"), "true") {
		return nil, false
	}
	runID, attempt := os.Getenv("GITHUB_RUN_ID"), os.Getenv("GITHUB_RUN_ATTEMPT")
	if runID == "" {
		return nil, false
	}
	// GITHUB_REPOSITORY is required to build a usable runUrl; without it, a
	// URL with an empty repo segment would be worse than no ci block at all.
	repo := os.Getenv("GITHUB_REPOSITORY")
	if repo == "" {
		return nil, false
	}
	if attempt == "" {
		attempt = "1"
	}
	server := strings.TrimRight(os.Getenv("GITHUB_SERVER_URL"), "/")
	if server == "" {
		server = "https://github.com"
	}
	return map[string]string{
		"runId":      runID,
		"runAttempt": attempt,
		"runUrl":     server + "/" + repo + "/actions/runs/" + runID + "/attempts/" + attempt,
	}, true
}
