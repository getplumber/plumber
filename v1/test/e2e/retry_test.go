//go:build cli && e2e

package e2e

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

// throttled matches gitlab.com refusing a request for rate reasons, after the
// CLI's own retries (gitlab/retry.go). The limit is per minute, so the run is
// retried; such a run says nothing about the CLI and never reaches a golden.
var throttled = regexp.MustCompile(`429 Too Many Requests|Rate limit exceeded after \d+ retry attempts`)

// hourlyLimit matches GitHub's primary rate limit. It resets once an hour, so
// waiting a minute is useless: the row fails at once.
var hourlyLimit = regexp.MustCompile(`API rate limit exceeded`)

// runRetrying runs args in sb, and runs them again up to 3 times, a minute
// apart, while the provider throttles the run. It removes report.json before
// each attempt, so the report read afterwards comes from the last run.
func runRetrying(t *testing.T, sb *sandbox, provider string, args []string) (stdout, stderr string, code int) {
	t.Helper()
	for attempt := 0; ; attempt++ {
		if err := os.Remove(filepath.Join(sb.work, "report.json")); err != nil && !errors.Is(err, fs.ErrNotExist) {
			t.Fatal(err)
		}
		stdout, stderr, code = sb.runPlumber(t.Context(), args)
		out := stdout + stderr
		if hourlyLimit.MatchString(out) {
			t.Fatal("GitHub's hourly API rate limit is spent: rerun after it resets, nothing was compared")
		}
		if !throttled.MatchString(out) {
			return stdout, stderr, code
		}
		if attempt == 3 {
			t.Fatalf("%s kept throttling the run (rate limit): rerun later, nothing was compared\n%s",
				provider, throttled.FindString(out))
		}
		t.Logf("%s throttled the run, retrying in a minute (%d/3)", provider, attempt+1)
		select {
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		case <-time.After(time.Minute):
		}
	}
}
