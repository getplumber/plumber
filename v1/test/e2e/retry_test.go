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

// throttled matches a provider refusing a request for rate reasons, after the
// CLI's own retries (gitlab/retry.go): gitlab.com's per-minute limit, or
// GitHub's secondary rate limit on a burst. Both clear within minutes, so the
// run is retried; such a run says nothing about the CLI and never reaches a
// golden.
var throttled = regexp.MustCompile(`429 Too Many Requests|Rate limit exceeded after \d+ retry attempts|secondary rate limit`)

// hourlyLimit matches GitHub's primary rate limit. It resets once an hour, so
// waiting a minute is useless: the row fails at once.
var hourlyLimit = regexp.MustCompile(`API rate limit exceeded`)

// retryWait is the wait between two runs of a throttled call.
const retryWait = time.Minute

// runRetrying runs args in sb, and runs them again up to 3 times, a minute
// apart, while the provider throttles the run. It removes report.json before
// each attempt, so the report read afterwards comes from the last run. A run
// that wrote its report and exited 0 or 1 (findings, or a blocked gate) is
// never rerun, even when a request on the way was throttled.
func runRetrying(t *testing.T, sb *sandbox, provider string, args []string) (stdout, stderr string, code int) {
	t.Helper()
	report := filepath.Join(sb.work, "report.json")
	for attempt := 0; ; attempt++ {
		if err := os.Remove(report); err != nil && !errors.Is(err, fs.ErrNotExist) {
			t.Fatal(err)
		}
		stdout, stderr, code = sb.runPlumber(t.Context(), args)
		if _, err := os.Stat(report); err == nil && (code == 0 || code == 1) {
			return stdout, stderr, code
		}
		out := stdout + stderr
		if provider == providerGitHub && hourlyLimit.MatchString(out) {
			t.Fatal("GitHub's hourly API rate limit is spent: rerun after it resets, nothing was compared")
		}
		if !throttled.MatchString(out) {
			return stdout, stderr, code
		}
		if attempt == 3 {
			t.Fatalf("%s kept throttling the run (rate limit): rerun later, nothing was compared\n%s",
				provider, throttled.FindString(out))
		}
		// go test -timeout panics instead of cancelling t.Context(), so stop
		// here while there is still time for the wait and one more run.
		if deadline, ok := t.Deadline(); ok && time.Until(deadline) < 2*retryWait {
			t.Fatalf("%s throttled the run and the go test -timeout is too close to wait: rerun later, nothing was compared", provider)
		}
		t.Logf("%s throttled the run, retrying in a minute (%d/3)", provider, attempt+1)
		time.Sleep(retryWait)
	}
}
