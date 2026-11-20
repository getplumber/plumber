package cmd

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	ghauth "github.com/cli/go-gh/v2/pkg/auth"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/getplumber/plumber/configuration"
	githubpkg "github.com/getplumber/plumber/github"
	"github.com/getplumber/plumber/internal/httpcount"
)

// defaultDebugFile is where a bare --debug writes its report.
const defaultDebugFile = "plumber-debug.md"

// debugFile is the --debug report path; empty means no report.
var debugFile string

// envDebugFallback applies PLUMBER_ANALYZE_DEBUG when --debug was not
// given: a boolean turns the report on (default file) or off, anything else
// is the report path.
func envDebugFallback(cmd *cobra.Command) error {
	if cmd.Flags().Changed("debug") {
		return nil
	}
	v := strings.TrimSpace(os.Getenv(envKeys["debug"]))
	if v == "" {
		return nil
	}
	if on, err := strconv.ParseBool(v); err == nil {
		if on {
			debugFile = defaultDebugFile
		}
		return nil
	}
	debugFile = v
	return nil
}

// fetchRateLimit reads GET /rate_limit for the report; tests stub it.
var fetchRateLimit = githubpkg.FetchRateLimit

// debugCredential is one credential the run uses, named by where it came
// from, never by its value. An empty token is the anonymous lane.
type debugCredential struct{ name, token string }

// debugCredentials lists the credentials a GitHub analyze on host uses: the
// lanes' token (or anonymous), then PLUMBER_METADATA_TOKEN when set, with
// the label the report shows for each.
func debugCredentials(host string) ([]debugCredential, []string) {
	var credentials []debugCredential
	var labels []string
	if token, source := ghauth.TokenForHost(host); token != "" {
		credentials = append(credentials, debugCredential{source, token})
		labels = append(labels, "GitHub lanes: "+source)
	} else {
		credentials = append(credentials, debugCredential{"anonymous", ""})
		labels = append(labels, "GitHub lanes: none (anonymous)")
	}
	if token := strings.TrimSpace(os.Getenv(githubpkg.EnvMetadataToken)); token != "" {
		credentials = append(credentials, debugCredential{githubpkg.EnvMetadataToken, token})
		labels = append(labels, "action metadata: "+githubpkg.EnvMetadataToken)
	}
	return credentials, labels
}

// credentialNames maps the httpcount.CredentialKey of each token, under both
// schemes it can be sent with (go-gh sends "token", app tokens "Bearer"), to
// the credential's name.
func credentialNames(credentials []debugCredential) map[string]string {
	names := map[string]string{}
	for _, c := range credentials {
		if c.token == "" {
			continue
		}
		for _, scheme := range []string{"token ", "Bearer "} {
			names[httpcount.CredentialKey(scheme+c.token)] = c.name
		}
	}
	return names
}

// startGitHubDebugReport starts the --debug report of a GitHub analyze and
// returns the function that writes it, meant to be deferred. Without
// --debug both do nothing, and no request is added to the run.
//
// The report lists every GitHub request the run sent (internal/httpcount)
// and GET /rate_limit read before and after, for each credential the run
// uses (plumber#618).
func startGitHubDebugReport(conf *configuration.Configuration, mode string) func() {
	if debugFile == "" {
		return func() {}
	}
	httpcount.Default.EnableLog()
	report := httpcount.Report{
		Version: Version,
		Target:  fmt.Sprintf("%s (%s)", conf.ProjectPath, mode),
		Host:    conf.GithubAPIHost,
		Started: time.Now(),
	}
	if conf.Branch != "" {
		report.Target += ", branch " + conf.Branch
	}
	if report.Host == "" {
		report.Host = "api.github.com"
	}

	host := conf.GithubAPIHost
	if host == "" {
		host = githubDotCom
	}
	credentials, labels := debugCredentials(host)
	report.Credentials = labels
	report.CredentialNames = credentialNames(credentials)
	for _, c := range credentials {
		rl := httpcount.RateLimit{Credential: c.name}
		rl.Before, rl.BeforeErr = fetchRateLimit(conf.GithubAPIHost, c.token)
		report.RateLimits = append(report.RateLimits, rl)
	}

	return func() {
		for i, c := range credentials {
			report.RateLimits[i].After, report.RateLimits[i].AfterErr = fetchRateLimit(conf.GithubAPIHost, c.token)
		}
		report.Finished = time.Now()
		report.Snapshot = httpcount.Default.Snapshot()
		var buf bytes.Buffer
		if err := report.WriteMarkdown(&buf); err != nil {
			logrus.Warnf("debug report: %v", err)
			return
		}
		if err := os.WriteFile(debugFile, buf.Bytes(), 0o644); err != nil {
			logrus.Warnf("debug report: %v", err)
			return
		}
		fmt.Fprintf(os.Stderr, "Debug report written to: %s\n", debugFile)
	}
}
