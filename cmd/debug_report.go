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

	// Name each credential by where it came from, never by its value.
	host := conf.GithubAPIHost
	if host == "" {
		host = githubDotCom
	}
	type credential struct{ name, token string }
	var credentials []credential
	if token, source := ghauth.TokenForHost(host); token != "" {
		credentials = append(credentials, credential{source, token})
		report.Credentials = append(report.Credentials, "GitHub lanes: "+source)
	} else {
		credentials = append(credentials, credential{"anonymous", ""})
		report.Credentials = append(report.Credentials, "GitHub lanes: none (anonymous)")
	}
	if token := strings.TrimSpace(os.Getenv(githubpkg.EnvMetadataToken)); token != "" {
		credentials = append(credentials, credential{githubpkg.EnvMetadataToken, token})
		report.Credentials = append(report.Credentials, "action metadata: "+githubpkg.EnvMetadataToken)
	}
	report.CredentialNames = map[string]string{}
	for _, c := range credentials {
		if c.token != "" {
			for _, scheme := range []string{"token ", "Bearer "} {
				report.CredentialNames[httpcount.CredentialKey(scheme+c.token)] = c.name
			}
		}
		rl := httpcount.RateLimit{Credential: c.name}
		rl.Before, rl.BeforeErr = githubpkg.FetchRateLimit(conf.GithubAPIHost, c.token)
		report.RateLimits = append(report.RateLimits, rl)
	}

	return func() {
		for i, c := range credentials {
			report.RateLimits[i].After, report.RateLimits[i].AfterErr = githubpkg.FetchRateLimit(conf.GithubAPIHost, c.token)
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
