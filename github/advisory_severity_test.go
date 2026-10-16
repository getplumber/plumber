package github

import (
	"net/http"
	"strings"
	"testing"
)

// The advisory listing the known-CVE check already reads carries each
// advisory's severity: the collector keeps it, lower-cased, by GHSA id,
// next to the ids that cover the pinned version, without a second read.
// The path assembly caps an ISSUE-703 path by it.
func TestAdvisorySeverityComesFromTheSameListing(t *testing.T) {
	advisoryReads := 0
	client := stubbedMetadataClient(t, func(r *http.Request) (string, int) {
		p := r.URL.Path
		switch {
		case strings.HasPrefix(p, "/advisories"):
			advisoryReads++
			return `[
			  {"ghsa_id":"GHSA-low1-aaaa-bbbb","severity":"LOW","vulnerabilities":[{"package":{"name":"pypa/gh-action-pypi-publish"},"vulnerable_version_range":"< 1.13.0","patched_versions":"1.13.0"}]},
			  {"ghsa_id":"GHSA-old1-cccc-dddd","severity":"high","vulnerabilities":[{"package":{"name":"pypa/gh-action-pypi-publish"},"vulnerable_version_range":"< 1.0.0","patched_versions":"1.0.0"}]}
			]`, http.StatusOK
		case strings.Count(p, "/") == 3 && strings.HasPrefix(p, "/repos/"):
			return `{"archived":false,"stargazers_count":900}`, http.StatusOK
		case strings.Contains(p, "/releases"):
			return `[]`, http.StatusOK
		}
		return `{}`, http.StatusNotFound
	})

	pipeline := pipelineWithOneAction("pypa/gh-action-pypi-publish@v1.12.4")
	enrichActionsWithClient(pipeline, client, false, nil)

	md := pipeline.Jobs[0].Uses[0].Metadata
	if md == nil {
		t.Fatal("no metadata on the action")
	}
	if len(md.Advisories) != 1 || md.Advisories[0] != "GHSA-low1-aaaa-bbbb" {
		t.Fatalf("Advisories = %v, want the one covering v1.12.4", md.Advisories)
	}
	if got := md.AdvisorySeverities; len(got) != 1 || got["GHSA-low1-aaaa-bbbb"] != "low" {
		t.Errorf("AdvisorySeverities = %v, want only GHSA-low1-aaaa-bbbb: low", got)
	}
	if advisoryReads != 1 {
		t.Errorf("advisory listing read %d times, want 1", advisoryReads)
	}
}
