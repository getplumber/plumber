package github

import (
	"testing"
)

// The advisory listing the known-CVE check already reads carries each
// advisory's severity: the collector keeps it, lower-cased, by GHSA id,
// next to the ids that cover the pinned version, without a second read.
// The path assembly caps an ISSUE-703 path by it. GraphQL's MODERATE
// reads as medium (storeAdvisories).
func TestAdvisorySeverityComesFromTheSameListing(t *testing.T) {
	client, loads, _ := worldClient(t, map[string]*fakeRepo{"pypa/gh-action-pypi-publish": {
		info: repoCacheEntry{stars: 900},
		advisories: []advisoryInfo{
			{GhsaID: "GHSA-low1-aaaa-bbbb", Severity: "low", VulnerableRange: "< 1.13.0", PatchedVersions: "1.13.0"},
			{GhsaID: "GHSA-old1-cccc-dddd", Severity: "high", VulnerableRange: "< 1.0.0", PatchedVersions: "1.0.0"},
		},
	}})

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
	reads := 0
	for _, reqs := range *loads {
		for _, r := range reqs {
			if r.advisories {
				reads++
			}
		}
	}
	if reads != 1 {
		t.Errorf("advisory listing read %d times, want 1", reads)
	}
}
