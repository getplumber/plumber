package utils

import (
	"slices"
	"testing"
)

func TestCacheWriteRiskyTriggers(t *testing.T) {
	cases := []struct {
		mode     string
		triggers []string
		want     []string
	}{
		{"write", []string{"issue_comment"}, []string{"issue_comment"}},
		{"write-only", []string{"push", "workflow_run", "pull_request_target"}, []string{"pull_request_target", "workflow_run"}},
		{"write", []string{"push", "workflow_dispatch", "repository_dispatch", "delete", "registry_package", "page_build", "schedule"}, nil},
		{"write", []string{"pull_request", "release", "merge_group", "pull_request_review", "pull_request_review_comment"}, nil},
		{"read", []string{"issue_comment"}, nil},
		{"none", []string{"issue_comment"}, nil},
		{"", []string{"issue_comment"}, nil},
		{"write", nil, nil},
	}
	for _, c := range cases {
		if got := CacheWriteRiskyTriggers(c.mode, c.triggers); !slices.Equal(got, c.want) {
			t.Errorf("CacheWriteRiskyTriggers(%q, %v) = %v, want %v", c.mode, c.triggers, got, c.want)
		}
	}
}

func TestCacheWriteExempt(t *testing.T) {
	workflows := []string{"triage.yml", "deploy-*.yml"}
	jobs := []string{"ci/warm", "bot/*"}
	cases := []struct {
		job, file string
		want      bool
	}{
		{"triage/label", ".github/workflows/triage.yml", true},
		{"deploy-prod/run", "/abs/repo/.github/workflows/deploy-prod.yml", true},
		{"ci/warm", ".github/workflows/ci.yml", true},
		{"bot/reply", ".github/workflows/bot.yml", true},
		{"ci/build", ".github/workflows/ci.yml", false},
		{"triage2/label", ".github/workflows/triage2.yml", false},
		{"x/y", "", false},
	}
	for _, c := range cases {
		if got := CacheWriteExempt(workflows, jobs, c.job, c.file); got != c.want {
			t.Errorf("CacheWriteExempt(%q, %q) = %v, want %v", c.job, c.file, got, c.want)
		}
	}
	if CacheWriteExempt(nil, nil, "triage/label", ".github/workflows/triage.yml") {
		t.Error("no pattern exempts nothing")
	}
}
