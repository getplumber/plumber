package control

import (
	"reflect"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

// An untrusted expression holds only in the runs of the events whose
// payload carries its context: one case per family, and a context the
// table does not know (none: today's behaviour, every run of the job).
func TestAnExpressionHoldsOnTheEventsCarryingItsContext(t *testing.T) {
	prEvents := []string{"pull_request", "pull_request_review", "pull_request_review_comment", "pull_request_target"}
	for subject, want := range map[string][]string{
		"github.event.pull_request.title":          prEvents,
		"github.head_ref":                          {"pull_request", "pull_request_target"},
		"github.event.issue.body":                  {"issue_comment", "issues"},
		"github.event.comment.body":                {"commit_comment", "discussion_comment", "issue_comment", "pull_request_review_comment"},
		"github.event.review.body":                 {"pull_request_review"},
		"github.event.discussion.title":            {"discussion", "discussion_comment"},
		"github.event.head_commit.message":         {"push"},
		"github.event.commits[0].message":          {"push"},
		"github.event.pusher.name":                 {"push"},
		"github.event.workflow_run.head_branch":    {"workflow_run"},
		"github.event.workflow_run.head_commit.id": {"workflow_run"},
		"${{ github.event.issue.title }}":          {"issue_comment", "issues"},
	} {
		got, ok := expressionEvents(subject)
		if !ok || !reflect.DeepEqual(got, want) {
			t.Errorf("%s: events %v (%v), want %v", subject, got, ok, want)
		}
	}
	for _, subject := range []string{"github.actor", "inputs.name", "env.TITLE"} {
		if got, ok := expressionEvents(subject); ok {
			t.Errorf("%s: want no events (every run), got %v", subject, got)
		}
	}
}

// An untrusted expression saves a cache only in the runs that carry its
// context: a pull request title on a [push, pull_request_target] job
// saves nothing (the push run has no title, the pull_request_target run
// only reads), a commit message saves where the push run does, and a
// context the table does not know keeps the job's save scopes.
func TestAnExpressionsCacheScopeIsItsEventsScope(t *testing.T) {
	js := JobSituation{CacheScopes: []string{"default"}, SaveScopesByEvent: map[string][]string{"push": {"default"}, "pull_request_target": {}}}
	for subject, want := range map[string][]string{
		"github.event.pull_request.title":  nil,
		"github.event.head_commit.message": {"default"},
		"github.actor":                     {"default"},
	} {
		if got := cacheWriterScope(EntryUntrustedExpression, subject, js); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: scope %v, want %v", subject, got, want)
		}
	}
}

// The cache hop follows the same rule: a pull request title in a job
// whose push run saves the cache a release restores reaches no job
// through that cache alone; a commit message, set in that push run, does.
func TestAnExpressionWalksACacheOnlyFromTheRunsCarryingIt(t *testing.T) {
	for subject, jobs := range map[string]int{"github.event.pull_request.title": 1, "github.event.head_commit.message": 2} {
		warm := JobSituation{RefTriggers: []string{"push"}, PrivilegedTriggers: []string{"pull_request_target"}, CacheScopes: defaultScope,
			SaveScopesByEvent: map[string][]string{"push": {"default"}, "pull_request_target": {}},
			Feeds:             []string{"release"}, FeedsVia: map[string][]string{"release": {FeedCache}}}
		sit := cacheSituation(map[string]JobSituation{"ci/warm": warm})
		paths := assemblePaths([]opaengine.Finding{entryFinding("ISSUE-207", "ci/warm", subject)}, sit)
		if len(paths) != 1 || len(paths[0].Jobs) != jobs {
			t.Errorf("%s: want %d walked jobs, got %+v", subject, jobs, paths)
		}
	}
}
