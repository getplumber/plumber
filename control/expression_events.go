package control

import (
	"regexp"
	"sort"
	"strings"
)

// expressionContexts maps the event payload an untrusted expression reads
// to the events whose payload carries it (GitHub's webhook payloads): the
// expression's value is set only in the runs of those events, empty in
// every other run of the job. github.event.pull_request is carried by the
// pull request events and pull_request_target (a workflow_run run reads
// its pull requests only through github.event.workflow_run), github.head_ref
// by pull_request and pull_request_target alone.
var expressionContexts = []struct {
	prefix string
	events []string
}{
	{"github.event.pull_request.", []string{"pull_request", "pull_request_review", "pull_request_review_comment", "pull_request_target"}},
	{"github.head_ref", []string{"pull_request", "pull_request_target"}},
	{"github.event.issue.", []string{"issue_comment", "issues"}},
	{"github.event.comment.", []string{"commit_comment", "discussion_comment", "issue_comment", "pull_request_review_comment"}},
	{"github.event.review.", []string{"pull_request_review"}},
	{"github.event.discussion.", []string{"discussion", "discussion_comment"}},
	{"github.event.head_commit.", []string{"push"}},
	{"github.event.commits", []string{"push"}},
	{"github.event.pusher.", []string{"push"}},
	{"github.event.workflow_run.", []string{"workflow_run"}},
}

// expressionContext finds each context reference in an expression subject.
var expressionContext = regexp.MustCompile(`github\.[A-Za-z0-9_.\[\]'"*-]+`)

// expressionEvents is the events in whose runs the expression subject has
// a value, sorted, the union over the contexts it reads; ok is false when
// one of them is not in expressionContexts (github.actor, inputs.*, env.*):
// the expression then holds in every run of its job.
func expressionEvents(subject string) (events []string, ok bool) {
	refs := expressionContext.FindAllString(subject, -1)
	if len(refs) == 0 {
		return nil, false
	}
	set := map[string]bool{}
	for _, ref := range refs {
		found := false
		for _, c := range expressionContexts {
			if strings.HasPrefix(ref, c.prefix) || ref+"." == c.prefix {
				for _, e := range c.events {
					set[e] = true
				}
				found = true
				break
			}
		}
		if !found {
			return nil, false
		}
	}
	for e := range set {
		events = append(events, e)
	}
	sort.Strings(events)
	return events, true
}

// expressionSaveScopes is the scopes the runs an untrusted expression is
// set in save the cache under (JobSituation.SaveScopesByEvent over
// expressionEvents), nil when none of them saves; the job's own save
// scopes when the expression's events are not known or the situation does
// not split them by event.
func expressionSaveScopes(subject string, js JobSituation) []string {
	events, ok := expressionEvents(subject)
	if !ok {
		return js.CacheScopes
	}
	if scopes, split := eventSaveScopes(events, js); split {
		return scopes
	}
	return js.CacheScopes
}

// eventSaveScopes is the scopes the runs of events save the cache under
// (JobSituation.SaveScopesByEvent), sorted, nil when none of them saves;
// ok is false when the situation does not split the job's scopes by event
// (GitLab, a job carrying no trigger) or no event is given, and the
// caller falls back to the job's union of scopes.
func eventSaveScopes(events []string, js JobSituation) (scopes []string, ok bool) {
	if len(js.SaveScopesByEvent) == 0 || len(events) == 0 {
		return nil, false
	}
	set := map[string]bool{}
	for _, e := range events {
		for _, sc := range js.SaveScopesByEvent[e] {
			set[sc] = true
		}
	}
	if len(set) == 0 {
		return nil, true
	}
	return sortedKeys(set), true
}
