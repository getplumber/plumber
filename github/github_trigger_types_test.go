package github

import (
	"reflect"
	"testing"
)

// TestGitHubTriggerTypes pins that on.<event>.types lands on every job of
// the workflow as Job.TriggerTypes, keyed by event name, the input
// ir.ClassifyGates reads to decide which event actions an outsider can
// produce; an event with no types: filter, and the string and list forms
// of on:, carry no entry (every type fires).
func TestGitHubTriggerTypes(t *testing.T) {
	wf := `
name: ci
on:
  pull_request_target:
    types: [labeled]
  issue_comment:
    types: created
  push:
    branches: [main]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`
	jobs, err := parseGitHubWorkflowJobs([]byte(wf), "", ".github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{"pull_request_target": {"labeled"}, "issue_comment": {"created"}}
	if got := jobs[0].TriggerTypes; !reflect.DeepEqual(got, want) {
		t.Errorf("TriggerTypes = %v, want %v", got, want)
	}

	bare := `
name: ci
on: [pull_request_target, push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`
	jobs, err = parseGitHubWorkflowJobs([]byte(bare), "", ".github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	if got := jobs[0].TriggerTypes; got != nil {
		t.Errorf("TriggerTypes = %v, want none", got)
	}
}
