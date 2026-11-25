.PHONY: test-integration test-integration-v0 test-integration-v1 golden-diff test-e2e test-e2e-github test-e2e-gitlab lint

# Run from the repository root with `make -C v1 <target>`.

# Local suites, every input that makes no backend request: test/v0/local runs
# the old CLI, test/v1/local the rewrite. No token, no network. A missing
# golden file fails its row. test/v0/e2e has the e2e build tag, so it doesn't
# run here. test-integration runs both in one go test call, so they build
# and run in parallel; CI runs each in its own job.
test-integration:
	go test -tags cli -count=1 ./test/v0/local ./test/v1/local

test-integration-v0:
	go test -tags cli -count=1 ./test/v0/local

test-integration-v1:
	go test -tags cli -count=1 ./test/v1/local

# docs/golden-diff.md: how each golden of test/v1/local differs from its
# namesake in test/v0/local. Run it after changing a golden of either suite;
# CI fails when the committed file is out of date. A changed or new v1 golden
# needs a note in internal/tools/goldendiff/notes.go. Deleted at the switch
# (step 15 of docs/project-structure.md), with test/v0 and the tool.
golden-diff:
	go run ./internal/tools/goldendiff

# e2e suite (test/v0/e2e), run against the plumber-cli-e2e fixture repository of
# each provider. It needs an exported token: GITHUB_TOKEN (or GH_TOKEN) for the
# GitHub tests, GITLAB_TOKEN for the GitLab ones, and fails without it. The
# settings rows also need the token to read the fixture's protection and
# settings (AGENTS.md, "e2e rows"). test-e2e runs both providers. Run one test
# with `go test -tags cli,e2e -run TestGitHubIssue102 ./test/v0/e2e`. The rows run
# one at a time and a throttled row waits up to 3 minutes, so each provider
# gets 30 minutes instead of go test's default 10, and test-e2e 60.
test-e2e:
	go test -tags cli,e2e -count=1 -timeout 60m ./test/v0/e2e

test-e2e-github:
	go test -tags cli,e2e -count=1 -timeout 30m -run '^TestGitHub' ./test/v0/e2e

test-e2e-gitlab:
	go test -tags cli,e2e -count=1 -timeout 30m -run '^TestGitLab' ./test/v0/e2e

# golangci-lint v2.15.0 with v1's config. CI runs the same version and arguments
# through golangci-lint-action (.github/workflows/v1.yml); keep them in sync.
lint:
	golangci-lint run -c .golangci.yml ./...
