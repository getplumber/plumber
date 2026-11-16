.PHONY: test-integration test-e2e test-e2e-github test-e2e-gitlab lint

# Run from the repository root with `make -C v1 <target>`.

# Local suite (test/local), every input that makes no backend request. No
# token, no network. A missing golden file fails its row. test/e2e has the
# e2e build tag, so it doesn't run here.
test-integration:
	go test -tags cli -count=1 ./test/...

# e2e suite (test/e2e), run against the plumber-cli-e2e fixture repository of
# each provider. It needs an exported token: GITHUB_TOKEN (or GH_TOKEN) for the
# GitHub tests, GITLAB_TOKEN for the GitLab ones, and fails without it.
# test-e2e runs both providers. Run one test with
# `go test -tags cli,e2e -run TestGitHubIssue102 ./test/e2e`. The rows run one at
# a time and a throttled row waits up to 3 minutes, so the 30-minute timeout
# replaces go test's default 10 minutes.
test-e2e:
	go test -tags cli,e2e -count=1 -timeout 30m ./test/e2e

test-e2e-github:
	go test -tags cli,e2e -count=1 -timeout 30m -run '^TestGitHub' ./test/e2e

test-e2e-gitlab:
	go test -tags cli,e2e -count=1 -timeout 30m -run '^TestGitLab' ./test/e2e

# golangci-lint v2.15.0 with v1's config. CI runs the same version and arguments
# through golangci-lint-action (.github/workflows/v1.yml); keep them in sync.
lint:
	golangci-lint run -c .golangci.yml ./...
