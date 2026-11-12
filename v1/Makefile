.PHONY: test-integration lint

# Run from the repository root with `make -C v1 <target>`.

# CLI suite: every input that makes no backend request. No token, no network.
# A missing golden file fails its row.
test-integration:
	go test -tags cli -count=1 ./test

# golangci-lint v2.15.0 with v1's config. CI runs the same version and arguments
# through golangci-lint-action (.github/workflows/v1.yml); keep them in sync.
lint:
	golangci-lint run -c .golangci.yml ./...
