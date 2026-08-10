.PHONY: build clean test lint deadcode vuln

# Binary name
BINARY=plumber

# Build the binary
build:
	go build -o $(BINARY) .

# Build for all platforms
build-all:
	GOOS=linux GOARCH=amd64 go build -o $(BINARY)-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build -o $(BINARY)-linux-arm64 .
	GOOS=darwin GOARCH=amd64 go build -o $(BINARY)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build -o $(BINARY)-darwin-arm64 .
	GOOS=windows GOARCH=amd64 go build -o $(BINARY)-windows-amd64.exe .

# Run tests
test:
	go test ./...

# Lint (mirrors CI configuration — requires golangci-lint v2+)
lint:
	golangci-lint run ./...

# Dead code check (mirrors CI). Whole-program reachability from main:
# catches unreachable functions the `unused` linter can't see (exported
# identifiers, and code kept alive only by its own tests). The command
# always exits 0, so fail on any output. The tool is built from an
# immutable commit pin (v0.30.0) verified by sum.golang.org; bump the
# hash and this version note together.
#
# finding/identity is exempt: it publishes the finding-identity recipe for
# consumers outside this module (getplumber/plumber #403), so reachability
# from our own main says nothing about whether its API is used. Its surface
# is pinned by finding/identity/identity_test.go instead. Keep the exemption
# to that one package.
#
# The analyzer runs on its own line, under set -e, and only its output is
# filtered. Piping it straight into `grep -v ... || true` would make a broken
# run (module download failure, toolchain mismatch, a package that does not
# compile) indistinguishable from a clean one: the `|| true` needed for the
# healthy path, where grep suppresses every line, would swallow the tool's own
# failure and report success with the safety net switched off.
deadcode:
	@set -e; \
	raw=$$(go run golang.org/x/tools/cmd/deadcode@09747cdf594a7924dcecb506312be3bd6e437962 ./...); \
	out=$$(printf '%s\n' "$$raw" | grep -v '^finding/identity/' || true); \
	if [ -n "$$out" ]; then echo "$$out"; echo "deadcode: unreachable functions found"; exit 1; fi

# Vulnerability scan. First run mirrors CI (reachability: what our code can
# actually reach). Second run is module-level — matches OpenSSF Scorecard /
# osv-scanner, catching vulnerable dependency versions even when unreachable.
vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...
	go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 -scan module

# Clean build artifacts
clean:
	rm -f $(BINARY) $(BINARY)-*

# Run the binary (for development)
run:
	go run .

# Install locally
install: build
	sudo mv $(BINARY) /usr/local/bin/
