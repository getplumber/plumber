.PHONY: build clean test embed lint deadcode vuln

# Binary name
BINARY=plumber

# Copy the shipped default config for embedding before building.
# Source is defaultConfig/.plumber.yaml — the universal baseline every
# zero-config user gets — NOT the repo-root .plumber.yaml, which is Plumber's
# own self-scan config. The two are independent artifacts (getplumber/plumber
# #352); defaultConfig/.plumber.yaml changes only via a deliberate, reviewed edit.
embed:
	@cp defaultConfig/.plumber.yaml internal/defaultconfig/default.yaml

# Build the binary
build: embed
	go build -o $(BINARY) .

# Build for all platforms
build-all: embed
	GOOS=linux GOARCH=amd64 go build -o $(BINARY)-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build -o $(BINARY)-linux-arm64 .
	GOOS=darwin GOARCH=amd64 go build -o $(BINARY)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build -o $(BINARY)-darwin-arm64 .
	GOOS=windows GOARCH=amd64 go build -o $(BINARY)-windows-amd64.exe .

# Run tests
test: embed
	go test ./...

# Lint (mirrors CI configuration — requires golangci-lint v2+)
lint: embed
	golangci-lint run ./...

# Dead code check (mirrors CI). Whole-program reachability from main:
# catches unreachable functions the `unused` linter can't see (exported
# identifiers, and code kept alive only by its own tests). The command
# always exits 0, so fail on any output. The tool is built from an
# immutable commit pin (v0.30.0) verified by sum.golang.org; bump the
# hash and this version note together.
deadcode: embed
	@out=$$(go run golang.org/x/tools/cmd/deadcode@09747cdf594a7924dcecb506312be3bd6e437962 ./...); \
	if [ -n "$$out" ]; then echo "$$out"; echo "deadcode: unreachable functions found"; exit 1; fi

# Vulnerability scan. First run mirrors CI (reachability: what our code can
# actually reach). Second run is module-level — matches OpenSSF Scorecard /
# osv-scanner, catching vulnerable dependency versions even when unreachable.
vuln: embed
	go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...
	go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 -scan module

# Clean build artifacts
clean:
	rm -f $(BINARY) $(BINARY)-*
	rm -f internal/defaultconfig/default.yaml

# Run the binary (for development)
run: embed
	go run .

# Install locally
install: build
	sudo mv $(BINARY) /usr/local/bin/
