.PHONY: build clean test embed lint vuln

# Binary name
BINARY=plumber

# Copy the shipped default config for embedding before building.
# Source is defaultConfig/.plumber.yaml — the universal baseline every
# zero-config user gets — NOT the repo-root .plumber.yaml, which is Plumber's
# own self-scan config. The two are independent artifacts (getplumber/plumber
# #352); defaultConfig/.plumber.yaml changes only via a deliberate, reviewed edit.
embed:
	@echo "# DO NOT EDIT - Generated from defaultConfig/.plumber.yaml by 'make build'" > internal/defaultconfig/default.yaml
	@cat defaultConfig/.plumber.yaml >> internal/defaultconfig/default.yaml

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
