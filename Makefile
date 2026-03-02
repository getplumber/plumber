.PHONY: build clean test embed lint

# Binary name
BINARY=plumber

# Copy the default config for embedding before building
embed:
	@echo "# DO NOT EDIT - Generated from .plumber.yaml by 'make build'" > internal/defaultconfig/default.yaml
	@cat .plumber.yaml >> internal/defaultconfig/default.yaml

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
