# TPM CLI

A command-line tool for checking the compliance of GitLab repositories against a defined set of controls.

## Requirements

- Go 1.25 or later

## Installation

```bash
# Clone the repository
git clone https://github.com/r2devops/tpm-cli.git
cd tpm-cli

# Install dependencies
go mod download

# Build the binary
go build -o tpm .
```

## Usage

### Commands

| Command   | Description                                      |
|-----------|--------------------------------------------------|
| `version` | Print version information                        |

### Global Flags

| Flag            | Short | Description                          |
|-----------------|-------|--------------------------------------|
| `--verbose`     | `-v`  | Enable verbose output                |

## Development

```bash
# Run tests
go test ./...

# Build with version info
go build -ldflags "-X github.com/r2devops/tpm-cli/cmd.Version=1.0.0 -X github.com/r2devops/tpm-cli/cmd.Commit=$(git rev-parse HEAD)" -o tpm .
```

## License

TO DEFINE
