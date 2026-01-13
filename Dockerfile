# Build stage
FROM golang:1.25-alpine AS builder

# Set working directory
WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o plumber .

# Final stage - distroless nonroot (rootless)
FROM gcr.io/distroless/static-debian12:nonroot

# Copy binary from builder
COPY --from=builder /app/plumber /plumber

# Copy default config file (the only hardcoded default)
COPY conf.r2.yaml /conf.r2.yaml

# Already running as nonroot user (65532:65532)
USER nonroot:nonroot

# Entrypoint: just the binary
# All flags (including --config) are passed by the GitLab CI component
# The default config file /conf.r2.yaml is available inside the image
# Required env var: R2_GITLAB_TOKEN
ENTRYPOINT ["/plumber"]
