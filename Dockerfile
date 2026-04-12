# Build stage
FROM golang:1.26-alpine@sha256:c2a1f7b2095d046ae14b286b18413a05bb82c9bca9b25fe7ff5efef0f0826166 AS builder

# Set working directory
WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Copy default config for embedding
RUN cp .plumber.yaml internal/defaultconfig/default.yaml

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o plumber .

# Final stage - Alpine (small, has shell for CI compatibility)
FROM alpine:3.22@sha256:55ae5d250caebc548793f321534bc6a8ef1d116f334f18f4ada1b2daad3251b2

# Upgrade base packages (including OpenSSL) and install CA certificates
RUN apk --no-cache upgrade && apk --no-cache add ca-certificates

# Copy binary from builder
COPY --from=builder /app/plumber /plumber

# Copy default config file
COPY .plumber.yaml /.plumber.yaml

# Create non-root user for security
RUN adduser -D -u 65532 plumber
USER plumber

# ENTRYPOINT for clean Docker usage: docker run getplumber/plumber:0.1 analyze ...
# GitLab CI overrides this entrypoint to use shell for script execution
ENTRYPOINT ["/plumber"]
