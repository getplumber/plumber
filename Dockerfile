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

# Copy default config for embedding
RUN cp .plumber.yaml internal/defaultconfig/default.yaml

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o plumber .

# Final stage - Alpine (small, has shell for CI compatibility)
FROM alpine:3.21@sha256:c3f8e73fdb79deaebaa2037150150191b9dcbfba68b4a46d70103204c53f4709

# Install CA certificates for HTTPS API calls
RUN apk --no-cache add ca-certificates

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
