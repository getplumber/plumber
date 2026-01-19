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

# Final stage - Alpine (small, has shell for CI compatibility)
FROM alpine:3.21

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
