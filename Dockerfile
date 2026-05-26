# Build stage
FROM golang:1.26-alpine@sha256:91eda9776261207ea25fd06b5b7fed8d397dd2c0a283e77f2ab6e91bfa71079d AS builder

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

# Upgrade base packages (including OpenSSL) and install CA certificates +
# git. Plumber shells out to `git` for auto-detection of the remote URL,
# repo root and HEAD SHA when analysing a local clone (see
# utils/gitremote.go). Without it, ad-hoc `docker run` invocations against
# a mounted working tree silently degrade and the user has to pass every
# coordinate (--gitlab-url / --github-url / --project / --branch)
# explicitly. The added layer is ~5 MB.
RUN apk --no-cache upgrade && apk --no-cache add ca-certificates git

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
