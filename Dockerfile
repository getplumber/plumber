# Build stage
# golang:1.26-alpine — pinned to a digest shipping Go 1.26.6 (fixes stdlib
# advisories GO-2026-5026, GO-2026-5972, GO-2026-6089, GO-2026-6090, all High).
# Bump this digest when go.mod's `toolchain` is raised so the bundled compiler
# carries stdlib security fixes.
FROM golang:1.26-alpine@sha256:70b46548e42db77e0966aaf3619fd068734dc6c77584d526b91126504fd95816 AS builder

# Set working directory
WORKDIR /app

# The golang image pins GOTOOLCHAIN=local, which makes `go` ignore the
# `toolchain` directive in go.mod. Force auto so a go.mod toolchain bump is
# honored (downloaded) here too, matching ci.yml — otherwise the compiled
# binary keeps the base image's stdlib even after go.mod is patched.
ENV GOTOOLCHAIN=auto

# Copy go mod files first for better caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Version metadata stamped into the binary (cmd/version.go). The release
# workflow passes these as build args so `plumber version` in the published
# image reports the release, matching the ldflags used for the release
# binaries in release.yml. Plain `docker build` (ci.yml, local) keeps the
# dev defaults. Declared here, after the cacheable dependency layers, so a
# changing BUILD_DATE never invalidates `go mod download`.
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w -X github.com/getplumber/plumber/cmd.Version=${VERSION} -X github.com/getplumber/plumber/cmd.Commit=${COMMIT} -X github.com/getplumber/plumber/cmd.BuildDate=${BUILD_DATE}" -o plumber .

# Final stage - Alpine (small, has shell for CI compatibility)
# Named `runtime` so CI can target it with build-push-action's `no-cache-filter:
# runtime`, forcing the `apk upgrade` layer below to re-run on every build. Without
# that, BuildKit caches this layer (its key is the pinned base digest + the literal
# RUN command, neither of which changes between releases) and `apk upgrade` silently
# stops pulling OS security fixes, leaving published images on stale openssl/curl/git.
FROM alpine:3.22@sha256:55ae5d250caebc548793f321534bc6a8ef1d116f334f18f4ada1b2daad3251b2 AS runtime

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

# Symlink the binary onto $PATH so the bare `plumber` command resolves. The
# GitLab CI component overrides the ENTRYPOINT and runs `plumber analyze` from a
# shell, where /plumber alone is not on $PATH. `docker run` keeps using /plumber
# via the ENTRYPOINT below. /usr/local/bin may not exist on alpine, so create it.
RUN mkdir -p /usr/local/bin && ln -s /plumber /usr/local/bin/plumber

# No default config is baked into the image: the binary carries the embedded
# default (embedded by defaultConfig/embed.go), so a scan with no
# local .plumber.yaml falls back to it. Shipping a second copy at /.plumber.yaml
# was redundant and confusing (getplumber/plumber#326).

# Create non-root user for security
RUN adduser -D -u 65532 plumber
USER plumber

# ENTRYPOINT for clean Docker usage: docker run getplumber/plumber:0.1 analyze ...
# GitLab CI overrides this entrypoint to use shell for script execution
ENTRYPOINT ["/plumber"]
