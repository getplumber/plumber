package github

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/utils"
)

// scanRenovateConfig looks for the usual Renovate config names at
// the repo root, under .github/, or under .gitlab/. Returns the
// first path found or the empty string. A match here is enough to
// consider "a dependency-update tool is configured" — Plumber does
// not try to evaluate the Renovate config's correctness.
func scanRenovateConfig(rootDir string) string {
	candidates := []string{
		"renovate.json",
		"renovate.json5",
		".renovaterc",
		".renovaterc.json",
		".github/renovate.json",
		".github/renovate.json5",
		".gitlab/renovate.json",
	}
	for _, c := range candidates {
		p := filepath.Join(rootDir, c)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}

// scanSecurityPolicy returns the path of the first SECURITY.md-like
// file found at the repository root, under .github/, or under
// docs/. GitHub itself recognises those three locations for the
// disclosure-policy field on the repo UI.
func scanSecurityPolicy(rootDir string) string {
	// Case-insensitive list covering the most common spellings.
	names := []string{
		"SECURITY.md", "security.md", "Security.md",
		"SECURITY.markdown", "security.markdown",
		"SECURITY", "security",
	}
	dirs := []string{"", ".github", "docs", ".gitlab"}
	for _, d := range dirs {
		for _, n := range names {
			p := filepath.Join(rootDir, d, n)
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
				return p
			}
		}
	}
	return ""
}

// scanDockerfiles discovers Dockerfile-shaped files at the
// repository root and under common build / service directories
// (up to two levels deep), then parses each for FROM directives.
// The scan is deliberately bounded to avoid walking every
// vendored dependency: projects that keep Dockerfiles elsewhere
// can still surface them via an explicit symlink at the root.
func scanDockerfiles(rootDir string) []ir.Dockerfile {
	var out []ir.Dockerfile
	// Stage 1: root + common build dirs one level down.
	candidates := map[string]struct{}{}
	collectDockerfileCandidates(rootDir, 2, candidates)
	paths := make([]string, 0, len(candidates))
	for path := range candidates {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		df, err := parseDockerfileBases(path)
		if err != nil {
			continue
		}
		df.Path = path
		out = append(out, df)
	}
	return out
}

var dockerfileNamePattern = regexp.MustCompile(`(?i)^(Dockerfile|Containerfile)([.\-][A-Za-z0-9._-]+)?$`)

func collectDockerfileCandidates(dir string, depth int, out map[string]struct{}) {
	if depth < 0 {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() {
			// Never descend into the big drains on a typical repo.
			switch name {
			case ".git", "node_modules", "vendor", "testdata", ".terraform":
				continue
			}
			// Hidden dirs beyond .github are skipped to avoid dotfiles
			// that ship fixture Dockerfiles (e.g. .devcontainer is OK).
			if strings.HasPrefix(name, ".") && name != ".github" && name != ".devcontainer" {
				continue
			}
			collectDockerfileCandidates(filepath.Join(dir, name), depth-1, out)
			continue
		}
		if dockerfileNamePattern.MatchString(name) {
			out[filepath.Join(dir, name)] = struct{}{}
		}
	}
}

// parseDockerfileBases extracts every `FROM <image>[:tag][@digest]`
// line from a Dockerfile, preserving the line number and digest-
// pinning state. Multi-stage builds surface every stage (the
// reviewer cares about each base, not just the final one).
//
// `ARG FOO=default` statements are collected and their default
// values substituted into any `FROM` ref that references them —
// idiomatic Dockerfiles pin the digest at the top (`ARG
// GOLANG_IMAGE_TAG=1.26-bookworm@sha256:…`) and reuse the variable
// across stages. Without substitution the parser would treat those
// stages as unpinned and flag false ISSUE-706 findings.
func parseDockerfileBases(path string) (ir.Dockerfile, error) {
	f, err := os.Open(path) // #nosec G304
	if err != nil {
		return ir.Dockerfile{}, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	var bases []ir.DockerfileBase
	argVals := map[string]string{}
	fromRe := regexp.MustCompile(`(?i)^\s*FROM\s+(--platform=\S+\s+)?(\S+)(\s+AS\s+\S+)?\s*$`)
	argRe := regexp.MustCompile(`(?i)^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$`)
	varRe := regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?`)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := strings.TrimRight(sc.Text(), " \t\r")
		if m := argRe.FindStringSubmatch(line); m != nil {
			// Strip surrounding quotes if any — `ARG X="value"`.
			val := strings.Trim(m[2], `"'`)
			argVals[m[1]] = val
			continue
		}
		m := fromRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ref := m[2]
		// Resolve `${VAR}` / `$VAR` references using the ARG defaults
		// collected so far. Unknown variables stay as-is so the
		// downstream check still flags a genuinely unpinned base.
		resolved := varRe.ReplaceAllStringFunc(ref, func(match string) string {
			name := strings.Trim(match, "${}")
			if v, ok := argVals[name]; ok {
				return v
			}
			return match
		})
		// Skip build-stage aliases — after substitution the ref is
		// typically a bare word (e.g. `builder`) with no slash or
		// colon; those are caught by the policy's stage-ref heuristic.
		if strings.HasPrefix(strings.ToLower(resolved), "$") {
			continue
		}
		bases = append(bases, ir.DockerfileBase{
			Image:          resolved,
			Line:           lineNum,
			PinnedByDigest: utils.HasDigestPin(resolved),
		})
	}
	if err := sc.Err(); err != nil {
		return ir.Dockerfile{}, fmt.Errorf("scan %s: %w", path, err)
	}
	return ir.Dockerfile{Path: path, Bases: bases}, nil
}
