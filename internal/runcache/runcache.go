// Package runcache keeps the JSON report of the last analysis of each
// project in the user cache directory, so a later command can read it back
// without running the analysis again.
//
// Layout, under the root (<user cache dir>/plumber/runs):
//
//	<provider>/<owner>/<repo>.json  a remote or detected project
//	local/<hash>.json               a local analysis with no project path,
//	                                the hash of its absolute working directory
//	last                            the path, relative to the root, of the
//	                                most recently written report
package runcache

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// lastFile names the pointer to the most recently written report.
const lastFile = "last"

// Root is the cache root under a user cache directory.
func Root(userCacheDir string) string {
	return filepath.Join(userCacheDir, "plumber", "runs")
}

// Key is where a run's report goes, relative to the root, in slash form:
// <provider>/<project segments>.json for a project, local/<hash>.json
// with no project, the hash read off cwd. Every segment is sanitized
// (segment), so a key never leaves the root.
func Key(provider, project, cwd string) string {
	if rel := projectKey(project); rel != "" {
		return segment(provider) + "/" + rel
	}
	sum := sha256.Sum256([]byte(cwd))
	return "local/" + hex.EncodeToString(sum[:])[:16] + ".json"
}

// projectKey is a project path as cache segments ending in ".json"; ""
// when it has no segment.
func projectKey(project string) string {
	var segs []string
	for _, s := range strings.Split(project, "/") {
		if s != "" {
			segs = append(segs, segment(s))
		}
	}
	if len(segs) == 0 {
		return ""
	}
	return strings.Join(segs, "/") + ".json"
}

// segment is s lower-cased, every character outside [a-z0-9._-] replaced
// by "-"; "", "." and ".." read "_".
func segment(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			return r
		}
		return '-'
	}, strings.ToLower(s))
	if s == "" || s == "." || s == ".." {
		return "_"
	}
	return s
}

// Write stores payload at rel under root, then points last at it. Both
// writes go through a temporary file renamed into place, readable by the
// user alone.
func Write(root, rel string, payload []byte) error {
	local := filepath.FromSlash(rel)
	if !filepath.IsLocal(local) {
		return fmt.Errorf("run cache path %q is outside the cache", rel)
	}
	if err := writeAtomic(filepath.Join(root, local), payload); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(root, lastFile), []byte(path.Clean(rel)))
}

func writeAtomic(dst string, payload []byte) error {
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".run-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.Write(payload)
	cerr := tmp.Close()
	if werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Chmod(name, 0o600)
	}
	if werr == nil {
		werr = os.Rename(name, dst)
	}
	if werr != nil {
		_ = os.Remove(name)
	}
	return werr
}

// Last is the path of the most recently written report; an error wrapping
// fs.ErrNotExist when no run was cached.
func Last(root string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(root, lastFile))
	if err != nil {
		return "", err
	}
	rel := filepath.FromSlash(strings.TrimSpace(string(raw)))
	if !filepath.IsLocal(rel) {
		return "", fmt.Errorf("run cache pointer %s names a path outside the cache", filepath.Join(root, lastFile))
	}
	return filepath.Join(root, rel), nil
}

// Find is the cached report of project, under provider, or under the one
// provider that has it when provider is empty; an error wrapping
// fs.ErrNotExist when none has it.
func Find(root, provider, project string) (string, error) {
	rel := projectKey(project)
	if rel == "" {
		return "", fmt.Errorf("no project path in %q", project)
	}
	var providers []string
	if provider != "" {
		providers = []string{segment(provider)}
	} else {
		entries, _ := os.ReadDir(root)
		for _, e := range entries {
			if e.IsDir() && e.Name() != "local" {
				providers = append(providers, e.Name())
			}
		}
	}
	var found []string
	for _, p := range providers {
		if st, err := os.Stat(filepath.Join(root, p, filepath.FromSlash(rel))); err == nil && st.Mode().IsRegular() {
			found = append(found, p)
		}
	}
	sort.Strings(found)
	switch len(found) {
	case 0:
		where := filepath.Join(root, "<provider>", filepath.FromSlash(rel))
		if provider != "" {
			where = filepath.Join(root, segment(provider), filepath.FromSlash(rel))
		}
		return "", fmt.Errorf("no cached run of %s at %s: %w", project, where, fs.ErrNotExist)
	case 1:
		return filepath.Join(root, found[0], filepath.FromSlash(rel)), nil
	}
	return "", fmt.Errorf("several providers have a cached run of %s (%s): add --provider", project, strings.Join(found, ", "))
}
