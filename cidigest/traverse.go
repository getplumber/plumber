package cidigest

import (
	"errors"
	"fmt"
	"path"
	"strings"

	"gopkg.in/yaml.v3"
)

// MaxFiles bounds the number of distinct files a single Traverse call will
// visit, root included (ADR-0034 rule 1: "capped at 50 files"). It exists
// to keep a maliciously deep or wide local-include graph from turning one
// digest computation into an unbounded number of fetches. Traversal is
// breadth-first in include-list order, so which files fall inside the cap
// is deterministic across identical inputs (a requirement of the
// wire-stable digest), not an artifact of map iteration or scheduling.
//
// Exceeding this cap does not silently stop discovery and return whatever
// was found so far: it ABORTS the whole computation (see ErrTooManyFiles).
// A truncation rule would be a false-verdict path: two configs identical in
// their first 50 traversal files but differing beyond the cap would compare
// digest-equal.
const MaxFiles = 50

// ErrTooManyFiles is the sentinel Traverse's returned error wraps when
// traversal would visit more than MaxFiles distinct files (ADR-0034 rule
// 1b). This is deliberately an ABORT, not a truncation: a digest computed
// over only the first MaxFiles files would compare equal for two configs
// that are identical up to the cap but differ beyond it, silently
// evaluating merged-yaml-dependent controls against the wrong config on
// exactly the divergent-branch case ADR-0034 exists to protect. Callers
// must treat this exactly like any other Traverse abort: no digest is
// produced, and a MISSING digest is treated as ALWAYS-DIVERGENT rather than
// trusted as a valid comparison key.
var ErrTooManyFiles = errors.New("cidigest: traversal exceeds the file cap")

// ErrNotFound is the sentinel a fetch function passed to Traverse must
// return for a referenced local include (or the root) that genuinely does
// not exist. Traverse treats this, and only this, as the ADR-0034 rule 1
// "does not exist" case: the path is recorded as Absent and traversal
// continues.
//
// Any other error is treated as an infra failure, not a content fact: a
// network timeout, a rate limit, or a transient provider error must never
// be silently folded into ABSENT, because that would produce a
// valid-looking digest over data that was never actually observed.
// Traverse aborts on any error other than ErrNotFound (see Traverse's doc
// comment) - which also includes ErrTooManyFiles (ADR-0034 rule 1b):
// exceeding MaxFiles is classified the same way a read failure is, callers
// must treat an aborted traversal as "resolution unavailable" (ADR-0034
// rule 2: "the anchor is stored WITHOUT a digest"), not as a degraded but
// otherwise valid digest.
//
// Fetch implementations should use errors.Is / wrap so errors.Is(err,
// ErrNotFound) is true for a genuine not-found; Traverse checks with
// errors.Is, not equality, so a wrapped ErrNotFound is still recognized.
var ErrNotFound = errors.New("cidigest: file not found")

// Traverse performs the static local-include scan ADR-0034 rule 1 defines,
// starting at root: it recursively follows every `include: local` entry
// (the map form, the bare-string shorthand, and both forms mixed into an
// array), using fetch to obtain each file's content. Remote, template,
// component and cross-project include entries are deliberately NOT
// followed: their content is not part of the digest; only their textual
// reference in the including file is, and that reference is already part
// of the including file's own content once hashed.
//
// The scan is cycle-safe: a path already visited is never re-fetched or
// re-queued, so an include cycle (A includes B, B includes A) terminates.
//
// If traversal would need to visit a distinct, not-yet-visited path after
// MaxFiles have already been recorded, Traverse ABORTS the whole
// computation and returns (nil, err) with err wrapping ErrTooManyFiles - it
// does not stop discovery and return a truncated, first-MaxFiles-only file
// map.
//
// fetch's error return is part of the contract, not incidental (ADR-0034
// rule 2): return ErrNotFound (or an error that wraps it, checked with
// errors.Is) for a path that genuinely does not exist, including the
// degenerate case where root itself is missing; Traverse records that
// path as Absent and continues. Any OTHER error aborts the whole
// traversal immediately: Traverse returns (nil, err) with err wrapping
// the failing path, so an infra failure never produces a digest that
// looks valid but was computed over incomplete data.
//
// The returned map, when err is nil, uses the same path keys fetch is
// called with and is suitable as-is for Compute.
func Traverse(root string, fetch func(path string) ([]byte, error)) (map[string][]byte, error) {
	files := make(map[string][]byte)
	visited := make(map[string]bool)
	queue := []string{normalizeIncludePath(root)}

	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		if visited[p] {
			continue
		}
		// Cap check happens HERE, right before committing to visit a NEW
		// (not-yet-visited) path - not as the loop condition above - so a
		// path already visited (a duplicate queue entry from a diamond
		// include, say) never trips the cap merely by being re-popped.
		// Exactly MaxFiles files never aborts; the (MaxFiles+1)th distinct
		// file always does (ADR-0034 rule 1b).
		if len(files) >= MaxFiles {
			return nil, fmt.Errorf("cidigest: traversal exceeds the %d-file cap at %q: %w", MaxFiles, p, ErrTooManyFiles)
		}
		visited[p] = true

		content, err := fetch(p)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				files[p] = Absent
				continue
			}
			return nil, fmt.Errorf("cidigest: fetch %q: %w", p, err)
		}
		files[p] = content

		for _, inc := range localIncludePaths(content) {
			np := normalizeIncludePath(inc)
			if !visited[np] {
				queue = append(queue, np)
			}
		}
	}

	return files, nil
}

// normalizeIncludePath canonicalizes a local include target so that two
// spellings of the same file (e.g. a leading slash, a redundant "./")
// converge on one path: one visited entry, one map key, one fetch call.
// GitLab CI local include paths are repo-relative regardless of the host
// OS, so this uses the slash-based "path" package, never "path/filepath".
func normalizeIncludePath(p string) string {
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return p
	}
	return path.Clean(p)
}

// localIncludePaths extracts every LOCAL include target from a CI config's
// top-level `include:` key, in the order they appear. It recognizes the
// bare-string shorthand (a single string, or a string inside the array
// form), the explicit map form ({local: path}), and that same map form
// given directly (not inside an array) as the whole `include:` value; any
// other include entry (remote, template, component, project, or a
// local-less map) is left alone, Traverse never fetches it. Unparsable
// YAML yields no local includes rather than an error: a file that fails to
// parse still has real bytes to digest, it simply cannot be traversed
// further, which mirrors how a fetch failure degrades (Absent), not how a
// hard error would.
func localIncludePaths(content []byte) []string {
	var doc map[string]interface{}
	if err := yaml.Unmarshal(content, &doc); err != nil {
		return nil
	}
	raw, ok := doc["include"]
	if !ok {
		return nil
	}

	var entries []interface{}
	if arr, ok := raw.([]interface{}); ok {
		entries = arr
	} else {
		entries = []interface{}{raw}
	}

	var out []string
	for _, e := range entries {
		switch entry := e.(type) {
		case string:
			out = append(out, entry)
		case map[string]interface{}:
			if local, ok := entry["local"]; ok {
				if s, ok := local.(string); ok {
					out = append(out, s)
				}
			}
			// A map entry without "local" (remote/template/component/
			// project) is intentionally ignored: not followed.
		}
	}
	return out
}
