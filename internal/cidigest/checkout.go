package cidigest

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// DefaultRootPath is the CI config file GitLab uses when a project sets no
// ci_config_path.
const DefaultRootPath = ".gitlab-ci.yml"

// maxFileBytes caps a single file read during traversal. It matches the
// limit the local CI config read already uses (control/task.go), so a file
// this package refuses to read is one the analyzer would refuse too.
//
// Exceeding it is a READ FAILURE, not an Absent: an over-cap file has real
// content that would have changed the digest, and recording it as absent
// would fabricate a digest over bytes never read. The abort propagates as
// "no digest", which callers treat as always-divergent - the safe direction.
const maxFileBytes = 2 << 20 // 2 MiB

// ErrExternalRootConfig reports that the project's ci_config_path points at
// a file in ANOTHER project ("path/file.yml@group/project"). The root of the
// include graph is then not in this checkout at all, so no digest over the
// checkout can describe what GitLab would merge. Callers treat it like any
// other abort: no digest, always-divergent, resolve through the platform.
var ErrExternalRootConfig = errors.New("cidigest: ci_config_path points at another project")

// RootPath resolves the traversal root from a project's ci_config_path
// setting: the setting itself when set, DefaultRootPath otherwise.
//
// GitLab's ci_config_path has three forms. A plain repo-relative path is
// the normal case. A path carrying a "@group/project" suffix names a config
// in a DIFFERENT project - the include graph's root is not in this checkout,
// so RootPath returns ErrExternalRootConfig rather than digesting a file
// that is not the real root. A "?ref=" query suffix pins a ref on such an
// external config and only ever appears alongside the "@" form, so it is
// covered by the same check.
func RootPath(ciConfigPath string) (string, error) {
	p := strings.TrimSpace(ciConfigPath)
	if p == "" {
		return DefaultRootPath, nil
	}
	if strings.Contains(p, "@") {
		return "", fmt.Errorf("%w: %q", ErrExternalRootConfig, p)
	}
	return p, nil
}

// FetchFromDir returns a Traverse fetch function that reads repo-relative
// paths from the checkout rooted at dir - the CLI's side of the shared
// digest, where the platform reads the same paths through the git host's
// API.
//
// The semantics each case must match on both sides:
//
//   - A path that is not a clean repo-relative path - absolute, or still
//     escaping the root with "../" after normalization - is NEVER resolved
//     against the filesystem and returns ErrNotFound, so it contributes
//     ABSENT. The git host answers 404 for the same paths (its file API
//     addresses repo-relative paths only), so both sides agree on the file
//     set. Refusing here is also what keeps a hostile include out of the
//     surrounding filesystem.
//   - A symlink is read as its TARGET PATH, not as the file it points at.
//     That is exactly what the git host serves: git stores a symlink as a
//     blob whose content is the target path, so the raw-file API returns
//     that string. Reading through the link would both diverge from the
//     platform and let an include reach outside the checkout.
//   - A directory returns ErrNotFound, matching the git host's 404 for a
//     path that is not a blob.
//   - A missing file returns ErrNotFound: an honest ABSENT.
//   - Any other read failure is returned as-is and ABORTS the traversal.
//     See maxFileBytes for why an over-cap file is a failure, not an
//     absence.
func FetchFromDir(dir string) func(string) ([]byte, error) {
	return func(p string) ([]byte, error) {
		rel, ok := repoRelative(p)
		if !ok {
			return nil, fmt.Errorf("%w: %q is not a repo-relative path", ErrNotFound, p)
		}
		full := filepath.Join(dir, filepath.FromSlash(rel))

		info, err := os.Lstat(full)
		switch {
		case errors.Is(err, os.ErrNotExist):
			return nil, fmt.Errorf("%w: %q", ErrNotFound, p)
		case err != nil:
			return nil, fmt.Errorf("stat %q: %w", p, err)
		}

		switch {
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(full)
			if err != nil {
				return nil, fmt.Errorf("readlink %q: %w", p, err)
			}
			return []byte(target), nil
		case info.IsDir():
			return nil, fmt.Errorf("%w: %q is a directory", ErrNotFound, p)
		case !info.Mode().IsRegular():
			return nil, fmt.Errorf("%w: %q is not a regular file", ErrNotFound, p)
		}

		return readCapped(full, p)
	}
}

// readCapped reads full, refusing anything larger than maxFileBytes. It
// reads one byte past the cap to tell "exactly at the cap" from "over it"
// without loading the whole file.
func readCapped(full, display string) ([]byte, error) {
	f, err := os.Open(full) //nolint:gosec // full is rooted at the caller's checkout dir and validated by repoRelative
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %q", ErrNotFound, display)
		}
		return nil, fmt.Errorf("open %q: %w", display, err)
	}
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", display, err)
	}
	if int64(len(data)) > maxFileBytes {
		return nil, fmt.Errorf("read %q: exceeds the %d-byte limit", display, maxFileBytes)
	}
	return data, nil
}

// repoRelative reports whether p, as Traverse normalized it, addresses a
// file inside the repository, and returns the path to join against the
// checkout root. Traverse strips ONE leading slash and path.Clean's the
// result, which leaves two shapes that do not address the repo: an absolute
// path (path.Clean("/../x") is "/x") and one that still climbs out ("../x").
// Both are rejected.
func repoRelative(p string) (string, bool) {
	if p == "" || path.IsAbs(p) {
		return "", false
	}
	clean := path.Clean(p)
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false
	}
	if clean == "." {
		return "", false
	}
	return clean, true
}

// ComputeForCheckout is the CLI's whole digest computation: resolve the
// traversal root from ciConfigPath, walk the local includes through the
// checkout at dir, and hash the resulting file set.
//
// It returns ("", err) for every case that must NOT produce a digest - an
// external root config, a traversal that overflowed MaxFiles, or a read
// failure - and callers must treat a missing digest as ALWAYS-DIVERGENT
// rather than as a comparison key. A missing root file is not one of those
// cases: it is an honest ABSENT entry and still yields a digest, which is
// what lets two branches that both lack a CI config compare equal.
func ComputeForCheckout(dir, ciConfigPath string) (string, error) {
	root, err := RootPath(ciConfigPath)
	if err != nil {
		return "", err
	}
	files, err := Traverse(root, FetchFromDir(dir))
	if err != nil {
		return "", err
	}
	return Compute(files), nil
}
