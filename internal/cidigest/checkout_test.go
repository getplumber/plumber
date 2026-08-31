package cidigest

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// writeTree materializes a path -> content map under a fresh temp dir and
// returns the root.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", rel, err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	return dir
}

func TestRootPath(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr error
	}{
		{name: "unset falls back to the GitLab default", in: "", want: DefaultRootPath},
		{name: "whitespace-only is also unset", in: "   ", want: DefaultRootPath},
		{name: "a plain repo-relative path is used as-is", in: "ci/main.yml", want: "ci/main.yml"},
		{name: "an external project config has no root in this checkout", in: "cfg.yml@grp/other", wantErr: ErrExternalRootConfig},
		{name: "an external config with a ref is equally external", in: "cfg.yml@grp/other?ref=v1", wantErr: ErrExternalRootConfig},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := RootPath(tc.in)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("got (%q, %v), want an error wrapping %v", got, err, tc.wantErr)
				}
				if got != "" {
					t.Fatalf("an errored RootPath must return no root, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestFetchFromDir_EscapingPathsAreAbsentNeverRead is the security-relevant
// case: an include that climbs out of the checkout must never reach the
// surrounding filesystem. It contributes ABSENT, exactly as the git host's
// 404 would on the platform side, so both digests still agree.
func TestFetchFromDir_EscapingPathsAreAbsentNeverRead(t *testing.T) {
	dir := writeTree(t, map[string]string{".gitlab-ci.yml": "stages: [build]\n"})

	// A real, readable file OUTSIDE the checkout, one level up.
	outside := filepath.Join(filepath.Dir(dir), "outside-secret.yml")
	if err := os.WriteFile(outside, []byte("secret: value\n"), 0o600); err != nil {
		t.Fatalf("write outside file: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(outside) })

	fetch := FetchFromDir(dir)
	for _, p := range []string{
		"../" + filepath.Base(outside),
		"../../etc/passwd",
		"/etc/passwd",
		"..",
	} {
		t.Run(p, func(t *testing.T) {
			got, err := fetch(p)
			if !errors.Is(err, ErrNotFound) {
				t.Fatalf("an escaping path must return ErrNotFound (so it digests as ABSENT), got (%q, %v)", got, err)
			}
			if got != nil {
				t.Fatalf("an escaping path must return no content, got %q", got)
			}
		})
	}
}

// TestFetchFromDir_SymlinkReadsTargetPathNotTarget pins parity with the git
// host: git stores a symlink as a blob whose content is the target path, so
// the raw-file API returns that string. Following the link would both
// diverge from the platform's digest and let an include escape the checkout.
func TestFetchFromDir_SymlinkReadsTargetPathNotTarget(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"ci/real.yml": "real:\n  script: echo real\n",
	})
	outside := filepath.Join(filepath.Dir(dir), "outside-target.yml")
	if err := os.WriteFile(outside, []byte("secret: value\n"), 0o600); err != nil {
		t.Fatalf("write outside file: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(outside) })

	if err := os.Symlink("ci/real.yml", filepath.Join(dir, "inside-link.yml")); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "escaping-link.yml")); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}

	fetch := FetchFromDir(dir)

	got, err := fetch("inside-link.yml")
	if err != nil {
		t.Fatalf("a symlink must be readable as its target path: %v", err)
	}
	if string(got) != "ci/real.yml" {
		t.Fatalf("a symlink must digest as its TARGET PATH, got %q", got)
	}

	got, err = fetch("escaping-link.yml")
	if err != nil {
		t.Fatalf("an escaping symlink must still read as its target path: %v", err)
	}
	if strings.Contains(string(got), "secret") {
		t.Fatalf("an escaping symlink must NOT be followed; got the pointed-at file's content: %q", got)
	}
}

func TestFetchFromDir_NotFoundCases(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"ci/real.yml": "real: {}\n",
	})
	fetch := FetchFromDir(dir)

	t.Run("a missing file is ErrNotFound", func(t *testing.T) {
		if _, err := fetch("ci/gone.yml"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("got %v, want ErrNotFound", err)
		}
	})
	t.Run("a directory is ErrNotFound, matching the host's 404 for a non-blob", func(t *testing.T) {
		if _, err := fetch("ci"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("got %v, want ErrNotFound", err)
		}
	})
	t.Run("a present file reads its bytes", func(t *testing.T) {
		got, err := fetch("ci/real.yml")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != "real: {}\n" {
			t.Fatalf("got %q", got)
		}
	})
}

// TestFetchFromDir_OverCapIsReadFailureNotAbsent pins the honest-digest
// rule: an over-cap file has real content that would have changed the
// digest, so it must abort the whole computation rather than silently
// contributing ABSENT.
func TestFetchFromDir_OverCapIsReadFailureNotAbsent(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "big.yml")
	if err := os.WriteFile(big, make([]byte, maxFileBytes+1), 0o600); err != nil {
		t.Fatalf("write big file: %v", err)
	}
	_, err := FetchFromDir(dir)("big.yml")
	if err == nil {
		t.Fatal("an over-cap file must fail the read")
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatalf("an over-cap file is a READ FAILURE, never ABSENT: got %v", err)
	}
}

// TestComputeForCheckout_MatchesGoldenVector walks a real on-disk repo whose
// include graph is the golden "root + include + absent" fixture, and checks
// the digest against the shared vector. This is the end-to-end proof that
// the CLI's file access feeds Traverse+Compute the same file set the
// platform's API access does.
func TestComputeForCheckout_MatchesGoldenVector(t *testing.T) {
	dir := writeTree(t, map[string]string{
		".gitlab-ci.yml": "include:\n  - local: 'ci/build.yml'\n  - local: 'ci/missing.yml'\nstages:\n  - build\n",
		"ci/build.yml":   "build:\n  stage: build\n  script: echo build\n",
	})
	got, err := ComputeForCheckout(dir, "")
	if err != nil {
		t.Fatalf("ComputeForCheckout: %v", err)
	}
	const want = "9f690e784999dd4e099ea2a93f004470301978b16cc36de386aa4ae7b9949b58"
	if got != want {
		t.Fatalf("checkout digest:\n got  %s\n want %s", got, want)
	}
}

// TestComputeForCheckout_MissingRootStillDigests: a repo with no CI config
// at all is a legitimate state, and two such repos must compare digest-equal
// rather than each failing to produce a digest.
func TestComputeForCheckout_MissingRootStillDigests(t *testing.T) {
	a, err := ComputeForCheckout(t.TempDir(), "")
	if err != nil {
		t.Fatalf("a missing root must still yield a digest: %v", err)
	}
	b, err := ComputeForCheckout(t.TempDir(), "")
	if err != nil {
		t.Fatalf("ComputeForCheckout: %v", err)
	}
	if a != b {
		t.Fatalf("two config-less checkouts must digest equal: %s vs %s", a, b)
	}
	if a != Compute(map[string][]byte{DefaultRootPath: Absent}) {
		t.Fatalf("a config-less checkout must digest as a single ABSENT root entry")
	}
}

// TestComputeForCheckout_HonorsCIConfigPath proves the root is the project's
// configured ci_config_path, not always .gitlab-ci.yml: pointing at a
// different file must produce a different file set.
func TestComputeForCheckout_HonorsCIConfigPath(t *testing.T) {
	dir := writeTree(t, map[string]string{
		".gitlab-ci.yml": "stages: [default]\n",
		"ci/custom.yml":  "stages: [custom]\n",
	})
	def, err := ComputeForCheckout(dir, "")
	if err != nil {
		t.Fatalf("ComputeForCheckout(default): %v", err)
	}
	custom, err := ComputeForCheckout(dir, "ci/custom.yml")
	if err != nil {
		t.Fatalf("ComputeForCheckout(custom): %v", err)
	}
	if def == custom {
		t.Fatal("a different ci_config_path must digest differently: the root file is part of the file set")
	}
	if want := Compute(map[string][]byte{"ci/custom.yml": []byte("stages: [custom]\n")}); custom != want {
		t.Fatalf("custom-root digest:\n got  %s\n want %s", custom, want)
	}
}

// TestComputeForCheckout_NoDigestCases enumerates every state that must
// yield NO digest. Callers treat a missing digest as always-divergent, which
// is the safe direction; a fabricated digest here would silently evaluate a
// branch against the wrong config.
func TestComputeForCheckout_NoDigestCases(t *testing.T) {
	t.Run("external root config", func(t *testing.T) {
		got, err := ComputeForCheckout(t.TempDir(), "cfg.yml@grp/other")
		if !errors.Is(err, ErrExternalRootConfig) {
			t.Fatalf("got (%q, %v), want ErrExternalRootConfig", got, err)
		}
		if got != "" {
			t.Fatalf("want no digest, got %q", got)
		}
	})

	t.Run("include chain past the file cap", func(t *testing.T) {
		files := map[string]string{}
		for i := 0; i < MaxFiles+1; i++ {
			name := "step" + itoa(i) + ".yml"
			if i == MaxFiles {
				files[name] = "job:\n  script: echo done\n"
				continue
			}
			files[name] = "include:\n  - local: 'step" + itoa(i+1) + ".yml'\n"
		}
		dir := writeTree(t, files)
		got, err := ComputeForCheckout(dir, "step0.yml")
		if !errors.Is(err, ErrTooManyFiles) {
			t.Fatalf("got (%q, %v), want ErrTooManyFiles", got, err)
		}
		if got != "" {
			t.Fatalf("want no digest on cap overflow, got %q", got)
		}
	})
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// TestFetchFromDir_NormalizedPathsReachTheSameFile pins that the spellings
// Traverse normalizes together all resolve to one file on disk.
func TestFetchFromDir_NormalizedPathsReachTheSameFile(t *testing.T) {
	dir := writeTree(t, map[string]string{"ci/one.yml": "one: {}\n"})
	fetch := FetchFromDir(dir)
	var got []string
	for _, spelling := range []string{"ci/one.yml", "./ci/one.yml", "ci/../ci/one.yml"} {
		content, err := fetch(spelling)
		if err != nil {
			t.Fatalf("fetch(%q): %v", spelling, err)
		}
		got = append(got, string(content))
	}
	if want := []string{"one: {}\n", "one: {}\n", "one: {}\n"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
