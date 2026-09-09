package cidigest

import "testing"

// Golden vectors computed with the platform's platform/backend/cidigest
// package (the package this one is a byte-for-byte replica of, ADR-0034
// rule 1). These pin Version "1"'s exact wire construction: this test must
// never be "fixed" by changing the expected hash, only by fixing a bug that
// makes this package diverge from the platform's construction.

func TestCompute_Vector1_RootPlusLocalInclude(t *testing.T) {
	files := map[string][]byte{
		".gitlab-ci.yml": []byte("include:\n  - local: ci/a.yml\nbuild:\n  script: make\n"),
		"ci/a.yml":       []byte("test:\n  script: go test ./...\n"),
	}
	got := Compute(files)
	want := "3764764fe11d900c53f379e64f76dc3b3caea9f35585d843f2bdf6dfed59cfe6"
	if got != want {
		t.Fatalf("Compute() = %q, want %q", got, want)
	}
}

func TestCompute_Vector2_AbsentInclude(t *testing.T) {
	files := map[string][]byte{
		".gitlab-ci.yml": []byte("include: ci/missing.yml\n"),
		"ci/missing.yml": Absent,
	}
	got := Compute(files)
	want := "1dd84b96d3982eff5a7f7fbedc1acaa73d4ce4906c4358ab9db96aaee9fec189"
	if got != want {
		t.Fatalf("Compute() = %q, want %q", got, want)
	}
}

func TestCompute_Vector3_NoIncludes(t *testing.T) {
	files := map[string][]byte{
		".gitlab-ci.yml": []byte("build:\n  script: make\n"),
	}
	got := Compute(files)
	want := "1528d12b72f92bff0923675939fc248a70767402f744acde8c24c0d108a0cedf"
	if got != want {
		t.Fatalf("Compute() = %q, want %q", got, want)
	}
}

func TestCompute_Vector4_TraverseThenCompute(t *testing.T) {
	sources := map[string][]byte{
		".gitlab-ci.yml": []byte("include:\n  - local: /ci/a.yml\n  - remote: https://example.com/x.yml\n  - ci/b.yml\n  - { local: ./ci/a.yml }\n"),
		"ci/a.yml":       []byte("include: { local: ci/c.yml }\n"),
		"ci/c.yml":       []byte("x: 1\n"),
	}
	fetch := func(path string) ([]byte, error) {
		if content, ok := sources[path]; ok {
			return content, nil
		}
		if path == "ci/b.yml" {
			return nil, ErrNotFound
		}
		return nil, ErrNotFound
	}

	files, err := Traverse(".gitlab-ci.yml", fetch)
	if err != nil {
		t.Fatalf("Traverse() error = %v", err)
	}

	wantVisited := map[string]bool{
		".gitlab-ci.yml": true,
		"ci/a.yml":       true,
		"ci/b.yml":       true,
		"ci/c.yml":       true,
	}
	if len(files) != len(wantVisited) {
		t.Fatalf("Traverse() visited %d files, want %d: got %v", len(files), len(wantVisited), files)
	}
	for p := range wantVisited {
		if _, ok := files[p]; !ok {
			t.Fatalf("Traverse() did not visit %q", p)
		}
	}
	if !isAbsent(files["ci/b.yml"]) {
		t.Fatalf("Traverse() ci/b.yml = %q, want the Absent sentinel", files["ci/b.yml"])
	}

	got := Compute(files)
	want := "b428728cabc8be05f026a263f97b5ca4723970f4b4923fcc7d65e88990156b5b"
	if got != want {
		t.Fatalf("Compute() = %q, want %q", got, want)
	}
}

// TestAbsent_IdentityNotContent proves isAbsent (via Compute) recognizes
// Absent by identity, not by byte content: a freshly allocated []byte with
// the exact same bytes as Absent is a different backing array and must be
// digested as real present content, not as the ABSENT marker.
func TestAbsent_IdentityNotContent(t *testing.T) {
	freshCopy := []byte("cidigest:absent")

	filesWithSentinel := map[string][]byte{"f.yml": Absent}
	filesWithFreshCopy := map[string][]byte{"f.yml": freshCopy}

	sentinelDigest := Compute(filesWithSentinel)
	freshCopyDigest := Compute(filesWithFreshCopy)

	if sentinelDigest == freshCopyDigest {
		t.Fatalf("Compute() treated a fresh []byte with Absent's bytes the same as the Absent sentinel: both = %q", sentinelDigest)
	}

	// The fresh copy must digest as ordinary content: sha256 of its own
	// bytes, not the literal "ABSENT" marker string.
	filesWithLiteralMarker := map[string][]byte{"f.yml": []byte(absentMarker)}
	if freshCopyDigest == Compute(filesWithLiteralMarker) {
		t.Fatalf("Compute() of a fresh copy of Absent's bytes matched digesting the literal marker string, want distinct")
	}
}
