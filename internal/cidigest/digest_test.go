package cidigest

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"testing"
)

// goldenVectors pins the exact byte construction of digest_v1: the
// "plumber-ci-digest/v1\n" prefix, byte-wise sorted path order, the NUL
// (\x00) separators, hex-encoded sha256 content hashes, and the literal
// "ABSENT" marker for an Absent entry.
//
// These are the SHARED vectors: the identical table lives in the platform's
// platform/backend/cidigest/digest_test.go, and each expected hex string was
// computed independently of both implementations (Python hashlib) from the
// formula in the spec. A drift on either side fails here. Do not "fix" a
// failure by updating a want value - a changed construction is a new
// digest_version, not a new vector.
var goldenVectors = []struct {
	name  string
	files map[string][]byte
	want  string
}{
	{
		name:  "empty file set",
		files: map[string][]byte{},
		want:  "170d88c3abf9ad4512cf393bcea920b23c66df70d31442d54d8b5260d723e836",
	},
	{
		name: "single root file",
		files: map[string][]byte{
			".gitlab-ci.yml": []byte("stages:\n  - build\n"),
		},
		want: "b2dc627c8d9fdad3ffb53f2138197a9ca4600b91ac59c515fa2e8fbe0cbe7009",
	},
	{
		name: "two files, insertion order reversed relative to sort order",
		files: map[string][]byte{
			"b.yml": []byte("job_b:\n  script: echo b\n"),
			"a.yml": []byte("job_a:\n  script: echo a\n"),
		},
		want: "9a0ff8926b2a061369ef54897605f8c2c940a02d299c5b604eeee0d7b33161f1",
	},
	{
		name: "one absent file",
		files: map[string][]byte{
			"missing.yml": Absent,
		},
		want: "4712fb00f779b34684a923f61dd33c7e2e7510044160663c06e3d70905ae018c",
	},
	{
		name: "mixed: root + include + absent",
		files: map[string][]byte{
			".gitlab-ci.yml": []byte("include:\n  - local: 'ci/build.yml'\n  - local: 'ci/missing.yml'\nstages:\n  - build\n"),
			"ci/build.yml":   []byte("build:\n  stage: build\n  script: echo build\n"),
			"ci/missing.yml": Absent,
		},
		want: "9f690e784999dd4e099ea2a93f004470301978b16cc36de386aa4ae7b9949b58",
	},
	{
		// Proves byte-wise sort, not a naive case-insensitive or path-depth
		// sort: "Z.yml" < "a.yml" < "a/b.yml" byte-wise ('Z'=0x5A < 'a'=0x61;
		// "a.yml" < "a/b.yml" because '.'=0x2E < '/'=0x2F).
		name: "byte-wise sort order across case and path depth",
		files: map[string][]byte{
			"Z.yml":   []byte("z\n"),
			"a/b.yml": []byte("ab\n"),
			"a.yml":   []byte("a\n"),
		},
		want: "f84e0ba32fd4514224aa3434cf6306ddd4c9210a3752903f1579e6f1f7b08987",
	},
}

func TestCompute_Golden(t *testing.T) {
	for _, tc := range goldenVectors {
		t.Run(tc.name, func(t *testing.T) {
			if got := Compute(tc.files); got != tc.want {
				t.Fatalf("digest_v1 construction drifted from the pinned wire vector:\n got  %s\n want %s", got, tc.want)
			}
		})
	}
}

// TestVersion pins the wire value paired with every digest. It travels with
// the digest on the resolve request and both sides refuse to compare across
// versions, so changing it is a protocol change, not a refactor.
func TestVersion(t *testing.T) {
	if Version != "1" {
		t.Fatalf("digest_version is wire-stable: got %q, want \"1\"", Version)
	}
}

// TestCompute_DeterministicUnderMapRandomization proves the digest does not
// depend on Go's randomized map iteration order. Without the byte-wise sort
// in Compute the same file set would hash differently between calls.
func TestCompute_DeterministicUnderMapRandomization(t *testing.T) {
	files := map[string][]byte{
		".gitlab-ci.yml": []byte("include:\n  - local: 'a.yml'\n"),
		"a.yml":          []byte("a\n"),
		"b.yml":          []byte("b\n"),
		"c/d.yml":        []byte("cd\n"),
		"missing.yml":    Absent,
	}
	first := Compute(files)
	for i := 0; i < 50; i++ {
		if got := Compute(files); got != first {
			t.Fatalf("Compute is not deterministic across map iteration orders: %s then %s", first, got)
		}
	}
}

// TestCompute_AbsentIsIdentityNotContent pins the one subtle rule of the
// construction: Absent is recognized by identity, so a real file whose bytes
// happen to equal the sentinel's is digested as PRESENT content. A
// content-equality check here would let a repo forge an ABSENT entry by
// committing a file containing "cidigest:absent".
func TestCompute_AbsentIsIdentityNotContent(t *testing.T) {
	lookalike := []byte("cidigest:absent") // same bytes, different backing array
	absentDigest := Compute(map[string][]byte{"x.yml": Absent})
	contentDigest := Compute(map[string][]byte{"x.yml": lookalike})
	if absentDigest == contentDigest {
		t.Fatalf("a file whose content equals the Absent sentinel's bytes must digest as PRESENT content, not as ABSENT (both gave %s)", absentDigest)
	}
}

// --- Traverse ---------------------------------------------------------------

// fakeFS is a Traverse fetch source over an in-memory file set. A path
// absent from files returns ErrNotFound; a path in fails returns a
// non-ErrNotFound error, which must abort the traversal.
type fakeFS struct {
	files map[string][]byte
	fails map[string]error
	seen  []string
}

func (f *fakeFS) fetch(p string) ([]byte, error) {
	f.seen = append(f.seen, p)
	if err, ok := f.fails[p]; ok {
		return nil, err
	}
	content, ok := f.files[p]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrNotFound, p)
	}
	return content, nil
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestTraverse_IncludeForms(t *testing.T) {
	cases := []struct {
		name string
		root []byte
		want []string
	}{
		{
			name: "bare string shorthand, single",
			root: []byte("include: 'ci/one.yml'\n"),
			want: []string{".gitlab-ci.yml", "ci/one.yml"},
		},
		{
			name: "bare strings in an array",
			root: []byte("include:\n  - 'ci/one.yml'\n  - 'ci/two.yml'\n"),
			want: []string{".gitlab-ci.yml", "ci/one.yml", "ci/two.yml"},
		},
		{
			name: "explicit map form given directly, not in an array",
			root: []byte("include:\n  local: 'ci/one.yml'\n"),
			want: []string{".gitlab-ci.yml", "ci/one.yml"},
		},
		{
			name: "array mixing local, bare string and non-local entries",
			root: []byte("include:\n  - local: 'ci/one.yml'\n  - 'ci/two.yml'\n  - remote: 'https://example.com/r.yml'\n  - template: 'Auto-DevOps.gitlab-ci.yml'\n  - project: 'grp/other'\n    file: '/f.yml'\n  - component: 'gitlab.com/c/c@1'\n"),
			want: []string{".gitlab-ci.yml", "ci/one.yml", "ci/two.yml"},
		},
		{
			name: "no include key at all",
			root: []byte("stages:\n  - build\n"),
			want: []string{".gitlab-ci.yml"},
		},
		{
			name: "unparsable YAML still digests, yields no includes",
			root: []byte("include: [oops\n\tbad: :\n"),
			want: []string{".gitlab-ci.yml"},
		},
		{
			name: "leading slash and ./ normalize to one entry",
			root: []byte("include:\n  - local: '/ci/one.yml'\n  - local: './ci/one.yml'\n  - local: 'ci/one.yml'\n"),
			want: []string{".gitlab-ci.yml", "ci/one.yml"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := &fakeFS{files: map[string][]byte{
				".gitlab-ci.yml": tc.root,
				"ci/one.yml":     []byte("one:\n  script: echo one\n"),
				"ci/two.yml":     []byte("two:\n  script: echo two\n"),
			}}
			got, err := Traverse(".gitlab-ci.yml", fs.fetch)
			if err != nil {
				t.Fatalf("Traverse: %v", err)
			}
			if !reflect.DeepEqual(keysOf(got), tc.want) {
				t.Fatalf("file set: got %v, want %v", keysOf(got), tc.want)
			}
		})
	}
}

// TestTraverse_NestedAndCyclic proves recursion through nested locals and
// termination on a cycle. An include cycle is legal YAML and must not hang.
func TestTraverse_NestedAndCyclic(t *testing.T) {
	t.Run("nested locals followed recursively", func(t *testing.T) {
		fs := &fakeFS{files: map[string][]byte{
			".gitlab-ci.yml": []byte("include:\n  - local: 'a.yml'\n"),
			"a.yml":          []byte("include:\n  - local: 'b.yml'\n"),
			"b.yml":          []byte("include:\n  - local: 'c.yml'\n"),
			"c.yml":          []byte("c:\n  script: echo c\n"),
		}}
		got, err := Traverse(".gitlab-ci.yml", fs.fetch)
		if err != nil {
			t.Fatalf("Traverse: %v", err)
		}
		want := []string{".gitlab-ci.yml", "a.yml", "b.yml", "c.yml"}
		if !reflect.DeepEqual(keysOf(got), want) {
			t.Fatalf("file set: got %v, want %v", keysOf(got), want)
		}
	})

	t.Run("cycle terminates and fetches each path once", func(t *testing.T) {
		fs := &fakeFS{files: map[string][]byte{
			"a.yml": []byte("include:\n  - local: 'b.yml'\n"),
			"b.yml": []byte("include:\n  - local: 'a.yml'\n"),
		}}
		got, err := Traverse("a.yml", fs.fetch)
		if err != nil {
			t.Fatalf("Traverse must terminate on an include cycle: %v", err)
		}
		if want := []string{"a.yml", "b.yml"}; !reflect.DeepEqual(keysOf(got), want) {
			t.Fatalf("file set: got %v, want %v", keysOf(got), want)
		}
		if len(fs.seen) != 2 {
			t.Fatalf("a visited path must never be re-fetched: fetched %v", fs.seen)
		}
	})
}

// TestTraverse_CapBoundary pins the exact cap semantics: MaxFiles distinct
// files never aborts, MaxFiles+1 always does, and an abort returns NO file
// map. A truncated map would let two configs identical up to the cap but
// different beyond it compare digest-equal.
func TestTraverse_CapBoundary(t *testing.T) {
	chain := func(n int) (*fakeFS, string) {
		files := map[string][]byte{}
		names := make([]string, n)
		for i := range names {
			names[i] = fmt.Sprintf("step%d.yml", i)
		}
		for i, name := range names {
			if i == n-1 {
				files[name] = []byte("job:\n  script: echo done\n")
				continue
			}
			files[name] = []byte("include:\n  - local: '" + names[i+1] + "'\n")
		}
		return &fakeFS{files: files}, names[0]
	}

	t.Run("exactly MaxFiles succeeds", func(t *testing.T) {
		fs, root := chain(MaxFiles)
		got, err := Traverse(root, fs.fetch)
		if err != nil {
			t.Fatalf("exactly %d files must not abort: %v", MaxFiles, err)
		}
		if len(got) != MaxFiles {
			t.Fatalf("got %d files, want %d", len(got), MaxFiles)
		}
	})

	t.Run("MaxFiles+1 aborts with no file map", func(t *testing.T) {
		fs, root := chain(MaxFiles + 1)
		got, err := Traverse(root, fs.fetch)
		if err == nil {
			t.Fatalf("the %dth distinct file must abort, got %d files and no error", MaxFiles+1, len(got))
		}
		if !errors.Is(err, ErrTooManyFiles) {
			t.Fatalf("abort error must wrap ErrTooManyFiles, got %v", err)
		}
		if got != nil {
			t.Fatalf("a cap-overflow abort must return NO file map, got %v", keysOf(got))
		}
		if AbortReason(err) != "overflow" {
			t.Fatalf("AbortReason: got %q, want \"overflow\"", AbortReason(err))
		}
	})

	t.Run("a diamond include does not trip the cap by re-popping", func(t *testing.T) {
		// Root includes a and b; both include the same shared.yml, so
		// shared.yml is queued twice but is only ever one distinct file.
		fs := &fakeFS{files: map[string][]byte{
			"root.yml":   []byte("include:\n  - local: 'a.yml'\n  - local: 'b.yml'\n"),
			"a.yml":      []byte("include:\n  - local: 'shared.yml'\n"),
			"b.yml":      []byte("include:\n  - local: 'shared.yml'\n"),
			"shared.yml": []byte("s:\n  script: echo s\n"),
		}}
		got, err := Traverse("root.yml", fs.fetch)
		if err != nil {
			t.Fatalf("Traverse: %v", err)
		}
		if want := []string{"a.yml", "b.yml", "root.yml", "shared.yml"}; !reflect.DeepEqual(keysOf(got), want) {
			t.Fatalf("file set: got %v, want %v", keysOf(got), want)
		}
	})
}

// TestTraverse_ErrorContract pins the split that keeps a digest honest: a
// genuinely missing file degrades to ABSENT and the scan continues; any
// other failure aborts with no digest at all. Folding a read failure into
// ABSENT would produce a valid-looking digest over bytes never read.
func TestTraverse_ErrorContract(t *testing.T) {
	t.Run("missing include degrades to Absent", func(t *testing.T) {
		fs := &fakeFS{files: map[string][]byte{
			".gitlab-ci.yml": []byte("include:\n  - local: 'ci/gone.yml'\n"),
		}}
		got, err := Traverse(".gitlab-ci.yml", fs.fetch)
		if err != nil {
			t.Fatalf("one missing include must not fail the scan: %v", err)
		}
		if !isAbsent(got["ci/gone.yml"]) {
			t.Fatalf("missing include must be recorded as Absent, got %q", got["ci/gone.yml"])
		}
	})

	t.Run("missing root degrades to Absent and still digests", func(t *testing.T) {
		fs := &fakeFS{files: map[string][]byte{}}
		got, err := Traverse(".gitlab-ci.yml", fs.fetch)
		if err != nil {
			t.Fatalf("a missing root must not fail the scan: %v", err)
		}
		if !isAbsent(got[".gitlab-ci.yml"]) {
			t.Fatalf("missing root must be recorded as Absent")
		}
		if Compute(got) == "" {
			t.Fatalf("a missing root must still yield a digest")
		}
	})

	t.Run("a non-ErrNotFound failure aborts with no file map", func(t *testing.T) {
		boom := errors.New("permission denied")
		fs := &fakeFS{
			files: map[string][]byte{".gitlab-ci.yml": []byte("include:\n  - local: 'ci/x.yml'\n")},
			fails: map[string]error{"ci/x.yml": boom},
		}
		got, err := Traverse(".gitlab-ci.yml", fs.fetch)
		if err == nil {
			t.Fatalf("a read failure must abort, got %v", keysOf(got))
		}
		if !errors.Is(err, boom) {
			t.Fatalf("abort must wrap the underlying error, got %v", err)
		}
		if got != nil {
			t.Fatalf("an aborted traversal must return NO file map, got %v", keysOf(got))
		}
		if AbortReason(err) != "read_failure" {
			t.Fatalf("AbortReason: got %q, want \"read_failure\"", AbortReason(err))
		}
	})

	t.Run("a failure on the root aborts too", func(t *testing.T) {
		boom := errors.New("i/o error")
		fs := &fakeFS{fails: map[string]error{".gitlab-ci.yml": boom}}
		if _, err := Traverse(".gitlab-ci.yml", fs.fetch); !errors.Is(err, boom) {
			t.Fatalf("a root read failure must abort, got %v", err)
		}
	})
}

// TestTraverse_ComputeIntegration walks a real include graph and checks the
// result against the golden vector for the same file set, proving Traverse
// and Compute compose into the digest the platform computes for that repo.
func TestTraverse_ComputeIntegration(t *testing.T) {
	fs := &fakeFS{files: map[string][]byte{
		".gitlab-ci.yml": []byte("include:\n  - local: 'ci/build.yml'\n  - local: 'ci/missing.yml'\nstages:\n  - build\n"),
		"ci/build.yml":   []byte("build:\n  stage: build\n  script: echo build\n"),
	}}
	files, err := Traverse(".gitlab-ci.yml", fs.fetch)
	if err != nil {
		t.Fatalf("Traverse: %v", err)
	}
	const want = "9f690e784999dd4e099ea2a93f004470301978b16cc36de386aa4ae7b9949b58"
	if got := Compute(files); got != want {
		t.Fatalf("traverse+compute over the golden include graph:\n got  %s\n want %s", got, want)
	}
}
