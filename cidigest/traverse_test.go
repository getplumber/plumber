package cidigest

import (
	"errors"
	"fmt"
	"testing"
)

func TestTraverse_CycleSafe(t *testing.T) {
	sources := map[string][]byte{
		"a.yml": []byte("include: { local: b.yml }\n"),
		"b.yml": []byte("include: { local: a.yml }\n"),
	}
	fetch := func(path string) ([]byte, error) {
		content, ok := sources[path]
		if !ok {
			return nil, ErrNotFound
		}
		return content, nil
	}

	files, err := Traverse("a.yml", fetch)
	if err != nil {
		t.Fatalf("Traverse() error = %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("Traverse() visited %d files, want 2 (a.yml, b.yml): got %v", len(files), files)
	}
	if _, ok := files["a.yml"]; !ok {
		t.Fatalf("Traverse() missing a.yml")
	}
	if _, ok := files["b.yml"]; !ok {
		t.Fatalf("Traverse() missing b.yml")
	}
}

func TestTraverse_TooManyFilesAborts(t *testing.T) {
	// root includes 51 distinct local files (0.yml .. 50.yml), each with no
	// further includes. Visiting the 51st distinct file must abort with an
	// error wrapping ErrTooManyFiles.
	const total = MaxFiles + 1

	rootInclude := "include:\n"
	for i := 0; i < total; i++ {
		rootInclude += fmt.Sprintf("  - local: %d.yml\n", i)
	}

	sources := map[string][]byte{
		"root.yml": []byte(rootInclude),
	}
	for i := 0; i < total; i++ {
		sources[fmt.Sprintf("%d.yml", i)] = []byte("x: 1\n")
	}

	fetch := func(path string) ([]byte, error) {
		content, ok := sources[path]
		if !ok {
			return nil, ErrNotFound
		}
		return content, nil
	}

	files, err := Traverse("root.yml", fetch)
	if err == nil {
		t.Fatalf("Traverse() error = nil, want an error wrapping ErrTooManyFiles")
	}
	if !errors.Is(err, ErrTooManyFiles) {
		t.Fatalf("Traverse() error = %v, want it to wrap ErrTooManyFiles", err)
	}
	if files != nil {
		t.Fatalf("Traverse() files = %v, want nil on abort", files)
	}
}

func TestTraverse_ExactlyMaxFilesSucceeds(t *testing.T) {
	// root plus (MaxFiles - 1) local includes = exactly MaxFiles distinct
	// files. This must NOT abort (the cap is exceeding MaxFiles, not
	// reaching it).
	const totalIncludes = MaxFiles - 1

	rootInclude := "include:\n"
	for i := 0; i < totalIncludes; i++ {
		rootInclude += fmt.Sprintf("  - local: %d.yml\n", i)
	}

	sources := map[string][]byte{
		"root.yml": []byte(rootInclude),
	}
	for i := 0; i < totalIncludes; i++ {
		sources[fmt.Sprintf("%d.yml", i)] = []byte("x: 1\n")
	}

	fetch := func(path string) ([]byte, error) {
		content, ok := sources[path]
		if !ok {
			return nil, ErrNotFound
		}
		return content, nil
	}

	files, err := Traverse("root.yml", fetch)
	if err != nil {
		t.Fatalf("Traverse() error = %v, want nil at exactly MaxFiles", err)
	}
	if len(files) != MaxFiles {
		t.Fatalf("Traverse() visited %d files, want exactly %d", len(files), MaxFiles)
	}
}

func TestTraverse_NonNotFoundErrorAborts(t *testing.T) {
	infraErr := errors.New("boom: connection reset")
	fetch := func(path string) ([]byte, error) {
		return nil, infraErr
	}

	files, err := Traverse("root.yml", fetch)
	if err == nil {
		t.Fatalf("Traverse() error = nil, want an error wrapping the infra failure")
	}
	if !errors.Is(err, infraErr) {
		t.Fatalf("Traverse() error = %v, want it to wrap the underlying fetch error", err)
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatalf("Traverse() error unexpectedly wraps ErrNotFound")
	}
	if files != nil {
		t.Fatalf("Traverse() files = %v, want nil on abort", files)
	}
}

func TestTraverse_RootNotFoundRecordsAbsent(t *testing.T) {
	fetch := func(path string) ([]byte, error) {
		return nil, ErrNotFound
	}

	files, err := Traverse("root.yml", fetch)
	if err != nil {
		t.Fatalf("Traverse() error = %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("Traverse() visited %d files, want 1", len(files))
	}
	if !isAbsent(files["root.yml"]) {
		t.Fatalf("Traverse() root.yml = %q, want the Absent sentinel", files["root.yml"])
	}
}

func TestNormalizeIncludePath(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"ci/a.yml", "ci/a.yml"},
		{"/ci/a.yml", "ci/a.yml"},
		{"./ci/a.yml", "ci/a.yml"},
		{"ci/../ci/a.yml", "ci/a.yml"},
		{"", ""},
		{"/", ""},
	}
	for _, tc := range cases {
		got := normalizeIncludePath(tc.in)
		if got != tc.want {
			t.Errorf("normalizeIncludePath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestLocalIncludePaths_BareString(t *testing.T) {
	got := localIncludePaths([]byte("include: ci/a.yml\n"))
	want := []string{"ci/a.yml"}
	assertStringSlicesEqual(t, got, want)
}

func TestLocalIncludePaths_StringInArray(t *testing.T) {
	got := localIncludePaths([]byte("include:\n  - ci/a.yml\n  - ci/b.yml\n"))
	want := []string{"ci/a.yml", "ci/b.yml"}
	assertStringSlicesEqual(t, got, want)
}

func TestLocalIncludePaths_LocalMapInArray(t *testing.T) {
	got := localIncludePaths([]byte("include:\n  - local: ci/a.yml\n"))
	want := []string{"ci/a.yml"}
	assertStringSlicesEqual(t, got, want)
}

func TestLocalIncludePaths_LocalMapAsWholeValue(t *testing.T) {
	got := localIncludePaths([]byte("include:\n  local: ci/a.yml\n"))
	want := []string{"ci/a.yml"}
	assertStringSlicesEqual(t, got, want)
}

func TestLocalIncludePaths_RemoteTemplateComponentIgnored(t *testing.T) {
	got := localIncludePaths([]byte("include:\n  - remote: https://example.com/x.yml\n  - template: Security/SAST.gitlab-ci.yml\n  - component: gitlab.com/to/component@1.0\n  - project: group/project\n    file: x.yml\n"))
	if len(got) != 0 {
		t.Fatalf("localIncludePaths() = %v, want empty (no local entries)", got)
	}
}

func TestLocalIncludePaths_MixedArray(t *testing.T) {
	got := localIncludePaths([]byte("include:\n  - local: ci/a.yml\n  - remote: https://example.com/x.yml\n  - ci/b.yml\n  - { local: ci/c.yml }\n"))
	want := []string{"ci/a.yml", "ci/b.yml", "ci/c.yml"}
	assertStringSlicesEqual(t, got, want)
}

func TestLocalIncludePaths_NoIncludeKey(t *testing.T) {
	got := localIncludePaths([]byte("build:\n  script: make\n"))
	if got != nil {
		t.Fatalf("localIncludePaths() = %v, want nil", got)
	}
}

func TestLocalIncludePaths_UnparsableYAML(t *testing.T) {
	got := localIncludePaths([]byte("this: is: not: valid: yaml: at: all:\n\t- broken\n"))
	if got != nil {
		t.Fatalf("localIncludePaths() = %v, want nil for unparsable YAML", got)
	}
}

func assertStringSlicesEqual(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}
