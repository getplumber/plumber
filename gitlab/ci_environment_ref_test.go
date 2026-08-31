package gitlab

import "testing"

// TestCIAnalyzedRef pins which ref a run with no --branch is about.
//
// A CI job analyses what it checked out. Falling back to the project's
// default branch would read the feature branch's CI file off disk and then
// label every source link with `main`, so a reviewer following a finding
// lands on a ref that does not contain it.
func TestCIAnalyzedRef(t *testing.T) {
	t.Run("outside CI there is no answer", func(t *testing.T) {
		t.Setenv("CI", "")
		t.Setenv("CI_COMMIT_REF_NAME", "feature/x")
		if got := CIAnalyzedRef(); got != "" {
			t.Errorf("CIAnalyzedRef() = %q outside CI, want empty so the caller keeps its own default", got)
		}
	})

	t.Run("in CI it is the checked-out ref", func(t *testing.T) {
		t.Setenv("CI", "true")
		t.Setenv("CI_COMMIT_REF_NAME", "feature/x")
		if got := CIAnalyzedRef(); got != "feature/x" {
			t.Errorf("CIAnalyzedRef() = %q, want the checked-out ref", got)
		}
	})
}

// TestCIConfigPathIsExternal covers the three forms GitLab accepts for
// ci_config_path, of which only the first is readable from this project.
// $CI_CONFIG_PATH exports whichever one the project configured, verbatim,
// so the other two would otherwise become a request certain to 404.
func TestCIConfigPathIsExternal(t *testing.T) {
	local := []string{".gitlab-ci.yml", "ci/pipeline.yml", "deeply/nested/path.yml"}
	external := []string{
		"f.yml@group/other",
		"f.yml@group/sub/other:v1.2",
		"https://example.com/ci.yml",
		"http://example.com/ci.yml",
	}
	for _, p := range local {
		if CIConfigPathIsExternal(p) {
			t.Errorf("%q is repo-relative and must be read normally", p)
		}
	}
	for _, p := range external {
		if !CIConfigPathIsExternal(p) {
			t.Errorf("%q is not in this repository; fetching it here can only 404", p)
		}
	}
}

// CheckoutIsAtRef gates whether the analyzed project's CI file is read from
// the checkout instead of fetched: reading one branch's file while
// reporting on another parses cleanly and is silently wrong, which is why
// every branch of this guard needs pinning (re-raised #431 review thread).
func TestCheckoutIsAtRef(t *testing.T) {
	t.Run("outside CI is never at the ref", func(t *testing.T) {
		t.Setenv("CI", "")
		t.Setenv("CI_COMMIT_REF_NAME", "main")
		if CheckoutIsAtRef("main") {
			t.Fatal("outside CI there is no checked-out ref to be at")
		}
	})
	t.Run("empty branch means the analyzed ref by definition", func(t *testing.T) {
		t.Setenv("CI", "true")
		t.Setenv("CI_COMMIT_REF_NAME", "feature/x")
		if !CheckoutIsAtRef("") {
			t.Fatal("a run that names no branch analyses what it stands in")
		}
	})
	t.Run("matching ref", func(t *testing.T) {
		t.Setenv("CI", "true")
		t.Setenv("CI_COMMIT_REF_NAME", "release/2.0")
		if !CheckoutIsAtRef("release/2.0") {
			t.Fatal("the job checked out exactly this ref")
		}
	})
	t.Run("differing ref refuses the checkout", func(t *testing.T) {
		t.Setenv("CI", "true")
		t.Setenv("CI_COMMIT_REF_NAME", "main")
		if CheckoutIsAtRef("release/2.0") {
			t.Fatal("analyzing release/2.0 from a job building main must not read main's tree")
		}
	})
	t.Run("no checked-out ref recorded refuses", func(t *testing.T) {
		t.Setenv("CI", "true")
		t.Setenv("CI_COMMIT_REF_NAME", "")
		if CheckoutIsAtRef("main") {
			t.Fatal("an absent $CI_COMMIT_REF_NAME cannot confirm the ref")
		}
	})
}
