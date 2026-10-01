package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

// TestParseAnalyzeTarget covers every form `plumber analyze TARGET` accepts:
// a browser URL with or without its scheme, a bare owner/repo, an SSH
// remote, and the suffixes a URL copied from the browser carries.
func TestParseAnalyzeTarget(t *testing.T) {
	gh := func(project, ref string) analyzeTarget {
		return analyzeTarget{provider: "github", project: project, ref: ref}
	}
	ghes := func(host, project string) analyzeTarget {
		return analyzeTarget{provider: "github", host: host, project: project}
	}
	gl := func(host, project, ref string) analyzeTarget {
		return analyzeTarget{provider: "gitlab", host: host, project: project, ref: ref}
	}

	tests := []struct {
		name     string
		arg      string
		provider string // the --provider flag, "" when unset
		want     analyzeTarget
	}{
		// GitHub, github.com: the host maps to an EMPTY --github-url
		// (api.github.com), never to "github.com".
		{"https github", "https://github.com/getplumber/plumber", "", gh("getplumber/plumber", "")},
		{"http github", "http://github.com/getplumber/plumber", "", gh("getplumber/plumber", "")},
		{"schemeless github", "github.com/getplumber/plumber", "", gh("getplumber/plumber", "")},
		{"github host case", "GitHub.com/getplumber/plumber", "", gh("getplumber/plumber", "")},
		{"github www", "https://www.github.com/getplumber/plumber", "", gh("getplumber/plumber", "")},
		{"github .git", "https://github.com/getplumber/plumber.git", "", gh("getplumber/plumber", "")},
		{"github trailing slash", "https://github.com/getplumber/plumber/", "", gh("getplumber/plumber", "")},
		{"github ssh scp", "git@github.com:getplumber/plumber.git", "", gh("getplumber/plumber", "")},
		{"github ssh url", "ssh://git@github.com/getplumber/plumber.git", "", gh("getplumber/plumber", "")},
		{"github tree ref", "https://github.com/getplumber/plumber/tree/main", "", gh("getplumber/plumber", "main")},
		{"github tree ref with slash", "https://github.com/getplumber/plumber/tree/feat/x", "", gh("getplumber/plumber", "feat/x")},
		{"github blob dropped", "https://github.com/getplumber/plumber/blob/main/README.md", "", gh("getplumber/plumber", "")},
		{"github pull dropped", "https://github.com/getplumber/plumber/pull/500", "", gh("getplumber/plumber", "")},
		{"github actions dropped", "https://github.com/getplumber/plumber/actions/runs/1", "", gh("getplumber/plumber", "")},
		{"github query dropped", "https://github.com/getplumber/plumber?tab=readme#x", "", gh("getplumber/plumber", "")},
		{"github provider agrees", "github.com/getplumber/plumber", "github", gh("getplumber/plumber", "")},
		{"github upper-case scheme", "HTTPS://github.com/getplumber/plumber", "", gh("getplumber/plumber", "")},

		// Bare owner/repo is github.com unless --provider gitlab says otherwise.
		{"bare is github", "getplumber/plumber", "", gh("getplumber/plumber", "")},
		{"bare provider github", "getplumber/plumber", "github", gh("getplumber/plumber", "")},
		{"bare provider gitlab", "group/sub/project", "gitlab", gl("https://gitlab.com", "group/sub/project", "")},
		{"bare dotted project is still bare", "my-group/my.project", "", gh("my-group/my.project", "")},

		// GitHub Enterprise Server: an unknown host is GitHub only when told so.
		{"ghes", "https://ghe.example.com/org/repo", "github", ghes("ghe.example.com", "org/repo")},
		{"ghes with port", "https://ghe.example.com:8443/org/repo", "github", ghes("ghe.example.com:8443", "org/repo")},

		// GitLab, SaaS and self-hosted, subgroups kept whole, scheme kept as given.
		{"https gitlab", "https://gitlab.com/group/project", "", gl("https://gitlab.com", "group/project", "")},
		{"schemeless gitlab", "gitlab.com/group/sub/project", "", gl("https://gitlab.com", "group/sub/project", "")},
		{"gitlab .git", "https://gitlab.com/group/project.git", "", gl("https://gitlab.com", "group/project", "")},
		{"gitlab ssh", "git@gitlab.com:group/sub/project.git", "", gl("https://gitlab.com", "group/sub/project", "")},
		{"self-hosted gitlab", "https://gitlab.example.com/g/sub/p", "", gl("https://gitlab.example.com", "g/sub/p", "")},
		{"self-hosted schemeless", "gitlab.example.com/g/p", "", gl("https://gitlab.example.com", "g/p", "")},
		{"self-hosted http kept", "http://gitlab.internal:8080/g/p", "", gl("http://gitlab.internal:8080", "g/p", "")},
		{"unknown host is gitlab", "https://code.example.org/g/p", "", gl("https://code.example.org", "g/p", "")},
		{"gitlab tree ref", "https://gitlab.com/group/project/-/tree/main", "", gl("https://gitlab.com", "group/project", "main")},
		{"gitlab tree ref with slash", "https://gitlab.com/group/project/-/tree/feat/x?ref_type=heads", "", gl("https://gitlab.com", "group/project", "feat/x")},
		{"gitlab mr dropped", "https://gitlab.com/group/project/-/merge_requests/3", "", gl("https://gitlab.com", "group/project", "")},
		{"gitlab pipelines dropped", "https://gitlab.com/group/project/-/pipelines", "", gl("https://gitlab.com", "group/project", "")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseAnalyzeTarget(tc.arg, tc.provider)
			if err != nil {
				t.Fatalf("parseAnalyzeTarget(%q, %q): %v", tc.arg, tc.provider, err)
			}
			if got != tc.want {
				t.Errorf("parseAnalyzeTarget(%q, %q)\n got  %+v\n want %+v", tc.arg, tc.provider, got, tc.want)
			}
		})
	}
}

// TestParseAnalyzeTargetRejects covers the inputs that must fail loudly
// rather than scan the wrong thing.
func TestParseAnalyzeTargetRejects(t *testing.T) {
	tests := []struct {
		name     string
		arg      string
		provider string
		wantMsg  string
	}{
		{"empty", "   ", "", "empty"},
		{"host only", "https://github.com", "", "owner/repo"},
		{"github owner only", "https://github.com/getplumber", "", "owner/repo"},
		{"bare single segment", "plumber", "", "owner/repo"},
		{"gitlab namespace only", "https://gitlab.com/group", "", "namespace/project"},
		{"provider contradicts github host", "github.com/getplumber/plumber", "gitlab", "--provider gitlab"},
		{"provider contradicts gitlab host", "gitlab.com/group/project", "github", "--provider github"},
		{"bad provider", "github.com/getplumber/plumber", "bitbucket", "--provider"},
		{"credential in url", "https://user:s3cret@gitlab.com/group/project", "", "token"},
		{"credential only in url", "https://glpat-abc@gitlab.com/group/project", "", "token"},
		{"credential without scheme", "user:s3cret@gitlab.com/group/project", "", "token"},
		{"credential only without scheme", "glpat-abc@gitlab.com/group/project", "", "token"},
		{"credential with upper-case scheme", "HTTPS://glpat-abc@gitlab.com/group/project", "", "token"},
		{"credential in github scheme-less", "s3cret@github.com/getplumber/plumber", "", "token"},
		{"unparsable scheme", "ftp://gitlab.com/group/project", "", "not a repository URL"},
		{"credential behind another scheme", "ftp://user:s3cret@gitlab.com/group/project", "", "token"},
		{"credential in a bad ssh url is redacted", "ssh://user:s3cret@gitlab.com", "", "not a repository URL"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseAnalyzeTarget(tc.arg, tc.provider)
			if err == nil {
				t.Fatalf("parseAnalyzeTarget(%q, %q): want an error containing %q, got nil", tc.arg, tc.provider, tc.wantMsg)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error %q does not mention %q", err.Error(), tc.wantMsg)
			}
			// A credential given in the URL must not come back in the message.
			if strings.Contains(err.Error(), "s3cret") || strings.Contains(err.Error(), "glpat-abc") {
				t.Errorf("error echoes the credential: %q", err.Error())
			}
		})
	}
}

// targetFlagSet mirrors the five analyze flags a target is written into, so
// applyAnalyzeTarget can be exercised without the package-level command.
func targetFlagSet() *pflag.FlagSet {
	fs := pflag.NewFlagSet("analyze", pflag.ContinueOnError)
	for _, name := range []string{"gitlab-url", "github-url", "project", "provider", "branch"} {
		fs.String(name, "", "")
	}
	return fs
}

func flagValue(t *testing.T, fs *pflag.FlagSet, name string) string {
	t.Helper()
	v, err := fs.GetString(name)
	if err != nil {
		t.Fatalf("GetString(%s): %v", name, err)
	}
	return v
}

// TestApplyAnalyzeTargetSetsFlags: the target lands in the existing flags and
// marks them Changed, so resolveProvider, dispatchGitHub and
// resolveGitLabTarget run exactly as they do for an explicit --project.
func TestApplyAnalyzeTargetSetsFlags(t *testing.T) {
	t.Run("github.com", func(t *testing.T) {
		fs := targetFlagSet()
		if err := applyAnalyzeTarget(fs, analyzeTarget{provider: "github", project: "o/r", ref: "dev"}); err != nil {
			t.Fatal(err)
		}
		if got := flagValue(t, fs, "project"); got != "o/r" {
			t.Errorf("project = %q", got)
		}
		if got := flagValue(t, fs, "provider"); got != "github" {
			t.Errorf("provider = %q", got)
		}
		if fs.Changed("github-url") || fs.Changed("gitlab-url") {
			t.Errorf("github.com must leave both URL flags untouched (api.github.com is the empty value)")
		}
		if got := flagValue(t, fs, "branch"); got != "dev" || !fs.Changed("branch") {
			t.Errorf("branch = %q changed=%v", got, fs.Changed("branch"))
		}
		if !fs.Changed("project") || !fs.Changed("provider") {
			t.Errorf("project and provider must read as Changed")
		}
	})
	t.Run("ghes", func(t *testing.T) {
		fs := targetFlagSet()
		if err := applyAnalyzeTarget(fs, analyzeTarget{provider: "github", host: "ghe.example.com", project: "o/r"}); err != nil {
			t.Fatal(err)
		}
		if got := flagValue(t, fs, "github-url"); got != "ghe.example.com" {
			t.Errorf("github-url = %q", got)
		}
		if fs.Changed("branch") {
			t.Errorf("no ref in the target must not touch --branch")
		}
	})
	t.Run("gitlab", func(t *testing.T) {
		fs := targetFlagSet()
		if err := applyAnalyzeTarget(fs, analyzeTarget{provider: "gitlab", host: "https://gitlab.example.com", project: "g/sub/p"}); err != nil {
			t.Fatal(err)
		}
		if got := flagValue(t, fs, "gitlab-url"); got != "https://gitlab.example.com" {
			t.Errorf("gitlab-url = %q", got)
		}
		if got := flagValue(t, fs, "project"); got != "g/sub/p" {
			t.Errorf("project = %q", got)
		}
		if fs.Changed("github-url") {
			t.Errorf("a GitLab target must not set --github-url")
		}
	})
}

// TestApplyAnalyzeTargetConflicts: a coordinate flag (or its PLUMBER_ANALYZE_*
// env var, which counts as a flag) that disagrees with the target is an
// error naming both values; one that agrees is fine; an explicit --branch
// beats the ref in the URL.
func TestApplyAnalyzeTargetConflicts(t *testing.T) {
	set := func(t *testing.T, fs *pflag.FlagSet, name, value string) {
		t.Helper()
		if err := fs.Set(name, value); err != nil {
			t.Fatal(err)
		}
	}
	gl := analyzeTarget{provider: "gitlab", host: "https://gitlab.com", project: "g/p", ref: "main"}
	gh := analyzeTarget{provider: "github", project: "o/r"}

	t.Run("project disagrees", func(t *testing.T) {
		fs := targetFlagSet()
		set(t, fs, "project", "other/thing")
		err := applyAnalyzeTarget(fs, gl)
		if err == nil || !strings.Contains(err.Error(), "other/thing") || !strings.Contains(err.Error(), "g/p") {
			t.Fatalf("want an error naming both projects, got %v", err)
		}
	})
	t.Run("project agrees", func(t *testing.T) {
		fs := targetFlagSet()
		set(t, fs, "project", "g/p")
		if err := applyAnalyzeTarget(fs, gl); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("gitlab-url disagrees", func(t *testing.T) {
		fs := targetFlagSet()
		set(t, fs, "gitlab-url", "https://gitlab.example.com")
		if err := applyAnalyzeTarget(fs, gl); err == nil || !strings.Contains(err.Error(), "gitlab.example.com") {
			t.Fatalf("want an error naming the other host, got %v", err)
		}
	})
	t.Run("gitlab-url agrees ignoring scheme and slash", func(t *testing.T) {
		fs := targetFlagSet()
		set(t, fs, "gitlab-url", "gitlab.com/")
		if err := applyAnalyzeTarget(fs, gl); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("gitlab-url agrees ignoring host case", func(t *testing.T) {
		fs := targetFlagSet()
		set(t, fs, "gitlab-url", "https://GitLab.com")
		if err := applyAnalyzeTarget(fs, gl); err != nil {
			t.Fatal(err)
		}
		if got := flagValue(t, fs, "gitlab-url"); got != "https://GitLab.com" {
			t.Errorf("an agreeing --gitlab-url must be left as given, got %q", got)
		}
	})
	t.Run("github-url against a gitlab target", func(t *testing.T) {
		fs := targetFlagSet()
		set(t, fs, "github-url", "ghe.example.com")
		if err := applyAnalyzeTarget(fs, gl); err == nil || !strings.Contains(err.Error(), "--github-url") {
			t.Fatalf("want a --github-url conflict, got %v", err)
		}
	})
	t.Run("gitlab-url against a github target", func(t *testing.T) {
		fs := targetFlagSet()
		set(t, fs, "gitlab-url", "https://gitlab.com")
		if err := applyAnalyzeTarget(fs, gh); err == nil || !strings.Contains(err.Error(), "--gitlab-url") {
			t.Fatalf("want a --gitlab-url conflict, got %v", err)
		}
	})
	t.Run("github-url disagrees with github.com", func(t *testing.T) {
		fs := targetFlagSet()
		set(t, fs, "github-url", "ghe.example.com")
		if err := applyAnalyzeTarget(fs, gh); err == nil || !strings.Contains(err.Error(), "ghe.example.com") {
			t.Fatalf("want an error naming the other host, got %v", err)
		}
	})
	t.Run("github-url github.com agrees with github.com", func(t *testing.T) {
		fs := targetFlagSet()
		set(t, fs, "github-url", "github.com")
		if err := applyAnalyzeTarget(fs, gh); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("github-url api.github.com agrees with github.com", func(t *testing.T) {
		fs := targetFlagSet()
		set(t, fs, "github-url", "https://api.github.com/")
		if err := applyAnalyzeTarget(fs, gh); err != nil {
			t.Fatal(err)
		}
		if fs.Changed("project") && flagValue(t, fs, "project") != "o/r" {
			t.Errorf("project = %q", flagValue(t, fs, "project"))
		}
	})
	ghes := analyzeTarget{provider: "github", host: "ghe.example.com", project: "o/r"}
	t.Run("github-url agrees with a GHES target ignoring scheme, slash and case", func(t *testing.T) {
		fs := targetFlagSet()
		set(t, fs, "github-url", "https://GHE.example.com/")
		if err := applyAnalyzeTarget(fs, ghes); err != nil {
			t.Fatal(err)
		}
		if got := flagValue(t, fs, "github-url"); got != "https://GHE.example.com/" {
			t.Errorf("an agreeing --github-url must be left as given, got %q", got)
		}
	})
	t.Run("github-url disagrees with a GHES target", func(t *testing.T) {
		fs := targetFlagSet()
		set(t, fs, "github-url", "other.example.com")
		if err := applyAnalyzeTarget(fs, ghes); err == nil || !strings.Contains(err.Error(), "ghe.example.com") || !strings.Contains(err.Error(), "other.example.com") {
			t.Fatalf("want an error naming both hosts, got %v", err)
		}
	})
	t.Run("provider disagrees", func(t *testing.T) {
		fs := targetFlagSet()
		set(t, fs, "provider", "github")
		if err := applyAnalyzeTarget(fs, gl); err == nil || !strings.Contains(err.Error(), "--provider github") {
			t.Fatalf("want a --provider conflict, got %v", err)
		}
	})
	t.Run("explicit branch wins over the url ref", func(t *testing.T) {
		fs := targetFlagSet()
		set(t, fs, "branch", "release")
		if err := applyAnalyzeTarget(fs, gl); err != nil {
			t.Fatal(err)
		}
		if got := flagValue(t, fs, "branch"); got != "release" {
			t.Errorf("branch = %q, want the explicit flag to win", got)
		}
	})
}

// TestAnalyzeCmdArgs: one positional target is accepted, two are refused.
// Before this, `plumber analyze https://github.com/x/y` ran and silently
// scanned the current directory's remote instead.
func TestAnalyzeCmdArgs(t *testing.T) {
	if analyzeCmd.Args == nil {
		t.Fatal("analyzeCmd has no Args validator: extra arguments are silently dropped")
	}
	if err := analyzeCmd.Args(analyzeCmd, nil); err != nil {
		t.Errorf("no argument must stay valid: %v", err)
	}
	if err := analyzeCmd.Args(analyzeCmd, []string{"github.com/o/r"}); err != nil {
		t.Errorf("one target must be valid: %v", err)
	}
	if err := analyzeCmd.Args(analyzeCmd, []string{"github.com/o/r", "github.com/o/s"}); err == nil {
		t.Error("two targets must be refused")
	}
	if !strings.HasPrefix(analyzeCmd.Use, "analyze [TARGET]") {
		t.Errorf("Use = %q, want the TARGET in the usage line", analyzeCmd.Use)
	}
}
