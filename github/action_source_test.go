package github

import (
	"strings"
	"testing"
)

func TestScanActionSource(t *testing.T) {
	cases := []struct {
		name     string
		files    map[string]string
		wantTier string // "" means expect nil
		wantURL  string // substring the reported URL must contain
	}{
		{
			name:     "grype install.sh from main is exec tier",
			files:    map[string]string{"action.js": "const u = `https://raw.githubusercontent.com/anchore/grype/main/install.sh`;\ntools.downloadTool(u);"},
			wantTier: "exec",
			wantURL:  "anchore/grype/main/install.sh",
		},
		{
			name:     "curl pipe sh is exec tier",
			files:    map[string]string{"action.yml": "runs:\n  using: composite\n  steps:\n    - run: curl -sSfL https://example.com/i.sh | sudo bash"},
			wantTier: "exec",
			wantURL:  "curl",
		},
		{
			name:     "docker release manifest from main is data tier",
			files:    map[string]string{"dist/index.js": `releasesURL:"https://raw.githubusercontent.com/docker/actions-toolkit/main/.github/buildx-releases.json"`},
			wantTier: "data",
			wantURL:  "buildx-releases.json",
		},
		{
			name:     "exec wins over data when both present",
			files:    map[string]string{"a.js": `"raw.githubusercontent.com/o/r/main/m.json"`, "b.js": `"raw.githubusercontent.com/o/r/main/install.sh"`},
			wantTier: "exec",
			wantURL:  "install.sh",
		},
		{
			name:     "pinned ref is not flagged",
			files:    map[string]string{"action.js": `"https://raw.githubusercontent.com/anchore/grype/v0.114.0/install.sh"`},
			wantTier: "",
		},
		{
			name:     "release-download URL (not raw moving) is not flagged",
			files:    map[string]string{"action.js": `"https://github.com/anchore/grype/releases/download/v0.114.0/grype.tar.gz"`},
			wantTier: "",
		},
		{
			name:     "clean action with no remote fetch",
			files:    map[string]string{"action.yml": "runs:\n  using: node20\n  main: dist/index.js", "dist/index.js": "console.log('hi')"},
			wantTier: "",
		},
		// --- obfuscation tier (critical) ---
		{
			name:     "base64 decode piped to sh is obfuscated",
			files:    map[string]string{"action.yml": "runs:\n  using: composite\n  steps:\n    - run: echo $PAYLOAD | base64 -d | sh"},
			wantTier: "obfuscated",
		},
		{
			name:     "eval(atob(...)) is obfuscated",
			files:    map[string]string{"dist/index.js": `const go = eval(atob(secret));`},
			wantTier: "obfuscated",
		},
		{
			name:     "obfuscation wins over a plain exec",
			files:    map[string]string{"a.yml": "run: curl -sSfL https://raw.githubusercontent.com/o/r/main/i.sh | sh", "b.yml": `run: eval "$(printf %s "$X" | base64 -d)"`},
			wantTier: "obfuscated",
		},
		// --- host-swap and download-then-run still caught as exec ---
		{
			name:     "github.com/<o>/<r>/raw host swap is exec",
			files:    map[string]string{"action.js": `const u = "https://github.com/anchore/grype/raw/main/install.sh";`},
			wantTier: "exec",
			wantURL:  "grype/raw/main/install.sh",
		},
		{
			name:     "download-then-run (no pipe) is exec",
			files:    map[string]string{"action.yml": "runs:\n  using: composite\n  steps:\n    - run: |\n        curl -o /tmp/b.sh https://raw.githubusercontent.com/o/r/main/b.sh\n        sh /tmp/b.sh"},
			wantTier: "exec",
		},
		{
			name:     "branch named stable (outside the old list) is exec",
			files:    map[string]string{"action.js": `"https://raw.githubusercontent.com/o/r/stable/install.sh"`},
			wantTier: "exec",
		},
		// --- checksum downgrades exec to the low data tier ---
		{
			name:     "exec that verifies a checksum is downgraded (not high)",
			files:    map[string]string{"action.yml": "runs:\n  using: composite\n  steps:\n    - run: |\n        curl -sSfL https://raw.githubusercontent.com/o/r/main/i.sh -o i.sh\n        echo \"abc123  i.sh\" | sha256sum -c\n        sh i.sh"},
			wantTier: "data",
		},
		// --- #299 review: reObfEval must not fire on benign minified bundles (blocker 1) ---
		{
			name:     "minified new Function boilerplate next to a base64 decode is NOT obfuscated",
			files:    map[string]string{"dist/index.js": `t=new Function("return this")();r=Buffer.from(e.data,"base64");`},
			wantTier: "",
		},
		{
			name:     "genuine new Function(atob(...)) is still obfuscated",
			files:    map[string]string{"dist/index.js": `const run = new Function(atob(payload));run();`},
			wantTier: "obfuscated",
		},
		// --- #299 review: pipe classified by URL/args mutability (blocker 2) ---
		{
			name:     "SHA-pinned URL piped to sh is data, not high (matches the ISSUE-714 remediation)",
			files:    map[string]string{"action.yml": "runs:\n  using: composite\n  steps:\n    - run: curl -sSfL https://raw.githubusercontent.com/anchore/grype/8f2a3cd90ff2b3a24e2ba5cbde5a29f3d1b2c4e5/install.sh | sh -s -- -b /usr/local/bin"},
			wantTier: "data",
		},
		{
			name:     "release-asset URL piped to interpreter is data",
			files:    map[string]string{"action.yml": "runs:\n  using: composite\n  steps:\n    - run: curl -L https://github.com/org/tool/releases/download/v1.2.3/bootstrap.py | python3 -"},
			wantTier: "data",
		},
		{
			name:     "remote data piped into a LOCAL committed script is not remote exec",
			files:    map[string]string{"action.yml": "runs:\n  using: composite\n  steps:\n    - run: curl -s https://api.example.com/matrix.json | python3 scripts/gen_matrix.py >> \"$GITHUB_OUTPUT\""},
			wantTier: "",
		},
		{
			name:     "moving-ref URL piped to sh stays exec",
			files:    map[string]string{"action.yml": "runs:\n  using: composite\n  steps:\n    - run: curl -sSfL https://raw.githubusercontent.com/o/r/main/i.sh | sh"},
			wantTier: "exec",
		},
		// --- #299 review: reDownloadRun must anchor the run to a statement (NB-1) ---
		// The download-then-`git push` case must not be reported as EXEC
		// (high). The `.json` from a moving ref is still recorded by the
		// separate data pass (low, not surfaced) — the FP that mattered was
		// the exec/high verdict, which the statement anchor removes.
		{
			name:     "download of a data file followed by git push is NOT exec (recorded as low data)",
			files:    map[string]string{"action.yml": "runs:\n  using: composite\n  steps:\n    - run: |\n        curl -sSfL https://raw.githubusercontent.com/org/repo/main/versions.json -o versions.json\n        git push origin HEAD"},
			wantTier: "data",
		},
		{
			name:     "download of a script then && ./run stays exec",
			files:    map[string]string{"action.yml": "runs:\n  using: composite\n  steps:\n    - run: curl -sSfL https://raw.githubusercontent.com/org/repo/main/x.sh -o x.sh && ./x.sh"},
			wantTier: "exec",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ScanActionSource(tc.files)
			if tc.wantTier == "" {
				if got != nil {
					t.Fatalf("expected no finding, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("expected %s-tier finding, got nil", tc.wantTier)
			}
			if got.Tier != tc.wantTier {
				t.Fatalf("tier = %q, want %q", got.Tier, tc.wantTier)
			}
			if tc.wantURL != "" && !strings.Contains(got.URL, tc.wantURL) {
				t.Fatalf("URL = %q, want to contain %q", got.URL, tc.wantURL)
			}
		})
	}
}

func TestAnalyzeActionMutableExec_Subpath(t *testing.T) {
	// A nested/composite action: action.yml lives under the subpath, and
	// its entrypoint resolves relative to that dir. Only those paths
	// exist in the fake fetcher; a root fetch must not be what triggers.
	fetch := func(owner, repo, ref, p string) (string, fetchStatus) {
		files := map[string]string{
			"hassfest/action.yml":    "runs:\n  using: node20\n  main: dist/index.js",
			"hassfest/dist/index.js": `tools.downloadTool("https://raw.githubusercontent.com/acme/tool/main/install.sh")`,
		}
		if owner == "acme" && repo == "actions" && ref == "v1" {
			if v, ok := files[p]; ok {
				return v, fetchOK
			}
		}
		return "", fetchMissing
	}
	got := analyzeActionMutableExec(fetch, "acme", "actions", "v1", "hassfest")
	if got == nil {
		t.Fatal("expected a finding for the subpath action, got nil (subpath not resolved)")
	}
	if got.Tier != "exec" || got.File != "hassfest/dist/index.js" {
		t.Fatalf("unexpected finding: %+v", got)
	}
}

func TestAnalyzeActionMutableExec_Unverified(t *testing.T) {
	// A network error fetching action.yml must surface as could-not-verify,
	// never a silent nil (which would read as "clean").
	fetchErr := func(owner, repo, ref, p string) (string, fetchStatus) {
		return "", fetchError
	}
	got := analyzeActionMutableExec(fetchErr, "acme", "tool", "v1", "")
	if got == nil || got.Tier != "unverified" {
		t.Fatalf("network error must yield tier=unverified, got %+v", got)
	}

	// A 404 (not an action / subpath absent) is a legitimate silent nil.
	fetchMiss := func(owner, repo, ref, p string) (string, fetchStatus) {
		return "", fetchMissing
	}
	if got := analyzeActionMutableExec(fetchMiss, "acme", "tool", "v1", ""); got != nil {
		t.Fatalf("a missing action.yml must yield nil, got %+v", got)
	}
}

func TestScanActionDefinition_Docker(t *testing.T) {
	noFetch := func(string) (string, fetchStatus) { return "", fetchMissing }

	t.Run("docker:// mutable tag is exec", func(t *testing.T) {
		yml := "runs:\n  using: docker\n  image: docker://ghcr.io/super-linter/super-linter:latest"
		got := scanActionDefinition(yml, "action.yml", noFetch)
		if got == nil || got.Tier != "exec" {
			t.Fatalf("mutable docker:// tag must be exec, got %+v", got)
		}
	})

	t.Run("docker:// version tag is low (data), not high", func(t *testing.T) {
		yml := "runs:\n  using: docker\n  image: docker://ghcr.io/super-linter/super-linter:v8.7.0"
		got := scanActionDefinition(yml, "action.yml", noFetch)
		if got == nil || got.Tier != "data" {
			t.Fatalf("version-tagged image must be data tier, got %+v", got)
		}
	})

	t.Run("docker:// pinned by digest is clean", func(t *testing.T) {
		yml := "runs:\n  using: docker\n  image: docker://ghcr.io/x/y@sha256:deadbeef"
		if got := scanActionDefinition(yml, "action.yml", noFetch); got != nil {
			t.Fatalf("digest-pinned image must be clean, got %+v", got)
		}
	})

	t.Run("Dockerfile RUN curl|sh is exec", func(t *testing.T) {
		yml := "runs:\n  using: docker\n  image: Dockerfile"
		fetch := func(rel string) (string, fetchStatus) {
			if rel == "Dockerfile" {
				return "FROM alpine\nRUN curl -fsSL https://get.docker.com | sh\n", fetchOK
			}
			return "", fetchMissing
		}
		got := scanActionDefinition(yml, "action.yml", fetch)
		if got == nil || got.Tier != "exec" {
			t.Fatalf("Dockerfile with curl|sh must be exec, got %+v", got)
		}
	})

	t.Run("clean Dockerfile is not flagged", func(t *testing.T) {
		yml := "runs:\n  using: docker\n  image: Dockerfile"
		fetch := func(rel string) (string, fetchStatus) {
			return "FROM alpine\nRUN apk add --no-cache bash\n", fetchOK
		}
		if got := scanActionDefinition(yml, "action.yml", fetch); got != nil {
			t.Fatalf("clean Dockerfile must not be flagged, got %+v", got)
		}
	})
}

func TestSplitActionRefWithSubpath(t *testing.T) {
	cases := []struct {
		uses                      string
		owner, repo, subpath, ref string
		ok                        bool
	}{
		{"anchore/scan-action@v7", "anchore", "scan-action", "", "v7", true},
		{"github/codeql-action/init@abc123", "github", "codeql-action", "init", "abc123", true},
		{"home-assistant/actions/hassfest@master", "home-assistant", "actions", "hassfest", "master", true},
		{"crowdsecurity/php-cs-bouncer/.github/workflows/test.yml@main", "", "", "", "", false}, // reusable workflow
		{"./local/action@v1", "", "", "", "", false},
		{"docker://alpine@sha256:x", "", "", "", "", false},
		{"noref", "", "", "", "", false},
	}
	for _, tc := range cases {
		o, r, s, ref, ok := splitActionRefWithSubpath(tc.uses)
		if ok != tc.ok || o != tc.owner || r != tc.repo || s != tc.subpath || ref != tc.ref {
			t.Errorf("%s → (%q,%q,%q,%q,%v), want (%q,%q,%q,%q,%v)",
				tc.uses, o, r, s, ref, ok, tc.owner, tc.repo, tc.subpath, tc.ref, tc.ok)
		}
	}
}

func TestEntrypointPaths(t *testing.T) {
	got := entrypointPaths("runs:\n  using: node20\n  main: dist/bundle.js\n")
	if len(got) == 0 || got[0] != "dist/bundle.js" {
		t.Fatalf("expected declared entrypoint first, got %v", got)
	}
	// the usual candidates are appended without duplicating the declared one
	if !contains(got, "action.js") || !contains(got, "dist/index.js") {
		t.Fatalf("expected candidate paths appended, got %v", got)
	}
}

// TestScanActionDefinition_UnreadableSiblingIsUnverified covers the collapse
// that scanned a rate-limited action clean.
//
// An entrypoint or Dockerfile that could not be FETCHED is not one that does
// not exist. Folding the two together omitted the file from the scan, and an
// action whose source nobody could read graded exactly like one with nothing
// to hide.
func TestScanActionDefinition_UnreadableSiblingIsUnverified(t *testing.T) {
	t.Run("Dockerfile fetch error", func(t *testing.T) {
		yml := "runs:\n  using: docker\n  image: Dockerfile"
		fetch := func(string) (string, fetchStatus) { return "", fetchError }
		got := scanActionDefinition(yml, "action.yml", fetch)
		if got == nil || got.Tier != "unverified" {
			t.Fatalf("an unreadable Dockerfile must be unverified, got %+v", got)
		}
	})

	t.Run("entrypoint fetch error", func(t *testing.T) {
		yml := "runs:\n  using: node20\n  main: dist/index.js"
		fetch := func(string) (string, fetchStatus) { return "", fetchError }
		got := scanActionDefinition(yml, "action.yml", fetch)
		if got == nil || got.Tier != "unverified" {
			t.Fatalf("an unreadable entrypoint must be unverified, got %+v", got)
		}
	})

	t.Run("a genuinely absent sibling stays clean", func(t *testing.T) {
		yml := "runs:\n  using: node20\n  main: dist/index.js"
		fetch := func(string) (string, fetchStatus) { return "", fetchMissing }
		if got := scanActionDefinition(yml, "action.yml", fetch); got != nil {
			t.Fatalf("a 404 is a real answer and must not downgrade the verdict, got %+v", got)
		}
	})

	t.Run("the offline switch stays silent", func(t *testing.T) {
		yml := "runs:\n  using: node20\n  main: dist/index.js"
		fetch := func(string) (string, fetchStatus) { return "", fetchDisabled }
		if got := scanActionDefinition(yml, "action.yml", fetch); got != nil {
			t.Fatalf("a deliberate opt-out must abstain silently, got %+v", got)
		}
	})
}
