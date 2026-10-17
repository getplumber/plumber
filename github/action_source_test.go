package github

import (
	"slices"
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
	if !slices.Contains(got, "action.js") || !slices.Contains(got, "dist/index.js") {
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

// TestScanActionSource_DownloadGuardAndVerified pins the two additive
// signals trust follows the party that can change the code with
// (control/trust.go): a fetch that only runs when a tool is NOT already
// on PATH (DownloadGuard names that tool), and a fetch whose downloaded
// content is checked against a checksum in the same step or the next
// (DownloadVerified): content-pinned, like an already-content-pinned
// fetch, even though the ref itself is not.
func TestScanActionSource_DownloadGuardAndVerified(t *testing.T) {
	t.Run("guarded rustup install names the guarded tool", func(t *testing.T) {
		// Mirrors dtolnay/rust-toolchain's own install step: the fetch
		// only runs when rustup is not already on the runner's PATH.
		files := map[string]string{
			"action.yml": "" +
				"runs:\n" +
				"  using: composite\n" +
				"  steps:\n" +
				"    - shell: bash\n" +
				"      run: |\n" +
				"        if ! command -v rustup >/dev/null 2>&1; then\n" +
				"          curl --proto '=https' --tlsv1.2 --retry 10 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none\n" +
				"        fi\n",
		}
		got := ScanActionSource(files)
		if got == nil {
			t.Fatal("expected a mutable-remote-exec signal, got nil")
		}
		if got.DownloadGuard != "rustup" {
			t.Fatalf("DownloadGuard = %q, want %q", got.DownloadGuard, "rustup")
		}
	})

	t.Run("checksum verified in the same step is content-pinned", func(t *testing.T) {
		// Mirrors a CodSpeedHQ-style release download: fetched from a
		// moving ref and verified against a checksum written inline,
		// in the SAME step (item 2: a later step never counts).
		files := map[string]string{
			"action.yml": "" +
				"runs:\n" +
				"  using: composite\n" +
				"  steps:\n" +
				"    - name: download and verify the codspeed runner\n" +
				"      shell: bash\n" +
				"      run: |\n" +
				"        curl -fsSL -o install.sh https://raw.githubusercontent.com/codspeedhq/codspeed-runner/main/scripts/install.sh\n" +
				"        echo \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  install.sh\" | sha256sum -c -\n",
		}
		got := ScanActionSource(files)
		if got == nil {
			t.Fatal("expected a mutable-remote-exec signal, got nil")
		}
		if !got.DownloadVerified {
			t.Fatalf("DownloadVerified = false, want true (checksum in the same step)")
		}
	})

	t.Run("no guard, no verification: both stay empty", func(t *testing.T) {
		files := map[string]string{
			"action.yml": "runs:\n  using: composite\n  steps:\n    - run: curl -sSfL https://example.com/i.sh | sudo bash\n",
		}
		got := ScanActionSource(files)
		if got == nil {
			t.Fatal("expected a mutable-remote-exec signal, got nil")
		}
		if got.DownloadGuard != "" {
			t.Fatalf("DownloadGuard = %q, want empty", got.DownloadGuard)
		}
		if got.DownloadVerified {
			t.Fatal("DownloadVerified = true, want false")
		}
	})
}

// TestScanActionSource_GuardScope (fix round 1, item 1) pins that a
// guard counts only when it is structurally connected to the fetch it
// is supposed to guard: the right-hand side of the SAME `||`, or
// inside the `then`/`fi` body of the `if` that tests it, and never
// across a step boundary.
func TestScanActionSource_GuardScope(t *testing.T) {
	t.Run("an unrelated earlier guard that exits gives no guard", func(t *testing.T) {
		// `command -v docker || { exit 1; }` guards nothing but its own
		// exit; the later, unconnected curl|bash is not inside its ||.
		files := map[string]string{
			"action.yml": "" +
				"runs:\n" +
				"  using: composite\n" +
				"  steps:\n" +
				"    - run: |\n" +
				"        command -v docker || { echo \"docker required\"; exit 1; }\n" +
				"        curl -sSfL https://example.com/i.sh | bash\n",
		}
		got := ScanActionSource(files)
		if got == nil {
			t.Fatal("expected a mutable-remote-exec signal, got nil")
		}
		if got.DownloadGuard != "" {
			t.Fatalf("DownloadGuard = %q, want empty (the docker guard exits, it does not guard the fetch)", got.DownloadGuard)
		}
	})

	t.Run("a guard in the previous step gives no guard", func(t *testing.T) {
		files := map[string]string{
			"action.yml": "" +
				"runs:\n" +
				"  using: composite\n" +
				"  steps:\n" +
				"    - run: |\n" +
				"        command -v rustup || true\n" +
				"    - run: |\n" +
				"        curl -sSf https://sh.rustup.rs | sh\n",
		}
		got := ScanActionSource(files)
		if got == nil {
			t.Fatal("expected a mutable-remote-exec signal, got nil")
		}
		if got.DownloadGuard != "" {
			t.Fatalf("DownloadGuard = %q, want empty (the guard is in a different step)", got.DownloadGuard)
		}
	})

	t.Run("if-block form names the guarded tool", func(t *testing.T) {
		files := map[string]string{
			"action.yml": "" +
				"runs:\n" +
				"  using: composite\n" +
				"  steps:\n" +
				"    - run: |\n" +
				"        if ! command -v rustup; then\n" +
				"          curl -sSf https://sh.rustup.rs | sh\n" +
				"        fi\n",
		}
		got := ScanActionSource(files)
		if got == nil {
			t.Fatal("expected a mutable-remote-exec signal, got nil")
		}
		if got.DownloadGuard != "rustup" {
			t.Fatalf("DownloadGuard = %q, want %q", got.DownloadGuard, "rustup")
		}
	})

	t.Run("direct short-circuit form names the guarded tool", func(t *testing.T) {
		files := map[string]string{
			"action.yml": "" +
				"runs:\n" +
				"  using: composite\n" +
				"  steps:\n" +
				"    - run: |\n" +
				"        command -v rustup >/dev/null 2>&1 || curl -sSf https://sh.rustup.rs | sh\n",
		}
		got := ScanActionSource(files)
		if got == nil {
			t.Fatal("expected a mutable-remote-exec signal, got nil")
		}
		if got.DownloadGuard != "rustup" {
			t.Fatalf("DownloadGuard = %q, want %q", got.DownloadGuard, "rustup")
		}
	})

	t.Run("direct short-circuit form guards a download-then-run fetch too", func(t *testing.T) {
		// The regex match for a download-then-run (or a moving-ref
		// script URL) fetch starts INSIDE the URL, not at the
		// "curl"/"wget" keyword the way a pipe-to-shell match does: the
		// same `||` guard must still be found by walking back to the
		// command's own start on the line, not just to the match.
		files := map[string]string{
			"action.yml": "" +
				"runs:\n" +
				"  using: composite\n" +
				"  steps:\n" +
				"    - run: |\n" +
				"        command -v rustup >/dev/null 2>&1 || curl -o install.sh https://raw.githubusercontent.com/o/r/main/install.sh\n" +
				"        sh install.sh\n",
		}
		got := ScanActionSource(files)
		if got == nil {
			t.Fatal("expected a mutable-remote-exec signal, got nil")
		}
		if got.DownloadGuard != "rustup" {
			t.Fatalf("DownloadGuard = %q, want %q", got.DownloadGuard, "rustup")
		}
	})

	// Fix round 2, item 1a: an `else` (or `elif`) branch of the negated
	// check is not guarded at all: the fetch there runs exactly when
	// the tool IS present, which is the opposite of what the `then`
	// branch's absence-guard means.
	t.Run("a fetch in the else branch of a negated check gives no guard", func(t *testing.T) {
		files := map[string]string{
			"action.yml": "" +
				"runs:\n" +
				"  using: composite\n" +
				"  steps:\n" +
				"    - run: |\n" +
				"        if ! command -v rustup >/dev/null; then\n" +
				"          echo missing\n" +
				"        else\n" +
				"          curl -sSf https://sh.rustup.rs | sh -s -- -y\n" +
				"        fi\n",
		}
		got := ScanActionSource(files)
		if got == nil {
			t.Fatal("expected a mutable-remote-exec signal, got nil")
		}
		if got.DownloadGuard != "" {
			t.Fatalf("DownloadGuard = %q, want empty (the fetch runs when rustup IS present, the else branch)", got.DownloadGuard)
		}
	})

	t.Run("a fetch in an elif branch gives no guard", func(t *testing.T) {
		files := map[string]string{
			"action.yml": "" +
				"runs:\n" +
				"  using: composite\n" +
				"  steps:\n" +
				"    - run: |\n" +
				"        if ! command -v rustup >/dev/null; then\n" +
				"          echo missing\n" +
				"        elif true; then\n" +
				"          curl -sSf https://sh.rustup.rs | sh -s -- -y\n" +
				"        fi\n",
		}
		got := ScanActionSource(files)
		if got == nil {
			t.Fatal("expected a mutable-remote-exec signal, got nil")
		}
		if got.DownloadGuard != "" {
			t.Fatalf("DownloadGuard = %q, want empty (the elif branch is not the negated check's then-branch)", got.DownloadGuard)
		}
	})

	// Fix round 2, item 1b: a negated direct short-circuit check
	// inverts the semantics entirely: the fetch runs exactly when the
	// tool IS found, so it must never read as a guard.
	t.Run("a negated direct short-circuit check gives no guard", func(t *testing.T) {
		files := map[string]string{
			"action.yml": "" +
				"runs:\n" +
				"  using: composite\n" +
				"  steps:\n" +
				"    - run: |\n" +
				"        ! command -v rustup >/dev/null || curl -sSf https://sh.rustup.rs | sh\n",
		}
		got := ScanActionSource(files)
		if got == nil {
			t.Fatal("expected a mutable-remote-exec signal, got nil")
		}
		if got.DownloadGuard != "" {
			t.Fatalf("DownloadGuard = %q, want empty (negated: the fetch runs when rustup IS present)", got.DownloadGuard)
		}
	})

	// The positive if-form (no negation) must stay unguarded too: the
	// fetch there runs exactly when the tool IS present.
	t.Run("a positive if-check (no negation) gives no guard", func(t *testing.T) {
		files := map[string]string{
			"action.yml": "" +
				"runs:\n" +
				"  using: composite\n" +
				"  steps:\n" +
				"    - run: |\n" +
				"        if command -v rustup; then\n" +
				"          curl -sSf https://sh.rustup.rs | sh\n" +
				"        fi\n",
		}
		got := ScanActionSource(files)
		if got == nil {
			t.Fatal("expected a mutable-remote-exec signal, got nil")
		}
		if got.DownloadGuard != "" {
			t.Fatalf("DownloadGuard = %q, want empty (positive check: the fetch runs when rustup IS present)", got.DownloadGuard)
		}
	})

	// Fix round 3, item 3: the single-line `- run: command -v X ||
	// fetch` YAML form must still be recognized once reGuardCheck is
	// anchored: the YAML key ("- run:"/"run:") sits before the guard
	// check on the same physical line and must be stripped first.
	t.Run("a single-line YAML run key with a direct guard still names the tool", func(t *testing.T) {
		files := map[string]string{
			"action.yml": "" +
				"runs:\n" +
				"  using: composite\n" +
				"  steps:\n" +
				"    - run: command -v rustup || curl -sSf https://sh.rustup.rs | sh\n",
		}
		got := ScanActionSource(files)
		if got == nil {
			t.Fatal("expected a mutable-remote-exec signal, got nil")
		}
		if got.DownloadGuard != "rustup" {
			t.Fatalf("DownloadGuard = %q, want %q", got.DownloadGuard, "rustup")
		}
	})
}

// TestScanActionSource_DownloadVerifiedScope (fix round 1, item 2)
// pins that DownloadVerified is about a downloaded FILE, never a
// pipe-to-shell (which has no file to verify at all), and that a bare
// hash computation with no actual check never counts.
func TestScanActionSource_DownloadVerifiedScope(t *testing.T) {
	t.Run("pipe to shell plus an unrelated container digest", func(t *testing.T) {
		files := map[string]string{
			"action.yml": "" +
				"runs:\n" +
				"  using: composite\n" +
				"  steps:\n" +
				"    - run: |\n" +
				"        curl -sSfL https://example.com/i.sh | bash\n" +
				"        docker run alpine@sha256:e4fbd3c6481aa3af9bf6b1dd8b0a2c0a3b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e\n",
		}
		got := ScanActionSource(files)
		if got == nil {
			t.Fatal("expected a mutable-remote-exec signal, got nil")
		}
		if got.DownloadVerified {
			t.Fatal("DownloadVerified = true, want false (a pipe to a shell has no file to verify)")
		}
	})

	t.Run("pipe to shell plus a checksum check in the next step", func(t *testing.T) {
		files := map[string]string{
			"action.yml": "" +
				"runs:\n" +
				"  using: composite\n" +
				"  steps:\n" +
				"    - run: curl -sSf https://example.com/i.sh | sh\n" +
				"    - run: sha256sum -c other.sha256\n",
		}
		got := ScanActionSource(files)
		if got == nil {
			t.Fatal("expected a mutable-remote-exec signal, got nil")
		}
		if got.DownloadVerified {
			t.Fatal("DownloadVerified = true, want false (a pipe to a shell is never verified, whatever runs after it)")
		}
	})

	t.Run("a bare hash computation with no check never counts", func(t *testing.T) {
		files := map[string]string{
			"action.yml": "" +
				"runs:\n" +
				"  using: composite\n" +
				"  steps:\n" +
				"    - run: |\n" +
				"        curl -fsSL -o somefile.sh https://raw.githubusercontent.com/o/r/main/somefile.sh\n" +
				"        shasum -a 256 somefile.sh\n",
		}
		got := ScanActionSource(files)
		if got == nil {
			t.Fatal("expected a mutable-remote-exec signal, got nil")
		}
		if got.DownloadVerified {
			t.Fatal("DownloadVerified = true, want false (shasum -a 256 alone prints a hash, it checks nothing)")
		}
	})

	t.Run("a checksum check of the actual downloaded file counts", func(t *testing.T) {
		files := map[string]string{
			"action.yml": "" +
				"runs:\n" +
				"  using: composite\n" +
				"  steps:\n" +
				"    - run: |\n" +
				"        curl -fsSL -o cs.sh https://raw.githubusercontent.com/o/r/main/cs.sh\n" +
				"        echo \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  cs.sh\" | sha256sum -c -\n",
		}
		got := ScanActionSource(files)
		if got == nil {
			t.Fatal("expected a mutable-remote-exec signal, got nil")
		}
		if !got.DownloadVerified {
			t.Fatal("DownloadVerified = false, want true (the checksum names the actual downloaded file)")
		}
	})

	// Fix round 2, item 2: a verify command in the SAME step, that
	// checks an UNRELATED sums file, must not count just because the
	// step separately mentions the downloaded file's name on the
	// download line itself (the co-occurrence fallback this closes).
	t.Run("a checksum check of an unrelated sums file never counts", func(t *testing.T) {
		files := map[string]string{
			"action.yml": "" +
				"runs:\n" +
				"  using: composite\n" +
				"  steps:\n" +
				"    - run: |\n" +
				"        curl -fsSL -o install.sh https://raw.githubusercontent.com/o/r/main/install.sh\n" +
				"        sha256sum -c other.sha256\n" +
				"        bash install.sh\n",
		}
		got := ScanActionSource(files)
		if got == nil {
			t.Fatal("expected a mutable-remote-exec signal, got nil")
		}
		if got.DownloadVerified {
			t.Fatal("DownloadVerified = true, want false (other.sha256 was never written in this step, let alone naming install.sh)")
		}
	})

	// A `sha256sum -c <sums>` DOES count once the sums file was
	// written earlier in the step by a line naming the downloaded
	// file.
	t.Run("a checksum check of a sums file written in the same step counts", func(t *testing.T) {
		files := map[string]string{
			"action.yml": "" +
				"runs:\n" +
				"  using: composite\n" +
				"  steps:\n" +
				"    - run: |\n" +
				"        curl -fsSL -o install.sh https://raw.githubusercontent.com/o/r/main/install.sh\n" +
				"        echo \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  install.sh\" > sums.txt\n" +
				"        sha256sum -c sums.txt\n",
		}
		got := ScanActionSource(files)
		if got == nil {
			t.Fatal("expected a mutable-remote-exec signal, got nil")
		}
		if !got.DownloadVerified {
			t.Fatal("DownloadVerified = false, want true (sums.txt was written in this step naming install.sh)")
		}
	})

	// A literal 64-hex digest on the download line itself (a
	// coincidental trailing token, naming the file it is downloading
	// right there) must never count as the file's own verification.
	t.Run("a literal digest on the download line itself never counts", func(t *testing.T) {
		files := map[string]string{
			"action.yml": "" +
				"runs:\n" +
				"  using: composite\n" +
				"  steps:\n" +
				"    - run: |\n" +
				"        curl -fsSL -o install.sh https://raw.githubusercontent.com/o/r/main/install.sh # aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa install.sh\n" +
				"        bash install.sh\n",
		}
		got := ScanActionSource(files)
		if got == nil {
			t.Fatal("expected a mutable-remote-exec signal, got nil")
		}
		if got.DownloadVerified {
			t.Fatal("DownloadVerified = true, want false (the digest-looking token is on the download line itself)")
		}
	})

	// Fix round 3, item 1a: a literal digest that is only PRINTED,
	// never fed into an actual check, proves nothing.
	t.Run("a bare echo of the expected digest never counts", func(t *testing.T) {
		files := map[string]string{
			"action.yml": "" +
				"runs:\n" +
				"  using: composite\n" +
				"  steps:\n" +
				"    - run: |\n" +
				"        curl -fsSL -o install.sh https://raw.githubusercontent.com/o/r/main/install.sh\n" +
				"        echo \"expected aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa for install.sh\"\n" +
				"        bash install.sh\n",
		}
		got := ScanActionSource(files)
		if got == nil {
			t.Fatal("expected a mutable-remote-exec signal, got nil")
		}
		if got.DownloadVerified {
			t.Fatal("DownloadVerified = true, want false (the digest is only echoed, never checked)")
		}
	})

	// A digest piped into sha256sum -c, or fed to a comparison, DOES
	// feed a check: the two already-green positive shapes, pinned
	// explicitly now that the bare echo above must fail.
	t.Run("sha256sum of the file piped into grep for the expected digest counts", func(t *testing.T) {
		files := map[string]string{
			"action.yml": "" +
				"runs:\n" +
				"  using: composite\n" +
				"  steps:\n" +
				"    - run: |\n" +
				"        curl -fsSL -o install.sh https://raw.githubusercontent.com/o/r/main/install.sh\n" +
				"        sha256sum install.sh | grep -q aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
		}
		got := ScanActionSource(files)
		if got == nil {
			t.Fatal("expected a mutable-remote-exec signal, got nil")
		}
		if !got.DownloadVerified {
			t.Fatal("DownloadVerified = false, want true (sha256sum of the actual file is grepped for the expected digest)")
		}
	})

	// A comparison counts only when the literal digest is an OPERAND
	// of it: a bracket followed later by an equals sign is not one.
	t.Run("a bracketed echo carrying a digest after an equals sign never counts", func(t *testing.T) {
		files := map[string]string{
			"action.yml": "" +
				"runs:\n" +
				"  using: composite\n" +
				"  steps:\n" +
				"    - run: |\n" +
				"        curl -fsSL -o install.sh https://raw.githubusercontent.com/o/r/main/install.sh\n" +
				"        echo \"[download] install.sh sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n" +
				"        bash install.sh\n",
		}
		got := ScanActionSource(files)
		if got == nil {
			t.Fatal("expected a mutable-remote-exec signal, got nil")
		}
		if got.DownloadVerified {
			t.Fatal("DownloadVerified = true, want false (the digest is printed by echo, never compared)")
		}
	})

	t.Run("a digest in a comment after an unrelated comparison never counts", func(t *testing.T) {
		files := map[string]string{
			"action.yml": "" +
				"runs:\n" +
				"  using: composite\n" +
				"  steps:\n" +
				"    - run: |\n" +
				"        curl -fsSL -o install.sh https://raw.githubusercontent.com/o/r/main/install.sh\n" +
				"        [ \"$a\" = \"$b\" ] # aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa install.sh\n" +
				"        bash install.sh\n",
		}
		got := ScanActionSource(files)
		if got == nil {
			t.Fatal("expected a mutable-remote-exec signal, got nil")
		}
		if got.DownloadVerified {
			t.Fatal("DownloadVerified = true, want false (the digest sits in a comment, not in the comparison)")
		}
	})

	t.Run("a comparison against the digest inside test brackets counts", func(t *testing.T) {
		files := map[string]string{
			"action.yml": "" +
				"runs:\n" +
				"  using: composite\n" +
				"  steps:\n" +
				"    - run: |\n" +
				"        curl -fsSL -o install.sh https://raw.githubusercontent.com/o/r/main/install.sh\n" +
				"        [ \"$(sha256sum install.sh | cut -d' ' -f1)\" = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\" ]\n",
		}
		got := ScanActionSource(files)
		if got == nil {
			t.Fatal("expected a mutable-remote-exec signal, got nil")
		}
		if !got.DownloadVerified {
			t.Fatal("DownloadVerified = false, want true (the digest feeds a [ = ] comparison)")
		}
	})

	// Fix round 3, item 1b: a sums file self-generated by computing the
	// hash at runtime (sha256sum install.sh > sums.txt) is NOT a pinned
	// digest: nothing commits it, it just reflects whatever the
	// download currently is.
	t.Run("a self-generated sums file never counts", func(t *testing.T) {
		files := map[string]string{
			"action.yml": "" +
				"runs:\n" +
				"  using: composite\n" +
				"  steps:\n" +
				"    - run: |\n" +
				"        curl -fsSL -o install.sh https://raw.githubusercontent.com/o/r/main/install.sh\n" +
				"        sha256sum install.sh > sums.txt\n" +
				"        sha256sum -c sums.txt\n",
		}
		got := ScanActionSource(files)
		if got == nil {
			t.Fatal("expected a mutable-remote-exec signal, got nil")
		}
		if got.DownloadVerified {
			t.Fatal("DownloadVerified = true, want false (the sums file is computed at runtime, not a pinned digest)")
		}
	})

	// Fix round 3, item 1c: a sums file fetched from the same moving
	// ref is no more pinned than the download itself.
	t.Run("a sums file fetched from the same moving ref never counts", func(t *testing.T) {
		files := map[string]string{
			"action.yml": "" +
				"runs:\n" +
				"  using: composite\n" +
				"  steps:\n" +
				"    - run: |\n" +
				"        curl -fsSL -o install.sh https://raw.githubusercontent.com/o/r/main/install.sh\n" +
				"        curl -fsSL -o sums.txt https://raw.githubusercontent.com/o/r/main/install.sh.sha256\n" +
				"        sha256sum -c sums.txt\n",
		}
		got := ScanActionSource(files)
		if got == nil {
			t.Fatal("expected a mutable-remote-exec signal, got nil")
		}
		if got.DownloadVerified {
			t.Fatal("DownloadVerified = true, want false (the sums file itself is fetched from the same mutable source)")
		}
	})

	// A literal digest in a heredoc BODY line, writing the sums file,
	// counts too: the digest and the file name need not sit on the
	// write line itself.
	t.Run("a sums file written via a heredoc with the digest in its body counts", func(t *testing.T) {
		files := map[string]string{
			"action.yml": "" +
				"runs:\n" +
				"  using: composite\n" +
				"  steps:\n" +
				"    - run: |\n" +
				"        curl -fsSL -o install.sh https://raw.githubusercontent.com/o/r/main/install.sh\n" +
				"        cat > sums.txt <<EOF\n" +
				"        aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  install.sh\n" +
				"        EOF\n" +
				"        sha256sum -c sums.txt\n",
		}
		got := ScanActionSource(files)
		if got == nil {
			t.Fatal("expected a mutable-remote-exec signal, got nil")
		}
		if !got.DownloadVerified {
			t.Fatal("DownloadVerified = false, want true (the heredoc body carries the digest and names install.sh)")
		}
	})
}

// TestScanActionSource_EveryFetchMustQualify (fix round 1, item 6)
// pins that ScanActionSource collects every exec fetch in the action
// source, not just the first: the anchor is suppressed only when
// EVERY one of them is guarded or verified, never when just the first
// one happens to be.
func TestScanActionSource_EveryFetchMustQualify(t *testing.T) {
	files := map[string]string{
		"action.yml": "" +
			"runs:\n" +
			"  using: composite\n" +
			"  steps:\n" +
			"    - run: |\n" +
			"        if ! command -v rustup; then\n" +
			"          curl -sSf https://sh.rustup.rs | sh\n" +
			"        fi\n" +
			"    - run: curl -sSfL https://example.com/unrelated.sh | bash\n",
	}
	got := ScanActionSource(files)
	if got == nil {
		t.Fatal("expected a mutable-remote-exec signal, got nil")
	}
	if got.Tier != "exec" {
		t.Fatalf("Tier = %q, want %q (the strongest fetch)", got.Tier, "exec")
	}
	if got.DownloadGuard != "" {
		t.Fatalf("DownloadGuard = %q, want empty: the second fetch is unguarded, so the action as a whole is not protected", got.DownloadGuard)
	}
	if got.DownloadVerified {
		t.Fatal("DownloadVerified = true, want false: the second fetch is not verified either")
	}
}

// TestScanActionSource_DownloadVerifiedBeforeTheRunOfTheWholeToken pins
// two limits of the verification reading. A check counts only when it
// runs between the download and the first run of the downloaded file:
// a digest checked after the code already ran, or a signature verified
// before the file even exists, proves nothing about what executed. And
// the check must name the downloaded file as a whole token: a digest of
// nodejs.tar.gz is no verification of a file called node.
func TestScanActionSource_DownloadVerifiedBeforeTheRunOfTheWholeToken(t *testing.T) {
	const digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	head := "runs:\n  using: composite\n  steps:\n    - run: |\n"
	cases := []struct {
		name string
		body string
		want bool
	}{
		{
			"a checksum checked after the file ran never counts",
			"        curl https://raw.githubusercontent.com/acme/tools/main/payload -o payload\n" +
				"        bash payload\n" +
				"        echo \"" + digest + "  payload\" | sha256sum -c\n",
			false,
		},
		{
			"a signature verified before the download never counts",
			"        gpg --verify payload.sig payload\n" +
				"        curl https://raw.githubusercontent.com/acme/tools/main/payload -o payload\n" +
				"        bash payload\n",
			false,
		},
		{
			"a signature verified between the download and the run counts",
			"        curl https://raw.githubusercontent.com/acme/tools/main/payload -o payload\n" +
				"        gpg --verify payload.sig payload\n" +
				"        bash payload\n",
			true,
		},
		{
			"a checksum of another file whose name contains the download never counts",
			"        curl https://raw.githubusercontent.com/acme/tools/main/node -o node\n" +
				"        curl -o nodejs.tar.gz https://releases.example.com/nodejs.tar.gz\n" +
				"        echo \"" + digest + "  nodejs.tar.gz\" | sha256sum -c\n" +
				"        ./node\n",
			false,
		},
		{
			"a checksum of the download itself between the download and the run counts",
			"        curl https://raw.githubusercontent.com/acme/tools/main/node -o node\n" +
				"        echo \"" + digest + "  node\" | sha256sum -c\n" +
				"        ./node\n",
			true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ScanActionSource(map[string]string{"action.yml": head + c.body})
			if got == nil {
				t.Fatal("expected a mutable-remote-exec signal, got nil")
			}
			if got.DownloadVerified != c.want {
				t.Fatalf("DownloadVerified = %v, want %v", got.DownloadVerified, c.want)
			}
		})
	}
}
