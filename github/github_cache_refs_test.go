package github

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

// cachesOf parses one workflow and returns the caches of its first job,
// stripped of the step line so the cases read on keys and modes.
func cachesOf(t *testing.T, workflow string) []ir.CacheRef {
	t.Helper()
	jobs, err := parseGitHubWorkflowJobs([]byte(workflow), "ci", ".github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) == 0 {
		t.Fatal("no job parsed")
	}
	out := jobs[0].Caches
	for i := range out {
		if out[i].Line == 0 {
			t.Errorf("cache %d carries no step line: %+v", i, out[i])
		}
		out[i].Line = 0
	}
	return out
}

const rustCacheWorkflow = `
name: ci
on: push
jobs:
  build-mac:
    runs-on: macos-latest
    steps:
      - uses: Swatinem/rust-cache@v2
%s
`

func rustCacheWith(with string) string {
	if with == "" {
		return fmt.Sprintf(rustCacheWorkflow, "")
	}
	return fmt.Sprintf(rustCacheWorkflow, "        with:\n"+with)
}

// TestRustCacheRecordsItsKeyFamily pins the key Swatinem/rust-cache saves
// and restores under: prefix-key (default v0-rust), then shared-key when
// given, else the key input followed by the job id (the action adds it
// unless add-job-id-key is false); the rest of the key (the toolchain and
// lock file hashes) is only known at run time, so the entry is a prefix,
// restored from the most recent cache under it. Key is what two jobs must
// share to reach each other's cache; Family, the key without the job id,
// is the name a reader recognizes. save-if: false makes the step restore
// only.
func TestRustCacheRecordsItsKeyFamily(t *testing.T) {
	const uses = "Swatinem/rust-cache@v2"
	cases := []struct {
		name, with string
		want       ir.CacheRef
	}{
		{"defaults", "", ir.CacheRef{Key: "v0-rust-build-mac", Family: "v0-rust", Mode: "both", Prefix: true, Uses: uses}},
		{"prefix-key", "          prefix-key: ${{ matrix.job.os }}\n", ir.CacheRef{Key: "${{ matrix.job.os }}-build-mac", Family: "${{ matrix.job.os }}", Mode: "both", Prefix: true, Uses: uses}},
		{"shared-key replaces the job part", "          prefix-key: v1\n          shared-key: deps\n          key: ignored\n", ir.CacheRef{Key: "v1-deps", Family: "v1-deps", Mode: "both", Prefix: true, Uses: uses}},
		{"key follows the prefix", "          prefix-key: lib\n          key: ${{ matrix.job.target }}\n", ir.CacheRef{Key: "lib-${{ matrix.job.target }}-build-mac", Family: "lib-${{ matrix.job.target }}", Mode: "both", Prefix: true, Uses: uses}},
		{"no job id", "          add-job-id-key: false\n", ir.CacheRef{Key: "v0-rust", Family: "v0-rust", Mode: "both", Prefix: true, Uses: uses}},
		{"save-if false restores only", "          save-if: false\n", ir.CacheRef{Key: "v0-rust-build-mac", Family: "v0-rust", Mode: "restore", Prefix: true, Uses: uses}},
		{"save-if quoted false restores only", "          save-if: 'false'\n", ir.CacheRef{Key: "v0-rust-build-mac", Family: "v0-rust", Mode: "restore", Prefix: true, Uses: uses}},
		{"save-if expression may save", "          save-if: ${{ github.ref == 'refs/heads/main' }}\n", ir.CacheRef{Key: "v0-rust-build-mac", Family: "v0-rust", Mode: "both", Prefix: true, Uses: uses}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := cachesOf(t, rustCacheWith(c.with))
			if !reflect.DeepEqual(got, []ir.CacheRef{c.want}) {
				t.Errorf("caches = %+v, want %+v", got, c.want)
			}
		})
	}
	lower := cachesOf(t, "name: ci\non: push\njobs:\n  b:\n    runs-on: x\n    steps:\n      - uses: swatinem/rust-cache@v2\n")
	if len(lower) != 1 || lower[0].Family != "v0-rust" {
		t.Errorf("an owner spelled in lower case is the same action: %+v", lower)
	}
}

// TestSetupActionCachesRecordTheirManager pins the built-in caches of the
// setup actions and the other caching actions, saved and restored, and
// none when the cache is off. A setup action keys its cache exactly on
// the manager and the hash of its dependency files, restoring that key
// alone: the entry is no prefix, and its key carries cache-dependency-path
// when given, two lock files being two caches. A buildx gha cache is keyed
// by its scope (default buildkit), one entry per scope it reads or
// writes. Family is the name a reader recognizes, the key without the
// part that tells two caches of one kind apart.
func TestSetupActionCachesRecordTheirManager(t *testing.T) {
	cases := []struct {
		name, step string
		want       []ir.CacheRef
	}{
		{"setup-node with npm", "      - uses: actions/setup-node@v5\n        with:\n          cache: npm\n",
			[]ir.CacheRef{{Key: "setup-node-npm", Family: "setup-node-npm", Mode: "both", Uses: "actions/setup-node@v5"}}},
		{"setup-node with a dependency path", "      - uses: actions/setup-node@v5\n        with:\n          cache: npm\n          cache-dependency-path: ./docs/package-lock.json\n",
			[]ir.CacheRef{{Key: "setup-node-npm (./docs/package-lock.json)", Family: "setup-node-npm", Mode: "both", Uses: "actions/setup-node@v5"}}},
		{"setup-python with two dependency paths", "      - uses: actions/setup-python@v5\n        with:\n          cache: pip\n          cache-dependency-path: |\n            a/requirements.txt\n            b/requirements.txt\n",
			[]ir.CacheRef{{Key: "setup-python-pip (a/requirements.txt, b/requirements.txt)", Family: "setup-python-pip", Mode: "both", Uses: "actions/setup-python@v5"}}},
		{"setup-node without cache", "      - uses: actions/setup-node@v5\n", nil},
		{"setup-python with pip", "      - uses: actions/setup-python@v5\n        with:\n          cache: pip\n",
			[]ir.CacheRef{{Key: "setup-python-pip", Family: "setup-python-pip", Mode: "both", Uses: "actions/setup-python@v5"}}},
		{"setup-java with gradle", "      - uses: actions/setup-java@v5\n        with:\n          cache: gradle\n",
			[]ir.CacheRef{{Key: "setup-java-gradle", Family: "setup-java-gradle", Mode: "both", Uses: "actions/setup-java@v5"}}},
		{"setup-go caches by default", "      - uses: actions/setup-go@v5\n",
			[]ir.CacheRef{{Key: "setup-go", Family: "setup-go", Mode: "both", Uses: "actions/setup-go@v5"}}},
		{"setup-go with a dependency path", "      - uses: actions/setup-go@v5\n        with:\n          cache-dependency-path: tools/go.sum\n",
			[]ir.CacheRef{{Key: "setup-go (tools/go.sum)", Family: "setup-go", Mode: "both", Uses: "actions/setup-go@v5"}}},
		{"setup-go cache off", "      - uses: actions/setup-go@v5\n        with:\n          cache: false\n", nil},
		{"setup-dotnet cache on", "      - uses: actions/setup-dotnet@v5\n        with:\n          cache: true\n",
			[]ir.CacheRef{{Key: "setup-dotnet", Family: "setup-dotnet", Mode: "both", Uses: "actions/setup-dotnet@v5"}}},
		{"setup-gradle", "      - uses: gradle/actions/setup-gradle@v5\n",
			[]ir.CacheRef{{Key: "gradle", Family: "gradle", Mode: "both", Prefix: true, Uses: "gradle/actions/setup-gradle@v5"}}},
		{"gradle-build-action", "      - uses: gradle/gradle-build-action@v3\n",
			[]ir.CacheRef{{Key: "gradle", Family: "gradle", Mode: "both", Prefix: true, Uses: "gradle/gradle-build-action@v3"}}},
		{"setup-gradle cache off", "      - uses: gradle/actions/setup-gradle@v5\n        with:\n          cache-disabled: true\n", nil},
		{"setup-gradle read only", "      - uses: gradle/actions/setup-gradle@v5\n        with:\n          cache-read-only: true\n",
			[]ir.CacheRef{{Key: "gradle", Family: "gradle", Mode: "restore", Prefix: true, Uses: "gradle/actions/setup-gradle@v5"}}},
		{"pnpm action-setup with cache", "      - uses: pnpm/action-setup@v5\n        with:\n          cache: true\n",
			[]ir.CacheRef{{Key: "pnpm/action-setup", Family: "pnpm/action-setup", Mode: "both", Prefix: true, Uses: "pnpm/action-setup@v5"}}},
		{"buildx gha cache", "      - uses: docker/build-push-action@v6\n        with:\n          cache-from: type=gha\n          cache-to: type=gha,mode=max\n",
			[]ir.CacheRef{{Key: "docker/build-push-action (scope=buildkit)", Family: "docker/build-push-action", Mode: "both", Uses: "docker/build-push-action@v6"}}},
		{"buildx gha cache read only", "      - uses: docker/build-push-action@v6\n        with:\n          cache-from: type=gha\n",
			[]ir.CacheRef{{Key: "docker/build-push-action (scope=buildkit)", Family: "docker/build-push-action", Mode: "restore", Uses: "docker/build-push-action@v6"}}},
		{"buildx gha scopes", "      - uses: docker/build-push-action@v6\n        with:\n          cache-from: |\n            type=gha,scope=main-${{ matrix.arch }}\n            type=gha,scope=pr\n          cache-to: type=gha,mode=max,scope=pr\n",
			[]ir.CacheRef{
				{Key: "docker/build-push-action (scope=main-${{ matrix.arch }})", Family: "docker/build-push-action", Mode: "restore", Uses: "docker/build-push-action@v6"},
				{Key: "docker/build-push-action (scope=pr)", Family: "docker/build-push-action", Mode: "both", Uses: "docker/build-push-action@v6"},
			}},
		{"buildx registry cache", "      - uses: docker/build-push-action@v6\n        with:\n          cache-from: type=registry,ref=x\n", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wf := "name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n" + c.step
			if got := cachesOf(t, wf); !reflect.DeepEqual(got, c.want) {
				t.Errorf("caches = %+v, want %+v", got, c.want)
			}
		})
	}
}
