package situation_test

import (
	"reflect"
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

// shippedPublishConfig is the publish inventory of the shipped default
// configuration (defaultConfig/.plumber.yaml), the one a real run hands the
// facts policy: it names no docker action and lists the release actions as
// publish actions.
var shippedPublishConfig = map[string]any{"cachePoisoning": map[string]any{
	"publishActions": []any{
		"pypa/gh-action-pypi-publish", "JS-DevTools/npm-publish", "gradle/publish-plugin",
		"softprops/action-gh-release", "ncipollo/release-action", "goreleaser/goreleaser-action",
		"crazy-max/ghaction-docker-buildx", "changesets/action",
	},
	"publishScriptPatterns": []any{
		`(?i)(npm|pnpm|yarn|bun)\s+publish`, `(?i)cargo\s+publish`, `(?i)twine\s+upload`,
		`(?i)poetry\s+publish`, `(?i)gh\s+release\s+create`, `(?i)goreleaser\s+release`,
		`(?i)semantic-release`, `(?i)gradlew?\b[^\n]*\bpublish`, `(?i)\bmvnw?\b[^\n]*\bdeploy\b`,
		`(?i)dotnet\s+nuget\s+push`, `(?i)gem\s+push`, `(?i)docker\s+push`,
	},
}}

// impactsWithConfig runs the facts policy on one GitHub job under cfg and
// returns its impacts as kind to state, every kind once.
func impactsWithConfig(t *testing.T, job ir.Job, cfg map[string]any) map[string]string {
	t.Helper()
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: []ir.Job{job}}
	out := map[string]string{}
	for _, i := range evaluate(t, p, cfg).Jobs[job.Name].Impact {
		if _, dup := out[i.Kind]; dup {
			t.Errorf("%s: kind %s counted twice", job.Name, i.Kind)
		}
		out[i.Kind] = i.State
	}
	return out
}

// TestKnownStepsAreOneImpactEach pins the impact of the steps whose effect
// is known by definition, whatever the configured publish inventory says:
// an image build that pushes publishes, a release action or a release
// command releases (never also publishes), a registry upload command
// publishes once (never also a release), a commit or pull request action
// pushes to the repository (proven: pushing is all it does). The token is
// read-only, so no impact comes from it.
func TestKnownStepsAreOneImpactEach(t *testing.T) {
	read := map[string]any{"contents": "read"}
	cases := []struct {
		name string
		job  ir.Job
		want map[string]string
	}{
		{"docker push", ir.Job{Uses: []ir.Action{{Uses: "docker/build-push-action@v7", With: map[string]any{"push": true}}}}, map[string]string{"publishes": "proven"}},
		{"blacksmith push", ir.Job{Uses: []ir.Action{{Uses: "useblacksmith/build-push-action@v2", With: map[string]any{"push": "true"}}}}, map[string]string{"publishes": "proven"}},
		{"docker no push", ir.Job{Uses: []ir.Action{{Uses: "docker/build-push-action@v7"}}}, map[string]string{}},
		{"buildx push", ir.Job{Scripts: []string{"docker buildx build --push -t ghcr.io/o/x ."}}, map[string]string{"publishes": "proven"}},
		{"imagetools", ir.Job{Scripts: []string{"docker buildx imagetools create -t \"${DEST}\" \"${SOURCE}\""}}, map[string]string{"publishes": "proven"}},
		{"gh release action", ir.Job{Uses: []ir.Action{{Uses: "softprops/action-gh-release@v2"}}}, map[string]string{"signs_or_releases": "proven"}},
		{"upload release action", ir.Job{Uses: []ir.Action{{Uses: "svenstaro/upload-release-action@v2"}}}, map[string]string{"signs_or_releases": "proven"}},
		{"release-tag", ir.Job{Uses: []ir.Action{{Uses: "yyx990803/release-tag@master"}}}, map[string]string{"signs_or_releases": "proven"}},
		{"gh release create", ir.Job{Scripts: []string{"gh release create v1 dist/*"}}, map[string]string{"signs_or_releases": "proven"}},
		{"komac submit", ir.Job{Scripts: []string{"komac update --version 1 --token ${{ secrets.T }} --submit ggml.llamacpp"}}, map[string]string{"publishes": "proven"}},
		{"komac dry", ir.Job{Scripts: []string{"komac update --version 1 ggml.llamacpp"}}, map[string]string{}},
		{"twine", ir.Job{Scripts: []string{"python -m twine upload dist/*"}}, map[string]string{"publishes": "proven"}},
		{"uv publish", ir.Job{Scripts: []string{"uv publish --trusted-publishing always"}}, map[string]string{"publishes": "proven"}},
		{"pdm publish", ir.Job{Scripts: []string{"pdm publish"}}, map[string]string{"publishes": "proven"}},
		{"poetry publish", ir.Job{Scripts: []string{"poetry publish --build"}}, map[string]string{"publishes": "proven"}},
		{"pypi action", ir.Job{Permissions: idTokenWrite, Uses: []ir.Action{{Uses: "pypa/gh-action-pypi-publish@release/v1"}}}, map[string]string{"publishes": "proven"}},
		{"create pull request", ir.Job{Uses: []ir.Action{{Uses: "peter-evans/create-pull-request@v7"}}}, map[string]string{"writes_repo": "proven"}},
		{"auto commit", ir.Job{Uses: []ir.Action{{Uses: "stefanzweifel/git-auto-commit-action@v7"}}}, map[string]string{"writes_repo": "proven"}},
		{"auto commit default token", ir.Job{Permissions: nil, Uses: []ir.Action{{Uses: "stefanzweifel/git-auto-commit-action@v7"}}}, map[string]string{"writes_repo": "proven"}},
		{"ad hoc signature", ir.Job{Scripts: []string{`codesign -s - "$SISO_BIN" || true`}}, map[string]string{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			job := c.job
			job.Name = "job"
			if job.Permissions == nil && c.name != "auto commit default token" {
				job.Permissions = read
			}
			if got := impactsWithConfig(t, job, shippedPublishConfig); !reflect.DeepEqual(got, c.want) {
				t.Errorf("impacts = %v, want %v", got, c.want)
			}
		})
	}
}

// TestALocalPublishScriptIsUnresolvable pins that a run step calling a
// repository script whose file name says it uploads or publishes is a
// publishes impact Plumber cannot check (the commands sit in the script).
func TestALocalPublishScriptIsUnresolvable(t *testing.T) {
	read := map[string]any{"contents": "read"}
	for _, line := range []string{"bash .ci/pytorch/binary_upload.sh", "./scripts/publish-rust-crates.sh", "python3 tools/upload_wheels.py"} {
		got := impactsWithConfig(t, ir.Job{Name: "job", Permissions: read, Scripts: []string{line}}, shippedPublishConfig)
		if !reflect.DeepEqual(got, map[string]string{"publishes": "unresolvable"}) {
			t.Errorf("%q: impacts = %v, want an unresolvable publish", line, got)
		}
	}
	got := impactsWithConfig(t, ir.Job{Name: "job", Permissions: read, Scripts: []string{"bash scripts/build.sh"}}, shippedPublishConfig)
	if len(got) != 0 {
		t.Errorf("a build script is no impact, got %v", got)
	}
}
