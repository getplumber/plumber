package situation_test

import (
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

// impactOn runs the facts policy on one GitHub job and returns its
// impacts by kind.
func impactOn(t *testing.T, job ir.Job) map[string]impact {
	t.Helper()
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: []ir.Job{job}}
	return impactKinds(evaluate(t, p, nil).Jobs[job.Name].Impact)
}

var idTokenWrite = map[string]string{"contents": "read", "id-token": "write"}

// TestImpactNpmPublishInALocalAction pins that a step calling a local
// action whose name says it publishes to npm is a publishes impact: the
// command itself sits in the action, out of the workflow's text. With a
// declared id-token write (npm trusted publishing) it is proven; without
// one Plumber cannot check what the action runs.
func TestImpactNpmPublishInALocalAction(t *testing.T) {
	step := ir.Action{Uses: "./.github/actions/build-npm-package", Name: "Build and Publish NPM Package"}
	got := impactOn(t, ir.Job{Name: "publish", Environment: "npm-publish", Permissions: idTokenWrite, Uses: []ir.Action{step}})
	if i, ok := got["publishes"]; !ok || i.State != "proven" {
		t.Errorf("with id-token write: publishes = %+v, want proven", i)
	}
	got = impactOn(t, ir.Job{Name: "publish", Permissions: map[string]string{"contents": "read"}, Uses: []ir.Action{step}})
	if i, ok := got["publishes"]; !ok || i.State != "unresolvable" {
		t.Errorf("without id-token write: publishes = %+v, want unresolvable", i)
	}
	other := ir.Action{Uses: "./.github/actions/build", Name: "Build the package"}
	if i, ok := impactOn(t, ir.Job{Name: "build", Uses: []ir.Action{other}})["publishes"]; ok {
		t.Errorf("a step not named for a publish must not publish, got %+v", i)
	}
}

// TestImpactCodeSigning pins the code-signing steps: importing a signing
// certificate (apple-actions/import-codesign-certs, `security import` of
// a .p12) and signing with `codesign`. Code signing uses the certificate,
// not the job token, so it is proven whatever the token is, the assumed
// default one included (no permissions block).
func TestImpactCodeSigning(t *testing.T) {
	perms := map[string]string{"contents": "read"}
	cases := []ir.Job{
		{Name: "a", Permissions: perms, Uses: []ir.Action{{Uses: "apple-actions/import-codesign-certs@v3"}}},
		{Name: "b", Permissions: perms, Scripts: []string{"security import cert.p12 -k build.keychain -P \"$PWD\""}},
		{Name: "c", Permissions: perms, Scripts: []string{"codesign --force --sign \"$IDENTITY\" build/App.app"}},
		{Name: "d", Uses: []ir.Action{{Uses: "apple-actions/import-codesign-certs@v3"}}},
		{Name: "e", Scripts: []string{"codesign -s \"$IDENTITY\" build/App.app"}},
	}
	for _, job := range cases {
		if i, ok := impactOn(t, job)["signs_or_releases"]; !ok || i.State != "proven" {
			t.Errorf("%s: signs_or_releases = %+v, want proven", job.Name, i)
		}
	}
	verify := ir.Job{Name: "v", Permissions: perms, Scripts: []string{"codesign --verify --deep build/App.app"}}
	if i, ok := impactOn(t, verify)["signs_or_releases"]; ok {
		t.Errorf("codesign --verify signs nothing, got %+v", i)
	}
}

// TestImpactSentryReleaseDeploy pins `sentry-cli releases deploys` as a
// deployment.
func TestImpactSentryReleaseDeploy(t *testing.T) {
	job := ir.Job{Name: "sentry", Scripts: []string{"sentry-cli releases finalize $R\nsentry-cli releases deploys $R new -e production"}}
	i, ok := impactOn(t, job)["deploys"]
	if !ok || i.State != "proven" {
		t.Fatalf("deploys = %+v, want proven", i)
	}
	if i.Evidence != "sentry-cli releases deploys $R new -e production" {
		t.Errorf("evidence = %q, want the deploy line", i.Evidence)
	}
}

// TestImpactTrustedPublishing pins that a registry upload through trusted
// publishing (pypa/gh-action-pypi-publish) is one publishes impact, with or
// without the id-token write: the attestation the registry makes is part
// of the publish, not a second impact. npm publish --provenance signs the
// provenance on top of publishing, a signing step proven by id-token.
func TestImpactTrustedPublishing(t *testing.T) {
	step := ir.Action{Uses: "pypa/gh-action-pypi-publish@release/v1"}
	for _, perms := range []map[string]string{idTokenWrite, {"contents": "read"}} {
		got := impactOn(t, ir.Job{Name: "pypi", Permissions: perms, Uses: []ir.Action{step}})
		if i, ok := got["signs_or_releases"]; ok {
			t.Errorf("%v: signs_or_releases = %+v, want none", perms, i)
		}
		if _, ok := got["publishes"]; !ok {
			t.Errorf("%v: publishes missing", perms)
		}
	}
	npm := ir.Job{Name: "npm", Permissions: idTokenWrite, Scripts: []string{"npm publish --provenance --access public"}}
	if i, ok := impactOn(t, npm)["signs_or_releases"]; !ok || i.State != "proven" {
		t.Errorf("npm publish --provenance: signs_or_releases = %+v, want proven", i)
	}
}
