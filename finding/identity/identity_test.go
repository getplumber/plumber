package identity_test

import (
	"slices"
	"testing"

	"github.com/getplumber/plumber/finding/identity"
)

// The whole point of the package: a consumer that needs to group findings into
// issues across runs gets the selected fields as data, not only a hash.
func TestOf_ReturnsTheSelectedFieldsAsData(t *testing.T) {
	f := identity.Finding{
		Code:    "ISSUE-701",
		File:    ".github/workflows/ci.yml",
		Job:     "build",
		Message: "job \"build\" references action \"owner/act@v1\" with a mutable ref",
		Data:    map[string]any{"uses": "owner/act@v1", "step": "Check out"},
	}
	got, ok := identity.Of(f)
	if !ok {
		t.Fatalf("Of reported no identity for a coded finding")
	}
	if got.Code != "ISSUE-701" || got.File != ".github/workflows/ci.yml" || got.Job != "build" {
		t.Errorf("canonical fields not selected: %+v", got)
	}
	if got.Subject.Key != "uses" || got.Subject.Value != "owner/act@v1" {
		t.Errorf("subject = %+v, want uses=owner/act@v1", got.Subject)
	}
	if got.Step != "Check out" {
		t.Errorf("step = %q, want %q", got.Step, "Check out")
	}
	// The version is part of what Of returns, not just a package constant: a
	// consumer stores the two together, and a Fields carrying version 0 would
	// silently defeat the detection a later bump exists to trigger. Pinned here
	// on the structured-subject branch, and again on the fallback branch, since
	// Of returns from two places.
	if got.Version != identity.RecipeVersion {
		t.Errorf("Version = %d, want %d", got.Version, identity.RecipeVersion)
	}
}

// Pairs is the wire form the platform stores: the selected key/value pairs, in
// the order they contribute to identity.
func TestFields_PairsAreOrderedAndComplete(t *testing.T) {
	f := identity.Finding{
		Code: "ISSUE-701", File: "ci.yml", Job: "build",
		Data: map[string]any{"uses": "owner/act@v1", "step": "Post PR comment"},
	}
	fields, _ := identity.Of(f)
	want := []identity.Field{
		{Key: "code", Value: "ISSUE-701"},
		{Key: "file", Value: "ci.yml"},
		{Key: "job", Value: "build"},
		{Key: "uses", Value: "owner/act@v1"},
		{Key: "step", Value: "Post PR comment"},
	}
	if got := fields.Pairs(); !slices.Equal(got, want) {
		t.Errorf("Pairs() = %+v, want %+v", got, want)
	}
}

// A finding with no resolved step contributes no step pair, so consumers do not
// have to special-case an empty value.
func TestFields_PairsOmitTheStepWhenAbsent(t *testing.T) {
	fields, _ := identity.Of(identity.Finding{Code: "ISSUE-701", Job: "build", Message: "x"})
	for _, p := range fields.Pairs() {
		if p.Key == "step" {
			t.Errorf("step pair emitted for a finding without a step: %+v", fields.Pairs())
		}
	}
}

// Exactly one subject key is selected: the first one present in priority order,
// so two keys on one finding cannot both carry identity.
func TestOf_SelectsTheHighestPrioritySubjectKey(t *testing.T) {
	f := identity.Finding{
		Code: "ISSUE-103", Job: "scan",
		Data: map[string]any{"tag": "7", "link": "registry.gitlab.com/security-products/secrets:7"},
	}
	got, _ := identity.Of(f)
	if got.Subject.Key != "link" {
		t.Errorf("subject key = %q, want link (higher priority than tag)", got.Subject.Key)
	}
	for _, p := range got.Pairs() {
		if p.Key == "tag" {
			t.Errorf("a second subject key entered the identity: %+v", got.Pairs())
		}
	}
}

// Rules that emit no structured key fall back to the message, and the fallback
// is reported as such so a consumer can tell prose-based identity apart.
func TestOf_FallsBackToTheMessage(t *testing.T) {
	got, _ := identity.Of(identity.Finding{Code: "ISSUE-801", Job: "build", Message: "first problem"})
	if got.Subject.Key != "message" || got.Subject.Value != "first problem" {
		t.Errorf("subject = %+v, want message=first problem", got.Subject)
	}
	if !got.SubjectFromMessage {
		t.Errorf("SubjectFromMessage = false; want true for a rule with no structured key")
	}
	// The other return path out of Of: a finding that never matched a subject
	// key must carry the version too.
	if got.Version != identity.RecipeVersion {
		t.Errorf("Version = %d, want %d", got.Version, identity.RecipeVersion)
	}
}

// Volatile payload changes for reasons unrelated to the finding, so it must not
// reach the identity at all.
func TestOf_ExcludesVolatilePayload(t *testing.T) {
	f := identity.Finding{
		Code: "ISSUE-703", File: "ci.yml", Job: "build", Message: "known CVE",
		Data: map[string]any{
			"uses": "owner/act@v1", "advisories": "GHSA-1", "latestVersion": "2.3.0",
			"metadata": map[string]any{"stars": 3}, "reasons": []string{"a"}, "status": "fail",
			"line": float64(12), "url": "https://example.com/ci.yml#L12",
		},
	}
	fields, _ := identity.Of(f)
	for _, p := range fields.Pairs() {
		switch p.Key {
		case "advisories", "latestVersion", "metadata", "reasons", "status", "line", "url":
			t.Errorf("volatile key %q entered the identity: %+v", p.Key, fields.Pairs())
		}
	}
}

// A subject key holding something other than a string is skipped rather than
// coerced, and the finding degrades to prose identity. A JSON round trip turns
// a numeric `tag: 7` into a float64, so this is reachable from real payload.
// Both sides of the recipe read the value the same way, so nothing diverges,
// and SubjectFromMessage makes the degradation visible; it is pinned here
// because the alternative (coercing) would re-key every finding it applies to
// and is therefore a versioned decision, not a free fix.
func TestOf_SkipsANonStringSubjectValue(t *testing.T) {
	f := identity.Finding{
		Code: "ISSUE-103", Job: "scan", Message: "image uses a mutable tag",
		Data: map[string]any{"tag": float64(7)},
	}

	got, _ := identity.Of(f)

	if got.Subject.Key != "message" || !got.SubjectFromMessage {
		t.Errorf("subject = %+v (fromMessage=%v), want the message fallback", got.Subject, got.SubjectFromMessage)
	}
}

// A coded finding with neither a subject key nor a message still has an
// identity: code, file and job. Not an error case, just the narrowest one, so
// every finding of that control in one job shares a fingerprint.
func TestOf_CodeFileJobAloneIsAnIdentity(t *testing.T) {
	got, ok := identity.Of(identity.Finding{Code: "ISSUE-701", File: "", Job: "build"})
	if !ok {
		t.Fatalf("no identity for a coded finding")
	}
	if got.Subject.Key != "message" || got.Subject.Value != "" {
		t.Errorf("subject = %+v, want an empty message subject", got.Subject)
	}
	if identity.Fingerprint(identity.Finding{Code: "ISSUE-701", Job: "build"}) == "" {
		t.Errorf("no fingerprint for a finding identified by code/file/job alone")
	}
}

// Codeless findings have nothing stable to report against, so they have no
// identity at all.
func TestOf_CodelessFindingHasNoIdentity(t *testing.T) {
	if _, ok := identity.Of(identity.Finding{Message: "x"}); ok {
		t.Errorf("Of reported an identity for a codeless finding")
	}
}

// The platform reads findings back from serialized JSON, where every input the
// recipe needs is flattened at the top level.
func TestFromMap_ReadsASerializedFinding(t *testing.T) {
	m := map[string]any{
		"code": "ISSUE-701", "file": "ci.yml", "job": "build", "line": float64(12),
		"message": "prose", "uses": "owner/act@v1", "step": "Check out",
	}
	got, ok := identity.Of(identity.FromMap(m))
	if !ok {
		t.Fatalf("no identity for a serialized coded finding")
	}
	if got.Code != "ISSUE-701" || got.File != "ci.yml" || got.Job != "build" {
		t.Errorf("canonical fields not read from the map: %+v", got)
	}
	if got.Subject.Key != "uses" || got.Subject.Value != "owner/act@v1" {
		t.Errorf("subject = %+v, want uses=owner/act@v1", got.Subject)
	}
	if got.Step != "Check out" {
		t.Errorf("step = %q, want %q", got.Step, "Check out")
	}
	if got.Version != identity.RecipeVersion {
		t.Errorf("Version = %d, want %d", got.Version, identity.RecipeVersion)
	}
	// The line rides along in the serialized object and must stay out of the
	// identity: it moves whenever unrelated code above the finding is edited.
	for _, p := range got.Pairs() {
		if p.Key == "line" {
			t.Errorf("line entered the identity: %+v", got.Pairs())
		}
	}
}

// The fingerprint is derived from the same selection, so the two can never
// disagree about what identifies a finding.
func TestFingerprint_IsDerivedFromTheSelection(t *testing.T) {
	f := identity.Finding{
		Code: "ISSUE-701", File: "ci.yml", Job: "build",
		Message: "prose that is about to be reworded",
		Data:    map[string]any{"uses": "owner/act@v1"},
	}
	reworded := f
	reworded.Message = "reworded in a later release"
	if identity.Fingerprint(f) != identity.Fingerprint(reworded) {
		t.Errorf("fingerprint moved on a message rewording while the selection did not")
	}
	if identity.Fingerprint(identity.Finding{Message: "x"}) != "" {
		t.Errorf("codeless finding got a fingerprint; want empty")
	}
}

// Golden values from the recipe as shipped. Moving the package must not move a
// single fingerprint in the wild: a change here re-keys every finding that used
// it, which downstream reads as one issue disappearing and another appearing.
func TestFingerprint_MatchesTheShippedValues(t *testing.T) {
	cases := []struct {
		name string
		in   identity.Finding
		want string
	}{
		{
			name: "structured subject",
			in: identity.Finding{
				Code: "ISSUE-701", File: "ci.yml", Job: "build",
				Data: map[string]any{"uses": "owner/act@v1"},
			},
			want: "16dd795c6db9b1a5",
		},
		{
			name: "structured subject with a resolved step",
			in: identity.Finding{
				Code: "ISSUE-713", File: ".github/workflows/ci.yml", Job: "coverage",
				Data: map[string]any{"uses": "owner/act@v1", "step": "Post PR comment"},
			},
			want: "b59e02be3cb9dc5f",
		},
		{
			name: "message fallback",
			in: identity.Finding{
				Code: "ISSUE-801", File: "ci.yml", Job: "build",
				Message: "no structured subject here",
			},
			want: "e9c1e3ed67a9960b",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := identity.Fingerprint(tc.in); got != tc.want {
				t.Errorf("Fingerprint = %q, want %q (the recipe changed: bump identity.RecipeVersion deliberately)", got, tc.want)
			}
		})
	}
}

// The subject-key priority list is part of the published recipe: the platform
// reads it to know which key it is looking at.
func TestSubjectKeys_ArePublishedInPriorityOrder(t *testing.T) {
	keys := identity.SubjectKeys()
	if len(keys) == 0 {
		t.Fatalf("SubjectKeys is empty")
	}
	if keys[0] != "uses" {
		t.Errorf("SubjectKeys()[0] = %q, want uses", keys[0])
	}
	if slices.Contains(keys, "message") {
		t.Errorf("message is the fallback, not a subject key: %v", keys)
	}
	// The caller gets a copy: a consumer that sorts the slice must not silently
	// re-key every finding the process computes afterwards.
	keys[0] = "mutated"
	if identity.SubjectKeys()[0] != "uses" {
		t.Errorf("SubjectKeys returned the package's own slice; a caller can mutate the recipe")
	}
}

// Every control that names what it is about must have its key in the list, or
// its findings ride on reformulable prose.
func TestSubjectKeys_CoverTheStructuredControls(t *testing.T) {
	keys := identity.SubjectKeys()
	for _, want := range []string{
		"uses", "branchName", "includePath", "templatePath", "componentPath",
		"requiredAction", "hardcodedJob",
	} {
		if !slices.Contains(keys, want) {
			t.Errorf("subject key %q missing from the recipe: %v", want, keys)
		}
	}
}

// componentName is payload, not identity. ISSUE-402 and ISSUE-403 emit it as an
// empty string for any include that is not a component, and it holds a bare
// name where includePath holds the full source. Two components named "deploy"
// in different groups would collide on the bare name.
func TestSubjectKeys_ExcludesComponentName(t *testing.T) {
	if slices.Contains(identity.SubjectKeys(), "componentName") {
		t.Errorf("componentName is payload, not a subject key: %v", identity.SubjectKeys())
	}
}

// A finding carrying both keys must identify on the full source.
func TestOf_IncludePathOutranksComponentName(t *testing.T) {
	f := identity.Finding{
		Code: "ISSUE-403", File: ".gitlab-ci.yml",
		Data: map[string]any{
			"componentName": "deploy",
			"includePath":   "gitlab.example.com/components/deploy/deploy",
		},
	}

	got, _ := identity.Of(f)

	if got.Subject.Key != "includePath" {
		t.Errorf("subject = %+v, want the includePath key", got.Subject)
	}
}

// A version consumers can store next to a grouped finding, so a later change to
// the selection is detectable and migratable instead of silent.
func TestRecipeVersion_IsExported(t *testing.T) {
	if identity.RecipeVersion < 1 {
		t.Errorf("RecipeVersion = %d, want a positive version", identity.RecipeVersion)
	}
}
