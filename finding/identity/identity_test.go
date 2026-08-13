package identity_test

import (
	"slices"
	"testing"

	"github.com/getplumber/plumber/finding/identity"
)

// pairValue returns the value of the pair with the given key in pairs, and
// whether the declaration carried that key at all. A v4 declared field always
// appears (possibly with an empty value), so callers use the second result to
// tell "declared but empty" apart from "not declared for this code".
func pairValue(pairs []identity.Field, key string) (string, bool) {
	for _, p := range pairs {
		if p.Key == key {
			return p.Value, true
		}
	}
	return "", false
}

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
	if got.Code != "ISSUE-701" {
		t.Errorf("code not selected: %+v", got)
	}
	if file, _ := pairValue(got.Selected, "file"); file != ".github/workflows/ci.yml" {
		t.Errorf("file = %q, want %q", file, ".github/workflows/ci.yml")
	}
	if job, _ := pairValue(got.Selected, "job"); job != "build" {
		t.Errorf("job = %q, want build", job)
	}
	if uses, _ := pairValue(got.Selected, "uses"); uses != "owner/act@v1" {
		t.Errorf("uses = %q, want owner/act@v1", uses)
	}
	if step, _ := pairValue(got.Selected, "step"); step != "Check out" {
		t.Errorf("step = %q, want %q", step, "Check out")
	}
	// The version is part of what Of returns, not just a package constant: a
	// consumer stores the two together, and a Fields carrying version 0 would
	// silently defeat the detection a later bump exists to trigger.
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

// v4 change from v3: a finding with no resolved step still contributes a step
// pair, empty rather than omitted, because ISSUE-701 declares "step"
// unconditionally. Consumers must not special-case an empty value as
// absence; see TestOf_V4_MissingDeclaredFieldContributesEmptyPair for the
// general rule every declared field follows.
func TestFields_PairsIncludeAnEmptyStepPairWhenAbsent(t *testing.T) {
	fields, _ := identity.Of(identity.Finding{Code: "ISSUE-701", Job: "build", Message: "x"})
	step, declared := pairValue(fields.Selected, "step")
	if !declared {
		t.Fatalf("step not declared for ISSUE-701: %+v", fields.Pairs())
	}
	if step != "" {
		t.Errorf("step = %q, want empty for a finding that resolved none", step)
	}
}

// v4 has no priority search: a code's declaration names exactly which Data
// keys matter, so a key it does not declare cannot enter the identity no
// matter what else the finding carries. ISSUE-102 declares link, not tag.
func TestOf_UndeclaredDataKeysNeverEnterTheIdentity(t *testing.T) {
	f := identity.Finding{
		Code: "ISSUE-102", Job: "scan",
		Data: map[string]any{"tag": "7", "link": "registry.gitlab.com/security-products/secrets:7"},
	}
	got, _ := identity.Of(f)
	if link, declared := pairValue(got.Selected, "link"); !declared || link != "registry.gitlab.com/security-products/secrets:7" {
		t.Errorf("link = %q declared=%v, want the link value", link, declared)
	}
	if _, declared := pairValue(got.Selected, "tag"); declared {
		t.Errorf("tag entered the identity: %+v", got.Pairs())
	}
}

// The former message-keyed GitHub controls no longer ride on prose. ISSUE-801,
// once on the exception list, now identifies on canonical coordinates and never
// sets SubjectFromMessage, so rewording its finding cannot re-key it. This is
// the regression guard for the message-elimination pass; the synthetic
// message-declaration path itself is covered by
// TestOf_V4_MessageDeclarationSetsSubjectFromMessage.
func TestOf_FormerMessageKeyedCodeNoLongerUsesMessage(t *testing.T) {
	got, _ := identity.Of(identity.Finding{Code: "ISSUE-801", File: "ci.yml", Job: "build", Message: "first problem"})
	if _, declared := pairValue(got.Selected, "message"); declared {
		t.Errorf("ISSUE-801 still declares message: %+v", got.Pairs())
	}
	if got.SubjectFromMessage {
		t.Errorf("SubjectFromMessage = true; ISSUE-801 must identify on structure now")
	}
	first := identity.Fingerprint(identity.Finding{Code: "ISSUE-801", File: "ci.yml", Job: "build", Message: "first problem"})
	reworded := identity.Fingerprint(identity.Finding{Code: "ISSUE-801", File: "ci.yml", Job: "build", Message: "second problem"})
	if first != reworded {
		t.Errorf("rewording re-keyed a now-structured code: %q vs %q", first, reworded)
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

// A declared field holding something other than a string is skipped rather
// than coerced, and renders as an empty pair -- the same treatment as an
// absent key. A JSON round trip turns a numeric `tag: 7` into a float64, so
// this is reachable from real payload. Both sides of the recipe read the
// value the same way, so nothing diverges. Coercing instead would re-key
// every finding it applies to, so it is a RecipeVersion decision, not a free
// fix.
func TestOf_SkipsANonStringDeclaredValue(t *testing.T) {
	f := identity.Finding{
		Code: "ISSUE-102", Job: "scan", Message: "image uses a mutable tag",
		Data: map[string]any{"link": float64(7)},
	}

	got, _ := identity.Of(f)

	link, declared := pairValue(got.Selected, "link")
	if !declared || link != "" {
		t.Errorf("link = %q declared=%v, want an empty declared pair, not a coerced value", link, declared)
	}
	// ISSUE-102 does not declare message, so a bad value on the field it does
	// declare must not fall back to it -- v4 has no fallback chain.
	if got.SubjectFromMessage {
		t.Errorf("SubjectFromMessage = true; ISSUE-102 has no message in its declaration")
	}
}

// A coded finding with no Data and no message still has an identity: every
// declared field renders, empty where the finding carries nothing. Not an
// error case, just the narrowest one, so every such finding of that control
// in one job shares a fingerprint.
func TestOf_NoDataAndNoMessageIsStillAnIdentity(t *testing.T) {
	got, ok := identity.Of(identity.Finding{Code: "ISSUE-801", File: "", Job: "build"})
	if !ok {
		t.Fatalf("no identity for a coded finding")
	}
	if job, declared := pairValue(got.Selected, "job"); !declared || job != "build" {
		t.Errorf("job = %q declared=%v, want the job to render", job, declared)
	}
	if identity.Fingerprint(identity.Finding{Code: "ISSUE-801", Job: "build"}) == "" {
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
	if got.Code != "ISSUE-701" {
		t.Errorf("code not read from the map: %+v", got)
	}
	if file, _ := pairValue(got.Selected, "file"); file != "ci.yml" {
		t.Errorf("file = %q, want ci.yml", file)
	}
	if job, _ := pairValue(got.Selected, "job"); job != "build" {
		t.Errorf("job = %q, want build", job)
	}
	if uses, _ := pairValue(got.Selected, "uses"); uses != "owner/act@v1" {
		t.Errorf("uses = %q, want owner/act@v1", uses)
	}
	if step, _ := pairValue(got.Selected, "step"); step != "Check out" {
		t.Errorf("step = %q, want Check out", step)
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
//
// Recipe v4 (identity.RecipeVersion 4): the canonical form is uniformly
// `code\nkey=value\n...` for every declared field. ISSUE-701 and ISSUE-713
// declare a structured subject (uses) plus a trailing "step" (present, empty,
// or resolved). ISSUE-801 identifies on canonical coordinates alone
// ({file, job}): it carries no structured subject, so its message is inert and
// rewording it cannot move this value.
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
			want: "22436ce2f849caa2",
		},
		{
			name: "structured subject with a resolved step",
			in: identity.Finding{
				Code: "ISSUE-713", File: ".github/workflows/ci.yml", Job: "coverage",
				Data: map[string]any{"uses": "owner/act@v1", "step": "Post PR comment"},
			},
			want: "ffd567e26ac35e87",
		},
		{
			name: "canonical coordinates only (no structured subject, message inert)",
			in: identity.Finding{
				Code: "ISSUE-801", File: "ci.yml", Job: "build",
				Message: "no structured subject here",
			},
			want: "3e3a4e64b3772d0e",
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

// TestDeclarations_EveryCodeFingerprintIsPinned is the whole-catalog regression
// net the recipe otherwise lacks. TestFingerprint_MatchesTheShippedValues above
// pins only three codes, so a declaration edit to any of the other 63 (a field
// added, dropped, or reordered) re-keys real fingerprints with no failing test.
// This fingerprints every declared code against a fixed empty finding, so the
// golden depends only on the code plus its declared field names and their
// order. Any declaration change moves exactly one value here and must be updated
// deliberately: a re-key is a RecipeVersion event, never a silent edit. When
// RecipeVersion is bumped on purpose, regenerate this map.
func TestDeclarations_EveryCodeFingerprintIsPinned(t *testing.T) {
	golden := map[string]string{
		"ISSUE-101": "042bff0ebb1d89ee",
		"ISSUE-102": "32b497995ae3be65",
		"ISSUE-103": "ae7c300b437b0bb0",
		"ISSUE-203": "0ebe5475110580fc",
		"ISSUE-204": "7c14264872de8ef4",
		"ISSUE-205": "f2974b453aec4776",
		"ISSUE-207": "a057345f5450abb9",
		"ISSUE-208": "2b98f71f015b242e",
		"ISSUE-209": "8db95f316a53dbd4",
		"ISSUE-210": "08e465d22142ff2c",
		"ISSUE-211": "ceb796eb817f8add",
		"ISSUE-212": "920b5adbc8ebefe0",
		"ISSUE-213": "b35b60424da3106c",
		"ISSUE-214": "459777fe828201c3",
		"ISSUE-215": "fcb8941c2d1f950e",
		"ISSUE-302": "c131f6dbb114f9af",
		"ISSUE-303": "ecf73e88d37310ae",
		"ISSUE-305": "4b3d732f9681dc92",
		"ISSUE-306": "aabc6270ca4e4304",
		"ISSUE-307": "05ed16253de98346",
		"ISSUE-308": "de132d1493cadafe",
		"ISSUE-309": "2e2c85d21a6492a6",
		"ISSUE-401": "468870372f32863b",
		"ISSUE-402": "574564223df032be",
		"ISSUE-403": "9c0211f37dbdd777",
		"ISSUE-404": "6d22a43975ac3476",
		"ISSUE-405": "de90ff665182fa46",
		"ISSUE-406": "89e96f29fbdc966c",
		"ISSUE-408": "303554d7d0a1f66a",
		"ISSUE-409": "4e8a0cb83c191ba0",
		"ISSUE-410": "7ec575989260503a",
		"ISSUE-411": "00a582d1c7ce3b61",
		"ISSUE-412": "a7e4aba60a34a04a",
		"ISSUE-413": "1388ae7203cc3eb8",
		"ISSUE-417": "9be7e2421e979408",
		"ISSUE-418": "b7d95784db1eafc2",
		"ISSUE-419": "6147e752a7f298fb",
		"ISSUE-420": "ac3048041dde8446",
		"ISSUE-421": "7573d13ae392133e",
		"ISSUE-501": "e36cebae06c15f85",
		"ISSUE-505": "4e929715c61fcba6",
		"ISSUE-601": "9c1ecbe668ad9a36",
		"ISSUE-701": "87a2f87a752971bd",
		"ISSUE-702": "875ec32b1513e8a8",
		"ISSUE-703": "cf522b35974397b7",
		"ISSUE-704": "5d5da28eff4463bc",
		"ISSUE-705": "f9a219129fa88eef",
		"ISSUE-706": "96136288dee3d9d0",
		"ISSUE-707": "9fa2d7e4325d1945",
		"ISSUE-708": "02b9293b41fd49ea",
		"ISSUE-709": "5b1c47498bc5b3c9",
		"ISSUE-711": "2a680e66277a78e7",
		"ISSUE-712": "626d1c97a59651bb",
		"ISSUE-713": "b8e68adcadca6cb2",
		"ISSUE-714": "4962cbb919d4ba0a",
		"ISSUE-715": "2eb0f41ca9a31bd8",
		"ISSUE-716": "c0112771c48f6ab5",
		"ISSUE-801": "1cf1a105d1a87734",
		"ISSUE-802": "d3d7331043f5614c",
		"ISSUE-803": "46e3e735b1ceec41",
		"ISSUE-804": "eceec2db4ce22c05",
		"ISSUE-901": "ca625b1497c56403",
		"ISSUE-902": "43f4f0601229026f",
		"ISSUE-903": "7fd2361c5d78fbb6",
		"ISSUE-904": "83315ec9a14da003",
		"ISSUE-905": "56786a18e9ce7f7c",
	}
	codes := identity.DeclaredCodes()
	if len(golden) != len(codes) {
		t.Fatalf("golden pins %d codes but %d are declared: a code was added or removed without updating this golden (regenerate it)", len(golden), len(codes))
	}
	for _, code := range codes {
		want, ok := golden[code]
		if !ok {
			t.Errorf("%s: declared but not pinned; add it to the golden", code)
			continue
		}
		// Empty finding: every declared field renders key=, so the hash depends
		// only on the code and its declared field names and order.
		if got := identity.Fingerprint(identity.Finding{Code: code}); got != want {
			t.Errorf("%s: fingerprint = %q, want %q -- its declaration changed (field added, dropped, or reordered); if intentional, bump RecipeVersion and regenerate this golden", code, got, want)
		}
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

// componentName was never a declared field for ISSUE-403 (see
// TestSubjectKeys_ExcludesComponentName: it is payload, not a subject key), so
// a finding carrying both keys identifies on includePath alone.
func TestOf_IncludePathIsSelectedOverComponentName(t *testing.T) {
	f := identity.Finding{
		Code: "ISSUE-403", File: ".gitlab-ci.yml",
		Data: map[string]any{
			"componentName": "deploy",
			"includePath":   "gitlab.example.com/components/deploy/deploy",
		},
	}

	got, _ := identity.Of(f)

	if path, declared := pairValue(got.Selected, "includePath"); !declared || path != "gitlab.example.com/components/deploy/deploy" {
		t.Errorf("includePath = %q declared=%v, want the include source", path, declared)
	}
	if _, declared := pairValue(got.Selected, "componentName"); declared {
		t.Errorf("componentName entered the identity: %+v", got.Pairs())
	}
}

// A version consumers can store next to a grouped finding, so a later change to
// the selection is detectable and migratable instead of silent.
func TestRecipeVersion_IsExported(t *testing.T) {
	if identity.RecipeVersion < 1 {
		t.Errorf("RecipeVersion = %d, want a positive version", identity.RecipeVersion)
	}
}

// v4: identity is code + the code's declared fields, in declared order,
// every pair rendered key=value. No global priority list, no auto-step.
func TestOf_V4_UsesDeclaredFieldsInDeclaredOrder(t *testing.T) {
	f := identity.Finding{
		Code: "ISSUE-701", File: ".github/workflows/ci.yml", Job: "ci/build",
		Data: map[string]any{"uses": "actions/checkout@v4", "step": "Checkout", "line": 12},
	}
	fields, ok := identity.Of(f)
	if !ok {
		t.Fatal("coded finding must have an identity")
	}
	if fields.Version != 4 {
		t.Errorf("Version = %d, want 4", fields.Version)
	}
	got := fields.Pairs()
	want := []identity.Field{
		{Key: "code", Value: "ISSUE-701"},
		{Key: "file", Value: ".github/workflows/ci.yml"},
		{Key: "job", Value: "ci/build"},
		{Key: "uses", Value: "actions/checkout@v4"},
		{Key: "step", Value: "Checkout"},
	}
	if len(got) != len(want) {
		t.Fatalf("pairs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("pair[%d] = %v, want %v", i, got[i], want[i])
		}
	}
	if fields.SubjectFromMessage {
		t.Error("SubjectFromMessage = true for a declared structured identity")
	}
}

// A declared field the finding does not carry contributes key= (empty),
// deterministically; it must not shift or drop segments.
func TestOf_V4_MissingDeclaredFieldContributesEmptyPair(t *testing.T) {
	f := identity.Finding{Code: "ISSUE-701", File: "ci.yml", Job: "ci/build",
		Data: map[string]any{"uses": "actions/checkout@v4"}} // no step
	fields, _ := identity.Of(f)
	last := fields.Pairs()[len(fields.Pairs())-1]
	if last.Key != "step" || last.Value != "" {
		t.Errorf("last pair = %v, want empty step pair", last)
	}
	a := identity.Fingerprint(f)
	f.Data["step"] = ""
	if b := identity.Fingerprint(f); a != b {
		t.Errorf("absent vs empty declared field changed the hash: %q vs %q", a, b)
	}
}

// An empty declaration is a per-project singleton: identity = code alone.
// No real code currently declares zero fields (every one of the 66 declares
// at least file, job and one more), so this uses a synthetic entry to
// exercise the path.
func TestOf_V4_EmptyDeclarationIsSingleton(t *testing.T) {
	identity.DeclareForTest(t, "ISSUE-TEST-SINGLETON", []string{})
	a := identity.Fingerprint(identity.Finding{Code: "ISSUE-TEST-SINGLETON", File: "x.yml", Job: "a",
		Message: "one", Data: map[string]any{"detail": "d1"}})
	b := identity.Fingerprint(identity.Finding{Code: "ISSUE-TEST-SINGLETON", File: "y.yml", Job: "b",
		Message: "two", Data: map[string]any{"detail": "d2"}})
	if a == "" || a != b {
		t.Errorf("singleton fingerprints differ: %q vs %q", a, b)
	}
}

// message is a reserved declarable name; declaring it flags the identity.
func TestOf_V4_MessageDeclarationSetsSubjectFromMessage(t *testing.T) {
	identity.DeclareForTest(t, "ISSUE-TEST-MSG", []string{"file", "job", "message"})
	fields, _ := identity.Of(identity.Finding{Code: "ISSUE-TEST-MSG", File: "f", Job: "j", Message: "the prose"})
	if !fields.SubjectFromMessage {
		t.Error("SubjectFromMessage = false for a message-keyed declaration")
	}
	pairs := fields.Pairs()
	if got := pairs[len(pairs)-1]; got.Key != "message" || got.Value != "the prose" {
		t.Errorf("message pair = %v", got)
	}
}

// The backstop: an undeclared code (unreachable once the parity test exists)
// hashes deterministically as code + message, flagged.
func TestOf_V4_UndeclaredCodeBackstop(t *testing.T) {
	fields, ok := identity.Of(identity.Finding{Code: "ISSUE-NEVER-DECLARED", Message: "m"})
	if !ok {
		t.Fatal("backstop must still produce an identity")
	}
	if !fields.SubjectFromMessage {
		t.Error("backstop identity must be flagged SubjectFromMessage")
	}
	if identity.Fingerprint(identity.Finding{Code: "ISSUE-NEVER-DECLARED", Message: "m"}) == "" {
		t.Error("backstop fingerprint empty")
	}
}

// FromMap findings still round-trip: same map, same identity, version 4.
func TestFromMap_V4_RoundTrip(t *testing.T) {
	m := map[string]any{"code": "ISSUE-701", "file": "ci.yml", "job": "ci/build",
		"message": "x", "uses": "actions/checkout@v4", "step": "Checkout"}
	fields, ok := identity.Of(identity.FromMap(m))
	if !ok || fields.Version != 4 {
		t.Fatalf("fields = %+v ok=%v, want version 4", fields, ok)
	}
}
