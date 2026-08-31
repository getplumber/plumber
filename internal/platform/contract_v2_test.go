package platform

import (
	"encoding/json"
	"testing"
)

// The snapshot contract gained four fields at schema_version "2" (the
// platform's 2026-08-25 entry). These tests pin the two that carry a rule
// rather than merely a value: degraded_fields is only meaningful once the
// version says the bookkeeping exists, and an unknown lane name must survive
// rather than be silently dropped.

func TestDegradedFieldsGateOnSchemaVersion(t *testing.T) {
	cases := []struct {
		name     string
		version  string
		degraded []string
		trusted  bool
		// wantBranchDegraded is what IsDegraded must answer for a lane that
		// IS listed. Below v2 it must answer false - not because the lane is
		// healthy, but because the payload cannot tell us.
		wantBranchDegraded bool
	}{
		{"v2 with a degraded lane", "2", []string{DegradedFieldBranchProtection}, true, true},
		{"v2 with nothing degraded", "2", nil, true, false},
		{"v3 stays trusted (forward tolerant)", "3", []string{DegradedFieldBranchProtection}, true, true},
		{"v1 is never trusted", "1", []string{DegradedFieldBranchProtection}, false, false},
		{"absent version is never trusted", "", []string{DegradedFieldBranchProtection}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &SnapshotData{SchemaVersion: tc.version, DegradedFields: tc.degraded}
			if got := d.DegradedFieldsTrusted(); got != tc.trusted {
				t.Fatalf("DegradedFieldsTrusted = %v, want %v", got, tc.trusted)
			}
			if got := d.IsDegraded(DegradedFieldBranchProtection); got != tc.wantBranchDegraded {
				t.Fatalf("IsDegraded = %v, want %v", got, tc.wantBranchDegraded)
			}
		})
	}

	// The nil receiver is the no-snapshot case and must not panic or claim
	// knowledge it does not have.
	var nilData *SnapshotData
	if nilData.DegradedFieldsTrusted() || nilData.IsDegraded(DegradedFieldVariables) {
		t.Fatal("a nil SnapshotData must report neither trusted nor degraded")
	}
}

// A lane identifier the CLI does not recognise is still carried: the set is
// closed by documentation, not by this decoder, and swallowing an unknown
// name would hide a platform bug instead of surfacing it.
func TestDegradedFieldsCarryUnknownLaneNames(t *testing.T) {
	var d SnapshotData
	if err := json.Unmarshal([]byte(`{"schema_version":"2","degraded_fields":["variables","something_new"]}`), &d); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !d.IsDegraded("something_new") {
		t.Fatal("an unrecognised lane name must still report as degraded, not be dropped")
	}
	if !d.IsDegraded(DegradedFieldVariables) {
		t.Fatal("a known lane alongside an unknown one must still be reported")
	}
}

// The whole point of Policy.requirements: two policies may declare the SAME
// control_type with DIFFERENT config, and neither may be read for the other.
func TestPolicyControlConfigIsPerPolicy(t *testing.T) {
	body := `{
	  "schema_version": 1,
	  "project": "grp/app",
	  "policies": [
	    {"id":"11111111-1111-1111-1111-111111111111","name":"Strict","enforcement":"block",
	     "requirements":[{"name":"Branches","controls":[
	       {"control_type":"branchMustBeProtected","config":{"enabled":true,"minMergeAccessLevel":40}}]}]},
	    {"id":"22222222-2222-2222-2222-222222222222","name":"Lenient","enforcement":"report",
	     "requirements":[{"name":"Branches","controls":[
	       {"control_type":"branchMustBeProtected","config":{"enabled":true,"minMergeAccessLevel":30}}]}]},
	    {"id":"00000000-0000-0000-0000-000000000000","name":"[Plumber default]","enforcement":"report",
	     "requirements":[]}
	  ],
	  "snapshot": {}
	}`
	var ctx ProjectContext
	if err := json.Unmarshal([]byte(body), &ctx); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(ctx.Policies) != 3 {
		t.Fatalf("want 3 policies, got %d", len(ctx.Policies))
	}

	strict, lenient, derived := ctx.Policies[0], ctx.Policies[1], ctx.Policies[2]

	sc, ok := strict.ControlConfig("branchMustBeProtected")
	if !ok {
		t.Fatal("Strict must declare branchMustBeProtected")
	}
	lc, ok := lenient.ControlConfig("branchMustBeProtected")
	if !ok {
		t.Fatal("Lenient must declare branchMustBeProtected")
	}
	if string(sc) == string(lc) {
		t.Fatalf("the two policies' configs must not be identical: both read %s", sc)
	}
	if !bytesContain(sc, "40") || !bytesContain(lc, "30") {
		t.Fatalf("each policy must carry ITS OWN config, got strict=%s lenient=%s", sc, lc)
	}

	// The derived fallback has no tree and must fall back, not evaluate
	// against an empty ruleset.
	if derived.DeclaresAnyControl() {
		t.Fatal("[Plumber default] must declare no controls")
	}
	if _, ok := derived.ControlConfig("branchMustBeProtected"); ok {
		t.Fatal("[Plumber default] must not resolve a control config")
	}
	// A control no policy declares resolves for neither.
	if _, ok := strict.ControlConfig("cicdVariablesMustBeMasked"); ok {
		t.Fatal("an undeclared control must not resolve")
	}
}

// The platform serves config as raw stored bytes specifically so a big
// integer survives. Decoding into a generic map and back would round it to
// a float64; the CLI must not undo that on its side of the wire.
func TestPolicyControlConfigPreservesLargeIntegers(t *testing.T) {
	const big = "9007199254740993" // 2^53 + 1: unrepresentable as float64
	body := `{"policies":[{"id":"1","name":"P","enforcement":"report","requirements":[
	  {"name":"R","controls":[{"control_type":"x","config":{"expectedProjectId":` + big + `}}]}]}]}`
	var ctx ProjectContext
	if err := json.Unmarshal([]byte(body), &ctx); err != nil {
		t.Fatalf("decode: %v", err)
	}
	cfg, ok := ctx.Policies[0].ControlConfig("x")
	if !ok {
		t.Fatal("control x must resolve")
	}
	if !bytesContain(cfg, big) {
		t.Fatalf("large integer was not preserved verbatim: %s", cfg)
	}
}

// includes / ci_config_path decode off the same payload, and their absence
// must stay distinguishable from an empty value.
func TestSnapshotIncludesAndConfigPathDecode(t *testing.T) {
	var d SnapshotData
	body := `{"schema_version":"2","ci_config_path":".ci/main.yml","includes":[
	  {"location":"gitlab.com/c/x@1.0.0","type":"component","blob":"https://example/blob"}]}`
	if err := json.Unmarshal([]byte(body), &d); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if d.CiConfigPath != ".ci/main.yml" {
		t.Fatalf("ci_config_path = %q", d.CiConfigPath)
	}
	if len(d.Includes) != 1 {
		t.Fatalf("want 1 include, got %d", len(d.Includes))
	}
	if !bytesContain(d.Includes[0], "gitlab.com/c/x@1.0.0") {
		t.Fatalf("include carried verbatim? got %s", d.Includes[0])
	}

	var empty SnapshotData
	if err := json.Unmarshal([]byte(`{"schema_version":"2"}`), &empty); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if empty.CiConfigPath != "" || len(empty.Includes) != 0 {
		t.Fatal("absent fields must stay absent, never defaulted to a value")
	}
}

func bytesContain(b []byte, sub string) bool {
	return len(b) > 0 && len(sub) > 0 && containsString(string(b), sub)
}

func containsString(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// The version gate must compare NUMERICALLY. A lexical compare puts "10"
// below "2", which would silently distrust every snapshot from schema 10
// onward - the failure would appear years later and look like the platform
// had stopped reporting degradation.
func TestDegradedFieldsGateComparesNumerically(t *testing.T) {
	for _, v := range []string{"2", "3", "9", "10", "11", "100"} {
		d := &SnapshotData{SchemaVersion: v, DegradedFields: []string{DegradedFieldVariables}}
		if !d.DegradedFieldsTrusted() {
			t.Errorf("schema_version %q is >= 2 and must be trusted", v)
		}
		if !d.IsDegraded(DegradedFieldVariables) {
			t.Errorf("schema_version %q must report its degraded lane", v)
		}
	}
	for _, v := range []string{"0", "1", "", "  ", "two", "2.0", "v2"} {
		d := &SnapshotData{SchemaVersion: v, DegradedFields: []string{DegradedFieldVariables}}
		if d.DegradedFieldsTrusted() {
			t.Errorf("schema_version %q is not a version >= 2 and must not be trusted", v)
		}
	}
}
