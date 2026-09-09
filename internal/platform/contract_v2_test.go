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

// The 2026-08-27/28 contract additions: project_details (with its eight
// OPTIONAL merge settings), security_policy_project, raw_config,
// merged_yaml_status and ci_errors. This pins the full-body decode: every
// field the contract now serves must reach the CLI's types, verbatim.
func TestSnapshotDecodesProjectDetailsSecurityPolicyRawConfigAndMergeStatus(t *testing.T) {
	body := `{
	  "schema_version": "2",
	  "raw_config": "stages: [test]\n",
	  "merged_yaml_status": "VALID",
	  "ci_errors": ["deprecated keyword: only"],
	  "project_details": {
	    "default_branch": "main",
	    "archived": false,
	    "path_with_namespace": "grp/app",
	    "merge_method": "ff",
	    "squash_option": "default_on",
	    "merge_pipelines_enabled": true,
	    "merge_trains_enabled": false,
	    "allow_merge_on_skipped_pipeline": true,
	    "resolve_outdated_diff_discussions": false,
	    "printing_merge_request_link_enabled": true,
	    "remove_source_branch_after_merge": true
	  },
	  "security_policy_project": {
	    "known": true,
	    "id": 4242,
	    "full_path": "grp/security-policies"
	  }
	}`
	var d SnapshotData
	if err := json.Unmarshal([]byte(body), &d); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if d.RawConfig != "stages: [test]\n" {
		t.Errorf("RawConfig = %q", d.RawConfig)
	}
	if d.MergedYamlStatus != "VALID" {
		t.Errorf("MergedYamlStatus = %q", d.MergedYamlStatus)
	}
	if len(d.CiErrors) != 1 || d.CiErrors[0] != "deprecated keyword: only" {
		t.Errorf("CiErrors = %v", d.CiErrors)
	}

	pd := d.ProjectDetails
	if pd == nil {
		t.Fatal("ProjectDetails must decode")
	}
	if pd.DefaultBranch != "main" || pd.Archived != false || pd.PathWithNamespace != "grp/app" {
		t.Errorf("ProjectDetails required fields = %+v", pd)
	}
	switch {
	case pd.MergeMethod == nil || *pd.MergeMethod != "ff":
		t.Errorf("MergeMethod = %v", pd.MergeMethod)
	case pd.SquashOption == nil || *pd.SquashOption != "default_on":
		t.Errorf("SquashOption = %v", pd.SquashOption)
	case pd.MergePipelinesEnabled == nil || *pd.MergePipelinesEnabled != true:
		t.Errorf("MergePipelinesEnabled = %v", pd.MergePipelinesEnabled)
	case pd.MergeTrainsEnabled == nil || *pd.MergeTrainsEnabled != false:
		t.Errorf("MergeTrainsEnabled = %v", pd.MergeTrainsEnabled)
	case pd.AllowMergeOnSkippedPipeline == nil || *pd.AllowMergeOnSkippedPipeline != true:
		t.Errorf("AllowMergeOnSkippedPipeline = %v", pd.AllowMergeOnSkippedPipeline)
	case pd.ResolveOutdatedDiffDiscussions == nil || *pd.ResolveOutdatedDiffDiscussions != false:
		t.Errorf("ResolveOutdatedDiffDiscussions = %v", pd.ResolveOutdatedDiffDiscussions)
	case pd.PrintingMergeRequestLinkEnabled == nil || *pd.PrintingMergeRequestLinkEnabled != true:
		t.Errorf("PrintingMergeRequestLinkEnabled = %v", pd.PrintingMergeRequestLinkEnabled)
	case pd.RemoveSourceBranchAfterMerge == nil || *pd.RemoveSourceBranchAfterMerge != true:
		t.Errorf("RemoveSourceBranchAfterMerge = %v", pd.RemoveSourceBranchAfterMerge)
	}

	sp := d.SecurityPolicyProject
	if sp == nil {
		t.Fatal("SecurityPolicyProject must decode")
	}
	if !sp.Known {
		t.Error("Known must be true")
	}
	if sp.ID == nil || *sp.ID != 4242 {
		t.Errorf("ID = %v", sp.ID)
	}
	if sp.FullPath == nil || *sp.FullPath != "grp/security-policies" {
		t.Errorf("FullPath = %v", sp.FullPath)
	}
}

// project_details on a snapshot stored before 2026-08-28 carries the three
// required facts but none of the eight merge settings. A required/non-pointer
// decode would fabricate false or zero values for a stale blob; the pointers
// must all stay nil instead - self-healing arrives on the next refresh, not
// by guessing now.
func TestSnapshotProjectDetailsOptionalMergeSettingsAbsentStayNil(t *testing.T) {
	body := `{"schema_version":"2","project_details":{
	  "default_branch":"main","archived":true,"path_with_namespace":"grp/app"
	}}`
	var d SnapshotData
	if err := json.Unmarshal([]byte(body), &d); err != nil {
		t.Fatalf("decode: %v", err)
	}
	pd := d.ProjectDetails
	if pd == nil {
		t.Fatal("ProjectDetails must decode")
	}
	if pd.DefaultBranch != "main" || !pd.Archived || pd.PathWithNamespace != "grp/app" {
		t.Errorf("required fields = %+v", pd)
	}
	if pd.MergeMethod != nil || pd.SquashOption != nil || pd.MergePipelinesEnabled != nil ||
		pd.MergeTrainsEnabled != nil || pd.AllowMergeOnSkippedPipeline != nil ||
		pd.ResolveOutdatedDiffDiscussions != nil || pd.PrintingMergeRequestLinkEnabled != nil ||
		pd.RemoveSourceBranchAfterMerge != nil {
		t.Errorf("an absent optional merge setting must decode nil, not a zero value: %+v", pd)
	}
}

// security_policy_project's three shapes: linked (known+id+full_path),
// read authoritatively but nothing linked (known alone - the real Critical
// for ISSUE-601), and not read authoritatively (known=false, paired with
// the degraded_fields entry). id/full_path must stay nil, not zero/"".
func TestSecurityPolicyProjectVariants(t *testing.T) {
	cases := []struct {
		name         string
		body         string
		wantKnown    bool
		wantID       *int
		wantFullPath *string
	}{
		{
			name:      "not read authoritatively",
			body:      `{"known":false}`,
			wantKnown: false,
		},
		{
			name:      "known, nothing linked",
			body:      `{"known":true}`,
			wantKnown: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var sp SecurityPolicyProject
			if err := json.Unmarshal([]byte(tc.body), &sp); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if sp.Known != tc.wantKnown {
				t.Errorf("Known = %v, want %v", sp.Known, tc.wantKnown)
			}
			if sp.ID != nil {
				t.Errorf("ID = %v, want nil", *sp.ID)
			}
			if sp.FullPath != nil {
				t.Errorf("FullPath = %v, want nil", *sp.FullPath)
			}
		})
	}
}

// A snapshot omitting the whole optional block (older payload, no merge
// happened yet) must decode with all four new top-level pointers/values
// absent, never fabricated.
func TestSnapshotNewFieldsAbsentWhenOmitted(t *testing.T) {
	var d SnapshotData
	if err := json.Unmarshal([]byte(`{"schema_version":"2"}`), &d); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if d.ProjectDetails != nil {
		t.Error("ProjectDetails must be nil when omitted")
	}
	if d.SecurityPolicyProject != nil {
		t.Error("SecurityPolicyProject must be nil when omitted")
	}
	if d.RawConfig != "" {
		t.Errorf("RawConfig = %q, want empty", d.RawConfig)
	}
	if d.MergedYamlStatus != "" {
		t.Errorf("MergedYamlStatus = %q, want empty", d.MergedYamlStatus)
	}
	if d.CiErrors != nil {
		t.Errorf("CiErrors = %v, want nil", d.CiErrors)
	}
}

// The contract's degraded_fields enum gained four identifiers on top of the
// original five: raw_config, source_catalog, security_policy_project,
// includes_jobs. IsDegraded is generic over the DegradedFields slice (the
// set is closed by documentation, not by a switch), so a new constant needs
// no new decode logic to participate - this pins that it actually does, and
// that an identifier outside even this larger set still passes through
// rather than being dropped.
func TestNewDegradedFieldIdentifiersRecognized(t *testing.T) {
	newFields := []struct {
		constant string
		wire     string
	}{
		{DegradedFieldRawConfig, "raw_config"},
		{DegradedFieldSourceCatalog, "source_catalog"},
		{DegradedFieldSecurityPolicyProject, "security_policy_project"},
		{DegradedFieldIncludesJobs, "includes_jobs"},
	}
	for _, f := range newFields {
		if f.constant != f.wire {
			t.Errorf("constant for %q = %q, want it to equal the wire identifier", f.wire, f.constant)
		}
		d := &SnapshotData{SchemaVersion: "2", DegradedFields: []string{f.wire}}
		if !d.IsDegraded(f.constant) {
			t.Errorf("IsDegraded(%q) = false, want true", f.constant)
		}
	}

	// An identifier the CLI has never heard of, even alongside the new
	// ones, must still be carried through - the closed set is documentation
	// only, and swallowing it would hide a platform bug.
	d := &SnapshotData{SchemaVersion: "2", DegradedFields: []string{
		DegradedFieldRawConfig, "not_even_in_the_docs_yet",
	}}
	if !d.IsDegraded("not_even_in_the_docs_yet") {
		t.Error("an unrecognised identifier alongside a known one must still report as degraded")
	}
}
