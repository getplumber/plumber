package cmd

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/platform"
	"github.com/getplumber/plumber/pbom"
	providerPkg "github.com/getplumber/plumber/provider"
)

// The ruling behind this file (review of task 6): in platform mode EVERY
// output derives from the resolved policies, not only the score keys. A local
// per-control verdict in the JSON report, the CSV or the OCSF feed is the same
// wrong verdict the mode exists to remove (QUESTIONS row 44).

// handMadePolicyRun builds an applied run directly, so a test can pick both
// the configuration a policy declares and the findings it reported without
// going through a Rego evaluation of a crafted pipeline.
func handMadePolicyRun(t *testing.T, name, configYAML string, findings []opaengine.Finding) policyRun {
	t.Helper()
	pc, _, _, err := configuration.LoadPlumberConfigFromBytes([]byte(configYAML), "test policy "+name)
	if err != nil {
		t.Fatalf("load the policy configuration: %v", err)
	}
	points := 66.0
	return policyRun{
		Policies: []platform.Policy{{ID: "policy-" + name, Name: name, Enforcement: platform.EnforcementReport}},
		Config:   pc,
		Result:   &control.AnalysisResult{CiValid: true, Findings: findings},
		Score:    &control.PlumberScoreResult{Score: "C", FinalPoints: points},
		Applied:  true,
	}
}

const debugTracePolicyYAML = `version: "2.0"
gitlab:
  controls:
    pipelineMustNotEnableDebugTrace:
      enabled: true
      forbiddenVariables: ["CI_DEBUG_TRACE"]
`

const imagePolicyYAML = `version: "2.0"
gitlab:
  controls:
    containerImageMustNotUseForbiddenTags:
      enabled: true
    containerImageMustComeFromAuthorizedSources:
      enabled: true
`

// The two image controls are INDEPENDENT, and enforcing tag pinning without a
// registry allowlist (or the reverse) is the common split. These two policies
// declare exactly one of them each.
const forbiddenTagOnlyPolicyYAML = `version: "2.0"
gitlab:
  controls:
    containerImageMustNotUseForbiddenTags:
      enabled: true
`

const authorizedSourceOnlyPolicyYAML = `version: "2.0"
gitlab:
  controls:
    containerImageMustComeFromAuthorizedSources:
      enabled: true
`

// localOnlyFinding is a finding the LOCAL configuration produced and no policy
// reported: it must not reach any platform-mode artifact.
func localOnlyFinding() opaengine.Finding {
	return opaengine.Finding{
		Code: "ISSUE-901", Message: "local only", Job: "build",
		File: ".gitlab-ci.yml", Fingerprint: "local-only",
	}
}

// debugTraceFinding is the finding a policy reported.
func debugTraceFinding() opaengine.Finding {
	return opaengine.Finding{
		Code: string(control.CodeDebugTraceEnabled), Message: "CI_DEBUG_TRACE is enabled", Job: "build",
		File: ".gitlab-ci.yml", Line: 4, Fingerprint: "policy-finding",
	}
}

// withArtifactFiles points the artifact flags at a temp directory for the
// duration of one test and restores them after.
func withArtifactFiles(t *testing.T) (dir string) {
	t.Helper()
	dir = t.TempDir()
	origOutput, origCSV, origOCSF := outputFile, csvFile, ocsfFile
	origPBOM, origCycloneDX := pbomFile, pbomCycloneDXFile
	t.Cleanup(func() {
		outputFile, csvFile, ocsfFile = origOutput, origCSV, origOCSF
		pbomFile, pbomCycloneDXFile = origPBOM, origCycloneDX
	})
	outputFile, csvFile, ocsfFile, pbomFile, pbomCycloneDXFile = "", "", "", "", ""
	return dir
}

// Spec s5 + the review ruling: the JSON report of a platform-mode run carries
// the per-policy view and nothing built from the local configuration. The
// legacy per-control *Result blocks and plumberConfig describe the local
// catalog under the local policy file, so both are omitted, and platformMode
// says why they are gone.
func TestBuildAnalysisJSONReport_PlatformMode_NoLocalControlBlocks(t *testing.T) {
	a := policyWithTree("A", "pipelineMustNotEnableDebugTrace", debugTraceControlConfig)
	conf := confWithPolicies(t, a)
	// The fixture has to CARRY a not-evaluable mark for the assertion below to
	// mean anything: debugTraceResult() sets none, the field is omitempty, and
	// an assertion that an absent key is absent holds whether or not the report
	// removes it (the re-review finding).
	collected := debugTraceResult()
	collected.MarkNotEvaluable("pipelineMustNotOverrideJobVariables", "raw_config_unavailable")
	runs := evaluatePlatformPolicies(testProvider(t), conf, debugTraceResult())

	decode := func(t *testing.T, s complianceSummary, runs []policyRun, v *platformVerdict) map[string]any {
		t.Helper()
		payload, err := buildAnalysisJSONReport(collected, conf.PlumberConfig, s,
			jsonOutputParams{provider: "gitlab"}, runs, v)
		if err != nil {
			t.Fatalf("buildAnalysisJSONReport: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(payload, &m); err != nil {
			t.Fatalf("the report is not valid JSON: %v", err)
		}
		return m
	}

	report := decode(t, complianceSummary{platformMode: true, scoreMode: true}, runs,
		&platformVerdict{GlobalScore: &platformScore{Letter: "C", Points: 66}})

	if report["platformMode"] != true {
		t.Errorf("platformMode must say why the local blocks are absent, got %v", report["platformMode"])
	}
	if _, present := report["plumberConfig"]; present {
		t.Error("plumberConfig names the LOCAL configuration as the author of a verdict the platform's policies produced")
	}
	for k := range report {
		if strings.HasSuffix(k, "Result") {
			t.Errorf("legacy per-control block %q is the local catalog's verdict and must be absent", k)
		}
	}
	if _, present := report["notEvaluable"]; present {
		t.Errorf("notEvaluable is a per-control verdict of the local evaluation and must be absent, got %v", report["notEvaluable"])
	}
	// The per-policy view is what replaces them.
	if pols, ok := report["policies"].([]any); !ok || len(pols) != 1 {
		t.Fatalf("policies: %#v", report["policies"])
	}

	// The SAME collected result, reported standalone, keeps the mark. That is
	// what makes the assertion above a difference the platform branch creates
	// rather than a property of the fixture.
	standalone := decode(t, complianceSummary{scoreMode: true, controlCount: 1}, nil, nil)
	marks, ok := standalone["notEvaluable"].(map[string]any)
	if !ok || marks["pipelineMustNotOverrideJobVariables"] != "raw_config_unavailable" {
		t.Fatalf("a standalone report keeps the run's not-evaluable marks, got %#v", standalone["notEvaluable"])
	}
}

// A standalone report keeps every one of those keys.
func TestBuildAnalysisJSONReport_StandaloneKeepsTheLocalBlocks(t *testing.T) {
	payload, err := buildAnalysisJSONReport(debugTraceResult(), confWithDebugTrace().PlumberConfig,
		complianceSummary{scoreMode: true, controlCount: 1}, jsonOutputParams{provider: "gitlab"}, nil, nil)
	if err != nil {
		t.Fatalf("buildAnalysisJSONReport: %v", err)
	}
	var report map[string]any
	if err := json.Unmarshal(payload, &report); err != nil {
		t.Fatalf("the report is not valid JSON: %v", err)
	}
	if _, present := report["plumberConfig"]; !present {
		t.Error("a standalone report keeps plumberConfig")
	}
	if _, present := report["platformMode"]; present {
		t.Error("platformMode must be absent outside platform mode")
	}
	blocks := 0
	for k := range report {
		if strings.HasSuffix(k, "Result") {
			blocks++
		}
	}
	if blocks == 0 {
		t.Error("a standalone report keeps its per-control *Result blocks")
	}
}

// The CSV of a platform-mode run reports the policies' findings and their
// controls, never the local catalog's, and names the policies each finding
// belongs to in a trailing column.
func TestWriteCSV_PlatformMode_OnlyThePoliciesFindings(t *testing.T) {
	dir := withArtifactFiles(t)
	csvFile = filepath.Join(dir, "out.csv")

	base := &control.AnalysisResult{CiValid: true, ProjectPath: "grp/app", Findings: []opaengine.Finding{localOnlyFinding()}}
	runs := []policyRun{handMadePolicyRun(t, "A", debugTracePolicyYAML, []opaengine.Finding{debugTraceFinding()})}
	conf := &configuration.Configuration{PlumberConfig: testDefaultPlumberConfig(t)}

	if err := writeOutputsWithProvider(&providerPkg.GitLabProvider{}, base, conf,
		complianceSummary{platformMode: true, scoreMode: true}, runs, nil); err != nil {
		t.Fatalf("write outputs: %v", err)
	}

	raw, err := os.ReadFile(csvFile)
	if err != nil {
		t.Fatalf("read the csv: %v", err)
	}
	records, err := csv.NewReader(strings.NewReader(string(raw))).ReadAll()
	if err != nil {
		t.Fatalf("the csv does not parse: %v", err)
	}
	header := records[0]
	if header[len(header)-1] != "policies" {
		t.Fatalf("the last column must be policies, got %v", header)
	}
	var codes, controls, policyCells []string
	for _, r := range records[1:] {
		codes = append(codes, r[0])
		controls = append(controls, r[2])
		policyCells = append(policyCells, r[len(r)-1])
	}
	if !contains(codes, string(control.CodeDebugTraceEnabled)) {
		t.Errorf("the policy's finding is missing from the csv: %v", records)
	}
	if contains(codes, "ISSUE-901") {
		t.Errorf("a local-only finding reached the csv: %v", records)
	}
	if contains(controls, "branchMustBeProtected") {
		t.Errorf("the local catalog leaked into the csv: no policy enables branchMustBeProtected: %v", controls)
	}
	if !contains(policyCells, "A") {
		t.Errorf("the finding row must name its policies: %v", records)
	}
}

// A standalone CSV keeps its exact columns: no policies column at all.
func TestWriteCSV_StandaloneHasNoPoliciesColumn(t *testing.T) {
	dir := withArtifactFiles(t)
	csvFile = filepath.Join(dir, "out.csv")
	conf := &configuration.Configuration{PlumberConfig: testDefaultPlumberConfig(t)}

	if err := writeOutputsWithProvider(&providerPkg.GitLabProvider{}, &control.AnalysisResult{CiValid: true}, conf,
		complianceSummary{scoreMode: true}, nil, nil); err != nil {
		t.Fatalf("write outputs: %v", err)
	}
	raw, err := os.ReadFile(csvFile)
	if err != nil {
		t.Fatalf("read the csv: %v", err)
	}
	if strings.Contains(strings.SplitN(string(raw), "\n", 2)[0], "policies") {
		t.Errorf("the standalone csv header must be unchanged, got %q", strings.SplitN(string(raw), "\n", 2)[0])
	}
}

// The OCSF feed of a platform-mode run: the policies' controls and findings,
// each record naming the policies it was evaluated under.
func TestWriteOCSF_PlatformMode_OnlyThePoliciesFindings(t *testing.T) {
	dir := withArtifactFiles(t)
	ocsfFile = filepath.Join(dir, "out.ocsf.json")

	base := &control.AnalysisResult{CiValid: true, ProjectPath: "grp/app", Findings: []opaengine.Finding{localOnlyFinding()}}
	runs := []policyRun{handMadePolicyRun(t, "A", debugTracePolicyYAML, []opaengine.Finding{debugTraceFinding()})}
	conf := &configuration.Configuration{PlumberConfig: testDefaultPlumberConfig(t)}

	if err := writeOutputsWithProvider(&providerPkg.GitLabProvider{}, base, conf,
		complianceSummary{platformMode: true, scoreMode: true}, runs, nil); err != nil {
		t.Fatalf("write outputs: %v", err)
	}

	raw, err := os.ReadFile(ocsfFile)
	if err != nil {
		t.Fatalf("read the ocsf feed: %v", err)
	}
	body := string(raw)
	if !strings.Contains(body, "pipelineMustNotEnableDebugTrace") {
		t.Errorf("the policy's control is missing from the ocsf feed:\n%s", body)
	}
	if strings.Contains(body, "branchMustBeProtected") {
		t.Errorf("the local catalog leaked into the ocsf feed:\n%s", body)
	}
	if strings.Contains(body, "ISSUE-901") {
		t.Errorf("a local-only finding reached the ocsf feed:\n%s", body)
	}
	var records []struct {
		Policies   []string `json:"policies"`
		Compliance struct {
			Control string `json:"control"`
		} `json:"compliance"`
	}
	if err := json.Unmarshal(raw, &records); err != nil {
		t.Fatalf("the ocsf feed is not valid JSON: %v", err)
	}
	if len(records) == 0 {
		t.Fatal("the policy's controls must produce records")
	}
	for _, r := range records {
		if len(r.Policies) != 1 || r.Policies[0] != "A" {
			t.Errorf("record for %q must name the policies it was evaluated under, got %v", r.Compliance.Control, r.Policies)
		}
	}
}

// A standalone OCSF record carries no policies key.
func TestWriteOCSF_StandaloneHasNoPoliciesKey(t *testing.T) {
	dir := withArtifactFiles(t)
	ocsfFile = filepath.Join(dir, "out.ocsf.json")
	conf := &configuration.Configuration{PlumberConfig: testDefaultPlumberConfig(t)}

	if err := writeOutputsWithProvider(&providerPkg.GitLabProvider{}, &control.AnalysisResult{CiValid: true}, conf,
		complianceSummary{scoreMode: true}, nil, nil); err != nil {
		t.Fatalf("write outputs: %v", err)
	}
	raw, err := os.ReadFile(ocsfFile)
	if err != nil {
		t.Fatalf("read the ocsf feed: %v", err)
	}
	if strings.Contains(string(raw), `"policies"`) {
		t.Errorf("the standalone ocsf feed must be unchanged")
	}
}

// The PBOM's per-image booleans are a positive claim ("this image is
// authorized"). In platform mode they may only state what a policy actually
// evaluated: the union's verdict when a policy enables the image controls,
// and NOTHING when none does.
func TestWritePBOM_PlatformMode_ImageVerdictFollowsThePolicies(t *testing.T) {
	imageFinding := opaengine.Finding{
		Code: string(control.CodeImageForbiddenTag), Message: "latest tag", Job: "build", Fingerprint: "img",
	}

	// onlyImage writes the platform-mode PBOM for one policy declaring the
	// given configuration and returns the single inventory image's entry.
	onlyImage := func(t *testing.T, policyYAML string, findings []opaengine.Finding) map[string]any {
		t.Helper()
		dir := withArtifactFiles(t)
		pbomFile = filepath.Join(dir, "pbom.json")
		runs := []policyRun{handMadePolicyRun(t, "Images", policyYAML, findings)}
		conf := &configuration.Configuration{PlumberConfig: testDefaultPlumberConfig(t)}

		if err := writeOutputsWithProvider(&providerPkg.GitLabProvider{}, gitLabPBOMFixture(), conf,
			complianceSummary{platformMode: true, scoreMode: true}, runs, nil); err != nil {
			t.Fatalf("write outputs: %v", err)
		}
		images := pbomImages(t, pbomFile)
		if len(images) != 1 {
			t.Fatalf("the inventory itself must survive: %#v", images)
		}
		return images[0]
	}

	// assertKeys checks each per-image boolean against what the policy asked
	// for: want is the expected value, and a nil want means the key must be
	// absent entirely (the tri-state "not assessed").
	assertKeys := func(t *testing.T, img map[string]any, forbiddenTag, authorized any) {
		t.Helper()
		for _, k := range []struct {
			name string
			want any
		}{{"forbiddenTag", forbiddenTag}, {"authorized", authorized}} {
			got, present := img[k.name]
			if k.want == nil {
				if present {
					t.Errorf("no policy evaluated the control behind %q, so it must be absent, got %v", k.name, got)
				}
				continue
			}
			if !present || got != k.want {
				t.Errorf("%q = %v (present %v), want %v: %#v", k.name, got, present, k.want, img)
			}
		}
	}

	t.Run("a policy that enables both image controls carries the union's verdict", func(t *testing.T) {
		assertKeys(t, onlyImage(t, imagePolicyYAML, []opaengine.Finding{imageFinding}), true, true)
	})

	// The two controls are independent claims. A policy pinning tags says
	// nothing about the registry an image comes from, so "authorized" is a
	// verdict nobody produced and must not be published.
	t.Run("only the forbidden-tag control claims only the forbidden tag", func(t *testing.T) {
		assertKeys(t, onlyImage(t, forbiddenTagOnlyPolicyYAML, []opaengine.Finding{imageFinding}), true, nil)
	})

	t.Run("only the authorized-source control claims only the source", func(t *testing.T) {
		assertKeys(t, onlyImage(t, authorizedSourceOnlyPolicyYAML, nil), nil, true)
	})

	t.Run("no policy enabling them means no claim at all", func(t *testing.T) {
		assertKeys(t, onlyImage(t, debugTracePolicyYAML, nil), nil, nil)
	})
}

// Spec s5: the PBOM and CycloneDX platform block is one entry per resolved
// policy plus the platform's own global score. This is the MAPPING (the pbom
// package tests build pb.Policies by hand and only assert the rendering), so
// a swap here - the raw points instead of the rounded final ones, a score on
// a run that evaluated nothing, the wrong enforcement - would ship a wrong
// per-policy verdict inside the artifact with every other test green.
func TestPlatformPBOMSummary_MapsEachRunAndTheGlobalScore(t *testing.T) {
	// 66.6 ROUNDS to 67, the same rounding the push and the badge apply.
	applied := scoredRun("Prod", "id-prod", "block", "C", 66.6)
	unapplied := unappliedRun("Later", "id-later", reasonTreeNotApplied)

	t.Run("an applied run carries its score, an un-applied one carries none", func(t *testing.T) {
		got := platformPBOMSummary([]policyRun{applied, unapplied},
			&platformVerdict{GlobalScore: &platformScore{Letter: "B", Points: 83}})

		if got == nil || len(got.Policies) != 2 {
			t.Fatalf("one entry per resolved policy: %#v", got)
		}
		first := got.Policies[0]
		if first.Name != "Prod" || first.Enforcement != "block" || first.Score != "C" || !first.Applied || first.Reason != "" {
			t.Errorf("the applied policy's entry is its own verdict: %#v", first)
		}
		if first.FinalPoints == nil || *first.FinalPoints != 67 {
			t.Errorf("finalPoints are the run's ROUNDED final points: %#v", first.FinalPoints)
		}
		second := got.Policies[1]
		if second.Name != "Later" || second.Enforcement != "report" || second.Applied || second.Reason != reasonTreeNotApplied {
			t.Errorf("an un-applied policy is listed with its reason: %#v", second)
		}
		if second.Score != "" || second.FinalPoints != nil {
			t.Errorf("a run that evaluated nothing has no score, not a zero one: %#v", second)
		}
		if got.GlobalScore == nil || *got.GlobalScore != (pbom.PlatformGlobalScore{Letter: "B", Points: 83}) {
			t.Errorf("the global score is the platform's own: %#v", got.GlobalScore)
		}
	})

	t.Run("no global score in the push response is no global score in the document", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			v    *platformVerdict
		}{
			{"a nil verdict", nil},
			{"a verdict that carried none", &platformVerdict{Gate: &platformGate{Evaluated: true}}},
		} {
			got := platformPBOMSummary([]policyRun{applied}, tc.v)
			if got == nil || got.GlobalScore != nil {
				t.Errorf("%s must leave platformGlobalScore out rather than publish a zero: %#v", tc.name, got)
			}
		}
	})

	// Outside platform mode there are no runs, and the summary is nil so the
	// standalone document is byte-identical to what it always was.
	t.Run("no runs is no platform block at all", func(t *testing.T) {
		if got := platformPBOMSummary(nil, &platformVerdict{GlobalScore: &platformScore{Letter: "B", Points: 83}}); got != nil {
			t.Errorf("a standalone document gains nothing: %#v", got)
		}
	})
}

// The same mapping through the WRITERS: what a --pbom / --pbom-cyclonedx run
// actually puts on disk after a push, rather than what the builder returns.
func TestPlatformFlow_PBOMCarriesThePolicyScoresAndGlobalScore(t *testing.T) {
	newGateFlagsCmd(t)
	origPrint := printOutput
	printOutput = false
	defer func() { printOutput = origPrint }()

	dir := withArtifactFiles(t)
	pbomFile = filepath.Join(dir, "pbom.json")
	pbomCycloneDXFile = filepath.Join(dir, "pbom.cdx.json")

	a := policyWithTree("A", "pipelineMustNotEnableDebugTrace", debugTraceControlConfig)
	// A tree the CLI cannot apply: the run is NOT applied, which is the entry
	// shape a hand-built fixture never produces on this path.
	broken := policyWithTree("Broken", "pipelineMustNotEnableDebugTrace", `{"enabled":true,"forbiddenVariables":"not-a-list"}`)
	conf := confWithPolicies(t, a, broken)

	var pushed []byte
	srv := pushServer(t, 200, `{"gate":{"evaluated":true,"blocking":false,"policies":[]},"global_score":{"letter":"B","points":83}}`, &pushed)
	defer srv.Close()
	restore := withPlatformTestEnv(t, srv.URL, "tok")
	defer restore()

	var err error
	_ = captureStderr(t, func() {
		err = presentResultWithProvider(testProvider(t), nil, debugTraceResult(), conf)
	})
	if err != nil {
		t.Fatalf("the gate does not block: want exit 0, got %v", err)
	}

	raw, readErr := os.ReadFile(pbomFile)
	if readErr != nil {
		t.Fatalf("read the pbom: %v", readErr)
	}
	var bom struct {
		Policies []struct {
			Name        string `json:"name"`
			Enforcement string `json:"enforcement"`
			Score       string `json:"score"`
			FinalPoints *int   `json:"finalPoints"`
			Applied     bool   `json:"applied"`
			Reason      string `json:"reason"`
		} `json:"policies"`
		PlatformGlobalScore *struct {
			Letter string `json:"letter"`
			Points int    `json:"points"`
		} `json:"platformGlobalScore"`
		PlumberScore any `json:"plumberScore"`
	}
	if err := json.Unmarshal(raw, &bom); err != nil {
		t.Fatalf("the pbom is not valid JSON: %v", err)
	}
	if len(bom.Policies) != 2 {
		t.Fatalf("one entry per resolved policy: %#v", bom.Policies)
	}
	applied := bom.Policies[0]
	if applied.Name != "A" || applied.Enforcement != "report" || !applied.Applied {
		t.Errorf("the applied policy's entry: %#v", applied)
	}
	if applied.Score == "" || applied.FinalPoints == nil {
		t.Errorf("an applied policy carries the score its own run produced: %#v", applied)
	}
	unapplied := bom.Policies[1]
	if unapplied.Name != "Broken" || unapplied.Applied {
		t.Fatalf("the second policy must be the un-applied one: %#v", unapplied)
	}
	if unapplied.Score != "" || unapplied.FinalPoints != nil || unapplied.Reason == "" {
		t.Errorf("an un-applied policy carries its reason and no score: %#v", unapplied)
	}
	if bom.PlatformGlobalScore == nil || bom.PlatformGlobalScore.Letter != "B" || bom.PlatformGlobalScore.Points != 83 {
		t.Errorf("platformGlobalScore is the push response's own: %#v", bom.PlatformGlobalScore)
	}
	if bom.PlumberScore != nil {
		t.Errorf("there is no run-level score in platform mode: %#v", bom.PlumberScore)
	}

	// The CycloneDX writer renders the same block as metadata properties, and
	// nothing else on this path exercises it in platform mode.
	cdxRaw, readErr := os.ReadFile(pbomCycloneDXFile)
	if readErr != nil {
		t.Fatalf("read the cyclonedx pbom: %v", readErr)
	}
	var cdx struct {
		Metadata struct {
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(cdxRaw, &cdx); err != nil {
		t.Fatalf("the cyclonedx pbom is not valid JSON: %v", err)
	}
	props := map[string]string{}
	for _, p := range cdx.Metadata.Properties {
		props[p.Name] = p.Value
	}
	if props["plumber:platform-global-score"] != "B" || props["plumber:platform-global-points"] != "83" {
		t.Errorf("the platform's global score must reach CycloneDX: %#v", props)
	}
	if props["plumber:policy:A:enforcement"] != "report" || props["plumber:policy:A:score"] == "" {
		t.Errorf("the applied policy's properties: %#v", props)
	}
	if _, present := props["plumber:policy:Broken:score"]; present {
		t.Errorf("an un-applied policy has no score property, only its enforcement: %#v", props)
	}
	if props["plumber:policy:Broken:enforcement"] != "report" {
		t.Errorf("an un-applied policy is still listed: %#v", props)
	}
}

func pbomImages(t *testing.T, path string) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the pbom: %v", err)
	}
	var bom struct {
		ContainerImages []map[string]any `json:"containerImages"`
	}
	if err := json.Unmarshal(raw, &bom); err != nil {
		t.Fatalf("the pbom is not valid JSON: %v", err)
	}
	return bom.ContainerImages
}

// Two findings sharing a fingerprint but sitting on different lines are two
// alerts, not one: the fingerprint is deliberately line-independent, so it
// cannot be the whole identity of a security-report row.
func TestPlatformUnionResult_KeepsFindingsThatDifferByLine(t *testing.T) {
	first := debugTraceFinding()
	second := debugTraceFinding()
	second.Line = 42
	runs := []policyRun{handMadePolicyRun(t, "A", debugTracePolicyYAML, []opaengine.Finding{first, second})}

	union := platformUnionResult(&control.AnalysisResult{CiValid: true}, runs)

	if len(union.Findings) != 2 {
		t.Fatalf("two lines are two findings, got %d", len(union.Findings))
	}
	doc := buildSARIF(union.Findings, ".plumber.yaml", "gitlab")
	if len(doc.Runs[0].Results) != 2 {
		t.Fatalf("SARIF results = %d, want 2", len(doc.Runs[0].Results))
	}
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
