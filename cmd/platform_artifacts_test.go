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
	origOutput, origCSV, origOCSF, origPBOM := outputFile, csvFile, ocsfFile, pbomFile
	t.Cleanup(func() { outputFile, csvFile, ocsfFile, pbomFile = origOutput, origCSV, origOCSF, origPBOM })
	outputFile, csvFile, ocsfFile, pbomFile = "", "", "", ""
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
	runs := evaluatePlatformPolicies(testProvider(t), conf, debugTraceResult())

	payload, err := buildAnalysisJSONReport(debugTraceResult(), conf.PlumberConfig,
		complianceSummary{platformMode: true, scoreMode: true}, jsonOutputParams{provider: "gitlab"},
		runs, &platformVerdict{GlobalScore: &platformScore{Letter: "C", Points: 66}})
	if err != nil {
		t.Fatalf("buildAnalysisJSONReport: %v", err)
	}
	var report map[string]any
	if err := json.Unmarshal(payload, &report); err != nil {
		t.Fatalf("the report is not valid JSON: %v", err)
	}

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
		t.Error("notEvaluable is a per-control verdict of the local evaluation and must be absent")
	}
	// The per-policy view is what replaces them.
	if pols, ok := report["policies"].([]any); !ok || len(pols) != 1 {
		t.Fatalf("policies: %#v", report["policies"])
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

	t.Run("a policy that enables the image controls carries the union's verdict", func(t *testing.T) {
		dir := withArtifactFiles(t)
		pbomFile = filepath.Join(dir, "pbom.json")
		runs := []policyRun{handMadePolicyRun(t, "Images", imagePolicyYAML, []opaengine.Finding{imageFinding})}
		conf := &configuration.Configuration{PlumberConfig: testDefaultPlumberConfig(t)}

		if err := writeOutputsWithProvider(&providerPkg.GitLabProvider{}, gitLabPBOMFixture(), conf,
			complianceSummary{platformMode: true, scoreMode: true}, runs, nil); err != nil {
			t.Fatalf("write outputs: %v", err)
		}
		images := pbomImages(t, pbomFile)
		if len(images) != 1 {
			t.Fatalf("images: %#v", images)
		}
		if images[0]["forbiddenTag"] != true {
			t.Errorf("the policy reported a forbidden tag on this image: %#v", images[0])
		}
	})

	t.Run("no policy enabling them means no claim at all", func(t *testing.T) {
		dir := withArtifactFiles(t)
		pbomFile = filepath.Join(dir, "pbom.json")
		runs := []policyRun{handMadePolicyRun(t, "A", debugTracePolicyYAML, nil)}
		conf := &configuration.Configuration{PlumberConfig: testDefaultPlumberConfig(t)}

		if err := writeOutputsWithProvider(&providerPkg.GitLabProvider{}, gitLabPBOMFixture(), conf,
			complianceSummary{platformMode: true, scoreMode: true}, runs, nil); err != nil {
			t.Fatalf("write outputs: %v", err)
		}
		images := pbomImages(t, pbomFile)
		if len(images) != 1 {
			t.Fatalf("the inventory itself must survive: %#v", images)
		}
		for _, k := range []string{"forbiddenTag", "authorized"} {
			if v, present := images[0][k]; present {
				t.Errorf("no policy evaluated the image controls, so %q must be absent, got %v", k, v)
			}
		}
	})
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
