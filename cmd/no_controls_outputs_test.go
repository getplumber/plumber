package cmd

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/gitlab"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/provider"
	"github.com/getplumber/plumber/utils"
	"github.com/spf13/cobra"
)

// noControlsPC loads the shipped default config, so these tests assert on
// what a real user's artifacts look like rather than on a hand-built config.
func noControlsPC(t *testing.T) *configuration.PlumberConfig {
	t.Helper()
	pc, _, _, err := configuration.LoadPlumberConfig("../defaultConfig/.plumber.yaml")
	if err != nil {
		t.Fatalf("load shipped default config: %v", err)
	}
	return pc
}

// TestJSONReport_NoControlsDoesNotClaimControlsPassed pins that the JSON
// artifact cannot be read as a clean scan. Withholding the score is not
// enough: the per-control `*Result` blocks are built from the catalog, not
// from the score, so with zero findings on a valid run every one of them
// would otherwise stamp `status: "passed"` for a control that never ran.
//
// The `status` field exists precisely so consumers stop inferring pass from
// an empty issues list, so it is the field that must tell the truth here.
//
// Both providers are covered because legacyResultsByName has two genuinely
// separate branches (GitHub blocks come from buildLegacyResultGitHub), and
// the GitLab half passing says nothing about the GitHub one.
func TestJSONReport_NoControlsDoesNotClaimControlsPassed(t *testing.T) {
	pc := noControlsPC(t)
	for _, prov := range []string{"gitlab", "github"} {
		t.Run(prov, func(t *testing.T) {
			result := &control.AnalysisResult{CiValid: true, ProjectPath: "group/project"}
			path := filepath.Join(t.TempDir(), "analysis.json")

			conf := &configuration.Configuration{PlumberConfig: pc, NoControls: true}
			s := buildComplianceSummary(&provider.GitLabProvider{}, result, conf)
			params := jsonOutputParams{filePath: path, provider: prov, noControls: conf.NoControls}
			if err := writeJSONToFile(result, pc, s, params); err != nil {
				t.Fatalf("write json: %v", err)
			}

			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read json: %v", err)
			}
			var out map[string]any
			if err := json.Unmarshal(raw, &out); err != nil {
				t.Fatalf("parse json: %v", err)
			}

			if out["noControls"] != true {
				t.Errorf("the report must say explicitly that no control ran, got noControls=%v", out["noControls"])
			}
			if _, ok := out["plumberScore"]; ok {
				t.Errorf("the score must be withheld, got %v", out["plumberScore"])
			}

			checked := 0
			for k, v := range out {
				if !strings.HasSuffix(k, "Result") {
					continue
				}
				block, ok := v.(map[string]any)
				if !ok {
					continue
				}
				checked++
				if block["status"] != control.StatusSkipped {
					t.Errorf("%s: status %v, want %q: a control that never ran must not report passed", k, block["status"], control.StatusSkipped)
				}
				// The legacy `skipped` boolean is not emitted by every block;
				// when it is, it must agree with the status.
				if b, ok := block["skipped"]; ok && b != true {
					t.Errorf("%s: skipped=%v, want true", k, b)
				}
			}
			if checked == 0 {
				t.Fatal("no per-control blocks in the report, this test would pass vacuously")
			}
		})
	}
}

// A run WITHOUT the flag must still report real per-control verdicts, on
// both providers: that is what stops the assertions above from passing by
// the blocks simply being absent.
func TestJSONReport_ControlsStillReportedByDefault(t *testing.T) {
	pc := noControlsPC(t)
	for _, prov := range []string{"gitlab", "github"} {
		t.Run(prov, func(t *testing.T) {
			result := &control.AnalysisResult{CiValid: true, ProjectPath: "group/project"}
			path := filepath.Join(t.TempDir(), "analysis.json")

			conf := &configuration.Configuration{PlumberConfig: pc}
			s := buildComplianceSummary(&provider.GitLabProvider{}, result, conf)
			if err := writeJSONToFile(result, pc, s, jsonOutputParams{filePath: path, provider: prov}); err != nil {
				t.Fatalf("write json: %v", err)
			}
			raw, _ := os.ReadFile(path)
			var out map[string]any
			if err := json.Unmarshal(raw, &out); err != nil {
				t.Fatalf("parse json: %v", err)
			}
			if _, ok := out["noControls"]; ok {
				t.Error("noControls must be absent on a normal run")
			}
			passed := 0
			for k, v := range out {
				if block, ok := v.(map[string]any); ok && strings.HasSuffix(k, "Result") {
					if block["status"] == control.StatusPassed {
						passed++
					}
				}
			}
			if passed == 0 {
				t.Fatal("a normal clean run must still report passed controls")
			}
		})
	}
}

// complianceAssertionProps are the CycloneDX properties that state a
// VERDICT about a component rather than record what was collected. They are
// all derived from findings, so on a --no-controls run every one of them
// must be absent: the artifact may list what the pipeline uses, and may not
// say whether it is acceptable.
//
// plumber:up-to-date is in the list because the GitHub generator repurposes
// Include.UpToDate as its action-pinning indicator.
var complianceAssertionProps = []string{
	"plumber:authorized",
	"plumber:forbidden-tag",
	"plumber:up-to-date",
	"plumber:archived",
	"plumber:has-cve",
	"plumber:advisories",
}

// gitLabPBOMFixture is a result carrying one collected image and one
// tracked include, so both verdict surfaces of the PBOM are exercised: the
// per-image flags AND the include `upToDate` field. An include is required
// here, not optional: without one, processIncludes produces nothing and any
// assertion about include verdicts passes vacuously.
func gitLabPBOMFixture() *control.AnalysisResult {
	origin := gitlab.GitlabPipelineOriginDataFull{}
	origin.OriginType = "include"
	origin.FromPlumber = true
	origin.PlumberOrigin = gitlab.GitlabPipelineJobPlumberOrigin{Path: "group/templates", LatestVersion: "2.0.0"}
	origin.GitlabIncludeOrigin = gitlab.IncludeOriginWithoutRef{Location: "group/templates/ci.yml", Project: "group/templates"}
	origin.Version = "1.0.0"
	// Out of date upstream: this is exactly what includesMustBeUpToDate
	// reports, so the PBOM must not state it on a run that ran no control.
	origin.UpToDate = false

	// processIncludes suppresses the upToDate verdict in TWO branches, and
	// they are reached by different origin shapes: FromPlumber above, and
	// the GitLab CI/CD Catalog component below. A fixture with only the
	// first leaves the component guard untested, so a regression there
	// would leak the verdict into a --no-controls PBOM undetected.
	component := gitlab.GitlabPipelineOriginDataFull{}
	component.OriginType = "component"
	component.FromGitlabCatalog = true
	component.GitlabComponent = gitlab.GitlabPipelineJobGitlabComponent{
		ComponentName:          "scan",
		ComponentLatestVersion: "3.0.0",
		ComponentIncludePath:   "gitlab.example/group/components/scan",
	}
	component.GitlabIncludeOrigin = gitlab.IncludeOriginWithoutRef{Location: "gitlab.example/group/components/scan", Project: "group/components"}
	component.Version = "2.0.0"
	component.UpToDate = false

	return &control.AnalysisResult{
		CiValid:     true,
		ProjectPath: "group/project",
		PipelineImageData: &gitlab.GitlabPipelineImageData{
			CiValid: true,
			Images: []gitlab.GitlabPipelineImageInfo{
				{Link: "docker.io/library/alpine:latest", Name: "alpine", Tag: "latest", Registry: "docker.io", Job: "build"},
			},
		},
		PipelineOriginData: &gitlab.GitlabPipelineOriginData{
			CiValid: true,
			Origins: []gitlab.GitlabPipelineOriginDataFull{origin, component},
		},
	}
}

// gitHubPBOMFixture carries one image and one action, plus the findings
// that make the GitHub compliance builder actually populate its maps.
//
// The findings are the point. On the GitHub path every consumed compliance
// field is derived from result.Findings, so a fixture with none makes
// BuildGitHubPBOMCompliance return empty maps and NO verdict property is
// emitted whether or not --no-controls suppressed it: an assertion that the
// properties are absent would hold either way and test nothing.
//
// A real --no-controls run does have zero findings (evaluatePolicies
// returns early), so this fixture is deliberately not that run. It pins the
// WRITER's contract, which is what the guard actually promises: verdicts are
// suppressed because the user asked for no controls, not because the
// findings slice happened to be empty. That is the property that has to
// survive a future compliance field sourced from collected state.
func gitHubPBOMFixture() *control.AnalysisResult {
	return &control.AnalysisResult{
		CiValid:     true,
		ProjectPath: "owner/repo",
		GitHubPipeline: &ir.NormalizedPipeline{
			Provider:    ir.Provider("github"),
			ProjectPath: "owner/repo",
			Jobs: []ir.Job{{
				Name:  "build",
				Image: &ir.Image{Name: "alpine", Tag: "latest", Registry: "docker.io"},
				Uses:  []ir.Action{{Uses: "actions/checkout@v4"}},
			}},
		},
		Findings: []opaengine.Finding{
			{
				Code: string(control.CodeActionUnpinned),
				Data: map[string]any{"uses": "actions/checkout@v4"},
			},
			{
				Code: string(control.CodeActionArchivedRepo),
				Data: map[string]any{"uses": "actions/checkout@v4"},
			},
			{
				Code: string(control.CodeImageForbiddenTag),
				Data: map[string]any{"link": "docker.io/alpine:latest"},
			},
		},
	}
}

// TestPBOM_NoControlsDoesNotAssertCompliance covers every PBOM writer on
// every provider: four call sites, each routing through its own
// noControlsAware* guard, and the CycloneDX pair is the documented primary
// use case of the flag (`--pbom-cyclonedx cdx.json --no-controls`).
//
// The flags these guards suppress come from findings, not from the score,
// so withholding the score is not enough: a zero-findings run would
// otherwise stamp forbiddenTag:false / authorized:true on every image and
// assert exactly the checks --no-controls skipped, inside the artifact the
// flag exists to produce.
func TestPBOM_NoControlsDoesNotAssertCompliance(t *testing.T) {
	pc := noControlsPC(t)
	// mustMention names the entries that have to appear in the artifact for
	// the assertions below to mean anything. For GitLab that is BOTH include
	// shapes: processIncludes suppresses the upToDate verdict in two
	// separate branches (a Plumber-tracked include and a GitLab CI/CD
	// Catalog component), and a fixture with only one leaves the other
	// guard unexercised.
	gitLabIncludes := []string{"group/templates/ci.yml", "gitlab.example/group/components/scan"}
	for _, tc := range []struct {
		name        string
		provider    provider.Provider
		result      *control.AnalysisResult
		cycloneDX   bool
		mustMention []string
	}{
		{"gitlab/pbom", &provider.GitLabProvider{}, gitLabPBOMFixture(), false, gitLabIncludes},
		{"gitlab/cyclonedx", &provider.GitLabProvider{}, gitLabPBOMFixture(), true, gitLabIncludes},
		{"github/pbom", &provider.GitHubProvider{}, gitHubPBOMFixture(), false, []string{"actions/checkout"}},
		{"github/cyclonedx", &provider.GitHubProvider{}, gitHubPBOMFixture(), true, []string{"actions/checkout"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "pbom.json")
			conf := &configuration.Configuration{PlumberConfig: pc, NoControls: true}
			var err error
			if tc.cycloneDX {
				err = tc.provider.WritePBOMCycloneDX(tc.result, conf, path, nil, false)
			} else {
				err = tc.provider.WritePBOM(tc.result, conf, path, nil, false)
			}
			if err != nil {
				t.Fatalf("write pbom: %v", err)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read pbom: %v", err)
			}

			for _, want := range tc.mustMention {
				if !strings.Contains(string(raw), want) {
					t.Fatalf("%q missing from the artifact; the verdict assertions below would be vacuous", want)
				}
			}

			if tc.cycloneDX {
				assertCycloneDXClaimsNothing(t, raw)
				return
			}
			assertPBOMClaimsNothing(t, raw)
		})
	}
}

func assertCycloneDXClaimsNothing(t *testing.T, raw []byte) {
	t.Helper()
	var cdx struct {
		Components []struct {
			Name       string `json:"name"`
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &cdx); err != nil {
		t.Fatalf("parse cyclonedx: %v", err)
	}
	if len(cdx.Components) == 0 {
		t.Fatal("the CycloneDX output must still carry the collected inventory")
	}
	for _, c := range cdx.Components {
		for _, prop := range c.Properties {
			for _, banned := range complianceAssertionProps {
				if prop.Name == banned {
					t.Errorf("component %q asserts %s=%s for a control that never ran", c.Name, prop.Name, prop.Value)
				}
			}
		}
	}
	if strings.Contains(string(raw), "plumber:score") {
		t.Error("the CycloneDX output must not carry a score")
	}
}

func assertPBOMClaimsNothing(t *testing.T, raw []byte) {
	t.Helper()
	var bom struct {
		ContainerImages []map[string]any `json:"containerImages"`
		Includes        []map[string]any `json:"includes"`
		PlumberScore    any              `json:"plumberScore"`
	}
	if err := json.Unmarshal(raw, &bom); err != nil {
		t.Fatalf("parse pbom: %v", err)
	}
	if len(bom.ContainerImages) == 0 {
		t.Fatal("the PBOM must still carry the collected image inventory")
	}
	if len(bom.Includes) == 0 {
		t.Fatal("the PBOM must still carry the collected include inventory, otherwise the include assertions are vacuous")
	}
	if bom.PlumberScore != nil {
		t.Errorf("the PBOM must not carry a score, got %v", bom.PlumberScore)
	}
	for _, entry := range append(append([]map[string]any{}, bom.ContainerImages...), bom.Includes...) {
		for _, k := range []string{"authorized", "forbiddenTag", "upToDate", "archived", "hasCve", "advisories"} {
			if v, ok := entry[k]; ok {
				t.Errorf("%v asserts %s=%v for a control that never ran", entry["image"], k, v)
			}
		}
	}
}

// TestPBOM_ComplianceStillAssertedByDefault stops the test above from
// passing vacuously: without the flag, the GitLab PBOM does stamp the
// per-image verdict on every image, which is the behaviour --no-controls
// has to suppress.
func TestPBOM_ComplianceStillAssertedByDefault(t *testing.T) {
	pc := noControlsPC(t)
	path := filepath.Join(t.TempDir(), "pbom.json")
	conf := &configuration.Configuration{PlumberConfig: pc}
	if err := (&provider.GitLabProvider{}).WritePBOM(gitLabPBOMFixture(), conf, path, nil, false); err != nil {
		t.Fatalf("write pbom: %v", err)
	}
	raw, _ := os.ReadFile(path)
	var bom struct {
		ContainerImages []map[string]any `json:"containerImages"`
		Includes        []map[string]any `json:"includes"`
	}
	if err := json.Unmarshal(raw, &bom); err != nil {
		t.Fatalf("parse pbom: %v", err)
	}
	if len(bom.ContainerImages) == 0 || len(bom.Includes) < 2 {
		t.Fatalf("fixture produced %d images and %d includes, expected both include shapes", len(bom.ContainerImages), len(bom.Includes))
	}
	for _, img := range bom.ContainerImages {
		if _, ok := img["authorized"]; !ok {
			t.Fatalf("without --no-controls the PBOM must still carry the per-image verdict, got %v", img)
		}
	}
	// The include verdict too: suppressing it must be scoped to
	// --no-controls, not a blanket removal.
	for _, inc := range bom.Includes {
		if _, ok := inc["upToDate"]; !ok {
			t.Fatalf("without --no-controls the PBOM must still carry the include verdict, got %v", inc)
		}
		if inc["latestVersion"] == nil || inc["latestVersion"] == "" {
			t.Fatalf("latestVersion is collected data and must survive either way, got %v", inc)
		}
	}

	// Same on the GitHub writer, whose compliance fields come from a
	// separate builder. Without this the GitHub half of the suppression
	// test above could pass by emitting nothing at all.
	ghPath := filepath.Join(t.TempDir(), "gh-pbom.json")
	if err := (&provider.GitHubProvider{}).WritePBOM(gitHubPBOMFixture(), &configuration.Configuration{PlumberConfig: pc}, ghPath, nil, false); err != nil {
		t.Fatalf("write github pbom: %v", err)
	}
	ghRaw, _ := os.ReadFile(ghPath)
	var ghBOM struct {
		ContainerImages []map[string]any `json:"containerImages"`
		Includes        []map[string]any `json:"includes"`
	}
	if err := json.Unmarshal(ghRaw, &ghBOM); err != nil {
		t.Fatalf("parse github pbom: %v", err)
	}
	verdicts := 0
	for _, entry := range append(append([]map[string]any{}, ghBOM.ContainerImages...), ghBOM.Includes...) {
		for _, k := range []string{"forbiddenTag", "upToDate", "archived"} {
			if _, ok := entry[k]; ok {
				verdicts++
			}
		}
	}
	if verdicts == 0 {
		t.Fatal("without --no-controls the GitHub PBOM must carry its verdicts, otherwise the GitHub suppression subtests prove nothing")
	}
}

// recordingProvider wraps the real GitLab provider so the test only has to
// override the one method it observes; embedding keeps it a full Provider.
type recordingProvider struct {
	*provider.GitLabProvider
	postCalled bool
}

func (p *recordingProvider) PostAnalysisActions(cmd *cobra.Command, result *control.AnalysisResult, conf *configuration.Configuration, s provider.PostActionSummary) error {
	p.postCalled = true
	return nil
}

// TestPublishAndFinalize_NoControlsSkipsPublishing pins the guard that is
// the whole safety of the feature. Nothing else stops a fake publish: under
// --no-controls with --score-push set, effectiveScorePush() still returns
// true, the run is not degraded, and buildPublishPayload still yields a
// payload, so the early return is the only thing keeping a badge or a
// platform push built from zero findings off the wire.
func TestPublishAndFinalize_NoControlsSkipsPublishing(t *testing.T) {
	oPush, oPlatform := pushScore, platformURL
	defer func() { pushScore, platformURL = oPush, oPlatform }()
	pushScore, platformURL = true, ""

	result := &control.AnalysisResult{CiValid: true, ProjectPath: "group/project"}
	pc := noControlsPC(t)

	p := &recordingProvider{GitLabProvider: &provider.GitLabProvider{}}
	conf := &configuration.Configuration{PlumberConfig: pc, NoControls: true}
	s := buildComplianceSummary(p, result, conf)
	var err error
	stderr := captureStderr(t, func() {
		err = publishAndFinalize(p, &cobra.Command{}, result, conf, s)
	})
	if err != nil {
		t.Fatalf("--no-controls run must not fail: %v", err)
	}
	if p.postCalled {
		t.Fatal("post-analysis actions (badge, MR comment) must not run for a run that evaluated nothing")
	}
	// The score push is a separate call from PostAnalysisActions and would
	// POST a report built from zero findings. handleScorePublishing always
	// announces itself on stderr when it runs, whether it publishes or
	// explains why it skipped, so the absence of any of its messages is the
	// evidence that it was never entered at all.
	//
	// The ignored-flags notice legitimately mentions --score-push, so it is
	// removed before looking for push output.
	var pushOutput []string
	for _, line := range strings.Split(stderr, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "Note: --no-controls") {
			continue
		}
		if strings.Contains(line, "score-push") || strings.Contains(line, "score push") || strings.Contains(line, "Score published") {
			pushOutput = append(pushOutput, line)
		}
	}
	if len(pushOutput) > 0 {
		t.Errorf("the score push must not be attempted at all for a run that evaluated nothing, got:\n%s", strings.Join(pushOutput, "\n"))
	}
	if !strings.Contains(stderr, "ignored: --score-push") {
		t.Errorf("the notice must tell the user --score-push was ignored, stderr:\n%s", stderr)
	}

	// Mirror case: the publish path still runs without the flag. Score push
	// off so the assertion is about PostAnalysisActions and nothing reaches
	// the network.
	pushScore = false
	p2 := &recordingProvider{GitLabProvider: &provider.GitLabProvider{}}
	conf2 := &configuration.Configuration{PlumberConfig: pc}
	s2 := buildComplianceSummary(p2, result, conf2)
	_ = publishAndFinalize(p2, &cobra.Command{}, result, conf2, s2)
	if !p2.postCalled {
		t.Fatal("without --no-controls the post-analysis actions must still run")
	}
}

// TestOutputText_NoControlsRendersNothingLikeACleanScan pins the terminal
// rendering branches. Their whole purpose is that the report must not read
// like a scan that found nothing wrong, so each of them is a one-line guard
// whose removal produces exactly that: the "no controls evaluated" failure
// warning, or an empty "(none with open issues)" table, or every catalog
// control listed as skipped.
func TestOutputText_NoControlsRendersNothingLikeACleanScan(t *testing.T) {
	oPrint := printOutput
	defer func() { printOutput = oPrint }()
	printOutput = true

	result := &control.AnalysisResult{CiValid: true, ProjectPath: "group/project", CIConfigSource: "remote"}
	pc := noControlsPC(t)
	p := &provider.GitLabProvider{}
	conf := &configuration.Configuration{PlumberConfig: pc, NoControls: true, GitlabURL: "https://gitlab.example"}
	s := buildComplianceSummary(p, result, conf)

	out := captureStdout(t, func() {
		if err := outputTextWithProvider(p, result, conf, s, nil, nil); err != nil {
			t.Fatalf("render: %v", err)
		}
	})

	if !strings.Contains(out, "none (--no-controls)") {
		t.Errorf("the header must state that no control ran, got:\n%s", out)
	}
	if strings.Contains(out, "No controls could be evaluated") {
		t.Errorf("the zero-control FAILURE warning must not fire when zero controls is the request, got:\n%s", out)
	}
	if strings.Contains(out, "none with open issues") {
		t.Errorf("an empty issues table reads as a clean scan, got:\n%s", out)
	}
	if strings.Contains(out, "Skipped Controls") {
		t.Errorf("nothing was selected, so no control should be listed as skipped, got:\n%s", out)
	}
	if !strings.Contains(out, "no controls requested, nothing to score") {
		t.Errorf("the status line must say the run asked for no controls, got:\n%s", out)
	}

	// The score is not merely absent, it is explained. An output that just
	// omits the banner reads as a rendering glitch; the run has to say that
	// nothing was evaluated and that there is therefore no score, or a
	// reader is left to infer which of the two happened.
	if !strings.Contains(out, "No control was run") {
		t.Errorf("the output must state plainly that no control ran, got:\n%s", out)
	}
	if !strings.Contains(out, "No Plumber Score") {
		t.Errorf("the output must state plainly that there is no score, got:\n%s", out)
	}
	// ... and no actual grade anywhere.
	if strings.Contains(out, "/ 100 pts") {
		t.Errorf("a points figure must never be rendered for a run that evaluated nothing, got:\n%s", out)
	}
}

// TestCSVAndOCSF_NoControlsDoNotClaimControlsPassed extends the JSON rule to
// the other two artifact writers that report a PER-CONTROL verdict. Both
// build their rows from the provider catalog and stamp control.StatusFor,
// which returns StatusPassed for an unskipped control with zero findings on
// a valid run. Under --no-controls the filters are empty by construction
// (they are mutually exclusive with the flag), so nothing would mark them
// skipped and every control would report as passing.
//
// This matters more here than in the terminal: OCSF and CSV are consumed by
// GRC platforms and security tooling, which would ingest a fully compliant
// posture for a run that evaluated nothing.
func TestCSVAndOCSF_NoControlsDoNotClaimControlsPassed(t *testing.T) {
	pc := noControlsPC(t)
	result := &control.AnalysisResult{CiValid: true, ProjectPath: "group/project"}
	p := &provider.GitLabProvider{}

	t.Run("csv", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "out.csv")
		conf := &configuration.Configuration{PlumberConfig: pc, NoControls: true}
		if err := writeCSVToFile(p, result, conf, path); err != nil {
			t.Fatalf("write csv: %v", err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read csv: %v", err)
		}
		records, err := csv.NewReader(strings.NewReader(string(raw))).ReadAll()
		if err != nil {
			t.Fatalf("parse csv: %v", err)
		}
		if len(records) < 2 {
			t.Fatal("the CSV must still list the catalog, otherwise this passes vacuously")
		}
		for _, row := range records[1:] {
			if row[3] == control.StatusPassed {
				t.Errorf("control %q reports passed for a run that evaluated nothing", row[2])
			}
		}
	})

	t.Run("ocsf", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "out.ocsf.json")
		conf := &configuration.Configuration{PlumberConfig: pc, NoControls: true}
		if err := writeOCSFToFile(p, result, conf, path); err != nil {
			t.Fatalf("write ocsf: %v", err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read ocsf: %v", err)
		}
		var events []struct {
			Compliance struct {
				Status   string `json:"status"`
				StatusID int    `json:"status_id"`
			} `json:"compliance"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(raw, &events); err != nil {
			t.Fatalf("parse ocsf: %v", err)
		}
		if len(events) == 0 {
			t.Fatal("the OCSF output must still list the catalog, otherwise this passes vacuously")
		}
		for _, e := range events {
			// status_id 1 is OCSF "Pass".
			if e.Compliance.StatusID == 1 {
				t.Errorf("OCSF event reports Pass for a run that evaluated nothing: %s", e.Message)
			}
		}
	})
}

// TestPublishAndFinalize_NoControlsStillFailsOnDegradedData pins the exit
// code the README and the help text promise: --no-controls exits 0 only
// when data collection succeeded. An incomplete collection means an
// incomplete PBOM inventory, so it must still fail (exit 3), and the flag
// must not be a way to silence that.
//
// The guarantee holds only because the --no-controls early return routes
// through finalizeRun rather than returning nil directly, which is exactly
// the kind of detail a later refactor of this shared tail would drop.
func TestPublishAndFinalize_NoControlsStillFailsOnDegradedData(t *testing.T) {
	pc := noControlsPC(t)
	p := &recordingProvider{GitLabProvider: &provider.GitLabProvider{}}
	conf := &configuration.Configuration{PlumberConfig: pc, NoControls: true}
	degraded := &control.AnalysisResult{
		CiValid:                true,
		ProjectPath:            "group/project",
		DataCollectionDegraded: true,
		DegradedReasons:        []string{"merged CI configuration could not be fetched"},
	}

	err := publishAndFinalize(p, &cobra.Command{}, degraded, conf, buildComplianceSummary(p, degraded, conf))
	var incomplete *IncompleteDataError
	if !errors.As(err, &incomplete) {
		t.Fatalf("--no-controls must not suppress the degraded-collection failure, got %v", err)
	}

	// Mirror: an intact collection exits 0.
	intact := &control.AnalysisResult{CiValid: true, ProjectPath: "group/project"}
	if err := publishAndFinalize(p, &cobra.Command{}, intact, conf, buildComplianceSummary(p, intact, conf)); err != nil {
		t.Fatalf("--no-controls on an intact collection must exit 0, got %v", err)
	}
}

// TestSecurityReports_NotWrittenUnderNoControls covers the two artifacts
// that have no honest empty form. SARIF and the GitLab SAST report exist to
// tell a security dashboard what was found, and an empty one is not a
// neutral statement: writeSARIFToFile's own contract is that "a clean run
// produces a valid empty-results document so downstream Code Scanning
// clears any previously-reported alerts", and buildGLSAST leaves
// Scan.Status at its "success" default unless collection was degraded.
//
// So a --no-controls run that uploaded them would dismiss existing Code
// Scanning alerts and show a clean GitLab Security Dashboard for a pipeline
// nobody checked. There is no field to set that fixes this, so the files
// are not written at all and the flags are named in the ignored list.
func TestSecurityReports_NotWrittenUnderNoControls(t *testing.T) {
	oSarif, oGLSAST := sarifFile, glsastFile
	defer func() { sarifFile, glsastFile = oSarif, oGLSAST }()

	dir := t.TempDir()
	sarifFile = filepath.Join(dir, "out.sarif")
	glsastFile = filepath.Join(dir, "gl-sast-report.json")

	pc := noControlsPC(t)
	result := &control.AnalysisResult{CiValid: true, ProjectPath: "group/project"}
	p := &provider.GitLabProvider{}
	conf := &configuration.Configuration{PlumberConfig: pc, NoControls: true}

	if err := writeOutputsWithProvider(p, result, conf, buildComplianceSummary(p, result, conf)); err != nil {
		t.Fatalf("write outputs: %v", err)
	}
	for _, f := range []string{sarifFile, glsastFile} {
		if _, err := os.Stat(f); err == nil {
			t.Errorf("%s was written; an empty security report clears existing alerts", filepath.Base(f))
		}
	}

	ignored := strings.Join(inertFlagsUnderNoControls(), ",")
	for _, flag := range []string{"--sarif", "--glsast"} {
		if !strings.Contains(ignored, flag) {
			t.Errorf("%s must be named in the ignored-flag notice, got %q", flag, ignored)
		}
	}

	// Mirror: without the flag both are written as usual.
	conf2 := &configuration.Configuration{PlumberConfig: pc}
	if err := writeOutputsWithProvider(p, result, conf2, buildComplianceSummary(p, result, conf2)); err != nil {
		t.Fatalf("write outputs: %v", err)
	}
	for _, f := range []string{sarifFile, glsastFile} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("without --no-controls %s must still be written: %v", filepath.Base(f), err)
		}
	}
}

// TestGateLine_NoControlsWinsOverDeprecatedThreshold pins that gateLine and
// gateErr agree on precedence. gateErr puts the noControls short-circuit
// first, so --threshold is inert; gateLine must say the same thing, or
// `--no-controls --threshold 100` renders "PASSED (0.0% of controls
// passing, deprecated threshold 100%)", a status line that contradicts
// itself and the flag.
func TestGateLine_NoControlsWinsOverDeprecatedThreshold(t *testing.T) {
	s := complianceSummary{
		thresholdSet: true, threshold: 100, compliance: 0,
		controlCount: 0, noControls: true,
	}
	if err := s.gateErr(); err != nil {
		t.Fatalf("precondition: the gate must pass, got %v", err)
	}
	if got := s.gateLine(); got != "no controls requested, nothing to score" {
		t.Fatalf("gateLine %q must match the gate it describes", got)
	}
}

// TestBuildGitLabConf_WiresNoControls covers the flag-to-config wiring
// itself. Every other test in this file starts from a Configuration with
// NoControls already set, so a dropped assignment in a config builder would
// leave the whole safety chain keyed off a false value and no test would
// notice: the run would evaluate everything, score it, and publish it.
func TestBuildGitLabConf_WiresNoControls(t *testing.T) {
	orig := noControls
	defer func() { noControls = orig }()

	noControls = true
	conf := buildGitLabConf("https://gitlab.example", "token", analyzeFlags{}, gitLabRemoteInfo{}, noControlsPC(t), nil, nil)
	if !conf.NoControls {
		t.Fatal("--no-controls must reach the Configuration the analysis reads")
	}

	noControls = false
	conf = buildGitLabConf("https://gitlab.example", "token", analyzeFlags{}, gitLabRemoteInfo{}, noControlsPC(t), nil, nil)
	if conf.NoControls {
		t.Fatal("NoControls must be false without the flag")
	}
}

// TestApplyControlScope_IsTheSingleWiringPoint pins the helper the three
// analyze entry points share. Keeping the three fields together in one
// place is what stops one provider path from silently losing --no-controls
// in a future refactor of a config builder.
func TestApplyControlScope_IsTheSingleWiringPoint(t *testing.T) {
	orig := noControls
	defer func() { noControls = orig }()

	noControls = true
	conf := &configuration.Configuration{}
	applyControlScope(conf, []string{"a"}, []string{"b"})
	if !conf.NoControls {
		t.Error("NoControls not wired")
	}
	if len(conf.ControlsFilter) != 1 || len(conf.SkipControlsFilter) != 1 {
		t.Errorf("filters not wired: %v %v", conf.ControlsFilter, conf.SkipControlsFilter)
	}
}

// TestNoControls_HasEnvFallback pins that --no-controls carries a
// PLUMBER_ANALYZE_* fallback like every other analyze flag, so the GitLab
// CI component (which passes settings as env vars, not flags) can reach it.
//
// It is deliberately not special-cased: anyone able to set this variable can
// already neutralise the gate with PLUMBER_ANALYZE_MIN_POINTS=0 or
// PLUMBER_ANALYZE_THRESHOLD=0, so withholding the fallback here would buy no
// security while making one flag behave unlike the rest.
func TestNoControls_HasEnvFallback(t *testing.T) {
	if envKeys["no-controls"] != "PLUMBER_ANALYZE_NO_CONTROLS" {
		t.Fatalf("--no-controls must keep its env fallback like every other flag, got %q", envKeys["no-controls"])
	}
}

// TestPublishAndFinalize_NoControlsFailsOnInvalidCIConfig covers the one
// collection failure that is deliberately NOT marked degraded: a
// .gitlab-ci.yml that was fetched but does not parse. The collector sets
// LimitedAnalysis and returns early, so no images or includes are
// gathered and the PBOM is empty.
//
// On a normal run the zero-control gate catches this and the errors are
// printed. --no-controls removes that gate, so without an explicit check
// the run exits 0 with an empty inventory and swallows the errors,
// contradicting the documented "exit 0 only if data collection succeeded".
func TestPublishAndFinalize_NoControlsFailsOnInvalidCIConfig(t *testing.T) {
	pc := noControlsPC(t)
	p := &recordingProvider{GitLabProvider: &provider.GitLabProvider{}}
	conf := &configuration.Configuration{PlumberConfig: pc, NoControls: true}
	invalid := &control.AnalysisResult{
		CiValid:     false,
		ProjectPath: "group/project",
		CiErrors:    []string{"jobs config should contain at least one visible job"},
	}

	err := publishAndFinalize(p, &cobra.Command{}, invalid, conf, buildComplianceSummary(p, invalid, conf))
	var incomplete *IncompleteDataError
	if !errors.As(err, &incomplete) {
		t.Fatalf("--no-controls must not exit 0 on an unusable CI config, got %v", err)
	}
}

// TestOutputText_NoControlsStillShowsCIErrors: the failure above has to be
// explicable. The zero-control warning is suppressed under --no-controls
// (it is the request, not a failure), which would also hide the CI errors
// that explain why the artifacts are empty.
func TestOutputText_NoControlsStillShowsCIErrors(t *testing.T) {
	oPrint := printOutput
	defer func() { printOutput = oPrint }()
	printOutput = true

	pc := noControlsPC(t)
	p := &provider.GitLabProvider{}
	conf := &configuration.Configuration{PlumberConfig: pc, NoControls: true, GitlabURL: "https://gitlab.example"}
	invalid := &control.AnalysisResult{
		CiValid:     false,
		ProjectPath: "group/project",
		CiErrors:    []string{"jobs config should contain at least one visible job"},
	}

	out := captureStdout(t, func() {
		if err := outputTextWithProvider(p, invalid, conf, buildComplianceSummary(p, invalid, conf), nil, nil); err != nil {
			t.Fatalf("render: %v", err)
		}
	})
	if !strings.Contains(out, "jobs config should contain at least one visible job") {
		t.Errorf("the CI errors explain the empty artifacts and must be shown, got:\n%s", out)
	}
}

// TestPublishAndFinalize_NoControlsAndMissingCIConfig covers the third
// collection-failure mode, and the deliberate asymmetry between providers.
//
// A GitLab project with no .gitlab-ci.yml sets CiMissing without setting
// CiErrors or DataCollectionDegraded, so neither of the other two guards
// fires. On a normal run the zero-control gate catches it
// (TestGate_ProviderZeroControlSemantics pins "GitLab CiMissing must
// fail"), and --no-controls removes that gate, so it needs its own check or
// it ships an empty PBOM as a successful inventory.
//
// GitHub is the opposite on purpose: a repo with no workflows keeps its
// control count and passes, restored in 0.4.0 so fleet scanners do not fail
// on CI-less repositories. --no-controls must not quietly reverse that.
func TestPublishAndFinalize_NoControlsAndMissingCIConfig(t *testing.T) {
	pc := noControlsPC(t)
	missing := func() *control.AnalysisResult {
		return &control.AnalysisResult{CiMissing: true, CiValid: true, ProjectPath: "group/project"}
	}

	t.Run("gitlab fails", func(t *testing.T) {
		p := &recordingProvider{GitLabProvider: &provider.GitLabProvider{}}
		conf := &configuration.Configuration{PlumberConfig: pc, NoControls: true}
		result := missing()
		err := publishAndFinalize(p, &cobra.Command{}, result, conf, buildComplianceSummary(p, result, conf))
		var incomplete *IncompleteDataError
		if !errors.As(err, &incomplete) {
			t.Fatalf("a GitLab project with no CI config has no pipeline to inventory; want IncompleteDataError, got %v", err)
		}
	})

	t.Run("github still passes", func(t *testing.T) {
		p := &provider.GitHubProvider{}
		conf := &configuration.Configuration{PlumberConfig: pc, NoControls: true}
		result := missing()
		if err := publishAndFinalize(p, nil, result, conf, buildComplianceSummary(p, result, conf)); err != nil {
			t.Fatalf("a CI-less GitHub repo must keep passing (fleet scans), got %v", err)
		}
	})
}

// TestPublishAndFinalize_NoControlsFailsOnInvalidCIWithoutErrors covers the
// GitLab collector state that reports an unusable CI config while leaving
// the error list empty: the origin collector's branch fires on
// `Status == "INVALID"` OR a non-empty error list, and with a non-empty
// ConfString it sets CiValid=false / CiMissing=false and never populates
// CiErrors.
//
// A guard keyed on CiErrors alone therefore misses it and ships an empty
// PBOM with exit 0. The check mirrors GitLabProvider.ComputeCompliance's
// own condition (CiMissing || !CiValid) so the two cannot disagree about
// what "no usable pipeline" means.
func TestPublishAndFinalize_NoControlsFailsOnInvalidCIWithoutErrors(t *testing.T) {
	pc := noControlsPC(t)
	p := &recordingProvider{GitLabProvider: &provider.GitLabProvider{}}
	conf := &configuration.Configuration{PlumberConfig: pc, NoControls: true}
	invalid := &control.AnalysisResult{
		CiValid:     false,
		CiMissing:   false,
		CiErrors:    nil, // the whole point: INVALID status, no error strings
		ProjectPath: "group/project",
	}

	err := publishAndFinalize(p, &cobra.Command{}, invalid, conf, buildComplianceSummary(p, invalid, conf))
	var incomplete *IncompleteDataError
	if !errors.As(err, &incomplete) {
		t.Fatalf("an invalid CI config with no error strings must still fail, got %v", err)
	}
}

// TestBuildGitHubConf_WiresNoControls is the GitHub counterpart of
// TestBuildGitLabConf_WiresNoControls. applyControlScope is unit-tested on
// its own, but nothing pinned that the GitHub entry points actually call
// it: a future edit reverting either to direct conf.ControlsFilter
// assignments would drop conf.NoControls silently, and a GitHub
// --no-controls run would evaluate everything, score it and publish it.
func TestBuildGitHubConf_WiresNoControls(t *testing.T) {
	orig := noControls
	defer func() { noControls = orig }()
	pc := noControlsPC(t)

	for _, tc := range []struct {
		name  string
		build func() *configuration.Configuration
	}{
		{"local clone", func() *configuration.Configuration {
			return buildGitHubLocalConf(&utils.GitRemoteInfo{ProjectPath: "owner/repo", RepoRoot: "/tmp/repo"}, pc, ".plumber.yaml", nil, nil)
		}},
		{"remote", func() *configuration.Configuration {
			return buildGitHubRemoteConf("owner", "repo", "main", "github.com", pc, ".plumber.yaml", nil, nil)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			noControls = true
			if !tc.build().NoControls {
				t.Fatal("--no-controls must reach the Configuration the analysis reads")
			}
			noControls = false
			if tc.build().NoControls {
				t.Fatal("NoControls must be false without the flag")
			}
		})
	}
}
