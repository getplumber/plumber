package cmd

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
)

// A --no-controls run takes the STANDALONE branch in continueRun under every
// mode, so its JSON report is the standalone inventory report.
//
// buildComplianceSummary set platformMode from the platform link alone, while
// buildAnalysisJSONReport keys its platform branches on that flag and nothing
// else. A linked inventory run therefore wrote platformMode:true and an empty
// policies array and dropped plumberConfig and every per-control block. The
// flag has to be the routing condition itself (platformPolicyMode).
func TestBuildComplianceSummary_NoControlsUnderPlatformStaysStandalone(t *testing.T) {
	newGateFlagsCmd(t)
	restore := withPlatformTestEnv(t, "https://platform.example.com", "tok")
	defer restore()
	p := testProvider(t)

	conf := &configuration.Configuration{
		PlumberConfig: testDefaultPlumberConfig(t),
		PlatformRun:   runContextWith(policyWithTree("A", "pipelineMustNotEnableDebugTrace", debugTraceControlConfig)),
	}
	// The control: the very same link, without --no-controls, IS platform
	// mode. Without it, a summary that never claims the mode would pass.
	if s := buildComplianceSummary(p, debugTraceResult(), conf); !s.platformMode {
		t.Fatal("a linked run that evaluates controls is platform mode")
	}

	conf.NoControls = true
	if s := buildComplianceSummary(p, debugTraceResult(), conf); s.platformMode {
		t.Error("--no-controls runs the standalone branch, so its summary must not claim platform mode")
	}
}

// The same fact where it is observable: the report a linked --no-controls run
// writes is the standalone inventory report, key for key. Adding --platform to
// an inventory run must not change the artifact, because the platform's
// policies were deliberately never consulted on that path.
func TestBuildAnalysisJSONReport_NoControlsUnderPlatformIsTheStandaloneReport(t *testing.T) {
	newGateFlagsCmd(t)
	p := testProvider(t)
	pol := policyWithTree("A", "pipelineMustNotEnableDebugTrace", debugTraceControlConfig)

	inventoryReport := func(t *testing.T, linked bool) map[string]any {
		t.Helper()
		conf := &configuration.Configuration{PlumberConfig: testDefaultPlumberConfig(t), NoControls: true}
		if linked {
			conf.PlatformRun = runContextWith(pol)
			restore := withPlatformTestEnv(t, "https://platform.example.com", "tok")
			defer restore()
		}
		// The summary is built the way production builds it, not hand-set:
		// the bug lived in buildComplianceSummary, so a literal
		// complianceSummary here would test nothing.
		s := buildComplianceSummary(p, debugTraceResult(), conf)
		payload, err := buildAnalysisJSONReport(debugTraceResult(), conf.PlumberConfig, s,
			jsonOutputParams{provider: "gitlab", noControls: true}, nil, nil)
		if err != nil {
			t.Fatalf("buildAnalysisJSONReport: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(payload, &m); err != nil {
			t.Fatalf("the report is not valid JSON: %v", err)
		}
		return m
	}

	linked := inventoryReport(t, true)
	standalone := inventoryReport(t, false)

	if _, present := linked["platformMode"]; present {
		t.Error("an inventory run took the standalone branch; platformMode would claim the policies produced it")
	}
	if _, present := linked["policies"]; present {
		t.Error("no policy was evaluated on this path, so an empty policies array must not be written")
	}
	if _, present := linked["plumberConfig"]; !present {
		t.Error("the inventory report names the local configuration it was collected under")
	}
	blocks := 0
	for k := range linked {
		if strings.HasSuffix(k, "Result") {
			blocks++
		}
	}
	if blocks == 0 {
		t.Error("the per-control inventory blocks are the point of a --no-controls report")
	}
	for k := range linked {
		if _, present := standalone[k]; !present {
			t.Errorf("the linked report gains key %q the standalone one does not have", k)
		}
	}
	for k := range standalone {
		if _, present := linked[k]; !present {
			t.Errorf("the linked report loses key %q the standalone one has", k)
		}
	}
}
