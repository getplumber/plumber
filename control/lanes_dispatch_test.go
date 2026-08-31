package control

import (
	"encoding/json"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/gitlab"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/platform"
)

// platformRun builds a RunContext in a named config state. It is the seam
// markPlatformLaneGaps branches on, so every case below differs only in
// (source, includes) and nothing else.
func platformRun(source platform.ConfigSource, merged string, includes []json.RawMessage) *platform.RunContext {
	return &platform.RunContext{
		Context: &platform.ProjectContext{
			Snapshot: platform.Snapshot{Data: &platform.SnapshotData{
				SchemaVersion: "2",
				Includes:      includes,
				// A HEALTHY snapshot carries the settings lanes, so these
				// fixtures have to as well. The platform writes
				// branch_protection and mr_approvals on every successful
				// collection, empty lists included, and their absence now
				// degrades their controls (lanesWhoseAbsenceIsAFailure).
				// Omitting them here would make every case in this file
				// assert the degraded path by accident.
				BranchProtection: json.RawMessage(`{"branches":["main"],"protections":[]}`),
				MrApprovals:      json.RawMessage(`{"rules":[]}`),
			}},
		},
		Config: &platform.ConfigResolution{
			Source:     source,
			MergedYAML: merged,
			Reason:     reasonFor(source),
		},
	}
}

func reasonFor(s platform.ConfigSource) string {
	if s == platform.SourceUnavailable {
		return platform.ReasonResolutionUnavailable
	}
	return ""
}

func oneInclude() []json.RawMessage {
	return []json.RawMessage{json.RawMessage(`{"location":"gitlab.com/c/x@1.0.0","type":"component"}`)}
}

// confWithControls enables every control the dispatch decisions touch, so a
// control staying evaluable is a real verdict rather than the side effect of
// it being disabled.
func confWithControls(run *platform.RunContext) *configuration.Configuration {
	on := true
	return &configuration.Configuration{
		PlatformRun: run,
		PlumberConfig: &configuration.PlumberConfig{
			Version: "2.0",
			GitLab: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
				PipelineMustNotIncludeHardcodedJobs: &configuration.HardcodedJobsControlConfig{Enabled: &on},
				ExternalRefsMustNotCollide:          &configuration.EnabledOnlyControlConfig{Enabled: &on},
				IncludesMustBeUpToDate:              &configuration.IncludesUpToDateControlConfig{Enabled: &on},
				BranchMustBeProtected:               &configuration.BranchProtectionControlConfig{Enabled: &on},
			}},
		},
	}
}

// THE REGRESSION THIS FILE EXISTS FOR.
//
// A digest-divergent branch evaluates the config the platform resolved for
// THAT branch, while the snapshot's includes still describe the anchor's
// config. Pairing them mis-attributes every job an include the branch
// changed contributed: upstream jobs read as project-authored and vice
// versa. That is the fabricated-finding mode attribution exists to prevent,
// and it lands on exactly the branch the digest exists to detect.
//
// Presence of includes is therefore NOT sufficient; they must belong to the
// config being evaluated.
func TestIncludeAttributionDegradesWhenTheConfigIsNotTheSnapshots(t *testing.T) {
	for _, tc := range []struct {
		name        string
		source      platform.ConfigSource
		includes    []json.RawMessage
		wantDegrade bool
	}{
		{"snapshot config with its own includes evaluates", platform.SourceSnapshot, oneInclude(), false},
		{"snapshot config with no includes degrades", platform.SourceSnapshot, nil, true},
		{"resolved branch config degrades even though includes are present", platform.SourceResolved, oneInclude(), true},
		{"resolved branch config with no includes degrades", platform.SourceResolved, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := &AnalysisResult{}
			conf := confWithControls(platformRun(tc.source, "stages: [build]", tc.includes))
			markPlatformLaneGaps(result, conf)

			_, marked := result.NotEvaluable["pipelineMustNotIncludeHardcodedJobs"]
			if marked != tc.wantDegrade {
				t.Fatalf("pipelineMustNotIncludeHardcodedJobs marked not_evaluable = %v, want %v", marked, tc.wantDegrade)
			}
			// A settings control never depends on include attribution and
			// must survive every one of these states.
			if _, s := result.NotEvaluable["branchMustBeProtected"]; s {
				t.Error("branchMustBeProtected reads the protection API, not the pipeline; it must stay evaluable")
			}
		})
	}
}

// The dispatcher chooses between three mutually exclusive treatments. A
// swapped or inverted branch here would either degrade a healthy run
// entirely or let an empty one report all-clean, and until now nothing
// failed on either.
func TestMarkPlatformLaneGapsDispatch(t *testing.T) {
	t.Run("unavailable config marks pipeline controls with the run's reason", func(t *testing.T) {
		result := &AnalysisResult{}
		conf := confWithControls(platformRun(platform.SourceUnavailable, "", nil))
		markPlatformLaneGaps(result, conf)

		reason, marked := result.NotEvaluable["pipelineMustNotIncludeHardcodedJobs"]
		if !marked {
			t.Fatal("a run with no merged configuration must mark the pipeline controls")
		}
		if reason != platform.ReasonResolutionUnavailable {
			t.Errorf("reason = %q, want the run's own %q", reason, platform.ReasonResolutionUnavailable)
		}
		if _, s := result.NotEvaluable["branchMustBeProtected"]; s {
			t.Error("a settings control must survive an unavailable merged configuration")
		}
	})

	t.Run("healthy snapshot run marks nothing", func(t *testing.T) {
		result := &AnalysisResult{}
		conf := confWithControls(platformRun(platform.SourceSnapshot, "stages: [build]", oneInclude()))
		markPlatformLaneGaps(result, conf)
		if len(result.NotEvaluable) != 0 {
			t.Fatalf("a healthy platform run must mark nothing, got %v", result.NotEvaluable)
		}
	})

	t.Run("standalone and failed-context runs are no-ops", func(t *testing.T) {
		for name, conf := range map[string]*configuration.Configuration{
			"nil PlatformRun": confWithControls(nil),
			"context fetch failed": confWithControls(&platform.RunContext{
				ContextErr: errNotFetched{},
			}),
		} {
			t.Run(name, func(t *testing.T) {
				result := &AnalysisResult{}
				markPlatformLaneGaps(result, conf)
				if len(result.NotEvaluable) != 0 {
					t.Fatalf("a run that never engaged platform mode collects locally and must mark nothing, got %v", result.NotEvaluable)
				}
			})
		}
	})
}

type errNotFetched struct{}

func (errNotFetched) Error() string { return "no context" }

// The dispatcher ends in DropNotEvaluableFindings, and that call is
// load-bearing rather than cosmetic: on a divergent branch the marked
// controls' findings are WRONG, not merely unverified. Shipping them would
// push fabricated violations to the platform and deduct real score for
// them. This pins that the dispatcher drops rather than relabels.
func TestMarkPlatformLaneGapsDropsFindingsOfMarkedControls(t *testing.T) {
	// ISSUE-410 belongs to securityJobsMustNotBeWeakened, which needs
	// include attribution. ISSUE-103 belongs to a control that does not.
	result := &AnalysisResult{
		Findings: []opaengine.Finding{{Code: "ISSUE-410"}, {Code: "ISSUE-103"}},
	}
	conf := confWithControls(platformRun(platform.SourceResolved, "stages: [build]", oneInclude()))
	conf.PlumberConfig.GitLab.Controls.SecurityJobsMustNotBeWeakened = &configuration.SecurityJobsWeakenedControlConfig{Enabled: boolPtr(true)}

	markPlatformLaneGaps(result, conf)

	for _, f := range result.Findings {
		if f.Code == "ISSUE-410" {
			t.Fatal("a finding from a control whose attribution did not match the evaluated config must be dropped, not reported")
		}
	}
	if len(result.Findings) != 1 || result.Findings[0].Code != "ISSUE-103" {
		t.Fatalf("the evaluable control's finding must survive, got %+v", result.Findings)
	}
}

func boolPtr(b bool) *bool { return &b }

// TestAbsentSettingsLaneDegradesItsControls covers the gap degraded_fields
// alone leaves. The platform writes branch_protection and mr_approvals on
// every successful collection, so a payload without them is a collection
// that did not finish - and on a pre-v2 snapshot it says nothing was
// degraded while it is at it.
//
// Without this, a run whose branch-protection collection failed reads as a
// project with no branches to check and passes branchMustBeProtected.
func TestAbsentSettingsLaneDegradesItsControls(t *testing.T) {
	cases := []struct {
		name     string
		data     *platform.SnapshotData
		degraded []string
		evaluate []string
	}{
		{
			name: "absent branch_protection degrades its control even with nothing listed",
			data: &platform.SnapshotData{
				SchemaVersion: "2",
				MrApprovals:   json.RawMessage(`{"rules":[]}`),
			},
			degraded: []string{"branchMustBeProtected"},
			evaluate: []string{"mergeRequestApprovalSettingsMustBeCompliant"},
		},
		{
			name: "absent mr_approvals degrades all three approval controls",
			data: &platform.SnapshotData{
				SchemaVersion:    "2",
				BranchProtection: json.RawMessage(`{"branches":["main"],"protections":[]}`),
			},
			degraded: []string{
				"mergeRequestApprovalRulesMustRequireMinimumApprovals",
				"mergeRequestApprovalRulesMustCoverAllProtectedBranches",
				"mergeRequestApprovalSettingsMustBeCompliant",
			},
			evaluate: []string{"branchMustBeProtected"},
		},
		{
			name: "an absent variables lane is a real empty listing, not a gap",
			data: &platform.SnapshotData{
				SchemaVersion:    "2",
				BranchProtection: json.RawMessage(`{"branches":["main"],"protections":[]}`),
				MrApprovals:      json.RawMessage(`{"rules":[]}`),
			},
			evaluate: []string{"cicdVariablesMustBeProtected", "cicdVariablesMustBeMasked"},
		},
		{
			name: "a pre-v2 snapshot missing a lane still degrades it",
			data: &platform.SnapshotData{
				SchemaVersion: "1",
				MrApprovals:   json.RawMessage(`{"rules":[]}`),
			},
			degraded: []string{"branchMustBeProtected"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			run := &platform.RunContext{
				Context: &platform.ProjectContext{Snapshot: platform.Snapshot{Data: tc.data}},
			}
			result := &AnalysisResult{}
			result.MarkDegradedSnapshotLanes(nil, run)

			for _, name := range tc.degraded {
				if reason, marked := result.NotEvaluable[name]; !marked {
					t.Errorf("%s must be not_evaluable when its lane is absent", name)
				} else if reason != ReasonSnapshotLaneDegraded {
					t.Errorf("%s reason = %q, want %q", name, reason, ReasonSnapshotLaneDegraded)
				}
			}
			for _, name := range tc.evaluate {
				if _, marked := result.NotEvaluable[name]; marked {
					t.Errorf("%s must still evaluate; its lane was served", name)
				}
			}
		})
	}
}

// TestPerPolicyMarkingUsesThePolicysOwnControls covers the gap between the
// run's not-evaluable set and each policy's.
//
// Every marker in this file skips controls the config it was handed had
// DISABLED - correctly, because a disabled control was not "unevaluated".
// But in platform mode there is no single config: each policy is evaluated
// under its own control tree, and a control the local config switches off
// may be switched on by a policy. Marking only against the local config
// leaves such a control unmarked, its findings survive DropNotEvaluableFindings,
// and they are pushed as that policy's verdict - computed over a lane that
// supplied nothing.
//
// The shipped default disables pipelineMustNotIncludeHardcodedJobs, so a
// zero-config run whose platform policy enables it is not a corner case; it
// is the ordinary one.
func TestPerPolicyMarkingUsesThePolicysOwnControls(t *testing.T) {
	on, off := true, false

	localDisables := &configuration.PlumberConfig{
		Version: "2.0",
		GitLab: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
			PipelineMustNotIncludeHardcodedJobs: &configuration.HardcodedJobsControlConfig{Enabled: &off},
		}},
	}
	policyEnables := &configuration.PlumberConfig{
		Version: "2.0",
		GitLab: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
			PipelineMustNotIncludeHardcodedJobs: &configuration.HardcodedJobsControlConfig{Enabled: &on},
		}},
	}

	// A resolved (digest-divergent) config: attribution cannot be trusted,
	// so the control must not report a verdict under any config that enables
	// it.
	run := platformRun(platform.SourceResolved, "stages: [build]", oneInclude())
	conf := &configuration.Configuration{PlatformRun: run, PlumberConfig: localDisables}

	runMarks := &AnalysisResult{}
	markPlatformLaneGaps(runMarks, conf)
	if _, marked := runMarks.NotEvaluable["pipelineMustNotIncludeHardcodedJobs"]; marked {
		t.Fatal("a control the LOCAL config disabled must not be marked for the run itself")
	}

	policyMarks := &AnalysisResult{}
	markPlatformLaneGapsFor(policyMarks, conf, policyEnables)
	if _, marked := policyMarks.NotEvaluable["pipelineMustNotIncludeHardcodedJobs"]; !marked {
		t.Error("a control the POLICY enables must be marked when its lane supplied nothing, " +
			"or its findings reach that policy's pushed verdict")
	}
}

// TestFailedIncludeResolutionDegradesAttributionControls covers the state a
// runner holding only a job token lands in on every run: the snapshot serves
// includes[] and they do describe this configuration, but resolving each
// include's own job list needs the config-merge API, which the token cannot
// reach.
//
// A dropped include takes its jobs with it. They remain in the merged
// pipeline with nothing attributing them upstream, so they read as
// project-authored and the rules keyed on that distinction fire on them.
// Without this the run reports those fabricated findings while claiming the
// control evaluated.
func TestFailedIncludeResolutionDegradesAttributionControls(t *testing.T) {
	conf := confWithControls(platformRun(platform.SourceSnapshot, "stages: [build]", oneInclude()))

	evaluated := &AnalysisResult{}
	markPlatformLaneGaps(evaluated, conf)
	if _, marked := evaluated.NotEvaluable["pipelineMustNotIncludeHardcodedJobs"]; marked {
		t.Fatal("with every include resolved, the attribution controls must evaluate")
	}

	dropped := &AnalysisResult{
		PipelineOriginData: &gitlab.GitlabPipelineOriginData{
			IncludesFailed: []string{"gitlab.com/c/x@1.0.0"},
		},
		Findings: []opaengine.Finding{{Code: "ISSUE-401"}},
	}
	markPlatformLaneGaps(dropped, conf)

	reason, marked := dropped.NotEvaluable["pipelineMustNotIncludeHardcodedJobs"]
	if !marked {
		t.Fatal("an include that could not be resolved leaves attribution incomplete; the control must abstain")
	}
	if reason != ReasonIncludeResolutionFailed {
		t.Errorf("reason = %q, want %q so an operator can tell this from a platform gap", reason, ReasonIncludeResolutionFailed)
	}
	if len(dropped.Findings) != 0 {
		t.Errorf("the control's findings must be dropped, not merely relabelled; got %d", len(dropped.Findings))
	}
}

// TestEmptyBranchListDegradesBranchProtection covers a lane that arrives
// looking healthy and carrying nothing.
//
// Every real project has at least one branch, so an empty name list is the
// lane not having survived the wire, not a fact about the project. The
// platform stores the collector's Go slices; a nil slice marshals to JSON
// null, and the context endpoint decodes into pointer fields tagged
// omitempty, so a null list is re-served with its key absent.
//
// The direction is what makes it worth a guard: with no names the rule
// iterates an empty list and PASSES, so a project whose protections could
// not be read is certified compliant.
func TestEmptyBranchListDegradesBranchProtection(t *testing.T) {
	conf := confWithControls(platformRun(platform.SourceSnapshot, "stages: [build]", oneInclude()))

	withBranches := &AnalysisResult{
		ProtectionData: &gitlab.GitlabProtectionAnalysisData{
			Branches:             []string{"main"},
			MRApprovalRulesKnown: true,
		},
	}
	markPlatformLaneGaps(withBranches, conf)
	if _, marked := withBranches.NotEvaluable["branchMustBeProtected"]; marked {
		t.Fatal("a lane carrying branch names must evaluate; zero protections on it is a real finding")
	}

	empty := &AnalysisResult{
		ProtectionData: &gitlab.GitlabProtectionAnalysisData{MRApprovalRulesKnown: true},
		Findings:       []opaengine.Finding{{Code: "ISSUE-501"}},
	}
	markPlatformLaneGaps(empty, conf)
	if _, marked := empty.NotEvaluable["branchMustBeProtected"]; !marked {
		t.Error("a branch-protection lane with no branch names must not be scored")
	}
	if len(empty.Findings) != 0 {
		t.Errorf("findings computed over a lost lane must be dropped; got %d", len(empty.Findings))
	}
}

// TestFailedUpstreamProbeDegradesRefConfusion covers a control that fails
// SILENTLY when its data is missing, which makes it the easiest one to
// mislead a reader with.
//
// externalRefsMustNotCollide fires only on a confirmed tag-and-branch double
// hit against the include's SOURCE project. That fail-safe design is right:
// an indeterminate probe must never assert ambiguity. But the resulting
// zero value reads downstream as "this ref is unambiguous", which is a clean
// answer nothing established.
//
// It matters more as the migration proceeds. The probe is two REST reads
// against a project other than the one being analyzed, so it is among the
// first things to fail for a token scoped to this project - and it fails for
// every include at once on a tokenless run.
func TestFailedUpstreamProbeDegradesRefConfusion(t *testing.T) {
	conf := confWithControls(platformRun(platform.SourceSnapshot, "stages: [build]", oneInclude()))

	completed := &AnalysisResult{
		PipelineOriginData: &gitlab.GitlabPipelineOriginData{},
	}
	markPlatformLaneGaps(completed, conf)
	if _, marked := completed.NotEvaluable["externalRefsMustNotCollide"]; marked {
		t.Fatal("a run whose probes all completed must report a real verdict")
	}

	failed := &AnalysisResult{
		PipelineOriginData: &gitlab.GitlabPipelineOriginData{
			RefProbesFailed: []string{"vendor/components@1.0.0"},
		},
	}
	markPlatformLaneGaps(failed, conf)

	reason, marked := failed.NotEvaluable["externalRefsMustNotCollide"]
	if !marked {
		t.Fatal("a ref whose upstream could not be probed must not be certified unambiguous")
	}
	if reason != ReasonUpstreamProbeFailed {
		t.Errorf("reason = %q, want %q", reason, ReasonUpstreamProbeFailed)
	}

	// One failed probe degrades ONE control. The rest of the include
	// reasoning is unaffected: the include list and the job attribution
	// behind it were both fine.
	if _, marked := failed.NotEvaluable["pipelineMustNotIncludeHardcodedJobs"]; marked {
		t.Error("a failed ref probe must not degrade the attribution controls with it")
	}
	if _, marked := failed.NotEvaluable["includesMustBeUpToDate"]; marked {
		t.Error("a failed ref probe says nothing about whether an include is up to date")
	}
}

// TestFailedVersionLookupDegradesUpToDate is the sibling case, and it fails
// the same silent way. includesMustBeUpToDate compares an include's pinned
// ref against the latest upstream version, and it skips any include whose
// latest version is unknown. A catalogue query or tag listing that could not
// be completed therefore leaves the control reporting a clean pass over
// includes it never compared against anything.
//
// Both lookups hit the include's SOURCE project, so a token scoped to the
// analyzed project loses them first, and a tokenless run loses all of them.
func TestFailedVersionLookupDegradesUpToDate(t *testing.T) {
	conf := confWithControls(platformRun(platform.SourceSnapshot, "stages: [build]", oneInclude()))

	failed := &AnalysisResult{
		PipelineOriginData: &gitlab.GitlabPipelineOriginData{
			VersionLookupsFailed: []string{"vendor/components"},
		},
	}
	markPlatformLaneGaps(failed, conf)

	reason, marked := failed.NotEvaluable["includesMustBeUpToDate"]
	if !marked {
		t.Fatal("an include whose latest version could not be looked up must not be reported up to date")
	}
	if reason != ReasonUpstreamProbeFailed {
		t.Errorf("reason = %q, want %q", reason, ReasonUpstreamProbeFailed)
	}
	if _, marked := failed.NotEvaluable["externalRefsMustNotCollide"]; marked {
		t.Error("a failed version lookup says nothing about whether a ref is ambiguous")
	}
}
