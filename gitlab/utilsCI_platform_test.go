package gitlab

import (
	"encoding/json"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/internal/platform"
)

func platformConf(source platform.ConfigSource, merged string, includes ...string) *configuration.Configuration {
	raw := make([]json.RawMessage, 0, len(includes))
	for _, i := range includes {
		raw = append(raw, json.RawMessage(i))
	}
	return &configuration.Configuration{PlatformRun: &platform.RunContext{
		Context: &platform.ProjectContext{
			Snapshot: platform.Snapshot{Data: &platform.SnapshotData{
				SchemaVersion: "2",
				Includes:      raw,
			}},
		},
		// Valid mirrors ResolveRunConfig, which starts every resolution
		// valid and only clears the flag when the git host says the merge
		// itself is INVALID. A fixture left at the zero value would assert
		// the invalid path by accident.
		Config: &platform.ConfigResolution{Source: source, MergedYAML: merged, Valid: true},
	}}
}

// The boolean second return is the standalone-vs-platform switch for the
// whole feature. If it ever returned false while platform mode is engaged,
// the run would silently fall back to resolving the merge over a
// CI_JOB_TOKEN that cannot do it, and nothing else would notice.
func TestPlatformMergedConfigIsTheStandaloneSwitch(t *testing.T) {
	t.Run("nil configuration is standalone", func(t *testing.T) {
		if _, platformMode := platformMergedConfig(nil); platformMode {
			t.Fatal("a nil configuration must report standalone, never platform mode")
		}
	})

	t.Run("no platform run is standalone", func(t *testing.T) {
		if _, platformMode := platformMergedConfig(&configuration.Configuration{}); platformMode {
			t.Fatal("a run without --platform must resolve the merge itself, exactly as before")
		}
	})

	t.Run("a run whose context fetch failed is standalone", func(t *testing.T) {
		conf := &configuration.Configuration{PlatformRun: &platform.RunContext{}}
		if _, platformMode := platformMergedConfig(conf); platformMode {
			t.Fatal("platform mode that never engaged must fall back to local collection")
		}
	})

	t.Run("engaged platform mode serves the snapshot's config", func(t *testing.T) {
		conf := platformConf(platform.SourceSnapshot, "stages:\n  - build\n")
		resp, platformMode := platformMergedConfig(conf)
		if !platformMode {
			t.Fatal("an engaged platform run must not fall back to the GitLab merge API")
		}
		if resp.CiConfig.MergedYaml != "stages:\n  - build\n" {
			t.Fatalf("merged YAML = %q, want the snapshot's", resp.CiConfig.MergedYaml)
		}
		if resp.CiConfig.Status != "VALID" {
			t.Fatalf("status = %q, want VALID", resp.CiConfig.Status)
		}
	})

	// A merge the git host itself rejected is a real answer about the
	// user's own CI file, and it must survive the platform lane. Reporting
	// it VALID hands the analysis a partial pipeline whose unmergeable jobs
	// are simply missing, so every control passes over what is left and the
	// run prints a clean verdict for a config that does not build.
	t.Run("an INVALID merge stays INVALID", func(t *testing.T) {
		conf := platformConf(platform.SourceResolved, "partial:\n  script: echo\n")
		conf.PlatformRun.Config.Valid = false

		resp, platformMode := platformMergedConfig(conf)
		if !platformMode {
			t.Fatal("an engaged platform run must not fall back to the GitLab merge API")
		}
		if resp.CiConfig.Status != "INVALID" {
			t.Fatalf("status = %q, want INVALID", resp.CiConfig.Status)
		}
		if len(resp.CiConfig.Errors) == 0 {
			t.Error("an INVALID merge must carry an error the report can show")
		}
	})
}

// An empty merged config in platform mode is the honest "nothing resolved"
// state, not a broken CI file. Status describes whether the git host could
// MERGE the configuration, which is a different question from whether this
// CLI obtained one. Reporting INVALID here would tell users their pipeline
// is broken when it is fine, and the caller marks the pipeline controls
// not_evaluable either way.
func TestPlatformMergedConfigReportsEmptyAsValidNotInvalid(t *testing.T) {
	conf := platformConf(platform.SourceUnavailable, "")
	resp, platformMode := platformMergedConfig(conf)
	if !platformMode {
		t.Fatal("an engaged platform run stays in platform mode even with nothing resolved")
	}
	if resp.CiConfig.MergedYaml != "" {
		t.Fatalf("merged YAML = %q, want empty", resp.CiConfig.MergedYaml)
	}
	if resp.CiConfig.Status != "VALID" {
		t.Fatalf("status = %q, want VALID: an unresolved config is not a broken one", resp.CiConfig.Status)
	}
}

// Attribution is only usable when it describes the configuration actually
// being evaluated. On a digest-divergent branch the config comes from the
// resolve endpoint (which serves no includes) while the snapshot's includes
// still describe the anchor, so pairing them would mis-classify every job an
// include the branch touched contributed.
func TestPlatformIncludesOnlyServeTheirOwnConfig(t *testing.T) {
	const inc = `{"location":"gitlab.com/c/x@1.0.0","type":"component"}`

	t.Run("snapshot config gets the snapshot's includes", func(t *testing.T) {
		got := platformIncludes(platformConf(platform.SourceSnapshot, "stages: [build]", inc))
		if len(got) != 1 {
			t.Fatalf("want 1 include, got %d", len(got))
		}
		if got[0].Location != "gitlab.com/c/x@1.0.0" {
			t.Fatalf("include location = %q", got[0].Location)
		}
	})

	for _, source := range []platform.ConfigSource{platform.SourceResolved, platform.SourceUnavailable} {
		t.Run("config from "+string(source)+" gets none", func(t *testing.T) {
			if got := platformIncludes(platformConf(source, "stages: [build]", inc)); len(got) != 0 {
				t.Fatalf("attribution from a different configuration must not be served, got %d includes", len(got))
			}
		})
	}
}

// A malformed include is DROPPED, not partially applied. A half-decoded
// include gives a confidently wrong origin; a short list is detected
// upstream as missing attribution and degrades honestly.
func TestPlatformIncludesDropsWhatItCannotDecode(t *testing.T) {
	conf := platformConf(platform.SourceSnapshot, "stages: [build]",
		`{"location":"gitlab.com/c/good@1.0.0","type":"component"}`,
		`{"location": 12345}`, // location is a string in the contract
	)
	got := platformIncludes(conf)
	if len(got) != 1 {
		t.Fatalf("want the malformed include dropped and the valid one kept, got %d: %+v", len(got), got)
	}
	if got[0].Location != "gitlab.com/c/good@1.0.0" {
		t.Fatalf("the surviving include must be the decodable one, got %q", got[0].Location)
	}
}

// snapshotMergeVerdict attaches the git host's own answer about the
// snapshot's merged configuration, as the platform has served it since
// 2026-08-28.
func snapshotMergeVerdict(conf *configuration.Configuration, status string, errs ...string) *configuration.Configuration {
	data := conf.PlatformRun.Context.Snapshot.Data
	data.MergedYamlStatus = status
	data.CiErrors = errs
	return conf
}

// The git host's verdict on the SNAPSHOT's merged configuration is served,
// and the served one is the only place a snapshot-path run can learn it.
// StartRunConfigResolution starts every resolution Valid and never clears
// the flag on the snapshot path, so the local synthesis can only ever say
// VALID there: a snapshot whose merge GitLab itself rejected was reported
// as a clean config, and every control passed over the jobs that failed to
// merge - exactly the silent-green mode platformMergedConfig's own doc
// comment says must never happen.
func TestPlatformMergedConfigUsesTheServedMergeVerdict(t *testing.T) {
	t.Run("a served INVALID and its errors are carried verbatim", func(t *testing.T) {
		conf := snapshotMergeVerdict(
			platformConf(platform.SourceSnapshot, "partial:\n  script: echo\n"),
			"INVALID",
			"jobs config should contain at least one visible job",
		)

		resp, platformMode := platformMergedConfig(conf)
		if !platformMode {
			t.Fatal("an engaged platform run must not fall back to the GitLab merge API")
		}
		if resp.CiConfig.Status != "INVALID" {
			t.Errorf("status = %q, want the served INVALID", resp.CiConfig.Status)
		}
		want := "jobs config should contain at least one visible job"
		if len(resp.CiConfig.Errors) != 1 || resp.CiConfig.Errors[0] != want {
			t.Errorf("errors = %v, want the host's own message %q, not a synthesized one", resp.CiConfig.Errors, want)
		}
	})

	t.Run("a served VALID invents no errors", func(t *testing.T) {
		conf := snapshotMergeVerdict(platformConf(platform.SourceSnapshot, "stages: [build]\n"), "VALID")

		resp, _ := platformMergedConfig(conf)
		if resp.CiConfig.Status != "VALID" {
			t.Errorf("status = %q, want VALID", resp.CiConfig.Status)
		}
		if len(resp.CiConfig.Errors) != 0 {
			t.Errorf("errors = %v, want none on a valid merge", resp.CiConfig.Errors)
		}
	})

	// Older snapshots carry neither field. The synthesis stays exactly what
	// it was for them, so no run that works today changes.
	t.Run("a snapshot serving neither falls back to the synthesis", func(t *testing.T) {
		conf := platformConf(platform.SourceSnapshot, "stages: [build]\n")
		if resp, _ := platformMergedConfig(conf); resp.CiConfig.Status != "VALID" {
			t.Errorf("status = %q, want the synthesized VALID", resp.CiConfig.Status)
		}

		conf = platformConf(platform.SourceResolved, "partial:\n  script: echo\n")
		conf.PlatformRun.Config.Valid = false
		resp, _ := platformMergedConfig(conf)
		if resp.CiConfig.Status != "INVALID" {
			t.Errorf("status = %q, want the synthesized INVALID", resp.CiConfig.Status)
		}
		if len(resp.CiConfig.Errors) == 0 {
			t.Error("an INVALID merge must carry an error the report can show")
		}
	})

	// The contract's status is a closed set of two values. Anything else is
	// a platform bug or a field that has grown a meaning this CLI does not
	// know, and neither may be forwarded: "VALID" and "INVALID" are the only
	// strings the readers downstream compare against, so an unrecognized one
	// would be read as "not INVALID" - a pass by default, decided by a value
	// nobody here understood.
	t.Run("a status outside the closed set falls back to the synthesis", func(t *testing.T) {
		conf := snapshotMergeVerdict(
			platformConf(platform.SourceSnapshot, "stages: [build]\n"),
			"PENDING",
			"a message about a state this CLI cannot read",
		)

		resp, _ := platformMergedConfig(conf)
		if resp.CiConfig.Status != "VALID" {
			t.Errorf("status = %q, want the synthesized VALID: PENDING is not in the contract", resp.CiConfig.Status)
		}
		if len(resp.CiConfig.Errors) != 0 {
			t.Errorf("errors = %v, want none: they describe a status this run did not adopt", resp.CiConfig.Errors)
		}
	})

	// Errors are attached to an INVALID verdict only. The origin collector
	// treats a non-empty error list as an invalid configuration on its own
	// (len(Errors) > 0 || Status == "INVALID"), so carrying errors under a
	// VALID status would flip the run to LimitedAnalysis and withhold the
	// score over a merge the git host accepted.
	t.Run("errors under a VALID verdict are not carried", func(t *testing.T) {
		conf := snapshotMergeVerdict(
			platformConf(platform.SourceSnapshot, "stages: [build]\n"),
			"VALID",
			"a warning that is not a merge failure",
		)

		resp, _ := platformMergedConfig(conf)
		if resp.CiConfig.Status != "VALID" {
			t.Errorf("status = %q, want VALID", resp.CiConfig.Status)
		}
		if len(resp.CiConfig.Errors) != 0 {
			t.Errorf("errors = %v: a valid merge has no errors to report, and these would invalidate the run", resp.CiConfig.Errors)
		}
	})

	// The served verdict describes the snapshot's merged_yaml. On a
	// digest-divergent branch the configuration being evaluated is the one
	// the resolve endpoint returned for THIS branch, and the anchor's
	// verdict is a statement about a different document - the same reason
	// the anchor's include attribution does not travel either. Borrowing it
	// would report the branch's own config broken (or clean) on evidence
	// nothing gathered about it.
	t.Run("the anchor's verdict does not travel to a divergent branch's config", func(t *testing.T) {
		conf := snapshotMergeVerdict(
			platformConf(platform.SourceResolved, "job:\n  script: echo\n"),
			"INVALID",
			"the anchor's own merge error",
		)

		resp, _ := platformMergedConfig(conf)
		if resp.CiConfig.Status != "VALID" {
			t.Errorf("status = %q: the resolve endpoint judged THIS branch's config valid", resp.CiConfig.Status)
		}
		if len(resp.CiConfig.Errors) != 0 {
			t.Errorf("errors = %v, want none: these describe the anchor's configuration", resp.CiConfig.Errors)
		}
	})
}

// TestGetFullGitlabCIUsesTheServedRawConfig covers the run with no checkout
// of the analyzed project: a ci_config_path pointing into another project,
// GIT_STRATEGY none, a sparse checkout, or a job whose file read was
// refused. The project's own UNMERGED CI file is then unreadable, and the
// two controls that compare it against the merged pipeline
// (pipelineMustNotIncludeHardcodedJobs, pipelineMustNotOverrideJobVariables)
// abstain with raw_config_unavailable.
//
// The platform has served that exact file as raw_config since 2026-08-27.
// Using it closes the lane without a request; a lane the platform reports
// as degraded (its own size cap) keeps today's honest abstention rather
// than being read as an empty root file, which yields no hardcoded jobs and
// no overridden variables - a silent pass.
//
// The served file is the one collected at the snapshot's ANCHOR, so it is
// used only for a run analysing that same ref or commit. See the divergent
// subtest for what pairing it with another revision's merged pipeline
// would produce.
func TestGetFullGitlabCIUsesTheServedRawConfig(t *testing.T) {
	const rawConfig = "include:\n  - component: example.com/vendor/build@1.0.0\nlocal_job:\n  script:\n    - echo local\n"
	const anchorSha = "0123456789abcdef0123456789abcdef01234567"

	// A ci_config_path in another project: this project's file API cannot
	// serve it, so GetFullGitlabCI never even tries. The URL below would
	// fail every request, which is what proves the root file came from the
	// snapshot rather than from the network.
	newRun := func(raw string, degraded ...string) (*ProjectInfo, *configuration.Configuration) {
		conf := platformConf(platform.SourceSnapshot, "local_job:\n  script:\n    - echo local\n")
		conf.PlatformRun.Context.Snapshot.Data.RawConfig = raw
		conf.PlatformRun.Context.Snapshot.Data.DegradedFields = degraded
		conf.PlatformRun.Config.AnchorRef = "main"
		conf.PlatformRun.Config.AnchorSha = anchorSha
		return &ProjectInfo{
			Path:                "group/project",
			CiConfPath:          "shared.yml@platform/ci-templates",
			DefaultBranch:       "main",
			AnalyzeBranch:       "main",
			LatestHeadCommitSha: anchorSha,
		}, conf
	}

	t.Run("the served file becomes the pre-merge document", func(t *testing.T) {
		project, conf := newRun(rawConfig)

		gitlabConf, _, _, confStr, _, err := GetFullGitlabCI(project, "main", "", "http://127.0.0.1:1", conf)
		if err != nil {
			t.Fatalf("GetFullGitlabCI: %v", err)
		}
		if confStr != rawConfig {
			t.Errorf("root config = %q, want the snapshot's raw_config", confStr)
		}
		if gitlabConf == nil {
			t.Fatal("the served root file must be parsed like any other")
		}
		if _, ok := gitlabConf.GitlabJobs["local_job"]; !ok {
			t.Errorf("the parsed root file must carry the project's own jobs, got %v", gitlabConf.GitlabJobs)
		}
	})

	t.Run("a degraded raw_config lane keeps the honest gap", func(t *testing.T) {
		project, conf := newRun(rawConfig, platform.DegradedFieldRawConfig)

		_, _, _, confStr, _, err := GetFullGitlabCI(project, "main", "", "http://127.0.0.1:1", conf)
		if err != nil {
			t.Fatalf("GetFullGitlabCI: %v", err)
		}
		if confStr != "" {
			t.Errorf("root config = %q, want none: the platform reported this lane degraded", confStr)
		}
	})

	t.Run("a snapshot serving no raw_config keeps the honest gap", func(t *testing.T) {
		project, conf := newRun("")

		_, _, _, confStr, _, err := GetFullGitlabCI(project, "main", "", "http://127.0.0.1:1", conf)
		if err != nil {
			t.Fatalf("GetFullGitlabCI: %v", err)
		}
		if confStr != "" {
			t.Errorf("root config = %q, want none: nothing served it", confStr)
		}
	})

	// A run analysing another ref must not borrow the anchor's root file.
	// The two documents are then different revisions, and the controls that
	// read the pre-merge file compare it against a merged pipeline resolved
	// for THIS branch: a variable the anchor declares globally and this
	// branch does not still reads as declared (ISSUE-205 from
	// localGlobalVariables), and every finding the root file carries points
	// at line numbers in a file this ref does not have. A run with no
	// checkout is always digest-divergent - there is no local file to
	// digest - so this is the state the gate exists for, not a corner.
	t.Run("another ref does not borrow the anchor's root file", func(t *testing.T) {
		project, conf := newRun(rawConfig)
		project.AnalyzeBranch = "feature/x"
		project.LatestHeadCommitSha = "fedcba9876543210fedcba9876543210fedcba98"
		conf.PlatformRun.Config.Source = platform.SourceResolved

		_, _, _, confStr, _, err := GetFullGitlabCI(project, "feature/x", "", "http://127.0.0.1:1", conf)
		if err != nil {
			t.Fatalf("GetFullGitlabCI: %v", err)
		}
		if confStr != "" {
			t.Errorf("root config = %q, want none: this file is the anchor's, not this branch's", confStr)
		}
	})

	// The commit answers when there is no ref to compare - a detached job.
	// It is the exact form of the same question: this run is reading the
	// very revision the platform collected.
	t.Run("with no ref to compare the anchor's own commit is served", func(t *testing.T) {
		project, conf := newRun(rawConfig)
		project.AnalyzeBranch = ""
		conf.PlatformRun.Config.Source = platform.SourceResolved

		_, _, _, confStr, _, err := GetFullGitlabCI(project, "", "", "http://127.0.0.1:1", conf)
		if err != nil {
			t.Fatalf("GetFullGitlabCI: %v", err)
		}
		if confStr != rawConfig {
			t.Errorf("root config = %q, want the snapshot's raw_config: this run is at the anchor's commit", confStr)
		}
	})

	// The sha is NOT an alternative to the ref, and this is the case that
	// says why. A run analysing another branch whose head could not be
	// fetched keeps the DEFAULT branch's sha (control/task.go warns and
	// carries on), which is the anchor's - so a sha that could stand in for
	// a ref would hand the anchor's root file to a feature branch exactly
	// when the run knew least about it.
	t.Run("another ref is withheld even at the anchor's sha", func(t *testing.T) {
		project, conf := newRun(rawConfig)
		project.AnalyzeBranch = "feature/x"
		conf.PlatformRun.Config.Source = platform.SourceResolved

		_, _, _, confStr, _, err := GetFullGitlabCI(project, "feature/x", "", "http://127.0.0.1:1", conf)
		if err != nil {
			t.Fatalf("GetFullGitlabCI: %v", err)
		}
		if confStr != "" {
			t.Errorf("root config = %q, want none: the sha is the analysed ref's head only when that lookup worked", confStr)
		}
	})
}
