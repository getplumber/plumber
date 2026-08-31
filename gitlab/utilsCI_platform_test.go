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
