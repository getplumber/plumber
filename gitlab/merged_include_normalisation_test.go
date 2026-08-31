package gitlab

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMergedIncludeLocationsArriveResolved pins the assumption the whole
// include-attribution path rests on, against a payload captured from a real
// GitLab rather than one written to agree with us.
//
// Job attribution works by hashing each include twice: once from the
// project's own UNMERGED .gitlab-ci.yml (to find its declared `inputs:`) and
// once from GitLab's MERGED response (to attribute jobs). The two hashes
// must agree, and they only can if both sides see the same location string.
//
// The project writes `$CI_SERVER_FQDN/...`. GitLab returns `gitlab.com/...`.
// #286 was this agreement breaking: an unresolved variable on one side left
// the include's inputs unfound, which dropped them from the per-include
// merge and turned an overridden component job into a reported "hardcoded"
// one. The fixture in control/platform_call_inventory_test.go still carries
// the UNRESOLVED spelling, which is convenient but is not what GitLab sends.
func TestMergedIncludeLocationsArriveResolved(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "merged_includes_real.json"))
	if err != nil {
		t.Fatalf("reading the captured payload: %v", err)
	}
	var captured struct {
		Includes []MergedCIConfResponseInclude `json:"includes"`
	}
	if err := json.Unmarshal(raw, &captured); err != nil {
		t.Fatalf("the captured payload no longer decodes into the include shape: %v", err)
	}
	if len(captured.Includes) == 0 {
		t.Fatal("the capture carries no includes; it proves nothing")
	}

	for _, inc := range captured.Includes {
		if strings.Contains(inc.Location, "$") {
			t.Errorf("GitLab returned an UNRESOLVED location %q. The two hash sites can no "+
				"longer agree, and include inputs will be dropped (#286).", inc.Location)
		}
		if inc.Location == "" {
			t.Error("an include arrived with no location; it cannot be attributed at all")
		}
	}
}
