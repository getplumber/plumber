package control

import (
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
)

// The site's catalog (https://getplumber.io/docs/cli/controls) groups
// controls by their issue-code block, so a control's Category must follow
// the block its registered codes live in. Pinning the derivation keeps a
// new control from landing in the wrong docs grouping silently (#440).
func TestControlCategoriesFollowTheCodeBlocks(t *testing.T) {
	blockCategory := map[byte]string{
		'1': configuration.CategoryContainerImages,
		'2': configuration.CategoryCICDVariables,
		'3': configuration.CategoryCICDSecrets,
		'4': configuration.CategoryPipelineComposition,
		'5': configuration.CategoryAccessAndAuthorization,
		'6': configuration.CategorySecuritySource,
		'7': configuration.CategoryThirdPartyActions,
		'8': configuration.CategoryWorkflowTriggersAndPermissions,
		'9': configuration.CategoryRepositoryHygiene,
	}
	for _, entry := range configuration.ControlsCatalog() {
		codes := CodesForControl(entry.Name)
		if len(codes) == 0 {
			continue
		}
		blocks := map[byte]bool{}
		for _, c := range codes {
			blocks[strings.TrimPrefix(string(c), "ISSUE-")[0]] = true
		}
		if len(blocks) != 1 {
			t.Errorf("%s: codes span more than one block (%v); the category derivation assumes one", entry.Name, codes)
			continue
		}
		for b := range blocks {
			if want := blockCategory[b]; entry.Category != want {
				t.Errorf("%s: category %q, want %q (its codes live in the %cxx block)", entry.Name, entry.Category, want, b)
			}
		}
	}
}

// The catalog's terminal display names and the exported table must agree:
// the table is what reports and embedders see, the ControlEntry name is
// what the terminal prints, and the two describing one control differently
// would be exactly the drift #440 exists to end.
//
// Two tolerated divergences, each deliberate: the forbidden-tags entry
// computes its terminal name per run from the configured tags, and a
// cross-provider control may word its terminal name per provider
// ("Pipeline must not ..." on GitLab, "Workflows must not ..." on GitHub)
// while the exported table carries ONE canonical name - which must then be
// one of the observed wordings, never a third.
func TestCatalogDisplayNamesMatchTheExportedTable(t *testing.T) {
	pc := &configuration.PlumberConfig{}
	glEntries := GitLabControls(pc)
	ghEntries := GitHubControls(pc)
	if len(glEntries) == 0 || len(ghEntries) == 0 {
		t.Fatalf("catalog built no entries (gitlab %d, github %d); the comparison would be vacuous", len(glEntries), len(ghEntries))
	}
	dynamic := map[string]bool{"containerImageMustNotUseForbiddenTags": true}
	observed := map[string]map[string]bool{}
	for _, e := range append(append([]ControlEntry{}, glEntries...), ghEntries...) {
		if _, ok := configuration.ControlMetaFor(e.ControlName); !ok {
			t.Errorf("%s: catalog entry has no exported table row", e.ControlName)
			continue
		}
		if observed[e.ControlName] == nil {
			observed[e.ControlName] = map[string]bool{}
		}
		observed[e.ControlName][e.DisplayName] = true
	}
	for name, wordings := range observed {
		if dynamic[name] {
			continue
		}
		meta, _ := configuration.ControlMetaFor(name)
		if !wordings[meta.DisplayName] {
			t.Errorf("%s: exported name %q matches none of the terminal wordings %v", name, meta.DisplayName, wordings)
		}
	}
}
