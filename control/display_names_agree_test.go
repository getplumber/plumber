package control

import (
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
)

// pinnedByDigestSuffix is the only sanctioned decoration a terminal
// catalog name may carry on top of the registry wording: the
// forbidden-reference control appends it when the configuration also
// requires digest pinning, so the operator sees which half is active.
const pinnedByDigestSuffix = " (pinned by digest)"

// providerFlavouredNames is the closed exemption list: a cross-provider
// control whose GitHub terminal name is DELIBERATELY worded in GitHub
// vocabulary, because the registry's single DisplayName is written in
// GitLab vocabulary ("Includes", "Pipeline") for the GitLab-only
// platform. Keyed by control name, then provider, holding the flavoured
// name that copy is allowed to carry (Thomas, 2026-09-22, ruling on the
// issues-page review batch C1). Two entries, and only these two: any
// THIRD divergence still fails the test below. Adding to this table is a
// wording decision, not a refactor.
var providerFlavouredNames = map[string]map[string]string{
	"pipelineMustNotUseDockerInDocker": {
		configuration.ProviderGitHub: "Workflows must not use Docker-in-Docker",
	},
	"externalRefsMustNotCollide": {
		configuration.ProviderGitHub: "Actions must not use ambiguous tag/branch refs",
	},
}

// Every control name the CLI shows comes from one of four copies: the
// registry in configuration/registry.go (canonical, exported in the
// catalog and pushed to the platform), the two terminal catalogs in
// catalog.go, and the MR comment headings in mrcomment.go. Until the
// 2026-09-22 issues-page review they drifted, so one control read
// differently depending on where you looked (spec section 5.2, item 3).
// This test makes the registry the single wording and every copy its
// echo, per provider, with the documented provider-flavoured exemptions
// above as the only allowed difference.
func TestControlDisplayNamesAgreeAcrossEveryCopy(t *testing.T) {
	// Both shapes of the catalog: with no configuration, and with digest
	// pinning required on both providers, which is the ONLY branch that
	// builds the "(pinned by digest)" variant. Without the second shape
	// the variant literal in catalog.go is compared to nothing and can
	// keep a retired base wording while every test stays green.
	digestRequired := true
	pinned := &configuration.PlumberConfig{
		GitLab: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
			ContainerImageMustNotUseForbiddenTags: &configuration.ImageForbiddenTagsControlConfig{
				ContainerImagesMustBePinnedByDigest: &digestRequired,
			},
		}},
		GitHub: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
			ContainerImageMustNotUseForbiddenTags: &configuration.ImageForbiddenTagsControlConfig{
				ContainerImagesMustBePinnedByDigest: &digestRequired,
			},
		}},
	}
	shapes := map[string]*configuration.PlumberConfig{
		"unconfigured":      {},
		"digest pinning on": pinned,
	}
	variantsSeen := 0
	for shape, pc := range shapes {
		byProvider := map[string][]ControlEntry{
			configuration.ProviderGitLab: GitLabControls(pc),
			configuration.ProviderGitHub: GitHubControls(pc),
		}
		if len(byProvider[configuration.ProviderGitLab]) == 0 || len(byProvider[configuration.ProviderGitHub]) == 0 {
			t.Fatalf("%s: catalog built no entries (gitlab %d, github %d); the comparison would be vacuous",
				shape, len(byProvider[configuration.ProviderGitLab]), len(byProvider[configuration.ProviderGitHub]))
		}
		for provider, entries := range byProvider {
			for _, e := range entries {
				meta, ok := configuration.ControlMetaFor(e.ControlName)
				if !ok {
					t.Errorf("%s (%s): terminal catalog entry has no registry row", e.ControlName, provider)
					continue
				}
				want := meta.DisplayName
				if exempt, ok := providerFlavouredNames[e.ControlName][provider]; ok {
					want = exempt
				}
				// The variant is the registry name plus the suffix, derived
				// here rather than pasted: a drift in EITHER half fails.
				if strings.HasSuffix(e.DisplayName, pinnedByDigestSuffix) {
					variantsSeen++
					want += pinnedByDigestSuffix
				}
				if e.DisplayName != want {
					t.Errorf("%s (%s, %s): terminal catalog says %q, want %q", e.ControlName, provider, shape, e.DisplayName, want)
				}
			}
		}
	}
	// One per provider on the digest-pinning shape, and none on the other:
	// a catalog that stopped building the variant would otherwise pass the
	// loop above by never entering the branch.
	if variantsSeen != 2 {
		t.Errorf("saw the %q variant %d times, want 2 (one per provider on the digest-pinning shape)", strings.TrimSpace(pinnedByDigestSuffix), variantsSeen)
	}
	for _, g := range mrCommentControlOrder {
		meta, ok := configuration.ControlMetaFor(g.controlName)
		if !ok {
			t.Errorf("%s: MR comment heading has no registry row", g.controlName)
			continue
		}
		if g.heading != meta.DisplayName {
			t.Errorf("%s: MR comment heading says %q, the registry says %q", g.controlName, g.heading, meta.DisplayName)
		}
	}
}
