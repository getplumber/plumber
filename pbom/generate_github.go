package pbom

import (
	"sort"
	"strings"
	"time"

	"github.com/getplumber/plumber/internal/ir"
)

// GitHubComplianceData carries the GitHub-side compliance lookups
// the PBOM enriches container images and actions with. Mirrors
// ImageComplianceData on the GitLab side; kept separate because the
// keys (action ref vs include path) and providers differ.
type GitHubComplianceData struct {
	// ForbiddenTagImages keys on the full image reference
	// (`docker.io/golang:1.22`).
	ForbiddenTagImages map[string]bool
	// ImagesPinnedByDigest keys on the full image reference; true
	// when the image carries an `@sha256:…` suffix.
	ImagesPinnedByDigest map[string]bool
	// UnpinnedActions keys on the full action ref (`actions/checkout@v4`);
	// true when the ref is not a 40-char SHA.
	UnpinnedActions map[string]bool
	// ArchivedActions keys on the full action ref; true when the
	// upstream repository is archived (ISSUE-702). Sourced from the
	// per-action GitHub API metadata enrichment.
	ArchivedActions map[string]bool
	// VulnerableActions keys on the full action ref; true when the
	// upstream repository has at least one published GitHub Advisory
	// (ISSUE-703). Same metadata enrichment path as ArchivedActions.
	VulnerableActions map[string]bool
	// ActionAdvisories keys on the full action ref, value is the
	// list of GHSA IDs published against the action's repository.
	// Populated alongside VulnerableActions and surfaced into the
	// Include / CDX layer so consumers see which advisories triggered
	// the finding.
	ActionAdvisories map[string][]string
}

// NewGitHubGenerator creates a PBOM generator pre-configured for the
// GitHub provider. URL is the GitHub host (`github.com` or a GHES
// host); branch is informational, used to stamp the project section.
func NewGitHubGenerator(projectPath, url, branch string) *Generator {
	return &Generator{
		projectPath: projectPath,
		gitlabURL:   url, // reused as the generic provider URL
		branch:      branch,
	}
}

// WithGitHubComplianceData attaches per-image and per-action
// compliance lookups so the resulting PBOM marks each image with its
// authorized/forbiddenTag flags and each action with a custom property
// for unpinned status.
func (g *Generator) WithGitHubComplianceData(data *GitHubComplianceData) *Generator {
	if data != nil {
		g.complianceData = &ImageComplianceData{
			ForbiddenTagImages: data.ForbiddenTagImages,
		}
	}
	g.githubData = data
	return g
}

// GenerateFromGitHubIR builds a PBOM from the normalized GitHub
// pipeline IR. Container images are extracted from each job's
// `image:` and `services:` blocks; the GitHub analogue of GitLab's
// "include" list is the merged set of third-party action references
// (`uses: owner/repo@ref`) and reusable-workflow calls
// (`jobs.<name>.uses: …/.github/workflows/x.yml@ref`).
func (g *Generator) GenerateFromGitHubIR(pipeline *ir.NormalizedPipeline) *PBOM {
	pbom := &PBOM{
		PBOMVersion: Version,
		GeneratedAt: time.Now().UTC(),
		Project: ProjectInfo{
			Path:     g.projectPath,
			Provider: "github",
			URL:      g.gitlabURL,
			Branch:   g.branch,
		},
		ContainerImages: make([]ContainerImage, 0),
		Includes:        make([]Include, 0),
	}
	if pipeline != nil {
		pbom.ContainerImages = g.processGitHubImages(pipeline)
		pbom.Includes = g.processGitHubIncludes(pipeline)
	}
	pbom.Summary = g.calculateSummary(pbom)
	return pbom
}

// processGitHubImages walks every job's image and services list,
// dedupes by full image reference, aggregates the jobs that use each
// image, and produces the ContainerImage shape consumers expect.
// Mirrors processImages on the GitLab path so downstream tooling
// reads the same fields regardless of which provider produced the
// PBOM.
func (g *Generator) processGitHubImages(pipeline *ir.NormalizedPipeline) []ContainerImage {
	type entry struct {
		ref      string
		registry string
		name     string
		tag      string
	}
	jobsByRef := map[string][]string{}
	infoByRef := map[string]entry{}

	addImage := func(img ir.Image, jobName string) {
		ref := normalizeImageRef(img)
		if ref == "" {
			return
		}
		jobsByRef[ref] = append(jobsByRef[ref], jobName)
		if _, ok := infoByRef[ref]; !ok {
			tag := img.Tag
			if img.Digest != "" {
				tag = img.Digest
			}
			infoByRef[ref] = entry{
				ref:      ref,
				registry: img.Registry,
				name:     img.Name,
				tag:      tag,
			}
		}
	}

	for i := range pipeline.Jobs {
		j := &pipeline.Jobs[i]
		if j.Image != nil {
			addImage(*j.Image, j.Name)
		}
		for _, s := range j.Services {
			addImage(s, j.Name)
		}
	}

	refs := make([]string, 0, len(jobsByRef))
	for r := range jobsByRef {
		refs = append(refs, r)
	}
	sort.Strings(refs)

	out := make([]ContainerImage, 0, len(refs))
	for _, r := range refs {
		info := infoByRef[r]
		img := ContainerImage{
			Image:    r,
			Registry: info.registry,
			Name:     info.name,
			Tag:      info.tag,
			Jobs:     uniqueSortedStrings(jobsByRef[r]),
		}
		if g.githubData != nil {
			if v, ok := g.githubData.ForbiddenTagImages[r]; ok {
				img.ForbiddenTag = &v
			}
		}
		out = append(out, img)
	}
	return out
}

// processGitHubIncludes builds the include list from third-party
// action references and reusable-workflow calls. Each unique `uses:`
// becomes one Include entry. Trusted-owner exemption (actions/*,
// github/*, …) is left out of this layer — the PBOM is a complete
// inventory; compliance interpretation lives on top via the
// ForbiddenTag / UnpinnedActions enrichment hooks.
func (g *Generator) processGitHubIncludes(pipeline *ir.NormalizedPipeline) []Include {
	type actionEntry struct {
		ref     string
		comment string
	}
	actions := map[string]actionEntry{}
	reusables := map[string]struct{}{}

	for i := range pipeline.Jobs {
		j := &pipeline.Jobs[i]
		if j.ReusableWorkflowUses != "" {
			reusables[j.ReusableWorkflowUses] = struct{}{}
		}
		for _, u := range j.Uses {
			if u.Uses == "" {
				continue
			}
			if _, ok := actions[u.Uses]; !ok {
				actions[u.Uses] = actionEntry{ref: u.Uses, comment: u.Comment}
			}
		}
	}

	out := make([]Include, 0, len(actions)+len(reusables))

	actionRefs := make([]string, 0, len(actions))
	for r := range actions {
		actionRefs = append(actionRefs, r)
	}
	sort.Strings(actionRefs)
	for _, r := range actionRefs {
		owner, repo, ref := splitActionRef(r)
		inc := Include{
			Type:     "action",
			Location: owner + "/" + repo,
			Project:  owner,
			Version:  ref,
		}
		if g.githubData != nil {
			if unpinned, ok := g.githubData.UnpinnedActions[r]; ok {
				// Re-use UpToDate as a tri-state pinning indicator on
				// the action variant: nil = unknown, false = not
				// pinned by SHA. The CycloneDX layer maps it back to a
				// dedicated property below.
				notPinned := !unpinned
				inc.UpToDate = &notPinned
			}
			if archived, ok := g.githubData.ArchivedActions[r]; ok {
				v := archived
				inc.Archived = &v
			}
			if vuln, ok := g.githubData.VulnerableActions[r]; ok {
				v := vuln
				inc.HasCVE = &v
			}
			if adv, ok := g.githubData.ActionAdvisories[r]; ok && len(adv) > 0 {
				inc.Advisories = append([]string(nil), adv...)
			}
		}
		// Comment from the workflow file ("@abc123 # v4.1.0") is the
		// human-readable version annotation. Stash it as the latest
		// version field so consumers see "advertised version" alongside
		// the SHA.
		if c := strings.TrimSpace(actions[r].comment); c != "" {
			inc.LatestVersion = c
		}
		out = append(out, inc)
	}

	reusableRefs := make([]string, 0, len(reusables))
	for r := range reusables {
		reusableRefs = append(reusableRefs, r)
	}
	sort.Strings(reusableRefs)
	for _, r := range reusableRefs {
		// Format: owner/repo/.github/workflows/x.yml@ref
		base, ref := r, ""
		if at := strings.LastIndex(r, "@"); at > 0 {
			base = r[:at]
			ref = r[at+1:]
		}
		inc := Include{
			Type:     "reusableWorkflow",
			Location: base,
			Version:  ref,
		}
		out = append(out, inc)
	}
	return out
}

// normalizeImageRef builds the canonical "registry/name:tag" or
// "registry/name@digest" form so dedup + display are stable. Empty
// when the IR Image has no usable name.
func normalizeImageRef(img ir.Image) string {
	if img.Name == "" {
		return ""
	}
	ref := img.Name
	if img.Registry != "" && !strings.Contains(ref, "/") {
		ref = img.Registry + "/" + ref
	} else if img.Registry != "" && !strings.HasPrefix(ref, img.Registry+"/") {
		ref = img.Registry + "/" + ref
	}
	if img.Digest != "" {
		ref += "@" + img.Digest
		return ref
	}
	if img.Tag != "" {
		ref += ":" + img.Tag
	}
	return ref
}

// splitActionRef splits "owner/repo@ref" (or "owner/repo/path@ref")
// into its three pieces. Trailing comment after a "#" was already
// stripped by the collector — kept here as a defensive guard.
func splitActionRef(s string) (owner, repo, ref string) {
	rest := s
	if at := strings.LastIndex(rest, "@"); at > 0 {
		ref = rest[at+1:]
		rest = rest[:at]
	}
	if i := strings.IndexByte(rest, '/'); i > 0 {
		owner = rest[:i]
		repo = rest[i+1:]
	}
	return
}
