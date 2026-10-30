package github

import (
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/cli/go-gh/v2/pkg/api"

	"github.com/getplumber/plumber/internal/ir"
)

// maxTagListingPages caps the /tags pagination: 10 pages × 100 entries.
// A repository with more tags than that is reported with TagsTruncated,
// which can only hide a finding (a matching tag not seen), never invent
// one.
const maxTagListingPages = 10

// remoteRulesetSummary is one entry of the rulesets listing. The listing
// carries no conditions and no rules; those need the per-ruleset call.
type remoteRulesetSummary struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Target      string `json:"target"`
	SourceType  string `json:"source_type"`
	Enforcement string `json:"enforcement"`
}

// remoteRuleset is a ruleset as GET /repos/{o}/{r}/rulesets/{id} returns
// it, reduced to what tagMustBeProtected reads. bypass_actors is
// deliberately absent: it needs admin rights, and the control does not
// depend on it.
type remoteRuleset struct {
	remoteRulesetSummary
	Conditions struct {
		RefName        *remoteIncludeExclude `json:"ref_name"`
		RepositoryName *remoteIncludeExclude `json:"repository_name"`
	} `json:"conditions"`
	Rules []struct {
		Type string `json:"type"`
	} `json:"rules"`
}

type remoteIncludeExclude struct {
	Include []string `json:"include"`
	Exclude []string `json:"exclude"`
}

type remoteTag struct {
	Name string `json:"name"`
}

// FetchGitHubTagProtection reads the repository's active tag rulesets
// (its own and those inherited from the organization or enterprise) and
// its existing tag names, for tagMustBeProtected (ISSUE-510).
//
// The legacy tag protection API is not used: GitHub retired it in 2024
// and migrated its rules to rulesets.
//
// Error contract, the same as the branch protection collector:
//   - no auth, or a 401/403/404 on any call (missing scope, a GHES
//     version without rulesets, an invisible repo): Known=false and a nil
//     error, so the control reports "not evaluated" without degrading the
//     run, and never a finding built on missing data.
//   - any other failure (network, 5xx, rate limit): Known=false and the
//     error, so the caller marks the run degraded.
func FetchGitHubTagProtection(host, owner, repo string) (*ir.TagProtection, error) {
	if owner == "" || repo == "" {
		return nil, fmt.Errorf("owner and repo are required")
	}
	unknown := &ir.TagProtection{Known: false}
	rest, err := newGitHubRESTClient(host)
	if err != nil {
		if errors.Is(err, ErrAuthRequired) {
			return unknown, nil
		}
		return unknown, fmt.Errorf("github api client: %w", err)
	}

	summaries, ok, err := listTagRulesets(rest, owner, repo)
	if err != nil || !ok {
		return unknown, err
	}
	out := &ir.TagProtection{}
	for _, s := range summaries {
		if s.Enforcement != "active" {
			// "evaluate" only reports and "disabled" does nothing: neither
			// stops a tag from moving.
			continue
		}
		rs, ok, err := fetchRuleset(rest, owner, repo, s.ID)
		if err != nil || !ok {
			return unknown, err
		}
		if !rulesetAppliesToRepo(rs, repo) {
			continue
		}
		out.Rules = append(out.Rules, rulesetToTagRule(rs))
	}

	tags, truncated, ok, err := listTagNames(rest, owner, repo)
	if err != nil || !ok {
		return unknown, err
	}
	out.Tags = tags
	out.TagsTruncated = truncated
	out.Known = true
	return out, nil
}

// listTagRulesets pages GET /repos/{o}/{r}/rulesets for tag rulesets,
// parents included. Returns (nil, false, nil) on 401/403/404, and when the
// listing outruns maxBranchListingPages: a ruleset past the cap could be
// the one protecting a pattern.
func listTagRulesets(rest *api.RESTClient, owner, repo string) ([]remoteRulesetSummary, bool, error) {
	const perPage = 100
	var out []remoteRulesetSummary
	for page := 1; page <= maxBranchListingPages; page++ {
		endpoint := fmt.Sprintf("repos/%s/%s/rulesets?includes_parents=true&targets=tag&per_page=%d&page=%d", owner, repo, perPage, page)
		var batch []remoteRulesetSummary
		if err := rest.Get(endpoint, &batch); err != nil {
			if isUnauthorized(err) || isNotFound(err) {
				return nil, false, nil
			}
			return nil, false, fmt.Errorf("tag rulesets: %w", err)
		}
		for _, s := range batch {
			// Older GHES versions ignore the targets filter.
			if s.Target == "tag" {
				out = append(out, s)
			}
		}
		if len(batch) < perPage {
			return out, true, nil
		}
	}
	return nil, false, nil
}

// fetchRuleset reads one ruleset's conditions and rules. Returns
// (nil, false, nil) on 401/403/404.
func fetchRuleset(rest *api.RESTClient, owner, repo string, id int64) (*remoteRuleset, bool, error) {
	endpoint := fmt.Sprintf("repos/%s/%s/rulesets/%d?includes_parents=true", owner, repo, id)
	var rs remoteRuleset
	if err := rest.Get(endpoint, &rs); err != nil {
		if isUnauthorized(err) || isNotFound(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("ruleset %d: %w", id, err)
	}
	return &rs, true, nil
}

// listTagNames pages GET /repos/{o}/{r}/tags, capped at
// maxTagListingPages. Returns ok=false on 401/403/404.
func listTagNames(rest *api.RESTClient, owner, repo string) (names []string, truncated, ok bool, err error) {
	const perPage = 100
	for page := 1; page <= maxTagListingPages; page++ {
		endpoint := fmt.Sprintf("repos/%s/%s/tags?per_page=%d&page=%d", owner, repo, perPage, page)
		var batch []remoteTag
		if err := rest.Get(endpoint, &batch); err != nil {
			if isUnauthorized(err) || isNotFound(err) {
				return nil, false, false, nil
			}
			return nil, false, false, fmt.Errorf("tags: %w", err)
		}
		for _, t := range batch {
			names = append(names, t.Name)
		}
		if len(batch) < perPage {
			return names, false, true, nil
		}
	}
	return names, true, true, nil
}

// rulesetAppliesToRepo honours an organization ruleset's repository_name
// condition. Rulesets targeting repositories by id or by custom property
// are trusted as returned: GitHub only lists a parent ruleset for a
// repository it applies to, and getting this wrong could only hide a
// finding.
func rulesetAppliesToRepo(rs *remoteRuleset, repo string) bool {
	c := rs.Conditions.RepositoryName
	if c == nil {
		return true
	}
	if len(c.Include) > 0 && !anyRepoPatternMatches(c.Include, repo) {
		return false
	}
	return !anyRepoPatternMatches(c.Exclude, repo)
}

func anyRepoPatternMatches(patterns []string, repo string) bool {
	for _, p := range patterns {
		if p == "~ALL" {
			return true
		}
		if ok, err := path.Match(p, repo); err == nil && ok {
			return true
		}
	}
	return false
}

// rulesetToTagRule maps a tag ruleset onto the provider-neutral rule
// tagMustBeProtected reads.
func rulesetToTagRule(rs *remoteRuleset) ir.TagProtectionRule {
	rule := ir.TagProtectionRule{
		ID:     strconv.FormatInt(rs.ID, 10),
		Name:   rs.Name,
		Source: rulesetSource(rs.SourceType),
	}
	if c := rs.Conditions.RefName; c != nil {
		for _, p := range c.Include {
			rule.Include = append(rule.Include, normalizeGitHubTagPattern(p))
		}
		for _, p := range c.Exclude {
			rule.Exclude = append(rule.Exclude, normalizeGitHubTagPattern(p))
		}
	}
	for _, r := range rs.Rules {
		switch r.Type {
		case "update":
			rule.BlocksUpdate = true
		case "deletion":
			rule.BlocksDeletion = true
		case "creation":
			rule.RestrictsCreation = true
		}
	}
	return rule
}

func rulesetSource(sourceType string) string {
	switch sourceType {
	case "Organization":
		return ir.TagRuleSourceOrganizationRuleset
	case "Enterprise":
		return ir.TagRuleSourceEnterpriseRuleset
	default:
		return ir.TagRuleSourceRepositoryRuleset
	}
}

// normalizeGitHubTagPattern turns a ruleset ref_name pattern into the
// shared glob dialect: refs/tags/ stripped, ~ALL as "**". GitHub's fnmatch
// already stops `*` at a slash, as the dialect does.
func normalizeGitHubTagPattern(p string) string {
	if p == "~ALL" {
		return "**"
	}
	return strings.TrimPrefix(p, "refs/tags/")
}
