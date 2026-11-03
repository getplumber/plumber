package gitlab

import (
	"errors"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	glab "gitlab.com/gitlab-org/api/client-go"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/internal/ir"
)

// maxTagListingPages caps the tag listing at 10 pages × 100 entries, most
// recently updated first. A project with more tags than that is reported
// with TagsTruncated, which can only hide a finding, never invent one.
const maxTagListingPages = 10

// errProtectedTagsTruncated: the protected tags outran maxTagListingPages.
// One past the cap could be the protection a pattern relies on, so the
// collection is unknown rather than partial.
var errProtectedTagsTruncated = errors.New("protected tags listing truncated")

// TagProtection is one GitLab protected tag (Settings > Repository >
// Protected tags): an exact name or a `*` wildcard, and who may create
// matching tags.
type TagProtection struct {
	Name               string                        `json:"name"`
	CreateAccessLevels []BranchProtectionAccessLevel `json:"createAccessLevels"`
}

// GitlabTagProtectionData is what tagMustBeProtected reads on GitLab: the
// protected tags and the existing tag names. Known is false when either
// listing could not be read, so the control reports not evaluated rather
// than read an unreadable listing as "nothing is protected".
type GitlabTagProtectionData struct {
	Known         bool            `json:"known"`
	Tags          []string        `json:"tags"`
	TagsTruncated bool            `json:"tagsTruncated"`
	Protections   []TagProtection `json:"protections"`
}

// CollectGitlabTagProtection reads the project's protected tags and its
// tag names. On any failure it returns Known=false alongside the error;
// the caller decides whether the error degrades the run (network) or only
// leaves the control not evaluated (a 401/403 on a token without scope).
func CollectGitlabTagProtection(projectPath, token string, conf *configuration.Configuration) (*GitlabTagProtectionData, error) {
	tags, truncated, protections, err := FetchProjectTagProtectionData(projectPath, token, conf.GitlabURL, conf)
	if err != nil {
		return &GitlabTagProtectionData{Known: false}, err
	}
	return &GitlabTagProtectionData{Known: true, Tags: tags, TagsTruncated: truncated, Protections: protections}, nil
}

// FetchProjectTagProtectionData fetches the protected tags and the tag
// names, both capped at maxTagListingPages; protected tags past the cap
// are an error, tags past it set truncated. A failed read returns
// an error, never an empty list: "no protected tags" is the exact
// violation tagMustBeProtected reports, so a read that failed must not
// arrive looking like one.
func FetchProjectTagProtectionData(projectPath, token, apiURL string, conf *configuration.Configuration) (tags []string, truncated bool, protections []TagProtection, err error) {
	l := logger.WithFields(logrus.Fields{
		"action":      "FetchProjectTagProtectionData",
		"projectPath": projectPath,
		"apiURL":      apiURL,
	})

	client, err := GetNewGitlabClient(token, apiURL, conf)
	if err != nil {
		l.WithError(err).Error("Unable to get a Gitlab client")
		return nil, false, nil, err
	}

	var perPage int64 = 100
	protOptions := &glab.ListProtectedTagsOptions{ListOptions: glab.ListOptions{PerPage: perPage}}
	for page := int64(1); ; page++ {
		if page > maxTagListingPages {
			l.Warnf("Protected tags exceed %d pages; the tag protection is unknown", maxTagListingPages)
			return nil, false, nil, fmt.Errorf("%w at %d pages", errProtectedTagsTruncated, maxTagListingPages)
		}
		protOptions.Page = page
		batch, _, err := client.ProtectedTags.ListProtectedTags(projectPath, protOptions)
		if err != nil {
			l.WithError(err).Warn("Failed to fetch protected tags; the tag protection is unknown, not empty")
			return nil, false, nil, err
		}
		for _, p := range batch {
			protections = append(protections, toTagProtection(p))
		}
		if int64(len(batch)) < perPage {
			break
		}
	}

	orderBy := "updated"
	sort := "desc"
	tagOptions := &glab.ListTagsOptions{ListOptions: glab.ListOptions{PerPage: perPage}, OrderBy: &orderBy, Sort: &sort}
	for page := int64(1); page <= maxTagListingPages; page++ {
		tagOptions.Page = page
		batch, _, err := client.Tags.ListTags(projectPath, tagOptions)
		if err != nil {
			l.WithError(err).Warn("Failed to fetch tags; the tag protection is unknown")
			return nil, false, nil, err
		}
		for _, t := range batch {
			tags = append(tags, t.Name)
		}
		if int64(len(batch)) < perPage {
			return tags, false, protections, nil
		}
	}
	l.Warnf("Tag listing capped at %d pages; older tags were not checked", maxTagListingPages)
	return tags, true, protections, nil
}

func toTagProtection(p *glab.ProtectedTag) TagProtection {
	tp := TagProtection{Name: p.Name}
	for _, a := range p.CreateAccessLevels {
		if a == nil {
			continue
		}
		if a.UserID != 0 || a.GroupID != 0 || a.DeployKeyID != 0 {
			// A user, group or deploy key entry: no role is let in.
			continue
		}
		tp.CreateAccessLevels = append(tp.CreateAccessLevels, BranchProtectionAccessLevel{
			AccessLevel:            int(a.AccessLevel),
			AccessLevelDescription: a.AccessLevelDescription,
		})
	}
	return tp
}

// maintainerAccessLevel is GitLab's Maintainer role. A create access
// level below it (Developer, Reporter, Guest) leaves tag creation open to
// people who cannot otherwise change protected settings; 0 is "No one".
const maintainerAccessLevel = 40

// BuildTagProtection maps the GitLab collection onto the provider-neutral
// IR. nil in, nil out: the collection did not run and the rule abstains.
//
// A protected tag cannot be updated or deleted by a push, so every one
// blocks both. Creation counts as restricted unless some role entry lets
// Developers (or below) create; no entry at all is GitLab's default,
// Maintainers.
func BuildTagProtection(d *GitlabTagProtectionData) *ir.TagProtection {
	if d == nil {
		return nil
	}
	out := &ir.TagProtection{Known: d.Known, Tags: d.Tags, TagsTruncated: d.TagsTruncated}
	if !d.Known {
		return out
	}
	for _, p := range d.Protections {
		restricted := true
		for _, a := range p.CreateAccessLevels {
			if a.AccessLevel > 0 && a.AccessLevel < maintainerAccessLevel {
				restricted = false
			}
		}
		out.Rules = append(out.Rules, ir.TagProtectionRule{
			ID:                p.Name,
			Name:              p.Name,
			Source:            ir.TagRuleSourceProtectedTag,
			Include:           []string{gitlabWildcardToGlob(p.Name)},
			BlocksUpdate:      true,
			BlocksDeletion:    true,
			RestrictsCreation: restricted,
		})
	}
	return out
}

// gitlabWildcardToGlob turns a GitLab protected tag name into the shared
// glob dialect. GitLab's only wildcard is `*`, and it matches across
// slashes, so it becomes `**`; every other glob metacharacter is literal
// on GitLab and is escaped.
func gitlabWildcardToGlob(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch r {
		case '*':
			b.WriteString("**")
		case '\\', '?', '[', ']', '{', '}':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
