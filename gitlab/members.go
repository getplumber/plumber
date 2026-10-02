package gitlab

import (
	"net/http"
	"regexp"

	"github.com/getplumber/plumber/configuration"
	"github.com/sirupsen/logrus"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// maxMemberPages bounds the members listing at 20 pages of 100. Past it the
// count is UNKNOWN rather than truncated: a project with more than 2000
// effective members is a group-scale question, and an honest abstention
// beats a wrong number the quota rule would then judge (spec 4.3).
const maxMemberPages = 20

// accessTokenBotUsername matches the username GitLab gives every project and
// group access-token bot user: the modern project_<id>_bot_<random> /
// group_<id>_bot_<random> form (GitLab 14.0+), and the legacy pre-14.0 forms
// that survive an upgrade unchanged, project_<id>_bot / project_<id>_bot1 /
// project_<id>_bot2 / ... and the group_ equivalents. The members payload
// carries no bot flag, so the username shape is the rule; it is anchored so
// a human whose name merely contains _bot_ (or is a suffix like "bottle")
// is still counted.
var accessTokenBotUsername = regexp.MustCompile(`^(project|group)_[0-9]+_bot([0-9]*|_[A-Za-z0-9]+)$`)

// MemberCounts are a project's member counts per role. Total counts every
// non-bot member at any level; the named roles count exactly that level.
type MemberCounts struct {
	Owners      int
	Maintainers int
	Developers  int
	Total       int
}

// GitlabMembersAnalysisData is the members collection the
// numberOfProjectMembersMustRespectQuota control reads.
//
// Known is true when the listing was read authoritatively; a zero count
// then means "nobody holds that role", a real state the rule fires on.
// False means the listing could not be read (403/404, the page cap, a
// transport failure) and the control reports not-evaluable, never a verdict.
type GitlabMembersAnalysisData struct {
	Counts MemberCounts
	Known  bool
}

// FetchProjectMemberCounts tallies GET /projects/:id/members/all: everyone
// with effective access (direct, inherited from ancestor groups, invited
// groups), each user once at their highest level, bots excluded. The second
// return is Known; the third is the HTTP status of a failed request (0 when
// there was no response) so the caller can tell a 403/404 from a hard
// failure. A listing longer than maxMemberPages returns Known=false and no
// error.
func FetchProjectMemberCounts(projectID int, token string, apiURL string, conf *configuration.Configuration) (MemberCounts, bool, int, error) {
	l := logger.WithFields(logrus.Fields{
		"action":    "FetchProjectMemberCounts",
		"projectID": projectID,
		"apiURL":    apiURL,
	})

	glab, err := GetNewGitlabClient(token, apiURL, conf)
	if err != nil {
		l.WithError(err).Error("Unable to get a Gitlab client")
		return MemberCounts{}, false, 0, err
	}

	var counts MemberCounts
	options := &gitlab.ListProjectMembersOptions{
		ListOptions: gitlab.ListOptions{PerPage: 100},
	}
	for page := int64(1); ; page++ {
		if page > maxMemberPages {
			l.WithField("pages", maxMemberPages).Warn("Project has more members than the listing cap; the member counts are reported as unknown")
			return MemberCounts{}, false, http.StatusOK, nil
		}
		options.Page = page
		members, resp, err := glab.ProjectMembers.ListAllProjectMembers(projectID, options)
		if err != nil {
			status := 0
			if resp != nil {
				status = resp.StatusCode
			}
			l.WithError(err).Warn("Failed to fetch project members")
			return MemberCounts{}, false, status, err
		}
		for _, m := range members {
			if accessTokenBotUsername.MatchString(m.Username) {
				continue
			}
			counts.Total++
			switch m.AccessLevel {
			case gitlab.OwnerPermissions:
				counts.Owners++
			case gitlab.MaintainerPermissions:
				counts.Maintainers++
			case gitlab.DeveloperPermissions:
				counts.Developers++
			}
		}
		if resp == nil || resp.NextPage == 0 {
			break
		}
	}

	l.WithFields(logrus.Fields{"owners": counts.Owners, "maintainers": counts.Maintainers, "developers": counts.Developers, "total": counts.Total}).Debug("Fetched project member counts")
	return counts, true, http.StatusOK, nil
}

// CollectProjectMembers reads the member counts for the run. A 403/404 is a
// permission fact: the counts stay unknown and no error is returned, so the
// control reports not-evaluable without degrading a complete run. Any other
// error is returned for the caller to classify (a network failure degrades
// the run, exit code 3).
func CollectProjectMembers(project *ProjectInfo, token string, conf *configuration.Configuration) (*GitlabMembersAnalysisData, error) {
	counts, known, status, err := FetchProjectMemberCounts(project.ID, token, conf.GitlabURL, conf)
	if err != nil {
		// isPremiumFeatureUnavailable is reused for its 403/404 classification only: members are not a premium feature.
		if isPremiumFeatureUnavailable(status) {
			logger.WithField("project", project.Path).Warn("Project members not readable with this token; the member quota control will report not-evaluable")
			return &GitlabMembersAnalysisData{}, nil
		}
		return &GitlabMembersAnalysisData{}, err
	}
	return &GitlabMembersAnalysisData{Counts: counts, Known: known}, nil
}
