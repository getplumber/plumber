package gitlab

import (
	"context"
	"strconv"
	"strings"

	"github.com/getplumber/plumber/configuration"
	"github.com/machinebox/graphql"
	"github.com/sirupsen/logrus"
)

// SecurityPolicyProjectLink is the GitLab security policy project linked to the
// analysed project. GitLab Ultimate: a project points at a single security
// policy project that carries the org's scan-execution and merge-request
// approval policies.
type SecurityPolicyProjectLink struct {
	// ID is the numeric project ID of the linked security policy project.
	ID int
	// FullPath is its namespace/path.
	FullPath string
}

// GetSecurityPolicyProject fetches the project's linked security policy project
// via GraphQL. It returns:
//   - (link, true, nil)  on a successful read where a policy project is linked;
//   - (nil, true, nil)   on a successful read where NONE is linked (the
//     GitLab-Free/Ultimate-but-unlinked case — the field answers null);
//   - (nil, false, err)  when the linkage could not be read authoritatively (an
//     auth error, or the field is unavailable on the instance). The bool is the
//     "known" flag: a false known maps to not-evaluable, never a false pass.
//
// Security policies require GitLab Ultimate. On a non-Ultimate project the field
// answers null (no linkage), which is indistinguishable from an Ultimate project
// that simply has not linked one — the caller surfaces a conditional tier caveat
// rather than asserting the tier.
func GetSecurityPolicyProject(fullPath, token, instanceUrl string, conf *configuration.Configuration) (*SecurityPolicyProjectLink, bool, error) {
	l := logrus.WithFields(logrus.Fields{
		"platform":        "gitlab",
		"action":          "GetSecurityPolicyProject",
		"projectFullPath": fullPath,
		"instanceUrl":     instanceUrl,
	})

	request := `
		query getSecurityPolicyProject($fullPath: ID!) {
			project(fullPath: $fullPath) {
				securityPolicyProject {
					id
					fullPath
				}
			}
		}
	`

	type policyProject struct {
		ID       string `json:"id"`
		FullPath string `json:"fullPath"`
	}
	type response struct {
		Project *struct {
			SecurityPolicyProject *policyProject `json:"securityPolicyProject"`
		} `json:"project"`
	}

	client := GetGraphQLClient(instanceUrl, conf)
	req := graphql.NewRequest(request)
	req.Var("fullPath", fullPath)
	req.Header.Add("Authorization", "Bearer "+token)

	var respData response
	if err := client.Run(context.Background(), req, &respData); err != nil {
		// The field is absent from this instance's schema (old or unlicensed
		// self-managed): treat as not-evaluable rather than a failure, matching
		// the platform's "continue without security policy data" handling.
		if strings.Contains(err.Error(), "securityPolicyProject") && strings.Contains(err.Error(), "doesn't exist") {
			l.WithError(err).Warning("securityPolicyProject field unavailable on this GitLab instance; reporting not-evaluable")
			return nil, false, nil
		}
		l.WithError(err).Error("Failed to read the security policy project through the GitLab GraphQL API")
		return nil, false, err
	}

	if respData.Project == nil {
		// A null `project` on HTTP 200 is GitLab's signature for "this token
		// cannot see the project through GraphQL" — the GraphQL API answers
		// with a null node rather than the 403 the REST API would return. It
		// is NOT an authoritative "nothing linked": reporting it as one fires
		// a Critical ISSUE-601 on a project whose linkage was never read.
		l.Warning("GraphQL returned a null project (token cannot read it); reporting not-evaluable")
		return nil, false, nil
	}
	if respData.Project.SecurityPolicyProject == nil {
		return nil, true, nil // the project WAS read; nothing is linked
	}
	p := respData.Project.SecurityPolicyProject
	return &SecurityPolicyProjectLink{ID: parseGitlabGID(p.ID), FullPath: p.FullPath}, true, nil
}

// parseGitlabGID extracts the trailing numeric id from a GitLab GraphQL global
// id such as "gid://gitlab/Project/12345". Returns 0 when the tail is not a
// number (an unexpected id shape), so a malformed id never matches a configured
// expectedProjectId by accident.
func parseGitlabGID(gid string) int {
	idx := strings.LastIndex(gid, "/")
	if idx < 0 || idx+1 >= len(gid) {
		return 0
	}
	n, err := strconv.Atoi(gid[idx+1:])
	if err != nil {
		return 0
	}
	return n
}

// SecurityPolicyData is the collected security-policy-project linkage for a
// run. It is deliberately its own collection rather than a field on
// GitlabProtectionAnalysisData: the linkage is read over GraphQL, a separate
// API surface from the REST protection endpoints, and folding it in made
// ISSUE-601 hostage to them. A token that cannot list branches aborts the
// protection collection before the GraphQL read is ever reached, which left
// the control reporting not-evaluable forever on a linkage it could have read
// perfectly well.
type SecurityPolicyData struct {
	// Known is true when the linkage was read authoritatively. A nil Project
	// then means "none linked", a real state the rule fires on. False means
	// the read failed (auth error, null project, or the field is unavailable
	// on this instance), so ISSUE-601 reports not-evaluable, not a false pass.
	Known bool
	// Project is the linked security policy project, or nil when none is
	// linked. Only meaningful when Known is true.
	Project *SecurityPolicyProjectLink
}

// CollectSecurityPolicy reads the project's security-policy-project linkage.
// The returned error is the transport/API failure, if any: the caller decides
// whether it degrades the run (a network blip should not read as a clean pass)
// while the returned data already carries Known=false so the control reports
// not-evaluable either way.
func CollectSecurityPolicy(fullPath, token, instanceUrl string, conf *configuration.Configuration) (*SecurityPolicyData, error) {
	link, known, err := GetSecurityPolicyProject(fullPath, token, instanceUrl, conf)
	return &SecurityPolicyData{Known: known, Project: link}, err
}
