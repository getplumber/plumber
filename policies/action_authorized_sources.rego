# action-authorized-sources — flag GitHub Actions workflow steps whose
# `uses:` reference comes from a source the project has not authorized.
# Every third-party action runs inside the caller workflow with its
# token and secrets, so an unvetted owner is a direct supply-chain
# entry point. Restricting actions to GitHub-official owners, an
# explicit org allowlist, and an optional minimum-popularity floor
# shrinks that surface to vetted sources. The minimum-stars floor also
# catches the rename/re-creation squat where an attacker re-creates a
# once-trusted repository name (the pattern seen around the
# tj-actions/changed-files compromise, CVE-2025-30066).
#
# Config:
#   input.config.githubActionMustComeFromAuthorizedSources.trustGithubOfficialActions
#     When true, trust actions/* and github/* (first-party GitHub-owned).
#   input.config.githubActionMustComeFromAuthorizedSources.trustSameOrgActions
#     When true (the default), trust actions whose owner is the same
#     org/user as the scanned repository (input.pipeline.projectPath).
#     An org's own actions are already inside its trust boundary.
#   input.config.githubActionMustComeFromAuthorizedSources.trustedGithubActions
#     Allowlist of `owner/repo` (exact) or `owner/*` (whole-org wildcard).
#   input.config.githubActionMustComeFromAuthorizedSources.minimumStars
#     When > 0, trust any action whose upstream repo has >= this many
#     stars. Driven by collect-time API metadata; when the star count is
#     unknown the reference falls back to the allowlist rather than
#     being flagged on missing data.
#
# Local actions (`./…`, `/…`) and docker-image refs (`docker://…`) live
# outside this trust model and are always exempt.
package action_authorized_sources

import rego.v1

# Step-level actions (`jobs.<id>.steps[].uses`).
deny contains finding if {
	input.config.githubActionMustComeFromAuthorizedSources
	some i, j
	job := input.pipeline.jobs[i]
	action := job.uses[j]
	_is_external(action.uses)
	not _authorized(action)
	finding := {
		"code":     "ISSUE-713",
		"severity": "high",
		"message":  sprintf("job %q references action %q from an unauthorized source — restrict actions to authorized owners (actions/*, github/*), an explicit allowlist, or a minimum-stars threshold", [job.name, action.uses]),
		"job":      job.name,
		"uses":     action.uses,
		"line":     object.get(action, "line", 0),
	}
}

# Job-level reusable-workflow calls (`jobs.<id>.uses:
# owner/repo/.github/workflows/x.yml@ref`). These carry no per-action
# API metadata, so only the official-owner and allowlist checks apply.
deny contains finding if {
	input.config.githubActionMustComeFromAuthorizedSources
	some i
	job := input.pipeline.jobs[i]
	use := object.get(job, "reusableWorkflowUses", "")
	use != ""
	_is_external(use)
	not _authorized({"uses": use})
	finding := {
		"code":     "ISSUE-713",
		"severity": "high",
		"message":  sprintf("job %q calls reusable workflow %q from an unauthorized source — restrict to authorized owners (actions/*, github/*) or an explicit allowlist", [job.name, use]),
		"job":      job.name,
		"uses":     use,
	}
}

# An action is authorized when ANY trust condition holds.
_authorized(action) if _is_official(action.uses)

_authorized(action) if _is_same_org(action.uses)

_authorized(action) if _in_allowlist(action.uses)

_authorized(action) if _has_enough_stars(action)

# First-party GitHub-owned actions, when the user trusts them.
_is_official(uses) if {
	input.config.githubActionMustComeFromAuthorizedSources.trustGithubOfficialActions == true
	owner := _owner_of(uses)
	owner in {"actions", "github"}
}

# Same-org actions: trust an action whose owner is the org/user that
# owns the scanned repository. Defaults on — an org's own actions are
# already inside its trust boundary. Owner comparison is case-insensitive
# (GitHub treats org/user names case-insensitively). Abstains when the
# scanned repo's owner is unknown (projectPath empty, e.g. non-GitHub or
# remote detection failed), so it never grants trust on missing data.
_is_same_org(uses) if {
	object.get(input.config.githubActionMustComeFromAuthorizedSources, "trustSameOrgActions", true) == true
	repo_owner := _owner_of(object.get(input.pipeline, "projectPath", ""))
	owner := _owner_of(uses)
	lower(owner) == lower(repo_owner)
}

# Allowlist match. Patterns are matched against `owner/repo` with `/` as
# a glob delimiter, so `owner/*` trusts a whole org and `owner/repo`
# matches exactly. Path-scoped composite refs (`owner/repo/path@ref`)
# collapse to `owner/repo` before matching.
_in_allowlist(uses) if {
	some pattern in input.config.githubActionMustComeFromAuthorizedSources.trustedGithubActions
	glob.match(pattern, ["/"], _owner_repo_of(uses))
}

# Minimum-stars floor. Abstains when the threshold is 0 (disabled) or
# the star count is unknown (metadata absent / repo unreachable).
_has_enough_stars(action) if {
	min := object.get(input.config.githubActionMustComeFromAuthorizedSources, "minimumStars", 0)
	min > 0
	object.get(action.metadata, "stargazersCount", 0) >= min
}

# _is_external is true for refs that point at an external GitHub
# repository — i.e. not a local action and not a docker image, and
# carrying a parseable owner/repo.
_is_external(uses) if {
	not _is_local(uses)
	not startswith(uses, "docker://")
	_owner_repo_of(uses) != ""
}

_is_local(uses) if startswith(uses, "./")

_is_local(uses) if startswith(uses, "/")

# _strip_ref drops the `@ref` suffix, leaving `owner/repo[/path]`.
_strip_ref(uses) := head if {
	idx := indexof(uses, "@")
	idx >= 0
	head := substring(uses, 0, idx)
} else := uses

# _owner_of returns the first path segment ("" when unparseable).
_owner_of(uses) := parts[0] if {
	parts := split(_strip_ref(uses), "/")
	count(parts) >= 1
	parts[0] != ""
}

# _owner_repo_of returns "owner/repo" ("" when unparseable).
_owner_repo_of(uses) := sprintf("%s/%s", [parts[0], parts[1]]) if {
	parts := split(_strip_ref(uses), "/")
	count(parts) >= 2
	parts[0] != ""
	parts[1] != ""
} else := ""
