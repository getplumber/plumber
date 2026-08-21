# security-policy-project — flag a GitLab project that does not link the
# expected security policy project (Settings > Security & Compliance >
# Policies). A linked security policy project carries the organization's
# scan-execution and merge-request approval policies; without it (or with the
# wrong one linked) those policies are not enforced on the project. GitLab-only
# singleton finding (one per project); the legacy platform's identity was empty,
# so the identity here is the code alone.
#
# Config projectMustHaveSecurityPolicySource, matched with this precedence:
#   - expectedProjectId set   => the linked project's numeric id must equal it
#     exactly (authoritative; the front end always sends the id);
#   - else expectedProjectPath set => the linked project's full path must equal
#     it, compared case-insensitively (a human-friendly alternative);
#   - else (neither set)      => any linked policy project passes, and the
#     control fails only when none is linked.
#
# Reads input.pipeline.securityPolicyProject, projected from the protection
# collection (gitlab/gitlab_ir.go::buildSecurityPolicyProject). The projection
# is absent when the control did not collect it, and carries known=false when
# the linkage could not be read (a 401/403, or the field is unavailable on the
# instance); the rule abstains in both cases, so the control reports
# not-evaluable, not a pass.
#
# Security policies require GitLab Ultimate. On a non-Ultimate project the
# linkage reads as none, which is indistinguishable from an Ultimate project
# that has not linked one — the Go layer surfaces a conditional Ultimate tier
# caveat next to this finding rather than the rule asserting the tier.
package security_policy_project

import rego.v1

deny contains finding if {
	input.pipeline.provider == "gitlab"
	sp := input.pipeline.securityPolicyProject
	sp.known == true
	cfg := object.get(input.config, "projectMustHaveSecurityPolicySource", {})
	finding := {
		"code": "ISSUE-601",
		"severity": "critical",
		"message": _violation(sp, cfg),
		"linkedProjectId": sp.linkedProjectId,
		"linkedProjectPath": sp.linkedProjectPath,
	}
}

# expectedProjectId 0 (or absent) means "no id configured"; GitLab project ids
# start at 1, so 0 is a safe sentinel. expectedProjectPath "" means "no path
# configured". The three modes below are mutually exclusive by their guards, so
# exactly one _violation body can match: id wins, then path, then any-linkage.
_expected_id(cfg) := object.get(cfg, "expectedProjectId", 0)

_expected_path(cfg) := object.get(cfg, "expectedProjectPath", "")

# Normalise a path for comparison: trim surrounding slashes and lowercase, since
# GitLab namespaces are case-insensitive.
_norm(p) := trim(lower(p), "/")

# ID mode (id set, authoritative): the linked id must equal it.
_violation(sp, cfg) := _mismatch_msg(sp, sprintf("id %d", [_expected_id(cfg)])) if {
	_expected_id(cfg) != 0
	sp.linkedProjectId != _expected_id(cfg)
}

# Path mode (no id, path set): the linked path must equal it, normalised.
_violation(sp, cfg) := _mismatch_msg(sp, sprintf("path %q", [_expected_path(cfg)])) if {
	_expected_id(cfg) == 0
	_expected_path(cfg) != ""
	_norm(sp.linkedProjectPath) != _norm(_expected_path(cfg))
}

# Any-linkage mode (neither set): fail only when nothing is linked.
_violation(sp, cfg) := "no GitLab security policy project is linked to this project" if {
	_expected_id(cfg) == 0
	_expected_path(cfg) == ""
	sp.linkedProjectId == 0
}

_mismatch_msg(sp, want) := sprintf("no GitLab security policy project is linked (expected %s)", [want]) if {
	sp.linkedProjectId == 0
}

_mismatch_msg(sp, want) := sprintf(
	"the linked GitLab security policy project (id %d, path %q) is not the expected project (%s)",
	[sp.linkedProjectId, sp.linkedProjectPath, want],
) if {
	sp.linkedProjectId != 0
}
