# artipacked — detect jobs that check out the repository with
# `actions/checkout` while credential persistence is enabled. By default
# `actions/checkout` writes the GITHUB_TOKEN into the cloned repo's
# `.git/config`, where it survives for the lifetime of the job.
#
# The severity is graded by whether the token is actually exfiltrated:
#
#   - ISSUE-307 (low) — the credential persists but nothing in the job
#     packs `.git` into an artifact. This is latent hygiene: the token is
#     discarded when the job ends, and the other exfiltration route
#     (persisted credential harvested by fork-controlled code) is owned
#     by dangerous-triggers (ISSUE-802) and pull-request-target-head-
#     checkout (ISSUE-804). Flagged as a heads-up to add the one-liner.
#
#   - ISSUE-310 (high) — the same persisted credential AND a later
#     `actions/upload-artifact` step that uploads a `.git`-inclusive path
#     (`.`, `./`, the workspace root, or any path naming `.git`). The
#     artifact is downloadable (anonymously, on public repos) and the
#     token is harvested. This is the canonical, demonstrable "ArtiPACKED"
#     leak, so it escalates from hygiene to a real exposure.
#
# The mitigation is a one-liner for both: `with: persist-credentials:
# false` (and push with an explicit token if the job needs to write back).
package artipacked

import rego.v1

# ISSUE-310 (high): credential persists AND `.git` is packed into an
# uploaded artifact — a demonstrable token leak.
deny contains finding if {
	some i, j
	job := input.pipeline.jobs[i]
	action := job.uses[j]
	startswith(action.uses, "actions/checkout@")
	not _credentials_disabled(action)
	upload := _git_packing_upload(job, object.get(action, "line", 0))
	finding := {
		"code":     "ISSUE-310",
		"severity": "high",
		"message":  sprintf("job %q runs %q with credential persistence, then %q uploads a `.git`-inclusive path (%q) — GITHUB_TOKEN is packed into a downloadable artifact and exfiltrable", [job.name, action.uses, upload.uses, _upload_path(upload)]),
		"job":      job.name,
		"line":     object.get(action, "line", 0),
	}
}

# ISSUE-307 (low): credential persists but nothing packs `.git` into an
# artifact — latent hygiene, not a demonstrated leak.
deny contains finding if {
	some i, j
	job := input.pipeline.jobs[i]
	action := job.uses[j]
	startswith(action.uses, "actions/checkout@")
	not _credentials_disabled(action)
	not _git_packing_upload(job, object.get(action, "line", 0))
	finding := {
		"code":     "ISSUE-307",
		"severity": "low",
		"message":  sprintf("job %q runs %q without `persist-credentials: false` — GITHUB_TOKEN lingers in .git/config (latent; becomes a leak if a later step packs .git into an artifact or runs fork-controlled code)", [job.name, action.uses]),
		"job":      job.name,
		"line":     object.get(action, "line", 0),
	}
}

# YAML represents `persist-credentials: false` as the boolean false.
# Accept both forms defensively in case a workflow uses quotes.
_credentials_disabled(action) if {
	action.with["persist-credentials"] == false
}

_credentials_disabled(action) if {
	action.with["persist-credentials"] == "false"
}

# _git_packing_upload returns an upload-artifact action from the same
# job that (a) runs after the checkout at checkoutLine and (b) uploads
# a path that would include the `.git` directory.
_git_packing_upload(job, checkoutLine) := upload if {
	some k
	upload := job.uses[k]
	startswith(upload.uses, "actions/upload-artifact@")
	object.get(upload, "line", 0) > checkoutLine
	_path_includes_git(_upload_path(upload))
}

_upload_path(upload) := path if {
	path := upload.with.path
}

# The `path:` input may be a single scalar or a newline-separated block
# (multiple paths). Flag if any line resolves to a `.git`-inclusive
# location.
_path_includes_git(path) if {
	is_string(path)
	_risky_path(trim_space(path))
}

_path_includes_git(path) if {
	is_string(path)
	some line in split(path, "\n")
	_risky_path(trim_space(line))
}

# A path that packs the whole workspace (and therefore `.git`), or that
# names `.git` directly.
_risky_path(p) if p == "."

_risky_path(p) if p == "./"

_risky_path(p) if contains(p, "github.workspace")

_risky_path(p) if contains(p, ".git")
