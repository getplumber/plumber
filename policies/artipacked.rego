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
	some upload in _git_packing_uploads(job, action)
	finding := {
		"code":     "ISSUE-310",
		"severity": "high",
		"message":  sprintf("job %q runs %q with credential persistence, then %q uploads a `.git`-inclusive path (%q) — GITHUB_TOKEN is packed into a downloadable artifact and exfiltrable", [job.name, action.uses, upload.uses, _upload_path(upload)]),
		"job":      job.name,
		# The checkout ref, not the upload's: it is what identifies WHICH
		# step persisted the credential. A job can check out twice (its own
		# repo plus another) and both can pack; without this they collapse
		# into one finding and the second checkout is never reported.
		"uses": action.uses,
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
	count(_git_packing_uploads(job, action)) == 0
	finding := {
		"code":     "ISSUE-307",
		"severity": "low",
		"message":  sprintf("job %q runs %q without `persist-credentials: false` — GITHUB_TOKEN lingers in .git/config (latent; becomes a leak if a later step packs .git into an artifact or runs fork-controlled code)", [job.name, action.uses]),
		"job":      job.name,
		"uses":     action.uses,
		"line":     object.get(action, "line", 0),
	}
}

# actions/checkout persists credentials only when the input, upper-cased,
# is exactly TRUE: YAML gives the boolean for an unquoted value, and any
# quoted string other than a spelling of true ("false", "False", "no")
# disables persistence at runtime. An expression (`${{ inputs.x }}`) is
# resolved by GitHub before the action runs and cannot be read here, so it
# is never taken as disabled: the persisted, flagged reading is the
# conservative one.
_credentials_disabled(action) if {
	action.with["persist-credentials"] == false
}

_credentials_disabled(action) if {
	v := action.with["persist-credentials"]
	is_string(v)
	not contains(v, "${{")
	upper(trim_space(v)) != "TRUE"
}

# _git_packing_uploads is the set of upload-artifact actions from the same
# job that (a) run after the given checkout step and (b) upload a path that
# would include that checkout's `.git` directory. Built as a comprehension
# so the function has exactly one output (the set) for a given input: a
# job may have several such uploads (a report directory plus files inside
# it), and a function returning one upload at a time failed the whole
# evaluation with eval_conflict_error (#489).
_git_packing_uploads(job, checkout) := {upload |
	some k
	upload := job.uses[k]
	startswith(upload.uses, "actions/upload-artifact@")
	object.get(upload, "line", 0) > object.get(checkout, "line", 0)
	_uploads_hidden_files(upload)
	_path_includes_git(_upload_path(upload), _checkout_dir(checkout))
}

# actions/upload-artifact v4 excludes hidden files, `.git` included, unless
# `include-hidden-files: true` is set; the v1 to v3 majors packed them
# unconditionally (and no longer run on github.com since their 2025
# shutdown, but a workflow may still say so). A ref that names one of those
# majors packs `.git`; every other ref (v4 and later, a commit SHA, a branch)
# packs it only with the input on.
_uploads_hidden_files(upload) if {
	upload.with["include-hidden-files"] == true
}

_uploads_hidden_files(upload) if {
	v := upload.with["include-hidden-files"]
	is_string(v)
	lower(trim_space(v)) == "true"
}

_uploads_hidden_files(upload) if {
	regex.match(`@v[123](\.|$)`, upload.uses)
}

# _checkout_dir is where actions/checkout writes the repository, and so
# where the persisted credential lives (`<dir>/.git/config`): its `path:`
# input made workspace-relative, "" for the workspace root.
_checkout_dir(checkout) := d if {
	d := _root_as_empty(trim_suffix(_workspace_relative(trim_space(checkout.with.path)), "/"))
}

# `path: .` and `path: ./` name the workspace root, like no path at all.
_root_as_empty(".") := ""

_root_as_empty(d) := d if {
	d != "."
}

_checkout_dir(checkout) := "" if {
	not checkout.with.path
}

_upload_path(upload) := path if {
	path := upload.with.path
}

# The `path:` input may be a single scalar or a newline-separated block
# (multiple patterns). Flag if any pattern resolves to a `.git`-inclusive
# location, unless a `!`-prefixed exclusion pattern in the same block
# excludes the checkout's `.git` directory: actions/upload-artifact honours
# those exclusions, so the credential is never packed.
_path_includes_git(path, checkoutDir) if {
	is_string(path)
	some line in split(path, "\n")
	_risky_path(trim_space(line), checkoutDir)
	not _excludes_git(path, checkoutDir)
}

# Only an exclusion that covers the CHECKOUT'S `.git` clears the upload:
# `!<dir>/.git`, `!<dir>/.git/`, `!<dir>/.git/*`, `!<dir>/.git/**` (with
# `<dir>/` absent for a root checkout), or the recursive `!**/.git` and
# `!**/.git/**`, with or without the workspace prefix. An exclusion of the
# root `.git` when the checkout lives under `path: repo`, of a nested
# repository (`!vendor/pkg/.git`), or of a part of `.git` (`!.git/lfs`)
# leaves `.git/config` and its credential in the artifact.
_excludes_git(path, checkoutDir) if {
	some line in split(path, "\n")
	p := trim_space(line)
	startswith(p, "!")
	_workspace_relative(trim_prefix(p, "!")) in _git_exclusions(checkoutDir)
}

_git_exclusions("") := {".git", ".git/", ".git/*", ".git/**", "**/.git", "**/.git/**"}

_git_exclusions(dir) := {concat("/", [dir, ".git"]), concat("/", [dir, ".git/"]), concat("/", [dir, ".git/*"]), concat("/", [dir, ".git/**"]), "**/.git", "**/.git/**"} if {
	dir != ""
}

# _workspace_relative strips a leading workspace expression and any leading
# `./` segments, so every spelling of the same location compares equal.
_workspace_relative(p) := regex.replace(regex.replace(p, `^\$\{\{\s*github\.workspace\s*\}\}/?`, ""), `^(\./)+`, "")

# A pattern that packs the whole workspace (and therefore `.git`), or that
# names the `.git` directory itself.
#
# Whole workspace, once made workspace-relative: nothing (the workspace
# expression alone), `.`, `/`-terminated forms of those, or a glob that
# expands through hidden directories from the root: `**`, `**/`, `**/*`, `*`
# (a top-level wildcard matches the `.git` entry), `*/**`, `.*` (the dot
# entries). A path UNDER the workspace (`dist`, `reports/**`) packs only
# that directory and never `.git`. Arbitrary glob evaluation is out of
# scope: a bespoke pattern that happens to match `.git` (`.g*`) is not
# recognised.
#
# The `.git` directory: the path is `.git`, starts with `.git/`, ends with
# `/.git` or contains `/.git/`. A dot-file such as `.gitignore` or the
# `.github` directory shares the prefix and packs no credential.
_risky_path(p, _) if {
	p != ""
	_workspace_relative(p) in {"", ".", "./", "**", "**/", "**/*", "*", "*/**", ".*"}
}

_risky_path(p, _) if _names_git_dir(_workspace_relative(p))

# A checkout under `path: <dir>` keeps its credential in `<dir>/.git`, so
# uploading that directory itself, a glob rooted in it, or any ANCESTOR
# directory (`a` or `a/**` for a checkout under `a/b`) packs it too.
_risky_path(p, checkoutDir) if {
	checkoutDir != ""
	_workspace_relative(p) in {checkoutDir, concat("/", [checkoutDir, ""]), concat("/", [checkoutDir, "**"]), concat("/", [checkoutDir, "*"]), concat("/", [checkoutDir, "**/*"]), concat("/", [checkoutDir, ".*"])}
}

_risky_path(p, checkoutDir) if {
	checkoutDir != ""
	d := _pattern_dir(_workspace_relative(p))
	d != ""
	startswith(checkoutDir, concat("", [d, "/"]))
}

# _pattern_dir is the directory an upload pattern is rooted in: the pattern
# without a trailing `/`, `/*`, `/**` or `/**/*`.
_pattern_dir(rel) := trim_suffix(trim_suffix(trim_suffix(trim_suffix(rel, "/**/*"), "/**"), "/*"), "/")

_names_git_dir(p) if p == ".git"

_names_git_dir(p) if startswith(p, ".git/")

_names_git_dir(p) if endswith(p, "/.git")

_names_git_dir(p) if contains(p, "/.git/")
