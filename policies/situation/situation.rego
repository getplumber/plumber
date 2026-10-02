# Package situation derives per-job facts from the normalized pipeline: who can
# make a job run with input they control (entries), what the job holds
# (privilege) and what it can change (impact). It emits no finding. Every fact
# carries evidence so the explanation can quote it. States: proven,
# unresolvable. Absence of a fact is absence from the output.
package situation

import rego.v1

result := {"exposure": exposure, "jobs": jobs}

exposure := v if {
	v := input.pipeline.visibility
	v != ""
} else := "unknown"

# jobs is keyed by job name, and two jobs can share one: workflow files
# "ci.yml" and "ci.yaml" both give the namespace "ci". Keying each job
# separately would raise an object-key conflict and fail the whole
# evaluation, so the facts of every job carrying a name are merged into
# one fact set under it: entries and impact as set unions, feeds as a
# sorted union.
job_names := {job.name | some job in input.pipeline.jobs}

jobs := {name: facts(named_jobs(name)) | some name in job_names}

# named_jobs keeps the input order, so a choice of one job in the group
# (the environment, in merged_privilege) is deterministic.
named_jobs(name) := [job | some job in input.pipeline.jobs; job.name == name]

facts(group) := {
	"entries": [e | some e in {e | some job in group; some e in entry_set(job)}],
	"privilege": merged_privilege(group),
	"impact": [i | some i in {i | some job in group; some i in impact(job)}],
	"feeds": sort({f | some job in group; some f in feeds(job)}),
}

# ---------------------------------------------------------------- entries

entry_set(job) := s if {
	s := fork_pr(job) | pr_target(job) | untrusted_expressions(job) | mutable_dependencies(job) | unprotected_push(job)
}

origin(job) := {"file": object.get(job, "originFile", ""), "line": object.get(job, "originLine", 0)}

entry(kind, state, evidence, subject, job) := object.union(
	{"kind": kind, "state": state, "evidence": evidence, "subject": subject},
	origin(job),
)

# fork_pr: GitHub pull_request without a same-repo guard; GitLab MR pipelines.
fork_pr(job) := {entry("fork_pr", "proven", "on: pull_request", "pull_request", job)} if {
	"pull_request" in object.get(job, "triggers", [])
	not same_repo_guard(job)
} else := {entry("fork_pr", "proven", "rules: merge_request_event", "merge_request_event", job)} if {
	input.pipeline.provider == "gitlab"
	merge_request_job(job)
	not forks_forbidden
} else := set()

# same_repo_guard_patterns: the family-1 (same-repository, non-fork
# pull-request) guard forms, copied from policies/dangerous_triggers.rego
# (ISSUE-802) and policies/pull_request_target_head_checkout.rego
# (ISSUE-804), which both recognize the operands in either order and
# both the ==false and !=true spellings of the fork check.
same_repo_guard_patterns := [
	`head\.repo\.full_name\s*==\s*github\.repository`,
	`github\.repository\s*==\s*[^=]*head\.repo\.full_name`,
	`head\.repo\.fork\s*==\s*false`,
	`head\.repo\.fork\s*!=\s*true`,
	`!\s*github\.event\.pull_request\.head\.repo\.fork`,
]

same_repo_guard(job) if {
	some text in job_conditions(job)
	some pattern in same_repo_guard_patterns
	regex.match(pattern, text)
}

job_conditions(job) := array.concat([object.get(job, "if", "")], object.get(job, "conditions", []))

# gitlab_rules_run_on(job, source): true when the job's rules: array lets it
# run on $CI_PIPELINE_SOURCE == source, read the way an operator would, not
# as a bare substring of the if: text. Two idioms include source:
#   1. an explicit if: '$CI_PIPELINE_SOURCE == "<source>"' (any quoting,
#      any spacing) whose when is not never;
#   2. the "exclude every other source, then run" idiom:
#      if: '$CI_PIPELINE_SOURCE != "<source>"' with when: never, followed
#      (ordering matters, exactly as GitLab evaluates rules: top to bottom)
#      by a later rule without if: (a genuine catch-all) whose when is not
#      never, so <source> is the one thing that idiom's exclusion lets
#      through. A later rule that carries its own if: is not statically
#      decidable here and yields no inclusion: for example, a later rule
#      gated on $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH might or might not
#      match a <source> pipeline, so this fact stays conservative (a
#      missing fact never blocks, the same rule the controls follow) and
#      does not read it as one.
# A rule reading "!= <source>" with a when that is NOT never is neither: it
# runs the job on every OTHER source, never on <source>, so it must not be
# read as an inclusion of <source>.
gitlab_rules_run_on(job, source) if {
	some rule in object.get(job, "rules", [])
	regex.match(sprintf(`\$CI_PIPELINE_SOURCE\s*==\s*['"]%s['"]`, [source]), object.get(rule, "if", ""))
	object.get(rule, "when", "") != "never"
}

gitlab_rules_run_on(job, source) if {
	rules := object.get(job, "rules", [])
	some i, ri in rules
	regex.match(sprintf(`\$CI_PIPELINE_SOURCE\s*!=\s*['"]%s['"]`, [source]), object.get(ri, "if", ""))
	object.get(ri, "when", "") == "never"
	some j, rj in rules
	j > i
	object.get(rj, "if", "") == ""
	object.get(rj, "when", "") != "never"
}

# A rule with when: never is an exclusion: the job does not run on the
# pipelines that rule matches, so it never makes the job an MR (or push)
# job by itself, here and in push_job below. merge_request_job and
# push_job both read their rules: through gitlab_rules_run_on above, so
# both idioms (an explicit == inclusion, and the exclude-then-run idiom)
# are recognized, and the "!=" operator is never mistaken for inclusion.
merge_request_job(job) if gitlab_rules_run_on(job, "merge_request_event")

merge_request_job(job) if {
	some only in object.get(job, "only", [])
	only == "merge_requests"
}

# $CI_MERGE_REQUEST_IID (or its _ID spelling) is only ever set on a
# merge-request pipeline, so a rule gated on its bare presence is the same
# idiom as an explicit $CI_PIPELINE_SOURCE == "merge_request_event", read
# the way an operator would. A rule that instead compares the variable to
# null or "" is testing for its ABSENCE, the opposite meaning, so that
# spelling is excluded here; it can still include the job through the
# "exclude then run" idiom below, the same shape gitlab_rules_run_on's
# second body already recognizes for $CI_PIPELINE_SOURCE.
merge_request_job(job) if {
	some rule in object.get(job, "rules", [])
	object.get(rule, "when", "") != "never"
	regex.match(`\$CI_MERGE_REQUEST_I?ID\b`, object.get(rule, "if", ""))
	not regex.match(`\$CI_MERGE_REQUEST_I?ID\s*==\s*(null|"")`, object.get(rule, "if", ""))
}

merge_request_job(job) if {
	rules := object.get(job, "rules", [])
	some i, ri in rules
	regex.match(`\$CI_MERGE_REQUEST_I?ID\s*==\s*(null|"")`, object.get(ri, "if", ""))
	object.get(ri, "when", "") == "never"
	some j, rj in rules
	j > i
	object.get(rj, "if", "") == ""
	object.get(rj, "when", "") != "never"
}

# forks_forbidden would read a fork-pipelines-allowed flag off
# input.pipeline.mrSettings, but the current IR's MRSettings (see
# internal/ir/pipeline.go) carries no such field: it has mergeMethod,
# squashOption, mergePipelinesEnabled, mergeTrainsEnabled and a handful of
# other merge settings, none about forks. This rule stays inert (always
# undefined, so "not forks_forbidden" is always true) until the collector
# adds the field.
forks_forbidden if false

# pr_target: a privileged trigger plus a checkout of the PR head, unless the
# job is guarded against it. Written as a set comprehension, not a complete
# rule with an if/else body: the job can have more than one privileged
# trigger and more than one checkout step, and a complete rule whose body
# can be satisfied multiple times with different bindings raises
# eval_conflict_error ("functions must not produce multiple outputs for
# same inputs") the moment it is. The comprehension collects one entry per
# matching checkout step instead, which is always a single well-defined set
# regardless of how many bindings satisfy it.
#
# The trigger set is the union of what the two anchoring controls watch:
# pull_request_target (policies/pull_request_target_head_checkout.rego,
# ISSUE-804) plus the eight events of policies/dangerous_triggers.rego
# (ISSUE-802), so a finding of either control always has a pr_target
# fact on the same job.
#
# The guard that exempts a job mirrors whichever control actually anchors
# its triggers, because the two controls do not honour the same guards:
# a pull_request_target job routes through ISSUE-804, which recognizes
# only the family-1 same-repo guard (an author_association allowlist does
# not satisfy it, so ISSUE-804 still flags such a job, and so must this
# fact); a job whose privileged triggers are the other eight events routes
# through ISSUE-802, which recognizes all three guard families. See
# pr_target_exempt below.
privileged_triggers := {
	"pull_request_target",
	"workflow_run",
	"issue_comment",
	"pull_request_review",
	"pull_request_review_comment",
	"discussion_comment",
	"discussion",
	"gollum",
	"fork",
}

# Attacker-controlled checkout refs: the union of ISSUE-802's
# untrusted_ref_patterns and ISSUE-804's fork_ref_patterns. The first
# pattern widens their head.sha / head.ref pair to any PR-head field. A
# bare "head" substring is never enough: an ordinary branch ref
# ("refs/heads/main") is not a checkout of attacker-controlled content.
attacker_ref_patterns := [
	`github\.event\.pull_request\.head\.`,
	`github\.head_ref`,
	`github\.event\.workflow_run\.head_sha`,
	`github\.event\.workflow_run\.head_branch`,
	`github\.event\.number`,
]

job_privileged_triggers(job) := sort([t |
	some t in object.get(job, "triggers", [])
	t in privileged_triggers
])

# pr_target_guard_patterns: the two guard families ISSUE-802 recognizes
# beyond family 1 (same_repo_guard_patterns above, ISSUE-804's whole guard
# set), copied verbatim from policies/dangerous_triggers.rego's
# guard_patterns: family 2 exempts a workflow_run gated to a trusted
# upstream push; family 3 exempts a trusted author_association allowlist,
# by equality or contains(), never the negated (denylist) spelling.
pr_target_guard_patterns := array.concat(same_repo_guard_patterns, [
	`github\.event\.workflow_run\.event\s*==\s*['"]push['"]`,
	`author_association\s*==\s*['"](OWNER|MEMBER|COLLABORATOR)['"]`,
	`contains\(.*(OWNER|MEMBER|COLLABORATOR).*author_association`,
])

# pr_target_exempt: true when the job's guard is one its anchoring control
# actually honours. A job whose privileged triggers include
# pull_request_target is exempt only through same_repo_guard (ISSUE-804's
# only guard); a job whose privileged triggers are drawn only from the
# other eight events is exempt through any of the three ISSUE-802 guard
# families. The two bodies are mutually exclusive (one requires
# pull_request_target present, the other requires it absent), so they
# never conflict as alternative values for the same job.
pr_target_exempt(job) if {
	"pull_request_target" in job_privileged_triggers(job)
	same_repo_guard(job)
}

pr_target_exempt(job) if {
	not "pull_request_target" in job_privileged_triggers(job)
	some text in job_conditions(job)
	some pattern in pr_target_guard_patterns
	regex.match(pattern, text)
}

pr_target(job) := {entry("pr_target", ref_state(ref), sprintf("on: %s + checkout ref %s", [concat(", ", triggers), ref]), ref_subject(ref), job) |
	triggers := job_privileged_triggers(job)
	count(triggers) > 0
	not pr_target_exempt(job)
	some action in object.get(job, "uses", [])
	startswith(action.uses, "actions/checkout@")
	ref := object.get(object.get(action, "with", {}), "ref", "")
	is_string(ref)
	checkout_ref_of_interest(ref)
}

checkout_ref_of_interest(ref) if attacker_ref(ref)

checkout_ref_of_interest(ref) if contains(ref, "inputs.")

attacker_ref(ref) if {
	some p in attacker_ref_patterns
	regex.match(p, ref)
}

# A ref that names an attacker-controlled field is proven whatever else it
# holds. A ref built only from workflow inputs cannot be judged statically:
# the caller decides what it points at, so it is unresolvable.
ref_state(ref) := "proven" if {
	attacker_ref(ref)
} else := "unresolvable"

ref_subject(ref) := trim_space(trim_suffix(trim_prefix(ref, "${{"), "}}"))

# untrusted_expression: attacker-controlled input reaching a script or a with value.
#
# Scripts are scanned per line, dropping any whole-line comment first (see
# script_lines below): ISSUE-204 (unsafe_variable_expansion.rego) does the
# same before its own variable match, and a commented-out script line must
# not fire a fact a commented-out control line would never flag either.
# This deliberately does NOT reuse _visible_line (the comment/quote
# stripper further below): that helper also strips quoted strings, which
# would hide eval "$CI_COMMIT_MESSAGE", the exact pattern ISSUE-204 flags.
# A trailing comment after real code on the same line still counts: only a
# whole-line comment (trim_space starts with "#") is dropped. Step with:
# values are not shell lines handed to a shell, so they get no comment
# handling, scanned as the whole value, as before. ISSUE-207 does not skip
# comments either: a 207 hit on a commented-out GitHub script line is a
# false positive of 207, so this fact deliberately does not reproduce it.
#
# GitHub: the patterns are policies/template_injection.rego's
# unsafe_patterns (ISSUE-207), copied verbatim. Two passes, as for
# secrets below: the first isolates each "${{ ..." expression up to its
# first "}" (the same span ISSUE-207's `[^}]*` allows), the second runs
# the control's patterns inside it. The subject is the expression with
# its "${{ }}" and surrounding spaces removed.
github_unsafe_patterns := [
	`\${{[^}]*github\.event\.[^}]*\.(title|body)\b`,
	`\${{[^}]*github\.head_ref\b`,
	`\${{[^}]*github\.event\.[^}]*\.head\.(ref|label)\b`,
	`\${{[^}]*github\.event\.[^}]*head_branch\b`,
	`\${{[^}]*github\.event\.[^}]*head\.repo\.default_branch\b`,
	`\${{[^}]*github\.event\.[^}]*head_repository\.default_branch\b`,
	`\${{[^}]*github\.event\.[^}]*\.message\b`,
	`\${{[^}]*github\.event\.[^}]*\.(description|homepage)\b`,
	`\${{[^}]*github\.event\.[^}]*(author|committer)\.(name|email)\b`,
	`\${{[^}]*github\.event\.[^}]*page_name\b`,
]

# GitLab: the variable names ISSUE-204 (policies/unsafe_variable_expansion.rego)
# reads from input.config.unsafeVariableExpansion.dangerousVariables, the
# key control/task.go writes. The control itself has no built-in list; the
# fallback below is its default list from defaultConfig/.plumber.yaml, for
# a run without that configuration.
gitlab_dangerous_variables := object.get(object.get(input.config, "unsafeVariableExpansion", {}), "dangerousVariables", [
	"CI_MERGE_REQUEST_TITLE",
	"CI_MERGE_REQUEST_DESCRIPTION",
	"CI_COMMIT_MESSAGE",
	"CI_COMMIT_TITLE",
	"CI_COMMIT_TAG_MESSAGE",
	"CI_COMMIT_REF_NAME",
	"CI_COMMIT_REF_SLUG",
	"CI_COMMIT_BRANCH",
	"CI_MERGE_REQUEST_SOURCE_BRANCH_NAME",
	"CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_NAME",
])

untrusted_expressions(job) := {entry("untrusted_expression", "proven", short_evidence(line), expression_subject(expr), job) |
	input.pipeline.provider == "github"
	some line in script_lines(job)
	some expr in regex.find_n(`\$\{\{[^}]*`, line, -1)
	github_unsafe(expr)
} | {entry("untrusted_expression", "proven", evidence, expression_subject(expr), job) |
	input.pipeline.provider == "github"
	some text in job_with_values(job)
	some expr in regex.find_n(`\$\{\{[^}]*`, text, -1)
	github_unsafe(expr)
	evidence := evidence_line(text, [l | some l in split(text, "\n"); contains(l, expr)])
} | {entry("untrusted_expression", "proven", short_evidence(line), name, job) |
	input.pipeline.provider == "gitlab"
	some line in script_lines(job)
	some name in gitlab_dangerous_variables
	gitlab_variable_used(line, name)
} | {entry("untrusted_expression", "proven", evidence, name, job) |
	input.pipeline.provider == "gitlab"
	some text in job_with_values(job)
	some name in gitlab_dangerous_variables
	gitlab_variable_used(text, name)
	evidence := evidence_line(text, [l | some l in split(text, "\n"); gitlab_variable_used(l, name)])
}

# script_lines: the non-comment lines of every scripts entry, split on
# "\n" and with a whole-line comment dropped (trim_space starts with "#"),
# mirroring ISSUE-204 at the line level. A trailing comment after real
# code on the same line is not stripped here, so it still counts for
# whatever scans the line.
script_lines(job) := [line |
	some text in object.get(job, "scripts", [])
	some line in split(text, "\n")
	not startswith(trim_space(line), "#")
]

# evidence_line: the evidence quoted for a match inside a script, the
# first matching line of the block (the caller passes the matching
# lines, in order), trimmed and cut to 200 characters. When no single
# line matches (a match spanning lines), the whole text, trimmed and cut.
# Total: both branches always produce a string.
evidence_line(text, matching) := short_evidence(matching[0]) if {
	count(matching) > 0
} else := short_evidence(text)

short_evidence(s) := substring(trim_space(s), 0, 200)

github_unsafe(expr) if {
	some p in github_unsafe_patterns
	regex.match(p, expr)
}

expression_subject(expr) := trim_space(trim_suffix(trim_prefix(expr, "${{"), "}}"))

# The two spellings ISSUE-204's _variable_used accepts: braced, exact
# name; unbraced, followed by a non-word character or the end of the text.
gitlab_variable_used(text, name) if regex.match(sprintf(`\$\{%s\}`, [name]), text)

gitlab_variable_used(text, name) if regex.match(sprintf(`\$%s($|[^a-zA-Z0-9_])`, [name]), text)

# job_texts: the shell sinks (run scripts) and the step with values, each
# returned whole (no comment handling: untrusted_expressions above reads
# the scripts half through script_lines instead for its own line-level
# comment skipping; the callers here, the secrets scan, want the whole
# text). A step if: is evaluated by the runner, never handed to a shell,
# so it is not scanned for untrusted input.
job_texts(job) := array.concat(object.get(job, "scripts", []), job_with_values(job))

# job_with_values: the step with values alone, a string per with: entry.
job_with_values(job) := [v |
	some action in object.get(job, "uses", [])
	some _, v in object.get(action, "with", {})
	is_string(v)
]

# mutable_dependency: a ref, image, include or fetched script that can change under the project.
mutable_dependencies(job) := mutable_actions(job) | mutable_reusable_workflow(job) | mutable_images(job) | fetched_scripts(job)

# Local actions ("./…", a bare "/…") live in the repository itself, outside
# any external trust boundary; docker-image actions ("docker://…") are
# covered by the container-image policies, not this one. Mirrors
# policies/action_unpinned.rego's _is_local.
local_or_docker(uses) if startswith(uses, "./")

local_or_docker(uses) if startswith(uses, "/")

local_or_docker(uses) if startswith(uses, "docker://")

mutable_actions(job) := {object.union(entry("mutable_dependency", state, action.uses, action.uses, job), {"line": object.get(action, "line", 0)}) |
	some action in object.get(job, "uses", [])
	not local_or_docker(action.uses)
	state := action_state(action)
}

# mutable_reusable_workflow: the job-level reusable-workflow call
# (reusableWorkflowUses, "owner/repo/.github/workflows/x.yml@ref"), which
# ISSUE-701 holds to the same pin-by-SHA rule as a step action. A ref that
# is not a SHA is mutable by construction; a local call is exempt. No
# metadata is fetched for a reusable workflow, so a SHA pin yields nothing.
mutable_reusable_workflow(job) := {entry("mutable_dependency", "proven", uses, uses, job) |
	uses := object.get(job, "reusableWorkflowUses", "")
	uses != ""
	not local_or_docker(uses)
	not sha_pinned(uses)
}

# ref_of mirrors policies/action_unpinned.rego's _ref_of: the substring
# after "@" in "owner/repo@ref", "" when there is no "@" at all (a bare
# "owner/repo", also unpinned).
ref_of(uses) := ref if {
	idx := indexof(uses, "@")
	idx >= 0
	ref := substring(uses, idx+1, -1)
} else := ""

# sha_pinned matches case-insensitively: Git and the GitHub API resolve SHAs
# case-insensitively, so an upper-case pin is still immutable. Mirrors
# policies/action_unpinned.rego's _is_sha.
sha_pinned(uses) if regex.match(`^[0-9a-f]{40}$`, lower(ref_of(uses)))

action_tier(action) := object.get(object.get(object.get(action, "metadata", {}), "mutableRemoteExec", {}), "tier", "")

# action_state answers from positive signals only, never from the absence
# of one. A ref that is not SHA-pinned (a branch or a tag, "@main", "@v4")
# is mutable by construction: no metadata lookup is needed to know a tag
# can move, so it is always "proven". A SHA-pinned ref needs its own
# positive signal from ActionMetadata.MutableRemoteExec, resolved by
# fetching the action's source: "unverified" (ISSUE-716: the source could
# not be fetched to check) is "unresolvable"; "exec" or "obfuscated"
# (ISSUE-714/715: the action's own source fetches and runs mutable remote
# code at runtime even though its ref is pinned) is "proven". Any other
# tier (including "data", a non-executed mutable manifest, or no
# MutableRemoteExec at all) yields no value here, so the comprehension
# above produces no entry for that action: a pinned ref with no positive
# signal found is not a mutable dependency. The three bodies below are
# mutually exclusive by construction (the first requires "not sha_pinned",
# the other two require "sha_pinned" with disjoint tier sets), so they
# never conflict as alternative values for the same action.
action_state(action) := "proven" if {
	not sha_pinned(action.uses)
}

action_state(action) := "unresolvable" if {
	sha_pinned(action.uses)
	action_tier(action) == "unverified"
}

action_state(action) := "proven" if {
	sha_pinned(action.uses)
	action_tier(action) in {"exec", "obfuscated"}
}

# An image that still held an unresolved `$VARIABLE` when it was parsed
# cannot be judged mutable or not: Name/Tag/Digest describe the raw
# placeholder text, not a real reference, so the entry is unresolvable
# rather than a guess either way.
mutable_images(job) := {entry("mutable_dependency", "unresolvable", image_ref(img), image_ref(img), job) |
	some img in job_images(job)
	object.get(img, "unresolved", false) == true
} | {entry("mutable_dependency", "proven", image_ref(img), image_ref(img), job) |
	some img in job_images(job)
	not object.get(img, "unresolved", false)
	mutable_image(img)
}

job_images(job) := array.concat(image_list(object.get(job, "image", null)), object.get(job, "services", []))

image_list(null) := []
image_list(img) := [img] if img != null

# Image.Tag/Digest are `omitempty` in the IR, so an empty value is absent
# from the JSON entirely, not present as "": object.get with a "" default
# is required here, a direct img.tag/img.digest would be undefined (and the
# rule would silently never match) whenever the field is empty.
image_tag(img) := object.get(img, "tag", "")

image_digest(img) := object.get(img, "digest", "")

image_name(img) := object.get(img, "name", "")

# image_ref: the whole reference, registry, tag and digest included, the
# value ISSUE-102 and ISSUE-103 carry for the same image (their
# registry/name:tag form, plus the digest when present). The GitLab
# collector's "unknown" registry is a placeholder for an unresolved
# reference, never written by the author, so it is left out.
image_ref(img) := concat("", [image_registry_prefix(img), image_name(img), image_tag_suffix(img), image_digest_suffix(img)])

image_registry_prefix(img) := concat("", [r, "/"]) if {
	r := object.get(img, "registry", "")
	not r in {"", "unknown"}
} else := ""

image_tag_suffix(img) := concat("", [":", image_tag(img)]) if image_tag(img) != "" else := ""

image_digest_suffix(img) := concat("", ["@", image_digest(img)]) if image_digest(img) != "" else := ""

# Production writes forbidden tag patterns at input.config.imageMutableTag.
# forbiddenTags (policies/image_mutable_tag.rego, control/task.go), glob
# patterns ("*", "?"), defaulting to ["latest"] when the operator configured
# none.
forbidden_tags := object.get(object.get(input.config, "imageMutableTag", {}), "forbiddenTags", ["latest"])

# An image is a mutable dependency when it has no digest, whatever its tag
# (per the spec: content that can change without a change in the repo, a
# tag can be repointed at the registry at any time, even one that looks
# pinned), OR its tag matches a forbidden glob pattern, even when a digest
# also happens to be present. The two conditions are an OR, not an AND: a
# forbidden tag is still worth flagging on an otherwise-digest-pinned image,
# and a merely untagged-by-digest image is worth flagging regardless of its
# tag text.
mutable_image(img) if image_digest(img) == ""

mutable_image(img) if {
	some pattern in forbidden_tags
	glob.match(pattern, null, image_tag(img))
}

# fetched_scripts: a line that fetches and runs, or installs, remote code
# at execution time, so what runs today may not be what runs tomorrow even
# though the CI file itself did not change.
#   - "(?m)" line-anchors "$" inside a multi-line run: block (a single
#     Scripts entry can itself hold several shell lines).
#   - the shell name requires a trailing word boundary ("\b") so a
#     checksum pipe ("| sha256sum") is not mistaken for a fetch-and-execute
#     pipe ("| bash"): "sha256sum" starts with the same two letters as
#     "sh" but is not the shell.
#   - an unversioned npx <tool> is deliberately NOT matched: it resolves
#     lockfile-pinned local binaries in the common case (npx tsc, npx
#     eslint, npx jest), and control 411 does not flag it, so this fact
#     layer must mirror 411 here, not exceed it.
#   - every form ISSUE-411 (policies/unverified_scripts.rego) detects is
#     also matched, through unverified_script_line below, so a finding of
#     that control always has a fact of this kind on the same job.
fetched_scripts(job) := {entry("mutable_dependency", "proven", evidence, url, job) |
	some line in object.get(job, "scripts", [])
	fetched_script_line(line)
	evidence := evidence_line(line, [l | some l in split(line, "\n"); fetched_script_line(l)])
	url := first_url_or_line(evidence)
}

# The same quoted-substring and comment stripping unverified_script_line
# applies before its own matching runs here too, so a pipe-to-shell
# hidden inside a string literal or a trailing comment does not trigger
# this branch either. The pipe character is excluded from the run
# between "curl"/"wget" and the shell name, so the match cannot cross a
# physical line: a fetch on one line followed by an unrelated "| sh" on
# a later line of the same block is not, by this branch alone, read as
# one fetch-and-execute.
fetched_script_line(line) if {
	regex.match(`(?m)(curl|wget)\s[^|\n]*\|\s*(ba|z)?sh\b|pip\s+install\s+https?://`, _visible_line(line))
}

fetched_script_line(line) if unverified_script_line(_visible_line(line), line)

# Copied verbatim from policies/unverified_scripts.rego (ISSUE-411): the
# interpreter list, the quote and comment stripping, and the five line
# patterns with their heredoc and local-echo exemptions on the generic
# form. The control's verification and trusted-URL exemptions are not
# copied: a verified or trusted fetch still runs code that can change
# without a change in the repository.
_shell := `bash|sh|zsh|python[23]?|perl|ruby|dash|ksh`

_visible_line(line) := stripped if {
	once := regex.replace(line, `"[^"]*"`, "")
	twice := regex.replace(once, `'[^']*'`, "")
	stripped := regex.replace(twice, `\s+#.*`, "")
}

_has_heredoc(line) if {
	regex.match(`<<-?\s*['"]?\w+`, line)
}

unverified_script_line(visible, _) if {
	regex.match(sprintf(`(?i)(curl|wget)\s+[^|&;\n]*\|\s*(sudo\s+)?(%s)\b`, [_shell]), visible)
}

unverified_script_line(visible, _) if {
	regex.match(sprintf(`(?i)(curl|wget)\s+[^&;\n]*&&\s*(sudo\s+)?(%s)\b`, [_shell]), visible)
}

unverified_script_line(visible, _) if {
	regex.match(sprintf(`(?i)(curl|wget)\s+[^;\n]*(?:>\s*\S+|-o\s+\S+)[^;\n]*(?:;|&&)\s*(sudo\s+)?(%s)\b`, [_shell]), visible)
}

unverified_script_line(visible, _) if {
	regex.match(sprintf(`(?i)(echo|printf)\s+[^|]*\|\s*base64\s+(-d|--decode)\s*\|\s*(sudo\s+)?(%s)\b`, [_shell]), visible)
}

unverified_script_line(visible, line) if {
	not _has_heredoc(line)
	not _echo_of_local_data(visible, line)
	regex.match(sprintf(`(?i)\|\s*(sudo\s+)?(%s)\b`, [_shell]), visible)
}

_echo_of_local_data(visible, line) if {
	regex.match(`(?i)^\s*(echo|printf)\b`, visible)
	not regex.match(`(?i)\b(curl|wget|base64)\b`, line)
}

first_url_or_line(line) := url if {
	urls := regex.find_n(`https?://[^\s'"]+`, line, 1)
	count(urls) > 0
	url := urls[0]
} else := line

# default_branch_name: input.pipeline.defaultBranch, safe against the
# field being entirely absent from the input, which is what an empty
# Go string collapses to once json's omitempty strips it before the
# engine builds the OPA input. Reading the bare path directly would
# make every expression built from it (a set literal, an array passed
# to sprintf) undefined rather than built with an empty string, so
# every reader of the default branch name goes through this instead.
default_branch_name := object.get(input.pipeline, "defaultBranch", "")

# unprotected_push: a push-triggered job while the default branch is
# unprotected. GitHub's on: push carries branches:/tags: filters the IR
# drops (parseOnTriggers and the collector it mirrors read only the
# event name), so a job gated to push: tags: ['v*'] looks here exactly
# like one that runs on every push to the default branch. A GitHub entry
# is therefore never proven, only unresolvable, until the IR carries
# those filters; a protected default branch still removes the entry
# outright, the one case a missing filter cannot turn into a false
# negative. GitLab's push state here comes from an explicit rules:
# condition (an inclusive $CI_PIPELINE_SOURCE == "push", the
# "exclude then run" idiom, or the $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
# idiom and its variants, see gitlab_push_state/gitlab_rules_branch_state
# below), the no-rules default, or the legacy only:/except: keywords
# (gitlab_only_except_state), none of which hides a filter the same way,
# so it keeps today's states except where the rules: or only:/except:
# reading itself cannot be decided statically. unprotected_push_decidable
# below draws the line on an unknown default branch name differently per
# provider: GitHub's default_branch_state needs the name to find a match in
# input.pipeline.branches, so without it there is nothing to resolve;
# GitLab's determination does not, and lands on unresolvable on its own
# when a named branch cannot be ruled in or out.
unprotected_push(job) := {entry("unprotected_push", push_entry_state(job), push_entry_evidence(job), default_branch_name, job)} if {
	push_job(job)
	unprotected_push_decidable(job)
	push_entry_state(job) != "protected"
} else := set()

unprotected_push_decidable(job) if input.pipeline.provider == "gitlab"

unprotected_push_decidable(job) if {
	input.pipeline.provider == "github"
	default_branch_name != ""
}

push_entry_state(job) := "unresolvable" if {
	input.pipeline.provider == "gitlab"
	gitlab_push_state(job) == "unresolvable"
} else := "unresolvable" if {
	input.pipeline.provider == "github"
	default_branch_state == "proven"
} else := default_branch_state

push_entry_evidence(job) := sprintf("on push; default branch %s %s; push filters (branches/tags) not visible", [default_branch_name, default_branch_state]) if {
	input.pipeline.provider == "github"
} else := sprintf("on push; default branch %s %s", [default_branch_name, push_entry_state(job)])

push_job(job) if "push" in object.get(job, "triggers", [])

push_job(job) if {
	input.pipeline.provider == "gitlab"
	gitlab_push_state(job) != "absent"
}

# gitlab_push_branch_refs: ref values that always mean "pushes to the
# default branch run", whatever the default branch's name: the
# branches/pushes keywords, GitLab's two names for the push trigger, and
# the project's actual configured default branch. Never a literal
# "main" or "master": only:/except: can legitimately gate a job to any
# branch name, and a project whose default branch is "main" can still
# name a job "master" without that meaning the default branch.
gitlab_push_branch_refs := {"branches", "pushes", default_branch_name}

# gitlab_push_absent_refs: only:/except: values that name a pipeline
# source other than a branch push.
gitlab_push_absent_refs := {
	"tags", "schedules", "triggers", "web", "api", "pipelines", "external", "merge_requests", "chat",
}

# gitlab_ref_is_regex: true for GitLab's /pattern/ only:/except: form,
# which can never be matched against a branch name statically. A bare
# name (a branch, or a tag sharing that name) is everything else.
gitlab_ref_is_regex(ref) if {
	startswith(ref, "/")
	endswith(ref, "/")
}

# gitlab_only_except_state decides, for a GitLab job with no rules: block,
# whether its legacy only:/except: keywords admit a push to the default
# branch, independent of whether that branch is protected. Total over
# every such job (no only, no except; only present; except present) and
# single-valued: proven, absent or unresolvable, never more than one.
#
# A bare name that is none of gitlab_push_branch_refs or
# gitlab_push_absent_refs names a branch other than the default: with
# the default branch known, that rules the push out (absent), since the
# name is confirmed to be some other, specific branch; with the default
# branch unknown, that same name might be the default branch under
# cover, so the outcome cannot be decided (unresolvable). A regex ref
# stays unresolvable regardless, for the same reason it is never
# compared against a branch name statically.
gitlab_only_except_state(job) := "absent" if {
	some ref in object.get(job, "except", [])
	ref in gitlab_push_branch_refs
} else := "proven" if {
	count(object.get(job, "only", [])) == 0
} else := "proven" if {
	some ref in object.get(job, "only", [])
	ref in gitlab_push_branch_refs
} else := "absent" if {
	default_branch_name != ""
	every ref in object.get(job, "only", []) {
		not gitlab_ref_is_regex(ref)
	}
} else := "absent" if {
	every ref in object.get(job, "only", []) {
		ref in gitlab_push_absent_refs
	}
} else := "unresolvable"

# gitlab_push_state folds the two ways a GitLab job's rules: block can admit
# a push to the default branch into one total, single-valued function, used
# by both push_job and push_entry_state so the two never drift apart:
#   - no rules: block at all: the legacy only:/except: reading
#     (gitlab_only_except_state) decides it, unchanged;
#   - otherwise, an explicit $CI_PIPELINE_SOURCE == "push" rule (including
#     the "exclude then run" idiom), read through gitlab_rules_run_on,
#     always wins when present;
#   - otherwise, the $CI_COMMIT_BRANCH idiom (gitlab_rules_branch_state)
#     decides it: a rule gated on it never also sets $CI_PIPELINE_SOURCE,
#     but checking gitlab_rules_run_on first costs nothing and keeps the
#     explicit idiom authoritative over the branch one if a job somehow
#     carries both.
gitlab_push_state(job) := gitlab_only_except_state(job) if {
	count(object.get(job, "rules", [])) == 0
} else := "proven" if {
	gitlab_rules_run_on(job, "push")
} else := gitlab_rules_branch_state(job)

# gitlab_rules_branch_state(job) reads the $CI_COMMIT_BRANCH idiom across
# every rule whose when is not never: proven if any rule proves it,
# else unresolvable if any rule leaves it unresolvable, else absent. Total
# over every GitLab job (including one with no rules: at all, where the
# comprehension below simply never matches and the chain falls to absent),
# single-valued by construction (an if/else chain).
#
# Earlier rules do not gate the reading: a $CI_COMMIT_BRANCH rule is
# matched by GitLab on a push to that branch whatever excluded other
# sources before it (an "$CI_PIPELINE_SOURCE != push, when: never" rule
# does not match a push, so evaluation reaches the branch rule), and a
# when: never rule earlier that would match the same push is the
# exclusion the when filter below already honours per rule.
gitlab_rules_branch_state(job) := "proven" if {
	some rule in object.get(job, "rules", [])
	object.get(rule, "when", "") != "never"
	_rule_branch_state(rule) == "proven"
} else := "unresolvable" if {
	some rule in object.get(job, "rules", [])
	object.get(rule, "when", "") != "never"
	_rule_branch_state(rule) == "unresolvable"
} else := "absent"

# _rule_branch_kind(if_text) classifies a single rule's if: text against the
# $CI_COMMIT_BRANCH idiom family, total and single-valued over any string
# (an if/else chain: exactly one of the five names always comes out,
# "none" when nothing below matches, including the never-an-inclusion
# "!=" and "!~" spellings). Kept separate from _rule_branch_state so the
# proven/unresolvable/no-value decision below never has to worry about two
# of its bodies matching the same text at once: the chain here has already
# picked the one shape that applies.
_rule_branch_kind(if_text) := "direct_equal" if {
	regex.match(`\$CI_COMMIT_BRANCH\s*==\s*\$CI_DEFAULT_BRANCH`, if_text)
} else := "direct_equal" if {
	regex.match(`\$CI_DEFAULT_BRANCH\s*==\s*\$CI_COMMIT_BRANCH`, if_text)
} else := "literal_equal" if {
	gitlab_branch_literal(if_text)
} else := "regex" if {
	regex.match(`\$CI_COMMIT_BRANCH\s*=~`, if_text)
} else := "bare" if {
	regex.match(`\$CI_COMMIT_BRANCH\b`, if_text)
	not regex.match(`\$CI_COMMIT_BRANCH\s*(==|!=|=~|!~)`, if_text)
} else := "none"

# gitlab_branch_literal(if_text): the quoted branch name $CI_COMMIT_BRANCH
# is compared to, when the if: reads that shape. Undefined (not "") when
# there is no such comparison, so _rule_branch_kind's "some lit in ..."-free
# "gitlab_branch_literal(if_text)" guard above reads as a plain existence
# check.
gitlab_branch_literal(if_text) := lit if {
	m := regex.find_all_string_submatch_n(`\$CI_COMMIT_BRANCH\s*==\s*['"]([^'"]*)['"]`, if_text, 1)
	count(m) > 0
	lit := m[0][1]
}

# _rule_branch_state(rule): proven/unresolvable/no-value for one rule,
# built on the if/else-total _rule_branch_kind above. "direct_equal" is
# always proven (every push to the default branch sets $CI_COMMIT_BRANCH
# to its name, so the comparison is true exactly on that push); "bare"
# likewise (the variable is set, full stop, on every branch push including
# the default one); "regex" is always unresolvable (never matched
# statically, same as gitlab_ref_is_regex); "literal_equal" depends on
# whether the literal names the configured default branch (proven),
# some other, specific branch (no value: that rule contributes nothing,
# it is not evidence of a push to the default branch, but it is not
# unresolvable either), or cannot be judged because the default branch
# name itself is unknown (unresolvable); "none" (including the "!=" and
# "!~" spellings, which exclude the default branch rather than include it)
# never proves or leaves this fact unresolvable.
_rule_branch_state(rule) := "proven" if {
	_rule_branch_kind(object.get(rule, "if", "")) == "direct_equal"
} else := "proven" if {
	_rule_branch_kind(object.get(rule, "if", "")) == "literal_equal"
	default_branch_name != ""
	gitlab_branch_literal(object.get(rule, "if", "")) == default_branch_name
} else := "unresolvable" if {
	_rule_branch_kind(object.get(rule, "if", "")) == "literal_equal"
	default_branch_name == ""
} else := "unresolvable" if {
	_rule_branch_kind(object.get(rule, "if", "")) == "regex"
} else := "proven" if {
	_rule_branch_kind(object.get(rule, "if", "")) == "bare"
}

default_branch_state := "proven" if {
	some b in object.get(input.pipeline, "branches", [])
	b.name == default_branch_name
	b.protected == false
} else := "protected" if {
	some b in object.get(input.pipeline, "branches", [])
	b.name == default_branch_name
	b.protected == true
} else := "unresolvable"

# ---------------------------------------------------------------- privilege

privilege(job) := {
	"secrets": secrets(job),
	"secretsState": secrets_state(job),
	"secretsInherit": object.get(job, "secretsInherit", false),
	"protectedSecrets": protected_secrets(job),
	"tokenWrite": token_write(job),
	"tokenWriteSource": token_write_source(job),
	"persistedCredentials": persisted_credentials(job),
	"environment": {"name": object.get(job, "environment", ""), "protected": environment_protected(job)},
}

# merged_privilege: the privilege of every job sharing one name (see jobs
# above), merged so the result never depends on input order: name lists
# as sorted unions; secretsState unresolvable if any job's is;
# secretsInherit true if any; persistedCredentials proven if any;
# tokenWriteSource the strongest signal present (declared, then default,
# then none); environment from the job with the smallest originFile, the
# first such job in input order on a tie. Total: the group is never empty.
merged_privilege(group) := {
	"secrets": sort({s | some job in group; some s in privilege(job).secrets}),
	"secretsState": merged_secrets_state(group),
	"secretsInherit": any_inherit(group),
	"protectedSecrets": sort({s | some job in group; some s in privilege(job).protectedSecrets}),
	"tokenWrite": sort({s | some job in group; some s in privilege(job).tokenWrite}),
	"tokenWriteSource": merged_token_write_source(group),
	"persistedCredentials": merged_persisted_credentials(group),
	"environment": privilege(environment_job(group)).environment,
}

merged_secrets_state(group) := "unresolvable" if {
	some job in group
	privilege(job).secretsState == "unresolvable"
} else := "proven"

any_inherit(group) if {
	some job in group
	privilege(job).secretsInherit == true
} else := false

merged_token_write_source(group) := "declared" if {
	some job in group
	privilege(job).tokenWriteSource == "declared"
} else := "default" if {
	some job in group
	privilege(job).tokenWriteSource == "default"
} else := "none"

merged_persisted_credentials(group) := "proven" if {
	some job in group
	privilege(job).persistedCredentials == "proven"
} else := "absent"

environment_job(group) := group[i] if {
	files := [object.get(job, "originFile", "") | some job in group]
	first := min(files)
	i := min({k | files[k] == first})
}

# secrets: GitHub names every distinct X in ${{ secrets.X }} across scripts,
# step with values and job variables/env values (GITHUB_TOKEN excluded: it
# is the token, handled by tokenWrite). GitLab names the settings variables
# in scope of the job. Total by construction: the final else covers every
# provider this module does not special-case.
#
# Two passes, not one regex over the whole text: a single greedy
# `\$\{\{[^}]*\bsecrets\.(...)` scan backtracks to the LAST secrets.X
# before the first "}", so "${{ secrets.A || secrets.B }}" would yield
# only B. The first pass isolates each whole "${{ ... }}" expression
# (non-overlapping by construction, so two expressions on one line stay
# separate); the second pass runs inside each isolated expression, where
# find_all_string_submatch_n's "all" correctly returns every secrets.X in
# it, including more than one in the same expression.
#
# The second pass reads both member forms, secrets.X and the bracket form
# secrets['X'] / secrets["X"].
secrets(job) := sort({name |
	input.pipeline.provider == "github"
	some expr in github_expressions(job)
	some m in regex.find_all_string_submatch_n(`\bsecrets(?:\.([A-Za-z_][A-Za-z0-9_]*)|\[\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*\])`, expr, -1)
	name := concat("", [m[1], m[2]])
	name != "GITHUB_TOKEN"
}) if {
	input.pipeline.provider == "github"
} else := sort({v.name |
	some v in object.get(input.pipeline, "settingsVariables", [])
	variable_in_scope(v, job)
	secret_variable(v)
}) if {
	input.pipeline.provider == "gitlab"
} else := []

# protectedSecrets: the names (never the values) of the GitLab settings
# variables in scope of the job that are also protected, so the assembler
# can drop them for fork entries. A plain set comprehension, not an
# if/else rule: it is always defined (empty on GitHub, or when nothing
# matches), no default branch needed.
protected_secrets(job) := sort({v.name |
	input.pipeline.provider == "gitlab"
	some v in object.get(input.pipeline, "settingsVariables", [])
	variable_in_scope(v, job)
	v.protected == true
})

# secret_variable: a GitLab settings variable is a secret when it is
# protected or masked. A plain variable (DOCKER_DRIVER and the like) is
# configuration, not a secret.
secret_variable(v) if v.protected == true

secret_variable(v) if v.masked == true

# variable_in_scope: the variable's environment scope covers the job: "*"
# (every environment), the job's own environment, or a wildcard scope
# ("review/*") matching it. The empty delimiter list is GitLab's own glob
# semantics for this scope: "*" matches any characters, including "/", so
# "review/*" covers "review/a/b", not just the one segment past the slash.
variable_in_scope(v, job) if v.environment == "*"

variable_in_scope(v, job) if v.environment == object.get(job, "environment", "")

variable_in_scope(v, job) if {
	contains(v.environment, "*")
	glob.match(v.environment, [], object.get(job, "environment", ""))
}

github_expressions(job) := {expr |
	some text in job_texts_and_env(job)
	some expr in regex.find_n(`\$\{\{[^}]*\}\}`, text, -1)
}

# secretsState: unresolvable when the list of secrets cannot be complete.
# GitLab: the settings-variable listing could not be fetched
# authoritatively. GitHub: an expression reads the whole secrets context
# (toJSON(secrets), or secrets bare, without a member), which exposes every
# secret of the repository, and no list of names can enumerate them.
secrets_state(job) := "unresolvable" if {
	input.pipeline.provider == "gitlab"
	object.get(input.pipeline, "settingsVariablesKnown", false) == false
} else := "unresolvable" if {
	input.pipeline.provider == "github"
	some expr in github_expressions(job)
	regex.match(`(^|[^.\w])secrets\s*([^.\[\w\s]|$)`, expr)
} else := "proven"

# job_texts_and_env: every text a secret reference can sit in. Step if:
# expressions are included here (unlike job_texts): a secret named in an
# if: is resolved by the runner for the job, so the job holds it.
job_texts_and_env(job) := array.concat(
	array.concat(job_texts(job), object.get(job, "scriptIfs", [])),
	array.concat(obj_values(object.get(job, "variables", {})), obj_values(object.get(job, "localVariables", {}))),
)

# obj_values: there is no object.values builtin in OPA v1; a comprehension
# over the map's own entries is the standard substitute.
obj_values(obj) := [v | some _, v in obj]

all_write_scopes := ["actions", "contents", "deployments", "id-token", "packages", "pull-requests", "security-events"]

# tokenWrite: a single function with clear, mutually exclusive guards
# (provider, then permissions shape), closed by an unconditional default,
# so it is total and can never leave privilege undefined. GitHub: the
# write-all shortcut expands to every scope; an explicit permissions map
# yields its write-level keys; no permissions block at all is the
# permissive repository default. GitLab: CI_JOB_TOKEN cannot push, so
# contents:write requires a positive signal, either a protected
# CI_PUSH_TOKEN variable in scope or a script that runs git push.
token_write(job) := all_write_scopes if {
	input.pipeline.provider == "github"
	object.get(job, "permissions", null) == "write-all"
} else := sort({scope |
	input.pipeline.provider == "github"
	perms := object.get(job, "permissions", null)
	is_object(perms)
	some scope, level in perms
	level == "write"
}) if {
	input.pipeline.provider == "github"
	is_object(object.get(job, "permissions", null))
} else := ["contents", "packages"] if {
	input.pipeline.provider == "github"
	object.get(job, "permissions", null) == null
} else := ["contents"] if {
	input.pipeline.provider == "gitlab"
	gitlab_contents_write(job)
} else := []

gitlab_contents_write(job) if {
	some v in object.get(input.pipeline, "settingsVariables", [])
	variable_in_scope(v, job)
	v.name == "CI_PUSH_TOKEN"
	v.protected == true
}

gitlab_contents_write(job) if {
	some line in object.get(job, "scripts", [])
	contains(line, "git push")
}

# tokenWriteSource: whether tokenWrite above is a real declaration
# ("declared": an explicit permissions object, or the write-all
# shortcut), a guess ("default": no permissions block at all, the
# permissive repository-default assumption), or neither ("none": GitLab,
# or a GitHub string shortcut other than write-all, e.g. read-all). Total
# by construction, the final else covers everything else. An assumed
# token write must not read as proven, so impacts that depend
# on it (writes_repo, and signs_or_releases when derived from the token)
# key their state off this, via token_dependent_state below.
token_write_source(job) := "declared" if {
	input.pipeline.provider == "github"
	object.get(job, "permissions", null) == "write-all"
} else := "declared" if {
	input.pipeline.provider == "github"
	is_object(object.get(job, "permissions", null))
} else := "default" if {
	input.pipeline.provider == "github"
	object.get(job, "permissions", null) == null
} else := "none"

# token_dependent_state: the state an impact gets when its only evidence
# that the job holds the write it needs is tokenWrite itself. A guessed
# (default) token write downgrades the impact to unresolvable; any real
# signal (declared, or none at all, which only fires impact rules that
# never reach here) stays proven.
token_dependent_state(job) := "unresolvable" if {
	token_write_source(job) == "default"
} else := "proven"

persisted_credentials(job) := "proven" if {
	input.pipeline.provider == "github"
	some action in object.get(job, "uses", [])
	startswith(action.uses, "actions/checkout@")
	not object.get(object.get(action, "with", {}), "persist-credentials", true) in {false, "false"}
	count(object.get(job, "scripts", [])) > 0
} else := "absent"

# environment.protected: unknown on GitHub always (the IR has no
# environment-protection data for that provider). On GitLab, true when
# either a protected branch shares the environment's name or a settings
# variable scoped to it is protected; unknown otherwise. The two signals
# are boolean partial rules ORed together, never a value-returning rule
# with two bodies, so there is no risk of conflicting outputs.
environment_protected(job) := "true" if {
	input.pipeline.provider == "gitlab"
	env := object.get(job, "environment", "")
	env != ""
	environment_protected_signal(env)
} else := "unknown"

environment_protected_signal(env) if {
	some b in object.get(input.pipeline, "branches", [])
	b.name == env
	b.protected == true
}

environment_protected_signal(env) if {
	some v in object.get(input.pipeline, "settingsVariables", [])
	v.environment == env
	v.protected == true
}

# ------------------------------------------------------------------- impact

impact(job) := [i | some i in impact_set(job)]

impact_set(job) := publishes(job) | deploys(job) | writes_repo(job) | signs_or_releases(job)

# Config comes from input.config.cachePoisoning: ReleaseWorkflowsMustNotRestoreUntrustedCache
# is the control name, but control/task.go writes its yaml under the
# "cachePoisoning" key (see policies/cache_poisoning.rego, which reads the
# same input.config.cachePoisoning.publishActions/publishScriptPatterns),
# not under the control's own name. Reusing that key keeps one operator-
# configured publish inventory for both rules instead of two to keep in
# sync.
cache_cfg := object.get(input.config, "cachePoisoning", {})

publish_patterns := object.get(cache_cfg, "publishScriptPatterns", [
	`npm publish`, `twine upload`, `cargo publish`, `gem push`, `docker push`,
	`mvn deploy`, `gradle publish`, `goreleaser release`, `helm push`,
])

publish_actions := object.get(cache_cfg, "publishActions", [
	"softprops/action-gh-release", "pypa/gh-action-pypi-publish", "docker/build-push-action",
	"JS-DevTools/npm-publish", "goreleaser/goreleaser-action", "ncipollo/release-action",
])

# publishScriptExcludePatterns: verification-only forms that veto a
# publish-script match on the same line, they never publish anything.
# Defaults mirror defaultConfig/.plumber.yaml's cachePoisoning block.
publish_script_exclude_patterns := object.get(cache_cfg, "publishScriptExcludePatterns", [
	`(?i)--dry-run`, `(?i)publishToMavenLocal`,
])

excluded(line) if {
	some pat in publish_script_exclude_patterns
	regex.match(pat, line)
}

# The exclusion applies to the whole script entry, as in
# policies/cache_poisoning.rego; only the evidence is narrowed to the
# matching line.
publishes(job) := {{"kind": "publishes", "state": "proven", "evidence": evidence} |
	some line in object.get(job, "scripts", [])
	some pat in publish_patterns
	regex.match(pat, line)
	not excluded(line)
	evidence := evidence_line(line, [l | some l in split(line, "\n"); regex.match(pat, l)])
} | {{"kind": "publishes", "state": state, "evidence": action.uses} |
	some action in object.get(job, "uses", [])
	some name in publish_actions
	startswith(action.uses, concat("", [name, "@"]))
	state := publish_action_state(action, name)
}

# publish_action_state: docker/build-push-action's own default for push:
# is false (it never pushes unless told to), unlike every other publish
# action here, which has no such input at all and so always counts once
# named. On docker/build-push-action a literal true (or the YAML string
# "true") is proven, an expression ("${{ ... }}", decided at run time) is
# unresolvable, and anything else (absent, false, "false") yields no value,
# so no impact. On any other action only an explicit false ("false")
# removes it. The bodies are mutually exclusive by their guards.
publish_action_state(action, name) := "proven" if {
	name == "docker/build-push-action"
	push_value(action) in {true, "true"}
}

publish_action_state(action, name) := "unresolvable" if {
	name == "docker/build-push-action"
	v := push_value(action)
	is_string(v)
	contains(v, "${{")
}

publish_action_state(action, name) := "proven" if {
	name != "docker/build-push-action"
	not push_value(action) in {false, "false"}
}

# push_value: the action's push: input, null when absent.
push_value(action) := object.get(object.get(action, "with", {}), "push", null)

deploy_pattern := `kubectl\s+apply|helm\s+upgrade|terraform\s+apply|aws\s.*\sdeploy|gcloud\s.*\sdeploy|az\s.*\sdeploy|ansible-playbook|ssh\s.*deploy|rsync\s.*\s[^\s]+:`

deploys(job) := {{"kind": "deploys", "state": "proven", "evidence": sprintf("environment: %s", [env])} |
	env := object.get(job, "environment", "")
	env != ""
} | {{"kind": "deploys", "state": "proven", "evidence": evidence} |
	some line in object.get(job, "scripts", [])
	regex.match(deploy_pattern, line)
	evidence := evidence_line(line, [l | some l in split(line, "\n"); regex.match(deploy_pattern, l)])
}

repo_writer_actions := {"peter-evans/create-pull-request", "stefanzweifel/git-auto-commit-action", "EndBug/add-and-commit"}

writes_repo(job) := {{"kind": "writes_repo", "state": token_dependent_state(job), "evidence": ev} |
	"contents" in token_write(job)
	some ev in repo_write_evidence(job)
}

repo_write_evidence(job) := {evidence_line(line, [l | some l in split(line, "\n"); contains(l, "git push")]) |
	some line in object.get(job, "scripts", [])
	contains(line, "git push")
} | {action.uses |
	some action in object.get(job, "uses", [])
	some name in repo_writer_actions
	startswith(action.uses, concat("", [name, "@"]))
}

signing_actions := {"sigstore/cosign-installer", "slsa-framework/slsa-github-generator", "actions/attest-build-provenance"}

signs_or_releases(job) := {{"kind": "signs_or_releases", "state": token_dependent_state(job), "evidence": "permissions: id-token: write"} |
	"id-token" in token_write(job)
	is_object(object.get(job, "permissions", null))
} | {{"kind": "signs_or_releases", "state": token_dependent_state(job), "evidence": "permissions: write-all"} |
	object.get(job, "permissions", null) == "write-all"
} | {{"kind": "signs_or_releases", "state": "proven", "evidence": action.uses} |
	some action in object.get(job, "uses", [])
	some name in signing_actions
	startswith(action.uses, concat("", [name, "@"]))
}

# -------------------------------------------------------------------- feeds

# feeds: names of jobs that consume an artifact this job produces, plus
# jobs that restore a cache this job saves, plus jobs that list this job
# in needs. Sorted so the output is deterministic regardless of job
# iteration order.
feeds(job) := sort({other.name |
	some other in input.pipeline.jobs
	other.name != job.name
	feeds_job(job, other)
})

feeds_job(job, other) if job.name in object.get(other, "needs", [])

feeds_job(job, other) if {
	some produced in object.get(job, "artifacts", [])
	produced.mode == "produce"
	some consumed in object.get(other, "artifacts", [])
	consumed.mode == "consume"
	artifact_matches(produced, consumed)
	same_workflow_if_github(job, other)
}

artifact_matches(produced, consumed) if object.get(consumed, "name", "") == ""

artifact_matches(produced, consumed) if object.get(consumed, "name", "") == object.get(produced, "name", "")

# same_workflow_if_github: a GitHub upload-artifact/download-artifact
# name is only unique within the one workflow run that declared it, so
# two jobs from different workflow files that happen to share an
# artifact name must not be wired together. GitLab artifacts are scoped
# to the job/pipeline, not a workflow file, so this never restricts
# GitLab. Caches are unaffected (they stay cross-workflow, intentionally
# shared) because this guard is only added to the artifact branch above.
same_workflow_if_github(job, other) if input.pipeline.provider != "github"

same_workflow_if_github(job, other) if {
	input.pipeline.provider == "github"
	object.get(job, "originFile", "") == object.get(other, "originFile", "")
}

feeds_job(job, other) if {
	some saved in object.get(job, "caches", [])
	saved.mode in {"save", "both"}
	some restored in object.get(other, "caches", [])
	restored.mode in {"restore", "both"}
	restored.key == saved.key
	restored.key != ""
}
