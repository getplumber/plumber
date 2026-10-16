# Package situation derives the per-job facts no control computes: what a
# job holds (privilege), what it can change (impact), which jobs it feeds,
# and the trigger structure an attack path needs, a fork pull request
# reaching the job and a push to the default branch running it, plus the
# repository's exposure and the jobs each include shapes. It emits no
# finding: the entry of an attack path is the finding that reports it.
# Every fact carries evidence so the explanation can quote it. States:
# proven, unknown. Absence of a fact is absence from the output.
package situation

import rego.v1

result := {
	"exposure": exposure,
	"jobs": jobs,
	"defaultBranch": default_branch_name,
	"provider": object.get(input.pipeline, "provider", ""),
	"includes": includes,
}

exposure := v if {
	v := input.pipeline.visibility
	v != ""
} else := "unknown"

# jobs is keyed by job name, and two jobs can share one: workflow files
# "ci.yml" and "ci.yaml" both give the namespace "ci". Keying each job
# separately would raise an object-key conflict and fail the whole
# evaluation, so the facts of every job carrying a name are merged into
# one fact set under it: trigger facts and impact as set unions, feeds and
# the kinds of each feed as sorted unions.
job_names := {job.name | some job in input.pipeline.jobs}

jobs := {name: facts(named_jobs(name)) | some name in job_names}

# named_jobs keeps the input order, so a choice of one job in the group
# (the environment, in merged_privilege) is deterministic.
named_jobs(name) := [job | some job in input.pipeline.jobs; job.name == name]

facts(group) := {
	"forkPR": [e | some e in {e | some job in group; some e in fork_pr(job)}],
	"privilegedTriggers": sort({t | some job in group; some t in privileged_triggers_of(job)}),
	"refTriggers": sort({t | some job in group; some t in ref_triggers_of(job)}),
	"push": [e | some e in {e | some job in group; some e in unprotected_push(job)}],
	"privilege": merged_privilege(group),
	"impact": [i | some i in {i | some job in group; some i in impact(job)}],
	"feeds": sort({f | some job in group; some f in feeds(job)}),
	"feedsVia": {f: sort({k | some job in group; some k in object.get(feeds_via(job), f, [])}) |
		some job in group
		some f in feeds(job)
	},
	"caches": sort({cache_fact(c) | some job in group; some c in object.get(job, "caches", [])}),
	"dead": every_dead(group),
	"inert": inert_reason(group),
	"ownImage": every_own_image(group),
	"callers": sort([c | some c in {caller_fact(job, c) | some job in group; some c in object.get(job, "callers", [])}]),
	"cacheScopes": sort({sc | some job in group; some sc in save_scopes(job)}),
	"restoresCache": count({job | some job in group; restores_cache(job)}) > 0,
	"uploads": any_upload(group),
	"gate": merged_gate(group),
}

# any_upload: some job sharing the name produces an artifact (an
# actions/upload-artifact or actions/upload-pages-artifact step on GitHub,
# an artifacts: block on GitLab): code on its runner can poison what a
# later run downloads.
any_upload(group) if {
	some job in group
	some a in object.get(job, "artifacts", [])
	a.mode == "produce"
} else := false

# _gate_ranks orders the gate classes ir.ClassifyGates stores on a job
# (job.gate) from the outsider's side: the lower, the easier to get in.
_gate_ranks := {"outsider": 0, "unknown": 1, "maintainer_approved": 2, "same_repo": 3}

# merged_gate: the weakest gate among the jobs sharing the name (an
# outsider let in by one of them is let in), the first in input order on
# a tie; null when none of them carries one (no privileged trigger, or
# GitLab). A job carrying a privileged trigger but no gate was never
# classified: it counts as an outsider's.
merged_gate(group) := g if {
	gates := [job_gate(job) | some job in group; job_gated(job)]
	count(gates) > 0
	lowest := min({object.get(_gate_ranks, x.class, 0) | some x in gates})
	g := [x | some x in gates; object.get(_gate_ranks, x.class, 0) == lowest][0]
} else := null

# job_gated: the job carries a gate, or a privileged trigger that should
# have one.
job_gated(job) if object.get(job, "gate", null) != null

job_gated(job) if count(privileged_triggers_of(job)) > 0

# job_gate: the job's own gate, an outsider's when it has none.
job_gate(job) := job.gate if object.get(job, "gate", null) != null
else := {"class": "outsider"}

# every_own_image: every job sharing the name runs in a container, and
# every image it resolves to (through its matrix, or each caller of a
# reusable workflow, Job.matrixImages) is the repository's own image: under
# its owner's namespace of the GitHub container registry
# (ghcr.io/<owner>/..., case-insensitive), the image analogue of an action
# of the repository's organization.
every_own_image(group) if {
	every job in group {
		images := job_images(job)
		count(images) > 0
		every img in images {
			own_image(img)
		}
	}
} else := false

job_images(job) := job.matrixImages if {
	count(object.get(job, "matrixImages", [])) > 0
} else := [job.image] if {
	is_object(object.get(job, "image", null))
} else := []

own_image(img) if {
	owner := lower(split(object.get(input.pipeline, "projectPath", ""), "/")[0])
	owner != ""
	startswith(lower(image_registry_and_name(img)), concat("", ["ghcr.io/", owner, "/"]))
}

image_registry_and_name(img) := concat("/", [img.registry, img.name]) if {
	not object.get(img, "registry", "") in {"", "unknown"}
} else := object.get(img, "name", "")

# every_dead: every job sharing the name is dead (a constant false if:,
# the collector's Job.Dead) or carries a non-empty inert reason
# (MarkInert, Job.Inert): either way none of them ever runs and no path
# enters it.
every_dead(group) if {
	every job in group {
		job_cannot_run(job)
	}
} else := false

job_cannot_run(job) if object.get(job, "dead", false) == true

job_cannot_run(job) if object.get(job, "inert", "") != ""

# inert_reason: the inert reason a path report prints under the job's
# findings, "" unless every job sharing the name is inert (the same
# condition every_dead tests): a group with a live member still runs
# through it, so it must carry no reason at all, never the first one
# found. Deterministic the same way merged_privilege's environment_job
# is (smallest originFile, the first such job in input order on a tie),
# for the rare case of two same-named jobs (e.g. ci.yml and ci.yaml)
# disagreeing on why they cannot run.
inert_reason(group) := r if {
	every job in group {
		object.get(job, "inert", "") != ""
	}
	files := [object.get(job, "originFile", "") | some job in group]
	first := min(files)
	i := min({k | files[k] == first})
	r := object.get(group[i], "inert", "")
} else := ""

# cache_fact: one cache the job restores, saves or both, with the step that
# declares it, so a path can match what a release job restores against
# what another job saves (the same rules as the cache edges of feeds_by).
cache_fact(c) := {
	"key": object.get(c, "key", ""),
	"family": cache_family(c),
	"mode": object.get(c, "mode", ""),
	"prefix": object.get(c, "prefix", false),
	"uses": object.get(c, "uses", ""),
	"line": object.get(c, "line", 0),
	"parts": object.get(c, "parts", {}),
}

# cache_family: the name a reader recognizes for the cache (the
# collector's family), the key itself when the collector gives none. Key
# is what the edges match on; family is what a path prints.
cache_family(c) := f if {
	f := object.get(c, "family", "")
	f != ""
} else := object.get(c, "key", "")

# ------------------------------------------------------------ cache scope

# cache_scopes: the refs GitHub files what the job's runs save to the
# cache under, the scope a restore can read from: "default" (a push to the
# default branch, a schedule, a dispatch, and every event that runs on the
# default branch: workflow_run, pull_request_target, issue_comment...),
# "tag" (a tag push, a release), "pull_request" (the pull request's merge
# ref), "merge_group" (a merge queue's ref). A run reads its own ref's
# caches and the default branch's, so a save in any scope but "default"
# reaches runs of that same kind of ref only. A job-level if: of the shape
# github.event_name == '<event>' narrows the job to that event, != removes
# it. "any" when the job carries no trigger at all (GitLab, whose cache
# scoping this does not model, or a job built without triggers).
cache_scopes(job) := {"any"} if {
	count(effective_triggers(job)) == 0
} else := {sc | some t in gated_triggers(job); some sc in trigger_cache_scopes(job, t)}

# effective_triggers: the job's own events; a reusable workflow
# (workflow_call) runs under each caller's events instead (job.callers).
effective_triggers(job) := {t | some t in object.get(job, "triggers", []); t != "workflow_call"} | {t |
	"workflow_call" in object.get(job, "triggers", [])
	some c in object.get(job, "callers", [])
	some t in object.get(c, "triggers", [])
}

gated_triggers(job) := {t} if {
	m := regex.find_all_string_submatch_n(`^\s*(?:\$\{\{)?\s*github\.event_name\s*==\s*'([a-z_]+)'\s*(?:\}\})?\s*$`, object.get(job, "if", ""), 1)
	count(m) > 0
	t := m[0][1]
	t in effective_triggers(job)
} else := effective_triggers(job) - {t} if {
	m := regex.find_all_string_submatch_n(`^\s*(?:\$\{\{)?\s*github\.event_name\s*!=\s*'([a-z_]+)'\s*(?:\}\})?\s*$`, object.get(job, "if", ""), 1)
	count(m) > 0
	t := m[0][1]
} else := effective_triggers(job)

trigger_cache_scopes(job, "push") := push_cache_scopes(job)

trigger_cache_scopes(_, "release") := {"tag"}

trigger_cache_scopes(_, "pull_request") := {"pull_request"}

trigger_cache_scopes(_, "pull_request_review") := {"pull_request"}

trigger_cache_scopes(_, "pull_request_review_comment") := {"pull_request"}

trigger_cache_scopes(_, "merge_group") := {"merge_group"}

trigger_cache_scopes(_, t) := {"default"} if not t in {"push", "release", "pull_request", "pull_request_review", "pull_request_review_comment", "merge_group"}

# push_cache_scopes: a push the filters let reach the default branch saves
# in its scope; a tag filter (or no filter at all, every ref) also in a
# tag's. A push only to other branches saves in a branch scope no other
# kind of run reads: "branch".
push_cache_scopes(job) := out if {
	tags := {"tag" |
		count(array.concat(object.get(job, "pushTags", []), object.get(job, "pushTagsIgnore", []))) > 0
	} | {"tag" | github_push_filters_absent(job)}
	branch := {"default" | github_push_trigger_state(job) != "absent"} | {"branch" |
		github_push_trigger_state(job) == "absent"
		not github_push_tags_only(job)
	}
	out := tags | branch
}

# cache_write_trusted: the events GitHub lets create or overwrite caches in
# the default branch's scope. Any other event that runs on the default
# branch (pull_request_target, issue_comment, workflow_run...) gets
# read-only cache access unless its cache-mode grants write.
cache_write_trusted := {
	"push", "workflow_dispatch", "repository_dispatch", "delete",
	"registry_package", "page_build", "schedule",
}

# cache_mode(job): the access the job's cache-mode grants (read, write,
# write-only, none), "" when it declares none GitHub would run.
cache_mode(job) := object.get(job, ["cacheMode", "effective"], "")

# saves_under(job, t): a run of the job on event t can save a cache. An
# explicit grant decides; without one, a trusted trigger saves and so does
# an event that runs on its own ref (a pull request's, a tag's, a merge
# queue's), while a low-trust event on the default branch only reads.
saves_under(job, _) if cache_mode(job) in {"write", "write-only"}

saves_under(job, t) if {
	not cache_mode(job) in {"read", "none", "write", "write-only"}
	t in cache_write_trusted | {"pull_request", "pull_request_review", "pull_request_review_comment", "release", "merge_group"}
}

# save_scopes: the scopes the job's runs save under, cache_scopes narrowed
# to the events that can save.
save_scopes(job) := {"any"} if {
	count(effective_triggers(job)) == 0
} else := {sc | some t in gated_triggers(job); saves_under(job, t); some sc in trigger_cache_scopes(job, t)}

# restores_cache(job): the job declares a cache it restores and its
# cache-mode leaves restoring on.
restores_cache(job) if {
	not cache_mode(job) in {"write-only", "none"}
	some c in object.get(job, "caches", [])
	c.mode in {"restore", "both"}
}

# cache_scope_reaches(saver, restorer): the restorer can read what the
# saver saves: a default-branch save reaches every run, a save in another
# scope reaches runs of that same scope, and an unknown scope on either
# side is not ruled out. The restorer has to restore at all.
cache_scope_reaches(saver, restorer) if {
	restores_cache(restorer)
	_scope_reaches(saver, restorer)
}

_scope_reaches(saver, _) if "any" in save_scopes(saver)

_scope_reaches(saver, restorer) if {
	count(save_scopes(saver)) > 0
	"any" in cache_scopes(restorer)
}

_scope_reaches(saver, _) if "default" in save_scopes(saver)

_scope_reaches(saver, restorer) if {
	some sc in save_scopes(saver) & cache_scopes(restorer)
	sc != "default"
}

# ---------------------------------------------------------------- triggers

origin(job) := {"file": object.get(job, "originFile", ""), "line": object.get(job, "originLine", 0)}

entry(kind, state, evidence, subject, job) := object.union(
	{"kind": kind, "state": state, "evidence": evidence, "subject": subject, "cacheScopes": sort(entry_cache_scope(kind, job))},
	origin(job),
)

# _entry_events: the event of the run that proves an entry of this kind,
# for the kinds whose proving run is one event whatever other trigger the
# job also carries: a fork pull request, or a base-context trigger (the
# caller's secrets and write token).
_entry_events := {
	"fork_pr": "pull_request",
	"pr_target": "pull_request_target",
	"issue_comment": "issue_comment",
	"workflow_run": "workflow_run",
	"pull_request_review": "pull_request_review",
	"pull_request_review_comment": "pull_request_review_comment",
	"discussion": "discussion",
	"issues": "issues",
}

# entry_cache_scope: the scopes the run that executes an entry of this
# kind saves its cache under. A kind proven by one event (_entry_events)
# saves under that event's scope (trigger_cache_scopes: a fork pull
# request or a review event in the pull request's merge ref, a
# base-context event in the default branch's), and only when GitHub lets
# that event save (saves_under: a low-trust event on the default branch
# reads only, unless the job's cache-mode grants write). Every other entry
# (mutable_dependency, unprotected_push, and any kind this policy does not
# special-case) takes the job's own save_scopes, since nothing about the
# entry itself narrows which of the job's runs it holds in.
entry_cache_scope(kind, job) := {sc |
	t := _entry_events[kind]
	saves_under(job, t)
	some sc in trigger_cache_scopes(job, t)
} if kind in object.keys(_entry_events)
else := save_scopes(job)

# fork_pr: GitHub pull_request without a same-repo guard; GitLab MR pipelines.
# A fork pull request run has no gate to evaluate, so its entry is always
# an outsider's (actor).
fork_pr(job) := {object.union(entry("fork_pr", "proven", "on: pull_request", "pull_request", job), {"actor": "outsider"})} if {
	"pull_request" in object.get(job, "triggers", [])
	not same_repo_guard(job)
} else := {object.union(entry("fork_pr", "proven", "rules: merge_request_event", "merge_request_event", job), {"actor": "outsider"})} if {
	input.pipeline.provider == "gitlab"
	merge_request_job(job)
	not forks_forbidden
} else := set()

# privileged_triggers: the events that run a workflow in the base
# repository's context, its secrets and write token included, whoever
# opened the pull request: pull_request_target plus the events
# policies/dangerous_triggers.rego (ISSUE-802) watches. A job carrying one
# keeps its privilege on a fork run whatever it checks out or guards, so
# the fact is the trigger alone.
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

privileged_triggers_of(job) := {t |
	some t in object.get(job, "triggers", [])
	t in privileged_triggers
}

# ref_triggers: the events that run a workflow on a branch or a tag of the
# repository itself, never on a pull request's merge ref, so what such a
# run saves to the cache is in that ref's scope.
ref_triggers := {"push", "schedule", "release", "workflow_dispatch"}

ref_triggers_of(job) := {t |
	some t in object.get(job, "triggers", [])
	t in ref_triggers
}

# same_repo_guard_patterns: the family-1 (same-repository, non-fork
# pull-request) guard forms, the ones policies/dangerous_triggers.rego
# (ISSUE-802) and policies/pull_request_target_head_checkout.rego
# (ISSUE-804) also recognize: the operands in either order, and both the
# ==false and !=true spellings of the fork check.
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

# merge_request_iid_absent: a condition comparing $CI_MERGE_REQUEST_IID (or
# its _ID spelling) to null or to the empty string, double or single
# quoted: a test for its absence, true outside a merge request pipeline.
merge_request_iid_absent := `\$CI_MERGE_REQUEST_I?ID\s*==\s*(null|""|'')`

# $CI_MERGE_REQUEST_IID (or its _ID spelling) is only ever set on a
# merge-request pipeline, so a rule gated on its bare presence is the same
# idiom as an explicit $CI_PIPELINE_SOURCE == "merge_request_event", read
# the way an operator would. A rule that instead compares the variable to
# null or the empty string is testing for its ABSENCE, the opposite meaning, so that
# spelling is excluded here; it can still include the job through the
# "exclude then run" idiom below, the same shape gitlab_rules_run_on's
# second body already recognizes for $CI_PIPELINE_SOURCE.
merge_request_job(job) if {
	some rule in object.get(job, "rules", [])
	object.get(rule, "when", "") != "never"
	regex.match(`\$CI_MERGE_REQUEST_I?ID\b`, object.get(rule, "if", ""))
	not regex.match(merge_request_iid_absent, object.get(rule, "if", ""))
}

merge_request_job(job) if {
	rules := object.get(job, "rules", [])
	some i, ri in rules
	regex.match(merge_request_iid_absent, object.get(ri, "if", ""))
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

# evidence_line: the evidence quoted for a match inside a script, the
# first matching line of the block (the caller passes the matching
# lines, in order), trimmed and cut to 200 characters. When no single
# line matches (a match spanning lines), the whole text, trimmed and cut.
# Total: both branches always produce a string.
evidence_line(text, matching) := short_evidence(matching[0]) if {
	count(matching) > 0
} else := short_evidence(text)

short_evidence(s) := substring(trim_space(s), 0, 200)

# job_texts: the shell sinks (run scripts) and the step with values, each
# returned whole, no comment handling: the secrets scan wants the whole
# text. A step if: is evaluated by the runner, never handed to a shell,
# so it is not scanned here.
job_texts(job) := array.concat(object.get(job, "scripts", []), job_with_values(job))

# job_with_values: the step with values alone, a string per with: entry.
job_with_values(job) := [v |
	some action in object.get(job, "uses", [])
	some _, v in object.get(action, "with", {})
	is_string(v)
]

# include_targets_job: the job carries the include's file directly, or no
# job in the pipeline does and it is therefore attached everywhere. The
# per-job branch can only ever match for a "local" include, whose Source
# really is a file path: a "project" include's Source is the other
# project's path (gitlab/gitlab_ir.go's GitlabIncludeOrigin.Location), not
# a file, and the GitLab collector sets every job's OriginFile to the
# scanned project's own CI config path (gitlab/gitlab_ir.go), never to an
# include's source. So today, with the collector as it stands, a
# "project" include always falls through to the second body below and is
# attached to every job; that is harmless (a superset, never a false
# negative) but it means no one should rely on the per-job match actually
# narrowing anything until the collector carries a local include's real
# origin file (PR #513 review).
include_targets_job(inc, job) if object.get(job, "originFile", "") == inc.source

include_targets_job(inc, job) if not _any_job_carries_include_file(inc.source)

_any_job_carries_include_file(source) if {
	some other in input.pipeline.jobs
	object.get(other, "originFile", "") == source
}

# includes: every pipeline include with a source, with the subject a
# job-less include finding names ("source@ref") and the jobs the include
# shapes (include_targets_job), so the finding can start a path on each.
includes := [object.union({
	"subject": include_subject(inc),
	"source": inc.source,
	"jobs": sort({job.name | some job in input.pipeline.jobs; include_targets_job(inc, job)}),
}, include_origin(inc)) |
	some inc in object.get(input.pipeline, "includes", [])
	object.get(inc, "source", "") != ""
]

# include_subject: the include path plus its ref, the subject a job-less
# ISSUE-404 or ISSUE-402 finding names, which its include is matched on.
include_subject(inc) := sprintf("%s@%s", [inc.source, inc.ref]) if object.get(inc, "ref", "") != "" else := inc.source

include_origin(inc) := {"file": f, "line": object.get(inc, "originLine", 0)} if {
	f := object.get(inc, "originFile", "")
	f != ""
} else := {}

# default_branch_name: input.pipeline.defaultBranch, safe against the
# field being entirely absent from the input, which is what an empty
# Go string collapses to once json's omitempty strips it before the
# engine builds the OPA input. Reading the bare path directly would
# make every expression built from it (a set literal, an array passed
# to sprintf) undefined rather than built with an empty string, so
# every reader of the default branch name goes through this instead.
default_branch_name := object.get(input.pipeline, "defaultBranch", "")

# unprotected_push: a push-triggered job while the default branch is
# unprotected. GitHub's state comes from github_push_trigger_state below,
# which reads Job.PushBranches/PushBranchesIgnore/PushTags/PushTagsIgnore
# (PR #513 review) to tell whether the push trigger's own filters actually
# reach the default branch, before folding in the branch's protection; a job
# whose filters rule the default branch out entirely (push_job below) never
# gets an entry at all. GitLab's push state here comes from an explicit
# rules: condition (an inclusive $CI_PIPELINE_SOURCE == "push", the
# "exclude then run" idiom, or the $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
# idiom and its variants, see gitlab_push_state/gitlab_rules_branch_state
# below), the no-rules default, or the legacy only:/except: keywords
# (gitlab_only_except_state). unprotected_push_decidable below draws the
# line on an unknown default branch name differently per provider: GitHub's
# default_branch_state needs the name to find a match in
# input.pipeline.branches, so without it there is nothing to resolve;
# GitLab's determination does not, and lands on unknown on its own
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

# push_entry_state: unknown when the provider's own trigger reading
# cannot be decided (GitLab's rules:, or GitHub's push filters carrying an
# expression); otherwise default_branch_state decides it (proven, protected
# or unknown per the branch's own protection). GitHub falls straight
# to default_branch_state once the filters are known to reach the default
# branch at all (push_job already excludes the case where they do not), so
# an unprotected default branch with no filter, or a filter that includes
# it, is now proven rather than forced unknown.
push_entry_state(job) := "unknown" if {
	input.pipeline.provider == "gitlab"
	gitlab_push_state(job) == "unknown"
} else := "unknown" if {
	input.pipeline.provider == "github"
	github_push_trigger_state(job) == "unknown"
} else := default_branch_state

push_entry_evidence(job) := sprintf("on push; default branch %s %s; push filter %s", [default_branch_name, default_branch_state, github_push_trigger_state(job)]) if {
	input.pipeline.provider == "github"
} else := sprintf("on push; default branch %s %s", [default_branch_name, push_entry_state(job)])

push_job(job) if {
	"push" in object.get(job, "triggers", [])
	input.pipeline.provider != "github"
}

push_job(job) if {
	"push" in object.get(job, "triggers", [])
	input.pipeline.provider == "github"
	github_push_trigger_state(job) != "absent"
}

push_job(job) if {
	input.pipeline.provider == "gitlab"
	gitlab_push_state(job) != "absent"
}

# github_push_trigger_state: whether the push trigger's own filters
# (Job.PushBranches/PushBranchesIgnore/PushTags/PushTagsIgnore) let a push
# to the default branch run the job, total and single-valued over any
# GitHub job:
#   - unknown: a filter entry is an unresolved workflow expression
#     ("${{"), which cannot be judged against a branch name statically;
#   - proven: no filter at all (push: with none of the four keys), or a
#     branches:/branches-ignore: filter that reaches the default branch
#     (github_push_branch_filter_state below decides which);
#   - absent otherwise: a branches:/branches-ignore: filter rules the
#     default branch out, or only tags:/tags-ignore: is set (a tag push,
#     or a filter that never admits a branch push at all, per GitHub: a
#     workflow that defines only a tag filter never runs on a branch push).
#
# glob.match is called throughout with ["/"] as the path delimiter: a
# single "*" does not cross a branch-name segment, "**" does, mirroring
# GitHub's own branches:/tags: glob semantics for those two wildcards.
# Two of GitHub's own quantifiers are not translated and are a documented
# divergence instead: GitHub reads "?" as "zero or one of the preceding
# character" and "+" as "one or more of the preceding character", while
# OPA's glob reads "?" as exactly one arbitrary character and "+" as a
# literal "+"; OPA's "{a,b}" alternation has no GitHub equivalent either.
# A character class ("[abc]") agrees between the two.
github_push_trigger_state(job) := "unknown" if {
	github_push_filter_has_expression(job)
} else := "proven" if {
	github_push_filters_absent(job)
} else := "absent" if {
	github_push_tags_only(job)
} else := github_push_branch_filter_state(job)

github_push_filter_has_expression(job) if {
	some v in array.concat(array.concat(array.concat(
		object.get(job, "pushBranches", []),
		object.get(job, "pushBranchesIgnore", []),
	), object.get(job, "pushTags", [])), object.get(job, "pushTagsIgnore", []))
	contains(v, "${{")
}

github_push_filters_absent(job) if {
	count(object.get(job, "pushBranches", [])) == 0
	count(object.get(job, "pushBranchesIgnore", [])) == 0
	count(object.get(job, "pushTags", [])) == 0
	count(object.get(job, "pushTagsIgnore", [])) == 0
}

# github_push_tags_only: a tag filter (tags: or tags-ignore:, either one)
# with no branch filter at all (neither branches: nor branches-ignore:).
# GitHub's own rule: defining only a tag filter means the workflow never
# runs on a branch push, tags-ignore-only reading exactly like tags-only
# (PR #513 review).
github_push_tags_only(job) if {
	count(object.get(job, "pushBranches", [])) == 0
	count(object.get(job, "pushBranchesIgnore", [])) == 0
	count(array.concat(object.get(job, "pushTags", []), object.get(job, "pushTagsIgnore", []))) > 0
}

# github_push_branch_filter_state(job): decides proven/absent once it is
# already known that a branch filter is present (pushBranches or
# pushBranchesIgnore is non-empty; github_push_trigger_state above never
# calls this otherwise). branches: is an allowlist: the default branch
# must be the last-matching pattern's positive match, or it is excluded,
# whatever pushBranchesIgnore separately holds (GitHub does not allow both
# on the same push: block, so pushBranches alone decides when present).
# branches-ignore: is a denylist: a last-matching PLAIN pattern excludes
# the default branch; a last-matching NEGATED ("!") pattern, or no match at
# all, lets it through.
github_push_branch_filter_state(job) := "proven" if {
	count(object.get(job, "pushBranches", [])) > 0
	_branch_filter_decision(object.get(job, "pushBranches", []), default_branch_name) == "included"
} else := "absent" if {
	count(object.get(job, "pushBranches", [])) > 0
} else := "absent" if {
	_branch_filter_decision(object.get(job, "pushBranchesIgnore", []), default_branch_name) == "included"
} else := "proven"

# _branch_filter_decision(patterns, name): GitHub walks branches:/
# branches-ignore: patterns in the order written and the LAST pattern that
# matches decides, a leading "!" negating that one pattern (PR #513
# review): ['**', '!main'] excludes main (the negated pattern matches
# last), ['!main', '**'] includes it (the plain catch-all matches last).
# "included"/"excluded" name the sign of that last match, not the final
# branches-ignore verdict (github_push_branch_filter_state above inverts
# it for the ignore list, where a plain match means excluded from the
# run, not included in it). "no_match" when nothing in the list matches
# the name at all, or the list is empty. Total: an if/else chain whose
# branches are mutually exclusive by construction (_last_matching_branch_
# pattern_index is single-valued, via max, so at most one sign can apply).
_branch_filter_decision(patterns, name) := "no_match" if {
	count(patterns) == 0
} else := "included" if {
	idx := _last_matching_branch_pattern_index(patterns, name)
	_branch_pattern_sign(patterns[idx]) == "positive"
} else := "excluded" if {
	idx := _last_matching_branch_pattern_index(patterns, name)
	_branch_pattern_sign(patterns[idx]) == "negative"
} else := "no_match"

# _last_matching_branch_pattern_index: the highest index of a pattern that
# matches name, undefined (not 0) when none does, so the else chain above
# falls through to "no_match" rather than mistaking "no match" for index 0.
_last_matching_branch_pattern_index(patterns, name) := max({i |
	some i, p in patterns
	_branch_pattern_matches(p, name)
})

_branch_pattern_matches(pattern, name) if glob.match(_branch_pattern_glob(pattern), ["/"], name)

_branch_pattern_sign(pattern) := "negative" if startswith(pattern, "!") else := "positive"

# _branch_pattern_glob: the glob to match against, the leading "!" of a
# negated pattern stripped (it marks the pattern, it is never part of it).
_branch_pattern_glob(pattern) := substring(pattern, 1, -1) if startswith(pattern, "!") else := pattern

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
# single-valued: proven, absent or unknown, never more than one.
#
# A bare name that is none of gitlab_push_branch_refs or
# gitlab_push_absent_refs names a branch other than the default: with
# the default branch known, that rules the push out (absent), since the
# name is confirmed to be some other, specific branch; with the default
# branch unknown, that same name might be the default branch under
# cover, so the outcome cannot be decided (unknown). A regex ref
# stays unknown regardless, for the same reason it is never
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
} else := "unknown"

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
# else unknown if any rule leaves it unknown, else absent. Total
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
} else := "unknown" if {
	some rule in object.get(job, "rules", [])
	object.get(rule, "when", "") != "never"
	_rule_branch_state(rule) == "unknown"
} else := "absent"

# _rule_branch_kind(if_text) classifies a single rule's if: text against the
# $CI_COMMIT_BRANCH idiom family, total and single-valued over any string
# (an if/else chain: exactly one of the five names always comes out,
# "none" when nothing below matches, including the never-an-inclusion
# "!=" and "!~" spellings). Kept separate from _rule_branch_state so the
# proven/unknown/no-value decision below never has to worry about two
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

# _rule_branch_state(rule): proven/unknown/no-value for one rule,
# built on the if/else-total _rule_branch_kind above. "direct_equal" is
# always proven (every push to the default branch sets $CI_COMMIT_BRANCH
# to its name, so the comparison is true exactly on that push); "bare"
# likewise (the variable is set, full stop, on every branch push including
# the default one); "regex" is always unknown (never matched
# statically, same as gitlab_ref_is_regex); "literal_equal" depends on
# whether the literal names the configured default branch (proven),
# some other, specific branch (no value: that rule contributes nothing,
# it is not evidence of a push to the default branch, but it is not
# unknown either), or cannot be judged because the default branch
# name itself is unknown (unknown); "none" (including the "!=" and
# "!~" spellings, which exclude the default branch rather than include it)
# never proves or leaves this fact unknown.
_rule_branch_state(rule) := "proven" if {
	_rule_branch_kind(object.get(rule, "if", "")) == "direct_equal"
} else := "proven" if {
	_rule_branch_kind(object.get(rule, "if", "")) == "literal_equal"
	default_branch_name != ""
	gitlab_branch_literal(object.get(rule, "if", "")) == default_branch_name
} else := "unknown" if {
	_rule_branch_kind(object.get(rule, "if", "")) == "literal_equal"
	default_branch_name == ""
} else := "unknown" if {
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
} else := "unknown"

# ---------------------------------------------------------------- privilege

privilege(job) := {
	"secrets": held_secrets(job),
	"secretsState": secrets_state(job),
	"secretsInherit": object.get(job, "secretsInherit", false),
	"allSecrets": all_secrets(job),
	"protectedSecrets": protected_secrets(job),
	"tokenWrite": token_write(job),
	"tokenWriteSource": token_write_source(job),
	"tokenWriteState": token_write_state(job),
	"persistedCredentials": persisted_credentials(job),
	"secretFirstLine": secret_first_line(job),
	"environment": {
		"name": object.get(job, "environment", ""),
		"protected": environment_protected(job),
		"reviewers": environment_reviewers_state(job),
		"requiredReviewers": environment_required_reviewers(job),
		"rules": environment_rules(job),
	},
}

# merged_privilege: the privilege of every job sharing one name (see jobs
# above), merged so the result never depends on input order: name lists
# as sorted unions; secretsState unknown if any job's is;
# secretsInherit true if any; persistedCredentials proven if any;
# tokenWriteSource the strongest signal present (declared, then log,
# then effect, then unknown, then none); environment from the job with
# the smallest originFile, the first such job in input order on a tie.
# Total: the group is never empty.
merged_privilege(group) := {
	"secrets": sort({s | some job in group; some s in privilege(job).secrets}),
	"secretsState": merged_secrets_state(group),
	"secretsInherit": any_inherit(group),
	"allSecrets": any_all_secrets(group),
	"protectedSecrets": sort({s | some job in group; some s in privilege(job).protectedSecrets}),
	"tokenWrite": sort({s | some job in group; some s in privilege(job).tokenWrite}),
	"tokenWriteSource": merged_token_write_source(group),
	"tokenWriteState": merged_token_write_state(group),
	"persistedCredentials": merged_persisted_credentials(group),
	"secretFirstLine": merged_secret_first_line(group),
	"environment": privilege(environment_job(group)).environment,
}

merged_secrets_state(group) := "unknown" if {
	some job in group
	privilege(job).secretsState == "unknown"
} else := "proven"

any_inherit(group) if {
	some job in group
	privilege(job).secretsInherit == true
} else := false

any_all_secrets(group) if {
	some job in group
	privilege(job).allSecrets == true
} else := false

merged_token_write_source(group) := "declared" if {
	some job in group
	privilege(job).tokenWriteSource == "declared"
} else := "log" if {
	some job in group
	privilege(job).tokenWriteSource == "log"
} else := "effect" if {
	some job in group
	privilege(job).tokenWriteSource == "effect"
} else := "unknown" if {
	some job in group
	privilege(job).tokenWriteSource == "unknown"
} else := "none"

merged_token_write_state(group) := "proven" if {
	merged_token_write_source(group) in {"declared", "log", "effect"}
} else := "proven" if {
	merged_token_write_source(group) == "none"
	some job in group
	token_write_state(job) == "proven"
} else := "unknown"

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
# step with values and job variables/env values (GITHUB_TOKEN excluded,
# any case: it is the token, handled by tokenWrite). GitLab names the
# settings variables in scope of the job. Total by construction: the final
# else covers every provider this module does not special-case.
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
	some m in regex.find_all_string_submatch_n(secret_member_pattern, expr, -1)
	name := concat("", [m[1], m[2]])
	upper(name) != "GITHUB_TOKEN"
}) if {
	input.pipeline.provider == "github"
} else := sort({v.name |
	some v in object.get(input.pipeline, "settingsVariables", [])
	variable_in_scope(v, job)
	variable_reaches_job(v, job)
	secret_variable(v)
}) if {
	input.pipeline.provider == "gitlab"
} else := []

# secret_first_line: the job's own Job.SecretFirstLine, passed through
# unchanged (the collector already excludes GITHUB_TOKEN in any case and
# already resolves a workflow-level env: reference to line 0). GitHub
# only; empty for every other provider, so a GitLab job's merge has
# nothing to combine.
secret_first_line(job) := object.get(job, "secretFirstLine", {}) if {
	input.pipeline.provider == "github"
} else := {}

# merged_secret_first_line: a line recorded against one workflow file is
# not comparable to a line recorded against another, so a group spanning
# more than one file can never trust any of its lines: the single-job
# case (no merge at all) passes its map through; a multi-job group whose
# every job was collected from the same file, and whose jobs never
# disagree on a name they both record, merges the union of their maps
# (same_origin_file, secret_first_lines_agree); every other group (a
# different file, or a real disagreement) carries no line for the name
# the step-order check reads a kept reach, never a line that could drop
# one wrongly.
merged_secret_first_line(group) := secret_first_line(group[0]) if {
	count(group) == 1
} else := {name: line |
	some job in group
	some name, line in secret_first_line(job)
} if {
	same_origin_file(group)
	secret_first_lines_agree(group)
} else := {}

# same_origin_file: every job of the group was collected from the same
# workflow file (Job.OriginFile), so their textual line numbers are
# positions in the same source and can be compared at all.
same_origin_file(group) if {
	count({object.get(job, "originFile", "") | some job in group}) == 1
}

# secret_first_lines_agree: no job of the group records a name at a line
# some other job of the group also records, but at a different one. A
# name only part of the group records is not a disagreement (nothing to
# compare it against), and agrees trivially.
secret_first_lines_agree(group) if {
	every job in group {
		every name, line in secret_first_line(job) {
			every other in group {
				object.get(secret_first_line(other), name, line) == line
			}
		}
	}
}

# ------------------------------------------------------- reusable workflows

# called_job: a job of a reusable workflow of the repository with the
# calls that run it (the collector's Job.Callers).
called_job(job) if {
	"workflow_call" in object.get(job, "triggers", [])
	count(object.get(job, "callers", [])) > 0
}

# held_secrets: the secrets the job reads; for a called job, the ones a
# call really passes (caller_secrets), by the caller's names.
held_secrets(job) := sort({n | some c in job.callers; some n in caller_secrets(job, c)}) if {
	input.pipeline.provider == "github"
	called_job(job)
} else := secrets(job)

# caller_secrets: what one call passes of the secrets the called job
# reads: all of them with secrets: inherit, else the caller's secrets
# behind each name of the explicit map (the job token passed as a secret
# is the token, no secret). A name the call does not pass is empty.
caller_secrets(job, c) := {n | some n in secrets(job)} if {
	object.get(c, "secretsInherit", false) == true
} else := {x |
	some n in secrets(job)
	v := object.get(object.get(c, "secrets", {}), n, "")
	some x in expression_secrets(v)
}

# expression_secrets: the secrets.X names in a text, GITHUB_TOKEN left
# out in any case (it is the job token).
expression_secrets(text) := {name |
	some expr in regex.find_n(`\$\{\{[^}]*\}\}`, text, -1)
	some m in regex.find_all_string_submatch_n(secret_member_pattern, expr, -1)
	name := concat("", [m[1], m[2]])
	upper(name) != "GITHUB_TOKEN"
}

# caller_fact: one call of a called job, what it gives the job: the token
# (caller_token_write), the secrets it passes, whether it passes every one
# (secrets: inherit), the events it runs on.
caller_fact(job, c) := {
	"job": object.get(c, "job", ""),
	"tokenWrite": caller_token_write(c),
	"tokenWriteSource": caller_token_source(c),
	"secrets": sort(caller_secrets(job, c)),
	"allSecrets": object.get(c, "secretsInherit", false) == true,
	"triggers": sort({t | some t in object.get(c, "triggers", [])}),
}

caller_token_write(c) := all_write_scopes if {
	object.get(c, "permissions", null) == "write-all"
} else := sort({scope |
	perms := object.get(c, "permissions", null)
	is_object(perms)
	some scope, level in perms
	level == "write"
}) if {
	is_object(object.get(c, "permissions", null))
} else := default_token_write_scopes if {
	object.get(c, "permissions", null) == null
	default_token_write == "true"
} else := [] if {
	object.get(c, "permissions", null) == null
	default_token_write == "false"
} else := ["contents", "packages"] if {
	object.get(c, "permissions", null) == null
} else := []

caller_token_source(c) := "declared" if {
	object.get(c, "permissions", null) == "write-all"
} else := "declared" if {
	is_object(object.get(c, "permissions", null))
} else := default_token_source if {
	object.get(c, "permissions", null) == null
} else := "none"

# callers_token_write: a called job with no permissions of its own runs
# with its caller's token: the union of what its calls give.
callers_token_write(job) := sort({s | some c in job.callers; some s in caller_token_write(c)})

# callers_token_source: unlike merged_token_write_source (which merges
# duplicate definitions of the SAME job and reads the strongest
# evidence found anywhere), a called job can run from ANY of its
# callers, so its privilege must read the WEAKEST one: one caller with
# an unresolved repository default (unknown) means this job's own
# write cannot be called proven either, whichever caller actually ran
# it. unknown dominates every other signal; short of that, the
# strongest real signal present wins (declared, then log, then
# effect); none only when every call gives nothing.
callers_token_source(job) := "unknown" if {
	some c in job.callers
	caller_token_source(c) == "unknown"
} else := "declared" if {
	some c in job.callers
	caller_token_source(c) == "declared"
} else := "log" if {
	some c in job.callers
	caller_token_source(c) == "log"
} else := "effect" if {
	some c in job.callers
	caller_token_source(c) == "effect"
} else := "none"

# inherits_caller_token: a called job declaring no permissions of its own
# (nor its workflow).
inherits_caller_token(job) if {
	input.pipeline.provider == "github"
	called_job(job)
	object.get(job, "permissions", null) == null
}

# protectedSecrets: the names (never the values) of the GitLab settings
# variables in scope of the job that are also protected, so the assembler
# can drop them for fork entries. A plain set comprehension, not an
# if/else rule: it is always defined (empty on GitHub, or when nothing
# matches), no default branch needed.
protected_secrets(job) := sort({v.name |
	input.pipeline.provider == "gitlab"
	some v in object.get(input.pipeline, "settingsVariables", [])
	variable_in_scope(v, job)
	variable_reaches_job(v, job)
	v.protected == true
})

# variable_reaches_job: whether the protection that gates a settings
# variable lets it into the job's runs at all. GitLab exports a protected
# variable only to pipelines on a protected branch or tag, so a job whose
# every way to run is a merge request pipeline (gitlab_merge_request_only)
# never receives one; an unprotected variable reaches every run. A merge
# request whose source branch is itself protected does receive protected
# variables, a case the rules alone cannot see and that this reading
# leaves out.
variable_reaches_job(v, _) if v.protected != true

variable_reaches_job(v, job) if {
	v.protected == true
	not gitlab_merge_request_only(job)
}

# gitlab_merge_request_only: every rule that can run the job is a merge
# request rule ($CI_PIPELINE_SOURCE == "merge_request_event", or the bare
# presence of $CI_MERGE_REQUEST_IID), with no || alternative on the same
# rule, and at least one such rule exists; or, without rules:, only: lists
# merge_requests and nothing else.
gitlab_merge_request_only(job) if {
	rules := object.get(job, "rules", [])
	count(rules) > 0
	some r in rules
	_merge_request_rule(r)
	every rule in rules {
		_merge_request_rule_or_never(rule)
	}
}

gitlab_merge_request_only(job) if {
	count(object.get(job, "rules", [])) == 0
	only := object.get(job, "only", [])
	count(only) > 0
	every o in only {
		o == "merge_requests"
	}
}

_merge_request_rule_or_never(rule) if object.get(rule, "when", "") == "never"

_merge_request_rule_or_never(rule) if _merge_request_rule(rule)

_merge_request_rule(rule) if {
	object.get(rule, "when", "") != "never"
	cond := object.get(rule, "if", "")
	not contains(cond, "||")
	regex.match(`\$CI_PIPELINE_SOURCE\s*==\s*['"]merge_request_event['"]`, cond)
}

_merge_request_rule(rule) if {
	object.get(rule, "when", "") != "never"
	cond := object.get(rule, "if", "")
	not contains(cond, "||")
	regex.match(`\$CI_MERGE_REQUEST_I?ID\b`, cond)
	not regex.match(merge_request_iid_absent, cond)
}

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

# secret_member_pattern: secrets.X and secrets['X']. A name may hold a
# hyphen: a reusable workflow declares its secrets under any name
# (`secrets.github-token`), and the expression syntax reads it whole.
secret_member_pattern := `\bsecrets(?:\.([A-Za-z_][A-Za-z0-9_-]*)|\[\s*['"]([A-Za-z_][A-Za-z0-9_-]*)['"]\s*\])`

github_expressions(job) := {expr |
	some text in job_texts_and_env(job)
	some expr in regex.find_n(`\$\{\{[^}]*\}\}`, text, -1)
}

# secretsState: unknown when the list of secrets cannot be complete:
# on GitLab, the settings-variable listing could not be fetched
# authoritatively.
secrets_state(job) := "unknown" if {
	input.pipeline.provider == "gitlab"
	object.get(input.pipeline, "settingsVariablesKnown", false) == false
} else := "proven"

# all_secrets: the job holds every secret of the repository, proven by the
# way it reads them, whatever their names: a reusable workflow call with
# secrets: inherit, or an expression reading the whole secrets context
# (toJSON(secrets), or secrets bare, without a member). Total: false
# otherwise.
all_secrets(job) if {
	input.pipeline.provider == "github"
	object.get(job, "secretsInherit", false) == true
} else := true if {
	input.pipeline.provider == "github"
	some expr in github_expressions(job)
	regex.match(`(^|[^.\w])secrets\s*([^.\[\w\s]|$)`, expr)
} else := false

# job_texts_and_env: every text a secret reference can sit in. Step if:
# expressions are included here (unlike job_texts): a secret named in an
# if: is resolved by the runner for the job, so the job holds it.
job_texts_and_env(job) := array.concat(
	array.concat(
		array.concat(job_texts(job), object.get(job, "scriptIfs", [])),
		array.concat(obj_values(object.get(job, "variables", {})), obj_values(object.get(job, "localVariables", {}))),
	),
	array.concat(
		obj_values(object.get(job, "reusableSecrets", {})),
		[v | some _, v in object.get(job, "reusableWith", {}); is_string(v)],
	),
)

# obj_values: there is no object.values builtin in OPA v1; a comprehension
# over the map's own entries is the standard substitute.
obj_values(obj) := [v | some _, v in obj]

all_write_scopes := ["actions", "contents", "deployments", "id-token", "packages", "pull-requests", "security-events"]

# default_token_write_scopes: every write scope the repository's real
# default GITHUB_TOKEN can hold, read off a run's own log or proved by
# a bot-authored write (FetchGitHubDefaultTokenWrite); id-token is left
# out, since the API never prints it in the GITHUB_TOKEN Permissions
# block.
default_token_write_scopes := ["actions", "checks", "contents", "deployments", "issues", "packages", "pull-requests", "security-events", "statuses"]

# default_token_write: input.pipeline.defaultTokenWrite, "unknown" when
# the lane never ran or never decided it (the field is omitted on the
# Go side in that case).
default_token_write := object.get(input.pipeline, "defaultTokenWrite", "unknown")

# default_token_source: the tokenWriteSource a job with no permissions
# block gets, once the repository's real default token write is
# known. Both "true" and "false" forward input.pipeline.defaultTokenSource
# verbatim: the effect route only ever proves "true", so "false" can
# only ever have come from the log route ("log"), the same read that
# proved "true" there too, and a read-only default is still a settled,
# proven answer, never an open question. Anything else (the lane never
# ran, or neither route resolved it) is "unknown".
default_token_source := object.get(input.pipeline, "defaultTokenSource", "unknown") if {
	default_token_write in {"true", "false"}
} else := "unknown"

# tokenWrite: a single function with clear, mutually exclusive guards
# (provider, then permissions shape), closed by an unconditional default,
# so it is total and can never leave privilege undefined. GitHub: the
# write-all shortcut expands to every scope; an explicit permissions map
# yields its write-level keys; no permissions block at all reads the
# repository's real default token write (default_token_write), proven
# when a run's log or a bot-authored write settled it, else the old
# assumed scopes (kept so nothing downstream loses the write
# assumption while it stays unresolved). GitLab: CI_JOB_TOKEN cannot
# push, so contents:write requires a positive signal, either a
# protected CI_PUSH_TOKEN variable in scope or a script that runs git
# push.
token_write(job) := callers_token_write(job) if {
	inherits_caller_token(job)
} else := all_write_scopes if {
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
} else := default_token_write_scopes if {
	input.pipeline.provider == "github"
	object.get(job, "permissions", null) == null
	default_token_write == "true"
} else := [] if {
	input.pipeline.provider == "github"
	object.get(job, "permissions", null) == null
	default_token_write == "false"
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
	variable_reaches_job(v, job)
	v.name == "CI_PUSH_TOKEN"
	v.protected == true
}

gitlab_contents_write(job) if {
	some line in object.get(job, "scripts", [])
	contains(line, "git push")
}

# tokenWriteSource: whether tokenWrite above is a real declaration
# ("declared": an explicit permissions object, or the write-all
# shortcut), the repository's real default token write once it is
# known ("log" or "effect", via default_token_source), a guess that
# stays open ("unknown": no permissions block at all, and neither
# route resolved the default), or neither ("none": GitLab, no write
# scope the default grants, or a GitHub string shortcut other than
# write-all, e.g. read-all). Total by construction, the final else
# covers everything else. An unresolved token write must not read as
# proven, so impacts that depend on it (writes_repo, and every signing
# or release step) key their state off this, via token_dependent_state
# below.
token_write_source(job) := callers_token_source(job) if {
	inherits_caller_token(job)
} else := "declared" if {
	input.pipeline.provider == "github"
	object.get(job, "permissions", null) == "write-all"
} else := "declared" if {
	input.pipeline.provider == "github"
	is_object(object.get(job, "permissions", null))
} else := default_token_source if {
	input.pipeline.provider == "github"
	object.get(job, "permissions", null) == null
} else := "none"

# token_dependent_state: the state an impact gets when its only evidence
# that the job holds the write it needs is tokenWrite itself. An
# unresolved (unknown) token write downgrades the impact to unknown;
# any real signal (declared, log, effect, or none at all, which only
# fires impact rules that never reach here) stays proven.
token_dependent_state(job) := "unknown" if {
	token_write_source(job) == "unknown"
} else := "proven"

# token_write_state: "proven" once tokenWriteSource is a real
# declaration or a read repository default (declared, log, effect),
# "unknown" when it is unresolved (unknown) or absent (none). On GitLab a
# contents write rests on a positive signal (gitlab_contents_write: a
# protected CI_PUSH_TOKEN reaching the job, or a script running git
# push), so it is proven too; its source stays "none", GitLab declaring
# no token scope.
token_write_state(job) := "proven" if {
	token_write_source(job) in {"declared", "log", "effect"}
} else := "proven" if {
	input.pipeline.provider == "gitlab"
	gitlab_contents_write(job)
} else := "unknown"

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

# environment_reviewers_state: "proven" once the GitHub environments lane
# has read the repository's environments (input.pipeline.environmentsKnown),
# whether or not the job's own environment is among them (one the API
# does not list protects nothing, which is itself a known answer). "unknown"
# while that lane never ran (GitLab) or failed (401/403/404/network).
environment_reviewers_state(job) := "proven" if {
	object.get(job, "environment", "") != ""
	input.pipeline.environmentsKnown == true
} else := "unknown"

# environment_required_reviewers: true when the environment the job names
# is in the known list and that entry requires reviewers; false otherwise,
# including when the job has none or the lane never ran.
environment_required_reviewers(job) if {
	env := object.get(job, "environment", "")
	env != ""
	some e in object.get(input.pipeline, "environments", [])
	e.name == env
	e.requiredReviewers == true
} else := false

# environment_rules: the protection rule names present on the environment
# the job names, in the fixed order required_reviewers, wait_timer,
# branch_policy; empty when the job has no environment, the environment is
# not in the known list, or it carries none of the three.
environment_rules(job) := rules if {
	env := object.get(job, "environment", "")
	env != ""
	some e in object.get(input.pipeline, "environments", [])
	e.name == env
	rules := [name |
		some name in ["required_reviewers", "wait_timer", "branch_policy"]
		environment_has_rule(e, name)
	]
} else := []

environment_has_rule(e, "required_reviewers") if e.requiredReviewers == true

environment_has_rule(e, "wait_timer") if object.get(e, "waitTimer", 0) > 0

environment_has_rule(e, "branch_policy") if e.branchPolicy == true

# ------------------------------------------------------------------- impact

impact(job) := [i | some i in impact_set(job)]

# impact_set: what the job's own steps do, plus what its declared token lets
# any code in the job do, one source per kind. A kind a step proves is never
# counted again from the token; the token replaces a step fact of that kind
# that could not be resolved; otherwise the step's fact stands.
impact_set(job) := {i |
	some i in step_impacts(job)
	not replaced_by_token(job, i)
} | {t |
	some t in token_impacts(job)
	not step_proves(job, t.kind)
}

step_impacts(job) := own_step_impacts(job) | called_step_impacts(job)

own_step_impacts(job) := publishes(job) | deploys(job) | writes_repo(job) | signs_or_releases(job)

# called_step_impacts: what the jobs a reusable workflow call runs do
# (Job.reusableCallees, every level of the chain), the job calling them
# doing it: each impact names the called job it comes from (via).
called_step_impacts(job) := {object.union(i, {"via": callee.name}) |
	some name in object.get(job, "reusableCallees", [])
	some callee in input.pipeline.jobs
	callee.name == name
	some i in own_step_impacts(callee)
}

step_proves(job, kind) if {
	some i in step_impacts(job)
	i.kind == kind
	i.state == "proven"
}

replaced_by_token(job, i) if {
	i.state == "unknown"
	not step_proves(job, i.kind)
	some t in token_impacts(job)
	t.kind == i.kind
}

# token_scope_impacts: the write scopes that let code in the job change
# something by themselves, and the impact each one is. Every other write
# scope (pull-requests, issues, id-token, security-events, actions, checks,
# statuses) is a privilege only.
token_scope_impacts := {"contents": "writes_repo", "packages": "publishes", "deployments": "deploys"}

# token_impacts: one proven impact per such scope the workflow or the job
# declares as write (a permissions map naming it, or write-all). The
# assumed default token (no permissions block) and a GitLab token declare
# no scope, so their real scopes are unknown: they stay a privilege only.
token_impacts(job) := {{"kind": kind, "state": "proven", "evidence": token_evidence(job, scope), "source": "token"} |
	token_write_source(job) == "declared"
	some scope in token_write(job)
	kind := token_scope_impacts[scope]
}

token_evidence(job, scope) := "permissions: write-all" if {
	object.get(job, "permissions", null) == "write-all"
} else := sprintf("permissions: %s: write", [scope])

# publish_patterns and configured_publish_actions: the publish inventory,
# the commands and actions that make a job ship what it builds. Built in:
# no control configures it.
publish_patterns := [
	`(?i)(npm|pnpm|yarn|bun)\s+publish`, `(?i)cargo\s+publish`, `(?i)twine\s+upload`,
	`(?i)poetry\s+publish`, `(?i)gh\s+release\s+create`, `(?i)goreleaser\s+release`,
	`(?i)semantic-release`, `(?i)gradlew?\b[^\n]*\bpublish`, `(?i)\bmvnw?\b[^\n]*\bdeploy\b`,
	`(?i)dotnet\s+nuget\s+push`, `(?i)gem\s+push`, `(?i)docker\s+push`, `(?i)helm\s+push`,
]

configured_publish_actions := [
	"pypa/gh-action-pypi-publish", "JS-DevTools/npm-publish", "gradle/publish-plugin",
	"softprops/action-gh-release", "ncipollo/release-action", "goreleaser/goreleaser-action",
	"crazy-max/ghaction-docker-buildx", "changesets/action",
]

# image_push_actions publish only when their push: input says so
# (publish_action_state); they are publish actions whatever the configured
# inventory lists, since what they do is known by definition.
image_push_actions := {"docker/build-push-action", "useblacksmith/build-push-action"}

# publish_actions: the configured inventory plus the image push actions,
# without the release actions, which cut a release (signs_or_releases) and
# never also publish: one impact per step.
publish_actions := {name |
	some name in array.concat(configured_publish_actions, [a | some a in image_push_actions])
	not lower(name) in {lower(r) | some r in release_actions}
}

# builtin_publish_script_patterns are publish commands known by definition,
# counted whatever the configured inventory lists: the Python registry
# uploaders, an image push through buildx, and a winget manifest submission.
builtin_publish_script_patterns := [
	`\btwine\s+upload\b`, `\buv\s+publish\b`, `\bpdm\s+publish\b`, `\bpoetry\s+publish\b`,
	`\bflit\s+publish\b`, `\bhatch\s+publish\b`, `\bdocker\s+push\b`,
	`\bdocker\s+buildx\s+build\b[^\n]*\s--push\b`, `\bdocker\s+buildx\s+imagetools\s+create\b`,
	`\bkomac\b[^\n]*\s--submit\b`,
]

all_publish_patterns := array.concat(publish_patterns, builtin_publish_script_patterns)

# release_only_line: a release command, a signs_or_releases impact and
# never also a publish, whatever the configured publish patterns hold.
release_only_line(l) if regex.match(`gh\s+release\s+(create|upload)`, _command_text(l))

# publish_text: a script entry without its release-only lines, the text
# the publish patterns read.
publish_text(script) := concat("\n", [l | some l in split(script, "\n"); not release_only_line(l)])

# local_publish_script_pattern: a run step calling a repository script
# whose file name says it uploads or publishes. The commands sit in the
# script, out of the workflow's text, so the publish is unknown.
local_publish_script_pattern := `(^|[\s;&|(])\.{0,2}/?([\w.-]+/)*[\w.-]*(publish|upload)[\w.-]*\.(sh|py|js|mjs|cjs|ts|ps1)(\s|$)`

# publishScriptExcludePatterns: verification-only forms that veto a
# publish-script match on the same line, they never publish anything.
publish_script_exclude_patterns := [`(?i)--dry-run`, `(?i)publishToMavenLocal`]

excluded(line) if {
	some pat in publish_script_exclude_patterns
	regex.match(pat, line)
}

# The exclusion applies to the whole script entry; only the evidence is
# narrowed to the matching line.
publishes(job) := {{"kind": "publishes", "state": "proven", "evidence": evidence} |
	some line in object.get(job, "scripts", [])
	text := publish_text(line)
	some pat in all_publish_patterns
	regex.match(pat, text)
	not excluded(line)
	evidence := evidence_line(text, [l | some l in split(text, "\n"); regex.match(pat, l)])
} | {{"kind": "publishes", "state": state, "evidence": action.uses} |
	some action in object.get(job, "uses", [])
	some name in publish_actions
	startswith(lower(action.uses), concat("", [lower(name), "@"]))
	state := publish_action_state(action, lower(name))
} | {{"kind": "publishes", "state": "unknown", "evidence": short_evidence(l)} |
	some line in object.get(job, "scripts", [])
	not publish_script_proven(line)
	some l in split(line, "\n")
	regex.match(local_publish_script_pattern, _command_text(l))
} | {{"kind": "publishes", "state": local_publish_state(job), "evidence": sprintf("%s (%s)", [action.name, action.uses])} |
	some action in object.get(job, "uses", [])
	local_action(action.uses)
	some pat in publish_step_name_patterns
	regex.match(pat, object.get(action, "name", ""))
	not excluded(object.get(action, "name", ""))
}

# publish_step_name_patterns: the name of a step calling a local action,
# whose commands are out of the workflow's text, saying it publishes.
publish_step_name_patterns := [`(?i)\bpublish\b.*\bnpm\b|\bnpm\b.*\bpublish\b`]

local_action(uses) if startswith(uses, "./")

local_action(uses) if startswith(uses, "$/")

# local_publish_state: a declared id-token write (registry trusted
# publishing) proves the publish; otherwise the name alone cannot.
local_publish_state(job) := "proven" if declared_id_token_write(job) else := "unknown"

publish_script_proven(line) if {
	some pat in all_publish_patterns
	regex.match(pat, publish_text(line))
	not excluded(line)
}

# publish_action_state: docker/build-push-action's own default for push:
# is false (it never pushes unless told to), unlike every other publish
# action here, which has no such input at all and so always counts once
# named. On docker/build-push-action a literal true (or the YAML string
# "true") is proven, an expression ("${{ ... }}", decided at run time) is
# unknown, and anything else (absent, false, "false") yields no value,
# so no impact. On any other action only an explicit false ("false")
# removes it. The bodies are mutually exclusive by their guards.
publish_action_state(action, name) := "proven" if {
	name in image_push_actions
	push_value(action) in {true, "true"}
}

publish_action_state(action, name) := "unknown" if {
	name in image_push_actions
	v := push_value(action)
	is_string(v)
	contains(v, "${{")
}

publish_action_state(action, name) := "proven" if {
	not name in image_push_actions
	not push_value(action) in {false, "false"}
}

# push_value: the action's push: input, null when absent.
push_value(action) := object.get(object.get(action, "with", {}), "push", null)

deploy_pattern := `kubectl\s+apply|helm\s+upgrade|terraform\s+apply|aws\s.*\sdeploy|gcloud\s.*\sdeploy|az\s.*\sdeploy|ansible-playbook|ssh\s.*deploy|rsync\s.*\s[^\s]+:|sentry-cli\s+releases\s+deploys|kubectl\b[^\n|;&]*\s(apply|create|replace|rollout|patch|set\s+image)\b|helm\b[^\n|;&]*\s(upgrade|install)\b|terraform\b[^\n|;&]*\sapply\b|\bwrangler\s+(deploy|publish)\b|\bfirebase\s+deploy\b|\bnetlify\s+deploy\b|\bvercel\s+(deploy\b|--prod\b)|\bfly(ctl)?\s+deploy\b|\b(serverless|sls)\s+deploy\b|\bcdk\s+deploy\b|\bpulumi\s+up\b`

# deploys: a deploy command. A job-level environment is never a deploy by
# itself: it is a protection (an approval, a wait timer, a branch policy) the
# job runs behind, not what the job changes; it stays a privilege fact
# (privilege.environment) the path can name in a Note. Whether it
# requires reviewers is not in the workflow, so that part is "unknown".
deploys(job) := {{"kind": "deploys", "state": "proven", "evidence": evidence} |
	some line in object.get(job, "scripts", [])
	regex.match(deploy_pattern, line)
	evidence := evidence_line(line, [l | some l in split(line, "\n"); regex.match(deploy_pattern, l)])
} | {{"kind": "deploys", "state": "proven", "evidence": action.uses} |
	some action in object.get(job, "uses", [])
	deploy_action(action)
}

# deploy_actions deploy by definition: the cloud and hosting deploy
# actions and the Pages deployment. deploy_action_prefixes name a family
# (bitovi's github-actions-deploy-* actions). Compared in lower case.
deploy_actions := {
	"azure/webapps-deploy", "azure/k8s-deploy", "azure/functions-action",
	"aws-actions/amazon-ecs-deploy-task-definition", "aws-actions/aws-cloudformation-github-deploy",
	"google-github-actions/deploy-cloudrun", "google-github-actions/deploy-appengine",
	"google-github-actions/deploy-cloud-functions", "firebaseextended/action-hosting-deploy",
	"actions/deploy-pages",
}

deploy_action_prefixes := ["bitovi/github-actions-deploy-"]

deploy_action(action) if {
	some name in deploy_actions
	startswith(lower(action.uses), concat("", [name, "@"]))
}

deploy_action(action) if {
	some prefix in deploy_action_prefixes
	startswith(lower(action.uses), prefix)
}

# wrangler-action runs `wrangler deploy` unless its command input says
# something else.
deploy_action(action) if {
	startswith(lower(action.uses), "cloudflare/wrangler-action@")
	command := object.get(object.get(action, "with", {}), "command", "")
	wrangler_command_deploys(command)
}

wrangler_command_deploys(command) if command == ""

wrangler_command_deploys(command) if regex.match(`\b(deploy|publish)\b`, command)

# A command run on a server over SSH, or files copied to one, is a deploy
# once the step is given what to run or where to copy.
deploy_action(action) if {
	startswith(lower(action.uses), "appleboy/ssh-action@")
	some key in ["script", "script_path"]
	object.get(object.get(action, "with", {}), key, "") != ""
}

deploy_action(action) if {
	startswith(lower(action.uses), "appleboy/scp-action@")
	object.get(object.get(action, "with", {}), "target", "") != ""
}

repo_writer_actions := {"peter-evans/create-pull-request", "stefanzweifel/git-auto-commit-action", "EndBug/add-and-commit"}

# writes_repo: a git push in a script, which needs the token's contents
# write (state following how sure that write is), or a commit or pull
# request action, which pushes by definition (with the job token or the
# token it is given): proven whatever the job token.
writes_repo(job) := {{"kind": "writes_repo", "state": token_dependent_state(job), "evidence": ev} |
	"contents" in token_write(job)
	some ev in repo_write_evidence(job)
} | {{"kind": "writes_repo", "state": "proven", "evidence": action.uses} |
	some action in object.get(job, "uses", [])
	some name in repo_writer_actions
	startswith(lower(action.uses), concat("", [lower(name), "@"]))
}

repo_write_evidence(job) := {evidence_line(line, [l | some l in split(line, "\n"); contains(l, "git push")]) |
	some line in object.get(job, "scripts", [])
	contains(line, "git push")
}

# sigstore/cosign-installer is deliberately not here: it only installs the
# cosign binary, the usual setup step ahead of `cosign verify` just as much
# as `cosign sign`, so keeping it would give a verify-only job the same
# false signs_or_releases impact the slsa- script pattern gave
# slsa-verifier. `cosign sign`/`cosign attest` in a script already counts,
# through signing_script_patterns below.
signing_actions := {"slsa-framework/slsa-github-generator", "actions/attest-build-provenance"}

# code_signing_actions and code_signing_script_patterns sign with a
# certificate, not with the job token: proven whatever the token is.
code_signing_actions := {"apple-actions/import-codesign-certs"}

code_signing_script_patterns := [`codesign\s.*(-s|--sign)\s`, `security\s+import\s.*\.p12`]

# ad_hoc_signature: codesign -s - signs with no identity at all (an ad-hoc
# signature a local tool needs to run), it ships nothing signed.
ad_hoc_signature(l) if regex.match(`codesign\s.*(-s|--sign)\s+-(\s|$)`, l)

# release_actions cut a release: a signs_or_releases impact, never also a
# publish, whatever the configured publish inventory lists (publish_actions
# leaves them out).
release_actions := {
	"softprops/action-gh-release", "ncipollo/release-action", "svenstaro/upload-release-action",
	"yyx990803/release-tag", "actions/create-release", "marvinpinto/action-automatic-releases",
}

signing_step_actions := signing_actions | release_actions

# signing_or_release_patterns are the script commands that sign an artifact
# or cut a release. A release command matching a publish pattern (goreleaser
# release, by default) is a publishes impact and is skipped here; a signing
# command always counts, npm publish --provenance included, since it signs
# the provenance on top of publishing.
release_script_patterns := [`gh\s+release\s+(create|upload)`, `goreleaser\s+release`]

signing_script_patterns := [`cosign\s+(sign|attest)`, `npm\s+publish\s.*--provenance`]

# signs_or_releases needs a signing or release step. id-token: write (or
# write-all) on its own is a privilege (it stays in tokenWrite): a job that
# mints an OIDC token to log in somewhere signs and releases nothing. The
# step is proven when the job declares an id-token write, and follows the
# token-dependent state otherwise.
signs_or_releases(job) := {{"kind": "signs_or_releases", "state": signing_state(job), "evidence": action.uses} |
	some action in object.get(job, "uses", [])
	some name in signing_step_actions
	startswith(lower(action.uses), concat("", [lower(name), "@"]))
} | {{"kind": "signs_or_releases", "state": signing_state(job), "evidence": evidence} |
	some line in object.get(job, "scripts", [])
	some l in split(line, "\n")
	signing_or_release_line(l)
	evidence := short_evidence(l)
} | {{"kind": "signs_or_releases", "state": "proven", "evidence": action.uses} |
	some action in object.get(job, "uses", [])
	some name in code_signing_actions
	startswith(action.uses, concat("", [name, "@"]))
} | {{"kind": "signs_or_releases", "state": "proven", "evidence": short_evidence(l)} |
	some line in object.get(job, "scripts", [])
	some l in split(line, "\n")
	some pat in code_signing_script_patterns
	regex.match(pat, _command_text(l))
	not ad_hoc_signature(_command_text(l))
}

declared_id_token_write(job) if {
	token_write_source(job) == "declared"
	"id-token" in token_write(job)
}

# The patterns read the command a line runs, never its comments or its
# quoted text: a commented-out command and a command only printed by an
# echo sign and release nothing. A verification-only form on the line (a
# --dry-run, publishScriptExcludePatterns) vetoes it as it vetoes a
# publish: a dry run signs and releases nothing either.
signing_or_release_line(l) if {
	some pat in signing_script_patterns
	regex.match(pat, _command_text(l))
	not excluded(l)
}

signing_or_release_line(l) if {
	some pat in release_script_patterns
	regex.match(pat, _command_text(l))
	not excluded(l)
	not publish_line(l)
}

# _visible_line: a script line with its quoted strings and its trailing
# comment removed.
_visible_line(line) := stripped if {
	once := regex.replace(line, `"[^"]*"`, "")
	twice := regex.replace(once, `'[^']*'`, "")
	stripped := regex.replace(twice, `\s+#.*`, "")
}

# _command_text: the line without its quoted substrings and its comment,
# a whole-line comment included (_visible_line only strips a comment that
# follows a space).
_command_text(l) := regex.replace(_visible_line(l), `^\s*#.*`, "")

publish_line(l) if {
	not release_only_line(l)
	some pat in all_publish_patterns
	regex.match(pat, l)
	not excluded(l)
}

signing_state(job) := "proven" if {
	declared_id_token_write(job)
} else := token_dependent_state(job)

# -------------------------------------------------------------------- feeds

# feeds: names of jobs that consume an artifact this job produces, plus
# jobs that restore a cache this job saves, plus jobs that read this job's
# outputs through needs (feeds_by "output", "output_compared" or
# "output_executed"). Sorted so the output is deterministic regardless of
# job iteration order.
feeds(job) := sort({other.name |
	some other in input.pipeline.jobs
	other.name != job.name
	feeds_job(job, other)
})

# feeds_via: per job feeds names, the kinds of edge that link the two,
# sorted: "artifact_executed" or "artifact_altered" (an artifact this job
# uploads, the other downloads and either runs something from or only
# moves, releases or publishes), "cache" (a cache this job saves, the
# other restores), "output" (GitLab: a needs dependency alone, which also
# downloads the needed job's artifacts there), "output_compared" (GitHub:
# the other reads this job's outputs only inside a comparison its runner
# evaluates itself, crossing no code) or "output_executed" (GitHub: that
# read reaches a script, a with: value, an env value, an image or a
# reusable call's input, see feeds_by below). Jobs sharing a name merge
# their kinds.
feeds_via(job) := {name: sort({kind |
	some other in input.pipeline.jobs
	other.name == name
	not job_cannot_run(job)
	not job_cannot_run(other)
	some kind in feed_kinds
	feeds_by(job, other, kind)
}) |
	some name in feeds(job)
}

feed_kinds := {
	"artifact", "artifact_executed", "artifact_altered",
	"cache", "output", "output_compared", "output_executed",
}

# A dead or inert job (Job.Dead, Job.Inert) never runs: it hands nothing
# over and takes nothing in, so it is no edge either way.
feeds_job(job, other) if {
	not job_cannot_run(job)
	not job_cannot_run(other)
	some kind in feed_kinds
	feeds_by(job, other, kind)
}

# The output edge: on GitHub, other lists job in needs and reads its job
# outputs (needs.<id>.outputs.*) somewhere they reach the run. A read
# inside only a comparison the runner evaluates itself (the job's or a
# step's if:) lets no code cross: that is output_compared. A read that
# reaches a script, a with: value, an env value, its container image or a
# reusable workflow call's with: input runs the value: that is
# output_executed, and wins over output_compared when other does both (see
# feed_kinds and control/paths.go's reachOver, which gives the two kinds
# different reach). A bare needs: only orders the two jobs and hands
# nothing over. On GitLab, needs: also downloads the needed job's
# artifacts, so the dependency alone stays an edge, kept as the one
# "output" kind.
feeds_by(job, other, "output") if {
	input.pipeline.provider != "github"
	job.name in object.get(other, "needs", [])
}

feeds_by(job, other, "output_executed") if {
	input.pipeline.provider == "github"
	job.name in object.get(other, "needs", [])
	reads_outputs_of(output_executed_texts(other), job_id(job.name))
}

feeds_by(job, other, "output_compared") if {
	input.pipeline.provider == "github"
	job.name in object.get(other, "needs", [])
	not reads_outputs_of(output_executed_texts(other), job_id(job.name))
	reads_outputs_of(output_compared_texts(other), job_id(job.name))
}

# job_id: the job's own id, the name without its workflow namespace, the
# name a needs.<id> context reads it by.
job_id(name) := id if {
	parts := split(name, "/")
	id := parts[count(parts) - 1]
}

reads_outputs_of(texts, id) if {
	q := regex_quote(id)
	pattern := sprintf(`\bneeds\.%s\.outputs\b|\bneeds\[\s*['"]%s['"]\s*\]\.outputs\b`, [q, q])
	some text in texts
	regex.match(pattern, text)
}

# output_compared_texts: the texts the runner itself evaluates before any
# step of the job runs, never handed to a shell or an action: the job's
# own if: and every step if: (job_conditions), and each run step's own
# if: carried separately for the cache-poisoning release-path resolution
# (scriptIfs). A needs output read only here crosses as a yes or no,
# never as a value.
output_compared_texts(job) := array.concat(job_conditions(job), object.get(job, "scriptIfs", []))

# output_executed_texts: the texts a needs output read here is run as a
# value, never merely compared: the run scripts and the step with: values
# (job_texts), the job's own env (variables, GitHub's env: merged in by
# the collector), its container image, and a reusable workflow call's
# with: inputs.
output_executed_texts(job) := array.concat(
	array.concat(job_texts(job), obj_values(object.get(job, "variables", {}))),
	array.concat(image_texts(job), [v | some _, v in object.get(job, "reusableWith", {}); is_string(v)]),
)

image_texts(job) := [concat(":", [object.get(img, "name", ""), object.get(img, "tag", "")]) |
	img := object.get(job, "image", null)
	is_object(img)
]

# regex_quote: the text with every regular-expression metacharacter
# escaped, so a job id is matched literally.
regex_quote(s) := regex.replace(s, `([.\\+*?()|\[\]{}^$])`, `\$1`)

# The artifact edge: on GitLab, needs: downloads the needed job's
# artifacts (see the output edge above), and so does an explicit
# dependencies:/artifacts: pair, read as the one untyped "artifact" kind,
# this task never touching GitLab's own model. On GitHub the edge splits
# by what the consumer does with the download: artifact_executed when it
# runs something from it (a script or a with: value naming the download,
# or, the download's own path not being tracked, any script segment that
# is not itself a recognized upload/release/publish command:
# conservative, crossing with the full reach is the safe error),
# artifact_altered when the consumer only re-uploads, releases or
# publishes it and runs nothing at all.
feeds_by(job, other, "artifact") if {
	input.pipeline.provider != "github"
	some produced in object.get(job, "artifacts", [])
	produced.mode == "produce"
	some consumed in object.get(other, "artifacts", [])
	consumed.mode == "consume"
	artifact_matches(produced, consumed)
	same_workflow_if_github(job, other, consumed)
}

feeds_by(job, other, "artifact_executed") if {
	input.pipeline.provider == "github"
	some produced in object.get(job, "artifacts", [])
	produced.mode == "produce"
	some consumed in object.get(other, "artifacts", [])
	consumed.mode == "consume"
	artifact_matches(produced, consumed)
	same_workflow_if_github(job, other, consumed)
	not artifact_consumption_altered_only(other)
}

feeds_by(job, other, "artifact_altered") if {
	input.pipeline.provider == "github"
	some produced in object.get(job, "artifacts", [])
	produced.mode == "produce"
	some consumed in object.get(other, "artifacts", [])
	consumed.mode == "consume"
	artifact_matches(produced, consumed)
	same_workflow_if_github(job, other, consumed)
	artifact_consumption_altered_only(other)
}

# artifact_consumption_altered_only: other carries a known
# upload/release/publish signal (an action or a command segment that only
# moves, lists, hashes, echoes or ships an artifact onward) and every
# command segment of its own scripts is itself one of those recognized
# commands: a chained command ("npm ci && npm publish") is read segment
# by segment, never as one string a single recognized verb anywhere in
# it can launder. Read job-wide rather than against the one downloaded
# path: ArtifactRef never carries a download's destination path (the
# GitHub collector's download-artifact branch sets none), so a per-path
# match is not available here, and one unrecognized segment already
# makes the whole edge artifact_executed.
artifact_consumption_altered_only(other) if {
	artifact_alter_signal(other)
	not artifact_has_non_alter_segment(other)
}

artifact_alter_signal(other) if {
	some action in object.get(other, "uses", [])
	artifact_alter_action(action)
}

artifact_alter_signal(other) if {
	some line in object.get(other, "scripts", [])
	some l in split(line, "\n")
	some seg in artifact_command_segments(_command_text(l))
	artifact_alter_only_command(seg)
}

artifact_alter_action(action) if {
	some name in artifact_alter_actions
	startswith(lower(action.uses), concat("", [lower(name), "@"]))
}

# artifact_alter_actions: actions.uses prefixes that only move, release or
# publish an artifact the job downloaded, release_actions (already
# defined above, for signs_or_releases) plus the official upload action
# itself (a re-upload, never an execution).
artifact_alter_actions := release_actions | {"actions/upload-artifact"}

# artifact_consumption_structural_actions: actions that are scaffolding
# for the consumption itself, never a sign other runs anything from the
# download: the checkout almost every job carries, and the artifact
# actions themselves (the download this edge is already about, and the
# upload/Pages actions that double as a produce step elsewhere). They
# never disqualify an alter-only read on their own, but they never grant
# one either: artifact_alter_signal still needs a real alter action or
# script to fire.
artifact_consumption_structural_actions := {
	"actions/checkout", "actions/download-artifact",
	"actions/upload-artifact", "actions/upload-pages-artifact", "actions/deploy-pages",
}

artifact_consumption_structural_action(action) if {
	some name in artifact_consumption_structural_actions
	startswith(lower(action.uses), concat("", [lower(name), "@"]))
}

# artifact_command_segments: a script line (after _command_text strips
# its quoted substrings and comment) split on the shell operators that
# chain one command into the next (&&, ||, ;, a pipe), each trimmed,
# empty segments (a trailing separator, a blank line) dropped. A command
# piped into another ("cat dist/manifest | sha256sum") is still two
# segments, both checked.
artifact_command_segments(text) := [s |
	some raw in regex.split(`&&|\|\||[;|]`, text)
	s := trim_space(raw)
	s != ""
]

# artifact_command_body: a command segment with any leading "sudo" and
# any leading NAME=value environment assignments stripped, so the
# anchored patterns below match the command itself whatever a caller
# puts in front of it.
artifact_command_body(seg) := body if {
	once := regex.replace(seg, `^sudo\s+`, "")
	body := regex.replace(once, `^([A-Za-z_][A-Za-z0-9_]*=\S*\s+)+`, "")
}

# artifact_segment_executing_patterns: a construct that runs something
# before, or regardless of, whatever verb opens the segment: command
# substitution ($(...) or backticks), process substitution (<(...) or
# >(...)), an eval, a source (by name or its leading-dot shorthand), or
# an interpreter/xargs/exec/env invocation anywhere in the text. A
# segment carrying one of these is never read as alter-only, however
# closely the rest of it matches a recognized verb: "echo $(./evil.sh)"
# matches "^echo\b" on its own, but the substitution runs the artifact's
# own script first.
artifact_segment_executing_patterns := [
	`\$\(`,
	"`",
	`<\(`,
	`>\(`,
	`\beval\b`,
	`\bsource\b`,
	`^\.\s`,
	`\bxargs\b`,
	`\bsh\b`,
	`\bbash\b`,
	`\bpython[0-9.]*\b`,
	`\bnode\b`,
	`\bexec\b`,
	`\benv\b`,
]

artifact_segment_executes(seg) if {
	some pat in artifact_segment_executing_patterns
	regex.match(pat, seg)
}

# artifact_alter_command_patterns: commands that only move, release,
# publish, list or hash an artifact, or a harmless shell preamble line
# that commonly precedes one (set -e and its variants, a plain export
# assignment, cd, mkdir -p, pwd), never running anything from inside the
# download, each anchored at the start of a command segment
# (artifact_command_body already stripped any sudo/env prefix) so a verb
# elsewhere in a longer word never matches ("lsof" is not "ls").
# artifact_segment_executes is checked ahead of every one of these (see
# artifact_alter_only_command): a substitution in an exported value still
# executes, whatever the leading keyword reads as.
artifact_alter_command_patterns := [
	`^gh\s+release\s+(create|upload)\b`,
	`^goreleaser\s+release\b`,
	`^twine\s+upload\b`,
	`^npm\s+publish\b`,
	`^cargo\s+publish\b`,
	`^gem\s+push\b`,
	`^aws\s+s3\s+(cp|sync)\b`,
	`^gsutil\s+(cp|rsync)\b`,
	`^az\s+storage\s+blob\s+upload\b`,
	`^cp\b`,
	`^mv\b`,
	`^ls\b`,
	`^echo\b`,
	`^sha256sum\b`,
	`^shasum\b`,
	`^cat\b`,
	`^set\s+[-+]\S+\b`,
	`^export\s+[A-Za-z_][A-Za-z0-9_]*=`,
	`^cd\s+\S+`,
	`^mkdir\s+-p\b`,
	`^pwd\b`,
]

artifact_alter_only_command(seg) if {
	not artifact_segment_executes(seg)
	some pat in artifact_alter_command_patterns
	regex.match(pat, artifact_command_body(seg))
}

# artifact_has_non_alter_segment: some command segment of other, in any
# script line, is not itself one of the recognized upload/release/list/
# hash commands, so whatever it runs is read, conservatively, as running
# something from the download; or other calls an action that is neither
# a recognized alter action nor mere scaffolding (checkout, the artifact
# actions themselves) and so can run anything, a local composite or
# Docker action (`uses: ./`) included.
artifact_has_non_alter_segment(other) if {
	some line in object.get(other, "scripts", [])
	some l in split(line, "\n")
	some seg in artifact_command_segments(_command_text(l))
	not artifact_alter_only_command(seg)
}

artifact_has_non_alter_segment(other) if {
	some action in object.get(other, "uses", [])
	not artifact_alter_action(action)
	not artifact_consumption_structural_action(action)
}

# A download with no name and no pattern takes every artifact of the run.
artifact_matches(produced, consumed) if {
	object.get(consumed, "name", "") == ""
	object.get(consumed, "pattern", "") == ""
}

# The same name on both sides always matches.
artifact_matches(produced, consumed) if {
	name := object.get(consumed, "name", "")
	name != ""
	name == object.get(produced, "name", "")
}

# On GitHub the consumer's name (which wins over a pattern, as in
# download-artifact) or its pattern must agree with the produced name.
# GitLab names are job names, matched by equality above only.
#
# Two names: an expression stands for one value of its own (a matrix
# entry, a version), never for any text, so two names holding expressions
# agree only when their literal parts, in order, are the same
# (`rustdesk-unsigned-macos-${{ a }}` is not `rustdesk-${{ v }}-${{ a }}.deb`).
# A name that is an expression alone agrees with the same expression only.
# A plain name agrees with a name holding expressions when that name has
# literal text and the expressions, read as wildcards, let it match.
artifact_matches(produced, consumed) if {
	input.pipeline.provider == "github"
	name := object.get(consumed, "name", "")
	name != ""
	artifact_names_match(object.get(produced, "name", ""), name)
}

# A pattern (download-artifact's `pattern:`) is a glob: an expression in
# the produced name only constrains the literal parts around it there.
artifact_matches(produced, consumed) if {
	input.pipeline.provider == "github"
	object.get(consumed, "name", "") == ""
	wanted := object.get(consumed, "pattern", "")
	wanted != ""
	produced_name := object.get(produced, "name", "")
	count([p | some p in artifact_literal_parts(produced_name); p != ""]) > 0
	artifact_names_agree(artifact_glob(produced_name), wanted)
}

artifact_names_match(a, b) if {
	has_expression(a)
	has_expression(b)
	artifact_literal_parts(a) == artifact_literal_parts(b)
	count([p | some p in artifact_literal_parts(a); p != ""]) > 0
}

artifact_names_match(a, b) if {
	has_expression(a)
	has_expression(b)
	count([p | some p in artifact_literal_parts(a); p != ""]) == 0
	normalized_expression(a) == normalized_expression(b)
}

artifact_names_match(a, b) if {
	has_expression(a)
	not has_expression(b)
	count([p | some p in artifact_literal_parts(a); p != ""]) > 0
	artifact_names_agree(artifact_glob(a), b)
}

artifact_names_match(a, b) if {
	not has_expression(a)
	has_expression(b)
	count([p | some p in artifact_literal_parts(b); p != ""]) > 0
	artifact_names_agree(a, artifact_glob(b))
}

has_expression(name) if contains(name, "${{")

# artifact_literal_parts: the literal text between the expressions of a
# name, adjacent expressions read as one value.
artifact_literal_parts(name) := split(regex.replace(name, `(\$\{\{[^}]*\}\})+`, "\u0000"), "\u0000")

normalized_expression(name) := regex.replace(name, `\s+`, "")

# artifact_glob: the name with each `${{ ... }}` expression as `*`.
artifact_glob(name) := regex.replace(name, `\$\{\{[^}]*\}\}`, "*")

artifact_wild(s) if regex.match(`[*?\[{]`, s)

# Two plain names agree when equal; a plain name and a glob when the glob
# matches it; two globs when their literal prefixes and their literal
# suffixes are compatible (one starts, respectively ends, with the other).
artifact_names_agree(a, b) if {
	not artifact_wild(a)
	not artifact_wild(b)
	a == b
}

artifact_names_agree(a, b) if {
	not artifact_wild(a)
	artifact_wild(b)
	glob.match(b, [], a)
}

artifact_names_agree(a, b) if {
	artifact_wild(a)
	not artifact_wild(b)
	glob.match(a, [], b)
}

artifact_names_agree(a, b) if {
	artifact_wild(a)
	artifact_wild(b)
	either_starts_with(regex.replace(a, `[*?\[{].*$`, ""), regex.replace(b, `[*?\[{].*$`, ""))
	either_ends_with(regex.replace(a, `^.*[*?\]}]`, ""), regex.replace(b, `^.*[*?\]}]`, ""))
}

either_starts_with(x, y) if startswith(x, y)

either_starts_with(x, y) if startswith(y, x)

either_ends_with(x, y) if endswith(x, y)

either_ends_with(x, y) if endswith(y, x)

# same_workflow_if_github: a GitHub upload-artifact/download-artifact
# name is only unique within the one workflow run that declared it, so
# two jobs from different workflow files that happen to share an
# artifact name must not be wired together. GitLab artifacts are scoped
# to the job/pipeline, not a workflow file, so this never restricts
# GitLab. Caches are unaffected (they stay cross-workflow, intentionally
# shared) because this guard is only added to the artifact branch above.
same_workflow_if_github(_, _, _) if input.pipeline.provider != "github"

same_workflow_if_github(job, other, _) if {
	input.pipeline.provider == "github"
	object.get(job, "originFile", "") == object.get(other, "originFile", "")
}

# A download with a run-id (ArtifactRef.crossRun) reads another run's
# artifacts: the one way an artifact crosses workflow files. In a workflow
# triggered by workflow_run that names its upstream workflows, the run is
# one of theirs (named by workflow name, or by file for a nameless one).
same_workflow_if_github(job, other, consumed) if {
	input.pipeline.provider == "github"
	object.get(consumed, "crossRun", false) == true
	cross_run_source(job, other)
}

cross_run_source(_, other) if count(object.get(other, "workflowRunWorkflows", [])) == 0

cross_run_source(job, other) if {
	some upstream in object.get(other, "workflowRunWorkflows", [])
	upstream_names(job)[upstream]
}

upstream_names(job) := {n |
	some n in [object.get(job, "workflowName", ""), object.get(job, "originFile", ""), workflow_file_name(job)]
	n != ""
}

workflow_file_name(job) := name if {
	parts := split(object.get(job, "originFile", ""), "/")
	name := parts[count(parts) - 1]
}

feeds_by(job, other, "cache") if {
	some saved in object.get(job, "caches", [])
	saved.mode in {"save", "both"}
	some restored in object.get(other, "caches", [])
	restored.mode in {"restore", "both"}
	restored.key == saved.key
	restored.key != ""
	not saves_key_first(other, job, saved.key)
	cache_scope_reaches(job, other)
}

# saves_key_first(earlier, later, key): earlier also saves key and later
# runs after it in the same run (it needs it, directly or through other
# jobs). A cache key is written once: earlier saves it on a miss, later
# then restores it with an exact hit and saves nothing, so later never
# writes what earlier restores. Two jobs both saving and restoring a key
# with no order between them keep an edge each way: either can save it
# first.
saves_key_first(earlier, later, key) if {
	some c in object.get(earlier, "caches", [])
	c.mode in {"save", "both"}
	c.key == key
	earlier.name != later.name
	earlier.name in graph.reachable(needs_graph, {later.name})
}

# needs_graph: each job's needs, for the run order. Jobs sharing a name
# merge their needs, so the object never holds a key twice.
needs_graph := {name: {n | some j2 in input.pipeline.jobs; j2.name == name; some n in object.get(j2, "needs", [])} |
	some j in input.pipeline.jobs
	name := j.name
}

# A restore-keys prefix (restored.prefix) restores the most recent cache
# whose key starts with it, so it is fed by every job saving such a key.
feeds_by(job, other, "cache") if {
	some saved in object.get(job, "caches", [])
	saved.mode in {"save", "both"}
	some restored in object.get(other, "caches", [])
	restored.mode in {"restore", "both"}
	object.get(restored, "prefix", false) == true
	restored.key != ""
	startswith(saved.key, restored.key)
	cache_scope_reaches(job, other)
}

# A saved key family (saved.prefix: a caching action saving under a fixed
# prefix followed by a hash only known at run time) can be the most recent
# cache under a restored prefix longer than its own: what follows the
# saved prefix is unknown, so it may start with the rest of the restored
# one. The other direction, the saved prefix starting with the restored
# one, is the rule above.
feeds_by(job, other, "cache") if {
	some saved in object.get(job, "caches", [])
	saved.mode in {"save", "both"}
	object.get(saved, "prefix", false) == true
	saved.key != ""
	some restored in object.get(other, "caches", [])
	restored.mode in {"restore", "both"}
	object.get(restored, "prefix", false) == true
	startswith(restored.key, saved.key)
	cache_scope_reaches(job, other)
}
