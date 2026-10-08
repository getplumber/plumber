# cache-poisoning — flag release / publish jobs that restore a build
# cache without a release-ref-scoped key. GitHub Actions caches are
# shared across branches with permissive fallback: a PR run on a feature
# branch can populate the same cache key that a later release-triggered
# job restores, silently injecting compromised artefacts into the
# published output (the May 2026 TanStack vector).
#
# A job is release context when its workflow triggers include `release`,
# it runs a publish action, or it runs a publish command in a script. A
# restore is flagged unless BOTH the cache key and every restore-keys
# fallback weave the release ref.
#
# Release context is resolved per trigger (issue #497): a step `if:`,
# a conditional enable input, or a default-mode conditional disable
# input of the shape github.event_name ==/!= '<event>' pins a step to
# a knowable event subset, and ISSUE-705 fires only when a restore and
# a publish can share an event. A whole-value enable or disable
# expression outside that shape cannot be resolved, so it reports the
# medium ISSUE-717 verify-manually finding instead of a High that
# asserts a restore which may never happen.
#
# This rule is data-driven: the entire action/script inventory AND the
# per-action cache semantics come from input.config.cachePoisoning, so
# the yaml is the single source of truth and the rego hardcodes nothing
# about which actions exist. Config shape:
#
#   publishActions:        ["owner/repo", ...]
#   publishScriptPatterns: ["<regex>", ...]
#   cacheActions:
#     - { action: "actions/cache",       mode: "always" }
#     - { action: "actions/setup-go",    mode: "default", disableInput: "cache", disableValue: false }
#     - { action: "gradle/actions/setup-gradle", mode: "default", disableInput: "cache-disabled", disableValue: true }
#     - { action: "actions/setup-node",  mode: "opt-in",  enableInput: "cache" }
#
# mode:
#   always   restores whenever the action is present.
#   default  restores unless disableInput holds disableValue.
#   opt-in   restores only when enableInput names a manager (a non-empty,
#            non-"false" string).
# Expression values in either input follow the per-trigger resolution
# described above and in the helpers below.
#
# The only thing kept in code is the github.ref* scope-token regex — what
# counts as "weaving the release ref" is fixed GitHub expression syntax.
package cache_poisoning

import rego.v1

_publish_actions := object.get(input, ["config", "cachePoisoning", "publishActions"], [])

_publish_script_patterns := object.get(input, ["config", "cachePoisoning", "publishScriptPatterns"], [])

_publish_script_exclude_patterns := object.get(input, ["config", "cachePoisoning", "publishScriptExcludePatterns"], [])

_cache_action_specs := object.get(input, ["config", "cachePoisoning", "cacheActions"], [])

# A release-scoped reference weaves the ref, tag, sha, or a run-unique
# token into the key as a real `${{ ... }}` expression. The literal text
# "github.ref_name" outside an expression is a constant string (never
# expanded, same key every run), and `github.ref_type` is just
# "branch"/"tag" (shared by every release) — the `\$\{\{` anchor and the
# trailing `\b` reject both. run_id / run_number are unique per run, so
# a key woven with them can never restore another run's cache.
release_scope_pattern := `\$\{\{[^}]*\bgithub\.(ref(_name)?|sha|run_id|run_number|event\.release|event\.pull_request\.head\.sha)\b[^}]*\}\}`

deny contains finding if {
	some i, j
	job := input.pipeline.jobs[i]
	not _job_allowed(job)
	action := job.uses[j]
	some spec in _cache_action_specs
	_uses_prefix(action.uses, spec.action)
	_cache_active(action, spec)
	not _properly_scoped(action, spec)
	not _enable_unresolved(action, spec)
	_restore_on_release_path(job, action, spec)
	finding := {
		"code":     "ISSUE-705",
		"severity": "high",
		"message":  sprintf("job %q restores a cache via %q on a release-type trigger — scope the key (and any restore-keys) to the release ref or disable caching on publish paths", [job.name, action.uses]),
		"job":      job.name,
		"uses":     action.uses,
		"line":     object.get(action, "line", 0),
		"subject":  _cache_subject(action),
	}
}

# The unresolvable arm (issue #497): an opt-in enable input or a
# default-mode disable input that is a whole-value expression outside
# the resolvable shapes cannot be resolved per trigger. Asserting the
# High restore would be a guess, so the rule reports the medium
# verify-manually code instead, and only when the step itself can share
# an event with a publish.
deny contains finding if {
	some i, j
	job := input.pipeline.jobs[i]
	not _job_allowed(job)
	action := job.uses[j]
	some spec in _cache_action_specs
	_uses_prefix(action.uses, spec.action)
	_cache_active(action, spec)
	not _properly_scoped(action, spec)
	_enable_unresolved(action, spec)
	_step_on_release_path(job, action)
	finding := {
		"code":     "ISSUE-717",
		"severity": "medium",
		"message":  sprintf("job %q gates the cache of %q with an expression that cannot be resolved per trigger on a release path, verify the cache is disabled on publish runs or scope the key (and any restore-keys) to the release ref", [job.name, action.uses]),
		"job":      job.name,
		"uses":     action.uses,
		"line":     object.get(action, "line", 0),
		"subject":  _cache_subject(action),
	}
}

# ── release context ──────────────────────────────────────────────────
_is_release_context(job) if {
	some t in job.triggers
	t == "release"
}

_is_release_context(job) if {
	some k
	_is_publish_action(job.uses[k].uses)
}

_is_release_context(job) if {
	some k
	_is_publish_script(job.scripts[k])
}

_is_publish_script(script) if {
	some pat in _publish_script_patterns
	regex.match(pat, script)
	not _script_excluded(script)
}

# A script that matches an exclude pattern is not publish intent — e.g.
# `npm publish --dry-run` pack checks or gradle publishToMavenLocal.
_script_excluded(script) if {
	some pat in _publish_script_exclude_patterns
	regex.match(pat, script)
}

_is_publish_action(uses) if {
	some p in _publish_actions
	_uses_prefix(uses, p)
}

# ── per-trigger resolution (issue #497) ──────────────────────────────
# GitHub expands `${{ }}` expressions before a step runs, so a step
# `if:` or an opt-in enable input of the single-comparison shape
# github.event_name ==/!= '<event>' pins the step to a knowable subset
# of the workflow's triggers. Only that shape is resolved; any other
# condition conservatively restricts nothing. With trigger data the
# finding requires an event where the action both restores (job
# triggers, narrowed by the step if and the enable expression) and the
# job publishes; without trigger data the job-level release context
# stands as before.
_has_triggers(job) if count(object.get(job, "triggers", [])) > 0

# The event universe. For an ordinary workflow it is the trigger list.
# A reusable workflow (workflow_call) runs under the CALLER's event:
# github.event_name is never the literal "workflow_call", so the
# universe is open (PR #500 review). The finite abstraction that keeps
# ==/!= resolution sound over an open universe: every event a condition
# in the job names (each a caller event the conditions distinguish),
# plus a caller token that satisfies every != but no ==.
_job_events(job) := {t | some t in job.triggers} if not _reusable(job)

_job_events(job) := out if {
	_reusable(job)
	concrete := {t | some t in job.triggers; t != "workflow_call"}
	out := (concrete | _mentioned_events(job)) | {"__caller_event__"}
}

_reusable(job) if {
	some t in job.triggers
	t == "workflow_call"
}

# Every event name a job's conditions test: the job-level if,
# step-level ifs on actions and run scripts, and whole-value
# with-input expressions (the enable and disable shapes both reduce to
# an event comparison).
_mentioned_events(job) := out if {
	from_job_if := {ev | cmp := _event_comparison(object.get(job, "if", "")); ev := cmp[1]}
	from_action_ifs := {ev | some k; cmp := _event_comparison(object.get(job.uses[k], "if", "")); ev := cmp[1]}
	from_script_ifs := {ev | some k; job.scripts[k] != ""; cmp := _event_comparison(_script_if(job, k)); ev := cmp[1]}
	from_inputs := {ev | some k; some name; ev := _with_value_event(job.uses[k].with[name])}
	out := ((from_job_if | from_action_ifs) | from_script_ifs) | from_inputs
}

_with_value_event(v) := ev if {
	cmp := _enable_expr(v)
	ev := cmp[1]
}

_with_value_event(v) := ev if {
	not _enable_expr(v)
	is_string(v)
	contains(v, "${{")
	cmp := _event_comparison(v)
	ev := cmp[1]
}

_restore_on_release_path(job, action, spec) if {
	_has_triggers(job)
	evs := _gated_job_events(job)
	restore := _cond_events(object.get(action, "if", ""), evs) & _enable_events(action, spec, evs)
	count(restore & _publish_events(job, evs)) > 0
}

_restore_on_release_path(job, _, _) if {
	not _has_triggers(job)
	_is_release_context(job)
}

# _step_on_release_path ignores the enable input entirely: it carries
# the unresolvable arm, where only the step's own if is trustworthy.
_step_on_release_path(job, action) if {
	_has_triggers(job)
	evs := _gated_job_events(job)
	step := _cond_events(object.get(action, "if", ""), evs)
	count(step & _publish_events(job, evs)) > 0
}

# The JOB-level if gates every step (PR #500 review): it narrows the
# whole event universe before any step-level resolution, so a job
# whose if excludes the release event is off the release path with
# every step it contains.
_gated_job_events(job) := _cond_events(object.get(job, "if", ""), _job_events(job))

_step_on_release_path(job, _) if {
	not _has_triggers(job)
	_is_release_context(job)
}

# The events on which the job publishes: the release trigger itself
# (read off the trigger list, never the abstract universe), plus each
# publish action or publish script narrowed by its own step-level if
# (`scriptIfs` mirrors `scripts` index for index).
_publish_events(job, evs) := out if {
	rel := {t | some t in job.triggers; t == "release"}
	acts := union({_cond_events(object.get(job.uses[k], "if", ""), evs) | some k; _is_publish_action(job.uses[k].uses)})
	scripts := union({_cond_events(_script_if(job, k), evs) | some k; _is_publish_script(job.scripts[k])})
	out := (rel | acts) | scripts
}

_script_if(job, k) := s if {
	ifs := object.get(job, "scriptIfs", [])
	k < count(ifs)
	s := ifs[k]
}

_script_if(job, k) := "" if {
	ifs := object.get(job, "scriptIfs", [])
	not k < count(ifs)
}

# _cond_events narrows an event set by a step-level `if:`. An
# unrecognized condition narrows nothing: the step may run anywhere.
_cond_events(cond, evs) := out if {
	cmp := _event_comparison(cond)
	out := _events_matching(cmp[0], cmp[1], evs)
}

_cond_events(cond, evs) := evs if not _event_comparison(cond)

_events_matching("==", ev, evs) := {e | some e in evs; e == ev}

_events_matching("!=", ev, evs) := {e | some e in evs; e != ev}

# _event_comparison parses `github.event_name ==/!= '<event>'` (bare or
# `${{ }}`-wrapped) into [operator, event]; undefined for anything else.
_event_comparison(s) := [op, ev] if {
	m := regex.find_all_string_submatch_n(`^github\.event_name\s*(==|!=)\s*'([^']+)'$`, _expr_body(s), 1)
	count(m) == 1
	op := m[0][1]
	ev := m[0][2]
}

# The expression body: the whole value is one `${{ ... }}` expression,
# or bare expression text with no braces at all (the `if:` form).
_expr_body(s) := b if {
	is_string(s)
	m := regex.find_all_string_submatch_n(`^\s*\$\{\{\s*(.*?)\s*\}\}\s*$`, s, 1)
	count(m) == 1
	b := m[0][1]
}

_expr_body(s) := trim_space(s) if {
	is_string(s)
	not contains(s, "${{")
}

# ── does the action restore a cache? (fully spec-driven) ─────────────
_cache_active(_, spec) if spec.mode == "always"

_cache_active(action, spec) if {
	spec.mode == "default"
	not _cache_disabled(action, spec)
}

_cache_active(action, spec) if {
	spec.mode == "opt-in"
	_cache_enabled(action, spec)
}

# A default-on action is disabled when its disableInput holds disableValue
# (matched against the YAML boolean and the quoted-string form, any case).
_cache_disabled(action, spec) if {
	v := action.with[spec.disableInput]
	_as_bool(v) == spec.disableValue
}

# An opt-in action caches only when its enableInput names a manager.
# When the spec carries enableContains, the input value must also
# contain that substring (e.g. build-push-action restores a poisonable
# cache only when cache-from mentions type=gha, not type=registry).
_cache_enabled(action, spec) if {
	c := action.with[spec.enableInput]
	is_string(c)
	c != ""
	lower(c) != "false"
	_enable_value_matches(c, spec)
}

_enable_value_matches(_, spec) if not spec.enableContains

_enable_value_matches(c, spec) if contains(lower(c), lower(spec.enableContains))

# ── enable-input event resolution (issue #497) ───────────────────────
# _enable_events: the events on which the action's cache is enabled.
_enable_events(_, spec, evs) := evs if spec.mode == "always"

_enable_events(action, spec, evs) := evs if {
	spec.mode == "default"
	not _cache_disabled(action, spec)
	not _disable_condition(action, spec)
}

# Default mode with a conditional disable (PR #500 review): the bare
# comparison ${{ github.event_name ==/!= '<event>' }} resolves to true
# exactly on the matching events, and the cache is disabled where the
# input equals disableValue. cache: ${{ github.event_name != 'release' }}
# on setup-go (disableValue false) therefore caches only where the
# comparison holds; cache-disabled: ${{ github.event_name == 'release' }}
# on setup-gradle (disableValue true) caches only where it does not.
_enable_events(action, spec, evs) := out if {
	spec.mode == "default"
	cmp := _disable_condition(action, spec)
	true_evs := _events_matching(cmp[0], cmp[1], evs)
	out := _disable_complement(spec.disableValue, true_evs, evs)
}

_disable_complement(false, true_evs, _) := true_evs

_disable_complement(true, true_evs, evs) := evs - true_evs

# The disable input holds a whole-value `${{ }}` event comparison.
# Braces are required: without them a with-input is a literal string.
_disable_condition(action, spec) := cmp if {
	c := action.with[spec.disableInput]
	is_string(c)
	contains(c, "${{")
	cmp := _event_comparison(c)
}

# Opt-in with a literal value (including a mixed literal that merely
# embeds an expression, like buildx cache-from lines): enabled on every
# event, exactly the pre-#497 semantics.
_enable_events(action, spec, evs) := evs if {
	spec.mode == "opt-in"
	not _enable_expr(action.with[spec.enableInput])
	_cache_enabled(action, spec)
}

# Opt-in with the canonical conditional shape: enabled exactly on the
# events satisfying the comparison, provided the manager it yields is a
# real cache manager for this spec.
_enable_events(action, spec, evs) := out if {
	spec.mode == "opt-in"
	cmp := _enable_expr(action.with[spec.enableInput])
	_enable_value_matches(cmp[2], spec)
	out := _events_matching(cmp[0], cmp[1], evs)
}

# The canonical conditional-enable shape:
#   ${{ github.event_name != '<event>' && '<manager>' || '' }}
# and its == inverse: the manager exactly on the events satisfying the
# comparison, '' on the rest. Braces are required: without them a
# with-input is a literal string, never an expression.
_enable_expr(c) := [op, ev, mgr] if {
	is_string(c)
	contains(c, "${{")
	m := regex.find_all_string_submatch_n(`^github\.event_name\s*(==|!=)\s*'([^']+)'\s*&&\s*'([^']+)'\s*\|\|\s*''$`, _expr_body(c), 1)
	count(m) == 1
	op := m[0][1]
	ev := m[0][2]
	mgr := m[0][3]
}

# A whole-value expression outside the canonical shape cannot be
# resolved per trigger (the unresolvable arm). A mixed literal value
# embedding an expression keeps the literal semantics instead.
_enable_unresolved(action, spec) if {
	spec.mode == "opt-in"
	_whole_value_expression(action.with[spec.enableInput])
	not _enable_expr(action.with[spec.enableInput])
}

# Same for a default-mode disable input: the author wired something
# conditional the analyzer cannot resolve, so asserting the restore
# would be a guess just as in the opt-in case.
_enable_unresolved(action, spec) if {
	spec.mode == "default"
	_whole_value_expression(action.with[spec.disableInput])
	not _disable_condition(action, spec)
}

_whole_value_expression(c) if {
	is_string(c)
	regex.match(`^\s*\$\{\{`, c)
	regex.match(`\}\}\s*$`, c)
}

# Normalise a with-value to a bool: a real bool as-is, or a "true"/"false"
# string (any case) to its bool. Anything else is undefined (no match).
_as_bool(v) := v if is_boolean(v)

_as_bool(v) := true if {
	is_string(v)
	lower(v) == "true"
}

_as_bool(v) := false if {
	is_string(v)
	lower(v) == "false"
}

# ── key scoping ──────────────────────────────────────────────────────
# Properly scoped means the key weaves the ref AND no restore-keys entry
# falls back to an unscoped prefix.
_properly_scoped(action, spec) if {
	_key_is_release_scoped(action, spec)
	not _has_unscoped_restore_key(action)
}

_key_is_release_scoped(action, _) if {
	key := action.with.key
	is_string(key)
	regex.match(release_scope_pattern, key)
}

# Buildx cache backends encode their key namespace in the backend options:
# scope for gha, and name for s3/azblob. Treat those like an actions/cache key.
# Specs without enableInput leave value undefined, skipping this clause so key applies.
_key_is_release_scoped(action, spec) if {
	value := action.with[spec.enableInput]
	is_string(value)
	some entry in split(value, "\n")
	some backend in [["gha", "scope"], ["s3", "name"], ["azblob", "name"]]
	regex.match(sprintf(`(?i)(^|,)[ ]*type[ ]*=[ ]*%s(,|$)`, [backend[0]]), entry)
	regex.match(sprintf(`(?i)(^|,)[ ]*%s[ ]*=[ ]*[^,]*%s`, [backend[1], release_scope_pattern]), entry)
	not _has_unscoped_backend_entry(value)
}

_has_unscoped_backend_entry(value) if {
	some entry in split(value, "\n")
	some backend in [["gha", "scope"], ["s3", "name"], ["azblob", "name"]]
	regex.match(sprintf(`(?i)(^|,)[ ]*type[ ]*=[ ]*%s(,|$)`, [backend[0]]), entry)
	not regex.match(sprintf(`(?i)(^|,)[ ]*%s[ ]*=[ ]*[^,]*%s`, [backend[1], release_scope_pattern]), entry)
}

_has_unscoped_restore_key(action) if {
	some k in _restore_keys(action)
	trim_space(k) != ""
	not regex.match(release_scope_pattern, k)
}

# restore-keys is authored either as a `|` block scalar (one key per
# line) or a YAML list.
_restore_keys(action) := ks if {
	is_string(action.with["restore-keys"])
	ks := split(action.with["restore-keys"], "\n")
}

_restore_keys(action) := ks if {
	is_array(action.with["restore-keys"])
	ks := action.with["restore-keys"]
}

# ── subject ──────────────────────────────────────────────────────────
# The cache a run that is not trusted can write, the entry of an attack
# path into the job that restores it: the key when it is not scoped to the
# release ref, else the first restore-keys prefix that is not, else the
# cache action itself (a setup action's built-in cache, a buildx backend).
# A restore-only key that no job of the pipeline saves (a sentinel such as
# `never_saved`, written so the restore-keys always decide) names no
# cache: the restore-keys prefix is the cache, so two restores sharing the
# sentinel stay two caches.
_cache_subject(action) := key if {
	key := object.get(action, ["with", "key"], "")
	is_string(key)
	key != ""
	not regex.match(release_scope_pattern, key)
	not _sentinel_key(action, key)
} else := prefixes[0] if {
	prefixes := [trim_space(k) |
		some k in _restore_keys(action)
		trim_space(k) != ""
		not regex.match(release_scope_pattern, k)
	]
	count(prefixes) > 0
} else := action.uses

# _sentinel_key: a literal key of a restore-only step (actions/cache/restore)
# with restore-keys, that no actions/cache or actions/cache/save step of the
# pipeline saves.
_sentinel_key(action, key) if {
	_uses_prefix(action.uses, "actions/cache/restore")
	not contains(key, "${{")
	count(_restore_keys(action)) > 0
	not _key_saved_somewhere(key)
}

_key_saved_somewhere(key) if {
	some job in input.pipeline.jobs
	some a in object.get(job, "uses", [])
	some saver in ["actions/cache", "actions/cache/save"]
	_uses_prefix(a.uses, saver)
	object.get(a, ["with", "key"], "") == key
}

# ── allowlist: jobs the org has reviewed and accepted ────────────────
_job_allowed(job) if {
	some pattern in object.get(input, ["config", "cachePoisoning", "allowedJobs"], [])
	glob.match(pattern, null, job.name)
}

# ── helpers ──────────────────────────────────────────────────────────
# GitHub resolves owner/repo case-insensitively, so the inventory match
# must too (swatinem/rust-cache == Swatinem/rust-cache).
_uses_prefix(uses, p) if lower(uses) == lower(p)

_uses_prefix(uses, p) if startswith(lower(uses), lower(sprintf("%s@", [p])))
