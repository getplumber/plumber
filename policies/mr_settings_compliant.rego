# mr-settings-compliant — flag a project whose merge-request/merge settings do
# not match the operator's configured expectations (GitLab: Settings > Merge
# requests — merge method, squash policy, merge trains, source-branch removal,
# and related options). GitLab-only singleton finding (one per project); the
# legacy platform's identity was empty, so the identity here is the code alone —
# changing WHICH settings deviate does not re-key the finding.
#
# Every expectation is optional (unset = not checked) and each set expectation
# is compared for EXACT equality against the project's actual value. This
# differs deliberately from the legacy platform, which compared all eight fields
# unconditionally with the policy's zero value when a field was unset; the
# platform always supplied a fully populated policy, so optional-here is
# equivalent in practice and keeps a hand-authored YAML from flagging on a field
# the operator never set. Two settings are enums validated at config load
# (mergeMethod, squashOption), so an unknown expectation never reaches here.
#
# The config key allowMergeOnSkippedPipeline maps to GitLab's
# allow_merge_on_skipped_pipeline; the legacy platform called it
# mergeTrainsSkipTrainAllowed, a misnomer corrected in this migration.
#
# Reads input.pipeline.mrSettings, projected in raw form from the protection
# collection (gitlab/gitlab_ir.go::buildMRSettings). The projection is nil —
# absent here — when the project payload could not be read; the rule abstains
# then, so the control reports not-evaluable, not a pass. Merge trains and
# merged-results pipelines are GitLab Premium/Ultimate (false on Free); the
# other settings exist on every tier, so no tier caveat applies to this control.
package mr_settings_compliant

import rego.v1

# The settings the control can check, mapping each key to the subject of its
# clause in the finding message: the setting named the way GitLab's own merge
# request settings page names it, with the verb that agrees with it. Listed
# once so the deviation set and the message cannot drift apart.
_labels := {
	"mergeMethod": "Merge method is",
	"squashOption": "Squash is",
	"mergePipelinesEnabled": "Merged results pipelines are",
	"mergeTrainsEnabled": "Merge trains are",
	"allowMergeOnSkippedPipeline": "Merging on a skipped pipeline is",
	"resolveOutdatedDiffDiscussions": "Resolving outdated diff discussions is",
	"printingMergeRequestLinkEnabled": "Printing the merge request link on push is",
	"removeSourceBranchAfterMerge": "Removing the source branch after merge is",
}

# The two enum settings travel as GitLab API tokens, meaningless to a reader
# of the issues page, which shows this message verbatim. Each value is
# rendered as the label GitLab itself shows for it.
#
# The maps cover every token GitLab defines today. Config validation rejects
# an unknown one on the EXPECTED side at load time; the ACTUAL side comes from
# the API and is never validated, so a token GitLab adds later arrives here
# unmapped and the fallback renders it verbatim rather than mapping it to
# something it is not. That is caught, not merely tolerated: the message-style
# lint (policies/message_style_test.go, enumClauseAllowlists) asserts that the
# text rendered on BOTH sides of these clauses is one of the labels below, so
# an unmapped token fails the build the first time a fixture renders it. That
# is the maintenance contract: a new merge method or squash option in GitLab
# means a new entry here, and the lint is what says so.
_merge_method_labels := {
	"merge": "Merge commit",
	"ff": "Fast-forward merge",
	"rebase_merge": "Rebase and merge",
}

_squash_labels := {
	"never": "Never",
	"always": "Always",
	"default_on": "Allow, on by default",
	"default_off": "Allow, off by default",
}

deny contains finding if {
	input.pipeline.provider == "gitlab"
	settings := input.pipeline.mrSettings
	cfg := object.get(input.config, "mergeRequestSettingsMustBeCompliant", {})
	deviations := _deviations(settings, cfg)
	count(deviations) > 0
	clauses := [_clause(name, settings, cfg) | some name in deviations]
	finding := {
		"code": "ISSUE-506",
		"severity": "medium",
		"message": sprintf(
			"Merge request settings do not match the policy: %s.",
			[concat(", ", clauses)],
		),
		"deviatingSettings": deviations,
	}
}

# _deviations returns the sorted list of setting names whose configured
# expectation does not equal the project's actual value. A setting absent from
# the config is not checked: its cfg lookup is undefined and the row drops.
_deviations(settings, cfg) := sort([name |
	some name, actual in settings
	expected := cfg[name]
	expected != actual
])

# _clause renders one deviation as a human-readable "<subject> <actual>
# (expected <expected>)" phrase, e.g. `Merge method is "Merge commit"
# (expected "Fast-forward merge")` or `Merge trains are disabled (expected
# enabled)`.
_clause(name, settings, cfg) := sprintf(
	"%s %s (expected %s)",
	[_labels[name], _value_text(name, settings[name]), _value_text(name, cfg[name])],
)

# _value_text renders one setting value as a reader sees it in GitLab: the two
# enums as their quoted labels, every other setting (all booleans) as enabled
# or disabled. The last fallback exists only so an unexpected shape renders as
# something rather than making the whole clause undefined.
_value_text(name, value) := sprintf("%q", [object.get(_merge_method_labels, value, value)]) if {
	name == "mergeMethod"
} else := sprintf("%q", [object.get(_squash_labels, value, value)]) if {
	name == "squashOption"
} else := "enabled" if {
	value == true
} else := "disabled" if {
	value == false
} else := sprintf("%v", [value])
