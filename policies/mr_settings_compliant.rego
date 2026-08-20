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

# The settings the control can check, mapping each key to a human-readable
# label used in the finding message. Listed once so the deviation set and the
# message cannot drift apart.
_labels := {
	"mergeMethod": "merge method",
	"squashOption": "squash option",
	"mergePipelinesEnabled": "merged results pipelines",
	"mergeTrainsEnabled": "merge trains",
	"allowMergeOnSkippedPipeline": "allow merge on skipped pipeline",
	"resolveOutdatedDiffDiscussions": "resolve outdated diff discussions",
	"printingMergeRequestLinkEnabled": "print merge request link on push",
	"removeSourceBranchAfterMerge": "remove source branch after merge",
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
			"merge request settings do not match the configured expectations: %s",
			[concat("; ", clauses)],
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

# _clause renders one deviation as a human-readable "<label> is <actual>
# (expected <expected>)" phrase.
_clause(name, settings, cfg) := sprintf(
	"%s is %v (expected %v)",
	[_labels[name], settings[name], cfg[name]],
)
