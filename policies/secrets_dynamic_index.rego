# secrets-dynamic-index — flag workflows that access a secret through
# a non-literal index: `${{ secrets[expr] }}` with expr = env.X,
# inputs.X, matrix.X, vars.X, or any expression. The bracket form
# resolves the secret name at runtime, which defers authorisation
# from the reviewer (who reads the YAML) to whatever drives expr.
#
# When expr is maintainer-controlled (an env binding in the same
# workflow) the immediate risk is low; the real concern is the
# pattern's fragility — a later refactor that introduces a template
# expression at the indexed position, or a matrix parameter that
# leaks into expr, promotes the weakness silently.
#
# Detection looks across scripts, env values and action `with:`
# inputs for the pattern `secrets[...]` where the inside is anything
# other than a pure quoted string literal.
package secrets_dynamic_index

import rego.v1

# Match `secrets[...]` where the inner content is NOT a quoted
# literal. The first character inside the brackets indicates what we
# caught:
#   - A single / double quote → `secrets['NAME']` is the safe form,
#     skip.
#   - Anything else (env., inputs., matrix., vars., `format(…)`, …)
#     → flag.
dynamic_index_pattern := `\$\{\{\s*secrets\s*\[\s*[^'"\s\]]`

deny contains finding if {
	some i
	job := input.pipeline.jobs[i]
	_job_uses_dynamic_secret_index(job)
	finding := {
		"code":     "ISSUE-308",
		"severity": "low",
		"message":  sprintf("job %q reads a secret through a dynamic index `secrets[...]` — the grant surface is not explicit in the workflow source", [job.name]),
		"job":      job.name,
	}
}

_job_uses_dynamic_secret_index(job) if {
	some k
	regex.match(dynamic_index_pattern, job.scripts[k])
}

_job_uses_dynamic_secret_index(job) if {
	some _, value in job.variables
	regex.match(dynamic_index_pattern, value)
}

_job_uses_dynamic_secret_index(job) if {
	some k
	action := job.uses[k]
	some _, value in action.with
	is_string(value)
	regex.match(dynamic_index_pattern, value)
}
