# docker-in-docker-insecure — flag Docker-in-Docker jobs whose daemon
# configuration is exposed without TLS. Two well-documented unsafe
# patterns:
#
#   - DOCKER_TLS_CERTDIR set to the empty string (disables TLS between
#     the Docker client and the daemon).
#   - DOCKER_HOST containing `:2375` (plain TCP daemon endpoint).
#
# The policy only fires when a dind service is already present on the
# job — a daemon that is not shipped with the pipeline cannot leak
# through these variables. Both job-level and pipeline-level globals
# are inspected (matching the legacy detectInsecureDaemon helper).
package docker_in_docker_insecure

import rego.v1

deny contains finding if {
	some i
	job := input.pipeline.jobs[i]
	dind := _first_dind_service(job)
	_insecure_for_job(job)
	detail := _insecure_detail(job)
	finding := {
		"code":     "ISSUE-413",
		"severity": "critical",
		"message":  sprintf("Job '%s': %s", [job.name, detail]),
		"job":      job.name,
		"detail":   detail,
	}
}

_first_dind_service(job) := svc if {
	matching := [s | some k; s := job.services[k]; _is_dind(s)]
	count(matching) > 0
	svc := matching[0]
}

_is_dind(img) if {
	_is_docker_name(img.name)
	img.tag != ""
	_is_dind_tag(img.tag)
}

_is_docker_name(name) if lower(name) == "docker"

_is_docker_name(name) if endswith(lower(name), "/docker")

_is_dind_tag(tag) if lower(tag) == "dind"

_is_dind_tag(tag) if lower(tag) == "latest"

_is_dind_tag(tag) if contains(lower(tag), "dind")

_insecure_for_job(job) if _vars_insecure(job.variables)

_insecure_for_job(job) if _vars_insecure(input.pipeline.globalVariables)

_vars_insecure(vars) if {
	some k, v in vars
	upper(k) == "DOCKER_TLS_CERTDIR"
	trim_space(v) == ""
}

_vars_insecure(vars) if {
	some k, v in vars
	upper(k) == "DOCKER_HOST"
	contains(v, ":2375")
}

# _insecure_detail builds the human-readable clause string for a DinD
# finding. When both insecure conditions are present (DOCKER_HOST on
# port 2375 AND DOCKER_TLS_CERTDIR empty), v0.2.x reported both —
# joined with `; ` and DOCKER_TLS_CERTDIR first — so downstream
# consumers could see the full picture. Mirror that order/wording.
_insecure_detail(job) := detail if {
	_tls_certdir_empty(job)
	host_value := _docker_host_value(job)
	detail := sprintf("DOCKER_TLS_CERTDIR is empty (TLS disabled); DOCKER_HOST uses non-TLS port 2375 (%s)", [host_value])
} else := "DOCKER_TLS_CERTDIR is empty (TLS disabled)" if {
	_tls_certdir_empty(job)
} else := detail if {
	host_value := _docker_host_value(job)
	detail := sprintf("DOCKER_HOST uses non-TLS port 2375 (%s)", [host_value])
} else := "insecure daemon configuration detected"

# _docker_host_value returns the DOCKER_HOST value referencing :2375
# from the job's own variables, falling back to pipeline globals.
_docker_host_value(job) := v if {
	some k, v in job.variables
	upper(k) == "DOCKER_HOST"
	contains(v, ":2375")
} else := v if {
	some k, v in input.pipeline.globalVariables
	upper(k) == "DOCKER_HOST"
	contains(v, ":2375")
}

_tls_certdir_empty(job) if {
	some k, v in job.variables
	upper(k) == "DOCKER_TLS_CERTDIR"
	trim_space(v) == ""
}

_tls_certdir_empty(job) if {
	some k, v in input.pipeline.globalVariables
	upper(k) == "DOCKER_TLS_CERTDIR"
	trim_space(v) == ""
}

_image_ref(img) := ref if {
	img.tag != ""
	ref := sprintf("%s:%s", [img.name, img.tag])
} else := img.name
