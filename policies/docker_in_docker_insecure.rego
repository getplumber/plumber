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

_insecure_detail(job) := detail if {
	detail := _detail_for_vars(job.variables)
} else := detail if {
	detail := _detail_for_vars(input.pipeline.globalVariables)
} else := "insecure daemon configuration detected"

_detail_for_vars(vars) := "DOCKER_TLS_CERTDIR set to empty string disables TLS" if {
	some k, v in vars
	upper(k) == "DOCKER_TLS_CERTDIR"
	trim_space(v) == ""
} else := sprintf("DOCKER_HOST=%q exposes the daemon over plain TCP (port 2375)", [v]) if {
	some k, v in vars
	upper(k) == "DOCKER_HOST"
	contains(v, ":2375")
}

_image_ref(img) := ref if {
	img.tag != ""
	ref := sprintf("%s:%s", [img.name, img.tag])
} else := img.name
