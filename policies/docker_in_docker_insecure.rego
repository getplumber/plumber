# docker-in-docker-insecure — flag Docker-in-Docker jobs whose daemon
# configuration is exposed without TLS. Two well-documented unsafe
# patterns:
#
#   - DOCKER_TLS_CERTDIR set to the empty string (disables TLS between
#     the Docker client and the daemon).
#   - DOCKER_HOST pointing to a plain tcp://…:2375 endpoint (same
#     effect, other pathway).
#
# The policy only fires when a dind service is already present on the
# job — a daemon that is not shipped with the pipeline cannot leak
# through these variables.
package docker_in_docker_insecure

import rego.v1

deny contains finding if {
	some i, j
	job := input.pipeline.jobs[i]
	svc := job.services[j]
	_is_dind(svc)
	_insecure_daemon(job.variables)
	finding := {
		"code":     "ISSUE-413",
		"severity": "critical",
		"message":  sprintf("job %q runs %q with an insecure daemon configuration", [job.name, _image_ref(svc)]),
		"job":      job.name,
		"detail":   _insecure_detail(job.variables),
	}
}

_insecure_detail(vars) := "DOCKER_TLS_CERTDIR set to empty string disables TLS" if {
	vars.DOCKER_TLS_CERTDIR == ""
} else := sprintf("DOCKER_HOST=%q exposes the daemon over plain TCP (port 2375)", [vars.DOCKER_HOST]) if {
	contains(vars.DOCKER_HOST, "tcp://")
	contains(vars.DOCKER_HOST, ":2375")
} else := "insecure daemon configuration detected"

_is_dind(img) if contains(img.tag, "dind")

_is_dind(img) if contains(img.name, "dind")

_insecure_daemon(vars) if {
	vars.DOCKER_TLS_CERTDIR == ""
}

_insecure_daemon(vars) if {
	contains(vars.DOCKER_HOST, "tcp://")
	contains(vars.DOCKER_HOST, ":2375")
}

_image_ref(img) := ref if {
	img.tag != ""
	ref := sprintf("%s:%s", [img.name, img.tag])
} else := img.name
