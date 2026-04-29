# docker-in-docker — flag CI/CD jobs that attach a Docker-in-Docker
# (dind) service. Running a Docker daemon inside a CI container on
# shared runners in privileged mode enables container escape and
# cross-job secret exfiltration. The upstream GitLab documentation
# now recommends Kaniko or Buildah for container builds instead.
#
# Parity with the legacy Go control (controlGitlabPipelineDockerInDocker.go):
#   - The image must be the `docker` image (registry-prefixed names
#     such as `registry.gitlab.com/group/docker:dind` are accepted —
#     only the trailing path segment matters).
#   - The tag must be `dind`, `latest`, or contain `dind`. Bare
#     `docker` (no tag) is intentionally NOT considered dind.
#   - At most one finding per job, mirroring the legacy `break` after
#     the first matched service.
package docker_in_docker

import rego.v1

deny contains finding if {
	some i
	job := input.pipeline.jobs[i]
	dind := _first_dind_service(job)
	finding := {
		"code":         "ISSUE-412",
		"severity":     "high",
		"message":      sprintf("job %q uses Docker-in-Docker service %q", [job.name, _image_ref(dind)]),
		"job":          job.name,
		"serviceImage": _image_ref(dind),
	}
}

# _first_dind_service preserves the legacy "first match wins" behaviour
# so a job with multiple services never produces more than one
# ISSUE-412 finding.
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

_image_ref(img) := ref if {
	img.tag != ""
	ref := sprintf("%s:%s", [img.name, img.tag])
} else := img.name
