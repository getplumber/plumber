# docker-in-docker — flag CI/CD jobs that attach a Docker-in-Docker
# (dind) service. Running a Docker daemon inside a CI container on
# shared runners in privileged mode enables container escape and
# cross-job secret exfiltration. The upstream GitLab documentation
# now recommends Kaniko or Buildah for container builds instead.
package docker_in_docker

import rego.v1

deny contains finding if {
	some i, j
	job := input.pipeline.jobs[i]
	svc := job.services[j]
	_is_dind(svc)
	finding := {
		"code":         "ISSUE-412",
		"severity":     "high",
		"message":      sprintf("job %q uses Docker-in-Docker service %q", [job.name, _image_ref(svc)]),
		"job":          job.name,
		"serviceImage": _image_ref(svc),
	}
}

_is_dind(img) if {
	contains(img.tag, "dind")
}

_is_dind(img) if {
	contains(img.name, "dind")
}

_image_ref(img) := ref if {
	img.tag != ""
	ref := sprintf("%s:%s", [img.name, img.tag])
} else := img.name
