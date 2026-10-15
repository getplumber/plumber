package utils

import "testing"

func TestCanonicalImageRepo(t *testing.T) {
	cases := []struct {
		registry, name, want string
	}{
		// Docker Hub, as each collector spells it.
		{"", "debian", "docker.io/library/debian"},
		{"docker.io", "debian", "docker.io/library/debian"},
		{"", "docker.io/debian", "docker.io/library/debian"},
		{"", "docker.io/library/debian", "docker.io/library/debian"},
		{"", "library/debian", "docker.io/library/debian"},
		{"docker.io", "library/debian", "docker.io/library/debian"},
		{"", "bitnami/redis", "docker.io/bitnami/redis"},
		{"", "index.docker.io/debian", "docker.io/library/debian"},
		// Other registries keep their host.
		{"ghcr.io", "my-org/report-tool", "ghcr.io/my-org/report-tool"},
		{"", "ghcr.io/my-org/report-tool", "ghcr.io/my-org/report-tool"},
		{"", "localhost/tool", "localhost/tool"},
		{"", "localhost:5000/tool", "localhost:5000/tool"},
		{"", "registry.local:5000/team/tool", "registry.local:5000/team/tool"},
		// The "unknown" registry the GitLab collector emits is not a host.
		{"unknown", "my-org/tool", "docker.io/my-org/tool"},
		// GitLab splits `python@sha256:…` into the name `python@sha256`.
		{"docker.io", "python@sha256", "docker.io/library/python"},
		{"", "", ""},
	}
	for _, tc := range cases {
		if got := CanonicalImageRepo(tc.registry, tc.name); got != tc.want {
			t.Errorf("CanonicalImageRepo(%q, %q) = %q, want %q", tc.registry, tc.name, got, tc.want)
		}
	}
}

func TestImageExempt(t *testing.T) {
	patterns := []string{
		"ghcr.io/my-org/report-tool",
		"debian",
		"quay.io/prometheus/*",
		"docker.io/library/redis",
		"*/busybox",
		"${CI_REGISTRY}/team/tool",
	}
	cases := []struct {
		name, registry, image string
		want                  bool
	}{
		{"exact", "", "ghcr.io/my-org/report-tool", true},
		{"exact split registry", "ghcr.io", "my-org/report-tool", true},
		{"exact is not a prefix", "", "ghcr.io/my-org/report-tool-extra", false},
		{"exact other org", "", "ghcr.io/other-org/report-tool", false},
		{"bare hub pattern, bare image", "", "debian", true},
		{"bare hub pattern, gitlab form", "docker.io", "debian", true},
		{"bare hub pattern, library form", "", "library/debian", true},
		{"bare hub pattern, full form", "", "docker.io/library/debian", true},
		{"hub name on another registry", "", "public.ecr.aws/docker/library/debian", false},
		{"hub lookalike", "", "debian-slim", false},
		{"glob pattern", "", "quay.io/prometheus/busybox", true},
		{"glob pattern crosses slashes", "quay.io", "prometheus/team/busybox", true},
		{"glob pattern other namespace", "", "quay.io/other/tool", false},
		{"canonical pattern, bare image", "", "redis", true},
		{"canonical pattern, gitlab form", "docker.io", "redis", true},
		{"leading glob, hub image", "", "busybox", true},
		{"leading glob, other registry", "", "quay.io/prometheus/busybox", true},
		{"variable pattern, braces in image", "", "${CI_REGISTRY}/team/tool", true},
		{"variable pattern, bare variable in image", "", "$CI_REGISTRY/team/tool", true},
		{"unmatched", "", "alpine", false},
	}
	forbidden := []string{"latest"}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ImageExempt(patterns, forbidden, tc.registry, tc.image, "latest"); got != tc.want {
				t.Errorf("ImageExempt(%q, %q) = %v, want %v", tc.registry, tc.image, got, tc.want)
			}
		})
	}
	if ImageExempt(nil, forbidden, "", "debian", "latest") {
		t.Error("no patterns must exempt nothing")
	}
	if ImageExempt([]string{"[invalid"}, forbidden, "", "debian", "latest") {
		t.Error("an invalid pattern must exempt nothing")
	}
}

// TestImageExemptNeedsForbiddenTag: an exemption covers an exempt image on a
// forbidden tag only. The same image on any other tag is judged as usual, and
// the tag is recovered from the spellings the collectors give a reference that
// carries both a tag and a digest.
func TestImageExemptNeedsForbiddenTag(t *testing.T) {
	patterns := []string{"ghcr.io/my-org/report-tool", "debian"}
	forbidden := []string{"latest", "v*-alpha"}
	cases := []struct {
		name, registry, image, tag string
		want                       bool
	}{
		{"forbidden tag", "", "ghcr.io/my-org/report-tool", "latest", true},
		{"forbidden glob tag", "", "ghcr.io/my-org/report-tool", "v2-alpha", true},
		{"version tag", "", "ghcr.io/my-org/report-tool", "v1.0.2", false},
		{"no tag", "", "ghcr.io/my-org/report-tool", "", false},
		// GitHub keeps the tag inside the name when a digest follows it.
		{"github tag and digest", "", "ghcr.io/my-org/report-tool:latest", "", true},
		{"github version tag and digest", "", "ghcr.io/my-org/report-tool:v1.0.2", "", false},
		{"github registry port, digest only", "", "localhost:5000/debian", "", false},
		// GitLab keeps `@<algo>` inside the tag, or inside the name when
		// there is no tag.
		{"gitlab tag and digest", "docker.io", "debian", "latest@sha256", true},
		{"gitlab version tag and digest", "docker.io", "debian", "12@sha256", false},
		{"gitlab digest only", "docker.io", "debian@sha256", "913f6706df59", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ImageExempt(patterns, forbidden, tc.registry, tc.image, tc.tag); got != tc.want {
				t.Errorf("ImageExempt(%q, %q, %q) = %v, want %v", tc.registry, tc.image, tc.tag, got, tc.want)
			}
		})
	}
	if ImageExempt(patterns, nil, "", "debian", "latest") {
		t.Error("with no forbidden tags configured, nothing is exempt")
	}
}

func TestTagForbidden(t *testing.T) {
	patterns := []string{"latest", "v*-alpha"}
	cases := []struct {
		tag  string
		want bool
	}{
		{"latest", true},
		{"v1.2-alpha", true},
		{"v1.2", false},
		{"latest-1", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := TagForbidden(patterns, tc.tag); got != tc.want {
			t.Errorf("TagForbidden(%q) = %v, want %v", tc.tag, got, tc.want)
		}
	}
}
