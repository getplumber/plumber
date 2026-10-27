package utils

import "testing"

// TestSplitGitHubImageRef pins the GitHub image parser shared by the
// workflow collector (container:, docker:// steps), the PBOM and the
// fixture parser: Docker Hub aliases like registry.hub.docker.com and
// index.docker.io are canonicalized to docker.io so trustedUrls patterns
// match regardless of Hub hostname, and a reference without tag or digest
// reads as `latest`.
func TestSplitGitHubImageRef(t *testing.T) {
	cases := []struct {
		ref        string
		wantName   string
		wantTag    string
		wantDigest string
	}{
		{"registry.hub.docker.com/library/node:alpine", "docker.io/library/node", "alpine", ""},
		{"index.docker.io/python:3.12", "docker.io/python", "3.12", ""},
		{"ghcr.io/astral-sh/uv:latest", "ghcr.io/astral-sh/uv", "latest", ""},
		{"alpine:3.20", "alpine", "3.20", ""},
		// No tag: Docker pulls `latest` (#571).
		{"alpine", "alpine", "latest", ""},
		{"ghcr.io/owner/image", "ghcr.io/owner/image", "latest", ""},
		// The colon before the last slash is a registry port, not a tag.
		{"localhost:5000/app", "localhost:5000/app", "latest", ""},
		{"localhost:5000/app:1.2", "localhost:5000/app", "1.2", ""},
		// A digest is the pin: no tag is made up.
		{"alpine@sha256:abc", "alpine", "", "sha256:abc"},
		// An expression is only known at run time: no tag is made up.
		{"${{ matrix.image }}", "${{ matrix.image }}", "", ""},
		{"${{ inputs.image }}", "${{ inputs.image }}", "", ""},
		{"", "", "", ""},
	}
	for _, tc := range cases {
		got := SplitGitHubImageRef(tc.ref)
		if got.Name != tc.wantName || got.Tag != tc.wantTag || got.Digest != tc.wantDigest {
			t.Errorf("SplitGitHubImageRef(%q) = {name:%q tag:%q digest:%q}, want {name:%q tag:%q digest:%q}",
				tc.ref, got.Name, got.Tag, got.Digest, tc.wantName, tc.wantTag, tc.wantDigest)
		}
	}
}
