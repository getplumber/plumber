package control

import "testing"

func TestGitlabInstanceHost(t *testing.T) {
	cases := []struct {
		name      string
		gitlabURL string
		want      string
	}{
		{name: "https_gitlab_com", gitlabURL: "https://gitlab.com", want: "gitlab.com"},
		{name: "trailing_slash_stripped", gitlabURL: "https://gitlab.com/", want: "gitlab.com"},
		{name: "http_scheme", gitlabURL: "http://gitlab.example.com", want: "gitlab.example.com"},
		{name: "port_preserved", gitlabURL: "https://gitlab.example.com:8443", want: "gitlab.example.com:8443"},
		{name: "no_scheme_passthrough", gitlabURL: "gitlab.com", want: "gitlab.com"},
		{name: "empty", gitlabURL: "", want: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := gitlabInstanceHost(tc.gitlabURL); got != tc.want {
				t.Errorf("gitlabInstanceHost(%q) = %q, want %q", tc.gitlabURL, got, tc.want)
			}
		})
	}
}

func TestIsGitlabSaaS(t *testing.T) {
	cases := []struct {
		name      string
		gitlabURL string
		want      bool
	}{
		{name: "https_gitlab_com", gitlabURL: "https://gitlab.com", want: true},
		{name: "trailing_slash", gitlabURL: "https://gitlab.com/", want: true},
		{name: "self_hosted", gitlabURL: "https://gitlab.example.com", want: false},
		{name: "http_scheme", gitlabURL: "http://gitlab.com", want: true},
		{name: "empty", gitlabURL: "", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isGitlabSaaS(tc.gitlabURL); got != tc.want {
				t.Errorf("isGitlabSaaS(%q) = %v, want %v", tc.gitlabURL, got, tc.want)
			}
		})
	}
}
