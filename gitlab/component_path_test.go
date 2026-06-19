package gitlab

import "testing"

func TestParseGitlabComponentPath(t *testing.T) {
	const instanceURL = "https://gitlab.example.com"

	cases := []struct {
		name         string
		path         string
		wantInstance string
		wantPath     string
		wantVersion  string
	}{
		{
			name:         "instance prefix with version",
			path:         "gitlab.example.com/group/comp@1.2.3",
			wantInstance: "gitlab.example.com",
			wantPath:     "group/comp",
			wantVersion:  "1.2.3",
		},
		{
			name:         "instance prefix without version",
			path:         "gitlab.example.com/group/comp",
			wantInstance: "gitlab.example.com",
			wantPath:     "group/comp",
			wantVersion:  "",
		},
		{
			name:         "CI_SERVER_FQDN variable prefix",
			path:         "$CI_SERVER_FQDN/group/comp@main",
			wantInstance: "$CI_SERVER_FQDN",
			wantPath:     "group/comp",
			wantVersion:  "main",
		},
		{
			name:         "CI_SERVER_HOST variable prefix",
			path:         "$CI_SERVER_HOST/group/comp@v1",
			wantInstance: "$CI_SERVER_HOST",
			wantPath:     "group/comp",
			wantVersion:  "v1",
		},
		{
			name:         "CI_SERVER_URL variable prefix",
			path:         "$CI_SERVER_URL/group/comp@v2",
			wantInstance: "$CI_SERVER_URL",
			wantPath:     "group/comp",
			wantVersion:  "v2",
		},
		{
			name: "no known prefix leaves instance empty and path intact",
			// A path that does not match the configured instance nor any
			// CI variable keeps instance empty and the path unchanged
			// (only the version is still split off).
			path:         "other-host.com/group/comp@3.0",
			wantInstance: "",
			wantPath:     "other-host.com/group/comp",
			wantVersion:  "3.0",
		},
		{
			name:         "no version separator yields empty version",
			path:         "gitlab.example.com/group/comp",
			wantInstance: "gitlab.example.com",
			wantPath:     "group/comp",
			wantVersion:  "",
		},
		{
			name: "multiple at signs keep only the first segment as path",
			// strings.Split keeps componentSplit[0] as the path and
			// componentSplit[1] as the version; any segment after a
			// second '@' is dropped. This locks that documented behaviour.
			path:         "gitlab.example.com/group/comp@1.0@extra",
			wantInstance: "gitlab.example.com",
			wantPath:     "group/comp",
			wantVersion:  "1.0",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotInstance, gotPath, gotVersion := ParseGitlabComponentPath(tc.path, instanceURL)
			if gotInstance != tc.wantInstance {
				t.Errorf("instance = %q, want %q", gotInstance, tc.wantInstance)
			}
			if gotPath != tc.wantPath {
				t.Errorf("path = %q, want %q", gotPath, tc.wantPath)
			}
			if gotVersion != tc.wantVersion {
				t.Errorf("version = %q, want %q", gotVersion, tc.wantVersion)
			}
		})
	}
}

// TestParseGitlabComponentPath_HTTPScheme confirms the instance match
// works when instanceURL uses http:// (the prefix is stripped before
// comparison, same as https://).
func TestParseGitlabComponentPath_HTTPScheme(t *testing.T) {
	instance, path, version := ParseGitlabComponentPath("gitlab.local/g/c@1", "http://gitlab.local")
	if instance != "gitlab.local" || path != "g/c" || version != "1" {
		t.Fatalf("got (%q, %q, %q), want (gitlab.local, g/c, 1)", instance, path, version)
	}
}
