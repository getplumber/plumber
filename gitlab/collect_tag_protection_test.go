package gitlab

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/internal/ir"
)

func tagProtectionServer(protectedStatus int, protectedBody, tagsBody string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/protected_tags"):
			if protectedStatus != http.StatusOK {
				w.WriteHeader(protectedStatus)
				return
			}
			_, _ = w.Write([]byte(protectedBody))
		case strings.HasSuffix(r.URL.Path, "/repository/tags"):
			_, _ = w.Write([]byte(tagsBody))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestCollectGitlabTagProtection(t *testing.T) {
	t.Run("success maps protected tags and tag names", func(t *testing.T) {
		srv := tagProtectionServer(http.StatusOK,
			`[{"name":"v*","create_access_levels":[{"access_level":40,"access_level_description":"Maintainers"}]},
			  {"name":"release-*","create_access_levels":[{"access_level":30},{"user_id":7,"access_level":40}]}]`,
			`[{"name":"v1.0.0"},{"name":"release-2"}]`)
		defer srv.Close()
		conf := &configuration.Configuration{GitlabURL: srv.URL, HTTPClientTimeout: 30 * time.Second}

		data, err := CollectGitlabTagProtection("group/project", "tok", conf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := &GitlabTagProtectionData{
			Known: true,
			Tags:  []string{"v1.0.0", "release-2"},
			Protections: []TagProtection{
				{Name: "v*", CreateAccessLevels: []BranchProtectionAccessLevel{{AccessLevel: 40, AccessLevelDescription: "Maintainers"}}},
				{Name: "release-*", CreateAccessLevels: []BranchProtectionAccessLevel{{AccessLevel: 30}}},
			},
		}
		if !reflect.DeepEqual(data, want) {
			t.Fatalf("got  %+v\nwant %+v", data, want)
		}
	})

	t.Run("protected tags past the page cap are unknown, not partial", func(t *testing.T) {
		entries := make([]string, 100)
		for i := range entries {
			entries[i] = fmt.Sprintf(`{"name":"p%d"}`, i)
		}
		// Every page comes back full, so the listing never ends.
		srv := tagProtectionServer(http.StatusOK, "["+strings.Join(entries, ",")+"]", `[]`)
		defer srv.Close()
		conf := &configuration.Configuration{GitlabURL: srv.URL, HTTPClientTimeout: 30 * time.Second}

		data, err := CollectGitlabTagProtection("group/project", "tok", conf)
		if !errors.Is(err, errProtectedTagsTruncated) {
			t.Fatalf("want errProtectedTagsTruncated, got %v", err)
		}
		if data == nil || data.Known {
			t.Fatalf("want Known=false, got %+v", data)
		}
	})

	t.Run("403 on protected tags is unknown, not empty", func(t *testing.T) {
		srv := tagProtectionServer(http.StatusForbidden, "", `[]`)
		defer srv.Close()
		conf := &configuration.Configuration{GitlabURL: srv.URL, HTTPClientTimeout: 30 * time.Second}

		data, err := CollectGitlabTagProtection("group/project", "tok", conf)
		if err == nil {
			t.Fatal("want the error surfaced")
		}
		if data == nil || data.Known {
			t.Fatalf("want Known=false, got %+v", data)
		}
	})
}

func TestBuildTagProtection(t *testing.T) {
	if BuildTagProtection(nil) != nil {
		t.Fatal("nil collection must map to nil (rule abstains)")
	}
	if got := BuildTagProtection(&GitlabTagProtectionData{Known: false, Tags: []string{"v1"}}); got == nil || got.Known || len(got.Rules) != 0 {
		t.Fatalf("unknown collection must stay unknown with no rules, got %+v", got)
	}

	got := BuildTagProtection(&GitlabTagProtectionData{
		Known: true,
		Tags:  []string{"v1.0.0"},
		Protections: []TagProtection{
			{Name: "v*"}, // no entry: GitLab's default, Maintainers
			{Name: "release-*", CreateAccessLevels: []BranchProtectionAccessLevel{{AccessLevel: 30}}},
			{Name: "stable", CreateAccessLevels: []BranchProtectionAccessLevel{{AccessLevel: 0}}},
			{Name: "rc-*"}, // only user, group or deploy key entries
		},
	})
	want := &ir.TagProtection{
		Known: true,
		Tags:  []string{"v1.0.0"},
		Rules: []ir.TagProtectionRule{
			{ID: "v*", Name: "v*", Source: ir.TagRuleSourceProtectedTag, Include: []string{"v**"}, BlocksUpdate: true, BlocksDeletion: true, RestrictsCreation: true},
			{ID: "release-*", Name: "release-*", Source: ir.TagRuleSourceProtectedTag, Include: []string{"release-**"}, BlocksUpdate: true, BlocksDeletion: true, RestrictsCreation: false},
			{ID: "stable", Name: "stable", Source: ir.TagRuleSourceProtectedTag, Include: []string{"stable"}, BlocksUpdate: true, BlocksDeletion: true, RestrictsCreation: true},
			{ID: "rc-*", Name: "rc-*", Source: ir.TagRuleSourceProtectedTag, Include: []string{"rc-**"}, BlocksUpdate: true, BlocksDeletion: true, RestrictsCreation: true},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %+v\nwant %+v", got, want)
	}
}

func TestGitlabWildcardToGlob(t *testing.T) {
	for in, want := range map[string]string{
		"v*":       "v**",
		"*-stable": "**-stable",
		"v1.0":     "v1.0",
		"v[1]?":    `v\[1\]\?`,
		"a{b}":     `a\{b\}`,
	} {
		if got := gitlabWildcardToGlob(in); got != want {
			t.Errorf("gitlabWildcardToGlob(%q) = %q, want %q", in, got, want)
		}
	}
}
