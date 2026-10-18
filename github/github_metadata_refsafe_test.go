package github

import (
	"net/http"
	"reflect"
	"testing"
)

func TestSafeActionAPIRef(t *testing.T) {
	ok := []struct{ o, r, ref string }{
		{"actions", "checkout", "v4"},
		{"actions", "checkout", "08eba0b27e820071cde6df949e0beb9ba4906955"},
		{"my-org", "setup-go", "release/1.0"}, // a slash branch ref is a real ref
		{"jdoe_acme", "tool", "v1"},           // EMU login with an underscore
		{"owner", "repo.js", "v2"},            // a dotted repo name
	}
	for _, c := range ok {
		if !safeActionAPIRef(c.o, c.r, c.ref) {
			t.Errorf("want safe: %s/%s@%s", c.o, c.r, c.ref)
		}
	}
	bad := []struct{ o, r, ref string }{
		{"owner", "repo", "v1?per_page=1"},    // query injection
		{"owner", "repo", "v1#frag"},          // fragment
		{"owner", "repo", "../../../../user"}, // path traversal
		{"owner", "repo", "v1 and a space"},   // space
		{"owner", "repo", "v1%2e%2e"},         // percent-encoding
		{"owner", "repo", ""},                 // empty
		{"ow/ner", "repo", "v1"},              // slash in owner
		{"owner", "repo", "v1\ninjected"},     // newline in ref
		{"owner", "repo", "v1\tX"},            // tab in ref
		{"owner", "repo", "v1\x7f"},           // DEL control character
		{"own\\ner", "repo", "v1"},            // backslash in owner
	}
	for _, c := range bad {
		if safeActionAPIRef(c.o, c.r, c.ref) {
			t.Errorf("want rejected: %q/%q@%q", c.o, c.r, c.ref)
		}
	}
}

// The guard must be wired into the call sites, not only the predicate: an
// unsafe ref returns the zero result without issuing any REST request.
func TestResolveAndResolveTagShaRejectUnsafeRefWithoutRequest(t *testing.T) {
	c := stubbedMetadataClient(t, func(r *http.Request) (string, int) {
		t.Errorf("unexpected REST request for an unsafe ref: %s", r.URL.Path)
		return "{}", http.StatusOK
	})
	for _, ref := range []string{"owner/repo@../../../../orgs/victim", "owner/repo@v1?per_page=1"} {
		if got := c.Resolve(ref); !reflect.DeepEqual(got, GitHubMetadata{}) {
			t.Errorf("Resolve(%q) = %+v, want zero metadata", ref, got)
		}
	}
	for _, tc := range []struct{ repo, tag string }{
		{"owner/repo", "v1\ninjected"},
		{"owner/repo", "v1?per_page=1"},
	} {
		if got := c.ResolveTagSha(tc.repo, tc.tag); got != "" {
			t.Errorf("ResolveTagSha(%q,%q) = %q, want empty", tc.repo, tc.tag, got)
		}
	}
}
