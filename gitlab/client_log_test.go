package gitlab

import (
	"strings"
	"testing"
)

// TestGraphQLDebugLineKeepsRequestsAndDropsResponses pins what the GraphQL
// client's debug hook forwards to the log. The request side (query text,
// variables, masked headers) is what a debug reader needs to see which call
// ran; the response side is the raw body the caller already unmarshals and
// reports on, so echoing it only duplicated the report into the log, at
// full size, for every page of every query.
func TestGraphQLDebugLineKeepsRequestsAndDropsResponses(t *testing.T) {
	cases := []struct {
		name string
		in   string
		keep bool
	}{
		{"query is kept", ">> query: query getProjectVariables($fullPath: ID!) { project(fullPath: $fullPath) { id } }", true},
		{"variables are kept", ">> variables: map[fullPath:group/project]", true},
		{"headers are kept and masked", ">> headers: map[Authorization:[Bearer glpat-abcdefghijklmnopqrst] Accept:[application/json]]", true},
		{"response body is dropped", `<< {"data":{"project":{"ciVariables":{"nodes":[{"key":"REGISTRY","value":"registry.example.com"}]}}}}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, keep := graphqlDebugLine(tc.in)
			if keep != tc.keep {
				t.Fatalf("keep = %v, want %v", keep, tc.keep)
			}
			if keep && strings.Contains(got, "glpat-") {
				t.Fatalf("a kept header line must be masked, got %q", got)
			}
		})
	}
}
