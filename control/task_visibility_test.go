package control

import (
	"testing"

	"github.com/getplumber/plumber/gitlab"
	"github.com/getplumber/plumber/internal/ir"
)

func TestApplyGitLabVisibility(t *testing.T) {
	cases := []struct {
		project *gitlab.Project
		want    string
	}{
		{&gitlab.Project{Visibility: "public"}, ir.VisibilityPublic},
		{&gitlab.Project{Visibility: "internal"}, ir.VisibilityPrivate},
		{&gitlab.Project{Visibility: "private"}, ir.VisibilityPrivate},
		{&gitlab.Project{}, ir.VisibilityUnknown},
		{nil, ir.VisibilityUnknown},
	}
	for _, tc := range cases {
		p := &ir.NormalizedPipeline{}
		applyGitLabVisibility(p, tc.project)
		if p.Visibility != tc.want {
			t.Errorf("project %+v: Visibility = %q, want %q", tc.project, p.Visibility, tc.want)
		}
	}
}
