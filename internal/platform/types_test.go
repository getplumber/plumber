package platform

import (
	"encoding/json"
	"testing"
)

// dismissed_issues (#447) is forward-tolerant like every other /context field:
// absent decodes to nil, treated the same as an empty served list, and present
// decodes into the three-field match key.
func TestProjectContext_DecodesDismissedIssues(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		var ctx ProjectContext
		if err := json.Unmarshal([]byte(`{"schema_version":1,"project":"grp/app","policies":[],"snapshot":{}}`), &ctx); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if ctx.DismissedIssues != nil {
			t.Fatalf("DismissedIssues = %#v, want nil when the field is absent", ctx.DismissedIssues)
		}
	})

	t.Run("present", func(t *testing.T) {
		body := `{"schema_version":1,"project":"grp/app","policies":[],"snapshot":{},
		  "dismissed_issues":[
		    {"identity_hash":"abc123","recipe_version":4,"control_type":"containerImageMustNotUseForbiddenTags"}
		  ]}`
		var ctx ProjectContext
		if err := json.Unmarshal([]byte(body), &ctx); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(ctx.DismissedIssues) != 1 {
			t.Fatalf("DismissedIssues = %#v, want exactly one entry", ctx.DismissedIssues)
		}
		got := ctx.DismissedIssues[0]
		want := DismissedIssue{IdentityHash: "abc123", RecipeVersion: 4, ControlType: "containerImageMustNotUseForbiddenTags"}
		if got != want {
			t.Fatalf("DismissedIssues[0] = %#v, want %#v", got, want)
		}
	})
}
