package expr

import "testing"

// TestHasStatusCallFindsTheConditionsThatRunAfterASkip pins which
// conditions make GitHub run a job whose predecessor was skipped:
// always(), failure() and cancelled() anywhere, success() only under a
// negation. A plain success() is the default and changes nothing.
func TestHasStatusCallFindsTheConditionsThatRunAfterASkip(t *testing.T) {
	cases := []struct {
		cond string
		want bool
	}{
		{"always()", true},
		{"${{ always() }}", true},
		{"failure()", true},
		{"cancelled()", true},
		{"!failure() && !cancelled()", true},
		{"always() && github.event_name == 'push'", true},
		{"Always()", true},
		{"!success()", true},
		{"!(success())", true},
		{"success()", false},
		{"success() && github.event_name == 'push'", false},
		{"github.event_name == 'push'", false},
		{"", false},
		{"contains(github.event.head_commit.message, 'always()')", false},
		// A status call the grammar swallows into an unparseable
		// fragment is still read, by the text fallback.
		{"github.ref == always()", true},
		{"foo(failure())", true},
	}
	for _, tc := range cases {
		if got := HasStatusCall(tc.cond); got != tc.want {
			t.Errorf("HasStatusCall(%q) = %v, want %v", tc.cond, got, tc.want)
		}
	}
}
