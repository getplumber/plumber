package github

import "testing"

// A false "verified" removes a real attack path: a comparison counts
// only when the literal digest is an operand of a test that starts a
// command.
func TestDigestIsComparisonOperand(t *testing.T) {
	const d = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cases := []struct {
		name string
		line string
		want bool
	}{
		{"single brackets, quoted digest on the right", `[ "$(sha256sum install.sh | cut -d' ' -f1)" = "` + d + `" ]`, true},
		{"double brackets, unquoted digest on the left", `[[ ` + d + ` == "$(sha256sum install.sh)" ]]`, true},
		{"not-equal after if, then exit", `if [ "$(sha256sum install.sh)" != '` + d + `' ]; then exit 1; fi`, true},
		{"test command after &&", `cd x && test "$sum" = ` + d, true},
		{"double brackets with a logical and inside", `[[ -f install.sh && "$s" == ` + d + ` ]]`, true},
		{"bracket inside an echo argument", `echo "[download] install.sh sha256=` + d + `"`, false},
		{"bracket word not starting a command", `echo [ x = ` + d + ` ]`, false},
		{"digest in a trailing comment", `[ "$a" = "$b" ] # ` + d + ` install.sh`, false},
		{"digest as a non-operand argument", `[ -n ` + d + ` ]`, false},
		{"glued equals is one word, not a comparison", `[ "$x"="` + d + `" ]`, false},
		{"unterminated bracket", `[ "$x" = ` + d, false},
		{"single brackets, backtick substitution on the left", "[ `sha256sum install.sh | cut -d' ' -f1` = " + d + " ]", true},
		{"double-quoted backtick substitution operand", "[ \"`sha256sum install.sh`\" = \"" + d + "\" ]", true},
		{"unterminated backtick", "[ `sha256sum install.sh = " + d, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := digestIsComparisonOperand(tc.line, d); got != tc.want {
				t.Fatalf("digestIsComparisonOperand(%q) = %v, want %v", tc.line, got, tc.want)
			}
		})
	}
}
