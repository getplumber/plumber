package runners

import "testing"

// TestPreinstalled pins the dated hosted-runner tool table
// (PreinstalledAsOf): a tool on the family's own list is preinstalled,
// one absent from it is not, and a family this table does not cover
// answers known=false rather than guessing not-preinstalled.
func TestPreinstalled(t *testing.T) {
	cases := []struct {
		name         string
		family, tool string
		preinstalled bool
		known        bool
	}{
		{"ubuntu rustup preinstalled", "ubuntu", "rustup", true, true},
		{"ubuntu docker preinstalled", "ubuntu", "docker", true, true},
		{"macos has no docker", "macos", "docker", false, true},
		{"windows has no rustup", "windows", "rustup", false, true},
		{"windows docker preinstalled", "windows", "docker", true, true},
		{"unknown family", "self-hosted", "rustup", false, false},
		{"empty family", "", "go", false, false},
		{"case insensitive family and tool", "Ubuntu", "RUSTUP", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			preinstalled, known := Preinstalled(tc.family, tc.tool)
			if preinstalled != tc.preinstalled || known != tc.known {
				t.Fatalf("Preinstalled(%q, %q) = (%v, %v), want (%v, %v)",
					tc.family, tc.tool, preinstalled, known, tc.preinstalled, tc.known)
			}
		})
	}
}

// TestLabelFamily pins how a job's runs-on labels resolve to a hosted
// OS family: a plain "<family>-*" label resolves with certainty, an
// expression or a disagreeing matrix never does.
func TestLabelFamily(t *testing.T) {
	cases := []struct {
		name       string
		labels     []string
		expression bool
		family     string
		known      bool
	}{
		{"ubuntu-latest", []string{"ubuntu-latest"}, false, "ubuntu", true},
		{"macos-14", []string{"macos-14"}, false, "macos", true},
		{"windows-2022", []string{"windows-2022"}, false, "windows", true},
		{"self-hosted label", []string{"self-hosted"}, false, "", false},
		{"custom label", []string{"gpu-runner"}, false, "", false},
		{"expression", []string{"${{ matrix.os }}"}, true, "", false},
		{"no labels", nil, false, "", false},
		{"matrix of agreeing labels", []string{"ubuntu-latest", "ubuntu-22.04"}, false, "ubuntu", true},
		{"matrix of disagreeing labels", []string{"ubuntu-latest", "windows-latest"}, false, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			family, known := LabelFamily(tc.labels, tc.expression)
			if family != tc.family || known != tc.known {
				t.Fatalf("LabelFamily(%v, %v) = (%q, %v), want (%q, %v)",
					tc.labels, tc.expression, family, known, tc.family, tc.known)
			}
		})
	}
}
