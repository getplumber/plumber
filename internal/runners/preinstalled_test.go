package runners

import (
	"reflect"
	"testing"
)

// TestPreinstalled pins the dated hosted-runner tool table
// (PreinstalledAsOf), per image: a tool on the image's own list is
// preinstalled, one absent from it is not, and an image this table does
// not cover answers known=false rather than guessing not-preinstalled.
func TestPreinstalled(t *testing.T) {
	cases := []struct {
		name         string
		image, tool  string
		preinstalled bool
		known        bool
	}{
		{"ubuntu-24.04 rustup preinstalled", "ubuntu-24.04", "rustup", true, true},
		{"ubuntu-24.04 docker preinstalled", "ubuntu-24.04", "docker", true, true},
		{"ubuntu-24.04 gcloud preinstalled", "ubuntu-24.04", "gcloud", true, true},
		{"ubuntu-24.04 dropped terraform", "ubuntu-24.04", "terraform", false, true},
		{"ubuntu-22.04 terraform preinstalled", "ubuntu-22.04", "terraform", true, true},
		{"no ubuntu image ships pnpm", "ubuntu-22.04", "pnpm", false, true},
		{"no ubuntu image ships uv", "ubuntu-24.04", "uv", false, true},
		{"macos has no docker", "macos", "docker", false, true},
		{"windows has no rustup", "windows", "rustup", false, true},
		{"windows docker preinstalled", "windows", "docker", true, true},
		{"an ubuntu image the table does not carry", "ubuntu-26.04", "rustup", false, false},
		{"unknown image", "self-hosted", "rustup", false, false},
		{"empty image", "", "go", false, false},
		{"case insensitive image and tool", "Ubuntu-24.04", "RUSTUP", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			preinstalled, known := Preinstalled(tc.image, tc.tool)
			if preinstalled != tc.preinstalled || known != tc.known {
				t.Fatalf("Preinstalled(%q, %q) = (%v, %v), want (%v, %v)",
					tc.image, tc.tool, preinstalled, known, tc.preinstalled, tc.known)
			}
		})
	}
}

// TestPlainHostedLabel pins the plain hosted-label parser: the labels
// GitHub documents for each family (ubuntu-<n>.<n>, ubuntu-latest,
// macos-<n>, macos-latest, windows-<n>, windows-latest), case
// insensitive; any other shape (a larger runner, an arm or intel
// variant, a self-hosted label) is not one.
func TestPlainHostedLabel(t *testing.T) {
	cases := []struct {
		label, family string
		ok            bool
	}{
		{"ubuntu-24.04", "ubuntu", true},
		{"Ubuntu-Latest", "ubuntu", true},
		{"macos-14", "macos", true},
		{"macos-latest", "macos", true},
		{"windows-2025", "windows", true},
		{"windows-latest", "windows", true},
		{"ubuntu-24.04-arm", "", false},
		{"ubuntu-latest-4-cores", "", false},
		{"macos-15-intel", "", false},
		{"macos-14-large", "", false},
		{"self-hosted", "", false},
		{"ubuntu-24", "", false},
	}
	for _, tc := range cases {
		family, ok := PlainHostedLabel(tc.label)
		if family != tc.family || ok != tc.ok {
			t.Errorf("PlainHostedLabel(%q) = (%q, %v), want (%q, %v)", tc.label, family, ok, tc.family, tc.ok)
		}
	}
}

// TestLabelImages pins how a job's runs-on labels resolve to the hosted
// images they run: each plain label to its image (ubuntu-latest to
// ubuntu-24.04 today), an expression, a label the parser does not read
// or no label at all never.
func TestLabelImages(t *testing.T) {
	cases := []struct {
		name       string
		labels     []string
		expression bool
		images     []string
		known      bool
	}{
		{"ubuntu-latest", []string{"ubuntu-latest"}, false, []string{"ubuntu-24.04"}, true},
		{"ubuntu-22.04", []string{"ubuntu-22.04"}, false, []string{"ubuntu-22.04"}, true},
		{"macos-14", []string{"macos-14"}, false, []string{"macos"}, true},
		{"windows-2022", []string{"windows-2022"}, false, []string{"windows"}, true},
		{"self-hosted label", []string{"self-hosted"}, false, nil, false},
		{"larger runner", []string{"ubuntu-latest-8-cores"}, false, nil, false},
		{"expression", []string{"${{ matrix.os }}"}, true, nil, false},
		{"no labels", nil, false, nil, false},
		{"several labels", []string{"ubuntu-latest", "ubuntu-22.04"}, false, []string{"ubuntu-24.04", "ubuntu-22.04"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			images, known := LabelImages(tc.labels, tc.expression)
			if !reflect.DeepEqual(images, tc.images) || known != tc.known {
				t.Fatalf("LabelImages(%v, %v) = (%v, %v), want (%v, %v)",
					tc.labels, tc.expression, images, known, tc.images, tc.known)
			}
		})
	}
}
