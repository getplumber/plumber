package capability

import (
	"reflect"
	"strings"
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

// Spec 4.3, the commands subject: a script entry is split on newlines (LF or CRLF), an
// unquoted `#` that starts a word runs to the end of its line and is removed, each line is
// trimmed and an empty one dropped. A `#` inside a word (`foo#bar`, `$#`) or inside quotes
// is not a comment.
func TestScriptLines_Spec43(t *testing.T) {
	cases := []struct {
		entries []string
		want    []string
	}{
		{[]string{"# old: make build && gitleaks detect\n"}, nil},
		{[]string{"echo start\n  # old: make build && gitleaks detect\necho end\n"}, []string{"echo start", "echo end"}},
		{[]string{"echo done # gitleaks detect"}, []string{"echo done"}},
		{[]string{`echo "a # b" && gitleaks detect`}, []string{`echo "a # b" && gitleaks detect`}},
		{[]string{"echo foo#bar && gitleaks detect"}, []string{"echo foo#bar && gitleaks detect"}},
		{[]string{"echo $# && gitleaks detect"}, []string{"echo $# && gitleaks detect"}},
		{[]string{"echo 'x' # c\ngitleaks detect"}, []string{"echo 'x'", "gitleaks detect"}},
		{[]string{"echo a;# c\ngitleaks detect"}, []string{"echo a;", "gitleaks detect"}},
		{[]string{"set -e\r\n./scripts/scan.sh\r\n"}, []string{"set -e", "./scripts/scan.sh"}},
		{[]string{"make build", "  ", "gitleaks detect"}, []string{"make build", "gitleaks detect"}},
		{[]string{`echo "unterminated # quote` + "\ngitleaks detect # x"}, []string{`echo "unterminated # quote`, "gitleaks detect"}},
	}
	for _, c := range cases {
		if got := scriptLines(c.entries); !reflect.DeepEqual(got, c.want) {
			t.Errorf("scriptLines(%q) = %q, want %q", c.entries, got, c.want)
		}
	}
}

// Spec 4.3, the images subject of a container-run line: the first field after `docker|podman|
// nerdctl run` that is neither a flag nor a flag's value. Boolean flags, combined boolean
// short flags (`-dit`) and `=` flags consume nothing, every other flag consumes the next
// field; the fields after the image are the container's command. A `docker run` with only
// flags, or another subcommand, yields nothing and never panics.
func TestContainerRunImage_Spec43(t *testing.T) {
	cases := []struct {
		line string
		want string
		ok   bool
	}{
		{"docker run --rm gcr.io/go-containerregistry/crane copy a b", "gcr.io/go-containerregistry/crane", true},
		{"docker run -dit --network=host --platform linux/amd64 img:1 arg", "img:1", true},
		{"podman run -itd -u 1000 -w /d --mount type=bind,src=.,dst=/d img2 run x", "img2", true},
		{"nerdctl run -p 80:80 --pull always --privileged --init img3", "img3", true},
		{"docker run -P --read-only -q --oom-kill-disable --no-healthcheck --sig-proxy img4", "img4", true},
		{`docker run -e "K=V" 'img5:1' x`, "img5:1", true},
		{`docker run --rm -v "$PWD:/pwd" --entrypoint gitleaks zricethezav/gitleaks:v8 detect`, "zricethezav/gitleaks:v8", true},
		{`sh -c "nerdctl run --rm zricethezav/gitleaks:v8.18.0"`, "zricethezav/gitleaks:v8.18.0", true},
		{"sudo /usr/bin/docker run img6", "img6", true},
		{"docker run --rm alpine:3 sh -c 'docker run inner'", "alpine:3", true},
		{"docker run --rm -it -v a:b", "", false},
		{"docker run", "", false},
		{"docker run -v", "", false},
		{"docker build -t trufflesecurity/trufflehog:latest .", "", false},
		{"echo run img", "", false},
	}
	for _, c := range cases {
		got, ok := containerRunImage(c.line)
		if got != c.want || ok != c.ok {
			t.Errorf("containerRunImage(%q) = (%q, %v), want (%q, %v)", c.line, got, ok, c.want, c.ok)
		}
	}
}

// Spec 4.3, the wrapper_script subject: a relative .sh/.bash path, after an optional `sh`,
// `bash`, `source` or `.`, in any segment the shell operators and newlines split; a relative
// `cd` before it applies, an absolute, bare, variable or escaping one ends the search; an
// absolute path or one with `..` is refused; a commented-out call is not a wrapper. The
// launcher's own options are skipped first: a word starting with `-` is skipped, `-o`/`+o`
// and a combined short option ending in `o` consume the next field as a value, `--` ends the
// options, and a `-c` anywhere among them (an inline command string) still yields no wrapper.
func TestWrapperPath_Spec43(t *testing.T) {
	cases := []struct {
		line string
		want string
		ok   bool
	}{
		{"./scripts/scan.sh", "scripts/scan.sh", true},
		{"sh scripts/scan.sh --fast", "scripts/scan.sh", true},
		{"bash ./ci/secrets.bash", "ci/secrets.bash", true},
		{"source tools/env.sh", "tools/env.sh", true},
		{". ./tools/env.sh", "tools/env.sh", true},
		{"FOO=1 ./scripts/scan.sh", "scripts/scan.sh", true},
		{"/usr/local/bin/scan.sh", "", false},
		{"../outside/scan.sh", "", false},
		{"gitleaks detect", "", false},
		{"sh -c \"gitleaks detect\"", "", false},
		{"python scripts/scan.py", "", false},
		{"bash -x ci/scan.sh", "ci/scan.sh", true},
		{"sh -e ci/scan.sh", "ci/scan.sh", true},
		{"sh -eu scan.sh", "scan.sh", true},
		{"bash -euo pipefail scan.sh", "scan.sh", true},
		{"bash -o pipefail scan.sh", "scan.sh", true},
		{"bash -- scan.sh", "scan.sh", true},
		{"bash -c \"./scan.sh\"", "", false},
		{"sh -x -c \"gitleaks detect\"", "", false},
		{"bash -x", "", false},
		{"bash -o", "", false},
		{"cd ci && ./scan.sh", "ci/scan.sh", true},
		{"make prep && ./scripts/scan.sh", "scripts/scan.sh", true},
		{"./scripts/scan.sh;", "scripts/scan.sh", true},
		{"cd /opt && ./scan.sh", "", false},
		{"cd .. && ./scan.sh", "", false},
		{"cd $DIR && ./scan.sh", "", false},
		{"set -e\n./scripts/scan.sh\n", "scripts/scan.sh", true},
		{"set -e\r\n./scripts/scan.sh\r\n", "scripts/scan.sh", true},
		{"cd ci\n./scan.sh\n", "ci/scan.sh", true},
		{"# ./scripts/scan.sh", "", false},
		{"#./scripts/scan.sh", "", false},
		{"set -e\n# ./scripts/scan.sh\n", "", false},
		{"echo hi # ./scripts/scan.sh", "", false},
		{"# old\n./scripts/scan.sh\n", "scripts/scan.sh", true},
	}
	for _, c := range cases {
		paths := wrapperPaths(c.line)
		got, ok := "", len(paths) > 0
		if ok {
			got = paths[0]
		}
		if got != c.want || ok != c.ok {
			t.Errorf("wrapperPaths(%q) = %q, want first (%q, %v)", c.line, paths, c.want, c.ok)
		}
	}
	// Every qualifying call of an entry, in order; an unsafe cd ends the search after the
	// calls before it; a cd chain past 16 segments ends it too.
	multi := []struct {
		entry string
		want  []string
	}{
		{"./ci/setup.sh\n./ci/scan.sh\n", []string{"ci/setup.sh", "ci/scan.sh"}},
		{"./a.sh && cd ci && ./b.sh; sh c.sh", []string{"a.sh", "ci/b.sh", "ci/c.sh"}},
		{"./a.sh && cd /opt && ./b.sh", []string{"a.sh"}},
		{strings.Repeat("cd a && ", 16) + "./x.sh", []string{strings.Repeat("a/", 16) + "x.sh"}},
		{strings.Repeat("cd a && ", 17) + "./x.sh", nil},
		{"cd " + strings.Repeat("a", 1024) + " && ./x.sh", nil},
	}
	for _, c := range multi {
		if got := wrapperPaths(c.entry); !reflect.DeepEqual(got, c.want) {
			t.Errorf("wrapperPaths(%q) = %q, want %q", c.entry, got, c.want)
		}
	}
}

// Spec 4.3, the images subject: <registry>/<name>, tag and digest stripped, a Docker Hub
// alias canonicalized, an unknown or empty registry read as Docker Hub unless the name
// itself starts with a registry host (an unresolved `ghcr.io/x/y:$TAG`).
func TestImageKey_Spec43(t *testing.T) {
	cases := []struct {
		img  *ir.Image
		want string
	}{
		{&ir.Image{Registry: "unknown", Name: "zricethezav/gitleaks", Tag: "$TAG"}, "docker.io/zricethezav/gitleaks"},
		{&ir.Image{Registry: "", Name: "alpine"}, "docker.io/alpine"},
		{&ir.Image{Registry: "docker.io", Name: "zricethezav/gitleaks:v8"}, "docker.io/zricethezav/gitleaks"},
		{&ir.Image{Registry: "index.docker.io", Name: "zricethezav/gitleaks"}, "docker.io/zricethezav/gitleaks"},
		{&ir.Image{Registry: "ghcr.io", Name: "gitleaks/gitleaks@sha256:abc"}, "ghcr.io/gitleaks/gitleaks"},
		{&ir.Image{Registry: "unknown", Name: "ghcr.io/gitleaks/gitleaks"}, "ghcr.io/gitleaks/gitleaks"},
		{&ir.Image{Registry: "localhost:5000", Name: "scan"}, "localhost:5000/scan"},
	}
	for _, c := range cases {
		if got := imageKey(c.img); got != c.want {
			t.Errorf("imageKey(%+v) = %q, want %q", *c.img, got, c.want)
		}
	}
}
