package capability

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

// Spec section 4.3 rule 4 (a script line): a `- |` entry is one string holding several
// lines, and each of its lines is a script line, so a newline (LF or CRLF) cuts segments
// exactly like `;`.
func TestCommandTokens_MultiLineEntry(t *testing.T) {
	cases := []struct {
		line string
		want []string
	}{
		{"echo start\ngitleaks detect\n", []string{"echo", "gitleaks"}},
		{"echo start\r\ngitleaks detect\r\n", []string{"echo", "gitleaks"}},
		{"set -e\n\n  FOO=1 trufflehog git file://.", []string{"set", "trufflehog"}},
	}
	for _, c := range cases {
		got, _, _ := lineTokens(c.line)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("lineTokens(%q) cmds = %v, want %v", c.line, got, c.want)
		}
	}
}

// Spec section 4.4: the wrapper rule follows a script called on any line of a `- |` entry,
// and a relative cd on an earlier line of the same entry still applies.
func TestWrapperPath_MultiLineEntry(t *testing.T) {
	cases := []struct {
		line string
		want string
		ok   bool
	}{
		{"set -e\n./scripts/scan.sh\n", "scripts/scan.sh", true},
		{"set -e\r\n./scripts/scan.sh\r\n", "scripts/scan.sh", true},
		{"cd ci\n./scan.sh\n", "ci/scan.sh", true},
	}
	for _, c := range cases {
		got, ok := wrapperPath(c.line)
		if got != c.want || ok != c.ok {
			t.Errorf("wrapperPath(%q) = (%q, %v), want (%q, %v)", c.line, got, ok, c.want, c.ok)
		}
	}
}

// Spec section 4.3 rule 4: script lines come from any analyzed project's CI config, so the
// `sh -c` unwrap is bounded to one level: a 256 KiB line of repeated `sh -c ` tokenizes in
// linear time instead of hanging the run.
func TestCommandTokens_ShCChainIsBounded(t *testing.T) {
	line := strings.Repeat("sh -c ", (256<<10)/len("sh -c "))
	done := make(chan struct{})
	go func() { lineTokens(line); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("lineTokens on a 256 KiB `sh -c` chain took over 2 s: the unwrap must not recurse on the remainder")
	}
	// one level of unwrap still reaches the quoted command
	if got, _, _ := lineTokens(`sh -c "gitleaks detect"`); !reflect.DeepEqual(got, []string{"sh", "gitleaks"}) {
		t.Errorf("single-level unwrap: got %v, want [sh gitleaks]", got)
	}
}

func TestCommandTokens(t *testing.T) {
	cases := []struct {
		line string
		want []string
	}{
		{"gitleaks detect --source .", []string{"gitleaks"}},
		{"  ./bin/trufflehog git file://. && echo done", []string{"trufflehog", "echo"}},
		{"make build; detect-secrets scan | tee out.json || true", []string{"make", "detect-secrets", "tee", "true"}},
		{`sh -c "ggshield secret scan path ."`, []string{"sh", "ggshield"}},
		{`bash -c 'cd src && betterleaks dir .'`, []string{"bash", "cd", "betterleaks"}},
		{"", nil},
		{"   ", nil},
		{"FOO=bar gitleaks detect", []string{"gitleaks"}}, // a leading assignment is skipped
	}
	for _, c := range cases {
		got, _, _ := lineTokens(c.line)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("lineTokens(%q) cmds = %v, want %v", c.line, got, c.want)
		}
	}
}

func TestWrapperPath(t *testing.T) {
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
		{"/usr/local/bin/scan.sh", "", false},                       // absolute: never under the root by construction
		{"../outside/scan.sh", "", false},                           // escapes the root
		{"gitleaks detect", "", false},                              // a command, not a script path
		{"sh -c \"gitleaks detect\"", "", false},                    // inline command, not a file
		{"python scripts/scan.py", "", false},                       // only .sh and .bash files are followed
		{"cd ci && ./scan.sh", "ci/scan.sh", true},                  // a later segment, under a relative cd
		{"make prep && ./scripts/scan.sh", "scripts/scan.sh", true}, // a later segment
		{"./scripts/scan.sh;", "scripts/scan.sh", true},             // a trailing `;`
		{"cd /opt && ./scan.sh", "", false},                         // an absolute cd leaves the root
		{"cd .. && ./scan.sh", "", false},                           // a cd that escapes the root
	}
	for _, c := range cases {
		got, ok := wrapperPath(c.line)
		if got != c.want || ok != c.ok {
			t.Errorf("wrapperPath(%q) = (%q, %v), want (%q, %v)", c.line, got, ok, c.want, c.ok)
		}
	}
}

// Spec section 4.3 rule 4, command prefixes (bot review of PR #557): a known prefix is
// skipped, a prefix with nothing after it yields no token and never panics, and a module
// invocation keeps the module name as written (no base name taken).
func TestCommandTokens_PrefixesAndModules(t *testing.T) {
	cases := []struct {
		line string
		want []string
	}{
		{"env", nil},
		{"sudo", nil},
		{"env A=1 B=2", nil},
		{"sudo -E -u", nil},
		{"python -m", []string{"python"}},
		{"python3 -m detect_secrets scan", []string{"detect_secrets"}},
		{"py -m detect_secrets scan", []string{"detect_secrets"}},
		{"/usr/bin/env FOO=1 /opt/bin/gitleaks detect", []string{"gitleaks"}},
		{"sudo -E sh -c 'trufflehog filesystem .'", []string{"sh", "trufflehog"}},
	}
	for _, c := range cases {
		got, _, _ := lineTokens(c.line)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("lineTokens(%q) cmds = %v, want %v", c.line, got, c.want)
		}
	}
}

// Spec section 4.3 rule 4, command prefixes (bot review round 2 of PR #557, G1): the
// value-taking options of `sudo` and `env` drop their argument with them, so the argument
// is never taken for the command; a value option with nothing after it yields no token and
// never panics.
func TestCommandTokens_PrefixOptionArguments(t *testing.T) {
	cases := []struct {
		line string
		want []string
	}{
		{"sudo -u ci-runner gitleaks detect", []string{"gitleaks"}},
		{"sudo --user=ci gitleaks detect", []string{"gitleaks"}},
		{"sudo --user ci gitleaks detect", []string{"gitleaks"}},
		{"sudo -E -g ci -C 3 gitleaks detect", []string{"gitleaks"}},
		{"env -u NAME gitleaks detect", []string{"gitleaks"}},
		{"env -i trufflehog filesystem .", []string{"trufflehog"}},
		{"env --unset NAME -C src -0 A=1 gitleaks detect", []string{"gitleaks"}},
		{"env --chdir src --ignore-environment --null gitleaks detect", []string{"gitleaks"}},
		{"sudo -u", nil},
		{"env -u", nil},
	}
	for _, c := range cases {
		got, _, _ := lineTokens(c.line)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("lineTokens(%q) cmds = %v, want %v", c.line, got, c.want)
		}
	}
}

// Spec section 4.3 rule 4 (bot review round 2 of PR #557, G3): a shell comment is not a
// command. An unquoted `#` that starts a field runs to the end of its line; a `#` inside a
// word or inside quotes is not a comment.
func TestCommandTokens_ShellComments(t *testing.T) {
	cases := []struct {
		line string
		want []string
	}{
		{"# old: make build && gitleaks detect\n", nil},
		{"echo start\n  # old: make build && gitleaks detect\necho end\n", []string{"echo", "echo"}},
		{"echo done # gitleaks detect", []string{"echo"}},
		{`echo "a # b" && gitleaks detect`, []string{"echo", "gitleaks"}},
		{"# cat dump.sql | gitleaks detect\ngitleaks detect", []string{"gitleaks"}},
		{"echo foo#bar && gitleaks detect", []string{"echo", "gitleaks"}},
		{"echo $# && gitleaks detect", []string{"echo", "gitleaks"}},
		{"echo 'x' # c\ngitleaks detect", []string{"echo", "gitleaks"}},
		{"echo a;# c\ngitleaks detect", []string{"echo", "gitleaks"}},
	}
	for _, c := range cases {
		got, _, _ := lineTokens(c.line)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("lineTokens(%q) cmds = %v, want %v", c.line, got, c.want)
		}
	}
}

// Spec section 4.4 (bot review round 2 of PR #557, G3): a commented-out script call is not
// a wrapper; the wrapper rule reads the same comment-free segments as the command rule.
func TestWrapperPath_ShellComments(t *testing.T) {
	cases := []struct {
		line string
		want string
		ok   bool
	}{
		{"# ./scripts/scan.sh", "", false},
		{"#./scripts/scan.sh", "", false},
		{"set -e\n# ./scripts/scan.sh\n", "", false},
		{"echo hi # ./scripts/scan.sh", "", false},
		{"# old\n./scripts/scan.sh\n", "scripts/scan.sh", true},
	}
	for _, c := range cases {
		got, ok := wrapperPath(c.line)
		if got != c.want || ok != c.ok {
			t.Errorf("wrapperPath(%q) = (%q, %v), want (%q, %v)", c.line, got, ok, c.want, c.ok)
		}
	}
}

// L2 fix (bot review round 6): `pre-commit run` takes the run's own value-consuming options
// into account before reading the hook id, so a run wrapped in `--hook-stage`, a pair of
// `--from-ref`/`--to-ref` or a `--color=` value (the `=` form of any option) still yields its
// hook, where the prior first-non-flag-field logic read the option name itself as the hook.
// `--files`/`--file` consume every non-flag field that follows, so a hook id placed right
// after them is indistinguishable from a file path and yields no hook: the run is ambiguous
// by design, not a bug. A value option left with no value at the end of the line
// (`--hook-stage` alone) must not panic and falls through to no hook, like `--all-files`.
func TestCommandTokens_PreCommitRunOptions(t *testing.T) {
	cases := []struct {
		line string
		want []string
	}{
		{"pre-commit run --hook-stage manual gitleaks", []string{"gitleaks"}},
		{"pre-commit run --from-ref HEAD~1 --to-ref HEAD detect-secrets", []string{"detect-secrets"}},
		{"pre-commit run --color=always gitleaks", []string{"gitleaks"}},
		{"pre-commit run --all-files", []string{"pre-commit"}},
		{"pre-commit run --hook-stage", []string{"pre-commit"}},
		{"pre-commit run --files a.py b.py gitleaks", []string{"pre-commit"}},
	}
	for _, c := range cases {
		got, _, _ := lineTokens(c.line)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("lineTokens(%q) cmds = %v, want %v", c.line, got, c.want)
		}
	}
}

// Spec section 4.3 rule 4 (bot review round 2 of PR #557, G4): a launcher runs the next
// field as the command, so the tool it launches is the token; `pre-commit run <hook>` takes
// the hook id as the token, like `python -m <module>`; a `make` target is not followed.
func TestCommandTokens_Launchers(t *testing.T) {
	cases := []struct {
		line string
		want []string
	}{
		{"bundle exec gitleaks detect", []string{"gitleaks"}},
		{"poetry run detect-secrets scan", []string{"detect-secrets"}},
		{"pipenv run detect-secrets scan", []string{"detect-secrets"}},
		{"uv run detect-secrets scan", []string{"detect-secrets"}},
		{"pdm run detect-secrets scan", []string{"detect-secrets"}},
		{"pipx run detect-secrets scan", []string{"detect-secrets"}},
		{"pnpm exec gitleaks detect", []string{"gitleaks"}},
		{"npx gitleaks detect", []string{"gitleaks"}},
		{"npx --yes gitleaks detect", []string{"gitleaks"}},
		{"npx -y --no-install gitleaks detect", []string{"gitleaks"}},
		{"npx -p some-pkg gitleaks detect", []string{"gitleaks"}},
		{"npx --package some-pkg gitleaks detect", []string{"gitleaks"}},
		{"npx @gitleaks/gitleaks detect", []string{"gitleaks"}},
		{"sudo -E bundle exec gitleaks detect", []string{"gitleaks"}},
		{"pre-commit run detect-secrets", []string{"detect-secrets"}},
		{"pre-commit run gitleaks", []string{"gitleaks"}},
		{"pre-commit run --all-files gitleaks", []string{"gitleaks"}},
		{"pre-commit run", []string{"pre-commit"}},
		{"pre-commit run --all-files", []string{"pre-commit"}},
		{"make secret-scan", []string{"make"}},
		{"npx", nil},
		{"npx -p", nil},
		{"bundle exec", nil},
	}
	for _, c := range cases {
		got, _, _ := lineTokens(c.line)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("lineTokens(%q) cmds = %v, want %v", c.line, got, c.want)
		}
	}
}

// Spec section 4.3 rule 4, multi-word commands (bot review round 3 of PR #557, false
// positive fix): lineTokens' third result gives, per cmds entry, the fields that follow it
// in its segment, so a recognizer command of several words (`ggshield secret`) can be
// matched against a subcommand rather than the bare tool name. A prefix is stripped before
// the command is taken, so `sudo ggshield secret scan` still reports `secret scan` as what
// follows `ggshield`.
func TestCommandTokens_Following(t *testing.T) {
	cases := []struct {
		line      string
		cmds      []string
		following [][]string
	}{
		{"ggshield secret scan ci", []string{"ggshield"}, [][]string{{"secret", "scan", "ci"}}},
		{"ggshield iac scan ci", []string{"ggshield"}, [][]string{{"iac", "scan", "ci"}}},
		{"sudo ggshield secret scan", []string{"ggshield"}, [][]string{{"secret", "scan"}}},
		{"gitleaks detect", []string{"gitleaks"}, [][]string{{"detect"}}},
		{"make build; detect-secrets scan", []string{"make", "detect-secrets"}, [][]string{{"build"}, {"scan"}}},
	}
	for _, c := range cases {
		cmds, _, following := lineTokens(c.line)
		if !reflect.DeepEqual(cmds, c.cmds) || !reflect.DeepEqual(following, c.following) {
			t.Errorf("lineTokens(%q) = (%v, _, %v), want (%v, _, %v)", c.line, cmds, following, c.cmds, c.following)
		}
	}
}

// Spec section 4.3 rule 4, container-run form (bot review round 4 of PR #557, J1): a
// container-run segment yields at most one image candidate, its first field after `run`
// that is neither a flag nor a flag's value. Boolean flags, combined boolean short flags
// (`-dit`, `-itd`) and `=` flags consume nothing, every other flag consumes the next field;
// a `docker run` with only flags (or a value flag missing its value) yields no candidate
// and does not panic.
func TestCommandTokens_ContainerRunImage(t *testing.T) {
	cases := []struct {
		line   string
		images []string
	}{
		{"docker run --rm gcr.io/go-containerregistry/crane copy a b", []string{"gcr.io/go-containerregistry/crane"}},
		{"docker run -dit --network=host --platform linux/amd64 img:1 arg", []string{"img:1"}},
		{"podman run -itd -u 1000 -w /d --mount type=bind,src=.,dst=/d img2 run x", []string{"img2"}},
		{"nerdctl run -p 80:80 --pull always --privileged --init img3", []string{"img3"}},
		{"docker run -P --read-only -q --oom-kill-disable --no-healthcheck --sig-proxy img4", []string{"img4"}},
		{`docker run -e "K=V" 'img5:1' x`, []string{"img5:1"}},
		{"docker run --rm -it -v a:b", nil},
		{"docker run", nil},
		{"docker run -v", nil},
	}
	for _, c := range cases {
		_, images, _ := lineTokens(c.line)
		if !reflect.DeepEqual(images, c.images) {
			t.Errorf("lineTokens(%q) images = %v, want %v", c.line, images, c.images)
		}
	}
}

// Spec section 4.3 rule 4, command prefixes (bot review round 5 of PR #557, K1): the `=`
// forms of the env value options (`--unset=NAME`, `--chdir=DIR`) drop only themselves, so
// the next field is the command, not an option value.
func TestCommandTokens_EnvEqualsOptions(t *testing.T) {
	cases := []struct {
		line string
		want []string
	}{
		{"env --unset=HTTP_PROXY gitleaks detect", []string{"gitleaks"}},
		{"env --chdir=src gitleaks detect", []string{"gitleaks"}},
		{"env --unset=A --chdir=src B=1 gitleaks detect", []string{"gitleaks"}},
	}
	for _, c := range cases {
		got, _, _ := lineTokens(c.line)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("lineTokens(%q) cmds = %v, want %v", c.line, got, c.want)
		}
	}
}

// Spec section 4.4 (K1): `env --chdir=DIR` changes the directory of its own command only,
// so it never moves the wrapper rule's base: a script called on a later segment still
// resolves relative to the repository root, and an env line is not itself a wrapper call.
func TestWrapperPath_EnvChdirDoesNotMoveTheRoot(t *testing.T) {
	cases := []struct {
		line string
		want string
		ok   bool
	}{
		{"env --chdir=src true && ./scripts/scan.sh", "scripts/scan.sh", true},
		{"env --chdir=src gitleaks detect", "", false},
	}
	for _, c := range cases {
		got, ok := wrapperPath(c.line)
		if got != c.want || ok != c.ok {
			t.Errorf("wrapperPath(%q) = (%q, %v), want (%q, %v)", c.line, got, ok, c.want, c.ok)
		}
	}
}

// Spec section 4.3 rule 4, known limitation (bot review round 5 of PR #557, K3): an
// all-hooks `pre-commit run` names no hook on the line; the hook list lives in
// `.pre-commit-config.yaml`, which the rules deliberately do not read (reading it would be a
// sixth evidence source), so the only token is `pre-commit` itself.
func TestCommandTokens_PreCommitAllHooksIsNotUnwrapped(t *testing.T) {
	for _, line := range []string{"pre-commit run --all-files", "pre-commit run"} {
		got, _, _ := lineTokens(line)
		if !reflect.DeepEqual(got, []string{"pre-commit"}) {
			t.Errorf("lineTokens(%q) cmds = %v, want [pre-commit]", line, got)
		}
	}
}

// Spec section 4.3 rule 4, command prefixes (bot review round 5 of PR #557, K4): `timeout
// [options] DURATION COMMAND` runs COMMAND, so its options (with their values), then its one
// duration field, are skipped; a `timeout` with no command yields no token and never panics.
func TestCommandTokens_Timeout(t *testing.T) {
	cases := []struct {
		line string
		want []string
	}{
		{"timeout 300 gitleaks detect --no-git", []string{"gitleaks"}},
		{"timeout -s KILL 5m trufflehog filesystem .", []string{"trufflehog"}},
		{"timeout --preserve-status 1h gitleaks detect", []string{"gitleaks"}},
		{"timeout --signal=TERM --kill-after 10s -v 2.5 gitleaks detect", []string{"gitleaks"}},
		{"timeout -k 5 --foreground --verbose --kill-after=3 1d sudo gitleaks detect", []string{"gitleaks"}},
		{"timeout", nil},
		{"timeout 300", nil},
		{"timeout -s", nil},
	}
	for _, c := range cases {
		got, _, _ := lineTokens(c.line)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("lineTokens(%q) cmds = %v, want %v", c.line, got, c.want)
		}
	}
}
