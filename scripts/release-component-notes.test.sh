#!/usr/bin/env bash
# Unit tests for release-component-notes.sh.
# Run: bash scripts/release-component-notes.test.sh
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
script="$here/release-component-notes.sh"
fails=0
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

DIGEST="sha256:$(printf 'c%.0s' {1..64})"
repo="$tmp/repo"
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.com GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.com
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
git init -q "$repo"
mkdir -p "$repo/templates" "$repo/control"

# commit <file> <subject> [body]: append a line to <file> and commit it.
commit() {
  echo "$2" >> "$repo/$1"
  git -C "$repo" add -A
  if [ -n "${3:-}" ]; then
    git -C "$repo" commit -q -m "$2" -m "$3"
  else
    git -C "$repo" commit -q -m "$2"
  fi
}
release() {
  commit templates/plumber.yml "chore(release): $1 [skip ci]"
  git -C "$repo" tag "v$1"
}

check() { # check <name> <output> <grep -F needle>
  if printf '%s\n' "$2" | grep -qF -- "$3"; then echo "ok: $1"; else echo "FAIL: $1 (missing: $3)"; fails=$((fails+1)); fi
}
check_not() {
  if printf '%s\n' "$2" | grep -qF -- "$3"; then echo "FAIL: $1 (unexpected: $3)"; fails=$((fails+1)); else echo "ok: $1"; fi
}
# section <output> <title>: the entries of one "### <title>" section.
section() { printf '%s\n' "$1" | awk -v t="### $2" '$0 == t {on=1; next} /^### / {on=0} on && /^- /'; }

# v0.7.9: first release, no previous tag.
commit templates/plumber.yml "feat(component): initial template"
release 0.7.9
out="$(bash "$script" 0.7.9 "$DIGEST" "$repo")"
check "heading with ISO date" "$out" "## [0.7.9] - $(git -C "$repo" log -1 --format=%cs v0.7.9)"
check "first release links the tag page" "$out" "[0.7.9]: https://gitlab.com/getplumber/plumber/-/tags/v0.7.9"
check "first release lists every template commit" "$out" "- Initial template."

# v0.7.10: digest-only release, with a CLI-only change in between.
commit control/x.go "feat(github): a GitHub-only control"
release 0.7.10
out="$(bash "$script" 0.7.10 "$DIGEST" "$repo")"
check "previous tag sorts by version (0.7.9 < 0.7.10)" "$out" "[0.7.10]: https://gitlab.com/getplumber/plumber/-/compare/v0.7.9...v0.7.10"
check "image entry under Changed" "$out" "- Image bumped to \`getplumber/plumber:0.7.10\` (\`${DIGEST}\`)."
check "full CLI changelog link" "$out" "The full CLI changelog is in the [v0.7.10 GitHub release](https://github.com/getplumber/plumber/releases/tag/v0.7.10)."
check_not "CLI-only commit left out" "$out" "GitHub-only control"
check_not "release commit left out" "$out" "skip ci"
check_not "no empty Added section" "$out" "### Added"
if [ "$(printf '%s\n' "$out" | grep -c '^### ')" = 1 ]; then echo "ok: digest-only release has only Changed"; else echo "FAIL: digest-only release has only Changed"; fails=$((fails+1)); fi

# v0.8.0: every section, in order.
commit templates/plumber.yml "feat(component): add a report_format input"
commit templates/plumber.yml "fix(component): quote the threshold"
commit templates/plumber.yml "feat(component)!: rename the config input"
commit templates/plumber.yml "refactor: split the script" "BREAKING CHANGE: the job name changed"
commit templates/plumber.yml "feat(component): deprecate the legacy input"
commit templates/plumber.yml "feat(component): dropdown selector for the report"
commit templates/plumber.yml "feat(component): drop-in replacement for the job"
commit templates/plumber.yml "feat(component): remove the verbose input"
commit templates/plumber.yml "fix(component,security): do not echo the token"
commit templates/plumber.yml "security: patch the token leak"
commit templates/plumber.yml "docs(component): explain the inputs"
commit templates/plumber.yml "Tweak the rules ordering"
commit templates/plumber.yml "ci(release): pin v0.7.11 refs [skip ci]"
commit control/x.go "fix(github): a GitHub-only fix"
release 0.8.0
out="$(bash "$script" 0.8.0 "$DIGEST" "$repo")"
check "feat -> Added" "$(section "$out" Added)" "- Add a report_format input."
check "fix -> Fixed" "$(section "$out" Fixed)" "- Quote the threshold."
check "bang marks breaking" "$out" "- **Breaking:** Rename the config input."
check "footer marks breaking" "$out" "- **Breaking:** Split the script."
check "deprecate -> Deprecated" "$(section "$out" Deprecated)" "- Deprecate the legacy input."
check "remove -> Removed" "$(section "$out" Removed)" "- Remove the verbose input."
check "dropdown -> Added" "$(section "$out" Added)" "- Dropdown selector for the report."
check "drop-in -> Added" "$(section "$out" Added)" "- Drop-in replacement for the job."
check_not "dropdown is not a removal" "$(section "$out" Removed)" "Dropdown"
check_not "drop-in is not a removal" "$(section "$out" Removed)" "Drop-in"
check "security scope -> Security" "$(section "$out" Security)" "- Do not echo the token."
check "security type -> Security" "$(section "$out" Security)" "- Patch the token leak."
check "other types -> Changed" "$out" "- Explain the inputs."
check "non-conventional subject -> Changed, capitalized" "$out" "- Tweak the rules ordering."
check_not "ci(release) commit left out" "$out" "Pin v0.7.11"
check_not "CLI-only fix left out" "$out" "GitHub-only fix"
order="$(printf '%s\n' "$out" | grep '^### ' | tr '\n' ' ')"
if [ "$order" = "### Added ### Changed ### Deprecated ### Removed ### Fixed ### Security " ]; then
  echo "ok: Keep a Changelog section order"
else
  echo "FAIL: Keep a Changelog section order (got: $order)"; fails=$((fails+1))
fi
if printf '%s\n' "$out" | grep -qE '^- (Image|Explain|Tweak|\*\*Breaking:\*\* Split)' \
   && [ "$(printf '%s\n' "$out" | sed -n '/^### Changed/,/^### /p' | grep -c '^- ')" = 4 ]; then
  echo "ok: Changed holds the image and the three other changes"
else
  echo "FAIL: Changed holds the image and the three other changes"; fails=$((fails+1))
fi

# URL overrides (the e2e lab points at its own projects).
out="$(COMPONENT_URL=https://gitlab.example.com/lab CLI_URL=https://github.com/example/lab bash "$script" 0.8.0 "$DIGEST" "$repo")"
check "COMPONENT_URL override" "$out" "[0.8.0]: https://gitlab.example.com/lab/-/compare/v0.7.10...v0.8.0"
check "CLI_URL override" "$out" "(https://github.com/example/lab/releases/tag/v0.8.0)"

# Bad input: fail with a diagnostic.
set +e
out="$(bash "$script" 0.8.0 "sha256:nothex" "$repo" 2>&1)"; rc=$?
set -e
if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q 'invalid digest'; then echo "ok: bad digest rejected"; else echo "FAIL: bad digest rejected (rc=$rc out=$out)"; fails=$((fails+1)); fi
set +e
out="$(bash "$script" 9.9.9 "$DIGEST" "$repo" 2>&1)"; rc=$?
set -e
if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q 'tag v9.9.9 not found'; then echo "ok: missing tag rejected"; else echo "FAIL: missing tag rejected (rc=$rc out=$out)"; fails=$((fails+1)); fi

if [ "$fails" -ne 0 ]; then echo "$fails test(s) failed"; exit 1; fi
echo "all tests passed"
