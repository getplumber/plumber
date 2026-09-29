#!/usr/bin/env bash
# Unit tests for release-bump-version.sh.
# Run: bash scripts/release-bump-version.test.sh
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
script="$here/release-bump-version.sh"
root="$(cd "$here/.." && pwd)"
fails=0
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

OLD="$(printf 'a%.0s' {1..64})"
NEW="$(printf 'b%.0s' {1..64})"

# fixture <dir>: a minimal repository root at the previous release.
fixture() {
  mkdir -p "$1/templates"
  cat > "$1/action.yml" <<'EOF'
inputs:
  version:
    description: "Plumber release tag to install (e.g. v0.4.16)"
    default: "v0.4.16"
  threshold:
    default: "100"
EOF
  cat > "$1/templates/plumber.yml" <<EOF
    image:
      description: "Docker image to use for the job"
      default: "getplumber/plumber@sha256:${OLD}" #v0.4.16
EOF
  printf '      - uses: getplumber/plumber@<version>\n' > "$1/README.md"
}

ok() { echo "ok: $1"; }
ko() { echo "FAIL: $1"; fails=$((fails+1)); }
no_backup() { if ls "$1"/*.bak "$1"/templates/*.bak >/dev/null 2>&1; then ko "$2"; else ok "$2"; fi; }

# 1. The tagged commit carries its own version and its own image digest.
d="$tmp/happy"; fixture "$d"
(cd "$d" && bash "$script" 0.4.17 "sha256:${NEW}" >/dev/null)
if grep -qF "default: \"getplumber/plumber@sha256:${NEW}\" #v0.4.17" "$d/templates/plumber.yml"; then ok "template pins the new digest with the new label"; else ko "template pins the new digest with the new label"; fi
if grep -q "$OLD" "$d/templates/plumber.yml"; then ko "previous digest is gone"; else ok "previous digest is gone"; fi
if grep -qF 'default: "v0.4.17"' "$d/action.yml" && grep -qF '(e.g. v0.4.17)' "$d/action.yml"; then ok "action.yml version and hint bumped"; else ko "action.yml version and hint bumped"; fi
if grep -qF 'default: "100"' "$d/action.yml"; then ok "other defaults untouched"; else ko "other defaults untouched"; fi
if [ "$(cat "$d/README.md")" = "      - uses: getplumber/plumber@<version>" ]; then ok "README untouched"; else ko "README untouched"; fi
no_backup "$d" "no backup files left"

# 2. The digest may come from the environment, without the sha256: prefix.
d="$tmp/env"; fixture "$d"
(cd "$d" && RELEASE_IMAGE_DIGEST="$NEW" bash "$script" 0.4.17 >/dev/null)
if grep -qF "getplumber/plumber@sha256:${NEW}\" #v0.4.17" "$d/templates/plumber.yml"; then ok "digest read from RELEASE_IMAGE_DIGEST"; else ko "digest read from RELEASE_IMAGE_DIGEST"; fi

# expect_fail <name> <needle> <dir> <args...>: non-zero exit with a
# diagnostic, BOTH files left exactly as they were, no backup left behind.
# A release that fails half way must not leave a half-bumped tree for
# semantic-release to commit.
expect_fail() {
  local name="$1" needle="$2" dir="$3"; shift 3
  local tpl act out rc
  tpl="$(cat "$dir/templates/plumber.yml")"
  act="$(cat "$dir/action.yml")"
  set +e
  out="$(cd "$dir" && env -u RELEASE_IMAGE_DIGEST bash "$script" "$@" 2>&1)"
  rc=$?
  set -e
  if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q "$needle"; then ok "$name"; else ko "$name (rc=$rc out=$out)"; fi
  if [ "$tpl" = "$(cat "$dir/templates/plumber.yml")" ]; then ok "$name: template untouched"; else ko "$name: template untouched"; fi
  if [ "$act" = "$(cat "$dir/action.yml")" ]; then ok "$name: action.yml untouched"; else ko "$name: action.yml untouched"; fi
  no_backup "$dir" "$name: no backup files left"
}

# 3. A release is never cut without the digest of its own image.
d="$tmp/nodigest"; fixture "$d"
expect_fail "missing digest rejected" "image digest required" "$d" 0.4.17
d="$tmp/baddigest"; fixture "$d"
expect_fail "malformed digest rejected" "bad digest" "$d" 0.4.17 "sha256:1234"
d="$tmp/badversion"; fixture "$d"
expect_fail "malformed version rejected" "bad version" "$d" v0.4.17 "$NEW"

# 4. A line that changed shape must fail the release, never pass silently: a
# sed that matches nothing exits 0 and would ship the previous value.
d="$tmp/noline"; fixture "$d"
printf '    image:\n      default: "getplumber/plumber:latest"\n' > "$d/templates/plumber.yml"
expect_fail "template without a digest line rejected" "no digest-pinned image line" "$d" 0.4.17 "$NEW"

d="$tmp/nodefault"; fixture "$d"
sed -i.orig 's/default: "v0.4.16"/default: v0.4.16/' "$d/action.yml"; rm -f "$d/action.yml.orig"
expect_fail "action.yml without a quoted version default rejected" "no version default line" "$d" 0.4.17 "$NEW"

d="$tmp/nohint"; fixture "$d"
sed -i.orig 's/(e\.g\. v0\.4\.16)/(for example v0.4.16)/' "$d/action.yml"; rm -f "$d/action.yml.orig"
expect_fail "action.yml without the (e.g. vX) hint rejected" "hint to update" "$d" 0.4.17 "$NEW"

# 5. Outside the repository root there is nothing to bump.
mkdir -p "$tmp/empty"
set +e
out="$(cd "$tmp/empty" && bash "$script" 0.4.17 "$NEW" 2>&1)"
rc=$?
set -e
if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q "not found"; then ok "missing files rejected"; else ko "missing files rejected (rc=$rc out=$out)"; fi

# 6. The files of THIS repository are in the shape the script expects. The
# fixtures above only prove the script; this proves the release. It fails the
# pull request that reshapes action.yml or the template, instead of the
# release that follows it.
d="$tmp/real"; mkdir -p "$d/templates"
cp "$root/action.yml" "$d/action.yml"
cp "$root/templates/plumber.yml" "$d/templates/plumber.yml"
set +e
out="$(cd "$d" && bash "$script" 99.98.97 "$NEW" 2>&1)"
rc=$?
set -e
if [ "$rc" -eq 0 ]; then ok "the repository's own files are bumped"; else ko "the repository's own files are bumped (rc=$rc out=$out)"; fi
if grep -qF "getplumber/plumber@sha256:${NEW}\" #v99.98.97" "$d/templates/plumber.yml"; then ok "the repository's template pins the digest"; else ko "the repository's template pins the digest"; fi
if grep -qF 'default: "v99.98.97"' "$d/action.yml" && grep -qF '(e.g. v99.98.97)' "$d/action.yml"; then ok "the repository's action.yml carries the version"; else ko "the repository's action.yml carries the version"; fi
if [ "$(grep -c 'v99.98.97' "$d/action.yml")" -eq 2 ] && [ "$(grep -c 'v99.98.97' "$d/templates/plumber.yml")" -eq 1 ]; then ok "exactly the three expected lines changed"; else ko "exactly the three expected lines changed"; fi

if [ "$fails" -gt 0 ]; then echo "${fails} failure(s)"; exit 1; fi
echo "all release-bump-version tests passed"
