#!/usr/bin/env bash
# Unit tests for release-plan.sh.
# Run: bash scripts/release-plan.test.sh
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
script="$here/release-plan.sh"
fails=0
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

ok() { echo "ok: $1"; }
ko() { echo "FAIL: $1"; fails=$((fails+1)); }

# 1. Plan job: the next version becomes step outputs.
out="$tmp/plan.out"; : > "$out"
env -u PLANNED_VERSION GITHUB_OUTPUT="$out" bash "$script" 0.4.17 >/dev/null
if grep -qx "planned_release=true" "$out" && grep -qx "planned_version=0.4.17" "$out"; then ok "plan outputs written"; else ko "plan outputs written ($(cat "$out"))"; fi

# 2. Release job: the version the image was built for is accepted.
out="$tmp/same.out"; : > "$out"
if PLANNED_VERSION=0.4.17 GITHUB_OUTPUT="$out" bash "$script" 0.4.17 >/dev/null; then ok "matching version accepted"; else ko "matching version accepted"; fi

# 3. Release job: another version is refused, with a diagnostic, and no
# output is written (nothing downstream may act on it).
out="$tmp/diff.out"; : > "$out"
set +e
msg="$(PLANNED_VERSION=0.4.17 GITHUB_OUTPUT="$out" bash "$script" 0.4.18 2>&1)"
rc=$?
set -e
if [ "$rc" -ne 0 ] && printf '%s' "$msg" | grep -q "image was built for 0.4.17"; then ok "version mismatch refused with message"; else ko "version mismatch refused with message (rc=$rc msg=$msg)"; fi
if [ ! -s "$out" ]; then ok "version mismatch writes no output"; else ko "version mismatch writes no output ($(cat "$out"))"; fi

# 4. Outside GitHub Actions the script is a no-op, not an error.
if env -u GITHUB_OUTPUT -u PLANNED_VERSION bash "$script" 0.4.17 >/dev/null; then ok "no GITHUB_OUTPUT is not an error"; else ko "no GITHUB_OUTPUT is not an error"; fi

# 5. The version is required.
if env -u GITHUB_OUTPUT bash "$script" >/dev/null 2>&1; then ko "missing version rejected"; else ok "missing version rejected"; fi

if [ "$fails" -gt 0 ]; then echo "${fails} failure(s)"; exit 1; fi
echo "all release-plan tests passed"
