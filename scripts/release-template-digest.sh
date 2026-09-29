#!/usr/bin/env bash
# Print the image digest pinned in a component template, verifying that its
# trailing #vX.Y.Z label matches the requested version. A mismatch means
# the release did not pin that version (or an older release was requested);
# callers must treat that as fatal before pushing anything anywhere.
#
# Usage: release-template-digest.sh <version> <template-file>
set -euo pipefail
ver="${1:?version required}"
tpl="${2:?template file required}"

[ -f "$tpl" ] || { echo "template file not found: $tpl" >&2; exit 1; }
line="$(grep -E 'getplumber/plumber@sha256:[0-9a-f]+' "$tpl" | head -n1 || true)"
[ -n "$line" ] || { echo "no digest-pinned image line in $tpl" >&2; exit 1; }
digest="$(printf '%s' "$line" | sed -E 's/.*@(sha256:[0-9a-f]+).*/\1/')"
label="$(printf '%s' "$line" | sed -E 's/.*#[[:space:]]*(v[0-9]+\.[0-9]+\.[0-9]+).*/\1/')"
if [ "$label" != "v${ver}" ]; then
  echo "template pinned to ${label}, expected v${ver} (the release did not pin it, or an older release was requested)" >&2
  exit 1
fi
printf '%s\n' "$digest"
