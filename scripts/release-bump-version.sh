#!/usr/bin/env bash
# Set everything the tagged release commit must carry. Run by
# semantic-release's prepareCmd, so the edits land in the commit the release
# tag points at (no lag, no extra commit):
#   - action.yml: the `version` input default and its "(e.g. vX)" hint
#   - templates/plumber.yml: the component image digest and its #vX label
#
# The image is built and pushed by digest BEFORE this step (release.yml, job
# `docker`), which is what makes its digest known here. A release tag whose
# template pins another version's image is what this ordering prevents.
#
# Usage: release-bump-version.sh <version> [digest]
#   <version>  e.g. 0.3.12  (no leading v)
#   [digest]   image digest, with or without the sha256: prefix. Defaults to
#              $RELEASE_IMAGE_DIGEST. Required either way: a release is never
#              cut without the digest of its own image.
#
# Works on the files of the current directory (the repository root). All or
# nothing: if one of the lines to update is not found, both files are left
# exactly as they were and the script fails.
set -euo pipefail
ver="${1:?version required (e.g. 0.3.12)}"
digest="${2:-${RELEASE_IMAGE_DIGEST:-}}"
v="v${ver}"
hex="${digest#sha256:}"
files=(action.yml templates/plumber.yml)

[[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "release-bump-version: bad version: ${ver}" >&2; exit 2; }
if [[ -z "$digest" ]]; then
  echo "release-bump-version: image digest required (second argument or RELEASE_IMAGE_DIGEST)" >&2
  exit 2
fi
[[ "$hex" =~ ^[0-9a-f]{64}$ ]] || { echo "release-bump-version: bad digest: ${digest}" >&2; exit 2; }
for f in "${files[@]}"; do
  [ -f "$f" ] || { echo "release-bump-version: ${f} not found (run from the repository root)" >&2; exit 1; }
done

# Every edit below keeps the original as <file>.bak. One sed per file, so the
# backup is always the file as it was before this script ran.
restore() {
  for f in "${files[@]}"; do
    if [ -f "${f}.bak" ]; then mv "${f}.bak" "$f"; fi
  done
}
fail() {
  echo "release-bump-version: $1" >&2
  restore
  exit 1
}

# action.yml: the `version` input default, and its "(e.g. vX)" hint. The
# vX.Y.Z guard keeps this from touching the other `default:` lines.
sed -i.bak -E \
  -e 's/^([[:space:]]*default: ")v[0-9]+\.[0-9]+\.[0-9]+(")/\1'"$v"'\2/' \
  -e 's/(release tag to install \(e\.g\. )v[0-9]+\.[0-9]+\.[0-9]+(\))/\1'"$v"'\2/' \
  action.yml

# templates/plumber.yml: pin the component image digest and refresh the #vX
# note in one pass (~ delimiter to avoid clashing with the #vX comment).
sed -i.bak -E 's~(getplumber/plumber@sha256:)[a-f0-9]+(" #)v[0-9]+\.[0-9]+\.[0-9]+~\1'"$hex"'\2'"$v"'~' templates/plumber.yml

# A sed that matches nothing still exits 0. If a line changed shape, fail here
# rather than tag a release that carries a stale version or pins a stale image.
grep -qE '^[[:space:]]*default: "'"$v"'"' action.yml \
  || fail "action.yml has no version default line to update"
grep -qF "release tag to install (e.g. ${v})" action.yml \
  || fail "action.yml has no \"(e.g. vX.Y.Z)\" hint to update"
grep -qF "getplumber/plumber@sha256:${hex}\" #${v}" templates/plumber.yml \
  || fail "templates/plumber.yml has no digest-pinned image line to update"

# README:
# - GitLab CI Component example uses `<version>` as a placeholder, with a
#   link to the GitLab Catalog so users pick the version they want.
# - GitHub Action example uses `getplumber/plumber@<version>`.
# Neither carries a version, so neither is bumped.

for f in "${files[@]}"; do rm -f "${f}.bak"; done
echo "release-bump-version: set version strings to ${v}, image digest sha256:${hex}"
