#!/usr/bin/env bash
# Write the release-detection outputs that downstream jobs gate on
# (new_release_published, new_release_version). Run by semantic-release's
# successCmd, which fires only after a release is actually published, so
# reaching this point means a release happened. This replaces the
# outputs the former cycjimmy/semantic-release-action wrapper exposed.
#
# new_release_notes is NOT written here: the notes are multi-line and
# carry arbitrary commit text, which cannot be passed safely through the
# exec template. The workflow extracts them from CHANGELOG.md instead.
#
# Usage: release-set-outputs.sh <version>     e.g. 0.3.12  (no leading v)
set -euo pipefail
ver="${1:?version required (e.g. 0.3.12)}"

# Only meaningful inside GitHub Actions; a local semantic-release dry run
# has no $GITHUB_OUTPUT and should be a no-op rather than an error.
if [[ -z "${GITHUB_OUTPUT:-}" ]]; then
  exit 0
fi

{
  echo "new_release_published=true"
  echo "new_release_version=${ver}"
} >>"${GITHUB_OUTPUT}"
