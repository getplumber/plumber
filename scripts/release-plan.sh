#!/usr/bin/env bash
# semantic-release's verifyReleaseCmd. It runs in both semantic-release runs
# of release.yml, once a release is known to be due and before anything is
# written:
#   - job `plan` (semantic-release --dry-run): exposes the next version as the
#     step outputs planned_release / planned_version, so the image can be
#     built for that version BEFORE the release commit and its tag exist.
#   - job `release` (the real run): asserts that the version it is about to
#     cut is the one the image was built for ($PLANNED_VERSION). They differ
#     only if a commit landed on main between the two jobs.
#
# Usage: release-plan.sh <version>     e.g. 0.3.12  (no leading v)
set -euo pipefail
ver="${1:?version required (e.g. 0.3.12)}"

if [[ -n "${PLANNED_VERSION:-}" && "${PLANNED_VERSION}" != "$ver" ]]; then
  echo "release-plan: this run would cut ${ver} but the image was built for ${PLANNED_VERSION}." >&2
  echo "release-plan: main moved between the plan and the release; the next push to main releases both." >&2
  exit 1
fi

# Only meaningful inside GitHub Actions; a local dry run has no
# $GITHUB_OUTPUT and should be a no-op rather than an error.
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "planned_release=true"
    echo "planned_version=${ver}"
  } >>"${GITHUB_OUTPUT}"
fi
echo "release-plan: next release ${ver}"
