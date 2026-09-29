#!/usr/bin/env bash
# Install semantic-release and every plugin .releaserc.json references. Run by
# the two semantic-release jobs of release.yml (`plan` and `release`), so the
# pinned versions live in one place.
#
# semantic-release is run directly instead of through the third-party
# cycjimmy/semantic-release-action wrapper. Top-level packages are pinned to
# exact, immutable npm versions (npm versions are immutable once published and
# npm verifies each tarball's registry integrity hash on install). A hardcoded
# checksum is not practical here: semantic-release pulls a large transitive
# dependency tree and this Go repo carries no package-lock.json to anchor it.
#
# Every plugin referenced by .releaserc.json is installed explicitly,
# including the commit-analyzer / release-notes-generator that ship as
# semantic-release dependencies, so plugin resolution never depends on
# transitive hoisting. Versions match semantic-release 23.1.1's declared
# ranges (commit-analyzer ^12, notes-generator ^13).
set -euo pipefail
npm install -g \
  semantic-release@23.1.1 \
  @semantic-release/commit-analyzer@12.0.0 \
  @semantic-release/release-notes-generator@13.0.0 \
  @semantic-release/changelog@6.0.3 \
  @semantic-release/exec@6.0.3 \
  @semantic-release/git@10.0.1 \
  conventional-changelog-conventionalcommits@7.0.2
