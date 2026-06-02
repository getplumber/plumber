#!/usr/bin/env bash
# Bump the version strings that are known at release time. Run by
# semantic-release's prepareCmd, so the edits land in the tagged release
# commit (no lag, no extra commit). The SHA and image digest are NOT set
# here (they don't exist until after the tag/build) -- see
# release-pin-refs.sh.
#
# Usage: release-bump-version.sh <version>     e.g. 0.3.12  (no leading v)
set -euo pipefail
ver="${1:?version required (e.g. 0.3.12)}"
v="v${ver}"

# action.yml: the `version` input default, and its "(e.g. vX)" hint. The
# vX.Y.Z guard keeps this from touching the other `default:` lines.
sed -i.bak -E 's/^([[:space:]]*default: ")v[0-9]+\.[0-9]+\.[0-9]+(")/\1'"$v"'\2/' action.yml
sed -i.bak -E 's/(release tag to install \(e\.g\. )v[0-9]+\.[0-9]+\.[0-9]+(\))/\1'"$v"'\2/' action.yml

# README: the GitLab CI Component pin in the GitLab CI Component section.
# Hard-pinned by policy (never `~latest`), so the example tracks each
# release. The GitHub Action `uses:` line is SHA-pinned and updated by
# release-pin-refs.sh after the build.
sed -i.bak -E "s~(component: gitlab.com/getplumber/plumber/plumber@)[0-9]+\.[0-9]+\.[0-9]+~\1${ver}~" README.md

rm -f action.yml.bak README.md.bak
echo "release-bump-version: set version strings to ${v}"
