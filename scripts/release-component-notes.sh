#!/usr/bin/env bash
# Print the GitLab component release notes for one release, in the Keep a
# Changelog 1.1.0 format (https://keepachangelog.com/en/1.1.0/).
#
# The component is templates/plumber.yml, so the notes only describe what
# changed in it: the image the release pins, plus one entry per commit
# touching templates/ since the previous release tag. The CLI changelog
# (GitHub-only controls, CI bumps, tests...) is left to the GitHub release,
# which the notes link to.
#
# Commits are read from <repo-dir> (the CLI repository, where templates/
# lives), between the highest vX.Y.Z tag below v<version> and v<version>.
# Release commits (any "(release)" scope: chore(release) today,
# ci(release) in older releases) are skipped: their only template change is the
# digest bump, already covered by the image entry. Conventional commit
# subjects map to sections:
#   security type or scope        -> Security
#   subject saying deprecate      -> Deprecated
#   subject starting remove/drop  -> Removed
#   feat                          -> Added
#   fix                           -> Fixed
#   anything else                 -> Changed
# A breaking change ("!" or a BREAKING CHANGE footer) gets a "Breaking:"
# prefix, wherever it lands. Empty sections are left out.
#
# Usage: release-component-notes.sh <version> <digest> [repo-dir]
# Env:   COMPONENT_URL  GitLab component project (default gitlab.com/getplumber/plumber)
#        CLI_URL        GitHub CLI repository (default github.com/getplumber/plumber)
set -euo pipefail
ver="${1:?version required}"
digest="${2:?digest required}"
dir="${3:-.}"
component_url="${COMPONENT_URL:-https://gitlab.com/getplumber/plumber}"
cli_url="${CLI_URL:-https://github.com/getplumber/plumber}"

[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "invalid digest: '${digest}'" >&2; exit 1; }
tag="v${ver}"
git -C "$dir" rev-parse -q --verify "refs/tags/${tag}" >/dev/null || { echo "tag ${tag} not found in ${dir}" >&2; exit 1; }

# The tag right before ours in version order. Empty for the first release.
prev="$(git -C "$dir" tag --list 'v*' --sort=v:refname \
  | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' \
  | grep -B1 -x "$tag" | grep -vx "$tag" || true)"
range="$tag"
if [ -n "$prev" ]; then range="${prev}..${tag}"; fi

added=() changed=() deprecated=() removed=() fixed=() security=()
changed+=("Image bumped to \`getplumber/plumber:${ver}\` (\`${digest}\`).")

re='^([a-zA-Z]+)(\(([^)]*)\))?(!)?: (.+)$'
while IFS= read -r sha; do
  [ -n "$sha" ] || continue
  subject="$(git -C "$dir" log -1 --format=%s "$sha")"
  body="$(git -C "$dir" log -1 --format=%b "$sha")"
  type="" scope="" bang="" desc="$subject"
  if [[ "$subject" =~ $re ]]; then
    type="$(printf '%s' "${BASH_REMATCH[1]}" | tr '[:upper:]' '[:lower:]')"
    scope="${BASH_REMATCH[3]}"
    bang="${BASH_REMATCH[4]}"
    desc="${BASH_REMATCH[5]}"
  fi
  if [ "$scope" = "release" ]; then continue; fi

  entry="$(printf '%s' "${desc:0:1}" | tr '[:lower:]' '[:upper:]')${desc:1}"
  if ! [[ "$entry" =~ [.!?]$ ]]; then entry="${entry}."; fi
  if [ -n "$bang" ] || printf '%s\n' "$body" | grep -qE '^BREAKING[ -]CHANGE:'; then
    entry="**Breaking:** ${entry}"
  fi

  if [ "$type" = "security" ] || [[ ",${scope}," =~ ,[[:space:]]*security[[:space:]]*, ]]; then
    security+=("$entry")
  elif printf '%s' "$desc" | grep -qi 'deprecat'; then
    deprecated+=("$entry")
  elif printf '%s' "$desc" | grep -qiE '^(remove|drop)'; then
    removed+=("$entry")
  elif [ "$type" = "feat" ]; then
    added+=("$entry")
  elif [ "$type" = "fix" ]; then
    fixed+=("$entry")
  else
    changed+=("$entry")
  fi
done < <(git -C "$dir" log --no-merges --reverse --format=%H "$range" -- templates/)

section() {
  local title="$1"; shift
  [ "$#" -gt 0 ] || return 0
  printf '\n### %s\n\n' "$title"
  printf -- '- %s\n' "$@"
}

date="$(git -C "$dir" log -1 --format=%cs "${tag}^{commit}")"
if [ -n "$prev" ]; then
  link="${component_url}/-/compare/${prev}...${tag}"
else
  link="${component_url}/-/tags/${tag}"
fi

printf '## [%s] - %s\n' "$ver" "$date"
section Added ${added[@]+"${added[@]}"}
section Changed "${changed[@]}"
section Deprecated ${deprecated[@]+"${deprecated[@]}"}
section Removed ${removed[@]+"${removed[@]}"}
section Fixed ${fixed[@]+"${fixed[@]}"}
section Security ${security[@]+"${security[@]}"}
printf '\nThe full CLI changelog is in the [%s GitHub release](%s/releases/tag/%s).\n' "$tag" "$cli_url" "$tag"
printf '\n[%s]: %s\n' "$ver" "$link"
