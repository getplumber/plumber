#!/usr/bin/env bash
# Refresh the README "used by" block: open source projects with 2k+ stars
# whose GitHub workflows run the Plumber Action. Run by the release pin-refs
# job, so the block is refreshed on every release and ships in the same
# [skip ci] commit as the pinned refs.
#
# Discovery is GitHub code search, with the same filters as the monorepo
# metrics collector: our own orgs excluded, forks and archived repos
# dropped, one entry per owner (its most-starred repo). Hand edits (owners
# to hide, a label or logo when the avatar is a personal photo) live in
# scripts/readme-adopters.overrides.json.
#
# Usage: readme-adopters.sh [readme]     (default: README.md)
# Env:   GH_TOKEN          token for `gh` (code search requires auth)
#        ADOPTERS_JSON     path to a pre-fetched adopter list; skips the
#                          GitHub API entirely (used by the tests)
#
# Never rewrites the README on a failed fetch: it exits non-zero and leaves
# the file untouched, and the release job treats that as a warning.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
readme="${1:-README.md}"
overrides="${ADOPTERS_OVERRIDES:-$here/readme-adopters.overrides.json}"
min_stars=2000
start='<!-- adopters:start -->'
end='<!-- adopters:end -->'

[ -f "$readme" ] || { echo "readme-adopters: $readme not found" >&2; exit 1; }
if ! grep -qF "$start" "$readme" || ! grep -qF "$end" "$readme"; then
  echo "readme-adopters: $readme has no $start / $end markers" >&2
  exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fetch() {
  # Code search caps at 1000 results; --paginate walks every page.
  gh api -X GET search/code --paginate \
    -f q='"uses: getplumber/plumber" path:.github/workflows' -f per_page=100 \
    --jq '.items[].repository.full_name' | sort -u > "$tmp/names"

  : > "$tmp/repos.jsonl"
  while read -r full; do
    case "${full%%/*}" in getplumber|getplumber-examples|GetPlumber) continue ;; esac
    # A repo that 404s since indexing (deleted, renamed, private) is skipped:
    # without its star count it cannot be placed against the threshold.
    gh api "repos/$full" --jq '{owner: .owner.login, type: .owner.type, id: .owner.id,
      repo: .full_name, url: .html_url, stars: .stargazers_count,
      fork: .fork, archived: .archived}' >> "$tmp/repos.jsonl" 2>/dev/null || true
  done < "$tmp/names"

  jq -s --argjson min "$min_stars" '
    map(select((.fork | not) and (.archived | not)))
    | group_by(.owner | ascii_downcase)
    | map(max_by(.stars))
    | map(select(.stars >= $min))
    | sort_by(-.stars)' "$tmp/repos.jsonl" > "$tmp/kept.json"

  # Org display names ("Lightpanda") read better than logins ("lightpanda-io").
  jq -c '.[]' "$tmp/kept.json" | while read -r r; do
    name="$(jq -r '.owner' <<<"$r")"
    if [ "$(jq -r '.type' <<<"$r")" = "Organization" ]; then
      org="$(gh api "orgs/$name" --jq '.name // empty' 2>/dev/null || true)"
      [ -n "$org" ] && name="$org"
    fi
    jq -c --arg name "$name" '. + {name: $name}' <<<"$r"
  done | jq -s '.'
}

if [ -n "${ADOPTERS_JSON:-}" ]; then
  cp "$ADOPTERS_JSON" "$tmp/adopters.json"
else
  fetch > "$tmp/adopters.json"
fi

# Apply the hand edits, then render one centered table cell per project.
jq -r --slurpfile ov "$overrides" '
  ($ov[0].exclude // [] | map(ascii_downcase)) as $ex
  | ($ov[0].owners // {}) as $own
  | map(select((.owner | ascii_downcase) as $o | $ex | index($o) | not))
  | map(. as $a | ($own[$a.owner | ascii_downcase] // {}) as $o
      | $a + {name: ($o.name // $a.name),
              logo: ($o.logo // "https://avatars.githubusercontent.com/u/\($a.id)?s=96")})
  | map(. + {starsLabel: (if .stars >= 1000
      then "\((.stars / 100 | floor) / 10)k" | sub("\\.0k$"; "k")
      else "\(.stars)" end)})
  | if length == 0 then empty else
      "<table align=\"center\">\n  <tr>",
      (.[] | "    <td align=\"center\"><a href=\"\(.url)\"><img src=\"\(.logo)\" width=\"48\" height=\"48\" alt=\"\(.name)\"><br><sub><b>\(.name)</b><br>&#9733; \(.starsLabel)</sub></a></td>"),
      "  </tr>\n</table>"
    end' "$tmp/adopters.json" > "$tmp/block"

if [ ! -s "$tmp/block" ]; then
  # Nothing to show: far more likely a search hiccup than every adopter
  # leaving at once, so keep whatever the README already has.
  echo "readme-adopters: empty adopter list, README left unchanged" >&2
  exit 0
fi

# Splice the block between the markers, keeping the markers themselves.
awk -v start="$start" -v end="$end" -v block="$tmp/block" '
  $0 == start { print; while ((getline line < block) > 0) print line; skip = 1; next }
  $0 == end   { skip = 0 }
  !skip       { print }
' "$readme" > "$tmp/readme"
cat "$tmp/readme" > "$readme"

echo "readme-adopters: $(jq length "$tmp/adopters.json") adopters rendered into $readme"
