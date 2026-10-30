#!/usr/bin/env bash
# Pushes every E2E case of this directory to its fixture repository, one
# branch per case: v1/testdata/e2e/<provider>/<case>/ becomes branch <case> of
#   github: getplumber-examples/plumber-cli-e2e
#   gitlab: getplumber/examples/plumber-cli-e2e
# plus a `main` branch holding only a README that lists the cases.
#
# Each branch is a single parentless commit with a fixed author and date, so
# the same content always gives the same commit SHA: running the script twice
# changes nothing, and the commit SHAs in the golden files stay stable.
#
# Usage: v1/testdata/e2e/sync.sh [github|gitlab]...   (default: both)
# Remotes can be overridden with PLUMBER_E2E_GITHUB_REMOTE / PLUMBER_E2E_GITLAB_REMOTE.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)

remote_for() {
  case "$1" in
    github) echo "${PLUMBER_E2E_GITHUB_REMOTE:-git@github.com:getplumber-examples/plumber-cli-e2e.git}" ;;
    gitlab) echo "${PLUMBER_E2E_GITLAB_REMOTE:-git@gitlab.com:getplumber/examples/plumber-cli-e2e.git}" ;;
    *) echo "unknown provider: $1" >&2; exit 2 ;;
  esac
}

export GIT_AUTHOR_NAME="Plumber E2E" GIT_AUTHOR_EMAIL="e2e@getplumber.io"
export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME" GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"
export GIT_AUTHOR_DATE="2026-01-01T00:00:00Z" GIT_COMMITTER_DATE="2026-01-01T00:00:00Z"

# commit_tree <src-dir> <branch> <message>: one orphan commit of <src-dir>.
commit_tree() {
  local src=$1 branch=$2 msg=$3
  git checkout -q --orphan "$branch"
  git rm -rq --cached . >/dev/null 2>&1 || true
  find . -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +
  cp -R "$src"/. .
  git add -A
  git -c commit.gpgsign=false commit -q --no-verify -m "$msg"
}

sync_provider() {
  local provider=$1 remote work cases=()
  remote=$(remote_for "$provider")
  work=$(mktemp -d)
  trap 'rm -rf "$work"' RETURN
  for d in "$here/$provider"/*/; do cases+=("$(basename "$d")"); done

  git -C "$work" init -q
  cd "$work"

  local readme="$work.readme"
  mkdir -p "$readme"
  {
    echo "# plumber-cli-e2e"
    echo
    echo "E2E fixtures for https://github.com/getplumber/plumber. Not a real project."
    echo "One branch per test case. The content of each branch is generated from"
    echo "\`v1/testdata/e2e/$provider/<case>/\` in the plumber repository by \`v1/testdata/e2e/sync.sh\`:"
    echo "edit it there, never here."
    echo
    for c in "${cases[@]}"; do echo "- \`$c\`"; done
  } > "$readme/README.md"
  commit_tree "$readme" main "E2E fixture index"
  rm -rf "$readme"

  for c in "${cases[@]}"; do
    commit_tree "$here/$provider/$c" "$c" "E2E case $c"
  done

  git push -q --force "$remote" main "${cases[@]}"
  echo "$provider: pushed main ${cases[*]} to $remote"
  cd - >/dev/null
}

providers=("$@")
[ ${#providers[@]} -eq 0 ] && providers=(github gitlab)
for p in "${providers[@]}"; do sync_provider "$p"; done
