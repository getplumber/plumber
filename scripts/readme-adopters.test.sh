#!/usr/bin/env bash
# Unit tests for readme-adopters.sh (offline: ADOPTERS_JSON skips the API).
# Run: bash scripts/readme-adopters.test.sh
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
script="$here/readme-adopters.sh"
fails=0
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

check() { if eval "$2"; then echo "ok: $1"; else echo "FAIL: $1"; fails=$((fails+1)); fi; }

cat > "$tmp/adopters.json" <<'EOF'
[
  {"owner": "big-org", "id": 1, "repo": "big-org/app", "url": "https://github.com/big-org/app", "stars": 35649, "name": "Big Org"},
  {"owner": "SoloDev", "id": 2, "repo": "SoloDev/tool", "url": "https://github.com/SoloDev/tool", "stars": 11000, "name": "SoloDev"},
  {"owner": "hidden", "id": 3, "repo": "hidden/x", "url": "https://github.com/hidden/x", "stars": 5000, "name": "Hidden"}
]
EOF
cat > "$tmp/overrides.json" <<'EOF'
{"exclude": ["Hidden"], "owners": {"solodev": {"name": "tool", "logo": "assets/adopters/tool.png"}}}
EOF
cat > "$tmp/README.md" <<'EOF'
# Title
<!-- adopters:start -->
stale line
<!-- adopters:end -->
after
EOF

export ADOPTERS_JSON="$tmp/adopters.json" ADOPTERS_OVERRIDES="$tmp/overrides.json"
bash "$script" "$tmp/README.md" > /dev/null
out="$(cat "$tmp/README.md")"

check "block replaces stale content" '! grep -q "stale line" <<<"$out"'
check "markers and surrounding text kept" 'grep -q "^# Title$" <<<"$out" && grep -q "^after$" <<<"$out" && grep -q "adopters:start" <<<"$out" && grep -q "adopters:end" <<<"$out"'
check "stars rounded down to one decimal" 'grep -q "&#9733; 35.6k" <<<"$out"'
check "trailing .0 dropped" 'grep -q "&#9733; 11k<" <<<"$out"'
check "default logo is the owner avatar" 'grep -q "avatars.githubusercontent.com/u/1?s=96" <<<"$out"'
check "override name and logo applied" 'grep -q "src=\"assets/adopters/tool.png\"" <<<"$out" && grep -q "<b>tool</b>" <<<"$out"'
check "excluded owner dropped (case-insensitive)" '! grep -q "hidden/x" <<<"$out"'

bash "$script" "$tmp/README.md" > /dev/null
check "idempotent" '[ "$(cat "$tmp/README.md")" = "$out" ]'

# Empty list: README must stay as it was.
echo '[]' > "$tmp/empty.json"
ADOPTERS_JSON="$tmp/empty.json" bash "$script" "$tmp/README.md" 2> /dev/null
check "empty list leaves README unchanged" '[ "$(cat "$tmp/README.md")" = "$out" ]'

# Missing markers: fail with a diagnostic, file untouched.
printf '# No markers\n' > "$tmp/nomarkers.md"
set +e
msg="$(bash "$script" "$tmp/nomarkers.md" 2>&1)"
rc=$?
set -e
check "missing markers rejected with message" '[ "$rc" -ne 0 ] && grep -q "no <!-- adopters:start -->" <<<"$msg"'

if [ "$fails" -gt 0 ]; then echo "${fails} failure(s)"; exit 1; fi
echo "all readme-adopters tests passed"
