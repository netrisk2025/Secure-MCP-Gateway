#!/usr/bin/env bash
# Fail when `npm audit` reports a high or critical advisory that is not in
# .github/npm-audit-allowlist.json (or whose allowlist entry has expired).
# Equivalent to `npm audit --audit-level=high` plus a reviewed allowlist.
#
#   scripts/npm-audit-gate.sh [site-dir]
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
dir=${1:-$root/site}
allow="$root/.github/npm-audit-allowlist.json"
today=$(date -u +%Y-%m-%d)

report=$(cd "$dir" && npm audit --json 2>/dev/null || true)
[ -n "$report" ] || { echo "npm-audit-gate: npm audit produced no output" >&2; exit 2; }
if ! jq -e '.vulnerabilities' >/dev/null 2>&1 <<<"$report"; then
  echo "npm-audit-gate: unexpected npm audit output:" >&2
  echo "$report" >&2
  exit 2
fi

allowed='[]'
if [ -f "$allow" ]; then
  allowed=$(jq --arg today "$today" '[.advisories[] | select(.expires >= $today) | .id]' "$allow")
  expired=$(jq -r --arg today "$today" '.advisories[] | select(.expires < $today) | "\(.id) (expired \(.expires))"' "$allow")
  [ -z "$expired" ] || printf 'npm-audit-gate: expired allowlist entries, no longer applied:\n%s\n' "$expired"
fi

# Advisory objects (not package back-references) at high or critical severity.
findings=$(jq -r --argjson allowed "$allowed" '
  [.vulnerabilities[] | .via[] | objects
   | select(.severity == "high" or .severity == "critical")
   | {id: (.url | split("/") | last), name, severity, title, url}]
  | unique_by(.id)
  | map(. + {allowed: (.id as $i | $allowed | index($i) != null)})
  | .[] | "\(if .allowed then "allowed" else "BLOCKING" end)\t\(.severity)\t\(.name)\t\(.id)\t\(.title)"' <<<"$report")

if [ -n "$findings" ]; then
  printf 'npm-audit-gate: high and critical advisories in %s:\n%s\n' "$dir" "$findings"
fi
if grep -q '^BLOCKING' <<<"$findings"; then
  echo "npm-audit-gate: FAIL (fix the dependency, or add a reviewed entry with an expiry to $allow)" >&2
  exit 1
fi
echo "npm-audit-gate: OK"
