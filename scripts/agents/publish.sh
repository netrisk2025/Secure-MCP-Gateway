#!/usr/bin/env bash
# Publish real-agent results to the orphan branch "site-data":
#   /agents.json   the results array of the latest suite run (STATUS CONTRACT agents)
#   /status.json   its "agents" field is replaced with the same array, when present
#
#   scripts/agents/publish.sh build/agents.json
#
# Runs in the "agents" workflow after the suite. The CI "status" job reads
# site-data/agents.json when it publishes a new status.json, so results
# survive the next push to main. Concurrent publishers are handled by
# retrying on a rejected push.
#
# Environment:
#   SITE_DATA_BRANCH   branch name (default site-data)
#   SITE_DATA_DRY_RUN  1 to build the commit without pushing
set -euo pipefail

[ $# -eq 1 ] || { echo "usage: $0 <agents.json>" >&2; exit 2; }
root=$(git rev-parse --show-toplevel)
src=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
branch=${SITE_DATA_BRANCH:-site-data}
jq -e 'type == "array" and all(.[]; has("client") and has("version") and has("mode") and has("result") and has("detail"))' "$src" >/dev/null \
  || { echo "publish: $src is not an agents results array" >&2; exit 1; }

tmp=$(mktemp -d)
wt="$tmp/site-data"
# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
  git -C "$root" worktree remove --force "$wt" >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT

prepare() {
  git -C "$root" worktree remove --force "$wt" >/dev/null 2>&1 || true
  if ! git -C "$root" ls-remote --exit-code --heads origin "$branch" >/dev/null 2>&1; then
    echo "publish: branch $branch does not exist yet; the CI status job creates it" >&2
    return 2
  fi
  git -C "$root" fetch --quiet --depth=1 origin "refs/heads/$branch"
  git -C "$root" worktree add --quiet --detach "$wt" FETCH_HEAD
  cp "$src" "$wt/agents.json"
  git -C "$wt" add agents.json
  if [ -f "$wt/status.json" ]; then
    jq --slurpfile a "$src" '.agents = $a[0]' "$wt/status.json" > "$tmp/status.json"
    mv "$tmp/status.json" "$wt/status.json"
    git -C "$wt" add status.json
  fi
  if git -C "$wt" diff --cached --quiet; then
    echo "publish: no change"
    return 1
  fi
  git -C "$wt" -c user.name="github-actions[bot]" -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
    commit --quiet -m "Publish real-agent results [skip ci]" -m "Source: ${GITHUB_SERVER_URL:-}/${GITHUB_REPOSITORY:-}/actions/runs/${GITHUB_RUN_ID:-local}"
}

for attempt in 1 2 3 4 5; do
  rc=0
  prepare || rc=$?
  case $rc in
    0) ;;
    1) exit 0 ;;
    *) exit 1 ;;
  esac
  if [ "${SITE_DATA_DRY_RUN:-0}" = 1 ]; then
    echo "publish: dry run; commit prepared in $wt:"
    git -C "$wt" show --stat --oneline HEAD | cat
    exit 0
  fi
  if git -C "$wt" push --quiet origin "HEAD:refs/heads/$branch"; then
    echo "publish: published agents.json to $branch"
    exit 0
  fi
  echo "publish: push rejected (attempt $attempt); refetching and retrying"
  sleep $((attempt * 2))
done
echo "publish: could not publish after 5 attempts" >&2
exit 1
