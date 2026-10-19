#!/usr/bin/env bash
# Publish the result of a verification workflow to the orphan branch
# "site-data" as one entry of /workflows.json, replacing the previous entry
# of the same workflow:
#
#   scripts/publish-workflow-result.sh <workflow> <conclusion> <ref> <commit> <requirement>...
#
#   scripts/publish-workflow-result.sh tap success v1.0.0 "$(git rev-list -n1 v1.0.0)" FR-13.3
#
# The CI "status" job fetches site-data/workflows.json and passes it to
# tools/reqreport with -workflows, which turns each entry into a claim on
# the requirements it names (full on a release tag, partial on any other
# ref, failing for conclusion "failure"). Concurrent publishers are handled
# by retrying on a rejected push.
#
# Environment:
#   SITE_DATA_BRANCH   branch name (default site-data)
#   SITE_DATA_DRY_RUN  1 to build the commit without pushing
set -euo pipefail

[ $# -ge 5 ] || { echo "usage: $0 <workflow> <conclusion> <ref> <commit> <requirement>..." >&2; exit 2; }
workflow=$1 conclusion=$2 ref=$3 commit=$4
shift 4
case $conclusion in success | failure | cancelled | skipped) ;; *) echo "publish-workflow-result: conclusion '$conclusion' is not a job result" >&2; exit 2 ;; esac
[[ $commit =~ ^[0-9a-f]{40}$ ]] || { echo "publish-workflow-result: commit '$commit' is not a full SHA" >&2; exit 2; }
root=$(git rev-parse --show-toplevel)
branch=${SITE_DATA_BRANCH:-site-data}
run_url="${GITHUB_SERVER_URL:-}/${GITHUB_REPOSITORY:-}/actions/runs/${GITHUB_RUN_ID:-local}"
date=$(date -u +%Y-%m-%dT%H:%M:%SZ)
reqs=$(printf '%s\n' "$@" | jq -R . | jq -sc .)
entry=$(jq -nc --arg w "$workflow" --arg c "$conclusion" --arg r "$ref" --arg s "$commit" --arg d "$date" --arg u "$run_url" --argjson q "$reqs" \
  '{workflow: $w, requirements: $q, ref: $r, commit: $s, conclusion: $c, date: $d, runUrl: $u}')

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
    echo "publish-workflow-result: branch $branch does not exist yet; the CI status job creates it" >&2
    return 2
  fi
  git -C "$root" fetch --quiet --depth=1 origin "refs/heads/$branch"
  git -C "$root" worktree add --quiet --detach "$wt" FETCH_HEAD
  if [ -f "$wt/workflows.json" ] && jq -e 'type == "array"' "$wt/workflows.json" >/dev/null 2>&1; then
    cp "$wt/workflows.json" "$tmp/old.json"
  else
    echo '[]' > "$tmp/old.json"
  fi
  jq --argjson e "$entry" '[.[] | select(.workflow != $e.workflow)] + [$e] | sort_by(.workflow)' "$tmp/old.json" > "$wt/workflows.json"
  git -C "$wt" add workflows.json
  if git -C "$wt" diff --cached --quiet; then
    echo "publish-workflow-result: no change"
    return 1
  fi
  git -C "$wt" -c user.name="github-actions[bot]" -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
    commit --quiet -m "Publish $workflow result for $ref [skip ci]" -m "Source: $run_url"
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
    echo "publish-workflow-result: dry run; commit prepared in $wt:"
    git -C "$wt" show HEAD -- workflows.json | cat
    exit 0
  fi
  if git -C "$wt" push --quiet origin "HEAD:refs/heads/$branch"; then
    echo "publish-workflow-result: published $workflow ($conclusion at $ref) to $branch"
    exit 0
  fi
  echo "publish-workflow-result: push rejected (attempt $attempt); refetching and retrying"
  sleep $((attempt * 2))
done
echo "publish-workflow-result: could not publish after 5 attempts" >&2
exit 1
