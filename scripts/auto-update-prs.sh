#!/usr/bin/env bash
# Check every open same-repository PR with auto-merge enabled against the
# latest main and label the ones that conflict. Used by .github/workflows/auto-update.yml.
#
#   GH_TOKEN=... scripts/auto-update-prs.sh owner/repo
#
# On a conflict: label "needs-rebase" and comment once.
# When the conflict is gone: remove "needs-rebase".
# Environment: DRY_RUN=1 prints what would happen without changing anything.
set -euo pipefail

repo=${1:?usage: $0 owner/repo}
label=needs-rebase
dry=${DRY_RUN:-0}

run() {
  if [ "$dry" = 1 ]; then echo "DRY RUN: $*"; else "$@"; fi
}

if [ "$dry" != 1 ]; then
  gh label create "$label" -R "$repo" --color B60205 \
    --description "Conflicts with main; rebase needed (set by the auto-update workflow)" >/dev/null 2>&1 || true
fi

prs=$(gh pr list -R "$repo" --state open --limit 200 \
  --json number,headRefName,headRefOid,isCrossRepository,autoMergeRequest,labels \
  --jq '.[] | select(.autoMergeRequest != null and (.isCrossRepository | not))
        | [.number, .headRefName, .headRefOid, ([.labels[].name] | index("'"$label"'") != null)] | @tsv')

if [ -z "$prs" ]; then
  echo "auto-update: no open PRs with auto-merge enabled"
  exit 0
fi

while IFS=$'\t' read -r num ref sha labeled; do
  echo "auto-update: PR #$num ($ref @ ${sha:0:12})"
  # Pushing an update with GITHUB_TOKEN leaves the PR's CI run waiting for
  # approval (runs started by github-actions[bot] are held), which blocks
  # the merge. So this job only reports conflicts; the PR's owner (or
  # scripts/merge-queue.sh) updates the branch with a user token, which
  # starts CI normally.
  state=""
  for _ in 1 2 3 4 5; do
    state=$(gh api "repos/$repo/pulls/$num" --jq '.mergeable_state // ""')
    [ "$state" != "unknown" ] && [ -n "$state" ] && break
    sleep 3
  done
  echo "  mergeable_state: ${state:-unknown}"
  if [ "$state" = dirty ]; then
    if [ "$labeled" != true ]; then
      run gh pr edit "$num" -R "$repo" --add-label "$label" >/dev/null || true
      run gh pr comment "$num" -R "$repo" --body "This branch conflicts with main. Rebase it onto main (or run scripts/merge-queue.sh $num, which regenerates generated files and unions CHANGELOG.md), then push. The label is removed once the conflict is gone." >/dev/null || true
    fi
  elif [ "$labeled" = true ]; then
    run gh pr edit "$num" -R "$repo" --remove-label "$label" >/dev/null || true
  fi
done <<<"$prs"
