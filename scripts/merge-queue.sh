#!/usr/bin/env bash
# Local merge queue for many parallel branches. For each PR, in order:
#
#   1. fetch main and the PR branch
#   2. rebase the branch onto origin/main in a temporary worktree, resolving
#      conflicts in generated files by regenerating them:
#        Secure_MCP_Gateway_SRS.md  python3 -I srs_build/gen.py
#        go.sum (any module)        union of both sides, then go mod tidy
#        site/package-lock.json     main's lock, then npm install --package-lock-only
#        CHANGELOG.md               union of both sides
#      Any other conflict stops that PR and is reported.
#   3. regenerate the generated files once more and commit any difference
#   4. make check
#   5. push with --force-with-lease (only if the branch is still where it was)
#   6. wait for the PR's checks (gh pr checks --watch)
#   7. squash-merge and delete the branch
#
# Usage:
#   scripts/merge-queue.sh [options] [PR...]
# Without PR numbers it takes open PRs labeled "ready", oldest first.
#
# Options:
#   --dry-run       rebase and check, but do not push or merge
#   --no-check      skip `make check`
#   --no-wait       push, but do not wait for checks or merge
#   --keep          keep the temporary worktrees
#   --label <name>  label that marks PRs as ready (default: ready)
#   -h, --help      show this help
#
# Environment: SMCP_REPO (default ethan03805/Secure-MCP-Gateway).
set -euo pipefail

REPO=${SMCP_REPO:-ethan03805/Secure-MCP-Gateway}
LABEL=ready
DRY=0
CHECK=1
WAIT=1
KEEP=0
prs=()

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1 ;;
    --no-check) CHECK=0 ;;
    --no-wait) WAIT=0 ;;
    --keep) KEEP=1 ;;
    --label) LABEL=${2:?--label needs a value}; shift ;;
    -h|--help) sed -n '2,32p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "merge-queue: unknown option $1" >&2; exit 2 ;;
    *) prs+=("$1") ;;
  esac
  shift
done

for tool in git gh jq python3 go make; do
  command -v "$tool" >/dev/null 2>&1 || { echo "merge-queue: $tool is required" >&2; exit 2; }
done

root=$(git rev-parse --show-toplevel)
remote=origin
case "$(git -C "$root" remote get-url "$remote")" in
  *"${REPO}"*|*"${REPO}.git") ;;
  *) echo "merge-queue: remote $remote is not $REPO" >&2; exit 2 ;;
esac

if [ ${#prs[@]} -eq 0 ]; then
  while IFS= read -r n; do [ -n "$n" ] && prs+=("$n"); done < <(
    gh pr list -R "$REPO" --state open --label "$LABEL" --limit 100 --json number --jq 'sort_by(.number) | .[].number')
fi
if [ ${#prs[@]} -eq 0 ]; then
  echo "merge-queue: no PRs to process (none given, none labeled \"$LABEL\")"
  exit 0
fi

merged=()
failed=()
skipped=()
worktrees=()

log() { printf '[merge-queue] %s\n' "$*"; }

cleanup() {
  if [ "$KEEP" = 0 ]; then
    for wt in "${worktrees[@]:-}"; do
      [ -n "$wt" ] && git -C "$root" worktree remove --force "$wt" >/dev/null 2>&1 || true
    done
  fi
}
trap cleanup EXIT

# union_merge <file>: keep the lines of both sides of a conflicted file.
union_merge() {
  local f=$1 tmp
  tmp=$(mktemp -d)
  git show ":1:$f" >"$tmp/base" 2>/dev/null || : >"$tmp/base"
  git show ":2:$f" >"$tmp/ours" 2>/dev/null || : >"$tmp/ours"
  git show ":3:$f" >"$tmp/theirs" 2>/dev/null || : >"$tmp/theirs"
  git merge-file --union -p "$tmp/ours" "$tmp/base" "$tmp/theirs" >"$f" || true
  rm -rf "$tmp"
  git add -- "$f"
}

# regenerate [srs] [tidy:<dir>...] [npm]: rebuild generated files.
regenerate() {
  local what
  for what in "$@"; do
    case "$what" in
      srs)
        python3 -I srs_build/gen.py . Secure_MCP_Gateway_SRS.md >/dev/null
        git add -- Secure_MCP_Gateway_SRS.md ;;
      tidy:*)
        local dir=${what#tidy:}
        (cd "$dir" && go mod tidy)
        git add -- "$dir/go.mod" "$dir/go.sum" ;;
      npm)
        (cd site && npm install --package-lock-only --no-audit --no-fund --ignore-scripts >/dev/null)
        git add -- site/package-lock.json ;;
    esac
  done
}

# resolve_conflicts: resolve the current rebase stop; prints unresolved files.
resolve_conflicts() {
  local f regen=() unresolved=()
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    case "$f" in
      Secure_MCP_Gateway_SRS.md)
        git checkout --ours -- "$f" 2>/dev/null || git rm --quiet --cached -- "$f"
        regen+=(srs) ;;
      go.sum|*/go.sum)
        union_merge "$f"
        regen+=("tidy:$(dirname "$f")") ;;
      site/package-lock.json)
        git checkout --ours -- "$f"
        regen+=(npm) ;;
      CHANGELOG.md)
        union_merge "$f" ;;
      *)
        unresolved+=("$f") ;;
    esac
  done < <(git diff --name-only --diff-filter=U)
  if [ ${#unresolved[@]} -gt 0 ]; then
    printf '%s\n' "${unresolved[@]}"
    return 1
  fi
  if [ ${#regen[@]} -gt 0 ]; then
    regenerate "${regen[@]}" || { echo "(regeneration failed)"; return 1; }
  fi
}

rebase_in_progress() {
  local gd
  gd=$(git rev-parse --git-dir)
  [ -d "$gd/rebase-merge" ] || [ -d "$gd/rebase-apply" ]
}

wait_for_checks() {
  local n=$1 out
  # Checks take a few seconds to register after a push.
  for _ in $(seq 1 30); do
    out=$(gh pr checks "$n" -R "$REPO" --required 2>&1 || true)
    case "$out" in
      *"no required checks"*)
        out=$(gh pr checks "$n" -R "$REPO" 2>&1 || true)
        case "$out" in *"no checks reported"*) sleep 10; continue ;; esac
        gh pr checks "$n" -R "$REPO" --watch --interval 20 --fail-fast
        return ;;
      *"no checks reported"*) sleep 10; continue ;;
      *) gh pr checks "$n" -R "$REPO" --required --watch --interval 20 --fail-fast
         return ;;
    esac
  done
  echo "no checks appeared within 5 minutes" >&2
  return 1
}

process() {
  local n=$1 info state draft cross ref oldsha title wt newsha conflicts
  info=$(gh pr view "$n" -R "$REPO" --json number,state,isDraft,isCrossRepository,headRefName,headRefOid,title)
  state=$(jq -r .state <<<"$info"); draft=$(jq -r .isDraft <<<"$info"); cross=$(jq -r .isCrossRepository <<<"$info")
  ref=$(jq -r .headRefName <<<"$info"); oldsha=$(jq -r .headRefOid <<<"$info"); title=$(jq -r .title <<<"$info")
  log "PR #$n: $title ($ref @ ${oldsha:0:12})"
  if [ "$state" != OPEN ]; then skipped+=("#$n: state $state"); return 0; fi
  if [ "$draft" = true ]; then skipped+=("#$n: draft"); return 0; fi
  if [ "$cross" = true ]; then skipped+=("#$n: branch is in a fork; cannot push"); return 0; fi

  git -C "$root" fetch --quiet "$remote" main "+refs/heads/$ref:refs/remotes/$remote/$ref"
  if [ "$(git -C "$root" rev-parse "refs/remotes/$remote/$ref")" != "$oldsha" ]; then
    oldsha=$(git -C "$root" rev-parse "refs/remotes/$remote/$ref")
    log "  branch moved; using ${oldsha:0:12}"
  fi
  wt=$(mktemp -d "${TMPDIR:-/tmp}/merge-queue.XXXXXX")/pr-$n
  git -C "$root" worktree add --quiet --detach "$wt" "$oldsha"

  (
    cd "$wt"
    export GIT_EDITOR=true
    if ! git -c rerere.enabled=false rebase --quiet "$remote/main" >/dev/null 2>&1; then
      steps=0
      while rebase_in_progress; do
        steps=$((steps + 1))
        if [ "$steps" -gt 500 ]; then
          git rebase --abort >/dev/null 2>&1 || true
          echo "rebase made no progress" >"$wt.reason"
          exit 1
        fi
        if ! conflicts=$(resolve_conflicts); then
          git rebase --abort >/dev/null 2>&1 || true
          echo "unresolved conflicts: $(echo "$conflicts" | tr '\n' ' ')" >"$wt.reason"
          exit 1
        fi
        if git diff --cached --quiet; then
          git rebase --skip >/dev/null 2>&1 || true
        else
          git rebase --continue >/dev/null 2>&1 || true
        fi
      done
    fi
    # Generated files can be stale after a clean textual rebase too.
    if ! regenerate srs tidy:. >/dev/null; then
      echo "regenerating the SRS or go.sum failed after the rebase" >"$wt.reason"
      exit 1
    fi
    if [ -f site/package-lock.json ] && ! git diff --quiet "$remote/main" HEAD -- site/package.json; then
      regenerate npm
    fi
    if ! git diff --cached --quiet; then
      git -c user.name="$(git -C "$root" config user.name)" -c user.email="$(git -C "$root" config user.email)" \
        commit --quiet -m "Regenerate generated files after rebase onto main" \
        -m "Secure_MCP_Gateway_SRS.md, go.mod/go.sum and site/package-lock.json rebuilt from their sources by scripts/merge-queue.sh."
    fi
    if [ "$CHECK" = 1 ]; then
      if ! make check >"$wt.check.log" 2>&1; then
        echo "make check failed; log: $wt.check.log" >"$wt.reason"
        exit 1
      fi
    fi
  ) || { failed+=("#$n: $(cat "$wt.reason" 2>/dev/null || echo "rebase failed") (worktree kept: $wt)"); return 0; }

  newsha=$(git -C "$wt" rev-parse HEAD)
  if [ "$DRY" = 1 ]; then
    skipped+=("#$n: dry run; rebased to ${newsha:0:12} (worktree kept: $wt)")
    return 0
  fi
  worktrees+=("$wt")
  if [ "$newsha" != "$oldsha" ]; then
    log "  pushing ${newsha:0:12} (lease ${oldsha:0:12})"
    if ! git -C "$wt" push --quiet --force-with-lease="refs/heads/$ref:$oldsha" "$remote" "HEAD:refs/heads/$ref"; then
      failed+=("#$n: push rejected; the branch moved during processing")
      return 0
    fi
  else
    log "  already up to date with main"
  fi
  if [ "$WAIT" = 0 ]; then
    skipped+=("#$n: pushed ${newsha:0:12}; not waiting for checks (--no-wait)")
    return 0
  fi
  log "  waiting for checks"
  if ! wait_for_checks "$n"; then
    failed+=("#$n: checks failed on ${newsha:0:12} ($(gh pr view "$n" -R "$REPO" --json url --jq .url))")
    return 0
  fi
  log "  merging (squash)"
  if (cd "$root" && gh pr merge "$n" -R "$REPO" --squash --delete-branch --match-head-commit "$newsha"); then
    merged+=("#$n: $title")
    git -C "$root" fetch --quiet "$remote" main
  else
    failed+=("#$n: gh pr merge failed")
  fi
}

for n in "${prs[@]}"; do
  process "$n"
done

echo
echo "merge-queue report"
echo "  merged:  ${#merged[@]}"; for x in "${merged[@]:-}"; do [ -n "$x" ] && echo "    $x"; done
echo "  failed:  ${#failed[@]}"; for x in "${failed[@]:-}"; do [ -n "$x" ] && echo "    $x"; done
echo "  skipped: ${#skipped[@]}"; for x in "${skipped[@]:-}"; do [ -n "$x" ] && echo "    $x"; done
[ ${#failed[@]} -eq 0 ]
