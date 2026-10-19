#!/usr/bin/env bash
# Install the Appendix K agent CLIs at the versions pinned in
# docs/clients/matrix.json (FR-15.10), for the "agents" workflow. A client
# without a pinned version gets the latest release; the suite records the
# version it actually ran. A failed install is reported and skipped: the
# suite then records that client as not-run.
#
#   scripts/agents/install-clis.sh            # all installable clients
#   scripts/agents/install-clis.sh codex      # only these client IDs
#
# Requires: jq, npm (Node.js), curl. Installs npm packages globally, Hermes
# under ~/.local and Goose into ~/.local/bin.
set -uo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
matrix="$root/docs/clients/matrix.json"
want=("$@")
failed=()

pin() { jq -r --arg c "$1" '.clients[] | select(.client == $c) | .pinnedVersion // empty' "$matrix"; }
selected() { [ "${#want[@]}" -eq 0 ] || printf '%s\n' "${want[@]}" | grep -qx "$1"; }
say() { printf '==> %s\n' "$*"; }

npm_install() { # id, matrix name, package
  selected "$1" || return 0
  local v; v=$(pin "$2")
  say "$2: npm install -g $3@${v:-latest}"
  npm install -g --no-audit --no-fund "$3@${v:-latest}" >/dev/null || failed+=("$2")
}

npm_install claude-code "Claude Code" @anthropic-ai/claude-code
npm_install codex "Codex CLI" @openai/codex
npm_install opencode "OpenCode" opencode-ai
npm_install gemini "Gemini CLI" @google/gemini-cli

mkdir -p "$HOME/.local/bin"
if selected goose; then
  v=$(pin "Goose")
  say "Goose: release ${v:-stable}"
  curl -fsSL https://github.com/block/goose/releases/download/stable/download_cli.sh \
    | CONFIGURE=false GOOSE_BIN_DIR="$HOME/.local/bin" GOOSE_VERSION="${v:+v$v}" bash >/dev/null 2>&1 \
    || failed+=("Goose")
fi

if selected hermes; then
  v=$(pin "Hermes Agent")
  # Hermes tags releases by date; this maps the pinned version to its tag.
  case "$v" in
    0.17.0) branch=v2026.6.19 ;;
    "") branch="" ;;
    *) echo "Hermes Agent $v: no known release tag; installing the stable channel" >&2; branch="" ;;
  esac
  # The installer at hermes-agent.nousresearch.com follows the main line and
  # cannot install older tags (from mid-2026 it expects a `pm` module that
  # v2026.6.19 lacks: "No module named 'pm'"), so a pinned tag is installed
  # with the installer from that tag.
  url=https://hermes-agent.nousresearch.com/install.sh
  [ -z "$branch" ] || url="https://raw.githubusercontent.com/NousResearch/hermes-agent/$branch/scripts/install.sh"
  say "Hermes Agent: ${branch:-stable channel} ($url)"
  log=$(mktemp)
  if ! curl -fsSL "$url" \
    | bash -s -- --non-interactive --skip-setup --skip-browser ${branch:+--branch "$branch"} >"$log" 2>&1 \
    || ! [ -x "$HOME/.local/bin/hermes" ]; then
    tail -n 30 "$log" >&2
    failed+=("Hermes Agent")
  fi
  rm -f "$log"
fi

for c in claude codex opencode gemini goose hermes; do
  if command -v "$c" >/dev/null 2>&1 || [ -x "$HOME/.local/bin/$c" ]; then
    printf '  %-9s %s\n' "$c" "$("$(command -v "$c" || echo "$HOME/.local/bin/$c")" --version 2>/dev/null | head -n1)"
  fi
done
if [ "${#failed[@]}" -gt 0 ]; then
  echo "install failed (recorded as not-run by the suite): ${failed[*]}" >&2
fi
exit 0
