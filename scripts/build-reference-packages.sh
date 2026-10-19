#!/usr/bin/env bash
# Build the four reference server packages (filesystem, git, fetch, memory)
# from their pinned recipes in packaging/reference, sign them with a test
# key, import and enable them in a fresh Gateway instance, and call one tool
# of each through the Gateway (FR-14.9). This is the only step that
# contacts the npm and PyPI registries.
#
# Usage:
#   scripts/build-reference-packages.sh [work-dir]
#
# Environment:
#   SMCP_PYTHON           absolute path of python3 used to build and run the
#                         PyPI packages (3.10 or later; default: python3.11,
#                         then python3 on PATH)
#   SMCP_NODE             absolute path of node (default: node on PATH)
#   SMCP_REFPKG_OFFLINE   1 to skip the fetch server's tool call (it needs
#                         outbound HTTPS)
#   SMCP_REFPKG_ONLY      space-separated subset, e.g. "filesystem memory"
#
# Requirements: Go, npm and node, a Python with pip, git. The packages are
# built for this host's platform and Python version: compiled wheels in the
# PyPI artifacts only run on the same platform and Python minor version.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=${1:-$(mktemp -d "${TMPDIR:-/tmp}/smcp-refpkg.XXXXXX")}
mkdir -p "$work"
work=$(cd "$work" && pwd)
bin="$work/bin"
inst="$work/instance"
pid=""
only=${SMCP_REFPKG_ONLY:-"filesystem memory git fetch"}

say() { printf '==> %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
cleanup() {
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT

py=${SMCP_PYTHON:-$(command -v python3.11 || command -v python3)}
node=${SMCP_NODE:-$(command -v node || true)}
[ -n "$py" ] && py=$(cd "$(dirname "$py")" && pwd)/$(basename "$py")
"$py" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || fail "$py is older than Python 3.10; set SMCP_PYTHON"
[ -n "$node" ] || fail "node not found; set SMCP_NODE"

say "Building smcpd, smcpctl, smcp-refserver and the test client into $bin"
mkdir -p "$bin"
(cd "$root" && go build -trimpath -o "$bin/" ./cmd/smcpd ./cmd/smcpctl ./cmd/smcp-refserver ./scripts/itest-client)

pw() { head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24; }
(umask 077 && pw > "$work/admin.pw" && pw > "$work/approver.pw")
say "Bootstrapping an instance in $inst"
mkdir -p "$inst"
"$bin/smcpctl" bootstrap --dir "$inst" --admin-password-file "$work/admin.pw" --approver-password-file "$work/approver.pw" \
  --port 18543 --admin-port 18544 >/dev/null
cfg="$inst/smcp.toml"

say "Creating a test signing key and enrolling it for low and moderate"
keyid=$("$bin/smcpctl" package keygen --out "$work/reference-test" --unencrypted | awk '/^key /{print $2}')
"$bin/smcpctl" trust add "$work/reference-test.pub" --name reference-test --key-id "$keyid" --classes low,moderate --expires 30d --config "$cfg"

for r in $only; do
  say "Packaging $r"
  rm -rf "$work/pkg-$r"
  "$bin/smcpctl" package build --recipe "$root/packaging/reference/$r/recipe.json" --out "$work/pkg-$r" --python "$py" --node "$node"
  "$bin/smcpctl" package sign "$work/pkg-$r" --key "$work/reference-test.key"
  "$bin/smcpctl" package verify "$work/pkg-$r" --config "$cfg"
  "$bin/smcpctl" package install "$work/pkg-$r" --enable --config "$cfg"
done

say "Adding the packaged servers to the configuration and policy"
data="$work/data"
mkdir -p "$data/files" "$data/memory" "$data/repo"
echo "reference package check" > "$data/files/hello.txt"
git -C "$data/repo" init -q
git -C "$data/repo" -c user.name=t -c user.email=t@example.invalid commit -q --allow-empty -m init
{
  echo
  for r in $only; do
    case $r in
      filesystem) printf '[[server]]\nalias = "fs"\npackage = "mcp-filesystem"\nslots = { root = "%s" }\n\n' "$data/files" ;;
      memory) printf '[[server]]\nalias = "mem"\npackage = "mcp-memory"\nslots = { data = "%s" }\n\n' "$data/memory" ;;
      git) printf '[[server]]\nalias = "git"\npackage = "mcp-git"\nslots = { repo = "%s" }\n\n' "$data/repo" ;;
      fetch) printf '[[server]]\nalias = "fetch"\npackage = "mcp-fetch"\n\n' ;;
    esac
  done
  printf '[packages]\nnode = "%s"\npython = "%s"\n' "$node" "$py"
} >> "$cfg"
rules='{ "id": "ref", "server": "ref", "tools": ["echo", "list_files", "read_file", "time_now"] }'
for r in $only; do
  case $r in
    filesystem) rules="$rules, { \"id\": \"fs\", \"server\": \"fs\", \"tools\": [\"list_directory\"] }" ;;
    memory) rules="$rules, { \"id\": \"mem\", \"server\": \"mem\", \"tools\": [\"read_graph\"] }" ;;
    git) rules="$rules, { \"id\": \"git\", \"server\": \"git\", \"tools\": [\"git_status\"] }" ;;
    fetch) rules="$rules, { \"id\": \"fetch\", \"server\": \"fetch\", \"tools\": [\"fetch\"] }" ;;
  esac
done
cat > "$inst/policy.json" <<EOF
{
  "revision": "refpkg-1",
  "framework_profiles": { "dev": { "templates": ["read-only"], "default_template": "read-only" } },
  "templates": { "read-only": { "description": "Reference package check", "rules": [ $rules ] } }
}
EOF
"$bin/smcpctl" config validate --config "$cfg"

say "Starting smcpd"
"$bin/smcpd" --config "$cfg" >"$work/smcpd.log" 2>&1 &
pid=$!
for _ in $(seq 1 120); do
  kill -0 "$pid" 2>/dev/null || { cat "$work/smcpd.log" >&2; fail "smcpd exited"; }
  "$bin/smcpctl" health --config "$cfg" >/dev/null 2>&1 && break
  sleep 0.5
done
health=$("$bin/smcpctl" health --config "$cfg")
echo "$health"
case $health in *unverified*) fail "a server is unverified" ;; esac
"$bin/smcpctl" package list --config "$cfg"

export SMCP_SIGNIN_PASSWORD
SMCP_SIGNIN_PASSWORD=$(cat "$work/approver.pw")
call() {
  "$bin/itest-client" -url "https://127.0.0.1:18543" -ca "$inst/state/tls/ca.crt" -call "$1" -args "$2" -expect "$3" \
    || { cat "$work/smcpd.log" >&2; fail "tool call $1"; }
}
# approve_next approves the next pending approval as the operator. The
# fetch tool's side-effect class is external, so its call carries the
# approval floor (SR-1.18-1) and is held until a person approves it.
approve_next() {
  for _ in $(seq 1 120); do
    id=$("$bin/smcpctl" approvals list --json --config "$cfg" 2>/dev/null |
      "$py" -c 'import json, sys; a = json.load(sys.stdin).get("approvals") or []; print(a[0]["id"] if a else "")') || id=""
    if [ -n "$id" ]; then
      "$bin/smcpctl" approvals approve "$id" --yes --comment "reference package check" --config "$cfg"
      return 0
    fi
    sleep 0.5
  done
  echo "no approval to approve" >&2
  return 1
}
for r in $only; do
  say "Calling one tool of $r"
  case $r in
    filesystem) call fs_list_directory "{\"path\": \"$data/files\"}" "hello.txt" ;;
    memory) call mem_read_graph '{}' "entities" ;;
    git) call git_git_status "{\"repo_path\": \"$data/repo\"}" "branch" ;;
    fetch)
      if [ "${SMCP_REFPKG_OFFLINE:-0}" = 1 ]; then
        echo "SKIP: fetch call (SMCP_REFPKG_OFFLINE=1)"
      else
        approve_next &
        approver=$!
        call fetch_fetch '{"url": "https://example.com/"}' "Example Domain"
        wait "$approver" || fail "the fetch call's approval was not given"
      fi ;;
  esac
done

say "Stopping smcpd and verifying the journal"
kill -TERM "$pid"
wait "$pid" || true
pid=""
"$bin/smcpctl" journal verify --config "$cfg"
say "Reference packages built, imported, enabled and called. Packages are in $work/pkg-*"
