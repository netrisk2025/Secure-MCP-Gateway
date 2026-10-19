#!/usr/bin/env bash
# Runs the acceptance suite (internal/acceptance) with outbound Internet
# access blocked (SRS FR-12.2, AT-17): in a new network namespace whose only
# interface is loopback, as the invoking user. Everything that needs the
# network happens first: the test binary is compiled, the build cache holds
# the binaries the suite builds, and the reference filesystem and git
# packages were built by scripts/build-reference-packages.sh.
#
# Used by the CI job "offline" (Linux, passwordless sudo):
#   SMCP_REFPKG_DIR=$RUNNER_TEMP/refpkg scripts/ci-offline.sh build/offline-test.json
#
# Environment:
#   SMCP_REFPKG_DIR  directory with pkg-filesystem, pkg-git and reference-test.pub
#   SMCP_NODE        absolute path of node (default: node on PATH)
#   SMCP_PYTHON      absolute path of python3 (default: python3 on PATH)
#   SMCP_ACCEPTANCE_PROFILE  "enforced" to run the suite in the Enforced
#                    profile (rootless Podman, which must work for the
#                    invoking user; XDG_RUNTIME_DIR, DBUS_SESSION_BUS_ADDRESS,
#                    SMCP_AT17_NODE_IMAGE and SMCP_AT17_PYTHON_IMAGE are
#                    passed on, and the images must already be pulled)
#   SMCP_OFFLINE_RUN  -test.run pattern (default: every test)
#
# The output is `go test -json` events with the package name
# .../internal/acceptance/offline (.../offline/enforced in the Enforced
# profile), so tools/reqreport keeps these results apart from the same
# tests run online.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
out=${1:-$root/build/offline-test.json}
mkdir -p "$(dirname "$out")"
out=$(cd "$(dirname "$out")" && pwd)/$(basename "$out")
: "${SMCP_REFPKG_DIR:?set SMCP_REFPKG_DIR to the reference package directory}"
node=${SMCP_NODE:-$(command -v node)}
python=${SMCP_PYTHON:-$(command -v python3)}
work=$(mktemp -d "${TMPDIR:-/tmp}/smcp-offline.XXXXXX")
trap 'rm -rf "$work"' EXIT

echo "==> Compiling the acceptance suite and filling the build cache"
(cd "$root" && go test -c -o "$work/acceptance.test" ./internal/acceptance/)
(cd "$root" && go build -trimpath -o "$work/" ./cmd/smcpd ./cmd/smcpctl ./cmd/smcp-hostile)
(cd "$root" && CGO_ENABLED=0 go build -trimpath -o "$work/" ./cmd/smcp-refserver)
(cd "$root" && go build -o "$work/" ./tools/reqreport)

gobin=$(dirname "$(command -v go)")
envs=(
  "PATH=$gobin:$PATH"
  "HOME=$HOME"
  "GOCACHE=$(go env GOCACHE)"
  "GOMODCACHE=$(go env GOMODCACHE)"
  "GOPATH=$(go env GOPATH)"
  "GOFLAGS=-mod=readonly"
  "GOPROXY=off"
  "GOTOOLCHAIN=local"
  "GONOSUMDB=*"
  "GOSUMDB=off"
  "TMPDIR=${TMPDIR:-/tmp}"
  "SMCP_ACCEPTANCE_OFFLINE=1"
  "SMCP_REFPKG_DIR=$SMCP_REFPKG_DIR"
  "SMCP_NODE=$node"
  "SMCP_PYTHON=$python"
)
pkg=github.com/ethan03805/secure-mcp-gateway/internal/acceptance/offline
if [ "${SMCP_ACCEPTANCE_PROFILE:-}" = enforced ]; then
  pkg=$pkg/enforced
  envs+=("SMCP_ACCEPTANCE_PROFILE=enforced")
  for v in XDG_RUNTIME_DIR DBUS_SESSION_BUS_ADDRESS SMCP_AT17_NODE_IMAGE SMCP_AT17_PYTHON_IMAGE SMCP_ENFORCED_CGROUP_MANAGER; do
    if [ -n "${!v:-}" ]; then envs+=("$v=${!v}"); fi
  done
fi
run=${SMCP_OFFLINE_RUN:-.}

echo "==> Running the suite in a network namespace with loopback only"
rc=0
sudo -n unshare -n -- /bin/sh -c '
  set -e
  ip link set lo up
  uid=$1 gid=$2 dir=$3 pkg=$4 bin=$5 run=$6
  shift 6
  cd "$dir"
  exec setpriv --reuid="$uid" --regid="$gid" --init-groups -- env -i "$@" \
    go tool test2json -p "$pkg" "$bin" -test.v -test.count=1 -test.timeout=40m -test.run "$run"
' _ "$(id -u)" "$(id -g)" "$root/internal/acceptance" "$pkg" "$work/acceptance.test" "$run" "${envs[@]}" > "$out" || rc=$?

passed=$(grep -c '"Action":"pass","Package":"'"$pkg"'","Test"' "$out" || true)
failed=$(grep -c '"Action":"fail","Package":"'"$pkg"'","Test"' "$out" || true)
echo "offline acceptance run: $passed passed, $failed failed (exit $rc); results in $out"
exit "$rc"
