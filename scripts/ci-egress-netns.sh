#!/usr/bin/env bash
# Kernel-level check of the Egress Broker (E-18): builds the egress test
# binary, then runs TestNetnsEnforcement as root. The test creates a
# network namespace with a veth pair, attaches it to the broker (which
# installs nftables rules inside the namespace) and checks that direct
# egress is blocked while brokered egress to a granted local HTTP server
# works. No Internet access is used.
#
# It then runs TestHostRulesInNamespace (internal/tunnel) as root: the
# nftables rules of `smcpctl remote enable` (SR-4.14-1) installed in a
# network namespace drop connections from another host to the Gateway
# listener ports while a loopback client inside still reaches them.
#
# Used by the "linux-integration" CI job; runs on any Linux host with sudo,
# iproute2 and nf_tables:
#   scripts/ci-egress-netns.sh
#
# Environment:
#   SMCP_ITEST_DIR      work directory (default: a new temporary directory)
#   SMCP_ITEST_RESULTS  file that receives the `go test -json` events of both
#                       tests (appended), so that tools/reqreport counts their
#                       claims; SMCP_TEST_JSON is an older name for it
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
if [ "$(uname -s)" != "Linux" ]; then
  echo "SKIP: the egress netns test needs Linux (network namespaces, nftables)"
  exit 0
fi
work=${SMCP_ITEST_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/smcp-egress.XXXXXX")}
mkdir -p "$work"
bin="$work/egress.test"
results=${SMCP_ITEST_RESULTS:-${SMCP_TEST_JSON:-$work/netns-test.json}}
mkdir -p "$(dirname "$results")"

echo "==> Building the egress test binary"
(cd "$root" && go test -c -o "$bin" ./internal/egress)

sudo_cmd=()
if [ "$(id -u)" -ne 0 ]; then
  sudo_cmd=(sudo -n)
fi
if command -v nft >/dev/null 2>&1; then nft --version; fi

echo "==> Running TestNetnsEnforcement as root"
(cd "$work" && "${sudo_cmd[@]}" env SMCP_EGRESS_NETNS_TEST=1 "$bin" \
  -test.run '^TestNetnsEnforcement$' -test.v=test2json -test.count=1) |
  (cd "$root" && go tool test2json -t -p github.com/ethan03805/secure-mcp-gateway/internal/egress) |
  tee -a "$results" | jq -rj 'select(.Action == "output") | .Output'

echo "==> Building the tunnel test binary"
tbin="$work/tunnel.test"
(cd "$root" && go test -c -o "$tbin" ./internal/tunnel)
if ! command -v nft >/dev/null 2>&1; then
  "${sudo_cmd[@]}" apt-get update -qq
  "${sudo_cmd[@]}" apt-get install -y -qq nftables >/dev/null
fi
nft --version

echo "==> Running TestHostRulesInNamespace as root (SR-4.14-1)"
(cd "$work" && "${sudo_cmd[@]}" env SMCP_REMOTE_NFT_TEST=1 "$tbin" \
  -test.run '^TestHostRulesInNamespace$' -test.v=test2json -test.count=1) |
  (cd "$root" && go tool test2json -t -p github.com/ethan03805/secure-mcp-gateway/internal/tunnel) |
  tee -a "$results" | jq -rj 'select(.Action == "output") | .Output'
