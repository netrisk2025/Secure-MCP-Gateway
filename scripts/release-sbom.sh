#!/usr/bin/env bash
# Write the SBOM that goes inside every release archive (SRS FR-13.1):
# build/sbom/sbom.spdx.json, SPDX JSON made by syft from the Go module
# requirements (go.mod, go.sum) and the console's npm lock file, whose
# packages are embedded in smcpd as the built console assets.
#
#   scripts/release-sbom.sh [VERSION]
#
# GoReleaser runs it as a before hook. With SMCP_SBOM=1 (the release
# workflow) syft is required; without it and without syft the script
# writes nothing and the archives carry no SBOM (local snapshots).
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
out=$root/build/sbom
rm -rf "$out"

if ! command -v syft >/dev/null 2>&1; then
  if [ "${SMCP_SBOM:-}" = 1 ]; then
    echo "release-sbom: SMCP_SBOM=1 but syft is not installed" >&2
    exit 1
  fi
  echo "release-sbom: syft not installed; the archives carry no SBOM" >&2
  exit 0
fi

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/console" "$out"
cp "$root/go.mod" "$root/go.sum" "$stage/"
cp "$root/console/package.json" "$root/console/package-lock.json" "$stage/console/"
# License fields (FR-12.1): read each Go module's license files from the
# module cache (GoReleaser's `go mod download` hook fills it), falling back
# to the module proxy; tools/sbomcheck checks the result in the release
# workflow.
SYFT_GOLANG_SEARCH_LOCAL_MOD_CACHE_LICENSES=true SYFT_GOLANG_SEARCH_REMOTE_LICENSES=true \
  syft scan "dir:$stage" --source-name smcp --source-version "${1:-dev}" -q -o "spdx-json=$out/sbom.spdx.json"
[ -s "$out/sbom.spdx.json" ] || { echo "release-sbom: syft wrote no SBOM" >&2; exit 1; }
echo "release-sbom: wrote $out/sbom.spdx.json"
