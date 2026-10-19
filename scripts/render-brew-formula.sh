#!/usr/bin/env bash
# Render packaging/homebrew/smcp.rb.tmpl for one release.
#
#   scripts/render-brew-formula.sh <tag> <checksums.txt> > smcp.rb
#
# <checksums.txt> is the release's smcp_<version>_checksums.txt (from
# build/dist after `make release-snapshot`, or downloaded from the release).
set -euo pipefail

[ $# -eq 2 ] || { echo "usage: $0 <tag> <checksums.txt>" >&2; exit 2; }
tag=$1
sums=$2
version=${tag#v}
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

sum_for() {
  local s
  s=$(awk -v f="smcp_${version}_$1.tar.gz" '$2 == f { print $1 }' "$sums")
  [ -n "$s" ] || { echo "render-brew-formula: smcp_${version}_$1.tar.gz not in $sums" >&2; exit 1; }
  printf '%s' "$s"
}

sed -e "s/@VERSION@/$version/g" \
    -e "s/@SHA256_DARWIN_ARM64@/$(sum_for darwin_arm64)/" \
    -e "s/@SHA256_DARWIN_AMD64@/$(sum_for darwin_amd64)/" \
    -e "s/@SHA256_LINUX_ARM64@/$(sum_for linux_arm64)/" \
    -e "s/@SHA256_LINUX_AMD64@/$(sum_for linux_amd64)/" \
    "$root/packaging/homebrew/smcp.rb.tmpl"
