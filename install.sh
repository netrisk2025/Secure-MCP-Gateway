#!/bin/sh
# Install the Secure MCP Gateway binaries from a GitHub release.
#
#   curl -fsSL https://raw.githubusercontent.com/ethan03805/Secure-MCP-Gateway/main/install.sh | sh
#   sh install.sh --version v1.0.0 --dir "$HOME/.local/bin"
#
# The script detects the OS (linux, darwin) and architecture (amd64, arm64),
# downloads the release archive, the checksum file and its minisign
# signature, verifies the signature with the release public key embedded
# below (SRS FR-13.2), verifies the archive's SHA-256 against the checksum
# file, and installs the binaries. When cosign is installed it also verifies
# the checksum file's Sigstore bundle against the release workflow identity.
# If any verification fails it installs nothing. It installs to
# ~/.local/bin unless --dir is given. It never runs sudo on its own: when
# the target directory is not writable it stops and prints the command to
# run.
#
# The minisign signature is checked with `minisign` when it is installed,
# otherwise with OpenSSL 3 (`openssl pkeyutl`, Ed25519 and BLAKE2b-512). On
# macOS, whose /usr/bin/openssl is LibreSSL, install one of them first:
# `brew install minisign`.
#
# Options:
#   --version <tag>   release tag to install (default: latest release)
#   --dir <path>      installation directory (default: $HOME/.local/bin)
#   --repo <o/r>      GitHub repository (default: ethan03805/Secure-MCP-Gateway)
#   --base-url <url>  download base URL, for a mirror (default: the release on GitHub)
#   --pubkey <key>    minisign public key, for a fork (default: the key below)
#   --no-cosign       skip the cosign check even when cosign is installed
#   --help            show this help
set -eu

REPO="ethan03805/Secure-MCP-Gateway"
VERSION=""
DIR="${SMCP_INSTALL_DIR:-$HOME/.local/bin}"
PROJECT="smcp"
BASE_URL=""
NO_COSIGN=0

# Release signing public key (minisign, key ID 064FAC0C64ACCED0). The same
# key is published in SECURITY.md.
PUBKEY="RWTQzqxkDKxPBk0ZPk07i/mcrUVaevLmrm8zRkQLqGrs14RwtUhG30Dq"

usage() {
  cat <<'USAGE'
usage: install.sh [--version <tag>] [--dir <path>] [--repo <owner/name>]
                  [--base-url <url>] [--pubkey <key>] [--no-cosign]

Downloads a Secure MCP Gateway release for this OS and architecture,
verifies the minisign signature of its checksum file with the embedded
release key, verifies the archive's SHA-256, checks the Sigstore bundle
when cosign is installed, and installs smcpd, smcpctl, smcp-refserver and
the harness adapters smcp-stdio, smcp-session and smcp-connect.

  --version <tag>   release tag to install (default: latest release)
  --dir <path>      installation directory (default: $HOME/.local/bin)
  --repo <o/r>      GitHub repository (default: ethan03805/Secure-MCP-Gateway)
  --base-url <url>  download base URL, for a mirror (default: the release on GitHub)
  --pubkey <key>    minisign public key, for a fork (default: the embedded key)
  --no-cosign       skip the cosign check even when cosign is installed

Signature checks need minisign or OpenSSL 3 (macOS: brew install minisign).
USAGE
}
err() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }
say() { printf 'install.sh: %s\n' "$*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --version) [ $# -ge 2 ] || err "--version needs a value"; VERSION="$2"; shift 2 ;;
    --version=*) VERSION="${1#*=}"; shift ;;
    --dir) [ $# -ge 2 ] || err "--dir needs a value"; DIR="$2"; shift 2 ;;
    --dir=*) DIR="${1#*=}"; shift ;;
    --repo) [ $# -ge 2 ] || err "--repo needs a value"; REPO="$2"; shift 2 ;;
    --repo=*) REPO="${1#*=}"; shift ;;
    --base-url) [ $# -ge 2 ] || err "--base-url needs a value"; BASE_URL="$2"; shift 2 ;;
    --base-url=*) BASE_URL="${1#*=}"; shift ;;
    --pubkey) [ $# -ge 2 ] || err "--pubkey needs a value"; PUBKEY="$2"; shift 2 ;;
    --pubkey=*) PUBKEY="${1#*=}"; shift ;;
    --no-cosign) NO_COSIGN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) err "unknown option: $1" ;;
  esac
done

need() { command -v "$1" >/dev/null 2>&1 || err "$1 is required"; }
need uname
need tar
need mktemp
need od

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"; }
  latest_url() { curl -fsSLI --proto '=https' --tlsv1.2 -o /dev/null -w '%{url_effective}' "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q --https-only -O "$2" "$1"; }
  latest_url() { wget --https-only -q -S --spider "$1" 2>&1 | sed -n 's/^ *Location: //p' | tail -n1 | tr -d '\r'; }
else
  err "curl or wget is required"
fi

if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
elif command -v openssl >/dev/null 2>&1; then
  sha256() { openssl dgst -sha256 "$1" | sed 's/^.*= //'; }
else
  err "sha256sum, shasum or openssl is required to verify the download"
fi

# hex <file>: the file's bytes as lowercase hex, no separators.
hex() { od -An -v -tx1 "$1" | tr -d ' \n'; }
b64d() { "$OPENSSL" base64 -d -A; }

# find_openssl3: print an OpenSSL 3 binary (pkeyutl -rawin with Ed25519),
# or nothing.
find_openssl3() {
  for o in openssl /opt/homebrew/opt/openssl@3/bin/openssl /usr/local/opt/openssl@3/bin/openssl; do
    if command -v "$o" >/dev/null 2>&1; then
      case "$("$o" version 2>/dev/null)" in
        "OpenSSL 3"*|"OpenSSL 4"*) echo "$o"; return 0 ;;
      esac
    fi
  done
  return 0
}

# verify_openssl <file> <sigfile> <workdir>: verify a minisign signature
# (legacy "Ed" or prehashed "ED") and its signed trusted comment with
# OpenSSL 3.
verify_openssl() {
  f=$1 sig=$2 w=$3
  printf '%s' "$PUBKEY" | b64d > "$w/pk.bin" 2>/dev/null || return 1
  [ "$(wc -c < "$w/pk.bin" | tr -d ' ')" = 42 ] || { say "malformed public key"; return 1; }
  [ "$(head -c 2 "$w/pk.bin")" = Ed ] || { say "the public key is not a minisign Ed25519 key"; return 1; }
  sed -n 2p "$sig" | tr -d '\r' | b64d > "$w/sig.bin" 2>/dev/null || return 1
  [ "$(wc -c < "$w/sig.bin" | tr -d ' ')" = 74 ] || { say "malformed signature"; return 1; }
  dd if="$w/pk.bin" of="$w/pk.id" bs=1 skip=2 count=8 2>/dev/null
  dd if="$w/sig.bin" of="$w/sig.id" bs=1 skip=2 count=8 2>/dev/null
  [ "$(hex "$w/pk.id")" = "$(hex "$w/sig.id")" ] || { say "the signature was made with a different key"; return 1; }
  # SubjectPublicKeyInfo DER prefix of an Ed25519 key, then the 32-byte key.
  printf '\060\052\060\005\006\003\053\145\160\003\041\000' > "$w/pk.der"
  tail -c 32 "$w/pk.bin" >> "$w/pk.der"
  "$OPENSSL" pkey -pubin -inform DER -in "$w/pk.der" -out "$w/pk.pem" 2>/dev/null || return 1
  tail -c 64 "$w/sig.bin" > "$w/sig.raw"
  case "$(head -c 2 "$w/sig.bin")" in
    ED) "$OPENSSL" dgst -blake2b512 -binary "$f" > "$w/msg" || return 1 ;;
    Ed) cp "$f" "$w/msg" ;;
    *) say "unknown signature algorithm"; return 1 ;;
  esac
  "$OPENSSL" pkeyutl -verify -pubin -inkey "$w/pk.pem" -rawin -in "$w/msg" -sigfile "$w/sig.raw" >/dev/null 2>&1 || return 1
  tc=$(sed -n 3p "$sig" | tr -d '\r')
  case "$tc" in
    "trusted comment: "*) ;;
    *) say "the signature has no trusted comment"; return 1 ;;
  esac
  sed -n 4p "$sig" | tr -d '\r' | b64d > "$w/global.raw" 2>/dev/null || return 1
  { cat "$w/sig.raw"; printf '%s' "${tc#trusted comment: }"; } > "$w/global.msg"
  "$OPENSSL" pkeyutl -verify -pubin -inkey "$w/pk.pem" -rawin -in "$w/global.msg" -sigfile "$w/global.raw" >/dev/null 2>&1 || return 1
}

# verify_signature <file> <sigfile> <workdir>
verify_signature() {
  if command -v minisign >/dev/null 2>&1; then
    VERIFIER=minisign
    minisign -V -q -P "$PUBKEY" -m "$1" -x "$2" >/dev/null 2>&1
    return
  fi
  OPENSSL=$(find_openssl3)
  if [ -n "$OPENSSL" ]; then
    VERIFIER="$OPENSSL"
    mkdir -p "$3"
    verify_openssl "$1" "$2" "$3"
    return
  fi
  err "cannot verify the release signature: install minisign (macOS: brew install minisign; Debian and Ubuntu: apt install minisign) or OpenSSL 3, then run install.sh again. Nothing was installed."
}

case "$(uname -s)" in
  Linux) OS=linux ;;
  Darwin) OS=darwin ;;
  *) err "unsupported operating system: $(uname -s) (supported: Linux, macOS)" ;;
esac
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  arm64|aarch64) ARCH=arm64 ;;
  *) err "unsupported architecture: $(uname -m) (supported: amd64, arm64)" ;;
esac

if [ -z "$VERSION" ]; then
  url=$(latest_url "https://github.com/$REPO/releases/latest") || err "could not resolve the latest release"
  VERSION="${url##*/}"
  case "$VERSION" in
    v[0-9]*) ;;
    *) err "could not determine the latest release (got '$VERSION'); pass --version" ;;
  esac
fi
case "$VERSION" in
  v*) ;;
  *) VERSION="v$VERSION" ;;
esac
NUM="${VERSION#v}"

ARCHIVE="${PROJECT}_${NUM}_${OS}_${ARCH}.tar.gz"
SUMS="${PROJECT}_${NUM}_checksums.txt"
BASE="${BASE_URL:-https://github.com/$REPO/releases/download/$VERSION}"
BASE="${BASE%/}"

TMP=$(mktemp -d 2>/dev/null || mktemp -d -t smcp)
trap 'rm -rf "$TMP"' EXIT INT TERM

say "downloading $ARCHIVE ($VERSION)"
fetch "$BASE/$ARCHIVE" "$TMP/$ARCHIVE" || err "download failed: $BASE/$ARCHIVE"
fetch "$BASE/$SUMS" "$TMP/$SUMS" || err "download failed: $BASE/$SUMS"
fetch "$BASE/$SUMS.minisig" "$TMP/$SUMS.minisig" || err "download failed: $BASE/$SUMS.minisig (no minisign signature; nothing was installed)"

# 1. The checksum file's minisign signature, with the embedded key.
VERIFIER=""
verify_signature "$TMP/$SUMS" "$TMP/$SUMS.minisig" "$TMP/sigcheck" \
  || err "the minisign signature of $SUMS does not verify with the release key; nothing was installed"
case "$(sed -n 3p "$TMP/$SUMS.minisig")" in
  *"file:$SUMS"*) ;;
  *) err "the signed trusted comment in $SUMS.minisig does not name $SUMS; nothing was installed" ;;
esac
say "signature verified ($SUMS, with $VERIFIER)"

# 2. The Sigstore bundle of the checksum file, when cosign is installed.
if [ "$NO_COSIGN" = 1 ]; then
  say "cosign check skipped (--no-cosign)"
elif command -v cosign >/dev/null 2>&1; then
  fetch "$BASE/$SUMS.sigstore.json" "$TMP/$SUMS.sigstore.json" \
    || err "download failed: $BASE/$SUMS.sigstore.json (cosign is installed but the release has no Sigstore bundle; pass --no-cosign to rely on the minisign signature alone)"
  cosign verify-blob --bundle "$TMP/$SUMS.sigstore.json" \
    --certificate-identity-regexp "^https://github.com/$REPO/.github/workflows/release.yml@" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com "$TMP/$SUMS" >/dev/null 2>&1 \
    || err "cosign could not verify $SUMS.sigstore.json against the $REPO release workflow; nothing was installed"
  say "Sigstore bundle verified (cosign, $REPO release workflow)"
else
  say "cosign is not installed; the Sigstore bundle was not checked (the minisign signature was)"
fi

# 3. The archive's SHA-256 against the verified checksum file.
want=$(awk -v f="$ARCHIVE" '$2 == f || $2 == "*" f { print $1 }' "$TMP/$SUMS")
[ -n "$want" ] || err "$ARCHIVE is not listed in $SUMS"
got=$(sha256 "$TMP/$ARCHIVE")
[ "$want" = "$got" ] || err "checksum mismatch for $ARCHIVE: expected $want, got $got; nothing was installed"
say "checksum verified ($got)"

mkdir -p "$TMP/x"
tar -xzf "$TMP/$ARCHIVE" -C "$TMP/x"

if ! mkdir -p "$DIR" 2>/dev/null || [ ! -w "$DIR" ]; then
  say "$DIR is not writable by $(id -un)."
  say "Either choose a directory you own (--dir \"\$HOME/.local/bin\"), or install as root after reviewing the files:"
  say "  sudo install -m 0755 $TMP/x/smcp* $DIR/"
  trap - EXIT INT TERM
  say "(the extracted files are kept in $TMP/x for that command)"
  exit 1
fi

installed=""
for b in smcpd smcpctl smcp-refserver smcp-stdio smcp-session smcp-connect; do
  if [ -f "$TMP/x/$b" ]; then
    cp "$TMP/x/$b" "$DIR/$b.tmp.$$"
    chmod 0755 "$DIR/$b.tmp.$$"
    mv -f "$DIR/$b.tmp.$$" "$DIR/$b"
    installed="$installed $b"
  fi
done
[ -n "$installed" ] || err "the archive contains no binaries"
say "installed$installed to $DIR"

case ":$PATH:" in
  *":$DIR:"*) ;;
  *) say "$DIR is not on PATH; add it, for example: export PATH=\"$DIR:\$PATH\"" ;;
esac
say "next: smcpctl install   (Standalone service; see docs/install.md)"
