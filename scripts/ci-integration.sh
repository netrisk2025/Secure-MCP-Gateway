#!/usr/bin/env bash
# End-to-end check of the built binaries, as an operator would run them:
# bootstrap a fresh instance in a temporary directory, start smcpd, drive a
# real MCP client through OAuth (PKCE, sign-in form) and a tool call, stop
# the daemon and verify the evidence journal. On Linux with Podman it then
# runs a second instance in the enforced profile and proves that a sandboxed
# backend cannot open network sockets or write outside its mount, that a
# sandboxed backend with network = "egress" reaches a granted local HTTP
# server only through the Egress Broker, and (scripts/ci-systemd.sh) that
# smcpd.service starts under systemd from packaging/linux.
#
# Used by the "linux-integration" CI job; runs locally too:
#   scripts/ci-integration.sh
#
# Environment:
#   SMCP_ITEST_DIR        work directory (default: a new temporary directory)
#   SMCP_REQUIRE_PREREQS  1 to fail when Podman or nftables is missing (CI on Linux)
#   SMCP_ENFORCED_MODE    profile mode of the sandboxed instance (default
#                         enforced; "auto" on hosts without systemd or an LSM)
#   SMCP_ENFORCED_CGROUP_MANAGER  runtime.cgroup_manager for that instance
#   SMCP_RUN_INSTALLER    1 to run packaging/linux/install-enforced.sh twice
#                         with sudo (default: SMCP_REQUIRE_PREREQS)
#   SMCP_RUN_SYSTEMD      1 to install packaging/linux and run smcpd.service
#                         under systemd (scripts/ci-systemd.sh; changes the
#                         host; default: SMCP_REQUIRE_PREREQS)
#   SMCP_ITEST_PORT       harness listener port (admin listener: port + 1,
#                         metrics: port + 2); default the bootstrap defaults
#                         8443, 8444 and 8445
#   SMCP_ITEST_RESULTS    file that receives the `go test -json` events of
#                         the Go tests run against real Podman (appended;
#                         needs jq), so that tools/reqreport counts their
#                         requirement claims; default: none, plain -v output
#
# Features that the current build does not provide are reported under
# "Skipped" and do not fail the run.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=${SMCP_ITEST_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/smcp-itest.XXXXXX")}
mkdir -p "$work"
bin="$work/bin"
inst="$work/instance"
log="$work/smcpd.log"
skipped=()
pid=""

say() { printf '==> %s\n' "$*"; }
skip() { skipped+=("$1"); printf 'SKIP: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

# go_test runs go test in the repository root with the given environment
# assignments and arguments. With SMCP_ITEST_RESULTS set, the events are
# appended to that file and their output printed as with -v.
go_test() {
  local envs=()
  while [ $# -gt 0 ] && [[ $1 == *=* ]]; do envs+=("$1"); shift; done
  if [ -n "${SMCP_ITEST_RESULTS:-}" ]; then
    (cd "$root" && env "${envs[@]}" go test -json "$@") | tee -a "$SMCP_ITEST_RESULTS" | jq -rj 'select(.Action == "output") | .Output'
  else
    (cd "$root" && env "${envs[@]}" go test -v "$@")
  fi
}

pidfile="$work/smcpd.pid"
cleanup() {
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  # smcpd started by the upgrade section's start command.
  if [ -f "$pidfile" ]; then
    kill "$(cat "$pidfile")" 2>/dev/null || true
  fi
}
trap cleanup EXIT

say "Building smcpd, smcpctl and the test client into $bin"
mkdir -p "$bin"
# bootstrap finds smcp-refserver next to smcpctl and writes its absolute
# path into the example configuration.
(cd "$root" && go build -trimpath -o "$bin/" ./cmd/smcpd ./cmd/smcpctl ./cmd/smcp-refserver ./scripts/itest-client)

new_password() {
  local p
  p=$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)
  [ "${#p}" -ge 12 ] || p="itest-password-$RANDOM$RANDOM"
  printf '%s' "$p"
}

say "Bootstrapping a new instance in $inst (non-interactive)"
mkdir -p "$inst"
# Passwords come from protected files, never from argv or the environment
# (SR-7.5-2). Harnesses sign in as the Session Approver (FR-2.23).
(umask 077 && new_password > "$work/admin.pw" && new_password > "$work/approver.pw")
port_args=()
if [ -n "${SMCP_ITEST_PORT:-}" ]; then
  port_args=(--port "$SMCP_ITEST_PORT" --admin-port "$((SMCP_ITEST_PORT + 1))")
fi
"$bin/smcpctl" bootstrap --dir "$inst" ${port_args[@]+"${port_args[@]}"} --notify off \
  --admin-password-file "$work/admin.pw" --approver-password-file "$work/approver.pw"
cfg="$inst/smcp.toml"
[ -f "$cfg" ] || fail "bootstrap did not write $cfg"
"$bin/smcpctl" config validate --config "$cfg"

sandbox="$inst/sandbox"
marker="smcp-itest-$(date +%s)"
printf '%s\n' "$marker" > "$sandbox/hello.txt"

address=$(sed -n 's/^address *= *"\(.*\)"/\1/p' "$cfg" | head -n1)
public_url=$(sed -n 's/^public_url *= *"\(.*\)"/\1/p' "$cfg" | head -n1)
[ -n "$public_url" ] || fail "no public_url in $cfg"

say "Starting smcpd on $address"
"$bin/smcpd" --config "$cfg" >"$log" 2>&1 &
pid=$!
ready=""
for _ in $(seq 1 120); do
  if ! kill -0 "$pid" 2>/dev/null; then
    cat "$log" >&2
    fail "smcpd exited during startup"
  fi
  if "$bin/smcpctl" health --config "$cfg" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.5
done
[ -n "$ready" ] || { cat "$log" >&2; fail "smcpd did not become healthy within 60 s"; }
"$bin/smcpctl" health --config "$cfg"

say "The example server is a signed, verified package (FR-14.10)"
"$bin/smcpctl" package list --config "$cfg"
"$bin/smcpctl" health --config "$cfg" > "$work/package-health.json"
if grep -q unverified_servers "$work/package-health.json"; then
  fail "the bootstrap example server is not served from a verified package"
fi

say "Every standalone element of the bootstrap configuration is wired (info.elements)"
# smcpctl health prints a summary line, then the status JSON. The element
# objects are printed with sorted keys: detail, id, name, state.
"$bin/smcpctl" health --config "$cfg" | tail -n +2 | tr -d ' \n' > "$work/elements.json"
for id in E-01/E-02/E-08/E-12 E-03/E-04 E-05/E-06 E-07 E-09/E-11 E-10 E-13/E-14 E-21 E-22 E-23 E-24 E-27/E-29-E-32; do
  grep -q "\"id\":\"$id\",\"name\":\"[^\"]*\",\"state\":\"active\"" "$work/elements.json" \
    || { cat "$work/elements.json" >&2; fail "element $id is not active"; }
done
for id in E-15/E-16/E-17 E-18 E-19/E-20 E-25/E-26/E-28 E-33; do
  grep -q "\"id\":\"$id\"" "$work/elements.json" || fail "element $id is missing from the report"
done
echo "elements: $(grep -o '"state":"active"' "$work/elements.json" | wc -l | tr -d ' ') active"
metrics_addr=$(sed -n '/^\[metrics\]/,/^\[/s/^address *= *"\(.*\)"/\1/p' "$cfg" | head -n1)
if command -v curl >/dev/null 2>&1 && [ -n "$metrics_addr" ]; then
  curl -fsS "http://$metrics_addr/metrics" > "$work/metrics.txt" || fail "metrics endpoint $metrics_addr"
  grep -q '^smcp_pending_approvals ' "$work/metrics.txt" || fail "metrics lack smcp_pending_approvals"
else
  skip "metrics endpoint check: curl or metrics address missing"
fi

say "Driving an MCP client through OAuth and tool calls"
ca="$inst/state/tls/ca.crt"
[ -f "$ca" ] || fail "CA certificate not found at $ca"
# The example configuration serves the sandbox through the bundled
# reference server (alias "ref"), whose paths are relative to its root.
SMCP_SIGNIN_PASSWORD=$(cat "$work/approver.pw")
export SMCP_SIGNIN_PASSWORD
read_marker() {
  "$bin/itest-client" -url "$public_url" -ca "$ca" \
    -call ref_read_file -args '{"path":"hello.txt"}' -expect "$marker"
}
read_marker || { cat "$log" >&2; fail "MCP client flow (ref_read_file)"; }
"$bin/itest-client" -url "$public_url" -ca "$ca" \
  -call ref_list_files -args '{"path":"."}' -expect "hello.txt" \
  || { cat "$log" >&2; fail "MCP client flow (ref_list_files)"; }

say "A held call passes the filters and is released by an approval (E-07)"
# The approval-demo template obliges approval for read_file; the call is
# held (CP-45) until smcpctl approves it.
"$bin/itest-client" -url "$public_url" -ca "$ca" -scope "smcp:template:approval-demo" \
  -call ref_read_file -args '{"path":"hello.txt"}' -expect "$marker" >"$work/approval-call.log" 2>&1 &
approval_pid=$!
approval_id=""
for _ in $(seq 1 120); do
  approval_id=$("$bin/smcpctl" approvals list --state pending --json --config "$cfg" | tr -d ' \n' | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
  [ -n "$approval_id" ] && break
  kill -0 "$approval_pid" 2>/dev/null || { cat "$work/approval-call.log" >&2; fail "the approval-obligated call ended without being held"; }
  sleep 0.5
done
[ -n "$approval_id" ] || { cat "$work/approval-call.log" >&2; fail "no pending approval appeared"; }
"$bin/smcpctl" approvals approve "$approval_id" --yes --config "$cfg" >/dev/null
wait "$approval_pid" || { cat "$work/approval-call.log" "$log" >&2; fail "the approved call did not return the tool result"; }
echo "approval $approval_id released the held call"

say "Emergency stop refuses tool calls; resume restores them"
"$bin/smcpctl" stop --config "$cfg" --reason "integration test"
if read_marker >"$work/stopped-call.log" 2>&1; then
  cat "$work/stopped-call.log" >&2
  fail "a tool call succeeded during emergency stop"
fi
# The endpoint fails closed: 503 before authentication, or EMERGENCY_STOP.
grep -qE 'status 503|EMERGENCY_STOP' "$work/stopped-call.log" \
  || { cat "$work/stopped-call.log" >&2; fail "call during emergency stop failed for another reason"; }
echo "refused during emergency stop: $(tail -n1 "$work/stopped-call.log")"
"$bin/smcpctl" resume --config "$cfg"
read_marker || { cat "$log" >&2; fail "tool call after resume"; }

call_read() {
  read_marker || { cat "$log" >&2; fail "MCP client flow (ref_read_file) $1"; }
}
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

if "$bin/smcpctl" help 2>&1 | grep -q "keys rotate"; then
  say "Key rotation under traffic (listener certificate, server CA with overlap, evidence key)"
  "$bin/smcpctl" keys status --config "$cfg" >/dev/null
  "$bin/smcpctl" keys rotate tls --config "$cfg" >/dev/null
  sleep 1.2 # the listener re-reads its certificate at most once per second
  call_read "after TLS rotation"
  "$bin/smcpctl" keys rotate ca --overlap 1h --config "$cfg" >/dev/null
  call_read "during the CA overlap"
  "$bin/smcpctl" keys rotate ca --finish --config "$cfg" >/dev/null
  sleep 1.2
  call_read "after the CA switch"
  "$bin/smcpctl" keys rotate evidence --config "$cfg" >/dev/null
  call_read "after evidence-key rotation"

  say "Online encrypted backup"
  (umask 077 && new_password > "$work/backup.pw")
  if "$bin/smcpctl" backup --config "$cfg" </dev/null >/dev/null 2>&1; then
    fail "a backup without passphrase or recipient was written"
  fi
  "$bin/smcpctl" backup --config "$cfg" --passphrase-file "$work/backup.pw"
  archive=$(ls -t "$inst"/backups/*.age | awk 'NR == 1')
  [ -f "$archive.sha256" ] || fail "no checksum file for $archive"
  # sed reads all of its input; head -n1 would close the pipe early and
  # pipefail would fail the script on smcpctl's SIGPIPE (exit 141).
  "$bin/smcpctl" health --config "$cfg" | sed -n 1p
  ops=1
else
  skip "operations commands (keys, backup, restore, upgrade): not in this build"
  ops=0
fi

say "Stopping smcpd"
kill -TERM "$pid"
wait "$pid" || true
pid=""

say "Verifying the evidence journal"
"$bin/smcpctl" journal verify --config "$cfg"

if [ "$ops" = 1 ]; then
  say "Restoring the backup (verify only, then for real)"
  "$bin/smcpctl" restore --config "$cfg" --archive "$archive" --passphrase-file "$work/backup.pw" --verify-only | tail -n1
  "$bin/smcpctl" restore --config "$cfg" --archive "$archive" --passphrase-file "$work/backup.pw" | tail -n1
  "$bin/smcpctl" journal verify --config "$cfg"

  say "Upgrade to a release, then a fault-injected upgrade that must roll back"
  installed="$work/installed" release="$work/release" badrel="$work/bad-release"
  mkdir -p "$installed" "$release" "$badrel"
  cp "$bin/smcpd" "$bin/smcpctl" "$installed/"
  # Release directories as GitHub serves them, signed with a throwaway
  # minisign key: smcpctl upgrade verifies them as install.sh does (FR-13.7,
  # FR-13.2).
  command -v minisign >/dev/null 2>&1 || fail "minisign signs the test releases: apt install minisign (macOS: brew install minisign)"
  minisign -G -W -f -p "$work/release.pub" -s "$work/release.key" >/dev/null
  relkey=$(tail -n 1 "$work/release.pub")
  case "$(uname -s)" in Darwin) ros=darwin ;; *) ros=linux ;; esac
  case "$(uname -m)" in x86_64 | amd64) rarch=amd64 ;; *) rarch=arm64 ;; esac
  make_release() { # DIR VERSION FILES_DIR
    local sums="smcp_$2_checksums.txt" arc="smcp_$2_${ros}_${rarch}.tar.gz"
    tar -czf "$1/$arc" -C "$3" smcpd smcpctl
    (cd "$1" && sha256_of "$arc" > "$sums")
    minisign -S -s "$work/release.key" -m "$1/$sums" -t "smcp $2 file:$sums" >/dev/null
  }
  mkdir -p "$work/release-files" "$work/bad-release-files"
  cp "$bin/smcpd" "$bin/smcpctl" "$work/release-files/"
  make_release "$release" 9.9.9 "$work/release-files"
  printf '#!/bin/sh\nexit 1\n' > "$work/bad-release-files/smcpd" && chmod 755 "$work/bad-release-files/smcpd"
  cp "$bin/smcpctl" "$work/bad-release-files/"
  make_release "$badrel" 9.9.10 "$work/bad-release-files"
  start_cmd="nohup \"$installed/smcpd\" --config \"\$SMCP_CONFIG\" >>\"$log\" 2>&1 & echo \$! > \"$pidfile\""
  stop_cmd="p=\$(cat \"$pidfile\" 2>/dev/null); [ -n \"\$p\" ] && kill \"\$p\" 2>/dev/null; while [ -n \"\$p\" ] && kill -0 \"\$p\" 2>/dev/null; do sleep 0.1; done; true"
  SMCP_CONFIG="$cfg" sh -c "$start_cmd"
  for _ in $(seq 1 100); do "$bin/smcpctl" health --config "$cfg" >/dev/null 2>&1 && break; sleep 0.2; done
  if out=$("$installed/smcpctl" upgrade --config "$cfg" --release "$release" --bin-dir "$installed" \
      --passphrase-file "$work/backup.pw" --start-cmd "$start_cmd" --stop-cmd "$stop_cmd" 2>&1); then
    printf '%s\n' "$out"
    fail "an upgrade to a release not signed with the release key was not refused"
  fi
  printf '%s\n' "$out" | grep -q "release verification failed, nothing changed" || { printf '%s\n' "$out"; fail "unsigned release: wrong refusal"; }
  "$installed/smcpctl" upgrade --config "$cfg" --release "$release" --pubkey "$relkey" --bin-dir "$installed" \
    --passphrase-file "$work/backup.pw" --start-cmd "$start_cmd" --stop-cmd "$stop_cmd" \
    || { cat "$log" >&2; fail "upgrade"; }
  [ -f "$installed/smcpd.prev" ] || fail "upgrade kept no previous binary"
  call_read "after the upgrade"
  if out=$("$installed/smcpctl" upgrade --config "$cfg" --release "$badrel" --pubkey "$relkey" --bin-dir "$installed" \
      --passphrase-file "$work/backup.pw" --start-cmd "$start_cmd" --stop-cmd "$stop_cmd" --health-timeout 10s 2>&1); then
    printf '%s\n' "$out"
    fail "the fault-injected upgrade did not fail"
  fi
  printf '%s\n' "$out" | tail -n3
  printf '%s\n' "$out" | grep -q "previous version is running" || fail "upgrade did not roll back"
  call_read "after the rollback"
  sh -c "$stop_cmd"
  rm -f "$pidfile"
  "$bin/smcpctl" journal verify --config "$cfg" --strict
  grep -q '"upgrade_rolled_back"' "$inst"/state/journal/segment-*.jsonl || fail "upgrade_rolled_back is not in the journal"

  say "Uninstall keeps the evidence"
  "$installed/smcpctl" uninstall --config "$cfg" --bin-dir "$installed" --stop-cmd "$stop_cmd" | tail -n2
  [ ! -e "$installed/smcpd" ] || fail "uninstall left smcpd"
  "$bin/smcpctl" journal verify --dir "$inst/state/journal" --key "$inst/state/keys/evidence-genesis.pub" --strict
fi

say "Enforced-profile prerequisites"
if [ "$(uname -s)" = "Linux" ]; then
  if command -v podman >/dev/null 2>&1; then
    podman --version
  elif [ "${SMCP_REQUIRE_PREREQS:-0}" = 1 ]; then
    fail "podman is not installed"
  else
    skip "podman: not installed"
  fi
  if ! command -v nft >/dev/null 2>&1 && [ "${SMCP_REQUIRE_PREREQS:-0}" = 1 ]; then
    say "nft not found; installing nftables"
    sudo apt-get install -y -qq nftables >/dev/null
  fi
  # Sandboxed servers with network = "egress" run on slirp4netns.
  if ! command -v slirp4netns >/dev/null 2>&1 && [ "${SMCP_REQUIRE_PREREQS:-0}" = 1 ]; then
    say "slirp4netns not found; installing it"
    sudo apt-get install -y -qq slirp4netns >/dev/null
  fi
  if command -v slirp4netns >/dev/null 2>&1; then
    slirp4netns --version | head -n 1
  else
    skip "slirp4netns: not installed (egress for sandboxed servers)"
  fi
  if command -v nft >/dev/null 2>&1; then
    nft --version
    if sudo -n nft list ruleset >/dev/null; then
      echo "nftables: ruleset readable with sudo ($(sudo -n nft list ruleset | grep -c '^table') tables)"
    elif [ "${SMCP_REQUIRE_PREREQS:-0}" = 1 ]; then
      fail "sudo nft list ruleset failed"
    else
      skip "nftables: sudo nft list ruleset not permitted"
    fi
  elif [ "${SMCP_REQUIRE_PREREQS:-0}" = 1 ]; then
    fail "nft is not installed"
  else
    skip "nftables: nft not installed"
  fi
else
  skip "enforced-profile prerequisites: Podman and nftables are checked on Linux only"
fi

# --- Enforced profile: servers in rootless Podman (E-15, E-16, E-17) --------
# A second instance runs with [profile] mode = "enforced" and
# [runtime] sandbox = "podman". The reference server and a hostile probe
# server run in the sandbox; the probe must fail to open network sockets and
# to write outside its writable grant.
enforced_section() {
  local mode=${SMCP_ENFORCED_MODE:-enforced}
  local einst="$work/enforced" share="$work/enforced-share" rw="$work/enforced-rw" sbin="$bin/static"
  local elog="$work/smcpd-enforced.log"
  say "Enforced profile: building statically linked servers into $sbin"
  mkdir -p "$sbin"
  (cd "$root" && CGO_ENABLED=0 go build -trimpath -o "$sbin/" ./cmd/smcp-refserver ./scripts/sandbox-probe)

  # Rootless Podman delegates cgroup controllers through the user's systemd
  # instance. A CI runner may have no user session; lingering starts one.
  if [ "${SMCP_REQUIRE_PREREQS:-0}" = 1 ] && ! podman info --format '{{.Host.CgroupControllers}}' 2>/dev/null | grep -q memory; then
    say "Enforced profile: no delegated memory controller; enabling a systemd user session for $(id -un)"
    sudo -n loginctl enable-linger "$(id -un)" || true
    for _ in $(seq 1 20); do [ -S "/run/user/$(id -u)/bus" ] && break; sleep 0.5; done
    XDG_RUNTIME_DIR="/run/user/$(id -u)"
    DBUS_SESSION_BUS_ADDRESS="unix:path=$XDG_RUNTIME_DIR/bus"
    export XDG_RUNTIME_DIR DBUS_SESSION_BUS_ADDRESS
    podman system migrate >/dev/null 2>&1 || true
    podman info --format 'cgroup manager {{.Host.CgroupManager}}, controllers {{.Host.CgroupControllers}}' || true
  fi

  say "Enforced profile: smcpctl runtime doctor"
  if ! "$bin/smcpctl" runtime doctor; then
    podman info >&2 || true
    [ "$mode" = enforced ] && fail "enforced-profile prerequisites missing"
  fi

  say "Enforced profile: Go integration tests against real Podman"
  local strict=0
  [ "$mode" = enforced ] && strict=1
  go_test CGO_ENABLED=0 SMCP_SANDBOX_IT=1 SMCP_SANDBOX_IT_STRICT=$strict \
    SMCP_SANDBOX_IT_CGROUP_MANAGER="${SMCP_ENFORCED_CGROUP_MANAGER:-}" \
    -count=1 -run Integration ./internal/sandbox/ || fail "sandbox integration tests"
  go_test SMCP_SANDBOX_IT=1 -count=1 -run '^TestIntegrationPackageBuildProbeSandbox$' ./cmd/smcpctl/ ||
    fail "package build probe in the sandbox"
  go_test CGO_ENABLED=0 SMCP_SANDBOX_IT=1 -count=1 -run '^TestIntegrationPackageBuildEachType$' ./internal/packaging/ ||
    fail "package build of each artifact type (OCI probed with Podman)"

  if [ "${SMCP_RUN_INSTALLER:-${SMCP_REQUIRE_PREREQS:-0}}" = 1 ] && sudo -n true 2>/dev/null; then
    say "Enforced profile: packaging/linux/install-enforced.sh (twice; the second run changes nothing)"
    sudo -n "$root/packaging/linux/install-enforced.sh" --no-start | tee "$work/install1.log"
    sudo -n "$root/packaging/linux/install-enforced.sh" --no-start | tee "$work/install2.log"
    if grep -q '^created\|^updated' "$work/install2.log"; then
      fail "second installer run changed the host"
    fi
    if [ -d /sys/kernel/security/apparmor ]; then
      say "Enforced profile: servers run confined by the AppArmor profile smcp-server"
      go_test CGO_ENABLED=0 SMCP_SANDBOX_IT=1 SMCP_SANDBOX_IT_STRICT=$strict SMCP_SANDBOX_IT_APPARMOR=1 \
        SMCP_SANDBOX_IT_CGROUP_MANAGER="${SMCP_ENFORCED_CGROUP_MANAGER:-}" \
        -count=1 -run 'IntegrationServerAppArmorProfile|IntegrationSecretFiles' ./internal/sandbox/ || fail "AppArmor server profile integration test"
    fi
  else
    skip "enforced installer: set SMCP_RUN_INSTALLER=1 with passwordless sudo to exercise it"
  fi

  # A local HTTP server that only the Egress Broker may reach (server
  # "net", network = "egress").
  local web="$work/enforced-web" webport webpid=""
  mkdir -p "$web"
  printf '%s\n' "egress-$(date +%s)" > "$web/hello.txt"
  webport=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')
  python3 -m http.server "$webport" --bind 127.0.0.1 --directory "$web" >"$work/enforced-web.log" 2>&1 &
  webpid=$!
  for _ in $(seq 1 50); do
    curl -fsS "http://127.0.0.1:$webport/hello.txt" >/dev/null 2>&1 && break
    sleep 0.1
  done

  mkdir -p "$einst" "$share" "$rw"
  # Instances run under subordinate UIDs: granted paths must be readable
  # (and the writable grant writable) by other users.
  chmod 755 "$share"
  chmod 777 "$rw"
  local emarker
  emarker="smcp-enforced-$(date +%s)"
  printf '%s\n' "$emarker" > "$share/hello.txt"
  chmod 644 "$share/hello.txt"
  "$bin/smcpctl" bootstrap --dir "$einst" --port 8543 --admin-port 8544 --notify off --refserver "$sbin/smcp-refserver" --sandbox "$share" \
    --admin-password-file "$work/admin.pw" --approver-password-file "$work/approver.pw"
  local ecfg="$einst/smcp.toml" cgm_line=""
  if [ -n "${SMCP_ENFORCED_CGROUP_MANAGER:-}" ]; then
    cgm_line="cgroup_manager = \"$SMCP_ENFORCED_CGROUP_MANAGER\""
  fi
  cat >> "$ecfg" <<EOF

# Every itest-client run signs in again and opens a session.
[limits]
sessions_per_principal = 32
# The sandbox checks below make more than ten calls within ten seconds as
# one principal; they test confinement, not the CP-11 burst (covered by the
# policy unit tests), so the burst window is off here.
principal_call_burst = 0

[profile]
mode = "$mode"

[runtime]
sandbox = "podman"
$cgm_line

[[runtime.server]]
alias = "ref"
[[runtime.server.mount]]
source = "$share"

[[server]]
alias = "probe"
command = "$sbin/sandbox-probe"
risk_classes = ["code-execution"]

[[runtime.server]]
alias = "probe"
[[runtime.server.mount]]
source = "$rw"
target = "/rw"
write = true

# A second copy of the probe attached to the Egress Broker.
[[server]]
alias = "net"
command = "$sbin/sandbox-probe"

[[runtime.server]]
alias = "net"
network = "egress"

[egress]
enabled = true

# The egress checks pass loopback URLs as tool arguments; the request
# filter refuses those by default (URL_PRIVATE_ADDRESS). The network
# confinement and the broker's own grant check are what is tested here.
[filters.urls]
allow_private = true

[[egress.grant]]
server = "net"
host = "127.0.0.1"
addresses = ["127.0.0.1"]
ports = [$webport]
methods = ["GET"]
EOF
  cat > "$einst/policy.json" <<'EOF'
{
  "revision": "r1",
  "framework_profiles": { "dev": { "templates": ["sandbox"], "default_template": "sandbox", "high_risk": ["code-execution"] } },
  "templates": {
    "sandbox": {
      "description": "Reference server and the hostile sandbox probe",
      "high_risk": ["code-execution"],
      "rules": [
        { "id": "ref", "server": "ref", "tools": ["echo", "time_now", "list_files", "read_file"] },
        { "id": "probe", "server": "probe", "tools": ["echo", "net_connect", "write_file", "read_file", "identity"] },
        { "id": "net", "server": "net", "tools": ["net_connect", "http_get"] }
      ]
    }
  }
}
EOF
  "$bin/smcpctl" config validate --config "$ecfg"
  "$bin/smcpctl" runtime spec --config "$ecfg" > "$work/launch-specs.json"
  grep -q '"--network=none"' "$work/launch-specs.json" || fail "launch specification lacks --network=none"
  grep -q '"--cap-drop=all"' "$work/launch-specs.json" || fail "launch specification lacks --cap-drop=all"

  local epublic
  epublic=$(sed -n 's/^public_url *= *"\(.*\)"/\1/p' "$ecfg" | head -n1)
  say "Enforced profile: starting smcpd ($mode)"
  "$bin/smcpd" --config "$ecfg" >"$elog" 2>&1 &
  pid=$!
  local up=""
  for _ in $(seq 1 120); do
    if ! kill -0 "$pid" 2>/dev/null; then
      cat "$elog" >&2
      fail "enforced smcpd exited during startup"
    fi
    if "$bin/smcpctl" health --config "$ecfg" >/dev/null 2>&1; then up=1; break; fi
    sleep 0.5
  done
  [ -n "$up" ] || { cat "$elog" >&2; fail "enforced smcpd did not become healthy within 60 s"; }
  "$bin/smcpctl" health --config "$ecfg" | tee "$work/enforced-health.json"
  if [ "$mode" = enforced ]; then
    grep -q '"profile": *"enforced"' "$work/enforced-health.json" || fail "health does not report the enforced profile"
    grep -q '"launcher": *"podman"' "$work/enforced-health.json" || fail "health does not report the podman launcher"
  fi
  "$bin/smcpctl" runtime instances --config "$ecfg" > "$work/instances.json"
  grep -q '"alias": *"probe"' "$work/instances.json" || fail "runtime instances lacks the probe"

  local eca="$einst/state/tls/ca.crt"
  ecall() { # tool, args, expected substring
    # Every run signs in again; the sign-in guard allows 30 requests per
    # source per minute (authguard), so a refused sign-in waits out the
    # window once.
    local out
    if out=$("$bin/itest-client" -url "$epublic" -ca "$eca" -call "$1" -args "$2" -expect "$3" 2>&1); then
      printf '%s\n' "$out"
      return 0
    fi
    if printf '%s' "$out" | grep -q 'status 429'; then
      echo "sign-in rate limit reached; waiting 61 s"
      sleep 61
      "$bin/itest-client" -url "$epublic" -ca "$eca" -call "$1" -args "$2" -expect "$3" \
        || { cat "$elog" >&2; fail "enforced: $1 $2 (expected \"$3\")"; }
      return 0
    fi
    printf '%s\n' "$out" >&2
    cat "$elog" >&2
    fail "enforced: $1 $2 (expected \"$3\")"
  }
  say "Enforced profile: the reference server works inside the sandbox"
  ecall ref_read_file '{"path":"hello.txt"}' "$emarker"
  say "Enforced profile: the probe cannot open network sockets"
  ecall probe_net_connect '{"address":"1.1.1.1:443"}' "blocked:"
  ecall probe_net_connect '{"address":"127.0.0.1:8543"}' "blocked:"
  ecall probe_net_connect '{"address":"127.0.0.1:8544"}' "blocked:"
  say "Enforced profile: the probe cannot write outside its writable grant"
  ecall probe_write_file "{\"path\":\"$work/escape.txt\",\"text\":\"x\"}" "blocked:"
  [ ! -e "$work/escape.txt" ] || fail "the probe wrote outside its mount"
  ecall probe_write_file "{\"path\":\"$share/escape.txt\",\"text\":\"x\"}" "blocked:"
  [ ! -e "$share/escape.txt" ] || fail "the probe wrote into a path granted only to another server"
  ecall probe_write_file '{"path":"/etc/escape","text":"x"}' "blocked:"
  ecall probe_write_file '{"path":"/smcp/bin/escape","text":"x"}' "blocked:"
  ecall probe_read_file "{\"path\":\"$einst/state/keys/admin.token\"}" "blocked:"
  ecall probe_write_file '{"path":"/rw/inside.txt","text":"ok"}' "wrote"
  [ -e "$rw/inside.txt" ] || fail "the writable grant did not reach the host"
  ecall probe_identity '{}' "NoNewPrivs:"$'\t'"1"
  ecall probe_identity '{}' "CapEff:"$'\t'"0000000000000000"
  say "Enforced profile: a server with network = \"egress\" reaches only its Egress Broker"
  ecall net_http_get "{\"url\":\"http://127.0.0.1:$webport/hello.txt\"}" "status 200: $(cat "$web/hello.txt")"
  ecall net_http_get '{"url":"http://127.0.0.1:8544/"}' "status 403"
  ecall net_net_connect "{\"address\":\"10.0.2.2:$webport\"}" "blocked:"
  ecall net_net_connect '{"address":"10.0.2.2:8544"}' "blocked:"
  ecall net_net_connect '{"address":"10.0.2.3:53"}' "blocked:"
  ecall net_net_connect '{"address":"1.1.1.1:443"}' "blocked:"
  grep -q "\"GET /hello.txt" "$work/enforced-web.log" || fail "the granted HTTP server saw no brokered request"

  say "Stopping the enforced smcpd"
  kill -TERM "$pid"
  wait "$pid" || true
  pid=""
  "$bin/smcpctl" journal verify --config "$ecfg"
  grep -rqs '"instance_launched"' "$einst/state/journal" || fail "no instance_launched evidence in the journal"
  if command -v podman >/dev/null && [ -n "$(podman ps -a --filter label=smcp.managed=1 -q)" ]; then
    podman ps -a --filter label=smcp.managed=1 >&2
    fail "server containers left behind after shutdown"
  fi
  kill "$webpid" 2>/dev/null || true
  say "Enforced profile: sandbox checks passed"

  if [ "${SMCP_RUN_SYSTEMD:-${SMCP_REQUIRE_PREREQS:-0}}" = 1 ] && [ -d /run/systemd/system ] && sudo -n true 2>/dev/null; then
    say "Enforced profile: smcpd.service under systemd (scripts/ci-systemd.sh)"
    "$root/scripts/ci-systemd.sh" "$bin" "$sbin" "$work" || fail "smcpd.service under systemd"
  else
    skip "smcpd.service under systemd: set SMCP_RUN_SYSTEMD=1 on a disposable Linux host with systemd and passwordless sudo"
  fi
}

if [ "$(uname -s)" = "Linux" ] && command -v podman >/dev/null 2>&1; then
  enforced_section
elif [ "$(uname -s)" = "Linux" ] && [ "${SMCP_REQUIRE_PREREQS:-0}" = 1 ]; then
  fail "enforced profile: podman is not installed"
else
  skip "enforced profile (Podman sandbox): runs on Linux with rootless Podman only"
fi

echo
echo "Integration run complete. Work directory: $work"
if [ "${#skipped[@]}" -gt 0 ]; then
  echo "Skipped (${#skipped[@]}):"
  printf '  - %s\n' "${skipped[@]}"
fi
