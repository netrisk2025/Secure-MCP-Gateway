#!/usr/bin/env bash
# `smcpctl install` in the Standalone profile with the host's real service
# manager (FR-13.6): a systemd user unit on Linux, a launchd user agent on
# macOS. It installs, checks the directories, the unit, the configuration
# value, the printed notice, the running service and health, runs the
# install a second time and checks that nothing changed (FR-13.4), then
# uninstalls and checks that the unit is gone and the journal is kept.
#
# Used by the CI job install-standalone (ubuntu-24.04 without Podman and
# macos-latest) through cmd/smcpctl.TestInstallStandaloneServiceManager.
# It changes the current user's service manager and home directory: run it
# on a disposable machine or account.
#
#   scripts/ci-install-standalone.sh BIN_DIR WORK_DIR
#
#   BIN_DIR   smcpd, smcpctl and smcp-refserver (uninstall removes them)
#   WORK_DIR  scratch directory (passwords, logs)
#
# Environment:
#   SMCP_INSTALL_PORT     harness listener port (admin: +1, metrics: +2;
#                         default 8743)
#   SMCP_REQUIRE_SERVICE  1 to fail instead of skipping when the user
#                         service manager is unavailable
set -euo pipefail

bin=${1:?usage: ci-install-standalone.sh BIN_DIR WORK_DIR}
work=${2:?usage: ci-install-standalone.sh BIN_DIR WORK_DIR}
port=${SMCP_INSTALL_PORT:-8743}
mkdir -p "$work"

say() { printf '==> install-standalone: %s\n' "$*"; }
fail() {
  printf 'FAIL: install-standalone: %s\n' "$*" >&2
  for f in "$work"/install*.log; do [ -f "$f" ] && { echo "--- $f" >&2; cat "$f" >&2; }; done
  case "$(uname -s)" in
    Linux)
      systemctl --user status smcpd.service --no-pager -l >&2 || true
      journalctl --user -u smcpd.service -n 100 --no-pager >&2 || true
      ;;
    Darwin) launchctl print "gui/$(id -u)/com.smcp.gateway" >&2 || true ;;
  esac
  [ -n "${log_file:-}" ] && [ -f "$log_file" ] && { echo "--- $log_file" >&2; tail -n 100 "$log_file" >&2; }
  exit 1
}
unavailable() {
  if [ "${SMCP_REQUIRE_SERVICE:-0}" = 1 ]; then fail "$*"; fi
  echo "SKIP: install-standalone: $*"
  exit 0
}
mode_of() { if [ "$(uname -s)" = Darwin ]; then stat -f '%Lp' "$1"; else stat -c '%a' "$1"; fi; }
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }

uid=$(id -u)
case "$(uname -s)" in
  Linux)
    os=linux
    if [ ! -S "/run/user/$uid/bus" ]; then
      # A CI runner has no login session; lingering starts the user manager.
      sudo -n loginctl enable-linger "$(id -un)" 2>/dev/null || true
      for _ in $(seq 1 40); do [ -S "/run/user/$uid/bus" ] && break; sleep 0.5; done
    fi
    [ -S "/run/user/$uid/bus" ] || unavailable "no systemd user manager for $(id -un)"
    export XDG_RUNTIME_DIR="/run/user/$uid"
    export DBUS_SESSION_BUS_ADDRESS="unix:path=$XDG_RUNTIME_DIR/bus"
    systemctl --user is-system-running >/dev/null 2>&1 || systemctl --user list-units >/dev/null 2>&1 \
      || unavailable "systemctl --user does not answer"
    cfg_dir="${XDG_CONFIG_HOME:-$HOME/.config}/smcp-gateway"
    state_dir="${XDG_STATE_HOME:-$HOME/.local/state}/smcp-gateway"
    log_file="$state_dir/log/smcpd.log"
    unit="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/smcpd.service"
    ;;
  Darwin)
    os=darwin
    launchctl print "gui/$uid" >/dev/null 2>&1 || unavailable "no launchd GUI domain gui/$uid for $(id -un)"
    cfg_dir="$HOME/Library/Application Support/smcp-gateway/config"
    state_dir="$HOME/Library/Application Support/smcp-gateway/state"
    log_file="$HOME/Library/Logs/smcp-gateway/smcpd.log"
    unit="$HOME/Library/LaunchAgents/com.smcp.gateway.plist"
    ;;
  *) unavailable "the Standalone profile installs on Linux and macOS only" ;;
esac
cfg="$cfg_dir/smcp.toml"
[ ! -e "$cfg" ] || fail "$cfg exists already; run on a clean account"

(umask 077 && head -c 18 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$work/admin.pw" && head -c 18 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$work/approver.pw")
args=(install --bin-dir "$bin" --admin-password-file "$work/admin.pw" --approver-password-file "$work/approver.pw"
  --port "$port" --admin-port "$((port + 1))" --metrics-port "$((port + 2))" --notify off)

say "smcpctl install ($os, Standalone profile)"
"$bin/smcpctl" "${args[@]}" > "$work/install1.log" 2>&1 || fail "smcpctl install"
cat "$work/install1.log"
grep -q "^created service unit $unit" "$work/install1.log" || fail "the install did not create $unit"
grep -q "^created configuration $cfg" "$work/install1.log" || fail "the install did not create $cfg"
grep -q '^health: degraded' "$work/install1.log" || fail "the install did not report health degraded"
grep -q 'This installation is not enforced (Standalone profile)' "$work/install1.log" || fail "the install did not print the not-enforced notice"
grep -q '^mode = "standalone"' "$cfg" || fail "$cfg does not set profile mode standalone"
for d in "$cfg_dir" "$state_dir"; do
  [ "$(mode_of "$d")" = 700 ] || fail "$d has mode $(mode_of "$d"), not 700"
done
[ -f "$unit" ] || fail "$unit missing"

say "the service manager runs smcpd"
if [ "$os" = linux ]; then
  systemctl --user is-active --quiet smcpd.service || fail "smcpd.service (user) is not active"
  systemctl --user is-enabled --quiet smcpd.service || fail "smcpd.service (user) is not enabled"
  systemctl --user show smcpd.service -p MainPID -p ActiveState -p ExecStart --no-pager
else
  launchctl print "gui/$uid/com.smcp.gateway" > "$work/launchd.txt" || fail "launchd does not know com.smcp.gateway"
  grep -q 'state = running' "$work/launchd.txt" || { cat "$work/launchd.txt"; fail "com.smcp.gateway is not running"; }
  grep -E '^\s*(state|pid|program) = ' "$work/launchd.txt" || true
fi
"$bin/smcpctl" health --config "$cfg" > "$work/health.json" || fail "smcpctl health"
grep -q '"profile": *"standalone"' "$work/health.json" || { cat "$work/health.json"; fail "health does not report the standalone profile"; }

say "a second smcpctl install changes nothing (FR-13.4)"
digests() {
  { find "$cfg_dir" "$state_dir/keys" "$state_dir/tls" "$state_dir/journal" "$unit" -type f -print0 2>/dev/null || true; } \
    | while IFS= read -r -d '' f; do sha "$f"; done | sort
}
digests > "$work/digests1"
[ -s "$work/digests1" ] || fail "no installed files to compare"
"$bin/smcpctl" "${args[@]}" > "$work/install2.log" 2>&1 || fail "second smcpctl install"
if grep -E '^(created|updated) ' "$work/install2.log"; then fail "the second install changed the host"; fi
grep -q "^present configuration $cfg" "$work/install2.log" || fail "the second install did not report the configuration present"
grep -q "^present service unit $unit" "$work/install2.log" || fail "the second install did not report the unit present"
digests > "$work/digests2"
diff "$work/digests1" "$work/digests2" || fail "the second install changed configuration, policy, keys, journal or the unit"
echo "second run: $(grep -c '^present' "$work/install2.log") steps present, none created or updated"

say "smcpctl uninstall keeps the journal"
cp "$bin/smcpctl" "$work/smcpctl-keep"
"$work/smcpctl-keep" uninstall --config "$cfg" --bin-dir "$bin" > "$work/uninstall.log" 2>&1 || { cat "$work/uninstall.log"; fail "smcpctl uninstall"; }
cat "$work/uninstall.log"
[ ! -e "$unit" ] || fail "uninstall left $unit"
[ ! -e "$bin/smcpd" ] || fail "uninstall left $bin/smcpd"
if [ "$os" = linux ]; then
  if systemctl --user is-active --quiet smcpd.service; then fail "smcpd.service (user) still active after uninstall"; fi
else
  if launchctl print "gui/$uid/com.smcp.gateway" >/dev/null 2>&1; then fail "com.smcp.gateway still loaded after uninstall"; fi
fi
[ -d "$state_dir/journal" ] || fail "uninstall removed the journal"
"$work/smcpctl-keep" journal verify --config "$cfg" || fail "journal verify after uninstall"
say "passed"
