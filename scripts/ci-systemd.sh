#!/usr/bin/env bash
# Enforced profile under real systemd: installs it with
# `smcpctl install --profile enforced` (FR-13.5: packaging/linux, the
# bootstrap as smcp-core, /etc/smcp/smcp.toml, smcpd.service started and
# healthy), runs the install a second time and checks that nothing changed
# (FR-13.4), adds the sandbox probe and a secret vault to the installed
# configuration, restarts smcpd.service with runtime.run_as = "smcp-srv", makes tool
# calls that run in rootless Podman containers of the separate server
# identity smcp-srv (CP-46), delivers an S3 secret file to a server in an
# auto user namespace, stops the service and verifies the evidence journal,
# then uninstalls and purges the installation (FR-13.11, FR-13.12).
# When AppArmor is enabled it also checks that smcpd runs confined by the
# shipped profile and that the servers run confined by smcp-server, which
# denies a read their own permissions allow.
#
# Called by the enforced section of scripts/ci-integration.sh (CI job
# linux-integration on ubuntu-24.04); runs standalone on a Linux host with
# systemd and passwordless sudo. It changes the host (users, /etc/smcp,
# /var/lib/smcp, systemd units): run it on a disposable machine.
#
#   scripts/ci-systemd.sh BIN_DIR STATIC_DIR WORK_DIR
#
#   BIN_DIR     smcpd, smcpctl and itest-client
#   STATIC_DIR  statically linked smcp-refserver (it runs in an empty root)
#   WORK_DIR    scratch directory (passwords, logs)
#
# Environment:
#   SMCP_SYSTEMD_PORT  harness listener port (admin: +1, metrics: +2;
#                      default 8643)
set -euo pipefail

bin=${1:?usage: ci-systemd.sh BIN_DIR STATIC_DIR WORK_DIR}
sbin=${2:?usage: ci-systemd.sh BIN_DIR STATIC_DIR WORK_DIR}
work=${3:?usage: ci-systemd.sh BIN_DIR STATIC_DIR WORK_DIR}
port=${SMCP_SYSTEMD_PORT:-8643}
mkdir -p "$work"

say() { printf '==> systemd: %s\n' "$*"; }
fail() {
  printf 'FAIL: systemd: %s\n' "$*" >&2
  sudo -n systemctl status smcpd.service --no-pager -l >&2 || true
  sudo -n journalctl -u smcpd.service -n 200 --no-pager >&2 || true
  if [ -d /sys/kernel/security/apparmor ]; then
    sudo -n journalctl -k -n 50 --no-pager -g 'apparmor="DENIED"' >&2 || true
  fi
  exit 1
}

state_root=/var/lib/smcp/state
cfg=/etc/smcp/smcp.toml
share=/srv/smcp/sandbox # the reference server's mount, created by smcpctl install
ci=/var/lib/smcp/ci     # files this script adds: vault passphrase, policies
as_core() { sudo -n -u smcp-core env XDG_RUNTIME_DIR=/run/smcp HOME=/var/lib/smcp/home/smcp-core "$@"; }
probe_bin=/srv/smcp-itest-bin

say "smcpctl install --profile enforced (FR-13.5)"
stage="$work/systemd-bin"
mkdir -p "$stage"
cp "$bin/smcpd" "$bin/smcpctl" "$stage/"
cp "$sbin/smcp-refserver" "$stage/"
install_args=(install --profile enforced --bin-dir "$stage"
  --admin-password-file "$work/admin.pw" --approver-password-file "$work/approver.pw"
  --port "$port" --admin-port "$((port + 1))" --metrics-port "$((port + 2))" --notify off)
# shellcheck disable=SC2024 # the log belongs to the runner
if ! sudo -n "$stage/smcpctl" "${install_args[@]}" > "$work/systemd-install.log" 2>&1; then
  cat "$work/systemd-install.log" >&2
  fail "smcpctl install --profile enforced"
fi
grep -v '^present' "$work/systemd-install.log" || true
grep -Eq '^(created|present|updated) file /etc/systemd/system/smcpd.service' "$work/systemd-install.log" \
  || fail "smcpctl install did not install smcpd.service"
grep -q "^created configuration $cfg" "$work/systemd-install.log" || fail "smcpctl install did not write $cfg"
grep -q '^health: ' "$work/systemd-install.log" || fail "smcpctl install did not report the health of the started Gateway"
if grep -q '^health: fail-closed' "$work/systemd-install.log"; then fail "the installed Gateway is fail-closed"; fi
sudo -n systemctl is-active --quiet smcpd.service || fail "smcpctl install did not start smcpd.service"
[ "$(sudo -n stat -c '%U:%G %a' "$cfg")" = "root:smcp 640" ] || fail "$cfg is $(sudo -n stat -c '%U:%G %a' "$cfg"), not root:smcp 640"
[ "$(sudo -n stat -c '%U' "$state_root/journal")" = smcp-core ] || fail "the state directory is not smcp-core's"
if [ -d /sys/kernel/security/apparmor ]; then
  sudo -n aa-status 2>/dev/null | grep -qx '   smcpd' || sudo -n aa-status 2>/dev/null | grep -q ' smcpd$' || fail "AppArmor profile smcpd is not loaded"
  echo "AppArmor profile smcpd is loaded"
fi

say "a second smcpctl install changes nothing (FR-13.4)"
digests() {
  { sudo -n find "$cfg" /var/lib/smcp/policy "$state_root/keys" "$state_root/tls" /etc/systemd/system/smcpd.service \
    -type f -exec sha256sum {} + 2>/dev/null || true; } | sort
}
digests > "$work/install-digests-1"
[ -s "$work/install-digests-1" ] || fail "no installed files to compare"
# shellcheck disable=SC2024 # the log belongs to the runner
sudo -n "$stage/smcpctl" "${install_args[@]}" > "$work/systemd-install2.log" 2>&1 || { cat "$work/systemd-install2.log" >&2; fail "second smcpctl install"; }
if grep -E '^(created|updated) ' "$work/systemd-install2.log"; then fail "the second smcpctl install changed the host"; fi
grep -q "^present configuration $cfg" "$work/systemd-install2.log" || fail "the second smcpctl install did not report the configuration present"
digests > "$work/install-digests-2"
diff "$work/install-digests-1" "$work/install-digests-2" || fail "the second smcpctl install changed configuration, keys, policy or units"
echo "second run: $(grep -c '^present' "$work/systemd-install2.log") steps present, none created or updated"

say "server identity smcp-srv (CP-46)"
srv_uid=$(id -u smcp-srv)
as_srv() {
  sudo -n -u smcp-srv env XDG_RUNTIME_DIR="/run/user/$srv_uid" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$srv_uid/bus" \
    HOME=/var/lib/smcp/home/smcp-srv "$@"
}
[ "$(id -gn smcp-srv)" = smcp-srv ] || fail "smcp-srv's primary group is $(id -gn smcp-srv), not smcp-srv"
if id -nG smcp-srv | tr ' ' '\n' | grep -qx smcp; then fail "smcp-srv is a member of group smcp (it could read /etc/smcp)"; fi
[ -e /var/lib/systemd/linger/smcp-srv ] || fail "lingering is not enabled for smcp-srv"
sudo -n test -S "/run/user/$srv_uid/bus" || fail "smcp-srv has no user manager bus"
sudo -n test -f /etc/sudoers.d/smcp-srv || fail "no sudoers rule for smcp-srv"
sudo -n test -f /etc/systemd/system/smcpd.service.d/smcp-srv.conf || fail "no smcpd.service drop-in for smcp-srv"
podman_path=$(command -v podman)
sudo -n -u smcp-core env -i PATH=/usr/bin:/bin XDG_RUNTIME_DIR="/run/user/$srv_uid" HOME=/var/lib/smcp/home/smcp-srv \
  sudo -n -E -u smcp-srv -- "$podman_path" --version || fail "smcp-core cannot run Podman as smcp-srv"
if sudo -n -u smcp-core sudo -n -u smcp-srv -- /bin/true 2>/dev/null; then fail "the sudoers rule lets smcp-core run more than Podman as smcp-srv"; fi
if sudo -n -u smcp-srv test -r /etc/smcp; then fail "smcp-srv can read /etc/smcp"; fi
echo "smcp-srv: uid $srv_uid, group $(id -gn smcp-srv), subuid $(grep '^smcp-srv:' /etc/subuid)"

say "adding the sandbox probe, a policy and a secret vault to the installed Gateway"
sudo -n systemctl stop smcpd.service
marker="smcp-systemd-$(date +%s)"
printf '%s\n' "$marker" | sudo -n tee "$share/hello.txt" >/dev/null
sudo -n chmod 0644 "$share/hello.txt"
sudo -n install -d -o smcp-core -g smcp -m 0700 "$ci"
# The sandbox probe (statically linked) as a second server.
sudo -n install -d -o root -g root -m 0755 "$probe_bin"
sudo -n install -o root -g root -m 0755 "$sbin/sandbox-probe" "$probe_bin/sandbox-probe"
head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$work/vault-pass"
sudo -n install -o smcp-core -g smcp -m 0600 "$work/vault-pass" "$ci/vault-pass"
secret_value="s3-secret-$(date +%s)-$RANDOM"
secret_sum="sha256:$(printf '%s' "$secret_value" | sha256sum | cut -d' ' -f1)"
cat > "$work/systemd-policy.json" <<'EOF'
{
  "revision": "ci-systemd-1",
  "framework_profiles": { "dev": { "templates": ["sandbox"], "default_template": "sandbox" } },
  "templates": {
    "sandbox": {
      "description": "Reference server and the sandbox probe",
      "rules": [
        { "id": "ref", "server": "ref", "tools": ["echo", "time_now", "list_files", "read_file"] },
        { "id": "probe", "server": "probe", "tools": ["read_file", "file_sha256", "identity"] }
      ]
    }
  }
}
EOF
sudo -n install -o smcp-core -g smcp -m 0600 "$work/systemd-policy.json" "$ci/policy.json"
cat > "$work/secret-use.json" <<'EOF'
{
  "revision": "ci-1",
  "slots": [ { "server": "probe", "name": "token", "modes": ["S3"], "file_env": "PROBE_TOKEN_FILE" } ],
  "policies": [ { "id": "probe-token", "secret": "probe-token", "server": "probe", "slot": "token", "mode": "S3", "tools": ["*"], "purpose": "ci secret file" } ]
}
EOF
sudo -n install -o smcp-core -g smcp -m 0600 "$work/secret-use.json" "$ci/secret-use.json"

# The installed configuration already selects the enforced profile, the
# Podman sandbox as smcp-srv and the reference server's mount; the policy
# file moves to $ci (the installed policy is already in the Policy Store,
# so the new file is published with smcpctl policy reload).
sudo -n cat "$cfg" | sed -e "s|^file = \"/var/lib/smcp/policy/policy.json\"|file = \"$ci/policy.json\"|" > "$work/smcp.toml"
grep -q "^file = \"$ci/policy.json\"" "$work/smcp.toml" || fail "the installed configuration has no policy file to replace"
grep -q '^mode = "enforced"' "$work/smcp.toml" || fail "the installed configuration does not select the enforced profile"
grep -q '^run_as = "smcp-srv"' "$work/smcp.toml" || fail "the installed configuration does not run servers as smcp-srv"
cat >> "$work/smcp.toml" <<EOF

[[server]]
alias = "probe"
command = "$probe_bin/sandbox-probe"

[[runtime.server]]
alias = "probe"

[secrets]
key_source = "passphrase"
passphrase_file = "$ci/vault-pass"
EOF
sudo -n install -o root -g smcp -m 0640 "$work/smcp.toml" "$cfg"
as_core /usr/local/bin/smcpctl config validate --config "$cfg" || fail "config validate"
as_core /usr/local/bin/smcpctl secrets init --key-source passphrase --passphrase-file "$ci/vault-pass" --config "$cfg" >/dev/null || fail "secrets init"

wait_healthy() {
  local ready=""
  for _ in $(seq 1 120); do
    if ! sudo -n systemctl is-active --quiet smcpd.service; then
      fail "smcpd.service is not active"
    fi
    if as_core /usr/local/bin/smcpctl health --config "$cfg" >"$work/systemd-health.json" 2>&1; then
      ready=1
      break
    fi
    sleep 0.5
  done
  [ -n "$ready" ] || { cat "$work/systemd-health.json" >&2; fail "smcpd.service did not become healthy within 60 s"; }
}

say "runtime doctor as smcp-core (Podman as smcp-srv)"
as_core /usr/local/bin/smcpctl runtime doctor --config "$cfg" || fail "runtime doctor as smcp-core"

say "starting smcpd.service"
sudo -n systemctl daemon-reload
sudo -n systemctl start smcpd.service || fail "systemctl start smcpd.service"
wait_healthy
as_core /usr/local/bin/smcpctl policy reload --config "$cfg" || fail "policy reload"

say "an S3 secret for the probe (userns = \"auto\", run as smcp-srv)"
printf '%s' "$secret_value" | as_core /usr/local/bin/smcpctl secrets set probe-token --value-file - --config "$cfg" >/dev/null || fail "secrets set"
printf 'use_policy_file = "%s"\n' "$ci/secret-use.json" >> "$work/smcp.toml"
sudo -n install -o root -g smcp -m 0640 "$work/smcp.toml" "$cfg"
as_core /usr/local/bin/smcpctl config validate --config "$cfg" || fail "config validate with the Secret Use Policy"
sudo -n systemctl restart smcpd.service || fail "systemctl restart smcpd.service"
wait_healthy
head -n 1 "$work/systemd-health.json"
grep -q '"profile": *"enforced"' "$work/systemd-health.json" || fail "health does not report the enforced profile"
grep -q '"launcher": *"podman"' "$work/systemd-health.json" || fail "health does not report the podman launcher"

mainpid=$(systemctl show -p MainPID --value smcpd.service)
echo "smcpd.service main PID $mainpid, user $(ps -o user= -p "$mainpid")"
[ "$(ps -o user= -p "$mainpid" | tr -d ' ')" = smcp-core ] || fail "smcpd does not run as smcp-core"
if [ -d /sys/kernel/security/apparmor ]; then
  label=$(sudo -n cat "/proc/$mainpid/attr/current")
  echo "smcpd AppArmor label: $label"
  [ "$label" = "smcpd (enforce)" ] || fail "smcpd is not confined by the smcpd AppArmor profile (label: $label)"
fi

say "a tool call through the sandbox"
# shellcheck disable=SC2024 # the copy belongs to the runner, only the read needs root
sudo -n cat "$state_root/tls/ca.crt" > "$work/systemd-ca.crt"
SMCP_SIGNIN_PASSWORD=$(cat "$work/approver.pw")
export SMCP_SIGNIN_PASSWORD
"$bin/itest-client" -url "https://127.0.0.1:$port" -ca "$work/systemd-ca.crt" \
  -call ref_read_file -args '{"path":"hello.txt"}' -expect "$marker" || fail "tool call through smcpd.service"
as_srv podman ps --filter label=smcp.managed=1 --format '{{.Names}} {{.Status}}' | tee "$work/systemd-containers.txt"
grep -q '^smcp-ref-' "$work/systemd-containers.txt" || fail "the reference server does not run in a Podman container of smcp-srv"
grep -q '^smcp-probe-' "$work/systemd-containers.txt" || fail "the probe does not run in a Podman container of smcp-srv"
if [ -n "$(as_core podman ps -a -q --filter label=smcp.managed=1 2>/dev/null)" ]; then
  fail "server containers run under smcp-core's Podman"
fi
as_core /usr/local/bin/smcpctl runtime instances --config "$cfg" | grep -q '"alias": *"ref"' || fail "runtime instances lacks ref"

say "smcpd runs as smcp-core (SR-4.1-1)"
core_uid=$(id -u smcp-core)
smcpd_pid=$(systemctl show smcpd.service -p MainPID --value)
smcpd_uid=$(ps -o uid= -p "$smcpd_pid" | tr -d ' ')
ps -o user=,uid=,pid=,comm= -p "$smcpd_pid"
[ "$smcpd_uid" = "$core_uid" ] || fail "smcpd (PID $smcpd_pid) runs as UID $smcpd_uid, not smcp-core ($core_uid)"
[ "$smcpd_uid" != 0 ] && [ "$smcpd_uid" != "$(id -u)" ] || fail "smcpd runs as root or as the operator's account"

say "server processes run under smcp-srv's subordinate UIDs, not smcp-core"
read -r srv_start srv_count < <(awk -F: '$1 == "smcp-srv" { print $2, $3; exit }' /etc/subuid)
while read -r name _ <&3; do
  cpid=$(as_srv podman inspect --format '{{.State.Pid}}' "$name")
  cuid=$(ps -o uid= -p "$cpid" | tr -d ' ')
  echo "$name: main PID $cpid, host UID $cuid"
  [ "$cuid" != "$core_uid" ] || fail "$name runs as smcp-core"
  [ "$cuid" -ge "$srv_start" ] && [ "$cuid" -lt "$((srv_start + srv_count))" ] || fail "$name runs as UID $cuid, outside smcp-srv's range $srv_start+$srv_count"
  if [ -d /sys/kernel/security/apparmor ]; then
    clabel=$(sudo -n cat "/proc/$cpid/attr/current")
    echo "$name: AppArmor label $clabel"
    [ "$clabel" = "smcp-server (enforce)" ] || fail "$name is not confined by the smcp-server AppArmor profile (label: $clabel)"
  fi
done 3< "$work/systemd-containers.txt"
conmon_users=$(ps -o user= -C conmon | sort -u | tr '\n' ' ')
echo "conmon processes run as: $conmon_users"
case " $conmon_users" in *" smcp-core "*) fail "a container monitor runs as smcp-core" ;; esac

probe_call() { # tool, args, expected substring
  "$bin/itest-client" -url "https://127.0.0.1:$port" -ca "$work/systemd-ca.crt" -call "$1" -args "$2" -expect "$3" \
    || fail "probe_$1 $2 (expected \"$3\")"
}
say "the probe reads its S3 secret file as a subordinate UID of smcp-srv"
probe_call probe_file_sha256 '{"path":"/smcp/secrets/token"}' "$secret_sum"
sudo -n find /run/smcp -maxdepth 3 -name 'probe-*' -exec getfacl -p {} + 2>/dev/null || true
if [ -d /sys/kernel/security/apparmor ]; then
  say "the AppArmor profile smcp-server denies a read the container allows"
  probe_call probe_read_file '{"path":"/proc/self/environ"}' "permission denied"
  probe_call probe_read_file '{"path":"/proc/self/status"}' "NoNewPrivs:"
  sudo -n journalctl -k --no-pager -g 'apparmor="DENIED".*profile="smcp-server"' | tail -n 3 || true
fi

say "unit hardening in effect"
systemctl show smcpd.service -p User -p ProtectSystem -p ProtectHome -p PrivateTmp -p NoNewPrivileges \
  -p RestrictSUIDSGID -p ProtectKernelTunables -p ProtectControlGroups -p AppArmorProfile -p Delegate --no-pager
if command -v systemd-analyze >/dev/null 2>&1; then
  sudo -n systemd-analyze security smcpd.service --no-pager 2>/dev/null | tail -n 1 || true
fi

say "stopping smcpd.service"
sudo -n systemctl stop smcpd.service
if sudo -n systemctl is-active --quiet smcpd.service; then fail "smcpd.service still active after stop"; fi
as_core /usr/local/bin/smcpctl journal verify --config "$cfg" || fail "journal verify after stop"
sudo -n grep -rqs '"instance_launched"' "$state_root/journal" || fail "no instance_launched evidence in the journal"
sudo -n systemctl disable --quiet smcpd.service

# SR-2.13-3 while the installation exists: the vault (one secret, stored
# above) and its passphrase file are read as every CP-46 identity other
# than smcp-core, the identity smcpd and its Secret Broker run as.
say "the vault is readable by the Secret Broker's identity only (SR-2.13-3)"
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
vault_env=(SMCP_VAULT_IT_DIR="$state_root/vault" SMCP_VAULT_IT_FILES="$ci/vault-pass")
if [ -n "${SMCP_ITEST_RESULTS:-}" ]; then
  (cd "$repo" && env "${vault_env[@]}" go test -json -count=1 -run '^TestIntegrationVaultIsolation$' ./internal/secrets/) \
    | tee -a "$SMCP_ITEST_RESULTS" | jq -rj 'select(.Action == "output") | .Output' || fail "vault isolation"
else
  (cd "$repo" && env "${vault_env[@]}" go test -v -count=1 -run '^TestIntegrationVaultIsolation$' ./internal/secrets/) || fail "vault isolation"
fi

# Uninstall and purge on this host (FR-13.11 Enforced half, FR-13.12),
# as the Go test cmd/smcpctl.TestEnforcedUninstallAndPurgeOnHost, whose
# events go to SMCP_ITEST_RESULTS for the status job. It removes the
# installation, so it comes last.
say "uninstall and purge of the Enforced installation (FR-13.11, FR-13.12)"
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
if [ -n "${SMCP_ITEST_RESULTS:-}" ]; then
  (cd "$repo" && SMCP_ENFORCED_HOST_TEST=1 go test -json -count=1 -run '^TestEnforcedUninstallAndPurgeOnHost$' ./cmd/smcpctl/) \
    | tee -a "$SMCP_ITEST_RESULTS" | jq -rj 'select(.Action == "output") | .Output' || fail "uninstall and purge"
else
  (cd "$repo" && SMCP_ENFORCED_HOST_TEST=1 go test -v -count=1 -run '^TestEnforcedUninstallAndPurgeOnHost$' ./cmd/smcpctl/) || fail "uninstall and purge"
fi
say "passed"
