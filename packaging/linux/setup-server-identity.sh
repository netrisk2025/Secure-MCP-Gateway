#!/usr/bin/env bash
# Prepare the CP-46 server identity smcp-srv so that smcpd (smcp-core) can
# run the server containers under it (runtime.run_as = "smcp-srv").
#
# Called by install-enforced.sh after the identities, subordinate ID ranges
# and CP-46 directories exist; runs as root. Like the installer, every step
# prints "present", "created" or "updated", and a second run prints only
# "present" lines.
#
#   setup-server-identity.sh PODMAN_PATH
#
# What it sets up, and why:
#   - smcp-srv in its own group smcp-srv (not smcp, so it cannot read
#     /etc/smcp) with the home /var/lib/smcp/home/smcp-srv for its rootless
#     Podman storage;
#   - lingering for smcp-srv: systemd starts user@<uid>.service at boot,
#     which owns /run/user/<uid> (Podman's runtime directory) and the user
#     bus through which Podman creates the containers' cgroups in a subtree
#     delegated to smcp-srv;
#   - /var/lib/smcp/srv (smcp-core:smcp-srv 0751), runtime.shared_dir: the
#     Gateway-built root directory of image-less servers, which smcp-srv
#     must read and the state directory does not allow;
#   - /etc/sudoers.d/smcp-srv: smcp-core may run Podman, and only Podman,
#     as smcp-srv without a password, keeping the environment (SETENV, for
#     sudo -E: Podman reads the instance values by name);
#   - /etc/systemd/system/smcpd.service.d/smcp-srv.conf: smcpd starts after
#     user@<uid>.service and may write /run/user/<uid> despite
#     ProtectSystem=strict.
set -euo pipefail

podman=${1:?usage: setup-server-identity.sh PODMAN_PATH}
srv=smcp-srv
home=/var/lib/smcp/home/$srv
shared=/var/lib/smcp/srv

say() { printf '%s %s\n' "$1" "$2"; }

uid=$(id -u "$srv")
if [ "$(id -gn "$srv")" = "$srv" ]; then
  say present "primary group $srv of $srv"
else
  usermod -g "$srv" "$srv"
  say updated "primary group $srv of $srv"
fi
if [ "$(getent passwd "$srv" | cut -d: -f6)" = "$home" ]; then
  say present "home $home of $srv"
else
  usermod -d "$home" "$srv"
  say updated "home $home of $srv"
fi

ensure_dir() { # path owner group mode
  local p=$1 o=$2 g=$3 m=$4
  if [ -d "$p" ]; then
    if [ "$(stat -c '%U:%G %a' "$p")" = "$o:$g ${m#0}" ]; then
      say present "directory $p"
    else
      chown "$o:$g" "$p"
      chmod "$m" "$p"
      say updated "directory $p ($o:$g $m)"
    fi
  else
    install -d -o "$o" -g "$g" -m "$m" "$p"
    say created "directory $p"
  fi
}
# 0711: rootless Podman sets the execute bit for others on the home and on
# ~/.local so that subordinate UIDs can reach its storage; a 0700 home would
# be reported "updated" by every later run and reset under Podman.
ensure_dir "$home" "$srv" "$srv" 0711
ensure_dir "$shared" smcp-core "$srv" 0751

if [ -e "/var/lib/systemd/linger/$srv" ]; then
  say present "lingering for $srv"
else
  loginctl enable-linger "$srv"
  say created "lingering for $srv"
fi
for _ in $(seq 1 50); do
  [ -S "/run/user/$uid/bus" ] && break
  sleep 0.2
done
[ -S "/run/user/$uid/bus" ] || echo "setup-server-identity: warning: /run/user/$uid/bus did not appear; check systemctl status user@$uid.service" >&2

write_if_changed() { # destination mode content
  local tmp
  tmp=$(mktemp)
  printf '%s\n' "$3" > "$tmp"
  if [ -f "$1" ] && cmp -s "$tmp" "$1"; then
    say present "file $1"
    rm -f "$tmp"
    return 1
  fi
  local verb=created
  [ -f "$1" ] && verb=updated
  install -o root -g root -m "$2" "$tmp" "$1"
  rm -f "$tmp"
  say "$verb" "file $1"
  return 0
}

sudoers="# Installed by packaging/linux/setup-server-identity.sh.
# smcpd (smcp-core) runs Podman as the server identity smcp-srv (CP-46,
# runtime.run_as). SETENV allows sudo -E, which passes HOME,
# XDG_RUNTIME_DIR and the instance values that Podman reads by name.
smcp-core ALL=($srv) NOPASSWD:SETENV: $podman"
tmp=$(mktemp)
printf '%s\n' "$sudoers" > "$tmp"
visudo -cqf "$tmp" || { rm -f "$tmp"; echo "setup-server-identity: the sudoers rule does not parse" >&2; exit 1; }
rm -f "$tmp"
install -d -m 0750 /etc/sudoers.d
write_if_changed /etc/sudoers.d/smcp-srv 0440 "$sudoers" || true

dropin="# Installed by packaging/linux/setup-server-identity.sh: smcpd runs the
# server containers as smcp-srv (runtime.run_as), whose rootless Podman
# needs its user manager and its runtime directory.
[Unit]
Wants=user@$uid.service
After=user@$uid.service

[Service]
ReadWritePaths=-/run/user/$uid"
install -d -m 0755 /etc/systemd/system/smcpd.service.d
if write_if_changed /etc/systemd/system/smcpd.service.d/smcp-srv.conf 0644 "$dropin"; then
  systemctl daemon-reload
  say updated "systemd unit files (daemon-reload)"
fi
