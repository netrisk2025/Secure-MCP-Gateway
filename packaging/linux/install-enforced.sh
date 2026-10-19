#!/usr/bin/env bash
# Prepare a Linux host for the Secure MCP Gateway enforced profile.
#
# Run as root. It first checks every prerequisite and changes nothing if one
# is missing. Then it creates, when absent, the CP-46 service identities and
# their subordinate UID/GID ranges, the CP-46 directories with their owners
# and modes, the nftables table `inet smcp`, the AppArmor profiles of smcpd
# and of server processes (when AppArmor is enabled), the systemd units and
# what smcpd needs to run servers as smcp-srv (setup-server-identity.sh:
# lingering, sudoers rule, shared directory, unit drop-in). Every step
# prints "present", "created" or "updated"; a second run prints only
# "present" lines and changes nothing. Keys, configuration, policy and the
# journal are never touched.
#
# Usage: install-enforced.sh [--check] [--bin-dir DIR] [--start] [--no-start]
#   --check        verify the prerequisites only
#   --bin-dir DIR  also install smcpd and smcpctl from DIR into /usr/local/bin
#   --start        start smcp-nftables and smcpd (needs /etc/smcp/smcp.toml)
#   --no-start     do not start anything (default)
#
# See docs/sandbox.md.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
check_only=0 start=0 bin_dir=""
while [ $# -gt 0 ]; do
  case "$1" in
    --check) check_only=1 ;;
    --start) start=1 ;;
    --no-start) start=0 ;;
    --bin-dir) bin_dir=${2:?--bin-dir needs a directory}; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "install-enforced: unknown option $1" >&2; exit 2 ;;
  esac
  shift
done

# Identities (CP-46). smcp-core runs smcpd; smcp-srv, in its own group,
# runs the server containers in its rootless Podman (runtime.run_as).
group=smcp
users=(smcp-core smcp-evidence smcp-keys smcp-vault smcp-data smcp-console smcp-srv)
subid_users=(smcp-core smcp-srv)
subid_size=65536

say() { printf '%s %s\n' "$1" "$2"; }

# --- Prerequisites (FR-13.5: verify before changing the host) --------------
missing=()
need() { command -v "$1" >/dev/null 2>&1 || missing+=("$2"); }
[ "$(uname -s)" = Linux ] || missing+=("Linux")
case "$(uname -m)" in x86_64|aarch64|arm64) ;; *) missing+=("x86_64 or arm64 (found $(uname -m))") ;; esac
[ "$(id -u)" = 0 ] || missing+=("root (run with sudo)")
kver=$(uname -r)
kmaj=${kver%%.*}; krest=${kver#*.}; kmin=${krest%%[!0-9]*}
if [ "${kmaj:-0}" -lt 6 ] || { [ "$kmaj" -eq 6 ] && [ "${kmin:-0}" -lt 8 ]; }; then missing+=("kernel 6.8 or later (found $kver)"); fi
[ -f /sys/fs/cgroup/cgroup.controllers ] || missing+=("cgroup v2")
if [ -r /proc/sys/user/max_user_namespaces ] && [ "$(cat /proc/sys/user/max_user_namespaces)" = 0 ]; then missing+=("user namespaces (user.max_user_namespaces=0)"); fi
need podman "podman"
need crun "crun"
need nft "nftables (nft)"
need newuidmap "newuidmap (uidmap package)"
need newgidmap "newgidmap (uidmap package)"
need useradd "useradd"
need groupadd "groupadd"
need usermod "usermod"
need systemctl "systemd (systemctl)"
need loginctl "loginctl (systemd-logind)"
need sudo "sudo"
need visudo "visudo (sudo package)"
[ -d /run/systemd/system ] || missing+=("systemd as the running service manager")
if [ ! -d /sys/kernel/security/apparmor ] && [ ! -e /sys/fs/selinux/enforce ]; then missing+=("AppArmor or SELinux"); fi
if [ -d /sys/kernel/security/apparmor ] && ! command -v apparmor_parser >/dev/null 2>&1 && [ ! -x /sbin/apparmor_parser ]; then
  missing+=("apparmor_parser (apparmor package)")
fi
if [ "${#missing[@]}" -gt 0 ]; then
  echo "install-enforced: prerequisites missing; nothing was changed:" >&2
  printf '  - %s\n' "${missing[@]}" >&2
  exit 2
fi
if [ "$check_only" = 1 ]; then
  echo "install-enforced: all prerequisites present"
  exit 0
fi

# --- Service identities -----------------------------------------------------
for g in "$group" smcp-srv; do
  if getent group "$g" >/dev/null; then say present "group $g"; else groupadd --system "$g"; say created "group $g"; fi
done
for u in "${users[@]}"; do
  if id -u "$u" >/dev/null 2>&1; then
    say present "user $u"
  else
    home=/nonexistent ugroup=$group
    [ "$u" = smcp-core ] && home=/var/lib/smcp/home/smcp-core
    [ "$u" = smcp-srv ] && home=/var/lib/smcp/home/smcp-srv ugroup=smcp-srv
    useradd --system --gid "$ugroup" --home-dir "$home" --no-create-home --shell /usr/sbin/nologin "$u"
    say created "user $u"
  fi
done

# Subordinate ID ranges: one non-overlapping block of $subid_size per user.
next_free() {
  local max=100000 f start count
  for f in /etc/subuid /etc/subgid; do
    [ -f "$f" ] || continue
    while IFS=: read -r _ start count; do
      [[ "$start" =~ ^[0-9]+$ && "$count" =~ ^[0-9]+$ ]] || continue
      [ $((start + count)) -gt "$max" ] && max=$((start + count))
    done < "$f"
  done
  echo "$max"
}
has_range() { # file user
  [ -f "$1" ] || return 1
  awk -F: -v u="$2" -v n="$subid_size" '$1 == u && $3 >= n { ok = 1 } END { exit ok ? 0 : 1 }' "$1"
}
for u in "${subid_users[@]}"; do
  if has_range /etc/subuid "$u" && has_range /etc/subgid "$u"; then
    say present "subordinate IDs for $u"
  else
    start=$(next_free)
    end=$((start + subid_size - 1))
    has_range /etc/subuid "$u" || usermod --add-subuids "$start-$end" "$u"
    has_range /etc/subgid "$u" || usermod --add-subgids "$start-$end" "$u"
    say created "subordinate IDs $start-$end for $u"
  fi
done

# --- Directories (CP-46) -----------------------------------------------------
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
ensure_dir /etc/smcp root "$group" 0750
ensure_dir /var/lib/smcp root "$group" 0755
for d in policy registry artifacts; do ensure_dir "/var/lib/smcp/$d" smcp-core "$group" 0700; done
ensure_dir /var/lib/smcp/journal smcp-evidence "$group" 0700
ensure_dir /var/lib/smcp/keys smcp-keys "$group" 0700
ensure_dir /var/lib/smcp/vault smcp-vault "$group" 0700
ensure_dir /var/lib/smcp/exports smcp-core "$group" 0750
# The Gateway's state directory (state.dir) and smcp-core's home, which
# holds rootless Podman's container storage.
ensure_dir /var/lib/smcp/state smcp-core "$group" 0700
# Parent of the service homes: smcp-srv must reach its own home below it.
ensure_dir /var/lib/smcp/home root root 0755
ensure_dir /var/lib/smcp/home/smcp-core smcp-core "$group" 0700
ensure_dir /var/log/smcp smcp-core "$group" 0750

# --- Server identity (runtime.run_as = "smcp-srv") ---------------------------
"$here/setup-server-identity.sh" "$(command -v podman)"

# --- Files ----------------------------------------------------------------
changed_units=0 changed_nft=0 changed_aa=0
ensure_file() { # source destination mode
  if [ -f "$2" ] && cmp -s "$1" "$2"; then
    say present "file $2"
  else
    local verb=created
    [ -f "$2" ] && verb=updated
    install -o root -g root -m "$3" "$1" "$2"
    say "$verb" "file $2"
    case "$2" in *.service) changed_units=1 ;; *.nft) changed_nft=1 ;; /etc/apparmor.d/*) changed_aa=1 ;; esac
  fi
}
ensure_file "$here/nftables/smcp.nft" /etc/smcp/smcp.nft 0644
ensure_file "$here/systemd/smcp-nftables.service" /etc/systemd/system/smcp-nftables.service 0644
ensure_file "$here/systemd/smcpd.service" /etc/systemd/system/smcpd.service 0644
if [ -n "$bin_dir" ]; then
  for b in smcpd smcpctl smcp-refserver; do
    [ -f "$bin_dir/$b" ] && ensure_file "$bin_dir/$b" "/usr/local/bin/$b" 0755
  done
fi

# --- nftables table ---------------------------------------------------------
nft -c -f /etc/smcp/smcp.nft
if ! nft list table inet smcp >/dev/null 2>&1; then
  nft -f /etc/smcp/smcp.nft
  say created "nftables table inet smcp"
elif [ "$changed_nft" = 1 ]; then
  nft -f /etc/smcp/smcp.nft
  say updated "nftables table inet smcp"
else
  say present "nftables table inet smcp"
fi

# --- AppArmor profiles (FR-13.5) ---------------------------------------------
# smcpd.service applies smcpd with AppArmorProfile=-smcpd; smcp-server
# attaches by path to server executables at /smcp/bin inside containers.
# On an SELinux host the profiles are skipped; smcpd runs in the unit's
# default domain.
for prof in smcpd smcp-server; do
  if [ -d /sys/kernel/security/apparmor ]; then
    parser=$(command -v apparmor_parser || echo /sbin/apparmor_parser)
    changed_aa=0
    ensure_file "$here/apparmor/$prof" "/etc/apparmor.d/$prof" 0644
    if ! grep -qx "$prof (enforce)" /sys/kernel/security/apparmor/profiles; then
      "$parser" -r -W "/etc/apparmor.d/$prof"
      say created "AppArmor profile $prof (enforce)"
    elif [ "$changed_aa" = 1 ]; then
      "$parser" -r -W "/etc/apparmor.d/$prof"
      say updated "AppArmor profile $prof (enforce)"
    else
      say present "AppArmor profile $prof (enforce)"
    fi
  else
    say skipped "AppArmor profile $prof (AppArmor is not enabled)"
  fi
done

# --- systemd ------------------------------------------------------------------
if [ "$changed_units" = 1 ]; then
  systemctl daemon-reload
  say updated "systemd unit files (daemon-reload)"
fi
for unit in smcp-nftables.service smcpd.service; do
  if systemctl is-enabled --quiet "$unit" 2>/dev/null; then
    say present "enabled $unit"
  else
    systemctl enable --quiet "$unit"
    say created "enabled $unit"
  fi
done
if [ "$start" = 1 ]; then
  [ -f /etc/smcp/smcp.toml ] || { echo "install-enforced: /etc/smcp/smcp.toml is missing; not starting smcpd" >&2; exit 1; }
  systemctl start smcp-nftables.service smcpd.service
  echo "started smcp-nftables.service smcpd.service"
fi

cat <<'EOF'

Next steps (once):
  1. Bootstrap state as smcp-core:
       sudo -u smcp-core smcpctl bootstrap --dir /var/lib/smcp/state
     then move the written smcp.toml to /etc/smcp/smcp.toml (root:smcp 0640)
     and set in it:
       [state]   dir = "/var/lib/smcp/state"
       [profile] mode = "enforced"
       [runtime] sandbox = "podman"
                 run_as = "smcp-srv"
                 shared_dir = "/var/lib/smcp/srv"
  2. Check the host as smcp-core:
       sudo -u smcp-core XDG_RUNTIME_DIR=/run/smcp smcpctl runtime doctor
  3. Start:  systemctl start smcpd
EOF
