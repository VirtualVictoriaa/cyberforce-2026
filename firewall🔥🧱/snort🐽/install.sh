#!/usr/bin/env bash
set -euo pipefail

IFACE=""
RULES_SRC=""
HOME_NET="10.0.47.128/27"
EXTERNAL_NET="any"

SNORT_ETC="/etc/snort"
RULES_DIR="$SNORT_ETC/rules"
CUSTOM_RULES_DIR="$RULES_DIR/custom"
MERGED_RULES="$RULES_DIR/local.rules"
COMMUNITY_RULES_DIR="/usr/local/etc/rules"
COMMUNITY_RULES_URL="https://www.snort.org/downloads/community/snort3-community-rules.tar.gz"
CONF_FILE="$SNORT_ETC/snort.lua"
LOG_DIR="/var/log/snort"
STATE_DIR="/var/lib/snort"

LOCAL_CONF="/etc/conf.d/snort-detect"
LOCAL_START="/etc/local.d/snort.start"
LOCAL_STOP="/etc/local.d/snort.stop"
START_LOG="$LOG_DIR/startup.log"

usage() {
  cat <<EOF
Usage:
  $0 -i <iface> -r <rules_dir> [-H <home_net>] [-E <external_net>]

Options:
  -i  Interface to sniff on, e.g. eth0
  -r  Directory containing *.rules files
  -H  HOME_NET in CIDR form (default: $HOME_NET)
  -E  EXTERNAL_NET (default: $EXTERNAL_NET)

Examples:
  $0 -i eth0 -r /root/snort3-community-rules -H 10.0.0.0/24 -E any
  $0 -i eth0 -r /root/snort3-community-rules -H 10.0.47.128/27 -E any
EOF
}

while getopts "i:r:H:E:h" opt; do
  case "$opt" in
    i) IFACE="$OPTARG" ;;
    r) RULES_SRC="$OPTARG" ;;
    H) HOME_NET="$OPTARG" ;;
    E) EXTERNAL_NET="$OPTARG" ;;
    h) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
  echo "[!] run as root" >&2
  exit 1
fi

# Validate required arguments
if [[ -z "$IFACE" || -z "$RULES_SRC" ]]; then
  usage
  exit 1
fi

# Validate rules directory and interface
if [[ ! -d "$RULES_SRC" && "$RULES_SRC" != "$COMMUNITY_RULES_DIR" ]]; then
  echo "[!] rules dir not found: $RULES_SRC" >&2
  exit 1
fi

# Validate interface exists
if ! ip link show "$IFACE" >/dev/null 2>&1; then
  echo "[!] interface not found: $IFACE" >&2
  exit 1
fi

# Normalize single IP to /32
if [[ "$HOME_NET" != */* ]]; then
  echo "[*] HOME_NET has no CIDR mask; treating it as /27"
  HOME_NET="${HOME_NET}/27"
fi

# Find snort_defaults.lua in common locations
find_snort_defaults() {
  local f
  for f in \
    /usr/share/snort/snort_defaults.lua \
    /etc/snort/snort_defaults.lua \
    /usr/share/snort/lua/snort_defaults.lua
  do
    [[ -r "$f" ]] && { echo "$f"; return 0; }
  done
  return 1
}

# Install Snort 3 and dependencies
echo "[+] updating apk indexes"
# Try package types
try apk update -y || true
try pacman -Sy|| true
try apt-get update -y || true
try dnf update -y || true
try yum update -y || true
try zypper update -y || true

echo "[+] installing snort"
try apk add --no-cache snort libpcap curl || true
try pacman -S --noconfirm snort libpcap curl || true
try apt-get install -y snort libpcap0.8 curl || true
try dnf install -y snort libpcap curl || true
try yum install -y snort libpcap curl || true
try zypper install -y snort libpcap1 curl || true

# Download and install Snort 3 community rules
echo "[+] downloading Snort 3 community rules"
RULES_TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$RULES_TMP_DIR"' EXIT
curl -fL "$COMMUNITY_RULES_URL" -o "$RULES_TMP_DIR/community-rules.tar.gz"
tar -xzf "$RULES_TMP_DIR/community-rules.tar.gz" -C "$RULES_TMP_DIR"
COMMUNITY_ARCHIVE_DIR="$RULES_TMP_DIR/snort3-community-rules"
if [[ ! -d "$COMMUNITY_ARCHIVE_DIR" ]]; then
  echo "[!] expected community rules directory not found in archive" >&2
  exit 1
fi
mkdir -p "$COMMUNITY_RULES_DIR"
cp -a "$COMMUNITY_ARCHIVE_DIR/." "$COMMUNITY_RULES_DIR/"

# Verify snort binary and defaults file
SNORT_BIN="$(command -v snort || true)"
if [[ -z "$SNORT_BIN" ]]; then
  echo "[!] snort binary not found after install" >&2
  exit 1
fi

# Find snort_defaults.lua
DEFAULTS_FILE="$(find_snort_defaults || true)"
if [[ -z "$DEFAULTS_FILE" ]]; then
  echo "[!] could not find snort_defaults.lua" >&2
  exit 1
fi

# Print configuration summary
echo "[+] snort binary: $SNORT_BIN"
echo "[+] defaults file: $DEFAULTS_FILE"

# Create snort user/group and directories
echo "[+] creating snort user/group if needed"
addgroup -S snort 2>/dev/null || true
if ! id snort >/dev/null 2>&1; then
  adduser -S -D -H -h "$STATE_DIR" -s /sbin/nologin -G snort snort
fi

# Create directories for Snort configuration, rules, logs, and state
echo "[+] creating directories"
mkdir -p "$SNORT_ETC" "$RULES_DIR" "$CUSTOM_RULES_DIR" "$LOG_DIR" "$STATE_DIR" /etc/local.d /etc/conf.d
chown -R snort:snort "$LOG_DIR" "$STATE_DIR"
chmod 750 "$LOG_DIR" "$STATE_DIR"

# Backup existing configuration and rules if they exist
STAMP="$(date +%F-%H%M%S)"
[[ -f "$CONF_FILE" ]] && cp -p "$CONF_FILE" "$CONF_FILE.bak.$STAMP"
[[ -f "$MERGED_RULES" ]] && cp -p "$MERGED_RULES" "$MERGED_RULES.bak.$STAMP"

# Create merged rules file and copy custom rules
echo "[+] importing rules"
: > "$MERGED_RULES"

# Use nullglob to avoid literal *.rules if no files match
shopt -s nullglob
RULE_SOURCES=( "$RULES_SRC" )
if [[ "$RULES_SRC" != "$COMMUNITY_RULES_DIR" ]]; then
  RULE_SOURCES+=( "$COMMUNITY_RULES_DIR" )
fi
RULE_FILES=()
for source in "${RULE_SOURCES[@]}"; do
  RULE_FILES+=( "$source"/*.rules )
done
shopt -u nullglob

# Validate that we found some .rules files
if [[ ${#RULE_FILES[@]} -eq 0 ]]; then
  echo "[!] no .rules files found in $RULES_SRC" >&2
  exit 1
fi

# Copy each .rules file to the custom rules directory and append its contents to the merged rules file
for f in "${RULE_FILES[@]}"; do
  base="$(basename "$f")"
  cp -f "$f" "$CUSTOM_RULES_DIR/$base"
  {
    echo "# ===== BEGIN $base ====="
    cat "$f"
    echo
    echo "# ===== END $base ====="
    echo
  } >> "$MERGED_RULES"
done

# Set ownership and permissions for the merged rules file
chown root:snort "$MERGED_RULES"
chmod 640 "$MERGED_RULES"

# Write the Snort 3 configuration file
echo "[+] writing Snort 3 config"
cat > "$CONF_FILE" <<EOF
-- autogenerated by install-snort3-alpine.sh

include '$DEFAULTS_FILE'

HOME_NET = '$HOME_NET'
EXTERNAL_NET = '$EXTERNAL_NET'

local custom_nets =
{
    HOME_NET       = HOME_NET,
    EXTERNAL_NET   = EXTERNAL_NET,
    DNS_SERVERS    = HOME_NET,
    SMTP_SERVERS   = HOME_NET,
    SQL_SERVERS    = HOME_NET,
    HTTP_SERVERS   = HOME_NET,
    TELNET_SERVERS = HOME_NET,
    SSH_SERVERS    = HOME_NET,
    FTP_SERVERS    = HOME_NET,
    SIP_SERVERS    = HOME_NET,
    AIM_SERVERS    = HOME_NET
}

local custom_ports = {}
if default_variables and default_variables.ports then
    custom_ports = default_variables.ports
end

ips =
{
    mode = tap,
    variables =
    {
        nets = custom_nets,
        ports = custom_ports
    },
    rules = [[
        include $MERGED_RULES
    ]]
}

alert_fast =
{
    file = true
}
EOF

# Set ownership and permissions for the configuration file
chown root:snort "$CONF_FILE"
chmod 640 "$CONF_FILE"

# Test the Snort configuration
echo "[+] testing config"
"$SNORT_BIN" -T -i "$IFACE" -c "$CONF_FILE" -l "$LOG_DIR" -k none

# Write the local.d runtime configuration
echo "[+] writing local.d runtime config"
cat > "$LOCAL_CONF" <<EOF
SNORT_BIN="$SNORT_BIN"
SNORT_IFACE="$IFACE"
SNORT_CONF="$CONF_FILE"
SNORT_LOG_DIR="$LOG_DIR"
SNORT_START_LOG="$START_LOG"

# detection mode only:
# no -Q
# no NFQUEUE
# no inline
SNORT_ARGS="-A alert_fast -k none"
EOF

echo "[+] writing startup script"
cat > "$LOCAL_START" <<'EOF'
#!/bin/sh
set -eu
. /etc/conf.d/snort-detect

mkdir -p "$SNORT_LOG_DIR"
: > "$SNORT_START_LOG"
chown snort:snort "$SNORT_LOG_DIR"

# Stop stale instances first
pkill -TERM -f "snort.*-c $SNORT_CONF" 2>/dev/null || true
sleep 1

"$SNORT_BIN" \
  -D \
  -u snort \
  -g snort \
  -i "$SNORT_IFACE" \
  -c "$SNORT_CONF" \
  -l "$SNORT_LOG_DIR" \
  $SNORT_ARGS \
  >>"$SNORT_START_LOG" 2>&1 || true

# Give daemon time to settle
for _ in 1 2 3 4 5; do
  if pgrep -f "snort.*-c $SNORT_CONF" >/dev/null 2>&1; then
    echo "[+] snort started"
    exit 0
  fi
  sleep 1
done

echo "[!] snort failed to start"
echo "[!] startup log: $SNORT_START_LOG"
tail -n 50 "$SNORT_START_LOG" 2>/dev/null || true
exit 1
EOF

echo "[+] writing stop script"
cat > "$LOCAL_STOP" <<'EOF'
#!/bin/sh
set -eu
. /etc/conf.d/snort-detect
pkill -TERM -f "snort.*-c $SNORT_CONF" 2>/dev/null || true
EOF

chmod +x "$LOCAL_START" "$LOCAL_STOP"

echo "[+] enabling local service at boot"
rc-update add local default >/dev/null 2>&1 || true

echo "[+] starting snort"
"$LOCAL_START"

echo
echo "[+] done"
echo "[+] config: $CONF_FILE"
echo "[+] rules:  $MERGED_RULES"
echo "[+] logs:   $LOG_DIR"
echo "[+] start log: $START_LOG"
echo "[+] check alerts with: tail -f $LOG_DIR/*"
