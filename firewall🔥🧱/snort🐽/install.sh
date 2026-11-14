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
SNORT_VERSION="3.13.2.0"
DAQ_VERSION="3.0.29"
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
    /usr/local/etc/snort/snort_defaults.lua \
    /usr/share/snort/snort_defaults.lua \
    /etc/snort/snort_defaults.lua \
    /usr/share/snort/lua/snort_defaults.lua
  do
    [[ -r "$f" ]] && { echo "$f"; return 0; }
  done
  return 1
}

# Detect supported distributions and install Snort build dependencies.
if [[ ! -r /etc/os-release ]]; then
  echo "[!] cannot identify this operating system (/etc/os-release missing)" >&2
  exit 1
fi
. /etc/os-release
OS_ID="${ID,,}"

case "$OS_ID" in
  debian|ubuntu)
    PKG_FAMILY="debian"
    echo "[+] installing build dependencies with apt"
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
      autoconf automake bison build-essential ca-certificates cmake curl flex \
      libdumbnet-dev libhwloc-dev libluajit-5.1-dev liblzma-dev libpcap-dev \
      libpcre2-dev libssl-dev libtirpc-dev libtool libunwind-dev pkg-config \
      tar uuid-dev zlib1g-dev
    ;;
  opensuse*|sles|sled)
    PKG_FAMILY="suse"
    ZLIB_DEV_PACKAGE="zlib-devel"
    if [[ "${VERSION_ID:-}" == 16* ]] || rpm -q zlib-ng-compat-devel >/dev/null 2>&1; then
      ZLIB_DEV_PACKAGE="zlib-ng-compat-devel"
    fi
    echo "[+] installing build dependencies with zypper"
    zypper --non-interactive refresh
    zypper --non-interactive install --no-recommends \
      autoconf automake bison cmake curl flex gcc gcc-c++ hwloc-devel \
      libdnet-devel xz-devel libopenssl-devel libpcap-devel libtirpc-devel \
      libtool libunwind-devel luajit-devel make pcre2-devel pkg-config \
      tar uuid-devel "$ZLIB_DEV_PACKAGE"
    ;;
  alpine)
    PKG_FAMILY="alpine"
    echo "[+] installing build dependencies with apk"
    apk update
    apk add --no-cache \
      autoconf automake bison build-base ca-certificates cmake curl flex \
      hwloc-dev libdnet-dev libpcap-dev libtirpc-dev libtool libunwind-dev \
      luajit-dev openssl-dev pcre2-dev pkgconf tar util-linux-dev xz-dev zlib-dev
    ;;
  *)
    echo "[!] unsupported distribution: $OS_ID (supported: Debian, Ubuntu, openSUSE, Alpine)" >&2
    exit 1
    ;;
esac

# Build upstream LibDAQ and Snort 3 into /usr/local.
INSTALL_TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$INSTALL_TMP_DIR"' EXIT
BUILD_DIR="$INSTALL_TMP_DIR/build"
BUILD_JOBS="${BUILD_JOBS:-2}"

echo "[+] building LibDAQ $DAQ_VERSION"
mkdir -p "$BUILD_DIR/libdaq"
curl -fL "https://github.com/snort3/libdaq/archive/refs/tags/v$DAQ_VERSION.tar.gz" \
  -o "$BUILD_DIR/libdaq.tar.gz"
tar -xzf "$BUILD_DIR/libdaq.tar.gz" --strip-components=1 -C "$BUILD_DIR/libdaq"
pushd "$BUILD_DIR/libdaq" >/dev/null
if [[ -x ./bootstrap ]]; then
  ./bootstrap
fi
./configure --prefix=/usr/local --enable-shared --enable-pcap-module
make -j"$BUILD_JOBS"
make install
popd >/dev/null

DAQ_MODULE_FILE="$(find /usr/local/lib /usr/local/lib64 -type f -name daq_pcap.so -print -quit 2>/dev/null || true)"
if [[ -z "$DAQ_MODULE_FILE" ]]; then
  echo "[!] LibDAQ's PCAP module was not installed; check that libpcap development files are available" >&2
  exit 1
fi
DAQ_MODULE_DIR="$(dirname "$DAQ_MODULE_FILE")"

if command -v ldconfig >/dev/null 2>&1; then
  ldconfig
fi

echo "[+] building Snort $SNORT_VERSION"
mkdir -p "$BUILD_DIR/snort"
curl -fL "https://github.com/snort3/snort3/archive/refs/tags/$SNORT_VERSION.tar.gz" \
  -o "$BUILD_DIR/snort.tar.gz"
tar -xzf "$BUILD_DIR/snort.tar.gz" --strip-components=1 -C "$BUILD_DIR/snort"
pushd "$BUILD_DIR/snort" >/dev/null
./configure_cmake.sh \
  --prefix=/usr/local \
  --without-libml \
  --disable-html-docs \
  --disable-pdf-docs \
  --disable-text-docs
cmake --build build --parallel "$BUILD_JOBS" 2>&1 | awk '
  BEGIN { threshold = 10 }
  match($0, /\[[[:space:]]*[0-9]+%\]/) {
    progress = substr($0, RSTART, RLENGTH)
    gsub(/[^0-9]/, "", progress)
    while (progress + 0 >= threshold && threshold <= 100) {
      printf "[%3d%%] Snort build\n", threshold
      fflush()
      threshold += 10
    }
    next
  }
  { print; fflush() }
'
cmake --install build
popd >/dev/null

if command -v ldconfig >/dev/null 2>&1; then
  ldconfig
fi

# Download and install Snort 3 community rules
echo "[+] downloading Snort 3 community rules"
RULES_TMP_DIR="$INSTALL_TMP_DIR/rules"
mkdir -p "$RULES_TMP_DIR"
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
SNORT_BIN="/usr/local/bin/snort"
if [[ ! -x "$SNORT_BIN" ]] || ! "$SNORT_BIN" -V 2>&1 | grep -q 'Version 3\.'; then
  echo "[!] expected a working Snort 3 binary at $SNORT_BIN" >&2
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
if ! grep -q '^snort:' /etc/group; then
  if [[ "$PKG_FAMILY" == "alpine" ]]; then
    addgroup -S snort
  else
    groupadd --system snort
  fi
fi
if ! id snort >/dev/null 2>&1; then
  if [[ "$PKG_FAMILY" == "alpine" ]]; then
    adduser -S -D -H -h "$STATE_DIR" -s /sbin/nologin -G snort snort
  else
    useradd --system --no-create-home --home-dir "$STATE_DIR" \
      --shell /usr/sbin/nologin --gid snort snort
  fi
fi

# Create directories for Snort configuration, rules, logs, and state
echo "[+] creating directories"
mkdir -p "$SNORT_ETC" "$RULES_DIR" "$CUSTOM_RULES_DIR" "$LOG_DIR" "$STATE_DIR"
if [[ "$PKG_FAMILY" == "alpine" ]]; then
  mkdir -p /etc/local.d /etc/conf.d
fi
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
-- autogenerated by install.sh

include '$DEFAULTS_FILE'

HOME_NET = '$HOME_NET'
EXTERNAL_NET = '$EXTERNAL_NET'

daq =
{
  module_dirs =
  {
    '$DAQ_MODULE_DIR'
  }
}

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

# Configure the service manager available on the supported distribution.
if [[ "$PKG_FAMILY" == "alpine" ]]; then
  echo "[+] writing OpenRC local service"
  cat > "$LOCAL_CONF" <<EOF
SNORT_BIN="$SNORT_BIN"
SNORT_IFACE="$IFACE"
SNORT_CONF="$CONF_FILE"
SNORT_LOG_DIR="$LOG_DIR"
SNORT_START_LOG="$START_LOG"
EOF

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
  -A alert_fast \
  -k none \
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

  cat > "$LOCAL_STOP" <<'EOF'
#!/bin/sh
set -eu
. /etc/conf.d/snort-detect
pkill -TERM -f "snort.*-c $SNORT_CONF" 2>/dev/null || true
EOF

  chmod +x "$LOCAL_START" "$LOCAL_STOP"

  echo "[+] enabling OpenRC local service at boot"
  rc-update add local default

  echo "[+] starting Snort"
  "$LOCAL_START"
else
  SERVICE_FILE="/etc/systemd/system/snort-detect.service"
  if [[ ! -d /run/systemd/system ]] || ! command -v systemctl >/dev/null 2>&1; then
    echo "[!] systemd is not running; cannot configure the Snort service" >&2
    exit 1
  fi

  echo "[+] writing systemd service"
  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Snort 3 Intrusion Detection System
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=snort
Group=snort
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=true
ExecStart=$SNORT_BIN -c $CONF_FILE -i $IFACE -l $LOG_DIR -A alert_fast -k none
Restart=on-failure
RestartSec=5
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$LOG_DIR $STATE_DIR

[Install]
WantedBy=multi-user.target
EOF

  echo "[+] enabling and starting Snort service"
  systemctl daemon-reload
  systemctl enable --now snort-detect.service
fi
echo
echo "[+] done"
echo "[+] config: $CONF_FILE"
echo "[+] rules:  $MERGED_RULES"
echo "[+] logs:   $LOG_DIR"
echo "[+] start log: $START_LOG"
echo "[+] check alerts with: tail -f $LOG_DIR/*"
