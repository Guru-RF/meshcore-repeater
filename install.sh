#!/bin/bash
# One-shot installer for the MeshCore ham repeater on Raspberry Pi OS (64-bit).
# Installs prerequisites, enables SPI, builds + self-tests, and installs the
# service under /opt as the dedicated 'meshcore' user.
#
#   sudo ./install.sh
#
set -e

APP="meshcore-repeater"
INSTALL_DIR="/opt/$APP"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_USER="${SUDO_USER:-root}"   # build as the invoking user, not root

if [ "$EUID" -ne 0 ]; then
  echo "❌ This installer must be run as root. Try:  sudo $0"
  exit 1
fi

echo "🚀 Installing $APP ..."

# --- Prerequisites -----------------------------------------------------------
echo "📦 Installing prerequisites (build-essential, pkg-config, libgpiod-dev, libreadline-dev)..."
apt-get update
# libgpiod-dev: SX126x GPIO;  libreadline-dev: meshcore-cli tab-completion + history
apt-get install -y build-essential pkg-config libgpiod-dev libreadline-dev

# --- Enable SPI (the SX126x radio needs /dev/spidev0.x) ----------------------
CONFIG_TXT="/boot/firmware/config.txt"
[ -f "$CONFIG_TXT" ] || CONFIG_TXT="/boot/config.txt"
SPI_JUST_ENABLED=0
if [ -f "$CONFIG_TXT" ]; then
  if ! grep -qE '^dtparam=spi=on' "$CONFIG_TXT"; then
    echo "🔌 Enabling SPI in $CONFIG_TXT (a reboot will be needed)..."
    sed -i '/^#\?dtparam=spi=/d' "$CONFIG_TXT"
    echo 'dtparam=spi=on' >> "$CONFIG_TXT"
    SPI_JUST_ENABLED=1
  else
    echo "🔌 SPI already enabled."
  fi
fi

# --- Build + self-test (as the invoking user, so artifacts aren't root-owned) -
echo "🛠️  Building (as $BUILD_USER)..."
sudo -u "$BUILD_USER" make -C "$SRC_DIR" clean
sudo -u "$BUILD_USER" make -C "$SRC_DIR"
echo "🧪 Running self-test (no radio needed)..."
sudo -u "$BUILD_USER" make -C "$SRC_DIR" test

# --- Install: creates the 'meshcore' user, /opt tree, meshcore-cli, systemd ---
echo "📁 Installing to $INSTALL_DIR ..."
make -C "$SRC_DIR" install

# --- Enable on boot ----------------------------------------------------------
systemctl enable "$APP.service"

# --- Restart if already running (a daemon-reload alone keeps the old binary) --
RESTARTED=0
if systemctl is-active --quiet "$APP.service"; then
  echo "🔄 Restarting the running service onto the new build..."
  systemctl restart "$APP.service"
  RESTARTED=1
fi

echo ""
echo "✅ $APP installed — runs as user 'meshcore' from $INSTALL_DIR."
echo "📝 Edit the config:   sudo nano $INSTALL_DIR/meshcore-repeater.conf"
echo "     • name / frequency (defaults follow the IARU R1 ham-MeshCore RFC)"
echo "     • optional APRS-IS iGate: aprs_enable, aprs_call  (aprs_passcode = auto)"
echo "🖥️  Control it live:    meshcore-cli status     (tab-completion enabled)"
if [ "$SPI_JUST_ENABLED" -eq 1 ]; then
  echo "🔁 SPI was just enabled — REBOOT before starting:  sudo reboot"
  echo "   (it is enabled to start on boot, so it will come up after the reboot)"
elif [ "$RESTARTED" -eq 1 ]; then
  echo "▶️  Already running the new build — check:  sudo systemctl status $APP"
else
  echo "▶️  Start it now:  sudo systemctl start $APP"
fi
