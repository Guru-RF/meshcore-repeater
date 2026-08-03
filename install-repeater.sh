#!/bin/bash
#
# RF.Guru MeshCore ham repeater -- one-shot installer for Raspberry Pi OS (64-bit).
#
#   wget -qO /tmp/install-repeater.sh https://raw.githubusercontent.com/Guru-RF/meshcore-repeater/main/install-repeater.sh && sudo bash /tmp/install-repeater.sh
#
# Upgrades the Pi, installs the build dependencies, enables SPI and the LED
# GPIOs in config.txt, builds and installs the repeater as a systemd service
# (dedicated 'meshcore' user, self-contained under /opt), asks for your callsign
# -- which becomes the repeater's on-air ID -- an optional position, and an
# optional APRS-IS iGate, then offers a reboot.

set -eu

export TERM="${TERM:-xterm-256color}"
export DEBIAN_FRONTEND=noninteractive

REPO_URL="${REPEATER_REPO_URL:-https://github.com/Guru-RF/meshcore-repeater.git}"
REPO_BRANCH="${REPEATER_REPO_BRANCH:-main}"
SELF_URL="${REPEATER_SELF_URL:-https://raw.githubusercontent.com/Guru-RF/meshcore-repeater/main/install-repeater.sh}"

APP_NAME="meshcore-repeater"
INSTALL_DIR="/opt/${APP_NAME}"
CONF="${INSTALL_DIR}/meshcore-repeater.conf"
SERVICE_USER="meshcore"
SRC_DIR="/usr/local/src/meshcore-repeater"

BLOCK_BEGIN="# >>> RF.Guru MeshCore repeater -- managed by install-repeater.sh >>>"
BLOCK_END="# <<< RF.Guru MeshCore repeater <<<"

# ---------------------------------------------------------------------------
# `wget -qO- ... | sudo bash` leaves stdin on the pipe, so every prompt below
# would read the *script* instead of the user. Re-fetch ourselves to a file and
# re-exec with the terminal attached. This has to stay at the very top: bash
# reads a piped script incrementally, and exec() replaces us before it gets the
# chance to read another line.
# ---------------------------------------------------------------------------
if [ ! -t 0 ] && [ -z "${REPEATER_INSTALL_REEXEC:-}" ]; then
  if [ -e /dev/tty ] && (exec </dev/tty) 2>/dev/null; then
    _self="$(mktemp /tmp/install-repeater.XXXXXX)"
    if command -v wget >/dev/null 2>&1; then
      wget -qO "$_self" "$SELF_URL" || { echo "Could not download $SELF_URL" >&2; exit 1; }
    elif command -v curl >/dev/null 2>&1; then
      curl -fsSL -o "$_self" "$SELF_URL" || { echo "Could not download $SELF_URL" >&2; exit 1; }
    else
      echo "Neither wget nor curl is installed." >&2
      exit 1
    fi
    export REPEATER_INSTALL_REEXEC=1
    exec bash "$_self" </dev/tty
  fi
  echo "No terminal available -- run this installer interactively:" >&2
  echo "  wget -qO /tmp/install-repeater.sh $SELF_URL && sudo bash /tmp/install-repeater.sh" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Output helpers (same look as the Analog-HotSPOT-SVXLink installers)
# ---------------------------------------------------------------------------
run() {
  local cmd="$1"
  printf "\x1b[38;5;104m --> %s\x1b[39m\n" "$cmd"
  eval "$cmd"
}

# Same, but a failure only warns. For the housekeeping steps: a mirror having a
# bad day is no reason to refuse to install the repeater.
try() {
  local cmd="$1"
  printf "\x1b[38;5;104m --> %s\x1b[39m\n" "$cmd"
  eval "$cmd" || oops "'${cmd}' failed -- continuing anyway."
}

say() {
  printf "\x1b[38;5;220m%s\x1b[38;5;255m\n" "${1:-}"
}

oops() {
  printf "\x1b[38;5;196m%s\x1b[39m\n" "$1" >&2
}

on_exit() {
  local st=$?
  if [ "$st" -ne 0 ]; then
    oops "Install aborted (exit ${st}). Nothing was started -- fix the error above and re-run."
  fi
}
trap on_exit EXIT

# ---------------------------------------------------------------------------
# Prompts -- gum when we have it, plain read when we don't
# ---------------------------------------------------------------------------
HAVE_GUM=0

banner() {
  if [ "$HAVE_GUM" -eq 1 ]; then
    gum style --border normal --margin "1" --padding "1 2" --border-foreground "#04B575" \
      "$(gum style --foreground 3 'RF.')Guru $(gum style --foreground 3 '-') MeshCore ham repeater"
  else
    printf "\n\x1b[38;5;220m== RF.Guru - MeshCore ham repeater ==\x1b[38;5;255m\n\n"
  fi
}

# ask <prompt> <default>  -> the answer on stdout
ask() {
  local prompt="$1" def="${2:-}" ans=""
  if [ "$HAVE_GUM" -eq 1 ]; then
    gum style --foreground "#04B575" "$prompt" >&2
    # A gum that bails out (no TTY, ...) must not spin the validation loop.
    ans="$(gum input --value "$def")" || ans=""
  else
    read -r -p "$(printf '\x1b[38;5;220m%s\x1b[38;5;255m [%s]: ' "$prompt" "$def")" ans || ans=""
  fi
  if [ -z "$ans" ]; then
    ans="$def"
  fi
  printf '%s' "$ans"
}

# echo the accepted value back, the way hotspot-config does
answered() {
  if [ "$HAVE_GUM" -eq 1 ]; then
    gum style --foreground 212 "$1"
  else
    printf "\x1b[38;5;212m%s\x1b[39m\n" "$1"
  fi
}

# confirm <prompt> [yes|no]   (defaults to yes)
confirm() {
  local prompt="$1" def="${2:-yes}" ans=""
  if [ "$HAVE_GUM" -eq 1 ]; then
    if [ "$def" = "no" ]; then
      gum confirm --default=false "$prompt"
    else
      gum confirm --default=true "$prompt"
    fi
  else
    # Enter takes the default; end-of-input means the default too, so a closed
    # stdin can never flip an answer on the user's behalf.
    if [ "$def" = "no" ]; then
      if read -r -p "$(printf '\x1b[38;5;220m%s\x1b[38;5;255m [y/N]: ' "$prompt")" ans; then
        case "$ans" in y* | Y*) return 0 ;; *) return 1 ;; esac
      fi
      return 1
    else
      if read -r -p "$(printf '\x1b[38;5;220m%s\x1b[38;5;255m [Y/n]: ' "$prompt")" ans; then
        case "$ans" in "" | y* | Y*) return 0 ;; *) return 1 ;; esac
      fi
      return 1
    fi
  fi
}

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  oops "This installer must run as root. Try: sudo bash $0"
  exit 1
fi

# Resolve our own directory while $0 can still be relative, then get out of
# whatever directory we were started from: the source step below removes and
# recreates its checkout, and deleting the shell's own cwd breaks git.
HERE="$(cd "$(dirname "$0")" 2>/dev/null && pwd || echo /)"
cd /

PI_MODEL="$(tr -d '\0' < /proc/device-tree/model 2>/dev/null || echo unknown)"
case "$PI_MODEL" in
  *Raspberry*) ;;
  *)
    oops "This does not look like a Raspberry Pi (model: ${PI_MODEL})."
    oops "Continuing anyway -- SPI and the GPIO LEDs will not work here."
    ;;
esac

banner
say "Installing the RF.Guru MeshCore repeater on ${PI_MODEL}"

# ---------------------------------------------------------------------------
# 1. Look at config.txt *before* anything touches it, so we can tell whether
#    SPI is newly enabled (and therefore whether a reboot is really needed).
# ---------------------------------------------------------------------------
CONFIG_TXT=""
for c in /boot/firmware/config.txt /boot/config.txt; do
  if [ -f "$c" ]; then
    CONFIG_TXT="$c"
    break
  fi
done

SPI_WAS_ON=0
NEED_REBOOT=0

if [ -n "$CONFIG_TXT" ]; then
  if grep -qE '^[[:space:]]*dtparam=spi=on' "$CONFIG_TXT"; then
    SPI_WAS_ON=1
  fi
  cp -a "$CONFIG_TXT" "${CONFIG_TXT}.meshcore.bak"
  say "Kept a copy of the current boot config as ${CONFIG_TXT}.meshcore.bak"
else
  oops "No config.txt found (/boot/firmware/config.txt, /boot/config.txt)."
  oops "Enable SPI yourself afterwards: sudo raspi-config nonint do_spi 0"
fi

# ---------------------------------------------------------------------------
# 2. Upgrade the Pi
# ---------------------------------------------------------------------------
say "Updating the package lists"
try "apt-get -y update"

say "Upgrading the system (this takes a while on a Pi Zero)"
try "apt-get -y full-upgrade"

say "Cleaning up"
try "apt-get -y autoremove"
try "apt-get -y clean"

# ---------------------------------------------------------------------------
# 3. Base dependencies. The repeater's own build deps (libgpiod-dev,
#    libreadline-dev, ...) are pulled in by install.sh further down.
# ---------------------------------------------------------------------------
say "Installing the base dependencies"
run "apt-get -y install build-essential git wget curl ca-certificates"

# ---------------------------------------------------------------------------
# 4. gum, for the prompts further down. The distro package first, then Charm's
#    own apt repo, and plain `read` prompts if neither works (no internet,
#    mirror down, ...) so the install never dead-ends on a cosmetic dependency.
# ---------------------------------------------------------------------------
install_gum() {
  if command -v gum >/dev/null 2>&1; then
    return 0
  fi

  say "Installing gum (for the interactive prompts)"
  apt-get -y install gum >/dev/null 2>&1 || true
  if command -v gum >/dev/null 2>&1; then
    return 0
  fi

  say "gum is not in the distro repo -- adding repo.charm.sh"
  apt-get -y install curl gpg >/dev/null 2>&1 || true
  mkdir -p /etc/apt/keyrings
  if curl -fsSL https://repo.charm.sh/apt/gpg.key 2>/dev/null |
      gpg --dearmor --yes -o /etc/apt/keyrings/charm.gpg 2>/dev/null; then
    chmod 0644 /etc/apt/keyrings/charm.gpg
    echo "deb [signed-by=/etc/apt/keyrings/charm.gpg] https://repo.charm.sh/apt/ * *" \
      > /etc/apt/sources.list.d/charm.list
    apt-get -y update >/dev/null 2>&1 || true
    apt-get -y install gum >/dev/null 2>&1 || true
  fi
  command -v gum >/dev/null 2>&1
}

if install_gum; then
  HAVE_GUM=1
else
  oops "gum could not be installed -- using plain prompts."
fi

# ---------------------------------------------------------------------------
# 5. Sources: build from this checkout when we are in one, otherwise clone.
#    A clone lands root-owned under /usr/local/src; hand it to the invoking
#    user so install.sh can build it as them (it deliberately avoids leaving
#    root-owned object files behind).
# ---------------------------------------------------------------------------
if [ -f "$HERE/Makefile" ] && [ -f "$HERE/meshcore-repeater.service" ]; then
  SRC_DIR="$HERE"
  say "Building from the local checkout in ${SRC_DIR}"
else
  if [ -d "$SRC_DIR/.git" ]; then
    say "Updating the sources in ${SRC_DIR}"
    run "git -C '${SRC_DIR}' fetch --prune origin '${REPO_BRANCH}'"
    run "git -C '${SRC_DIR}' reset --hard 'origin/${REPO_BRANCH}'"
  else
    say "Cloning ${REPO_URL} into ${SRC_DIR}"
    run "rm -rf '${SRC_DIR}'"
    run "mkdir -p '$(dirname "$SRC_DIR")'"
    run "git clone --branch '${REPO_BRANCH}' '${REPO_URL}' '${SRC_DIR}'"
  fi
  if [ -n "${SUDO_USER:-}" ]; then
    run "chown -R '${SUDO_USER}' '${SRC_DIR}'"
  fi
fi

# ---------------------------------------------------------------------------
# 6. Compile, self-test, install the binary + default config + systemd unit +
#    the meshcore-cli control client. install.sh creates the 'meshcore' user,
#    the /opt tree and enables the service on boot.
# ---------------------------------------------------------------------------
say "Building and installing ${APP_NAME}"
run "bash '${SRC_DIR}/install.sh'"

if [ ! -f "$CONF" ]; then
  oops "${CONF} is missing -- the build did not install cleanly."
  exit 1
fi

# The unit runs with SupplementaryGroups=spi gpio. On Raspberry Pi OS those
# groups exist; on anything else systemd refuses to start a service whose
# supplementary group is missing, so make sure they are there.
for g in spi gpio; do
  getent group "$g" >/dev/null 2>&1 || run "groupadd --system $g"
done

# ---------------------------------------------------------------------------
# 7. config.txt: SPI (for /dev/spidev0.x) and the LED GPIOs.
#
#    Deliberately after install.sh: that script also normalises the
#    dtparam=spi= line, so writing our block last leaves the file identical
#    after every run instead of alternating between two shapes.
# ---------------------------------------------------------------------------
# Read a value back the way the daemon does (config.c): the first '#' starts a
# comment and there is no quoting, so a plain "key = value" round-trips cleanly.
conf_get() {
  awk -v k="$1" '
    $0 ~ "^[ \t]*" k "[ \t]*=" {
      v = $0
      sub(/^[^=]*=[ \t]*/, "", v)
      h = index(v, "#"); if (h) v = substr(v, 1, h - 1)
      sub(/[ \t]+$/, "", v)
      print v
      exit
    }' "$CONF"
}

conf_set() {
  local key="$1" val="$2" tmp
  tmp="$(mktemp)"
  awk -v k="$key" -v v="$val" '
    !seen && $0 ~ "^[ \t]*" k "[ \t]*=" { print k " = " v; seen = 1; next }
    { print }
    END { if (!seen) print k " = " v }
  ' "$CONF" > "$tmp"
  cat "$tmp" > "$CONF"
  rm -f "$tmp"
}

led_pins() {
  local on data
  on="$(conf_get gpio_led_on)"
  data="$(conf_get gpio_led_data)"
  [ -n "$on" ]   || on=19
  [ -n "$data" ] || data=26
  printf '%s,%s' "$on" "$data"
}

if [ -n "$CONFIG_TXT" ]; then
  USE_LEDS="$(conf_get use_leds)"
  PINS="$(led_pins)"
  if [ "$USE_LEDS" = "false" ]; then
    say "Enabling SPI in ${CONFIG_TXT} (LEDs disabled in the config)"
  else
    say "Enabling SPI and the LED GPIOs (${PINS}) in ${CONFIG_TXT}"
  fi

  # Drop a previous block of ours, plus any stray dtparam=spi= line elsewhere
  # in the file, then append one authoritative block. Idempotent: re-running
  # the installer never stacks duplicates.
  tmp="$(mktemp)"
  awk -v b="$BLOCK_BEGIN" -v e="$BLOCK_END" '
    $0 == b { skip = 1; next }
    $0 == e { skip = 0; next }
    skip { next }
    /^[ \t]*#?[ \t]*dtparam=spi=/ { next }
    /^[ \t]*gpio=[0-9,]+=op,dl[ \t]*$/ { next }
    { print }
  ' "$CONFIG_TXT" > "$tmp"
  {
    printf '%s\n' "$BLOCK_BEGIN"
    printf '# SPI gives the SX1268 its /dev/spidev0.x node -- without it the radio\n'
    printf '# cannot be reached at all.\n'
    printf 'dtparam=spi=on\n'
    if [ "$USE_LEDS" != "false" ]; then
      printf '# Status + activity LED lines: outputs, driven low, so they stay dark from\n'
      printf '# boot until the repeater claims them on the GPIO character device.\n'
      printf 'gpio=%s=op,dl\n' "$PINS"
    fi
    printf '%s\n' "$BLOCK_END"
  } >> "$tmp"
  cat "$tmp" > "$CONFIG_TXT"
  rm -f "$tmp"

  if [ "$SPI_WAS_ON" -eq 0 ]; then
    say "SPI was off -- /dev/spidev0.x only appears after a reboot"
    NEED_REBOOT=1
  fi
fi

if [ -e /var/run/reboot-required ]; then
  NEED_REBOOT=1
fi
ls /dev/spidev* >/dev/null 2>&1 || NEED_REBOOT=1

# ---------------------------------------------------------------------------
# 8. Callsign -- this becomes the repeater's node name, i.e. its on-air ID.
#    Amateur radio requires an automatic station to identify, so a real
#    callsign here (not "HamRepeater") is what makes the periodic advert count.
# ---------------------------------------------------------------------------
banner

OLDNAME="$(conf_get name)"
case "$OLDNAME" in
  "" | HamRepeater | N0CALL* | URECALL*) OLDNAME="ON0RFG" ;;
esac

# 3-7 alphanumerics -- a bare callsign, no SSID (MeshCore names carry no SSID).
while :; do
  CALLSIGN="$(ask "Callsign -- the repeater's on-air ID, e.g. ON0RFG:" "$OLDNAME")"
  CALLSIGN="$(printf '%s' "$CALLSIGN" | tr '[:lower:]' '[:upper:]' | tr -d '[:space:]')"
  case "$CALLSIGN" in
    *-*)
      oops "Leave the -SSID off: the mesh node name is the bare callsign."
      continue
      ;;
  esac
  if printf '%s' "$CALLSIGN" | grep -qE '^[A-Z0-9]{3,7}$'; then
    break
  fi
  oops "'${CALLSIGN}' is not a callsign: 3 to 7 letters and digits."
done
answered "$CALLSIGN"
conf_set name "$CALLSIGN"
say "Repeater node name / ID: ${CALLSIGN}"

# ---------------------------------------------------------------------------
# 9. Position -- optional. Carried in the advert, and reused as the APRS beacon
#    position below. A repeater advertising the wrong spot is worse than one
#    that advertises none, so this is opt-in and defaults to off.
# ---------------------------------------------------------------------------
is_number() { printf '%s' "$1" | grep -qE '^-?[0-9]+([.][0-9]+)?$'; }
in_range() { awk -v v="$1" -v lo="$2" -v hi="$3" 'BEGIN { exit !(v >= lo && v <= hi) }'; }

# Pull the first "<key>": value out of a compact JSON document on stdin. Enough
# for the two flat replies we ask for, and it keeps this installer free of the
# Python the daemon itself deliberately does without.
json_field() {
  awk -v k="$1" '
    {
      p = "\"" k "\"[ \t]*:[ \t]*(\"[^\"]*\"|-?[0-9.]+)"
      if (match($0, p)) {
        v = substr($0, RSTART, RLENGTH)
        sub("^\"" k "\"[ \t]*:[ \t]*", "", v)
        gsub(/^"|"$/, "", v)
        print v
        exit
      }
    }'
}

# Address -> coordinates, via Nominatim (OpenStreetMap): free, no API key, but
# its usage policy asks for a real User-Agent. Prints the JSON reply.
geocode() {
  local json
  command -v curl >/dev/null 2>&1 || return 1
  json="$(curl -sG --connect-timeout 5 --max-time 15 \
    -H "User-Agent: rfguru-meshcore-repeater/1.0 (https://github.com/Guru-RF/meshcore-repeater)" \
    --data-urlencode "q=$1" \
    --data "format=json&limit=1" \
    "https://nominatim.openstreetmap.org/search" 2>/dev/null)" || return 1
  case "$json" in "" | "[]") return 1 ;; esac
  printf '%s' "$json"
}

# Ground elevation for a coordinate, in whole meters. Saves looking up the one
# number nobody knows off the top of their head.
elevation() {
  local json m
  command -v curl >/dev/null 2>&1 || return 1
  json="$(curl -sG --connect-timeout 5 --max-time 15 \
    --data "latitude=$1&longitude=$2" \
    "https://api.open-meteo.com/v1/elevation" 2>/dev/null)" || return 1
  m="$(printf '%s' "$json" | awk '
    match($0, /"elevation"[ \t]*:[ \t]*\[[ \t]*-?[0-9.]+/) {
      v = substr($0, RSTART, RLENGTH)
      sub(/.*\[[ \t]*/, "", v)
      printf "%.0f", v
      exit
    }')"
  [ -n "$m" ] || return 1
  printf '%s' "$m"
}

HAVE_POS=0
POS_LAT=""
POS_LON=""
POS_ALT=""

if confirm "Set the repeater position now? (goes out in every advert)" "no"; then
  DEF_LAT="$(conf_get latitude)"
  DEF_LON="$(conf_get longitude)"
  DEF_ALT="$(conf_get aprs_altitude)"

  LOCATION="$(ask "Location -- a full street address gives the most accurate fix, and Belgium is assumed if you leave the country off. Empty to type coordinates yourself:" "")"

  if [ -n "$LOCATION" ]; then
    FOUND=0

    # Coordinates pasted straight in ("51.2194, 4.4025") need no lookup.
    case "$LOCATION" in
      *[0-9]*,*[0-9]*)
        CAND_LAT="$(printf '%s' "$LOCATION" | cut -d, -f1 | tr -d '[:space:]')"
        CAND_LON="$(printf '%s' "$LOCATION" | cut -d, -f2 | tr -d '[:space:]')"
        if is_number "$CAND_LAT" && in_range "$CAND_LAT" -90 90 &&
          is_number "$CAND_LON" && in_range "$CAND_LON" -180 180; then
          DEF_LAT="$CAND_LAT"
          DEF_LON="$CAND_LON"
          FOUND=1
          say "Read as coordinates: ${DEF_LAT}, ${DEF_LON}"
        fi
        ;;
    esac

    if [ "$FOUND" -eq 0 ]; then
      QUERY="$LOCATION"
      case "$QUERY" in
        *,*) ;;
        *) QUERY="${LOCATION}, Belgium" ;;
      esac

      say "Looking up ${QUERY} ..."
      if GEO="$(geocode "$QUERY")"; then
        GEO_LAT="$(printf '%s' "$GEO" | json_field lat)"
        GEO_LON="$(printf '%s' "$GEO" | json_field lon)"
        GEO_NAME="$(printf '%s' "$GEO" | json_field display_name)"
        if is_number "$GEO_LAT" && in_range "$GEO_LAT" -90 90 &&
          is_number "$GEO_LON" && in_range "$GEO_LON" -180 180; then
          answered "${GEO_NAME:-$QUERY}"
          say "Found ${GEO_LAT}, ${GEO_LON}"
          DEF_LAT="$GEO_LAT"
          DEF_LON="$GEO_LON"
          FOUND=1
        else
          oops "No usable coordinates came back -- keeping ${DEF_LAT}, ${DEF_LON}."
        fi
      else
        oops "Could not look up '${QUERY}' (offline?) -- keeping ${DEF_LAT}, ${DEF_LON}."
      fi
    fi

    if [ "$FOUND" -eq 1 ]; then
      if GEO_ALT="$(elevation "$DEF_LAT" "$DEF_LON")"; then
        say "Ground elevation there is about ${GEO_ALT} m"
        DEF_ALT="$GEO_ALT"
      fi
      say "Nothing but the coordinates is kept -- not the address you typed. They"
      say "do go out in every advert though, so round them off below if you would"
      say "rather not put your doorstep on the map."
    fi
  fi

  while :; do
    LAT="$(ask "Latitude in decimal degrees (north is positive):" "$DEF_LAT")"
    if is_number "$LAT" && in_range "$LAT" -90 90; then
      break
    fi
    oops "'${LAT}' is not a latitude between -90 and 90."
  done
  answered "$LAT"

  while :; do
    LON="$(ask "Longitude in decimal degrees (east is positive):" "$DEF_LON")"
    if is_number "$LON" && in_range "$LON" -180 180; then
      break
    fi
    oops "'${LON}' is not a longitude between -180 and 180."
  done
  answered "$LON"

  conf_set location true
  conf_set latitude "$LAT"
  conf_set longitude "$LON"
  HAVE_POS=1
  POS_LAT="$LAT"
  POS_LON="$LON"
  POS_ALT="$DEF_ALT"
fi

# ---------------------------------------------------------------------------
# 10. APRS-IS RX iGate -- optional. Gates adverts-with-GPS from ham-callsign
#     nodes to APRS-IS, and beacons this repeater's own position. Off by
#     default: it injects under your callsign, so it needs a licence.
# ---------------------------------------------------------------------------
if confirm "Enable the APRS-IS iGate too? (gate positions + beacon this repeater)" "no"; then
  OLDCALL="$(conf_get aprs_call)"
  OLDSSID="5"
  case "$OLDCALL" in
    *-*) OLDSSID="${OLDCALL#*-}" ;;
  esac

  while :; do
    SSID="$(ask "APRS SSID -- the number after the dash, e.g. 5 for ${CALLSIGN}-5:" "$OLDSSID")"
    SSID="$(printf '%s' "$SSID" | tr '[:lower:]' '[:upper:]' | tr -d '[:space:]-')"
    if printf '%s' "$SSID" | grep -qE '^[A-Z0-9]{1,2}$'; then
      break
    fi
    oops "'${SSID}' is not a valid SSID: 1 or 2 letters or digits."
  done
  answered "$SSID"

  APRS_CALL="${CALLSIGN}-${SSID}"
  conf_set aprs_enable true
  conf_set aprs_call "$APRS_CALL"
  conf_set aprs_passcode auto
  say "APRS call: ${APRS_CALL} (passcode derived automatically)"

  if [ "$HAVE_POS" -eq 1 ]; then
    ALT="$(ask "Antenna altitude in meters (for the APRS beacon):" "${POS_ALT:-0}")"
    is_number "$ALT" || ALT=0
    answered "$ALT"
    conf_set aprs_altitude "$ALT"
  else
    oops "No position set -- the APRS *own-beacon* needs one, but gating received"
    oops "nodes still works. Add latitude/longitude to ${CONF} later to beacon."
  fi
fi

# The daemon owns its config; keep it that way after our edits.
chown "${SERVICE_USER}:${SERVICE_USER}" "$CONF" 2>/dev/null || true
chmod 0644 "$CONF"

# ---------------------------------------------------------------------------
# 11. Service -- install.sh already enabled it on boot; make sure, then start.
# ---------------------------------------------------------------------------
run "systemctl daemon-reload"
run "systemctl enable ${APP_NAME}.service"

if [ "$NEED_REBOOT" -eq 0 ]; then
  say "Starting ${APP_NAME}"
  run "systemctl restart ${APP_NAME}.service"
else
  say "Not starting yet -- ${APP_NAME} needs the reboot below to see the radio"
fi

# ---------------------------------------------------------------------------
# 12. Done
# ---------------------------------------------------------------------------
say ""
say "${APP_NAME} is installed as ${CALLSIGN}, running as the '${SERVICE_USER}' user"
say "from ${INSTALL_DIR}. It self-advertises (IDs) every 30 min by default."
say ""
say "run [>sudo nano ${CONF}] to change the station settings"
say "run [>meshcore-cli status] to talk to it live (tab-completion enabled)"
say "run [>sudo systemctl restart ${APP_NAME}] to apply config changes"
say "run [>journalctl -u ${APP_NAME} -f] to watch it live"
say ""

if [ "$NEED_REBOOT" -eq 1 ]; then
  say "A reboot is required: SPI and the GPIO lines are set up by the firmware at"
  say "boot, so /dev/spidev0.x only shows up afterwards."
else
  say "No reboot is required, but one never hurts after a system upgrade."
fi

if confirm "Reboot now?"; then
  say "Rebooting -- ${APP_NAME} starts by itself."
  reboot
else
  say "please reboot your system with:"
  say "run [>sudo reboot]"
fi
