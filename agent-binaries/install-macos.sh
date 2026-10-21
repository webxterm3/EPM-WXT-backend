#!/bin/bash
#
# wxt-agent installer for macOS.
#
# Fetched and run from a terminal:
#
#   curl -fsSL http://HOST/agent/install-macos.sh | sudo bash -s -- --token … --host …
#
# Why this exists alongside the disk image.
#
# macOS marks anything a BROWSER downloads with com.apple.quarantine, and
# Gatekeeper refuses to open it: "Apple could not verify this is free of
# malware". curl does not set that attribute, so a terminal install never meets
# Gatekeeper at all. Nothing here weakens anything — Gatekeeper is not disabled
# and no warning is suppressed; the files simply never acquire the mark that
# triggers it.
#
# This is a stopgap. Signing with a Developer ID and notarising is what makes
# the double-click path work, and it is also what makes the macOS permission
# grants survive an upgrade. Until that exists, this is the way to install
# without a prompt.

set -euo pipefail

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/vsay"
LOG_DIR="/var/log/vsay"
APP_DIR="/Applications/wxt-agent.app"

die() { echo "error: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run this with sudo:
  curl -fsSL <url>/agent/install-macos.sh | sudo bash -s -- --token … --host …"

[ $# -gt 0 ] || die "no enrolment arguments given.
Copy the command from the EPM portal: Machines › Add Machine."

# The host the agent will talk to is also the host this came from, so the
# download base is taken from the arguments rather than asked for twice.
HOST=""
prev=""
for arg in "$@"; do
    if [ "$prev" = "--host" ]; then HOST="$arg"; break; fi
    case "$arg" in --host=*) HOST="${arg#--host=}"; break ;; esac
    prev="$arg"
done
[ -n "$HOST" ] || die "--host is missing from the enrolment command"
HOST="${HOST%/}"

case "$(uname -m)" in
    arm64)  ARCH=arm64 ;;
    x86_64) ARCH=amd64 ;;
    *)      die "unsupported architecture: $(uname -m)" ;;
esac

TARBALL="wxt-agent-macos-${ARCH}.tar.gz"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "Downloading ${TARBALL}…"
# Cache-busted: the filename is stable, so without this a proxy in front of the
# backend can serve a build from last week for ever.
curl -fL --no-progress-meter \
     -H "Cache-Control: no-cache" -H "Pragma: no-cache" \
     -o "$WORK/$TARBALL" \
     "${HOST}/agent/download/${TARBALL}?t=$(date +%s)" \
    || die "could not download ${HOST}/agent/download/${TARBALL}"

tar -xzf "$WORK/$TARBALL" -C "$WORK" || die "the download is not a readable archive"
[ -d "$WORK/wxt-agent.app" ] || die "the archive does not contain wxt-agent.app"

echo "Installing…"

# Stop anything already running, so the files underneath it can be replaced.
launchctl bootout system/io.wxt.agent 2>/dev/null || true

mkdir -p "$INSTALL_DIR" "$CONFIG_DIR/certs" "$LOG_DIR"

# The parent is created rather than assumed. /Applications always exists on a
# real Mac, but cp -R fails with a bare "No such file or directory" naming the
# DESTINATION when it does not — an error that reads as though the thing being
# copied is missing.
mkdir -p "$(dirname "$APP_DIR")"
rm -rf "$APP_DIR"
cp -R "$WORK/wxt-agent.app" "$APP_DIR"

# The agent binary also goes in PATH so `wxt-agent …` works in a terminal. The
# session helper deliberately does NOT: it runs from inside the bundle, which
# is what gives the product one row in System Settings rather than two.
cp "$APP_DIR/Contents/MacOS/wxt-agent" "$INSTALL_DIR/wxt-agent"
chmod 755 "$INSTALL_DIR/wxt-agent"
rm -f "$INSTALL_DIR/wxt-agent-session"

echo "Enrolling…"
# stdin is closed for this call on purpose.
#
# This script is normally run as `curl … | sudo bash -s -- …`, which means
# bash is READING THE SCRIPT ITSELF from stdin. A child that reads stdin would
# swallow the rest of the script, and the install would stop halfway through
# with no error — the classic curl-pipe-to-shell trap. configure does not
# prompt today; this makes sure that staying true is not a condition of the
# installer working.
"$INSTALL_DIR/wxt-agent" configure "$@" < /dev/null

cat <<'NOTE'

Installed.

One more step — macOS will not grant these silently:

  System Settings › Privacy & Security › Accessibility
  System Settings › Privacy & Security › Screen Recording

Switch on wxt-agent in both. The entry appears there by itself the first time
somebody tries to connect; you do not have to add any files by hand.

The agent restarts itself once the grants are in place.
NOTE
