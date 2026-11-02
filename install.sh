#!/usr/bin/env bash
#
# Installing security-watch on a server: build, copy, systemd service.
#
# Run on the server from the source directory:
#   sudo ./install.sh
#
# Running it again updates the binary and restarts the service; the
# configuration file is left alone if it already exists.
set -euo pipefail

BIN_DIR="/opt/security-watch"
CONF_DIR="/etc/security-watch"
STATE_DIR="/var/lib/security-watch"
LOG_DIR="/var/log/security-watch"

if [[ $EUID -ne 0 ]]; then
  echo "root privileges are required: sudo ./install.sh" >&2
  exit 1
fi

echo "==> Building"
go build -o /tmp/security-watch ./cmd/security-watch

echo "==> Directories"
mkdir -p "$BIN_DIR" "$CONF_DIR" "$STATE_DIR" "$LOG_DIR"
chmod 750 "$STATE_DIR" "$LOG_DIR"

echo "==> Binary"
install -m 0755 /tmp/security-watch "$BIN_DIR/security-watch"
rm -f /tmp/security-watch
install -m 0644 README.md "$BIN_DIR/README.md"

if [[ ! -f "$CONF_DIR/config.json" ]]; then
  echo "==> Configuration (example, edit $CONF_DIR/config.json)"
  install -m 0640 config.example.json "$CONF_DIR/config.json"
else
  echo "==> Configuration already exists, leaving it alone"
fi

echo "==> Event log rotation"
install -m 0644 logrotate.conf /etc/logrotate.d/security-watch

echo "==> Service"
install -m 0644 systemd/security-watch.service /etc/systemd/system/security-watch.service
systemctl daemon-reload
systemctl enable security-watch
systemctl restart security-watch

echo "==> Done. Status:"
systemctl --no-pager --lines=5 status security-watch || true
