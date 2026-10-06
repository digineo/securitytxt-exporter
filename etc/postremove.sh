#!/bin/sh
# Unloads the removed unit file.
set -e
[ -d /run/systemd/system ] || exit 0

systemctl daemon-reload
