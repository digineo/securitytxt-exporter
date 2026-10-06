#!/bin/sh
# deb postinst: $1 = configure, $2 = old version (empty on install)
# rpm %post:    $1 = 1 on install, 2 on upgrade
set -e
[ -d /run/systemd/system ] || exit 0

systemctl daemon-reload
if [ "$1" = 1 ] || { [ "$1" = configure ] && [ -z "$2" ]; }; then
	systemctl enable --now securitytxt-exporter.service
else
	systemctl try-restart securitytxt-exporter.service
fi
