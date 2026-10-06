#!/bin/sh
# deb prerm:  $1 = remove on removal, upgrade on upgrade
# rpm %preun: $1 = 0 on removal, 1 on upgrade
#
# Runs before the unit file is gone, systemctl disable fails afterwards.
set -e
[ -d /run/systemd/system ] || exit 0

if [ "$1" = remove ] || [ "$1" = 0 ]; then
	systemctl disable --now securitytxt-exporter.service
fi
