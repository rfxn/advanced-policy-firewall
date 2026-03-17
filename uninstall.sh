#!/bin/bash
#
##
# Advanced Policy Firewall (APF) v2.0.2
#             (C) 2002-2026, R-fx Networks <proj@rfxn.com>
#             (C) 2026, Ryan MacDonald <ryan@rfxn.com>
# This program may be freely redistributed under the terms of the GNU GPL v2
##
#
INSTALL_PATH=${INSTALL_PATH:-"/etc/apf"}
BINPATH=${BINPATH:-"/usr/local/sbin/apf"}
COMPAT_BINPATH=${COMPAT_BINPATH:-"/usr/local/sbin/fwmgr"}

if [ "$(id -u)" != "0" ]; then
	echo "Error: uninstall.sh must be run as root"
	exit 1
fi

if [ ! -d "$INSTALL_PATH" ]; then
	echo "Error: APF install path $INSTALL_PATH does not exist"
	exit 1
fi

# Source shared packaging library
# shellcheck disable=SC1091
. "$INSTALL_PATH/internals/pkg_lib.sh"

echo "APF Uninstaller"
echo ""

# Stop the firewall if running
if [ -x "$INSTALL_PATH/apf" ]; then
	echo "Stopping firewall..."
	"$INSTALL_PATH/apf" --flush 2>/dev/null || true  # safe: may already be stopped
fi

# Remove service (systemd units, SysV init scripts, rc.local entries)
echo "Removing service..."
pkg_service_uninstall "apf"

# Remove cron entries (current + all legacy + runtime-created variants)
echo "Removing cron entries..."
pkg_uninstall_cron \
	/etc/cron.d/apf /etc/cron.d/apf_ipset /etc/cron.d/apf_temp \
	/etc/cron.d/fwdev /etc/cron.daily/apf /etc/cron.daily/fw \
	/etc/cron.hourly/fw \
	/etc/cron.d/refresh.apf /etc/cron.d/apf_develmode \
	/etc/cron.d/ctlimit.apf

# Remove logrotate config
pkg_uninstall_logrotate "apf"

# Remove bash completion
pkg_uninstall_completion "apf"

# Remove symlinks
echo "Removing symlinks..."
pkg_symlink_cleanup "$BINPATH" "$COMPAT_BINPATH"

# Remove man page
echo "Removing man page..."
pkg_uninstall_man "8" "apf"

# Prompt to remove install directory
printf "Remove install directory %s? [y/N] " "$INSTALL_PATH"
read -r _answer
case "$_answer" in
	y|Y|yes|YES)
		command rm -rf "$INSTALL_PATH"
		echo "  Removed $INSTALL_PATH"
		;;
	*)
		echo "  Kept $INSTALL_PATH"
		;;
esac

# Prompt to remove log files
printf "Remove APF log files? [y/N] "
read -r _answer
case "$_answer" in
	y|Y|yes|YES)
		command rm -f /var/log/apf_log /var/log/apf_log.prev
		echo "  Removed log files"
		;;
	*)
		echo "  Kept log files"
		;;
esac

echo ""
echo "APF uninstall complete."
