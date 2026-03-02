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

echo "APF Uninstaller"
echo ""

# Stop the firewall if running
if [ -x "$INSTALL_PATH/apf" ]; then
	echo "Stopping firewall..."
	"$INSTALL_PATH/apf" --flush 2>/dev/null || true
fi

# Remove systemd service
if [ -f "/etc/systemd/system/apf.service" ]; then
	echo "Removing systemd service..."
	systemctl stop apf.service 2>/dev/null || true
	systemctl disable apf.service 2>/dev/null || true
	rm -f /etc/systemd/system/apf.service
	systemctl daemon-reload 2>/dev/null || true
fi

# Remove SysV init scripts
if [ -f "/etc/rc.d/init.d/apf" ]; then
	echo "Removing SysV init script (rc.d)..."
	if command -v chkconfig > /dev/null 2>&1; then
		chkconfig --del apf 2>/dev/null || true
	fi
	rm -f /etc/rc.d/init.d/apf
fi
if [ -f "/etc/init.d/apf" ]; then
	echo "Removing SysV init script (init.d)..."
	rm -f /etc/init.d/apf
fi

# Remove rc.local entry
if [ -f "/etc/rc.local" ]; then
	if grep -q "apf" /etc/rc.local 2>/dev/null; then
		echo "Removing rc.local entry..."
		grep -v "apf" /etc/rc.local > /tmp/.apf_rclocal_clean
		cat /tmp/.apf_rclocal_clean > /etc/rc.local
		rm -f /tmp/.apf_rclocal_clean
	fi
fi

# Remove cron entries (current + all legacy + runtime-created variants)
echo "Removing cron entries..."
rm -f /etc/cron.d/apf /etc/cron.d/apf_ipset /etc/cron.d/apf_temp
rm -f /etc/cron.d/fwdev /etc/cron.daily/apf /etc/cron.daily/fw
rm -f /etc/cron.hourly/fw
rm -f /etc/cron.d/refresh.apf /etc/cron.d/apf_develmode

# Remove logrotate config
if [ -f "/etc/logrotate.d/apf" ]; then
	echo "Removing logrotate config..."
	rm -f /etc/logrotate.d/apf
fi

# Remove symlinks
if [ -L "$BINPATH" ]; then
	echo "Removing $BINPATH symlink..."
	rm -f "$BINPATH"
fi
if [ -L "$COMPAT_BINPATH" ]; then
	echo "Removing $COMPAT_BINPATH symlink..."
	rm -f "$COMPAT_BINPATH"
fi

# Remove man page
if [ -f "/usr/share/man/man8/apf.8.gz" ]; then
	echo "Removing man page..."
	rm -f /usr/share/man/man8/apf.8.gz
fi

# Prompt to remove install directory
printf "Remove install directory %s? [y/N] " "$INSTALL_PATH"
read -r _answer
case "$_answer" in
	y|Y|yes|YES)
		rm -rf "$INSTALL_PATH"
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
		rm -f /var/log/apf_log /var/log/apf_log.prev
		echo "  Removed log files"
		;;
	*)
		echo "  Kept log files"
		;;
esac

echo ""
echo "APF uninstall complete."
