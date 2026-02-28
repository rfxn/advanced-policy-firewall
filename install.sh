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

cd "$(dirname "$0")" || { echo "Error: cannot cd to script directory"; exit 1; }
[ -f "files/VERSION" ] || { echo "Error: source files not found — run install.sh from the APF source directory"; exit 1; }

install() {
        mkdir -p "$INSTALL_PATH" || { echo "Error: cannot create $INSTALL_PATH"; exit 1; }
        cp -fR files/* "$INSTALL_PATH" || { echo "Error: file copy failed"; exit 1; }
        if [ "$INSTALL_PATH" != "/etc/apf" ]; then
                grep -rl '/etc/apf' "$INSTALL_PATH" 2>/dev/null | while IFS= read -r f; do
                        sed -i "s:/etc/apf:$INSTALL_PATH:g" "$f"
                done
        fi
        find "$INSTALL_PATH" -type d -exec chmod 750 {} +
        find "$INSTALL_PATH" -type f -exec chmod 640 {} +
        chmod 750 "$INSTALL_PATH/apf"
        chmod 750 "$INSTALL_PATH/firewall"
        chmod 750 "$INSTALL_PATH/vnet/vnetgen"
	chmod 750 "$INSTALL_PATH/extras/get_ports"
	cp -pf .ca.def importconf "$INSTALL_PATH/extras/"
	mkdir -p "$INSTALL_PATH/doc"
	cp README CHANGELOG COPYING.GPL apf.8 FLOW "$INSTALL_PATH/doc"
        ln -fs "$INSTALL_PATH/apf" "$BINPATH"
        ln -fs "$INSTALL_PATH/apf" "$COMPAT_BINPATH"
	rm -f /etc/cron.hourly/fw /etc/cron.daily/fw /etc/cron.d/fwdev "$INSTALL_PATH/cron.fwdev"
	# Clean up legacy cron entries (pre-2.0.2 used separate files)
	rm -f /etc/cron.daily/apf /etc/cron.d/apf_ipset /etc/cron.d/apf_temp
	# Consolidated cron: daily restart, hourly ipset refresh, per-minute temp expiry
	if [ -d "/etc/cron.d" ] && [ -f "cron.d.apf" ]; then
		cp cron.d.apf /etc/cron.d/apf
		chmod 644 /etc/cron.d/apf
		if [ "$INSTALL_PATH" != "/etc/apf" ]; then
			sed -i "s:/etc/apf:$INSTALL_PATH:g" /etc/cron.d/apf
		fi
	fi
	# Service installation: prefer systemd, then SysV init, then rc.local
	if [ -d "/run/systemd/system" ]; then
		cp -f apf.service /etc/systemd/system/apf.service
		if [ "$INSTALL_PATH" != "/etc/apf" ]; then
			sed -i "s:/etc/apf:$INSTALL_PATH:g" /etc/systemd/system/apf.service
		fi
		systemctl daemon-reload
		systemctl enable apf.service >> /dev/null 2>&1
	elif [ -d "/etc/rc.d/init.d" ]; then
		cp -f apf.init /etc/rc.d/init.d/apf
		if [ "$INSTALL_PATH" != "/etc/apf" ]; then
			sed -i "s:/etc/apf:$INSTALL_PATH:g" /etc/rc.d/init.d/apf
		fi
		if [ -f "/sbin/chkconfig" ]; then
			/sbin/chkconfig --add apf
			/sbin/chkconfig --level 345 apf on
		fi
	elif [ -d "/etc/init.d" ]; then
		cp -f apf.init /etc/init.d/apf
		if [ "$INSTALL_PATH" != "/etc/apf" ]; then
			sed -i "s:/etc/apf:$INSTALL_PATH:g" /etc/init.d/apf
		fi
	else
		if [ -f "/etc/rc.local" ]; then
			val=$(grep -i apf /etc/rc.local)
			if [ -z "$val" ]; then
				echo "$INSTALL_PATH/apf -s >> /dev/null 2>&1" >> /etc/rc.local
			fi
		fi
	fi
	if [ -f "/var/log/apf_log" ]; then
		mv -f /var/log/apf_log /var/log/apf_log.prev
	fi
	rm -f /var/log/apfados_log
	if [ -d "/etc/logrotate.d" ] && [ -f "logrotate.d.apf" ]; then
		cp logrotate.d.apf /etc/logrotate.d/apf
	fi
	# Install man page
	if [ -d "/usr/share/man/man8" ] && [ -f "apf.8" ]; then
		cp apf.8 /usr/share/man/man8/apf.8
		if [ "$INSTALL_PATH" != "/etc/apf" ]; then
			sed -i "s:/etc/apf:$INSTALL_PATH:g" /usr/share/man/man8/apf.8
		fi
		gzip -f /usr/share/man/man8/apf.8
		chmod 644 /usr/share/man/man8/apf.8.gz
	fi
	"$INSTALL_PATH/vnet/vnetgen" 2>/dev/null
	if [ -f "/usr/bin/dialog" ] && [ -d "$INSTALL_PATH/extras/apf-m" ]; then
		last=$(pwd)
		cd "$INSTALL_PATH/extras/apf-m/"
		sh install -i
		cd "$last"
	fi
	chmod 750 "$INSTALL_PATH"
}

detect_iface() {
	local iface=""
	local ip_bin
	ip_bin=$(command -v ip 2>/dev/null)
	if [ -n "$ip_bin" ]; then
		iface=$($ip_bin route show default 2>/dev/null | awk '/^default/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1); exit}')
	fi
	if [ -z "$iface" ] && command -v route > /dev/null 2>&1; then
		iface=$(route -n 2>/dev/null | awk '/^0\.0\.0\.0/ {print $NF; exit}')
	fi
	echo "$iface"
}

show_iface_info() {
	local default_iface other_ifaces ip_bin
	default_iface=$(detect_iface)
	ip_bin=$(command -v ip 2>/dev/null)
	if [ -n "$default_iface" ]; then
		echo "  Default interface:    $default_iface"
	else
		echo "  Default interface:    (not detected — no default route found)"
		echo "  Note: Set IFACE_UNTRUSTED manually in $INSTALL_PATH/conf.apf"
	fi
	if [ -n "$ip_bin" ]; then
		other_ifaces=$($ip_bin -o link show up 2>/dev/null | awk -F': ' '{print $2}' | sed 's/@.*//' | grep -v '^lo$' | grep -v "^${default_iface}$" | sort -u | paste -sd ',' -)
		if [ -n "$other_ifaces" ]; then
			echo "  Other interfaces:     $other_ifaces"
		fi
	fi
}

VER=$(awk '/version/ {print$2}' files/VERSION)
if [ -d "$INSTALL_PATH" ]; then
	DVAL=$(date +"%d%m%Y-%s")
	cp -R "$INSTALL_PATH" "$INSTALL_PATH.bk$DVAL" || { echo "Backup failed, aborting."; exit 1; }
	rm -f "$INSTALL_PATH.bk.last"
	ln -fs "$INSTALL_PATH.bk$DVAL" "${INSTALL_PATH}.bk.last"
	echo -n "Installing APF $VER: "
	install
else
        echo -n "Installing APF $VER: "
	install
fi

echo "Completed."
echo ""
echo "Installation Details:"
echo "  Install path:         $INSTALL_PATH/"
echo "  Config path:          $INSTALL_PATH/conf.apf"
echo "  Executable path:      $BINPATH"
if [ -f "/usr/share/man/man8/apf.8.gz" ]; then
	echo "  Man page:             /usr/share/man/man8/apf.8.gz"
fi
echo ""
echo "Other Details:"
if [ -d "$INSTALL_PATH.bk.last" ]; then
	./importconf
	show_iface_info
	. "$INSTALL_PATH/extras/get_ports"
	echo "  Note: Please review $INSTALL_PATH/conf.apf for consistency, install default backed up to $INSTALL_PATH/conf.apf.orig"
else
	# Auto-detect default network interface on fresh install
	_detected_iface=$(detect_iface)
	if [ -n "$_detected_iface" ] && [ "$_detected_iface" != "eth0" ]; then
		sed -i "s/^IFACE_UNTRUSTED=\"eth0\"/IFACE_UNTRUSTED=\"$_detected_iface\"/" "$INSTALL_PATH/conf.apf"
	fi
	show_iface_info
	if [ -n "$_detected_iface" ] && [ "$_detected_iface" != "eth0" ]; then
		echo "                        (set as IFACE_UNTRUSTED)"
	fi
	. "$INSTALL_PATH/extras/get_ports"
	echo "  Note: These ports are not auto-configured; they are simply presented for information purposes. You must manually configure all port options."
fi

# Post-install dependency warnings (non-fatal for chroot/container builds)
_dep_warn=0
if ! command -v iptables > /dev/null 2>&1; then
	_dep_warn=1
	echo ""
	echo "  WARNING: iptables not found in PATH"
	if command -v apt-get > /dev/null 2>&1; then
		echo "           Install with: apt-get install iptables"
	elif command -v dnf > /dev/null 2>&1; then
		echo "           Install with: dnf install iptables"
	elif command -v yum > /dev/null 2>&1; then
		echo "           Install with: yum install iptables"
	fi
fi
if ! command -v ip > /dev/null 2>&1; then
	_dep_warn=1
	echo ""
	echo "  WARNING: ip (iproute2) not found in PATH"
	if command -v apt-get > /dev/null 2>&1; then
		echo "           Install with: apt-get install iproute2"
	elif command -v dnf > /dev/null 2>&1; then
		echo "           Install with: dnf install iproute"
	elif command -v yum > /dev/null 2>&1; then
		echo "           Install with: yum install iproute"
	fi
fi
if ! command -v modprobe > /dev/null 2>&1; then
	_dep_warn=1
	echo ""
	echo "  WARNING: modprobe (kmod) not found in PATH"
	if command -v apt-get > /dev/null 2>&1; then
		echo "           Install with: apt-get install kmod"
	elif command -v dnf > /dev/null 2>&1; then
		echo "           Install with: dnf install kmod"
	elif command -v yum > /dev/null 2>&1; then
		echo "           Install with: yum install kmod"
	fi
fi
if [ "$_dep_warn" = "1" ]; then
	echo ""
	echo "  Note: Missing dependencies must be installed before running APF."
	echo "        This is expected in chroot/container builds where binaries"
	echo "        will be available at runtime."
fi

rm -f .conf.apf
