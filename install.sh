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

if [ "$(id -u)" != "0" ]; then
	echo "Error: install.sh must be run as root"
	exit 1
fi

# Source shared packaging library
# shellcheck disable=SC1091
. "files/internals/pkg_lib.sh"

# Configure pkg_lib backup to use copy method (APF keeps original in place)
# shellcheck disable=SC2034 # consumed by pkg_lib.sh pkg_backup()
PKG_BACKUP_METHOD="copy"

install() {
	mkdir -p "$INSTALL_PATH" || { pkg_error "cannot create $INSTALL_PATH"; exit 1; }

	# Copy source files to install path
	pkg_copy_tree "files" "$INSTALL_PATH" || { pkg_error "file copy failed"; exit 1; }

	# Create GeoIP data cache directory
	mkdir -p "$INSTALL_PATH/geoip"

	# Replace hardcoded paths when installing to a custom location
	if [ "$INSTALL_PATH" != "/etc/apf" ]; then
		# shellcheck disable=SC2046
		pkg_sed_replace "/etc/apf" "$INSTALL_PATH" \
			$(grep -rl '/etc/apf' "$INSTALL_PATH" 2>/dev/null)
	fi

	# Set file permissions: dirs=750, files=640, executables=750
	pkg_set_perms "$INSTALL_PATH" "750" "640" \
		"apf" "firewall" "vnet/vnetgen" "extras/get_ports"

	# Copy extras (importconf)
	command cp -pf importconf "$INSTALL_PATH/extras/"

	# Install documentation to doc/ subdirectory
	pkg_doc_install "$INSTALL_PATH/doc" README.md CHANGELOG COPYING.GPL apf.8 FLOW

	# Create binary symlinks
	pkg_symlink "$INSTALL_PATH/apf" "$BINPATH"
	pkg_symlink "$INSTALL_PATH/apf" "$COMPAT_BINPATH"

	# Clean up legacy cron entries (ancient + pre-2.0.2 variants)
	pkg_cron_remove /etc/cron.hourly/fw /etc/cron.daily/fw /etc/cron.d/fwdev
	command rm -f "$INSTALL_PATH/cron.fwdev"
	pkg_cron_remove /etc/cron.daily/apf /etc/cron.d/apf_ipset /etc/cron.d/apf_temp

	# Install consolidated cron: daily restart, hourly ipset refresh, per-minute temp expiry
	if [ -d "/etc/cron.d" ] && [ -f "cron.d.apf" ]; then
		pkg_cron_install "cron.d.apf" "/etc/cron.d/apf"
		if [ "$INSTALL_PATH" != "/etc/apf" ]; then
			pkg_sed_replace "/etc/apf" "$INSTALL_PATH" "/etc/cron.d/apf"
		fi
	fi

	# Bash tab completion
	if [ -f "apf.bash-completion" ]; then
		pkg_bash_completion "apf.bash-completion" "apf"
		if [ "$INSTALL_PATH" != "/etc/apf" ]; then
			pkg_sed_replace "/etc/apf" "$INSTALL_PATH" /etc/bash_completion.d/apf
		fi
	fi

	# Service installation: systemd unit or SysV init script
	pkg_detect_init
	if [ "$_PKG_INIT_SYSTEM" = "systemd" ]; then
		pkg_service_install "apf" "apf.service"
		if [ "$INSTALL_PATH" != "/etc/apf" ]; then
			local _unit_dir
			_unit_dir=$(_pkg_systemd_unit_dir)
			pkg_sed_replace "/etc/apf" "$INSTALL_PATH" "${_unit_dir}/apf.service"
		fi
		pkg_service_enable "apf"
	elif [ -d "/etc/rc.d/init.d" ] || [ -d "/etc/init.d" ]; then
		pkg_service_install "apf" "apf.init"
		local _init_path
		_init_path=$(_pkg_init_script_path "apf") || true
		if [ -n "${_init_path:-}" ] && [ "$INSTALL_PATH" != "/etc/apf" ]; then
			pkg_sed_replace "/etc/apf" "$INSTALL_PATH" "$_init_path"
		fi
		pkg_service_enable "apf"
	else
		# Fallback: rc.local entry
		pkg_rclocal_add "$INSTALL_PATH/apf -s >> /dev/null 2>&1"
	fi

	# Disable conflicting firewall services (firewalld, ufw)
	# These manage iptables/nftables independently and conflict with APF
	_disable_conflicting_service "firewalld"
	_disable_conflicting_service "ufw"

	# Rotate old log file
	if [ -f "/var/log/apf_log" ]; then
		command mv -f /var/log/apf_log /var/log/apf_log.prev
	fi
	command rm -f /var/log/apfados_log

	# Install logrotate config
	if [ -f "logrotate.d.apf" ]; then
		pkg_logrotate_install "logrotate.d.apf" "apf"
	fi

	# Install man page (with path replacement if custom install path)
	if [ -f "apf.8" ]; then
		if [ "$INSTALL_PATH" != "/etc/apf" ]; then
			pkg_man_install "apf.8" "8" "apf" "/etc/apf|$INSTALL_PATH"
		else
			pkg_man_install "apf.8" "8" "apf"
		fi
	fi

	# Generate VNET rules
	"$INSTALL_PATH/vnet/vnetgen" 2>/dev/null  # safe: may fail in containers without interfaces

	# Install apf-m menu system if dialog is available
	if [ -f "/usr/bin/dialog" ] && [ -d "$INSTALL_PATH/extras/apf-m" ]; then
		(cd "$INSTALL_PATH/extras/apf-m/" && sh install -i)
	fi

	chmod 750 "$INSTALL_PATH"
}

# _disable_conflicting_service name — stop and disable a conflicting service
# Only acts if the service is currently active (running).
_disable_conflicting_service() {
	local _svc="$1"
	if command -v systemctl > /dev/null 2>&1; then
		if systemctl is-active "$_svc" > /dev/null 2>&1; then
			pkg_service_stop "$_svc" 2>/dev/null  # safe: best-effort
			pkg_service_disable "$_svc" 2>/dev/null  # safe: best-effort
			echo "  Note: $_svc was active and has been stopped and disabled."
			echo "        APF manages iptables directly; $_svc cannot coexist."
		fi
	fi
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
# Pre-install cleanup: remove runtime-created cron entries before backup
# These are recreated by apf -s as needed; must happen before backup to
# ensure cleanup even if backup step fails (e.g., rapid re-installs)
pkg_cron_remove /etc/cron.d/refresh.apf /etc/cron.d/apf_develmode /etc/cron.d/ctlimit.apf

if [ -d "$INSTALL_PATH" ]; then
	pkg_backup "$INSTALL_PATH" "copy" || { echo "Backup failed, aborting."; exit 1; }
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
if pkg_backup_exists "$INSTALL_PATH"; then
	BK_LAST=$(pkg_backup_path "$INSTALL_PATH") ./importconf
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
pkg_check_dep "iptables" "iptables" "iptables" "recommended" || _dep_warn=1
pkg_check_dep "ip" "iproute" "iproute2" "recommended" || _dep_warn=1
pkg_check_dep "modprobe" "kmod" "kmod" "recommended" || _dep_warn=1
if [ "$_dep_warn" = "1" ]; then
	echo ""
	echo "  Note: Missing dependencies must be installed before running APF."
	echo "        This is expected in chroot/container builds where binaries"
	echo "        will be available at runtime."
fi
