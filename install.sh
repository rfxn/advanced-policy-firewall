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

if [ "$(id -u)" != "0" ]; then
	echo "Error: install.sh must be run as root"
	exit 1
fi

[ -f "files/VERSION" ] || { echo "Error: source files not found — run install.sh from the APF source directory"; exit 1; }

# Source shared packaging library
# shellcheck disable=SC1091
. "files/internals/pkg_lib.sh"

# Configure pkg_lib backup to use copy method (APF keeps original in place)
# shellcheck disable=SC2034 # consumed by pkg_lib.sh pkg_backup()
PKG_BACKUP_METHOD="copy"

install() {
	command mkdir -p "$INSTALL_PATH" || { pkg_error "cannot create $INSTALL_PATH"; exit 1; }

	# Convert RPM/DEB FHS symlink farm to flat layout before copying:
	# RPM/DEB ship extras/doc as dir symlinks into /usr/lib/apf and
	# /usr/share/doc/apf, plus per-file symlinks in internals/ and
	# vnet/vnetgen. cp -pR cannot overwrite a symlink-to-dir with a
	# directory; per-file symlinks would silently write through and
	# corrupt the package-managed copies under /usr/lib/apf.
	_migrate_fhs_symlinks "$INSTALL_PATH"

	# Copy source files to install path
	pkg_copy_tree "files" "$INSTALL_PATH" || { pkg_error "file copy failed"; exit 1; }

	# Clean up files from pre-decomposition layout (2.0.2 upgrade)
	command rm -f "$INSTALL_PATH/firewall"
	command rm -f "$INSTALL_PATH/internals/functions.apf"
	command rm -f "$INSTALL_PATH/internals/geoip.apf"
	command rm -f "$INSTALL_PATH/internals/ctlimit.apf"

	# Create GeoIP data cache directory
	command mkdir -p "$INSTALL_PATH/geoip"

	# Replace hardcoded paths when installing to a custom location
	if [ "$INSTALL_PATH" != "/etc/apf" ]; then
		# shellcheck disable=SC2046
		pkg_sed_replace "/etc/apf" "$INSTALL_PATH" \
			$(grep -rl '/etc/apf' "$INSTALL_PATH" 2>/dev/null)
	fi

	# Set file permissions: dirs=750, files=640, executables=750
	pkg_set_perms "$INSTALL_PATH" "750" "640" \
		"apf" "vnet/vnetgen" "extras/get_ports"

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
	pkg_bash_completion "apf.bash-completion" "apf"
	if [ "$INSTALL_PATH" != "/etc/apf" ]; then
		pkg_sed_replace "/etc/apf" "$INSTALL_PATH" /etc/bash_completion.d/apf
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
		_init_path=$(_pkg_init_script_path "apf") || true  # safe: init path may not exist on systemd-only hosts
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

	command chmod 750 "$INSTALL_PATH"
}

# _migrate_fhs_symlinks path — remove RPM/DEB FHS symlink farm under path
# Targets only symlinks pointing into /usr/lib/apf or /usr/share/doc/apf,
# leaving any user-created symlinks intact.
_migrate_fhs_symlinks() {
	local _root="$1"
	local _migrated=0
	local _entry _path _target _link
	for _entry in extras doc vnet/vnetgen; do
		_path="${_root}/${_entry}"
		[ -L "$_path" ] || continue
		_target=$(readlink "$_path" 2>/dev/null)  # readlink may fail on broken symlinks
		case "$_target" in
			/usr/lib/apf/*|/usr/share/doc/apf*)
				command rm -f "$_path"
				_migrated=1
				;;
		esac
	done
	if [ -d "${_root}/internals" ]; then
		while IFS= read -r _link; do
			_target=$(readlink "$_link" 2>/dev/null)  # readlink may fail on broken symlinks
			case "$_target" in
				/usr/lib/apf/*)
					command rm -f "$_link"
					_migrated=1
					;;
			esac
		done < <(find "${_root}/internals" -maxdepth 1 -type l)
	fi
	if [ "$_migrated" = "1" ]; then
		pkg_info "Migrated RPM/DEB symlink farm to install.sh layout"
	fi
}

# _disable_conflicting_service name — stop and disable a conflicting service
# Only acts if the service is currently active (running).
_disable_conflicting_service() {
	local _svc="$1"
	if command -v systemctl > /dev/null 2>&1; then
		if systemctl is-active "$_svc" > /dev/null 2>&1; then
			pkg_service_stop "$_svc" 2>/dev/null  # safe: best-effort
			pkg_service_disable "$_svc" 2>/dev/null  # safe: best-effort
			pkg_info "$_svc was active — stopped and disabled"
			pkg_info "APF manages iptables directly; $_svc cannot coexist"
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
		pkg_item "Default interface" "$default_iface"
	else
		pkg_item "Default interface" "(not detected)"
		pkg_info "Set IFACE_UNTRUSTED manually in $INSTALL_PATH/conf.apf"
	fi
	if [ -n "$ip_bin" ]; then
		other_ifaces=$($ip_bin -o link show up 2>/dev/null | awk -F': ' '{print $2}' | sed 's/@.*//' | grep -v '^lo$' | grep -v "^${default_iface}$" | sort -u | paste -sd ',' -)
		if [ -n "$other_ifaces" ]; then
			pkg_item "Other interfaces" "$other_ifaces"
		fi
	fi
}

postinfo() {
	echo ""
	pkg_item "Install path" "$INSTALL_PATH"
	pkg_item "Config" "$INSTALL_PATH/conf.apf"
	pkg_item "Executable" "$BINPATH"
	if [ -f "/usr/share/man/man8/apf.8.gz" ]; then
		pkg_item "Man page" "/usr/share/man/man8/apf.8.gz"
	fi
	show_iface_info
	. "$INSTALL_PATH/extras/get_ports"
}

# _check_deps — non-fatal dependency warnings for chroot/container builds
_check_deps() {
	local _dep_warn=0
	pkg_check_dep "iptables" "iptables" "iptables" "recommended" || _dep_warn=1
	pkg_check_dep "ip" "iproute" "iproute2" "recommended" || _dep_warn=1
	pkg_check_dep "modprobe" "kmod" "kmod" "recommended" || _dep_warn=1
	if [ "$_dep_warn" = "1" ]; then
		echo ""
		pkg_info "Missing dependencies must be installed before running APF."
		pkg_info "This is expected in chroot/container builds where binaries"
		pkg_info "will be available at runtime."
	fi
}

VER=$(awk '/version/ {print$2}' files/VERSION)
# Pre-install cleanup: remove runtime-created cron entries before backup
# These are recreated by apf -s as needed; must happen before backup to
# ensure cleanup even if backup step fails (e.g., rapid re-installs)
pkg_cron_remove /etc/cron.d/refresh.apf /etc/cron.d/apf_develmode /etc/cron.d/ctlimit.apf

if [ -d "$INSTALL_PATH" ]; then
	# --- Upgrade path ---
	pkg_header "APF" "$VER" "upgrade"
	pkg_section "Backing up existing installation"
	pkg_backup "$INSTALL_PATH" "copy" || { pkg_error "backup failed, aborting."; exit 1; }
	pkg_section "Installing files"
	install
	pkg_section "Importing configuration"
	BK_LAST=$(pkg_backup_path "$INSTALL_PATH") ./importconf
	postinfo
	pkg_info "Review $INSTALL_PATH/conf.apf for consistency"
	pkg_info "Install default backed up to $INSTALL_PATH/conf.apf.orig"
	_check_deps

	# Re-create runtime cron entries from imported config (pre-install cleanup
	# removed them; they are normally created by apf -s but the upgrade does
	# not restart the firewall)
	if [ -d "/etc/cron.d" ]; then
		_int_re='^[0-9]+$'
		_sr=$(pkg_config_get "$INSTALL_PATH/conf.apf" "SET_REFRESH") || _sr=""
		if [[ "$_sr" =~ $_int_re ]] && [ "$_sr" != "0" ]; then
command cat<<EOF > "$INSTALL_PATH/internals/cron.refresh"
*/$_sr * * * * root $INSTALL_PATH/apf --refresh >> /dev/null 2>&1
EOF
			command chmod 644 "$INSTALL_PATH/internals/cron.refresh"
			command ln -fs "$INSTALL_PATH/internals/cron.refresh" /etc/cron.d/refresh.apf
		fi
		_ct=$(pkg_config_get "$INSTALL_PATH/conf.apf" "CT_LIMIT") || _ct=""
		if [[ "$_ct" =~ $_int_re ]] && [ "$_ct" != "0" ]; then
			_ci=$(pkg_config_get "$INSTALL_PATH/conf.apf" "CT_INTERVAL") || _ci=""
			[[ "$_ci" =~ $_int_re ]] || _ci=30
			_ci=$(( _ci / 60 ))
			[ "$_ci" -lt 1 ] && _ci=1
command cat<<EOF > "$INSTALL_PATH/internals/cron.ctlimit"
*/$_ci * * * * root $INSTALL_PATH/apf --ct-scan >> /dev/null 2>&1
EOF
			command chmod 644 "$INSTALL_PATH/internals/cron.ctlimit"
			command ln -fs "$INSTALL_PATH/internals/cron.ctlimit" /etc/cron.d/ctlimit.apf
		fi
	fi

	pkg_success "APF ${VER} upgrade complete"
	pkg_info "Tab completion updated — reload with: . /etc/bash_completion.d/apf"
else
	# --- Fresh install path ---
	pkg_header "APF" "$VER" "install"
	pkg_section "Installing files"
	install
	# Auto-detect default network interface
	_detected_iface=$(detect_iface)
	if [ -n "$_detected_iface" ] && [ "$_detected_iface" != "eth0" ]; then
		sed -i "s/^IFACE_UNTRUSTED=\"eth0\"/IFACE_UNTRUSTED=\"$_detected_iface\"/" "$INSTALL_PATH/conf.apf"
	fi
	postinfo
	if [ -n "${_detected_iface:-}" ] && [ "$_detected_iface" != "eth0" ]; then
		pkg_info "Auto-configured IFACE_UNTRUSTED=$_detected_iface"
	fi
	pkg_info "Ports shown for reference only — configure manually in conf.apf"
	_check_deps
	pkg_success "APF ${VER} installation complete"
	pkg_info "Tab completion available — reload with: . /etc/bash_completion.d/apf"
fi
