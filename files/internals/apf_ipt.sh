#!/bin/bash
# shellcheck shell=bash
#
##
# Advanced Policy Firewall (APF) v2.0.2
#             (C) 2002-2026, R-fx Networks <proj@rfxn.com>
#             (C) 2026, Ryan MacDonald <ryan@rfxn.com>
# This program may be freely redistributed under the terms of the GNU GPL v2
##
#
# APF iptables helpers and kernel module loading

# Source guard
[[ -n "${_APF_IPT_LOADED:-}" ]] && return 0 2>/dev/null
_APF_IPT_LOADED=1

# shellcheck disable=SC2034
APF_IPT_VERSION="1.0.0"

## Detect iptables backend (nft vs legacy)
# Sets global IPT_BACKEND to "nft" or "legacy" based on iptables --version output.
# Called by snapshot_save() and fast load path to avoid duplicated detection.
detect_ipt_backend() {
	IPT_BACKEND="legacy"
	if $IPT --version 2>&1 | grep -q nf_tables; then
		IPT_BACKEND="nft"
	fi
}

## Snapshot save: atomic write with integrity validation
# Writes iptables-save output to temp file, validates it, then atomically
# moves into place. Handles both IPv4 and IPv6 (when USE_IPV6=1).
# Also writes the backend marker (.apf.restore.backend).
# Returns 0 on success, 1 on failure (IPv4 failure is fatal to caller;
# IPv6 failure logs warning but does not fail the function).
snapshot_save() {
	local snap_dir="$INSTALL_PATH/internals"
	local snap_tmp snap_rc

	# IPv4 snapshot
	snap_tmp=$(mktemp "$snap_dir/.apf.restore.XXXXXX")
	_apf_reg_tmp "$snap_tmp"
	$IPTS > "$snap_tmp" 2>/dev/null
	snap_rc=$?
	if [ "$snap_rc" -ne 0 ]; then
		eout "{glob} snapshot save failed (iptables-save exit $snap_rc)"
		elog_event "error_occurred" "error" "{glob} snapshot save failed (iptables-save exit $snap_rc)"
		command rm -f "$snap_tmp"
		return 1
	fi
	if [ ! -s "$snap_tmp" ] || ! grep -q '^\*' "$snap_tmp"; then
		eout "{glob} snapshot save failed (empty or invalid output)"
		elog_event "error_occurred" "error" "{glob} snapshot save failed (empty or invalid output)"
		command rm -f "$snap_tmp"
		return 1
	fi
	command mv -f "$snap_tmp" "$snap_dir/.apf.restore"

	# IPv6 snapshot (non-fatal — IPv4 snapshot survives if this fails)
	if [ "$USE_IPV6" == "1" ] && [ -n "$IP6TS" ]; then
		snap_tmp=$(mktemp "$snap_dir/.apf6.restore.XXXXXX")
		_apf_reg_tmp "$snap_tmp"
		$IP6TS > "$snap_tmp" 2>/dev/null
		snap_rc=$?
		if [ "$snap_rc" -ne 0 ]; then
			eout "{glob} IPv6 snapshot save failed (ip6tables-save exit $snap_rc)"
			command rm -f "$snap_tmp"
		elif [ ! -s "$snap_tmp" ] || ! grep -q '^\*' "$snap_tmp"; then
			eout "{glob} IPv6 snapshot save failed (empty or invalid output)"
			command rm -f "$snap_tmp"
		else
			command mv -f "$snap_tmp" "$snap_dir/.apf6.restore"
		fi
	fi

	# Backend marker
	detect_ipt_backend
	echo "$IPT_BACKEND" > "$snap_dir/.apf.restore.backend"
	eout "{glob} fast load snapshot saved (backend: $IPT_BACKEND)"
	return 0
}

## Dual-stack iptables helpers
# ipt()  — apply rule to both IPv4 and IPv6 (protocol-agnostic rules only)
# ipt4() — IPv4 only (explicit)
# ipt6() — IPv6 only when USE_IPV6=1 (explicit)
ipt() {
	$IPT $IPT_FLAGS "$@"
	if [ "$USE_IPV6" == "1" ]; then
		$IP6T $IPT_FLAGS "$@"
	fi
}
ipt4() { $IPT $IPT_FLAGS "$@"; }
ipt6() {
	if [ "$USE_IPV6" == "1" ]; then
		$IP6T $IPT_FLAGS "$@"
	fi
}

# VNET-aware dual-stack helpers for port filtering.
# When VNET is a specific IP (SET_VNET=1), IPv4 gets -d/-s $VNET and IPv6
# applies without address restriction. When VNET is "0/0" (SET_VNET=0),
# both stacks apply without address restriction (0/0 is the default).
ipt_dst() {
	if [ -n "$VNET" ] && [ "$VNET" != "0/0" ]; then
		ipt4 -d "$VNET" "$@"
		ipt6 "$@"
	else
		ipt "$@"
	fi
}
ipt_src() {
	if [ -n "$VNET" ] && [ "$VNET" != "0/0" ]; then
		ipt4 -s "$VNET" "$@"
		ipt6 "$@"
	else
		ipt "$@"
	fi
}

# Route iptables command to correct table based on host address family.
# Sets IPT_H (binary) and ANY_ADDR (0/0 or ::/0) for the caller.
# Returns 1 if IPv6 host but USE_IPV6 is not enabled.
ipt_for_host() {
	if [[ "$1" == *:* ]]; then
		if [ "$USE_IPV6" != "1" ]; then return 1; fi
		IPT_H="$IP6T"
		ANY_ADDR="::/0"
	else
		IPT_H="$IPT"
		ANY_ADDR="0/0"
	fi
	return 0
}

ml() {
 local FATAL="$2"
 local MEXT="ko"

 # Primary: use modprobe --dry-run (handles .ko, .ko.xz, .ko.zst, all paths)
 if $MPB --dry-run "$1" >> /dev/null 2>&1; then
        $MPB $1 >> /dev/null 2>&1 &
        return 0
 fi

 # Fallback: manual path check for systems where --dry-run behaves oddly
 local KMOD
 KMOD="/lib/modules/$(uname -r)/kernel/net"
 local ext subdir
 for ext in "$MEXT" "${MEXT}.xz" "${MEXT}.zst"; do
        for subdir in "ipv4/netfilter" "netfilter"; do
                if [ -f "$KMOD/$subdir/$1.$ext" ]; then
                        $MPB $1 >> /dev/null 2>&1 &
                        return 0
                fi
        done
 done

 # Module not found
 if [ "$FATAL" == "1" ]; then
        if [ "$SET_VERBOSE" != "1" ]; then
                echo "Unable to load iptables module ($1), aborting."
                echo "  On RHEL/Alma/Rocky 10, try: dnf install kernel-modules-extra"
        fi
        eout "{glob} unable to load iptables module ($1), aborting."
        mutex_unlock
        exit 1
 fi
}

modinit() {
 local IPC_VAL modlist mod ip6modlist
 # Remove ipchains module if loaded (kernel 2.4 only)
 if [ "$KREL" == "2.4" ]; then
  IPC_VAL=$($LSM | grep ipchains)
  if [ -n "$IPC_VAL" ]; then
        $RMM ipchains
  fi
 fi
 if [ "$SET_MONOKERN" != "1" ]; then
        # Loading Kernel Modules
        ml ip_tables 1
 fi
	modlist="ip_conntrack ip_conntrack_ftp ip_conntrack_irc iptable_filter iptable_mangle ipt_ecn ipt_length ipt_limit ipt_LOG ipt_mac ipt_multiport ipt_owner ipt_recent ipt_REJECT ipt_state ipt_TCPMSS ipt_TOS ipt_ttl ipt_ULOG nf_conntrack nf_conntrack_ftp nf_conntrack_irc xt_connlimit xt_conntrack xt_conntrack_ftp xt_conntrack_irc xt_ecn xt_length xt_limit xt_LOG xt_mac xt_multiport xt_owner xt_recent xt_REJECT xt_state xt_TCPMSS xt_TOS xt_ttl xt_ULOG"
	for mod in $modlist; do
		ml $mod
	done

	# ipset modules (non-fatal)
	if [ "$USE_IPSET" == "1" ]; then
		ml ip_set
		ml xt_set
	fi

	# IPv6 modules (non-fatal; nft backend handles both protocols natively)
	if [ "$USE_IPV6" == "1" ]; then
		if [ ! -f "/proc/net/ip6_tables_names" ]; then
			# Legacy backend: load IPv6 modules explicitly
			ip6modlist="ip6_tables ip6table_filter ip6table_mangle nf_conntrack_ipv6"
			for mod in $ip6modlist; do
				ml $mod
			done
		fi
	fi
}
