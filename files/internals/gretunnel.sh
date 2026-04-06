#!/bin/bash
#
##
# Advanced Policy Firewall (APF) v2.0.2
#             (C) 2002-2026, R-fx Networks <proj@rfxn.com>
#             (C) 2026, Ryan MacDonald <ryan@rfxn.com>
# This program may be freely redistributed under the terms of the GNU GPL v2
##
#
# GRE tunnel management functions -- sourced by internals.conf

create_gretun() {
	local linkid="$1"
	local routefrom="$2"
	local routeto="$3"
	local ipfile="$4"
	local _cg_int='^[0-9]+$'

	# Validate linkid: must be integer 1-99
	if ! [[ "$linkid" =~ $_cg_int ]]; then
		eout "{gre} error: linkid '$linkid' is not a valid integer"
		unset gre_keepalive gre_mtu gre_ttl gre_key
		return 1
	fi
	if [ "$linkid" -lt 1 ] || [ "$linkid" -gt 99 ]; then
		eout "{gre} error: linkid must be 1-99, got '$linkid'"
		unset gre_keepalive gre_mtu gre_ttl gre_key
		return 1
	fi

	# Validate IPs (GRE requires IP addresses, not hostnames)
	if [ -z "$routefrom" ] || [ -z "$routeto" ]; then
		eout "{gre} error: routefrom and routeto are required"
		unset gre_keepalive gre_mtu gre_ttl gre_key
		return 1
	fi
	if ! valid_ip_cidr "$routefrom"; then
		eout "{gre} error: invalid routefrom IP address '$routefrom'"
		unset gre_keepalive gre_mtu gre_ttl gre_key
		return 1
	fi
	if ! valid_ip_cidr "$routeto"; then
		eout "{gre} error: invalid routeto IP address '$routeto'"
		unset gre_keepalive gre_mtu gre_ttl gre_key
		return 1
	fi

	# Validate role
	if [ "$role" != "source" ] && [ "$role" != "target" ]; then
		eout "{gre} error: role must be 'source' or 'target', got '$role'"
		unset gre_keepalive gre_mtu gre_ttl gre_key
		return 1
	fi

	# Validate ipfile if specified
	if [ -n "$ipfile" ] && [ ! -f "$ipfile" ]; then
		eout "{gre} error: ipfile '$ipfile' does not exist"
		unset gre_keepalive gre_mtu gre_ttl gre_key
		return 1
	fi

	local linkname="gre${linkid}"
	local greip_src="192.168.${linkid}.1"
	local greip_dst="192.168.${linkid}.2"

	# Resolve per-tunnel overrides with fallback to global config
	local ttl="${gre_ttl:-$GRE_TTL}"
	local mtu="${gre_mtu:-$GRE_MTU}"
	local ka="${gre_keepalive:-$GRE_KEEPALIVE}"
	local key="${gre_key:-}"

	# Validate key as integer if specified
	if [ -n "$key" ] && ! [[ "$key" =~ $_cg_int ]]; then
		eout "{gre} error: invalid key '$key' (must be integer)"
		unset gre_keepalive gre_mtu gre_ttl gre_key
		return 1
	fi

	# Determine local/remote and tunnel IP based on role
	local local_ip remote_ip greip greip_peer
	if [ "$role" == "source" ]; then
		local_ip="$routefrom"
		remote_ip="$routeto"
		greip="$greip_src"
		greip_peer="$greip_dst"
	else
		local_ip="$routeto"
		remote_ip="$routefrom"
		greip="$greip_dst"
		greip_peer="$greip_src"
	fi

	# Create tunnel interface if it doesn't already exist (idempotent)
	if ! $ip link show "$linkname" >/dev/null 2>&1; then  # safe: probe whether interface exists
		if [ -n "$key" ]; then
			$ip tunnel add "$linkname" mode gre remote "$remote_ip" local "$local_ip" ttl "$ttl" key "$key"
		else
			$ip tunnel add "$linkname" mode gre remote "$remote_ip" local "$local_ip" ttl "$ttl"
		fi
		if [ $? -ne 0 ]; then
			eout "{gre} error: failed to create tunnel $linkname"
			unset gre_keepalive gre_mtu gre_ttl gre_key
			return 1
		fi
		if ! $ip link set "$linkname" up; then
			eout "{gre} error: failed to bring up tunnel $linkname"
			unset gre_keepalive gre_mtu gre_ttl gre_key
			return 1
		fi
		$ip addr add "$greip/32" peer "$greip_peer/32" dev "$linkname"
		eout "{gre} tunnel $linkname created: local=$local_ip remote=$remote_ip"
	else
		eout "{gre} tunnel $linkname already exists, skipping interface creation"
	fi

	# MTU: auto-calculate if empty
	if [ -z "$mtu" ]; then
		local parent_mtu
		parent_mtu=$($ip link show "$IFACE_UNTRUSTED" 2>/dev/null | grep -o 'mtu [0-9]*' | awk '{print $2}')  # safe: interface may not exist yet
		if [ -n "$parent_mtu" ]; then
			mtu=$((parent_mtu - 24))
		else
			mtu=1476
		fi
	fi
	$ip link set "$linkname" mtu "$mtu"
	eout "{gre} tunnel $linkname mtu set to $mtu"

	# Keepalive
	local ka_int ka_ret
	read -r ka_int ka_ret <<< "$ka"
	ka_ret="${ka_ret:-3}"
	if [ "$ka_int" != "0" ] || [ "$ka_ret" != "0" ]; then
		$ip tunnel change "$linkname" keepalive "$ka_int" "$ka_ret" 2>/dev/null || true  # safe: keepalive may not be supported on older kernels
		eout "{gre} tunnel $linkname keepalive set to ${ka_int}s ${ka_ret} retries"
	fi

	# Firewall rules: protocol 47 (GRE) and interface accept
	ipt4 -A GRE_IN -p 47 -s "$remote_ip" -j ACCEPT
	ipt4 -A GRE_OUT -p 47 -d "$remote_ip" -j ACCEPT
	ipt4 -A GRE_IN -i "$linkname" -j ACCEPT
	ipt4 -A GRE_OUT -o "$linkname" -j ACCEPT
	eout "{gre} firewall rules added for $linkname"

	# Role-specific setup
	if [ "$role" == "source" ]; then
		local routedif routedgw
		routedif=$($ip route show default 2>/dev/null | awk '{print $5; exit}')  # safe: no default route on isolated hosts
		routedgw=$($ip route show default 2>/dev/null | awk '{print $3; exit}')  # safe: no default route on isolated hosts

		if [ -n "$routedif" ]; then
			sysctl -w "net.ipv4.conf.${routedif}.proxy_arp=1" >/dev/null 2>&1  # safe: sysctl warnings non-fatal
		fi
		sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1  # safe: sysctl warnings non-fatal

		if [ -n "$ipfile" ] && [ -f "$ipfile" ]; then
			local ARPING
			ARPING=$(command -v arping 2>/dev/null)  # safe: arping may not be installed
			while IFS= read -r routedip; do
				case "$routedip" in
					\#*|"") continue ;;
				esac
				if ! valid_ip_cidr "$routedip"; then
					eout "{gre} skipping invalid ip: $routedip"
					continue
				fi
				$ip route add "$routedip" via "$greip_peer" dev "$linkname" 2>/dev/null || true  # safe: route may already exist
				if [ -n "$ARPING" ] && [ -n "$routedif" ] && [ -n "$routedgw" ]; then
					$ARPING -I "$routedif" -s "$routedip" "$routedgw" -c1 >/dev/null 2>&1 || true  # safe: gratuitous ARP may fail on non-broadcast interfaces
				fi
				eout "{gre} source route: $routedip via $greip_peer dev $linkname"
			done < "$ipfile"
		fi
	elif [ "$role" == "target" ]; then
		sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1  # safe: sysctl warnings non-fatal
		sysctl -w "net.ipv4.conf.${linkname}.rp_filter=0" >/dev/null 2>&1  # safe: sysctl warnings non-fatal

		if [ -n "$ipfile" ] && [ -f "$ipfile" ]; then
			while IFS= read -r routedip; do
				case "$routedip" in
					\#*|"") continue ;;
				esac
				if ! valid_ip_cidr "$routedip"; then
					eout "{gre} skipping invalid ip: $routedip"
					continue
				fi
				$ip addr add "$routedip/32" dev "$linkname" 2>/dev/null || true  # safe: address may already exist on interface
				eout "{gre} target bind: $routedip on $linkname"
			done < "$ipfile"
		fi
	fi

	# Track active tunnel
	echo "$linkid" >> "$INSTALL_PATH/internals/.gre.tunnels"

	# Cleanup per-tunnel overrides
	unset gre_keepalive gre_mtu gre_ttl gre_key
}

destroy_gretun() {
	local linkid="$1"
	local linkname="gre${linkid}"
	$ip link set "$linkname" down 2>/dev/null  # safe: tunnel may not exist during teardown
	$ip tunnel del "$linkname" 2>/dev/null  # safe: tunnel may not exist during teardown
	eout "{gre} tunnel $linkname destroyed"
}

gre_init() {
	if [ "$USE_GRE" != "1" ] || [ -z "$ip" ]; then
		return
	fi

	# Load GRE kernel module (non-fatal)
	ml ip_gre

	# Create chains (idempotent — safe if already exists from prior apf -s)
	if ! $IPT $IPT_FLAGS -L GRE_IN -n >/dev/null 2>&1; then  # safe: probe chain existence
		ipt4 -N GRE_IN
		ipt4 -A INPUT -j GRE_IN
	fi
	if ! $IPT $IPT_FLAGS -L GRE_OUT -n >/dev/null 2>&1; then  # safe: probe chain existence
		ipt4 -N GRE_OUT
		ipt4 -A OUTPUT -j GRE_OUT
	fi

	# Clear tracking file
	> "$INSTALL_PATH/internals/.gre.tunnels"

	# Source tunnel definitions
	if [ -f "$INSTALL_PATH/gre.rules" ]; then
		. "$INSTALL_PATH/gre.rules"
	fi

	eout "{gre} tunnel initialization complete"
}

_gre_remove_chains() {
	if $IPT $IPT_FLAGS -L GRE_IN -n >/dev/null 2>&1; then  # safe: probe chain existence
		ipt4 -D INPUT -j GRE_IN 2>/dev/null || true  # safe: rule may not exist if chain is inactive
		ipt4 -F GRE_IN
		ipt4 -X GRE_IN
	fi
	if $IPT $IPT_FLAGS -L GRE_OUT -n >/dev/null 2>&1; then  # safe: probe chain existence
		ipt4 -D OUTPUT -j GRE_OUT 2>/dev/null || true  # safe: rule may not exist if chain is inactive
		ipt4 -F GRE_OUT
		ipt4 -X GRE_OUT
	fi
}

gre_flush() {
	if [ "$USE_GRE" != "1" ]; then
		return
	fi

	_gre_remove_chains

	# Tear down interfaces if not persistent
	if [ "$GRE_PERSIST" != "1" ]; then
		gre_teardown
	fi
}

gre_teardown() {
	local tracking="$INSTALL_PATH/internals/.gre.tunnels"
	if [ -f "$tracking" ]; then
		while IFS= read -r linkid; do
			[ -z "$linkid" ] && continue
			destroy_gretun "$linkid"
		done < "$tracking"
		> "$tracking"
	fi

	_gre_remove_chains

	eout "{gre} all tunnels torn down"
}

gre_status() {
	if [ -z "$ip" ]; then
		echo "Error: ip command not found"
		return 1
	fi

	echo "=== GRE Tunnel Interfaces ==="
	$ip -d tunnel show mode gre 2>/dev/null || echo "  (none or not supported)"  # safe: kernel may lack GRE support
	echo ""

	local tracking="$INSTALL_PATH/internals/.gre.tunnels"
	if [ -f "$tracking" ] && [ -s "$tracking" ]; then
		echo "=== Tunnel Addresses ==="
		while IFS= read -r linkid; do
			[ -z "$linkid" ] && continue
			local linkname="gre${linkid}"
			$ip addr show "$linkname" 2>/dev/null || echo "  $linkname: not found"  # safe: tunnel may have been destroyed
		done < "$tracking"
		echo ""
	fi

	echo "=== GRE Routes ==="
	$ip route show 2>/dev/null | grep gre || echo "  (none)"  # safe: no routes if no GRE tunnels active
	echo ""

	echo "=== GRE Firewall Rules ==="
	if [ -n "$IPT" ]; then
		$IPT $IPT_FLAGS -L GRE_IN -nv 2>/dev/null || echo "  GRE_IN chain: not found"  # safe: chain absent when GRE disabled
		echo ""
		$IPT $IPT_FLAGS -L GRE_OUT -nv 2>/dev/null || echo "  GRE_OUT chain: not found"  # safe: chain absent when GRE disabled
	fi
}

## Dispatch: apf gre <verb> [args]
_dispatch_gre() {
	case "${1:-}" in
	-h|--help) _gre_help ;;
	""|status) gre_status ;;
	up)
		if [ "$USE_GRE" == "1" ]; then
			mutex_lock; gre_init
		else
			echo "GRE tunnels not enabled (USE_GRE=0 in conf.apf)"
		fi
		;;
	down)
		if [ "$USE_GRE" == "1" ]; then
			mutex_lock; gre_teardown
		else
			echo "GRE tunnels not enabled (USE_GRE=0 in conf.apf)"
		fi
		;;
	*)  _cli_unknown_verb "apf gre" "$1" "up down status"; return 1 ;;
	esac
}

_gre_help() {
	echo "usage: apf gre <command>"
	echo ""
	echo "  up                     bring up GRE tunnels"
	echo "  down                   tear down GRE tunnels"
	echo "  status                 show GRE tunnel status"
	echo ""
	echo "  Examples:  apf gre up"
	echo "             apf gre status"
}
