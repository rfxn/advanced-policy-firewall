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
# APF trust system: trust parsing, CLI operations, block escalation,
# temp entry management, trust file loading, refresh cycle

# Source guard
[[ -n "${_APF_TRUST_LOADED:-}" ]] && return 0 2>/dev/null  # safe: return outside function context is benign
_APF_TRUST_LOADED=1

# shellcheck disable=SC2034
APF_TRUST_VERSION="1.0.0"

## Trust parsing and rule generation

trust_protect_ipv6() {
	# Protect bracketed IPv6 in advanced trust entries from colon-splitting
	# Input:  "d=22:s=[2001:db8::1]"  Output: "d=22:s=2001@db8@@1"
	# Result in _TPV6_RESULT (variable-return, no subshell)
	local entry="$1"
	case "$entry" in
		*\[*\]*)
			local ipv6="${entry#*\[}"
			ipv6="${ipv6%%\]*}"
			local safe="${ipv6//:/@}"
			_TPV6_RESULT="${entry/\[$ipv6\]/$safe}"
			;;
		*)
			_TPV6_RESULT="$entry"
			;;
	esac
}

trust_restore_ipv6() {
	# Restore @ placeholders back to colons after awk field extraction
	# Result in _TRV6_RESULT (variable-return, no subshell)
	_TRV6_RESULT="${1//@/:}"
}

trust_parse_fields() {
	# Split advanced trust entry on ':' and '=' into positional fields
	# Input: "d=22:s=10.0.0.1" → _TF1=d _TF2=22 _TF3=s _TF4=10.0.0.1
	local IFS=':='
	set -f  # disable glob expansion for unquoted $1 split
	set -- $1
	set +f
	_TF_COUNT=$#
	_TF1="${1:-}"; _TF2="${2:-}"; _TF3="${3:-}"
	_TF4="${4:-}"; _TF5="${5:-}"; _TF6="${6:-}"
}

# Unpack advanced trust entry fields from trust_parse_fields() globals.
# Caller must have called trust_protect_ipv6(entry) and
# trust_parse_fields($_TPV6_RESULT) before invoking this helper.
# Sets _TUF_PROTO, _TUF_DIR, _TUF_PFLOW, _TUF_PORT, _TUF_IPFLOW, _TUF_PIP.
# Returns 1 on unrecognized token count.
_trust_unpack_fields() {
	_TUF_PROTO=""
	_TUF_DIR=""
	_TUF_PFLOW=""
	_TUF_PORT=""
	_TUF_IPFLOW=""
	_TUF_PIP=""
	case "$_TF_COUNT" in
		4)
			_TUF_PFLOW="$_TF1"; _TUF_PORT="$_TF2"
			_TUF_IPFLOW="$_TF3"
			trust_restore_ipv6 "$_TF4"; _TUF_PIP="$_TRV6_RESULT"
			;;
		5)
			_TUF_DIR="$_TF1"; _TUF_PFLOW="$_TF2"
			_TUF_PORT="$_TF3"; _TUF_IPFLOW="$_TF4"
			trust_restore_ipv6 "$_TF5"; _TUF_PIP="$_TRV6_RESULT"
			;;
		6)
			_TUF_PROTO="$_TF1"; _TUF_DIR="$_TF2"
			_TUF_PFLOW="$_TF3"; _TUF_PORT="$_TF4"
			_TUF_IPFLOW="$_TF5"
			trust_restore_ipv6 "$_TF6"; _TUF_PIP="$_TRV6_RESULT"
			;;
		*)
			return 1
			;;
	esac
	return 0
}

# Validate an advanced trust entry (contains '=') or delegate to valid_host().
# Sets _VTE_IP to the extracted IP for local-addr checks.
# Returns 0 on valid, 1 on invalid.
valid_trust_entry() {
	local entry="$1"
	if [[ "$entry" != *=* ]]; then
		_VTE_IP="$entry"
		valid_host "$entry"
		return $?
	fi
	trust_protect_ipv6 "$entry"; local safe="$_TPV6_RESULT"
	# Reject glob metacharacters after IPv6 bracket removal — never valid in trust syntax
	case "$safe" in
		*[\*\?\[]*) return 1 ;;
	esac
	trust_parse_fields "$safe"
	_trust_unpack_fields || return 1
	local proto="$_TUF_PROTO" dir="$_TUF_DIR" pflow="$_TUF_PFLOW"
	local port="$_TUF_PORT" ipflow="$_TUF_IPFLOW" pip="$_TUF_PIP"
	# Validate protocol if present
	if [ -n "$proto" ]; then
		[ "$proto" == "tcp" ] || [ "$proto" == "udp" ] || return 1
	fi
	# Validate direction if present
	if [ -n "$dir" ]; then
		[ "$dir" == "in" ] || [ "$dir" == "out" ] || return 1
	fi
	# Validate port flow
	[ "$pflow" == "s" ] || [ "$pflow" == "d" ] || return 1
	# Validate port (numeric or underscore range)
	local _vte_ppat='^[0-9_]+$'
	[[ "$port" =~ $_vte_ppat ]] || return 1
	# Validate IP flow
	[ "$ipflow" == "s" ] || [ "$ipflow" == "d" ] || return 1
	# Validate IP address
	valid_host "$pip" || return 1
	_VTE_IP="$pip"
	return 0
}

# Generate iptables rule(s) for an advanced trust entry.
# Args: $1=entry $2=chain $3=action(ALLOW/DENY) $4=mode(-I/-A/-D)
# Sets _TER_IP (extracted IP) and _TER_DESC (description for logging).
# Returns 1 on parse failure.
trust_entry_rule() {
	local entry="$1" chain="$2" action="$3" mode="$4"
	local action_tcp action_udp
	if [ "$action" == "DENY" ]; then
		action_tcp="$TCP_STOP"; action_udp="$UDP_STOP"
	else
		action_tcp="ACCEPT"; action_udp="ACCEPT"
	fi

	trust_protect_ipv6 "$entry"; local safe="$_TPV6_RESULT"
	trust_parse_fields "$safe"
	_trust_unpack_fields || return 1
	local proto="$_TUF_PROTO" dir="$_TUF_DIR" pflow="$_TUF_PFLOW"
	local port="$_TUF_PORT" ipflow="$_TUF_IPFLOW" pip="$_TUF_PIP"

	expand_port "$port"; port="$_PORT"
	if ! ipt_for_host "$pip"; then
		return 1
	fi
	_TER_IP="$pip"

	# Build port flow flag
	local pflag
	if [ "$pflow" == "s" ]; then pflag="sport"; else pflag="dport"; fi

	# Build description
	local proto_desc="${proto:+$proto }"
	local dir_desc=""
	[ "$dir" == "in" ] && dir_desc="inbound "
	[ "$dir" == "out" ] && dir_desc="outbound "
	local flow_desc
	if [ "$pflow" == "d" ]; then flow_desc="to"; else flow_desc="from"; fi
	_TER_DESC="${dir_desc}${proto_desc}${pip} ${flow_desc} port ${port}"

	# Build rule string(s)
	local _ter_r1 _ter_r2=""
	if [ -n "$proto" ]; then
		local jtarget
		if [ "$proto" == "tcp" ]; then jtarget="$action_tcp"; else jtarget="$action_udp"; fi
		_ter_r1="$mode $chain -p $proto -m multiport -$ipflow $pip --$pflag $port -j $jtarget"
	else
		_ter_r1="$mode $chain -p tcp -m multiport -$ipflow $pip --$pflag $port -j $action_tcp"
		_ter_r2="$mode $chain -p udp -m multiport -$ipflow $pip --$pflag $port -j $action_udp"
	fi

	# Apply: buffer for batch restore or execute immediately
	if [ -n "$_TER_BUFFER_MODE" ]; then
		if [ "$IPT_H" == "$IP6T" ]; then
			_th_rf6="${_th_rf6}${_ter_r1}
"
			[ -n "$_ter_r2" ] && _th_rf6="${_th_rf6}${_ter_r2}
"
		else
			_th_rf4="${_th_rf4}${_ter_r1}
"
			[ -n "$_ter_r2" ] && _th_rf4="${_th_rf4}${_ter_r2}
"
		fi
	else
		# shellcheck disable=SC2086
		$IPT_H $IPT_FLAGS $_ter_r1
		# shellcheck disable=SC2086
		[ -n "$_ter_r2" ] && $IPT_H $IPT_FLAGS $_ter_r2
	fi
	return 0
}

## Address resolution

load_local_addrs() {
	# Cache local address files into _LOCAL_ADDRS for is_local_addr() lookups
	_LOCAL_ADDRS=""
	[ -f "$INSTALL_PATH/internals/.localaddrs" ] && \
		_LOCAL_ADDRS=$(< "$INSTALL_PATH/internals/.localaddrs")
	[ -f "$INSTALL_PATH/internals/.localaddrs6" ] && \
		_LOCAL_ADDRS="$_LOCAL_ADDRS"$'\n'"$(< "$INSTALL_PATH/internals/.localaddrs6")"
}

is_local_addr() {
	local line
	while IFS= read -r line; do
		[ "$line" = "$1" ] && return 0
	done <<< "$_LOCAL_ADDRS"
	return 1
}

# Resolve FQDN to IP addresses via getent ahosts.
# Sets _RESOLVED_IPS (newline-separated unique IPs).
# Returns 1 on failure (timeout, no results, missing tools).
resolve_fqdn() {
	local host="$1"
	_RESOLVED_IPS=""
	if [ -z "$GETENT" ]; then
		eout "{trust} getent not available, cannot resolve FQDN $host"
		return 1
	fi
	local raw
	if [ -n "$TIMEOUT" ]; then
		raw=$($TIMEOUT "$FQDN_TIMEOUT" $GETENT ahosts "$host" 2>/dev/null)  # safe: DNS resolution may fail
	else
		raw=$($GETENT ahosts "$host" 2>/dev/null)  # safe: DNS resolution may fail
	fi
	# Fallback: getent hosts (catches IPv6-only entries where ahosts may fail)
	if [ -z "$raw" ]; then
		if [ -n "$TIMEOUT" ]; then
			raw=$($TIMEOUT "$FQDN_TIMEOUT" $GETENT hosts "$host" 2>/dev/null)  # safe: DNS resolution may fail
		else
			raw=$($GETENT hosts "$host" 2>/dev/null)  # safe: DNS resolution may fail
		fi
	fi
	if [ -z "$raw" ]; then
		return 1
	fi
	# Extract unique IPs, filter by address family
	local ip seen=""
	while read -r ip _; do
		# Deduplicate
		case "$seen" in *"|$ip|"*) continue ;; esac
		seen="${seen}|$ip|"
		# Filter IPv6 when disabled
		if [[ "$ip" == *:* ]]; then
			[ "$USE_IPV6" != "1" ] && continue
		fi
		if [ -z "$_RESOLVED_IPS" ]; then
			_RESOLVED_IPS="$ip"
		else
			_RESOLVED_IPS="$_RESOLVED_IPS"$'\n'"$ip"
		fi
	done <<< "$raw"
	[ -n "$_RESOLVED_IPS" ] || return 1
	return 0
}

## Trust CLI operations

# Resolve FQDN to IPs using trust file metadata or live resolution.
# Sets global: _FQDN_RESOLVED_IPS (comma-separated)
_resolve_fqdn_metadata() {
	local fqdn="$1"
	_FQDN_RESOLVED_IPS=""
	local _rfm_rline
	for f in "$ALLOW_HOSTS" "$DENY_HOSTS" "$GALLOW_HOSTS" "$GDENY_HOSTS"; do
		[ -f "$f" ] || continue
		_rfm_rline=$(grep -F "resolved=" "$f" 2>/dev/null | grep -F "$fqdn" | head -n1)  # safe: file read may race with deletion
		if [ -n "$_rfm_rline" ]; then
			_FQDN_RESOLVED_IPS="${_rfm_rline##*resolved=}"
			_FQDN_RESOLVED_IPS="${_FQDN_RESOLVED_IPS%% *}"
			return 0
		fi
	done
	if resolve_fqdn "$fqdn"; then
		_FQDN_RESOLVED_IPS="${_RESOLVED_IPS//$'\n'/,}"
		return 0
	fi
	return 1
}

# Delete iptables rules for a specific IP across all trust chains.
# Modifies caller's `found` variable (set to 1 when any rule is deleted).
_trust_remove_ip_rules() {
	local ip="$1"
	if ! ipt_for_host "$ip"; then return; fi
	$IPT_H $IPT_FLAGS -D INPUT -s "$ip" -j ACCEPT 2>/dev/null && found=1  # safe: rule may not exist if chain is inactive
	$IPT_H $IPT_FLAGS -D OUTPUT -d "$ip" -j ACCEPT 2>/dev/null && found=1  # safe: rule may not exist if chain is inactive
	$IPT_H $IPT_FLAGS -D INPUT -s "$ip" -j $ALL_STOP 2>/dev/null && found=1  # safe: rule may not exist if chain is inactive
	$IPT_H $IPT_FLAGS -D OUTPUT -d "$ip" -j $ALL_STOP 2>/dev/null && found=1  # safe: rule may not exist if chain is inactive
	$IPT_H $IPT_FLAGS -D TALLOW -s "$ip" -j ACCEPT 2>/dev/null && found=1  # safe: rule may not exist if chain is inactive
	$IPT_H $IPT_FLAGS -D TALLOW -d "$ip" -j ACCEPT 2>/dev/null && found=1  # safe: rule may not exist if chain is inactive
	$IPT_H $IPT_FLAGS -D TDENY -s "$ip" -j $ALL_STOP 2>/dev/null && found=1  # safe: rule may not exist if chain is inactive
	$IPT_H $IPT_FLAGS -D TDENY -d "$ip" -j $ALL_STOP 2>/dev/null && found=1  # safe: rule may not exist if chain is inactive
	$IPT_H $IPT_FLAGS -D TGALLOW -s "$ip" -j ACCEPT 2>/dev/null && found=1  # safe: rule may not exist if chain is inactive
	$IPT_H $IPT_FLAGS -D TGALLOW -d "$ip" -j ACCEPT 2>/dev/null && found=1  # safe: rule may not exist if chain is inactive
	$IPT_H $IPT_FLAGS -D TGDENY -s "$ip" -j $ALL_STOP 2>/dev/null && found=1  # safe: rule may not exist if chain is inactive
	$IPT_H $IPT_FLAGS -D TGDENY -d "$ip" -j $ALL_STOP 2>/dev/null && found=1  # safe: rule may not exist if chain is inactive
	# Spec-based cleanup for any remaining rules referencing this IP
	local _ctr_chain _ctr_rule _ctr_spec
	for _ctr_chain in INPUT OUTPUT TALLOW TDENY TGALLOW TGDENY; do
		while IFS= read -r _ctr_rule; do
			[ -z "$_ctr_rule" ] && continue
			_ctr_spec="${_ctr_rule#-A $_ctr_chain }"
			# shellcheck disable=SC2086
			$IPT_H $IPT_FLAGS -D "$_ctr_chain" $_ctr_spec 2>/dev/null && found=1  # safe: rule may not exist
		done < <($IPT_H $IPT_FLAGS -S "$_ctr_chain" 2>/dev/null | grep -w -- "$ip")  # safe: chain may not exist
	done
}

# Remove advanced trust entries containing a host and their iptables rules.
# Modifies caller's `found` variable.
_trust_remove_advanced_entries() {
	local host="$1"
	local _ctr_adv_entry
	for f in "$ALLOW_HOSTS" "$DENY_HOSTS" "$GALLOW_HOSTS" "$GDENY_HOSTS"; do
		[ -f "$f" ] || continue
		while IFS= read -r _ctr_adv_entry; do
			[ -z "$_ctr_adv_entry" ] && continue
			cli_trust_remove "$_ctr_adv_entry" >> /dev/null 2>&1 && found=1
		done < <(grep -v '^#' "$f" | grep '=' | grep -Fw "$host")
	done
}

cli_trust_remove() {
	local DIP="$1"
	if [ -z "$DIP" ]; then
		echo "an FQDN or IP address is required for this option" >&2
		return 1
	fi

	# Advanced syntax removal
	if [[ "$DIP" == *=* ]]; then
		# Check if last field is a country code → delegate to apf_geoip.sh
		local _ctr_last_field="${DIP##*=}"
		if valid_cc "$_ctr_last_field" || [[ "$_ctr_last_field" == @* ]]; then
			# shellcheck disable=SC1090,SC1091
			. "$INSTALL_PATH/internals/apf_geoip.sh"
			if [[ "$_ctr_last_field" == @* ]]; then
				cli_cc_remove "$_ctr_last_field"
			else
				cli_cc_remove_entry "$DIP" "$_ctr_last_field"
			fi
			return $?
		fi
		if ! valid_trust_entry "$DIP"; then
			echo "Invalid trust entry '$DIP'" >&2
			local _abbr_cidr='^[0-9]+/[0-9]+$'
			if [[ "${DIP##*=}" =~ $_abbr_cidr ]]; then
				echo "  Hint: abbreviated CIDR (e.g. '0/0') is not valid; use full notation (e.g. '0.0.0.0/0')" >&2
			fi
			return 1
		fi
		local found=0
		if is_fqdn "$_VTE_IP"; then
			_resolve_fqdn_metadata "$_VTE_IP"
			local _ctr_rip _ctr_resolved_entry
			for _ctr_rip in ${_FQDN_RESOLVED_IPS//,/ }; do
				_ctr_resolved_entry="${DIP//$_VTE_IP/$_ctr_rip}"
				trust_entry_rule "$_ctr_resolved_entry" "TALLOW" "ALLOW" "-D" 2>/dev/null && found=1  # safe: rule may not exist if chain is inactive
				trust_entry_rule "$_ctr_resolved_entry" "TDENY" "DENY" "-D" 2>/dev/null && found=1  # safe: rule may not exist if chain is inactive
				trust_entry_rule "$_ctr_resolved_entry" "TGALLOW" "ALLOW" "-D" 2>/dev/null && found=1  # safe: rule may not exist if chain is inactive
				trust_entry_rule "$_ctr_resolved_entry" "TGDENY" "DENY" "-D" 2>/dev/null && found=1  # safe: rule may not exist if chain is inactive
			done
		else
			trust_entry_rule "$DIP" "TALLOW" "ALLOW" "-D" 2>/dev/null && found=1  # safe: rule may not exist if chain is inactive
			trust_entry_rule "$DIP" "TDENY" "DENY" "-D" 2>/dev/null && found=1  # safe: rule may not exist if chain is inactive
			trust_entry_rule "$DIP" "TGALLOW" "ALLOW" "-D" 2>/dev/null && found=1  # safe: rule may not exist if chain is inactive
			trust_entry_rule "$DIP" "TGDENY" "DENY" "-D" 2>/dev/null && found=1  # safe: rule may not exist if chain is inactive
		fi
		# Remove exact entry + associated comment from trust files
		local escaped_entry
		escaped_entry=$(echo "$DIP" | sed 's/[.\/\[\]]/\\&/g')
		for f in "$ALLOW_HOSTS" "$DENY_HOSTS" "$GALLOW_HOSTS" "$GDENY_HOSTS"; do
			[ -f "$f" ] || continue
			if grep -Fq "$DIP" "$f" 2>/dev/null; then  # safe: entry may not exist in file
				found=1
			fi
			sed -i "\%# added ${escaped_entry} %d" "$f"
			sed -i "\%^${escaped_entry}$%d" "$f"
		done
		if [ "$found" == "0" ]; then
			return 1
		fi
		return 0
	fi

	if ! valid_host "$DIP"; then
		# Not a valid host — check if it's a country code
		if valid_cc "$DIP" || [[ "$DIP" == @* ]]; then
			# shellcheck disable=SC1090,SC1091
			. "$INSTALL_PATH/internals/apf_geoip.sh"
			cli_cc_remove "$DIP"
			return $?
		fi
		echo "Invalid host '$DIP': must be a valid IP/IPv6 address, CIDR block, FQDN, or country code" >&2
		local _abbr_cidr='^[0-9]+/[0-9]+$'
		if [[ "$DIP" =~ $_abbr_cidr ]]; then
			echo "  Hint: abbreviated CIDR (e.g. '0/0') is not valid; use full notation (e.g. '0.0.0.0/0')" >&2
		fi
		return 1
	fi

	local found=0

	if is_fqdn "$DIP"; then
		_resolve_fqdn_metadata "$DIP"
		local _ctr_rip
		for _ctr_rip in ${_FQDN_RESOLVED_IPS//,/ }; do
			_trust_remove_ip_rules "$_ctr_rip"
		done
		# Remove FQDN + comment from trust files
		local escaped_fqdn="${DIP//./\\.}"
		if grep -q -- "^${escaped_fqdn}$" "$ALLOW_HOSTS" "$DENY_HOSTS" "$GALLOW_HOSTS" "$GDENY_HOSTS" 2>/dev/null; then  # safe: some trust files may not exist
			found=1
		fi
		sed -i "\%# added ${escaped_fqdn} %d" "$ALLOW_HOSTS" "$DENY_HOSTS" "$GALLOW_HOSTS" "$GDENY_HOSTS"
		sed -i "\%^${escaped_fqdn}$%d" "$ALLOW_HOSTS" "$DENY_HOSTS" "$GALLOW_HOSTS" "$GDENY_HOSTS"
		_trust_remove_advanced_entries "$DIP"
	else
		# IP/CIDR removal
		if ! ipt_for_host "$DIP"; then
			echo "Cannot remove '$DIP': IPv6 address but USE_IPV6 is not enabled" >&2
			return 1
		fi
		_trust_remove_ip_rules "$DIP"
		# Check trust files for entry before removing
		local escaped_ip="${DIP//./\\.}"
		if grep -q -- "^${escaped_ip}\b" "$ALLOW_HOSTS" "$DENY_HOSTS" "$GALLOW_HOSTS" "$GDENY_HOSTS" 2>/dev/null; then  # safe: some trust files may not exist
			found=1
		fi
		sed -i "\%^${escaped_ip}\b%d" "$ALLOW_HOSTS" "$DENY_HOSTS" "$GALLOW_HOSTS" "$GDENY_HOSTS"
		_trust_remove_advanced_entries "$DIP"
	fi

	# Remove comment lines referencing the FQDN/IP (covers resolved= metadata)
	local escaped_dip="${DIP//./\\.}"
	sed -i "\%# added ${escaped_dip} %d" "$ALLOW_HOSTS" "$DENY_HOSTS" "$GALLOW_HOSTS" "$GDENY_HOSTS"

	if [ "$found" == "0" ]; then
		return 1
	fi
	return 0
}

# Set JACTION from ACTION (DENY→ALL_STOP, ALLOW→ACCEPT) in caller scope
_trust_action_target() {
	if [ "$ACTION" == "DENY" ]; then
		JACTION="$ALL_STOP"
	elif [ "$ACTION" == "ALLOW" ]; then
		JACTION="ACCEPT"
	fi
}

# Write a trust entry (comment + data line) to a trust file.
# Centralizes the comment format for cli_trust() and cli_trust_temp().
# Args: host file comment [extra_key=val ...]
# Extra args are appended to metadata (e.g., ttl=N expire=E resolved=IPs).
_cli_trust_write_entry() {
	local host="$1" file="$2" comment="$3"
	shift 3
	local TIME ADDED_EPOCH CMT="$comment"
	TIME=$(date +"%D %H:%M:%S")
	ADDED_EPOCH=$(date +%s)
	_sanitize_comment
	local meta="addedtime=$ADDED_EPOCH"
	local _wte_arg
	for _wte_arg in "$@"; do
		[ -n "$_wte_arg" ] && meta="$meta $_wte_arg"
	done
	if [ -n "$CMT" ]; then
		echo "# added $host on $TIME $meta with comment: $CMT" >> "$file"
	else
		echo "# added $host on $TIME $meta" >> "$file"
	fi
	echo "$host" >> "$file"
}

# Resolve FQDN to IPs and check that none resolve to a local address.
# Sets _RESOLVED_IPS on success (newline-separated).
# Returns 0 (success), 1 (resolve failed), 2 (resolves to local addr).
_cli_trust_resolve_fqdn() {
	local host="$1"
	if ! resolve_fqdn "$host"; then
		echo "Failed to resolve FQDN '$host'" >&2
		return 1
	fi
	local _crf_rip
	while IFS= read -r _crf_rip; do
		if is_local_addr "$_crf_rip"; then
			echo "$host resolves to local address $_crf_rip and can not be added to the trust system" >&2
			return 2
		fi
	done <<< "$_RESOLVED_IPS"
	return 0
}

## Check if a trust entry already exists in any trust file.
# Sets caller's $tlist to space-separated list of files containing the entry.
# Args: host_entry
_trust_check_duplicate() {
	local _tcd_host="$1" _tcd_f
	tlist=""
	for _tcd_f in $DENY_HOSTS $ALLOW_HOSTS $GALLOW_HOSTS $GDENY_HOSTS; do
		if [ -f "$_tcd_f" ] && grep -v '^#' "$_tcd_f" | grep -Fxq "$_tcd_host"; then
			tlist="$tlist$_tcd_f "
		fi
	done
}

cli_trust() {
 local CHAIN="$1" ACTION="$2" FILE="$3" HOST="$4" CMT="$5"
 local tlist f JACTION
 if [ -z "$HOST" ]; then
        echo "an FQDN or IP address is required for this option" >&2
        return 1
 fi

 # Advanced trust syntax (contains '=')
 if [[ "$HOST" == *=* ]]; then
	# Check if last field is a country code → delegate to apf_geoip.sh
	local _ct_last_field="${HOST##*=}"
	if valid_cc "$_ct_last_field" || [[ "$_ct_last_field" == @* ]]; then
		# shellcheck disable=SC1090,SC1091
		. "$INSTALL_PATH/internals/apf_geoip.sh"
		cli_cc_trust_advanced "$HOST" "$CHAIN" "$ACTION" "$FILE" "$CMT"
		return $?
	fi
	if ! valid_trust_entry "$HOST"; then
		echo "Invalid trust entry '$HOST'" >&2
		local _abbr_cidr='^[0-9]+/[0-9]+$'
		if [[ "${HOST##*=}" =~ $_abbr_cidr ]]; then
			echo "  Hint: abbreviated CIDR (e.g. '0/0') is not valid; use full notation (e.g. '0.0.0.0/0')" >&2
		fi
		return 1
	fi
	_trust_check_duplicate "$HOST"
	load_local_addrs
	if [ -n "$tlist" ]; then
		echo "$HOST already exists in $tlist"
	elif is_fqdn "$_VTE_IP"; then
		# Advanced syntax with FQDN — resolve before iptables
		local _ct_rc=0
		_cli_trust_resolve_fqdn "$_VTE_IP" || _ct_rc=$?
		if [ "$_ct_rc" -eq 1 ]; then return 1; fi
		if [ "$_ct_rc" -eq 0 ]; then
			local _ct_csv="${_RESOLVED_IPS//$'\n'/,}"
			_cli_trust_write_entry "$HOST" "$FILE" "$CMT" "resolved=$_ct_csv"
			local _ct_rip _ct_resolved_entry
			while IFS= read -r _ct_rip; do
				# Substitute FQDN with resolved IP in entry
				_ct_resolved_entry="${HOST//$_VTE_IP/$_ct_rip}"
				if trust_entry_rule "$_ct_resolved_entry" "$CHAIN" "$ACTION" "-I"; then
					eout "{trust} added $ACTION $_TER_DESC (resolved from $_VTE_IP)"
					if [ "$SET_VERBOSE" != "1" ]; then
						echo "Inserted into firewall: $ACTION $_TER_DESC"
					fi
				fi
			done <<< "$_RESOLVED_IPS"
			elog_event "trust_added" "info" "{trust} added $ACTION $_TER_DESC" \
				"host=$HOST" "action=$ACTION"
		fi
	elif is_local_addr "$_VTE_IP"; then
		echo "$_VTE_IP is a local address and can not be added to the trust system" >&2
	else
		_cli_trust_write_entry "$HOST" "$FILE" "$CMT"
		if trust_entry_rule "$HOST" "$CHAIN" "$ACTION" "-I"; then
			eout "{trust} added $ACTION $_TER_DESC"
			elog_event "trust_added" "info" "{trust} added $ACTION $_TER_DESC" \
				"host=$HOST" "action=$ACTION"
			if [ "$SET_VERBOSE" != "1" ]; then
				echo "Inserted into firewall: $ACTION $_TER_DESC"
			fi
		else
			echo "Failed to insert rule for '$HOST'" >&2
			return 1
		fi
	fi
	return 0
 fi

 # Bare host path (IP/CIDR/FQDN or country code)
 if ! valid_host "$HOST"; then
	# Not a valid host — check if it's a country code
	if valid_cc "$HOST" || [[ "$HOST" == @* ]]; then
		# shellcheck disable=SC1090,SC1091
		. "$INSTALL_PATH/internals/apf_geoip.sh"
		cli_cc_trust "$HOST" "$CHAIN" "$ACTION" "$FILE" "$CMT"
		return $?
	fi
	echo "Invalid host '$HOST': must be a valid IP/IPv6 address, CIDR block, FQDN, or country code" >&2
	local _abbr_cidr='^[0-9]+/[0-9]+$'
	if [[ "$HOST" =~ $_abbr_cidr ]]; then
		echo "  Hint: abbreviated CIDR (e.g. '0/0') is not valid; use full notation (e.g. '0.0.0.0/0')" >&2
	fi
	return 1
 fi
 _trust_check_duplicate "$HOST"
 load_local_addrs
 if [ "$tlist" ]; then
         echo "$HOST already exists in $tlist"
 elif is_fqdn "$HOST"; then
	# FQDN — resolve before iptables
	local _ct_rc=0
	_cli_trust_resolve_fqdn "$HOST" || _ct_rc=$?
	if [ "$_ct_rc" -eq 1 ]; then return 1; fi
	if [ "$_ct_rc" -eq 0 ]; then
		local _ct_csv="${_RESOLVED_IPS//$'\n'/,}"
		_cli_trust_write_entry "$HOST" "$FILE" "$CMT" "resolved=$_ct_csv"
		_trust_action_target
		local _ct_rip
		while IFS= read -r _ct_rip; do
			if ipt_for_host "$_ct_rip"; then
				$IPT_H $IPT_FLAGS -I $CHAIN -s "$_ct_rip" -j $JACTION
				$IPT_H $IPT_FLAGS -I $CHAIN -d "$_ct_rip" -j $JACTION
			fi
		done <<< "$_RESOLVED_IPS"
		eout "{trust} added $ACTION all to/from $HOST (resolved: $_ct_csv)"
		elog_event "trust_added" "info" "{trust} added $ACTION all to/from $HOST" \
			"host=$HOST" "action=$ACTION" "resolved=$_ct_csv"
		if [ "$SET_VERBOSE" != "1" ]; then
			echo "Inserted into firewall: $ACTION all to/from $HOST (resolved: $_ct_csv)"
		fi
	fi
 elif is_local_addr "$HOST"; then
         echo "$HOST is a local address and can not be added to the trust system" >&2
 elif ! ipt_for_host "$HOST"; then
         echo "$HOST appears to be IPv6 but USE_IPV6 is not enabled" >&2
 else
	_cli_trust_write_entry "$HOST" "$FILE" "$CMT"
	_trust_action_target
         $IPT_H $IPT_FLAGS -I $CHAIN -s "$HOST" -j $JACTION
        	$IPT_H $IPT_FLAGS -I $CHAIN -d "$HOST" -j $JACTION
         eout "{trust} added $ACTION all to/from $HOST"
         elog_event "trust_added" "info" "{trust} added $ACTION all to/from $HOST" \
             "host=$HOST" "action=$ACTION"
         if [ "$SET_VERBOSE" != "1" ]; then
	        echo "Inserted into firewall: $ACTION all to/from $HOST"
	fi
 fi
}

cli_trust_temp() {
 local CHAIN="$1" ACTION="$2" FILE="$3" HOST="$4" TTL_STR="$5" CMT="$6"
 local tlist f EXPIRE_EPOCH JACTION EXPIRE_DISP
 if [ -z "$HOST" ]; then
	echo "an FQDN or IP address is required for this option" >&2
	return 1
 fi

 # Validate entry (advanced or bare)
 if [[ "$HOST" == *=* ]]; then
	# Check if last field is a country code → delegate to apf_geoip.sh
	local _ctt_last="${HOST##*=}"
	if valid_cc "$_ctt_last" || [[ "$_ctt_last" == @* ]]; then
		# shellcheck disable=SC1090,SC1091
		. "$INSTALL_PATH/internals/apf_geoip.sh"
		cli_cc_trust_temp "$HOST" "$CHAIN" "$ACTION" "$FILE" "$TTL_STR" "$CMT"
		return $?
	fi
	if ! valid_trust_entry "$HOST"; then
		echo "Invalid trust entry '$HOST'" >&2
		local _abbr_cidr='^[0-9]+/[0-9]+$'
		if [[ "${HOST##*=}" =~ $_abbr_cidr ]]; then
			echo "  Hint: abbreviated CIDR (e.g. '0/0') is not valid; use full notation (e.g. '0.0.0.0/0')" >&2
		fi
		return 1
	fi
 else
	if ! valid_host "$HOST"; then
		# Not a valid host — check if it's a country code
		if valid_cc "$HOST" || [[ "$HOST" == @* ]]; then
			# shellcheck disable=SC1090,SC1091
			. "$INSTALL_PATH/internals/apf_geoip.sh"
			cli_cc_trust_temp "$HOST" "$CHAIN" "$ACTION" "$FILE" "$TTL_STR" "$CMT"
			return $?
		fi
		echo "Invalid host '$HOST': must be a valid IP/IPv6 address, CIDR block, FQDN, or country code" >&2
		local _abbr_cidr='^[0-9]+/[0-9]+$'
		if [[ "$HOST" =~ $_abbr_cidr ]]; then
			echo "  Hint: abbreviated CIDR (e.g. '0/0') is not valid; use full notation (e.g. '0.0.0.0/0')" >&2
		fi
		return 1
	fi
	_VTE_IP="$HOST"
 fi

 if [ -z "$TTL_STR" ]; then
	echo "a TTL value is required (e.g., 300, 5m, 1h, 7d)" >&2
	return 1
 fi
 if ! parse_ttl "$TTL_STR"; then
	echo "Invalid TTL '$TTL_STR': must be a positive number with optional suffix (s/m/h/d)" >&2
	return 1
 fi
 _trust_check_duplicate "$HOST"
 load_local_addrs
 if [ "$tlist" ]; then
	echo "$HOST already exists in $tlist"
 elif is_fqdn "$_VTE_IP"; then
	# FQDN (bare or in advanced syntax) — resolve before iptables
	local _ctt_rc=0
	_cli_trust_resolve_fqdn "$_VTE_IP" || _ctt_rc=$?
	if [ "$_ctt_rc" -eq 1 ]; then return 1; fi
	if [ "$_ctt_rc" -eq 0 ]; then
		EXPIRE_EPOCH=$(($(date +%s) + _TTL_SECONDS))
		local _ctt_csv="${_RESOLVED_IPS//$'\n'/,}"
		_cli_trust_write_entry "$HOST" "$FILE" "$CMT" \
			"ttl=$_TTL_SECONDS" "expire=$EXPIRE_EPOCH" "resolved=$_ctt_csv"
		EXPIRE_DISP=$(date -d "@$EXPIRE_EPOCH" +"%D %H:%M:%S")
		if [[ "$HOST" == *=* ]]; then
			# Advanced syntax with FQDN
			local _ctt_rip _ctt_resolved_entry
			while IFS= read -r _ctt_rip; do
				_ctt_resolved_entry="${HOST//$_VTE_IP/$_ctt_rip}"
				if trust_entry_rule "$_ctt_resolved_entry" "$CHAIN" "$ACTION" "-I"; then
					eout "{trust} added temporary $ACTION $_TER_DESC (resolved from $_VTE_IP, ttl=${_TTL_SECONDS}s, expires $EXPIRE_DISP)"
					if [ "$SET_VERBOSE" != "1" ]; then
						echo "Inserted into firewall: temporary $ACTION $_TER_DESC (ttl=${_TTL_SECONDS}s, expires $EXPIRE_DISP)"
					fi
				fi
				_maybe_block_escalate "$_ctt_rip" "$ACTION"
			done <<< "$_RESOLVED_IPS"
			elog_event "trust_added" "info" "{trust} added temporary $ACTION $_TER_DESC" \
				"host=$HOST" "action=$ACTION" "ttl=$_TTL_SECONDS"
		else
			# Bare FQDN
			_trust_action_target
			local _ctt_rip
			while IFS= read -r _ctt_rip; do
				if ipt_for_host "$_ctt_rip"; then
					$IPT_H $IPT_FLAGS -I $CHAIN -s "$_ctt_rip" -j $JACTION
					$IPT_H $IPT_FLAGS -I $CHAIN -d "$_ctt_rip" -j $JACTION
				fi
				_maybe_block_escalate "$_ctt_rip" "$ACTION"
			done <<< "$_RESOLVED_IPS"
			eout "{trust} added temporary $ACTION all to/from $HOST (resolved: $_ctt_csv, ttl=${_TTL_SECONDS}s, expires $EXPIRE_DISP)"
			elog_event "trust_added" "info" "{trust} added temporary $ACTION all to/from $HOST" \
				"host=$HOST" "action=$ACTION" "ttl=$_TTL_SECONDS"
			if [ "$SET_VERBOSE" != "1" ]; then
				echo "Inserted into firewall: temporary $ACTION all to/from $HOST (resolved: $_ctt_csv, ttl=${_TTL_SECONDS}s, expires $EXPIRE_DISP)"
			fi
		fi
	fi
 elif is_local_addr "$_VTE_IP"; then
	echo "$_VTE_IP is a local address and can not be added to the trust system" >&2
 else
	EXPIRE_EPOCH=$(($(date +%s) + _TTL_SECONDS))
	_cli_trust_write_entry "$HOST" "$FILE" "$CMT" \
		"ttl=$_TTL_SECONDS" "expire=$EXPIRE_EPOCH"

	if [[ "$HOST" == *=* ]]; then
		# Advanced syntax — use trust_entry_rule for iptables insertion
		if ! trust_entry_rule "$HOST" "$CHAIN" "$ACTION" "-I"; then
			echo "Failed to insert rule for '$HOST'" >&2
			return 1
		fi
		EXPIRE_DISP=$(date -d "@$EXPIRE_EPOCH" +"%D %H:%M:%S")
		eout "{trust} added temporary $ACTION $_TER_DESC (ttl=${_TTL_SECONDS}s, expires $EXPIRE_DISP)"
		elog_event "trust_added" "info" "{trust} added temporary $ACTION $_TER_DESC" \
			"host=$HOST" "action=$ACTION" "ttl=$_TTL_SECONDS"
		if [ "$SET_VERBOSE" != "1" ]; then
			echo "Inserted into firewall: temporary $ACTION $_TER_DESC (ttl=${_TTL_SECONDS}s, expires $EXPIRE_DISP)"
		fi
		_maybe_block_escalate "$_TER_IP" "$ACTION"
	else
		# Bare host path
		if ! ipt_for_host "$HOST"; then
			echo "$HOST appears to be IPv6 but USE_IPV6 is not enabled" >&2
			return 1
		fi
		_trust_action_target
		$IPT_H $IPT_FLAGS -I $CHAIN -s "$HOST" -j $JACTION
		$IPT_H $IPT_FLAGS -I $CHAIN -d "$HOST" -j $JACTION
		EXPIRE_DISP=$(date -d "@$EXPIRE_EPOCH" +"%D %H:%M:%S")
		eout "{trust} added temporary $ACTION all to/from $HOST (ttl=${_TTL_SECONDS}s, expires $EXPIRE_DISP)"
		elog_event "trust_added" "info" "{trust} added temporary $ACTION all to/from $HOST" \
			"host=$HOST" "action=$ACTION" "ttl=$_TTL_SECONDS"
		if [ "$SET_VERBOSE" != "1" ]; then
			echo "Inserted into firewall: temporary $ACTION all to/from $HOST (ttl=${_TTL_SECONDS}s, expires $EXPIRE_DISP)"
		fi
		_maybe_block_escalate "$HOST" "$ACTION"
	fi
 fi
}

## Block escalation (RAB)

record_block() {
	local ip="$1"
	local history_file="$INSTALL_PATH/internals/.block_history"
	local now h_ip count first last found_entry=0
	now=$(date +%s)
	local tmpfile
	tmpfile=$(mktemp "$INSTALL_PATH/internals/.block_history.XXXXXX")
	_apf_reg_tmp "$tmpfile"

	if [ -f "$history_file" ]; then
		while IFS='|' read -r h_ip count first last; do
			[ -z "$h_ip" ] && continue
			# Prune entries outside the interval window
			if [ $((now - first)) -gt "$PERMBLOCK_INTERVAL" ]; then
				continue
			fi
			if [ "$h_ip" = "$ip" ]; then
				count=$((count + 1))
				last="$now"
				found_entry=1
			fi
			echo "${h_ip}|${count}|${first}|${last}"
		done < "$history_file" > "$tmpfile"
	fi

	if [ "$found_entry" -eq 0 ]; then
		echo "${ip}|1|${now}|${now}" >> "$tmpfile"
	fi

	command mv -f "$tmpfile" "$history_file"
	command chmod 640 "$history_file"
}

check_block_escalation() {
	local ip="$1"
	local history_file="$INSTALL_PATH/internals/.block_history"
	[ ! -f "$history_file" ] && return 1

	local count escaped_ip_re
	escaped_ip_re="${ip//./\\.}"
	count=$(grep -m1 "^${escaped_ip_re}|" "$history_file" | cut -d'|' -f2)
	[ -z "$count" ] && return 1

	if [ "$count" -ge "$PERMBLOCK_COUNT" ]; then
		return 0
	fi
	return 1
}

escalate_to_permanent() {
	local ip="$1"
	local escaped_ip="${ip//./\\.}"

	# Remove temp entry markers from deny_hosts.rules
	sed -i "\%# added ${escaped_ip} .*ttl=.*expire=%d" "$DENY_HOSTS"
	sed -i "\%^${escaped_ip}$%d" "$DENY_HOSTS"

	# Add as permanent with static noexpire markers
	echo "# added $ip on $(date +"%D %H:%M:%S") addedtime=$(date +%s) static noexpire with comment: auto-escalated from temp deny (PERMBLOCK)" >> "$DENY_HOSTS"
	echo "$ip" >> "$DENY_HOSTS"

	eout "{trust} $ip auto-escalated to permanent deny (PERMBLOCK_COUNT=$PERMBLOCK_COUNT reached)"
	elog_event "block_escalated" "error" "{trust} $ip auto-escalated to permanent deny" \
		"host=$ip" "threshold=$PERMBLOCK_COUNT"

	# Remove from block history (escalation complete)
	local history_file="$INSTALL_PATH/internals/.block_history"
	sed -i "\%^${escaped_ip}|%d" "$history_file"
}

_maybe_block_escalate() {
	local ip="$1" action="$2"
	if [ "$PERMBLOCK_COUNT" -gt 0 ] && [ "$action" == "DENY" ]; then
		record_block "$ip"
		if check_block_escalation "$ip"; then
			escalate_to_permanent "$ip"
		fi
	fi
}

## Trust file loading

_trust_local_addr_blocked() {
	# Check if advanced trust entry would create a self-referencing allow rule.
	# Only applies when direction is present; 3-field entries (no direction)
	# never trigger this. Returns 0 (blocked) or 1 (not blocked).
	# Args: $1=verb $2=ipflow(s/d) $3=dir(in/out) $4=ip
	local verb="$1" ipflow="$2" dir="$3" pip="$4"
	[ "$verb" != "allow" ] && return 1
	[ -z "$dir" ] && return 1
	if [ "$ipflow" == "s" ] && [ "$dir" == "in" ] && is_local_addr "$pip"; then
		return 0
	fi
	if [ "$ipflow" == "d" ] && [ "$dir" == "out" ] && is_local_addr "$pip"; then
		return 0
	fi
	return 1
}

_trust_hosts_advanced() {
	# Process an advanced trust entry (contains '=') during bulk file loading.
	# Pre-parses to extract IP (for FQDN detection) and direction+ipflow
	# (for local-addr protection), then delegates rule creation to
	# trust_entry_rule() — single source of truth for iptables commands.
	# Args: $1=entry $2=chain $3=action(ALLOW/DENY) $4=verb(allow/deny)
	local entry="$1" chain="$2" ter_action="$3" verb="$4"

	# Pre-parse: extract fields needed for FQDN and local-addr checks
	trust_protect_ipv6 "$entry"; local safe="$_TPV6_RESULT"
	trust_parse_fields "$safe"
	_trust_unpack_fields || return 1
	local dir="$_TUF_DIR" pflow="$_TUF_PFLOW"
	local port="$_TUF_PORT" ipflow="$_TUF_IPFLOW" pip="$_TUF_PIP"

	# Build description fragments for local-addr blocked log messages
	expand_port "$port"; port="$_PORT"
	local dir_desc="" pflow_desc=""
	[ "$dir" == "in" ] && dir_desc="inbound "
	[ "$dir" == "out" ] && dir_desc="outbound "
	if [ "$pflow" == "d" ]; then pflow_desc="to"; else pflow_desc="from"; fi

	if is_fqdn "$pip"; then
		if ! resolve_fqdn "$pip"; then
			eout "{trust} failed to resolve FQDN $pip, skipping"
			return 1
		fi
		local _tha_rip _tha_resolved_entry
		while IFS= read -r _tha_rip; do
			if _trust_local_addr_blocked "$verb" "$ipflow" "$dir" "$_tha_rip"; then
				eout "{trust} ignored local ip $verb rule '${dir_desc}$_tha_rip $pflow_desc port $port'"
			else
				_tha_resolved_entry="${entry//$pip/$_tha_rip}"
				if trust_entry_rule "$_tha_resolved_entry" "$chain" "$ter_action" "-A"; then
					eout "{trust} $verb $_TER_DESC (resolved from $pip)"
				fi
			fi
		done <<< "$_RESOLVED_IPS"
	else
		if _trust_local_addr_blocked "$verb" "$ipflow" "$dir" "$pip"; then
			eout "{trust} ignored local ip $verb rule '${dir_desc}$pip $pflow_desc port $port'"
			return 0
		fi
		if trust_entry_rule "$entry" "$chain" "$ter_action" "-A"; then
			eout "{trust} $verb $_TER_DESC"
		fi
	fi
	return 0
}

trust_hosts() {
local file="$1"
local chain="$2"
local action_all="$3" verb="$4"
local i
local _TER_BUFFER_MODE=1
load_local_addrs
if [ -z "$file" ] || [ -z "$chain" ]; then
        eout "{trust} could not process trust_hosts $file $chain, fatal error, aborting!"
        "$INSTALL_PATH/apf" -f
        mutex_unlock
        exit 1
fi

local _th_raw
_th_raw=$(grep -v '^#' "$file" | grep -v '^[[:space:]]*$')
if [ -n "$_th_raw" ]; then
        eout "{glob} loading $file"
        local ter_action
        if [ "$verb" == "allow" ]; then ter_action="ALLOW"; else ter_action="DENY"; fi
        # Batch buffers for iptables-restore --noflush
        local _th_rf4="" _th_rf6=""
        while IFS= read -r i; do
                [ -z "$i" ] && continue
                if [[ "$i" != *=* ]]; then
                        # Bare host (IP/CIDR/FQDN)
                        if ! valid_host "$i"; then
                                eout "{trust} skipping invalid entry in $file: $i"
                                continue
                        fi
                        if is_fqdn "$i"; then
                         if resolve_fqdn "$i"; then
                          local _th_rip
                          while IFS= read -r _th_rip; do
                           if ! is_local_addr "$_th_rip"; then
                            if [[ "$_th_rip" == *:* ]]; then
                                if [ "$USE_IPV6" == "1" ]; then
                                    eout "{trust} $verb all to/from $i (resolved: $_th_rip)"
                                    _th_rf6="${_th_rf6}-A $chain -s $_th_rip -d ::/0 -j $action_all
-A $chain -d $_th_rip -s ::/0 -j $action_all
"
                                fi
                            else
                                eout "{trust} $verb all to/from $i (resolved: $_th_rip)"
                                _th_rf4="${_th_rf4}-A $chain -s $_th_rip -d 0/0 -j $action_all
-A $chain -d $_th_rip -s 0/0 -j $action_all
"
                            fi
                           fi
                          done <<< "$_RESOLVED_IPS"
                         else
                          eout "{trust} failed to resolve FQDN $i, skipping"
                         fi
                        elif ! is_local_addr "$i"; then
                         if [ -f "$file" ]; then
                          if [[ "$i" == *:* ]]; then
                                if [ "$USE_IPV6" == "1" ]; then
                                    eout "{trust} $verb all to/from $i"
                                    _th_rf6="${_th_rf6}-A $chain -s $i -d ::/0 -j $action_all
-A $chain -d $i -s ::/0 -j $action_all
"
                                fi
                          else
                                eout "{trust} $verb all to/from $i"
                                _th_rf4="${_th_rf4}-A $chain -s $i -d 0/0 -j $action_all
-A $chain -d $i -s 0/0 -j $action_all
"
                          fi
                         fi
                        fi
                else
                        # Advanced syntax (contains '=')
                        _trust_hosts_advanced "$i" "$chain" "$ter_action" "$verb"
                fi
        done <<< "$_th_raw"
        # Apply batched rules via iptables-restore --noflush
        if [ -n "$_th_rf4" ] && [ -n "$IPTR" ]; then
                printf '*filter\n%sCOMMIT\n' "$_th_rf4" | $IPTR --noflush
        fi
        if [ -n "$_th_rf6" ] && [ "$USE_IPV6" == "1" ] && [ -n "$IP6TR" ]; then
                printf '*filter\n%sCOMMIT\n' "$_th_rf6" | $IP6TR --noflush
        fi
fi
}

allow_hosts() { trust_hosts "$1" "$2" ACCEPT "allow"; }

deny_hosts() { trust_hosts "$1" "$2" "$ALL_STOP" "deny"; }

## Temp entry management

# Parse temp trust comment line: "# added IP on ... ttl=N expire=E ..."
# Sets: _PTC_IP, _PTC_TTL, _PTC_EPOCH
_parse_temp_comment() {
	local line="$1"
	_PTC_IP="${line#\# added }"
	_PTC_IP="${_PTC_IP%% *}"
	_PTC_TTL="${line#*ttl=}"
	_PTC_TTL="${_PTC_TTL%% *}"
	_PTC_EPOCH="${line#*expire=}"
	_PTC_EPOCH="${_PTC_EPOCH%% *}"
}

expirebans() {
local ip ban_time time_diff expire_time check_time REFRESH_TIME eff_expire line
local _eb_date_str
local -a _eb_expired=()
if [ -z "$SET_EXPIRE" ]; then
        eff_expire=0
else
        eff_expire="$SET_EXPIRE"
fi
if [ "$eff_expire" -ge "60" ]; then
 REFRESH_TIME=$(($SET_REFRESH*60))
 if [ "$eff_expire" -lt "$REFRESH_TIME" ]; then
        eff_expire="$REFRESH_TIME"
 fi
 if [ -f "$DENY_HOSTS" ]; then
         expire_time="$eff_expire"
         check_time=$(date +%s)
         while IFS= read -r line; do
                # Extract IP: "# added IP on ..."
                ip="${line#\# added }"
                ip="${ip%% *}"
                [ -z "$ip" ] && continue

                # Dual-track: structured addedtime= marker preferred;
                # legacy date --date fallback for pre-2.0.2 entries
                if [[ "$line" == *addedtime=* ]]; then
                        ban_time="${line#*addedtime=}"
                        ban_time="${ban_time%% *}"
                else
                        # Legacy fallback: extract date/time after "on "
                        _eb_date_str="${line#*on }"
                        # Trim everything after the timestamp (space-delimited)
                        _eb_date_str="${_eb_date_str%% addedtime=*}"
                        _eb_date_str="${_eb_date_str%% resolved=*}"
                        _eb_date_str="${_eb_date_str%% with comment:*}"
                        # _eb_date_str is now "MM/DD/YY HH:MM:SS"
                        ban_time=$(date --date "$_eb_date_str" +%s 2>/dev/null)  # safe: legacy date format may be invalid
                fi
                # Validate numeric
                case "$ban_time" in *[!0-9]*) continue ;; esac
                [ -z "$ban_time" ] && continue

                time_diff=$(($check_time-$ban_time))
                if [ "$time_diff" -ge "$expire_time" ]; then
                        eout "{trust} removed expired ban for $ip (${time_diff}s/${expire_time}s)"
                        _eb_expired+=("$ip")
                fi
         done < <(grep -vE "static|noexpire|ttl=" "$DENY_HOSTS" | grep -E "# added .* on ")
         # Deferred removal: avoids modifying deny_hosts.rules while iterating;
         # cli_trust_remove handles both iptables rules and file cleanup
         for ip in "${_eb_expired[@]}"; do
                cli_trust_remove "$ip" >> /dev/null 2>&1
         done
 fi
fi
}

expire_temp_entries() {
	local current_time file line count=0
	local -a _et_expired=()
	local -a _et_cc_expired=()
	local -a _et_cc_files=()
	current_time=$(date +%s)
	for file in "$ALLOW_HOSTS" "$DENY_HOSTS" "$CC_DENY_HOSTS" "$CC_ALLOW_HOSTS"; do
		[ -f "$file" ] || continue
		local _is_cc_file=0
		if [ "$file" = "$CC_DENY_HOSTS" ] || [ "$file" = "$CC_ALLOW_HOSTS" ]; then
			_is_cc_file=1
		fi
		while IFS= read -r line; do
			_parse_temp_comment "$line"
			if [ "$current_time" -ge "$_PTC_EPOCH" ] 2>/dev/null; then  # safe: value may not be numeric
				eout "{trust} removed expired temp entry for $_PTC_IP"
				if [ "$_is_cc_file" = "1" ]; then
					_et_cc_expired+=("$_PTC_IP")
					_et_cc_files+=("$file")
				else
					_et_expired+=("$_PTC_IP")
				fi
				count=$(($count + 1))
			fi
		done < <(grep '# added .* ttl=.*expire=' "$file")
	done
	# Deferred removal: avoids modifying trust files while iterating
	# Regular trust entries: cli_trust_remove handles iptables + file cleanup
	local _et_ip
	for _et_ip in "${_et_expired[@]}"; do
		cli_trust_remove "$_et_ip" >> /dev/null 2>&1
	done
	# CC entries: _expire_cc_temp_entry removes only the temp metadata;
	# preserves permanent entries, ipsets, and iptables rules for that CC
	if [ "${#_et_cc_expired[@]}" -gt 0 ]; then
		# shellcheck disable=SC1090,SC1091
		. "$INSTALL_PATH/internals/apf_geoip.sh"
		local _et_i
		for _et_i in "${!_et_cc_expired[@]}"; do
			_expire_cc_temp_entry "${_et_cc_expired[$_et_i]}" "${_et_cc_files[$_et_i]}" 2>/dev/null  # safe: entry may already be expired
		done
	fi
	if [ "$count" -gt 0 ]; then
		eout "{trust} expired $count temporary trust entries"
		elog_event "trust_removed" "info" "{trust} expired $count temporary trust entries" \
			"count=$count"
	fi
}

list_temp_entries() {
	local current_time file type cmt remaining line found=0
	current_time=$(date +%s)
	for file in "$ALLOW_HOSTS" "$DENY_HOSTS" "$CC_DENY_HOSTS" "$CC_ALLOW_HOSTS"; do
		[ -f "$file" ] || continue
		if [ "$file" == "$ALLOW_HOSTS" ] || [ "$file" == "$CC_ALLOW_HOSTS" ]; then
			type="ALLOW"
		else
			type="DENY"
		fi
		while IFS= read -r line; do
			_parse_temp_comment "$line"
			if [[ "$line" == *"with comment: "* ]]; then
				cmt="${line#*with comment: }"
			else
				cmt=""
			fi
			remaining=$(($_PTC_EPOCH - $current_time))
			if [ "$remaining" -lt 0 ]; then
				remaining=0
			fi
			local disp
			if [ "$remaining" -ge 86400 ]; then
				disp="$((remaining / 86400))d $((remaining % 86400 / 3600))h"
			elif [ "$remaining" -ge 3600 ]; then
				disp="$((remaining / 3600))h $((remaining % 3600 / 60))m"
			elif [ "$remaining" -ge 60 ]; then
				disp="$((remaining / 60))m $((remaining % 60))s"
			else
				disp="${remaining}s"
			fi
			echo "$type $_PTC_IP ttl=${_PTC_TTL}s remains=${disp} $cmt"
			found=1
		done < <(grep '# added .* ttl=.*expire=' "$file")
	done
	if [ "$found" -eq 0 ]; then
		echo "No temporary entries."
	fi
}

flush_temp_entries() {
	local file line count=0
	local -a _ft_expired=()
	local -a _ft_cc_expired=()
	local -a _ft_cc_files=()
	for file in "$ALLOW_HOSTS" "$DENY_HOSTS" "$CC_DENY_HOSTS" "$CC_ALLOW_HOSTS"; do
		[ -f "$file" ] || continue
		local _is_cc_file=0
		if [ "$file" = "$CC_DENY_HOSTS" ] || [ "$file" = "$CC_ALLOW_HOSTS" ]; then
			_is_cc_file=1
		fi
		while IFS= read -r line; do
			_parse_temp_comment "$line"
			if [ "$_is_cc_file" = "1" ]; then
				_ft_cc_expired+=("$_PTC_IP")
				_ft_cc_files+=("$file")
			else
				_ft_expired+=("$_PTC_IP")
			fi
			count=$(($count + 1))
		done < <(grep '# added .* ttl=.*expire=' "$file")
	done
	# Deferred removal: avoids modifying trust files while iterating
	# Regular trust entries: cli_trust_remove handles iptables + file cleanup
	local _ft_ip
	for _ft_ip in "${_ft_expired[@]}"; do
		# Suppress errors: iptables rules may not exist after firewall restart
		cli_trust_remove "$_ft_ip" >> /dev/null 2>&1
	done
	# Safety net: remove any orphaned ttl= comment lines not cleaned
	# by per-IP cli_trust_remove (e.g., partial flush after restart);
	# runs AFTER cli_trust_remove so FQDN resolved= metadata is available
	for file in "$ALLOW_HOSTS" "$DENY_HOSTS"; do
		[ -f "$file" ] || continue
		sed -i '/# added .* ttl=.*expire=/d' "$file"
	done
	# CC entries: _expire_cc_temp_entry removes only the temp metadata;
	# preserves permanent entries, ipsets, and iptables rules for that CC
	if [ "${#_ft_cc_expired[@]}" -gt 0 ]; then
		# shellcheck disable=SC1090,SC1091
		. "$INSTALL_PATH/internals/apf_geoip.sh"
		local _ft_i
		for _ft_i in "${!_ft_cc_expired[@]}"; do
			_expire_cc_temp_entry "${_ft_cc_expired[$_ft_i]}" "${_ft_cc_files[$_ft_i]}" 2>/dev/null  # safe: entry may already be expired
		done
	fi
	eout "{trust} flushed $count temporary trust entries"
	elog_event "trust_removed" "info" "{trust} flushed $count temporary trust entries" \
		"count=$count"
	if [ "$SET_VERBOSE" != "1" ]; then
		echo "Flushed $count temporary trust entries."
	fi
}

## Refresh cycle

refresh() {
	# Clean up orphaned temp files from pre-2.0.2 refresh() implementation
	_apf_cleanup_stale_tmp
	apf_loaded=$($IPT $IPT_FLAGS --list --numeric 2>/dev/null | grep TALLOW)  # safe: firewall may not be loaded
	if [ -z "$apf_loaded" ] && [ "$USE_IPV6" == "1" ]; then
		apf_loaded=$($IP6T $IPT_FLAGS --list --numeric 2>/dev/null | grep TALLOW)  # safe: firewall may not be loaded
	fi
	if [ -z "$apf_loaded" ]; then
	        eout "{glob} apf does not appear to have rules loaded, doing nothing."
	        mutex_unlock
		exit 1
	fi

        eout "{glob} refreshing trust system rules"

        if [ "$SET_EXPIRE" -ge "60" ]; then
                # expire deny_hosts bans
                expirebans
        fi

	if [ "$SET_REFRESH_MD5" == "1" ] && [ "$MD5" ]; then
 	 glob_allow_download
	 glob_deny_download
	 trusts_md5=$($MD5 $DENY_HOSTS $GDENY_HOSTS $ALLOW_HOSTS $GALLOW_HOSTS | $MD5 | awk '{print$1}')
	 if [ -f "$INSTALL_PATH/internals/.trusts.md5" ]; then
		read -r last_trusts_md5 < "$INSTALL_PATH/internals/.trusts.md5"
		if [ "$trusts_md5" == "$last_trusts_md5" ]; then
		        eout "{glob} trust rules unchanged since last refresh, doing nothing."
	                echo "$trusts_md5" > "$INSTALL_PATH/internals/.trusts.md5"
		        mutex_unlock
			exit 0
		else
	                echo "$trusts_md5" > "$INSTALL_PATH/internals/.trusts.md5"
		fi
	 else
		echo "$trusts_md5" > "$INSTALL_PATH/internals/.trusts.md5"
	 fi
	else
		glob_allow_download
		glob_deny_download
	fi

	# Populate REFRESH_TEMP from trust files (more reliable than iptables-save
	# parsing, which can miss entries added since last save)
	ipt -F REFRESH_TEMP
	local _rf_file _rf_line _rf_rip _rf_pip
	for _rf_file in "$ALLOW_HOSTS" "$GALLOW_HOSTS"; do
		[ -f "$_rf_file" ] || continue
		while IFS= read -r _rf_line; do
			case "$_rf_line" in '#'*|'') continue ;; esac
			if [[ "$_rf_line" == *=* ]]; then
				# Advanced entry — extract IP for REFRESH_TEMP protection
				trust_protect_ipv6 "$_rf_line"
				trust_parse_fields "$_TPV6_RESULT"
				_trust_unpack_fields || continue
				_rf_pip="$_TUF_PIP"
				if is_fqdn "$_rf_pip"; then
					if resolve_fqdn "$_rf_pip"; then
						while IFS= read -r _rf_rip; do
							if ipt_for_host "$_rf_rip"; then
								$IPT_H $IPT_FLAGS -A REFRESH_TEMP -s "$_rf_rip" -j ACCEPT 2>/dev/null  # safe: chain may not exist during refresh
								$IPT_H $IPT_FLAGS -A REFRESH_TEMP -d "$_rf_rip" -j ACCEPT 2>/dev/null  # safe: chain may not exist during refresh
							fi
						done <<< "$_RESOLVED_IPS"
					fi
				elif ipt_for_host "$_rf_pip"; then
					$IPT_H $IPT_FLAGS -A REFRESH_TEMP -s "$_rf_pip" -j ACCEPT 2>/dev/null  # safe: chain may not exist during refresh
					$IPT_H $IPT_FLAGS -A REFRESH_TEMP -d "$_rf_pip" -j ACCEPT 2>/dev/null  # safe: chain may not exist during refresh
				fi
			elif is_fqdn "$_rf_line"; then
				if resolve_fqdn "$_rf_line"; then
					while IFS= read -r _rf_rip; do
						if ipt_for_host "$_rf_rip"; then
							$IPT_H $IPT_FLAGS -A REFRESH_TEMP -s "$_rf_rip" -j ACCEPT 2>/dev/null  # safe: chain may not exist during refresh
							$IPT_H $IPT_FLAGS -A REFRESH_TEMP -d "$_rf_rip" -j ACCEPT 2>/dev/null  # safe: chain may not exist during refresh
						fi
					done <<< "$_RESOLVED_IPS"
				fi
			elif ipt_for_host "$_rf_line"; then
				$IPT_H $IPT_FLAGS -A REFRESH_TEMP -s "$_rf_line" -j ACCEPT 2>/dev/null  # safe: chain may not exist during refresh
				$IPT_H $IPT_FLAGS -A REFRESH_TEMP -d "$_rf_line" -j ACCEPT 2>/dev/null  # safe: chain may not exist during refresh
			fi
		done < "$_rf_file"
	done
	for _rf_file in "$DENY_HOSTS" "$GDENY_HOSTS"; do
		[ -f "$_rf_file" ] || continue
		while IFS= read -r _rf_line; do
			case "$_rf_line" in '#'*|'') continue ;; esac
			if [[ "$_rf_line" == *=* ]]; then
				# Advanced entry — extract IP for REFRESH_TEMP protection
				trust_protect_ipv6 "$_rf_line"
				trust_parse_fields "$_TPV6_RESULT"
				_trust_unpack_fields || continue
				_rf_pip="$_TUF_PIP"
				if is_fqdn "$_rf_pip"; then
					if resolve_fqdn "$_rf_pip"; then
						while IFS= read -r _rf_rip; do
							if ipt_for_host "$_rf_rip"; then
								$IPT_H $IPT_FLAGS -A REFRESH_TEMP -s "$_rf_rip" -j $ALL_STOP 2>/dev/null  # safe: chain may not exist during refresh
								$IPT_H $IPT_FLAGS -A REFRESH_TEMP -d "$_rf_rip" -j $ALL_STOP 2>/dev/null  # safe: chain may not exist during refresh
							fi
						done <<< "$_RESOLVED_IPS"
					fi
				elif ipt_for_host "$_rf_pip"; then
					$IPT_H $IPT_FLAGS -A REFRESH_TEMP -s "$_rf_pip" -j $ALL_STOP 2>/dev/null  # safe: chain may not exist during refresh
					$IPT_H $IPT_FLAGS -A REFRESH_TEMP -d "$_rf_pip" -j $ALL_STOP 2>/dev/null  # safe: chain may not exist during refresh
				fi
			elif is_fqdn "$_rf_line"; then
				if resolve_fqdn "$_rf_line"; then
					while IFS= read -r _rf_rip; do
						if ipt_for_host "$_rf_rip"; then
							$IPT_H $IPT_FLAGS -A REFRESH_TEMP -s "$_rf_rip" -j $ALL_STOP 2>/dev/null  # safe: chain may not exist during refresh
							$IPT_H $IPT_FLAGS -A REFRESH_TEMP -d "$_rf_rip" -j $ALL_STOP 2>/dev/null  # safe: chain may not exist during refresh
						fi
					done <<< "$_RESOLVED_IPS"
				fi
			elif ipt_for_host "$_rf_line"; then
				$IPT_H $IPT_FLAGS -A REFRESH_TEMP -s "$_rf_line" -j $ALL_STOP 2>/dev/null  # safe: chain may not exist during refresh
				$IPT_H $IPT_FLAGS -A REFRESH_TEMP -d "$_rf_line" -j $ALL_STOP 2>/dev/null  # safe: chain may not exist during refresh
			fi
		done < "$_rf_file"
	done
        trim $DENY_HOSTS $SET_TRIM
        trim $GDENY_HOSTS $SET_TRIM
        ipt -F TDENY
        ipt -F TGDENY
        ipt -F TALLOW
        ipt -F TGALLOW
	allow_hosts $GALLOW_HOSTS TGALLOW
	allow_hosts $ALLOW_HOSTS TALLOW
	deny_hosts $GDENY_HOSTS TGDENY
	deny_hosts $DENY_HOSTS TDENY
        ipt -F REFRESH_TEMP
}

## Shared helper: trust remove with output (eliminates triple duplication)
# Used by: _dispatch_trust(remove), _dispatch_trust_temp(remove), and Tier 1 -u
_cli_trust_remove_with_output() {
	local host="$1"
	if cli_trust_remove "$host"; then
		eout "{trust} removed $host from trust system"
		elog_event "trust_removed" "info" "{trust} removed $host from trust system" \
			"host=$host"
		if [ "$SET_VERBOSE" != "1" ]; then
			echo "Removed $host from trust system."
		fi
	else
		eout "{trust} $host not found in trust system"
		if [ "$SET_VERBOSE" != "1" ]; then
			echo "$host not found in trust system." >&2
		fi
		return 1
	fi
}

## Dispatch: apf trust <verb> [args]
_dispatch_trust() {
	case "${1:-}" in
	-h|--help|"") _trust_help ;;
	add)
		shift
		if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then _trust_help; exit 0; fi
		mutex_lock
		cli_trust "TALLOW" "ALLOW" "$ALLOW_HOSTS" "$@" || exit 1
		;;
	deny)
		shift
		if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then _trust_help; exit 0; fi
		mutex_lock
		cli_trust "TDENY" "DENY" "$DENY_HOSTS" "$@" || exit 1
		;;
	remove)
		shift
		if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then _trust_help; exit 0; fi
		mutex_lock
		_cli_trust_remove_with_output "$1" || exit 1
		;;
	list)
		shift
		case "${1:-}" in
		--allow) list_trust_file "$ALLOW_HOSTS" "allow_hosts.rules" ;;
		--deny)  list_trust_file "$DENY_HOSTS" "deny_hosts.rules" ;;
		--temp)  list_temp_entries ;;
		*)       list_trust_file "$ALLOW_HOSTS" "allow_hosts.rules"
		         echo ""
		         list_trust_file "$DENY_HOSTS" "deny_hosts.rules" ;;
		esac
		;;
	lookup)
		shift
		if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then _trust_help; exit 0; fi
		trust_lookup "$@" || exit 1
		;;
	refresh)
		mutex_lock; refresh
		;;
	flush)
		shift
		case "${1:-}" in
		--deny)  echo "apf trust flush --deny: not yet implemented" >&2; exit 1 ;;
		--allow) echo "apf trust flush --allow: not yet implemented" >&2; exit 1 ;;
		--temp)  mutex_lock; flush_temp_entries ;;
		*)       echo "apf trust flush: expected --temp, --deny, or --allow." >&2; return 1 ;;
		esac
		;;
	temp)
		shift; _dispatch_trust_temp "$@"
		;;
	*)  _cli_unknown_verb "apf trust" "$1" "add deny remove list lookup refresh flush temp"; return 1 ;;
	esac
}

## Dispatch: apf trust temp <verb> [args]
_dispatch_trust_temp() {
	case "${1:-}" in
	-h|--help|"") _trust_temp_help ;;
	add)
		shift
		if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then _trust_temp_help; exit 0; fi
		mutex_lock
		cli_trust_temp "TALLOW" "ALLOW" "$ALLOW_HOSTS" "$@" || exit 1
		;;
	deny)
		shift
		if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then _trust_temp_help; exit 0; fi
		mutex_lock
		cli_trust_temp "TDENY" "DENY" "$DENY_HOSTS" "$@" || exit 1
		;;
	remove)
		shift
		if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then _trust_temp_help; exit 0; fi
		mutex_lock
		_cli_trust_remove_with_output "$1" || exit 1
		;;
	list)  list_temp_entries ;;
	flush) mutex_lock; flush_temp_entries ;;
	expire)
		if grep -q '# added .* ttl=' "$ALLOW_HOSTS" "$DENY_HOSTS" "$CC_DENY_HOSTS" "$CC_ALLOW_HOSTS" 2>/dev/null; then  # safe: files may not exist during first run
			mutex_lock; expire_temp_entries
		fi
		;;
	*)  _cli_unknown_verb "apf trust temp" "$1" "add deny remove list flush"; return 1 ;;
	esac
}

_trust_help() {
	echo "usage: apf trust <command> [args]"
	echo ""
	echo "  add HOST [CMT]         allow a host (= apf -a)"
	echo "  deny HOST [CMT]        deny a host (= apf -d)"
	echo "  remove HOST            remove from all lists (= apf -u)"
	echo "  list                   show all trust entries"
	echo "  list --allow           show allow entries only"
	echo "  list --deny            show deny entries only"
	echo "  list --temp            show temporary entries with TTL"
	echo "  lookup HOST            check if host exists in trust system"
	echo "  refresh                re-resolve FQDNs (= apf -e)"
	echo "  flush --temp           remove all temporary entries"
	echo "  temp                   temporary trust operations (see: apf trust temp --help)"
	echo ""
	echo "  Advanced syntax:  apf trust deny \"tcp:in:d=22:s=10.0.0.0/8\""
	echo "  Country codes:    apf trust deny CN"
	echo "                    apf trust deny @EU"
	echo ""
	echo "  Examples:  apf trust add 10.0.0.1 \"office server\""
	echo "             apf trust deny tcp:in:d=22:s=10.0.0.0/8"
	echo "             apf trust list --temp"
}

_trust_temp_help() {
	echo "usage: apf trust temp <command> [args]"
	echo ""
	echo "  add HOST TTL [CMT]     temporarily allow host (5m, 1h, 7d)"
	echo "  deny HOST TTL [CMT]    temporarily deny host"
	echo "  remove HOST            remove temporary entry"
	echo "  list                   list temp entries with remaining TTL"
	echo "  flush                  remove all temporary entries"
	echo ""
	echo "  Examples:  apf trust temp add 10.0.0.1 1h \"maintenance\""
	echo "             apf trust temp deny 192.168.1.50 30m"
}
