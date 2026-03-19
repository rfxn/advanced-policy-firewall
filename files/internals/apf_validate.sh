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
# APF input and configuration validation

# Source guard
[[ -n "${_APF_VALIDATE_LOADED:-}" ]] && return 0 2>/dev/null
_APF_VALIDATE_LOADED=1

# shellcheck disable=SC2034
APF_VALIDATE_VERSION="1.0.0"

# Parse human-readable TTL string into seconds.
# Sets _TTL_SECONDS (variable-return, no subshell).
# Accepts: bare seconds (300), or suffix: s/m/h/d (300s, 5m, 1h, 7d).
# Returns 1 on invalid or zero input.
parse_ttl() {
	local val="$1"
	local num factor=1
	local _pt_int='^[0-9]+$'
	case "$val" in
		*d) num="${val%d}" ; factor=86400 ;;
		*h) num="${val%h}" ; factor=3600 ;;
		*m) num="${val%m}" ; factor=60 ;;
		*s) num="${val%s}" ;;
		*)  num="$val" ;;
	esac
	if ! [[ "$num" =~ $_pt_int ]] || [ "$num" -eq 0 ]; then
		return 1
	fi
	_TTL_SECONDS=$(($num * $factor))
	return 0
}

expand_port() {
	# Convert underscore port ranges to colon format for iptables
	# Input: "6881_6889" → _PORT="6881:6889"; "22" → _PORT="22"
	if [[ "$1" == *_* ]]; then
		_PORT="${1//_/:}"
	else
		_PORT="$1"
	fi
}

valid_ip_cidr() {
	local _vic_ipv4='^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$'
	[[ "$1" =~ $_vic_ipv4 ]] || return 1
	local IFS='./'; set -- $1
	[ "$1" -le 255 ] && [ "$2" -le 255 ] && [ "$3" -le 255 ] && [ "$4" -le 255 ] || return 1
	[ -n "$5" ] && { [ "$5" -le 32 ] || return 1; }
	return 0
}

valid_host() {
	local h="$1"
	local _vh_ipv4='^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$'
	local _vh_ipv6='^[0-9a-fA-F]{0,4}(:[0-9a-fA-F]{0,4}){2,7}(/[0-9]{1,3})?$'
	local _vh_fqdn='^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$'
	# IPv4 address or CIDR — delegate to valid_ip_cidr for octet/mask range checking
	if [[ "$h" =~ $_vh_ipv4 ]]; then
		valid_ip_cidr "$h"
		return $?
	fi
	# IPv6 address or CIDR
	if [[ "$h" =~ $_vh_ipv6 ]]; then
		if [[ "$h" == */* ]]; then
			local mask="${h##*/}"
			[ "$mask" -le 128 ] || return 1
		fi
		return 0
	fi
	# FQDN: requires at least one dot, alphanumeric labels, TLD 2+ chars
	if [[ "$h" =~ $_vh_fqdn ]]; then
		return 0
	fi
	return 1
}

# Detect whether input is an FQDN (not an IP or CIDR).
# Reuses the FQDN regex from valid_host().
# Excludes IPv4 addresses — they match the dot-separated alphanumeric pattern.
is_fqdn() {
	local _if_ipv4='^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$'
	[[ "$1" =~ $_if_ipv4 ]] && return 1
	local _if_fqdn='^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$'
	[[ "$1" =~ $_if_fqdn ]]
}

# Validate ISO 3166-1 country code or continent shorthand.
# Thin wrapper: delegates to geoip_validate_cc() then bridges output variables.
# Sets: _VCC_TYPE ("country" or "continent"), _VCC_CODES (comma-separated CCs)
# Accepts: XX (2-letter country code) or @XX (continent shorthand).
# Returns 1 on invalid input.
valid_cc() {
	if ! geoip_validate_cc "$1"; then
		_VCC_TYPE=""
		_VCC_CODES=""
		return 1
	fi
	_VCC_TYPE="$_GEOIP_VCC_TYPE"
	_VCC_CODES="$_GEOIP_VCC_CODES"
	return 0
}

# Check if country code filtering is active (entries exist in cc rules files).
# Returns 0 if either CC_DENY_HOSTS or CC_ALLOW_HOSTS has non-comment entries.
cc_enabled() {
	# shellcheck disable=SC2154
	{ [ -f "$CC_DENY_HOSTS" ] && grep -qvE '^(#|$)' "$CC_DENY_HOSTS" 2>/dev/null; } || \
	{ [ -f "$CC_ALLOW_HOSTS" ] && grep -qvE '^(#|$)' "$CC_ALLOW_HOSTS" 2>/dev/null; }
}

# Check if CT_LIMIT (connection tracking limit) is enabled.
# Returns 0 if CT_LIMIT is set to a positive integer.
ct_enabled() { [ -n "$CT_LIMIT" ] && [ "$CT_LIMIT" != "0" ]; }

# Expand continent shorthand to comma-separated country codes.
# Thin wrapper: uses geoip_lib module-level continent variables, then bridges
# the result into APF's _VCC_CODES. Also sets _GEOIP_VCC_CODES so that
# geoip_validate_cc() (which reads _GEOIP_VCC_CODES) works correctly when
# it calls this function.
# Returns 1 for unknown continent.
# Note: cannot delegate to geoip_lib's geoip_expand_codes() because both
# share the same function name (last definition wins, causing recursion).
geoip_expand_codes() {
	local input="$1"
	case "$input" in
		@AF) _VCC_CODES="$_GEOIP_CC_AF" ;;
		@AS) _VCC_CODES="$_GEOIP_CC_AS" ;;
		@EU) _VCC_CODES="$_GEOIP_CC_EU" ;;
		@NA) _VCC_CODES="$_GEOIP_CC_NA" ;;
		@SA) _VCC_CODES="$_GEOIP_CC_SA" ;;
		@OC) _VCC_CODES="$_GEOIP_CC_OC" ;;
		*) return 1 ;;
	esac
	_GEOIP_VCC_CODES="$_VCC_CODES"
	return 0
}

# geoip_cc_name() — provided by geoip_lib.sh (identical signature).
# APF's copy removed; the library definition is authoritative.

# Strip control characters from trust comment field (caller's CMT variable)
_sanitize_comment() {
	CMT="${CMT//$'\n'/ }"
	CMT="${CMT//$'\r'/}"
	CMT="${CMT//$'\t'/ }"
}

validate_config() {
 local err=""
 local _vc_rate='^[0-9]+/[smh]$'
 local _vc_int='^[0-9]+$'
 local _vc_name _vc_val _vc_entry
 # Validate IFACE_UNTRUSTED is set
 if [ -z "$IFACE_UNTRUSTED" ]; then
    err="${err}IFACE_UNTRUSTED is not set (conf.apf must define the untrusted network interface); "
 fi
 # Validate stop targets
 for _vc_pair in "TCP_STOP:$TCP_STOP" "UDP_STOP:$UDP_STOP" "ALL_STOP:$ALL_STOP"; do
    _vc_name="${_vc_pair%%:*}"; _vc_val="${_vc_pair#*:}"
    case "$_vc_val" in
        DROP|REJECT|RESET|PROHIBIT) ;;
        *) err="${err}${_vc_name}='${_vc_val}' is invalid (must be DROP, REJECT, RESET, or PROHIBIT); " ;;
    esac
 done
 # Validate SYNFLOOD rate/burst (only when enabled)
 if [ "$SYNFLOOD" == "1" ]; then
    if [[ ! "$SYNFLOOD_RATE" =~ $_vc_rate ]]; then
        err="${err}SYNFLOOD_RATE='$SYNFLOOD_RATE' is invalid (must be number/s, number/m, or number/h); "
    fi
    if [[ ! "$SYNFLOOD_BURST" =~ $_vc_int ]]; then
        err="${err}SYNFLOOD_BURST='$SYNFLOOD_BURST' is invalid (must be a positive integer); "
    elif [ "$SYNFLOOD_BURST" == "0" ]; then
        err="${err}SYNFLOOD_BURST='0' is invalid (must be greater than 0); "
    fi
 fi
 # Validate RAB settings (only when RAB is enabled)
 if [ "$RAB" == "1" ]; then
    case "$RAB_PSCAN_LEVEL" in
        0|1|2|3) ;;
        *) err="${err}RAB_PSCAN_LEVEL='$RAB_PSCAN_LEVEL' is invalid (must be 0, 1, 2, or 3); " ;;
    esac
    if [[ ! "$RAB_HITCOUNT" =~ $_vc_int ]]; then
        err="${err}RAB_HITCOUNT='$RAB_HITCOUNT' is invalid (must be a non-negative integer); "
    fi
    if [[ ! "$RAB_TIMER" =~ $_vc_int ]]; then
        err="${err}RAB_TIMER='$RAB_TIMER' is invalid (must be a positive integer); "
    elif [ "$RAB_TIMER" == "0" ]; then
        err="${err}RAB_TIMER='0' is invalid (must be greater than 0); "
    fi
 fi
 # Validate ICMP_LIM rate format (only when set and non-zero)
 if [ -n "$ICMP_LIM" ] && [ "$ICMP_LIM" != "0" ]; then
    if [[ ! "$ICMP_LIM" =~ $_vc_rate ]]; then
        err="${err}ICMP_LIM='$ICMP_LIM' is invalid (must be 0 or number/s, number/m, or number/h); "
    fi
 fi
 # Validate LOG_LEVEL (only when LOG_DROP is enabled)
 if [ "$LOG_DROP" == "1" ] && [ -n "$LOG_LEVEL" ]; then
    case "$LOG_LEVEL" in
        emerg|alert|crit|err|warning|notice|info|debug) ;;
        *) err="${err}LOG_LEVEL='$LOG_LEVEL' is invalid (must be emerg, alert, crit, err, warning, notice, info, or debug); " ;;
    esac
 fi
 # Validate LOG_TARGET (only when LOG_DROP is enabled)
 if [ "$LOG_DROP" == "1" ] && [ -n "$LOG_TARGET" ]; then
    case "$LOG_TARGET" in
        LOG|ULOG|NFLOG) ;;
        *) err="${err}LOG_TARGET='$LOG_TARGET' is invalid (must be LOG, ULOG, or NFLOG); " ;;
    esac
 fi
 # Validate LOG_RATE (only when LOG_DROP is enabled)
 if [ "$LOG_DROP" == "1" ] && [ -n "$LOG_RATE" ]; then
    if [[ ! "$LOG_RATE" =~ $_vc_int ]]; then
        err="${err}LOG_RATE='$LOG_RATE' is invalid (must be a positive integer); "
    elif [ "$LOG_RATE" == "0" ]; then
        err="${err}LOG_RATE='0' is invalid (must be greater than 0); "
    fi
 fi
 # Validate connlimit entries
 local _vc_clpat='^[0-9_]+:[0-9]+$'
 for _vc_pair in "IG_TCP_CLIMIT:$IG_TCP_CLIMIT" "IG_UDP_CLIMIT:$IG_UDP_CLIMIT"; do
    _vc_name="${_vc_pair%%:*}"; _vc_val="${_vc_pair#*:}"
    [ -z "$_vc_val" ] && continue
    for _vc_entry in ${_vc_val//,/ }; do
        [ -z "$_vc_entry" ] && continue
        if [[ ! "$_vc_entry" =~ $_vc_clpat ]]; then
            err="${err}${_vc_name} entry '${_vc_entry}' is invalid (must be port:limit or port_range:limit); "
        fi
    done
 done
 # Validate SYNCOOKIES / OVERFLOW mutual exclusion
 if [ "$SYSCTL_SYNCOOKIES" == "1" ] && [ "$SYSCTL_OVERFLOW" == "1" ]; then
    err="${err}SYSCTL_SYNCOOKIES and SYSCTL_OVERFLOW are both enabled (conf.apf recommends only one); "
 fi
 # Validate SYSCTL_CONNTRACK (when set and non-empty)
 if [ -n "$SYSCTL_CONNTRACK" ]; then
    if [[ ! "$SYSCTL_CONNTRACK" =~ $_vc_int ]]; then
        err="${err}SYSCTL_CONNTRACK='$SYSCTL_CONNTRACK' is invalid (must be a positive integer); "
    fi
 fi
 # Validate PERMBLOCK settings
 if [ -n "$PERMBLOCK_COUNT" ] && [ "$PERMBLOCK_COUNT" != "0" ]; then
    if [[ ! "$PERMBLOCK_COUNT" =~ $_vc_int ]]; then
        err="${err}PERMBLOCK_COUNT='$PERMBLOCK_COUNT' is invalid (must be a positive integer or 0); "
    fi
    if [ -n "$PERMBLOCK_INTERVAL" ] && [[ ! "$PERMBLOCK_INTERVAL" =~ $_vc_int ]]; then
        err="${err}PERMBLOCK_INTERVAL='$PERMBLOCK_INTERVAL' is invalid (must be a positive integer); "
    fi
 fi
 if [[ "$PERMBLOCK_COUNT" =~ $_vc_int ]] && [ "$PERMBLOCK_COUNT" -gt 0 ]; then
    if [[ "$PERMBLOCK_INTERVAL" =~ $_vc_int ]] && [ "$PERMBLOCK_INTERVAL" -lt 60 ]; then
        err="${err}PERMBLOCK_INTERVAL must be at least 60 seconds; "
    fi
 fi
 # Validate SET_EXPIRE (non-negative integer; 0 = disabled)
 if [ -n "$SET_EXPIRE" ]; then
    if [[ ! "$SET_EXPIRE" =~ $_vc_int ]]; then
        err="${err}SET_EXPIRE='$SET_EXPIRE' is invalid (must be a non-negative integer); "
    fi
 fi
 # Validate FQDN_TIMEOUT (positive integer; passed to timeout command)
 if [ -n "$FQDN_TIMEOUT" ]; then
    if [[ ! "$FQDN_TIMEOUT" =~ $_vc_int ]]; then
        err="${err}FQDN_TIMEOUT='$FQDN_TIMEOUT' is invalid (must be a positive integer); "
    elif [ "$FQDN_TIMEOUT" == "0" ]; then
        err="${err}FQDN_TIMEOUT='0' is invalid (must be greater than 0); "
    fi
 fi
 # Validate SET_REFRESH (non-negative integer; 0 = disabled)
 if [ -n "$SET_REFRESH" ]; then
    if [[ ! "$SET_REFRESH" =~ $_vc_int ]]; then
        err="${err}SET_REFRESH='$SET_REFRESH' is invalid (must be a non-negative integer); "
    fi
 fi
 # Validate CT_LIMIT settings (only when enabled)
 if ct_enabled; then
    if [[ ! "$CT_LIMIT" =~ $_vc_int ]]; then
        err="${err}CT_LIMIT='$CT_LIMIT' is invalid (must be a positive integer or 0); "
    fi
    if [ -n "$CT_INTERVAL" ]; then
        if [[ ! "$CT_INTERVAL" =~ $_vc_int ]]; then
            err="${err}CT_INTERVAL='$CT_INTERVAL' is invalid (must be a positive integer); "
        elif [ "$CT_INTERVAL" == "0" ]; then
            err="${err}CT_INTERVAL='0' is invalid (must be greater than 0); "
        fi
    fi
    if [ -n "$CT_BLOCK_TIME" ]; then
        if [[ ! "$CT_BLOCK_TIME" =~ $_vc_int ]]; then
            err="${err}CT_BLOCK_TIME='$CT_BLOCK_TIME' is invalid (must be a positive integer); "
        elif [ "$CT_BLOCK_TIME" == "0" ]; then
            err="${err}CT_BLOCK_TIME='0' is invalid (must be greater than 0); "
        fi
    fi
 fi
 if [ -n "$err" ]; then
    eout "{glob} configuration error: $err"
    [ "$SET_VERBOSE" != "1" ] && echo "apf($$): configuration error: $err"
    mutex_unlock
    exit 1
 fi
}
