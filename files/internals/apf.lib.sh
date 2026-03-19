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
# APF sourcing hub: loads upstream libraries and all apf_*.sh sub-libraries
# in dependency order. Shared micro-utilities live here.

# Source guard
[[ -n "${_APF_LIB_LOADED:-}" ]] && return 0 2>/dev/null
_APF_LIB_LOADED=1

# shellcheck disable=SC2034
APF_LIB_VERSION="1.0.0"

# Resolve internals directory from this file's location
_internals_dir="${BASH_SOURCE[0]%/*}"

## Shared micro-utilities (used across 3+ sub-libraries)

eout() {
	local _msg="$1"
	local _force_stdout="${2:-0}"
	if [ -n "$_msg" ]; then
		if [ "$_force_stdout" = "1" ]; then
			elog info "$_msg" 1
		else
			elog info "$_msg"
		fi
	fi
}

devm() {
 local cron_file="/etc/cron.d/apf_develmode"
 if [ "$DEVEL_MODE" == "1" ]; then
        DEVEL_ON=1
        if [ "$SET_VERBOSE" != "1" ]; then
                eout "{glob} !!DEVELOPMENT MODE ENABLED!! - firewall will flush every 5 minutes." 1
        fi
        echo "*/5 * * * * root $INSTALL_PATH/apf -f >> /dev/null 2>&1" > "$cron_file"
        chmod 644 "$cron_file"
 elif [ "$DEVEL_MODE" == "0" ]; then
        command rm -f "$cron_file"
 fi
}

## Temp file tracking for signal-safe cleanup
_APF_TMPFILES=""
_apf_reg_tmp() { _APF_TMPFILES="$_APF_TMPFILES $1"; }
_apf_cleanup_tmp() {
	local f
	for f in $_APF_TMPFILES; do
		[ -e "$f" ] && rm -rf "$f"
	done
	_APF_TMPFILES=""
}

## Remove orphaned temp files from previous APF versions.
# Pre-2.0.2 refresh() created refresh.allow.*/refresh.drop.* temp files via
# mktemp without cleanup registration; these accumulate across restarts.
# Also cleans stale .apf-* temp files left by interrupted operations.
# Safe to call repeatedly (rm -f on non-existent files is a no-op).
_apf_cleanup_stale_tmp() {
	command rm -f "$INSTALL_PATH"/internals/refresh.allow.* 2>/dev/null
	command rm -f "$INSTALL_PATH"/internals/refresh.drop.* 2>/dev/null
	command rm -f "$INSTALL_PATH"/.apf-* 2>/dev/null
	# rm -rf for geoip: _geoip_world_fetch() creates temp directories via mktemp -d
	command rm -rf "$INSTALL_PATH"/.apf-geoip-* 2>/dev/null
}

trim() {
 local FILE="$1"
 local MAXLINES="$2"
 local LINES CHK_CMT CHK_SCMT

 if [ -z "$MAXLINES" ]; then
	MAXLINES=0
 fi
 if [ "$MAXLINES" != "0" ] && [ -f "$FILE" ]; then
	LINES=$(grep -cvE '^(#|$)' "$FILE")
        if [ "$LINES" -gt "$MAXLINES" ]; then
                eout "{glob} trimming $FILE to $MAXLINES lines"
                CHK_CMT=$(tail -n "$MAXLINES" "$FILE" | grep -c "#")
                MAXLINES=$(($CHK_CMT+$MAXLINES))
                CHK_SCMT=$(tail -n "$MAXLINES" "$FILE" | tac | tail -n 1 | grep "#")
                if [ -z "$CHK_SCMT" ]; then
                        MAXLINES=$((1+$MAXLINES))
                fi
                local _trim_tmp
                _trim_tmp=$(mktemp "$(dirname "$FILE")/.trim.XXXXXX")
                _apf_reg_tmp "$_trim_tmp"
                tail -n "$MAXLINES" "$FILE" > "$_trim_tmp"
                cat "$_trim_tmp" > "$FILE"
                command rm -f "$_trim_tmp"
        fi
 fi
}

## Source upstream shared libraries
# shellcheck disable=SC1090,SC1091
. "$_internals_dir/geoip_lib.sh"

# shellcheck disable=SC1090,SC1091
. "$_internals_dir/elog_lib.sh"
# NOTE: ELOG_* defaults (ELOG_APP, ELOG_LOG_FILE, etc.) are set by internals.conf
# AFTER this hub returns. Do not call elog/eout at source-time in sub-libraries.

## Source APF sub-libraries in dependency order

# shellcheck disable=SC1090,SC1091
. "$_internals_dir/apf_ipt.sh"

# shellcheck disable=SC1090,SC1091
. "$_internals_dir/apf_validate.sh"

# shellcheck disable=SC1090,SC1091
. "$_internals_dir/apf_trust.sh"

# shellcheck disable=SC1090,SC1091
. "$_internals_dir/apf_ipset.sh"

# shellcheck disable=SC1090,SC1091
. "$_internals_dir/apf_dlist.sh"

# shellcheck disable=SC1090,SC1091
. "$_internals_dir/apf_cli.sh"

# shellcheck disable=SC1090,SC1091
. "$_internals_dir/functions.apf"
