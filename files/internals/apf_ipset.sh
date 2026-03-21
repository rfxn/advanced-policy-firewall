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
# APF ipset management

# Source guard
[[ -n "${_APF_IPSET_LOADED:-}" ]] && return 0 2>/dev/null
_APF_IPSET_LOADED=1

# shellcheck disable=SC2034
APF_IPSET_VERSION="1.0.0"

ipset_migrate_rules() {
local ipset_rules="$INSTALL_PATH/ipset.rules"
[ -f "$ipset_rules" ] || return 0
local migrated=0
local _imr_int='^[0-9]+$'
local tmp
tmp=$(mktemp "$INSTALL_PATH/.apf-XXXXXX")
_apf_reg_tmp "$tmp"
while IFS= read -r line; do
	case "$line" in
		\#*|"")
			printf '%s\n' "$line" >> "$tmp"
			continue
			;;
	esac
	local f1 f2 f3 f4 f5 f6 f7
	IFS=: read -r f1 f2 f3 f4 f5 f6 f7 <<< "$line"
	if [ -n "$f4" ] && [ "$f4" != "0" ] && [ "$f4" != "1" ]; then
		# Old 4-field format — f4 starts file_or_url; insert log=0:interval=0:maxelem=0
		local orig_path="$f4"
		[ -n "$f5" ] && orig_path="${orig_path}:${f5}"
		[ -n "$f6" ] && orig_path="${orig_path}:${f6}"
		[ -n "$f7" ] && orig_path="${orig_path}:${f7}"
		printf '%s\n' "${f1}:${f2}:${f3}:0:0:0:${orig_path}" >> "$tmp"
		migrated=$((migrated + 1))
	elif [ -n "$f5" ] && ! [[ "$f5" =~ $_imr_int ]]; then
		# v2.0.1 5-field format — f4 is log flag, f5 starts file_or_url
		local orig_path="$f5"
		[ -n "$f6" ] && orig_path="${orig_path}:${f6}"
		[ -n "$f7" ] && orig_path="${orig_path}:${f7}"
		printf '%s\n' "${f1}:${f2}:${f3}:${f4}:0:0:${orig_path}" >> "$tmp"
		migrated=$((migrated + 1))
	else
		printf '%s\n' "$line" >> "$tmp"
	fi
done < "$ipset_rules"
if [ "$migrated" -gt 0 ]; then
	command cp "$tmp" "$ipset_rules"
	eout "{ipset} migrated $migrated entries in ipset.rules to 7-field format"
fi
command rm -f "$tmp"
}

## Shared ipset populate helper: filter data file into restore format and load.
# Usage: ipset_populate_set set_name ipset_maxelem data_file
# Sets _IPSET_COUNT global with the number of entries loaded (avoids subshell).
ipset_populate_set() {
	local _ips_set="$1" _ips_max="$2" _ips_data="$3"
	local _ips_restore
	_ips_restore=$(mktemp "$INSTALL_PATH/.apf-XXXXXX")
	_apf_reg_tmp "$_ips_restore"
	awk -v max="$_ips_max" '
		BEGIN { count = 0 }
		/^[[:space:]]*#/ || /^[[:space:]]*$/ || /^;;/ { next }
		{
			entry = $1
			gsub(/;/, "", entry)
			if (entry ~ /^[0-9]+\.[0-9]+\.[0-9]+\./) {
				count++
				if (count > max) next
				print "add " set "-tmp " entry
			}
		}
	' set="$_ips_set" "$_ips_data" > "$_ips_restore"
	_IPSET_COUNT=$(wc -l < "$_ips_restore")
	if [ "$_IPSET_COUNT" -gt 0 ]; then
		$IPSET restore -exist < "$_ips_restore" 2>/dev/null
	fi
	command rm -f "$_ips_restore"
}

# Parse and validate an ipset.rules entry line.
# Sets: _IPE_NAME, _IPE_FLOW, _IPE_IPTYPE, _IPE_LOGFLAG, _IPE_INTERVAL,
#       _IPE_MAXELEM, _IPE_FILE_OR_URL
# Returns: 0 on valid entry, 1 on skip
_ipset_parse_entry() {
	local line="$1"
	local _ipe_int='^[0-9]+$'
	local _rest
	IFS=: read -r _IPE_NAME _IPE_FLOW _IPE_IPTYPE _IPE_LOGFLAG _IPE_INTERVAL _IPE_MAXELEM _rest <<< "$line"
	_IPE_FILE_OR_URL="$_rest"
	[[ "$_IPE_INTERVAL" =~ $_ipe_int ]] || _IPE_INTERVAL=0
	[[ "$_IPE_MAXELEM" =~ $_ipe_int ]] || _IPE_MAXELEM=0
	if [ -z "$_IPE_NAME" ] || [ -z "$_IPE_FLOW" ] || [ -z "$_IPE_IPTYPE" ] || [ -z "$_IPE_LOGFLAG" ] || [ -z "$_IPE_FILE_OR_URL" ]; then
		eout "{ipset} skipping malformed entry: $line"
		return 1
	fi
	if [ "$_IPE_FLOW" != "src" ] && [ "$_IPE_FLOW" != "dst" ]; then
		eout "{ipset} invalid flow '$_IPE_FLOW' in entry: $_IPE_NAME"
		return 1
	fi
	if [ "$_IPE_IPTYPE" != "ip" ] && [ "$_IPE_IPTYPE" != "net" ]; then
		eout "{ipset} invalid type '$_IPE_IPTYPE' in entry: $_IPE_NAME"
		return 1
	fi
	if [ "$_IPE_LOGFLAG" != "0" ] && [ "$_IPE_LOGFLAG" != "1" ]; then
		eout "{ipset} invalid log value '$_IPE_LOGFLAG' in entry: $_IPE_NAME"
		return 1
	fi
	return 0
}

# Download URL (if needed), validate data file, compute maxelem.
# Uses: _IPE_NAME, _IPE_FILE_OR_URL, _IPE_MAXELEM, _IPE_IPTYPE
# Sets: _IPE_DATA_FILE, _IPE_URL_TMP, _IPE_HASH_TYPE, _IPE_IPSET_MAXELEM
# Returns: 0 on success, 1 on failure (cleans up tmp on error)
_ipset_resolve_data() {
	local _ipe_url='^https?://'
	_IPE_DATA_FILE=""
	_IPE_URL_TMP=""
	_IPE_HASH_TYPE="hash:$_IPE_IPTYPE"
	if [[ "$_IPE_FILE_OR_URL" =~ $_ipe_url ]]; then
		_IPE_URL_TMP=$(mktemp "$INSTALL_PATH/.apf-XXXXXX")
		_apf_reg_tmp "$_IPE_URL_TMP"
		# Error policy: ipset continues with next entry (non-blocking)
		if ! download_url "$_IPE_FILE_OR_URL" "$_IPE_URL_TMP"; then
			eout "{ipset} download failed for $_IPE_NAME: $_IPE_FILE_OR_URL"
			command rm -f "$_IPE_URL_TMP"
			_IPE_URL_TMP=""
			return 1
		fi
		_IPE_DATA_FILE="$_IPE_URL_TMP"
	else
		_IPE_DATA_FILE="$_IPE_FILE_OR_URL"
	fi
	if [ ! -f "$_IPE_DATA_FILE" ] || [ ! -s "$_IPE_DATA_FILE" ]; then
		eout "{ipset} empty or missing data for $_IPE_NAME"
		[ -n "$_IPE_URL_TMP" ] && command rm -f "$_IPE_URL_TMP"
		_IPE_URL_TMP=""
		return 1
	fi
	_IPE_IPSET_MAXELEM=1048576
	if [ "$_IPE_MAXELEM" -gt 0 ]; then
		_IPE_IPSET_MAXELEM="$_IPE_MAXELEM"
		[ "$_IPE_IPSET_MAXELEM" -gt 1048576 ] && _IPE_IPSET_MAXELEM=1048576
	fi
	return 0
}

ipset_load() {
if [ "$USE_IPSET" != "1" ] || [ -z "$IPSET" ]; then
	return
fi
local ipset_rules="$INSTALL_PATH/ipset.rules"
if [ ! -f "$ipset_rules" ]; then
	return
fi
ipset_migrate_rules
eout "{ipset} loading ipset block lists"
while IFS= read -r line; do
	case "$line" in
		\#*|"") continue ;;
	esac

	_ipset_parse_entry "$line" || continue
	eout "{ipset} loading set $_IPE_NAME from $_IPE_FILE_OR_URL"
	_ipset_resolve_data || continue

	# Create sets and populate with atomic swap
	$IPSET create "$_IPE_NAME" "$_IPE_HASH_TYPE" maxelem "$_IPE_IPSET_MAXELEM" 2>/dev/null || true  # safe: set may already exist
	$IPSET create "${_IPE_NAME}-tmp" "$_IPE_HASH_TYPE" maxelem "$_IPE_IPSET_MAXELEM" 2>/dev/null || true  # safe: set may already exist
	$IPSET flush "${_IPE_NAME}-tmp"

	ipset_populate_set "$_IPE_NAME" "$_IPE_IPSET_MAXELEM" "$_IPE_DATA_FILE"
	local count="$_IPSET_COUNT"

	[ -n "$_IPE_URL_TMP" ] && command rm -f "$_IPE_URL_TMP"

	if [ "$count" -eq 0 ]; then
		eout "{ipset} no valid entries for $_IPE_NAME, skipping"
		$IPSET destroy "${_IPE_NAME}-tmp" 2>/dev/null
		$IPSET destroy "$_IPE_NAME" 2>/dev/null
		continue
	fi

	$IPSET swap "${_IPE_NAME}-tmp" "$_IPE_NAME"
	$IPSET flush "${_IPE_NAME}-tmp"
	$IPSET destroy "${_IPE_NAME}-tmp" 2>/dev/null
	eout "{ipset} loaded $count entries into $_IPE_NAME ($_IPE_HASH_TYPE)"
	ipset_update_timestamp "$_IPE_NAME" "$(date +%s)"

	# Create iptables chain (IPv4 only — ipset entries are IPv4-filtered)
	ipt4 -N "IPSET_${_IPE_NAME}" 2>/dev/null
	if [ "$_IPE_LOGFLAG" == "1" ] && [ "$LOG_DROP" == "1" ]; then
		ipt4 -A "IPSET_${_IPE_NAME}" -m set --match-set "$_IPE_NAME" "$_IPE_FLOW" -m limit --limit="${IPSET_LOG_RATE}/minute" -j $LOG_TARGET --log-level=$LOG_LEVEL $LEXT --log-prefix="** IPSET_${_IPE_NAME} ** "
	fi
	ipt4 -A "IPSET_${_IPE_NAME}" -m set --match-set "$_IPE_NAME" "$_IPE_FLOW" -j $ALL_STOP
	ipt4 -A INPUT -j "IPSET_${_IPE_NAME}"
	ipt4 -A OUTPUT -j "IPSET_${_IPE_NAME}"
done < "$ipset_rules"
}

ipset_update_timestamp() {
local ts_name="$1"
local ts_epoch="$2"
local ts_file="$INSTALL_PATH/internals/.ipset.timestamps"
local ts_tmp
ts_tmp=$(mktemp "$INSTALL_PATH/.apf-XXXXXX")
_apf_reg_tmp "$ts_tmp"
if [ -f "$ts_file" ]; then
	grep -v "^${ts_name}:" "$ts_file" > "$ts_tmp" 2>/dev/null || true  # safe: empty result is valid (new timestamp entry)
fi
printf '%s\n' "${ts_name}:${ts_epoch}" >> "$ts_tmp"
command cp "$ts_tmp" "$ts_file"
chmod 600 "$ts_file"
command rm -f "$ts_tmp"
}

ipset_update() {
if [ "$USE_IPSET" != "1" ] || [ -z "$IPSET" ]; then
	return
fi
local ipset_rules="$INSTALL_PATH/ipset.rules"
if [ ! -f "$ipset_rules" ]; then
	return
fi
eout "{ipset} updating ipset block lists"
while IFS= read -r line; do
	case "$line" in
		\#*|"") continue ;;
	esac

	_ipset_parse_entry "$line" || continue

	# Only update sets that already exist (created during full load)
	if ! $IPSET list "$_IPE_NAME" > /dev/null 2>&1; then
		continue
	fi

	# Check per-list interval before downloading
	local eff_interval="$_IPE_INTERVAL"
	[ "$eff_interval" -eq 0 ] && eff_interval="${IPSET_REFRESH:-21600}"
	local ts_file="$INSTALL_PATH/internals/.ipset.timestamps"
	if [ -f "$ts_file" ]; then
		local last_ts
		last_ts=$(grep "^${_IPE_NAME}:" "$ts_file" 2>/dev/null | tail -1)
		if [ -n "$last_ts" ]; then
			local last_epoch="${last_ts#*:}"
			local now_epoch
			now_epoch=$(date +%s)
			local elapsed=$((now_epoch - last_epoch))
			if [ "$elapsed" -lt "$eff_interval" ]; then
				eout "{ipset} skipping $_IPE_NAME (refreshes in $((eff_interval - elapsed))s)"
				continue
			fi
		fi
	fi

	eout "{ipset} updating set $_IPE_NAME from $_IPE_FILE_OR_URL"
	_ipset_resolve_data || continue

	$IPSET create "${_IPE_NAME}-tmp" "$_IPE_HASH_TYPE" maxelem "$_IPE_IPSET_MAXELEM" 2>/dev/null || true  # safe: set may already exist
	$IPSET flush "${_IPE_NAME}-tmp"

	ipset_populate_set "$_IPE_NAME" "$_IPE_IPSET_MAXELEM" "$_IPE_DATA_FILE"
	local count="$_IPSET_COUNT"

	[ -n "$_IPE_URL_TMP" ] && command rm -f "$_IPE_URL_TMP"

	if [ "$count" -gt 0 ]; then
		$IPSET swap "${_IPE_NAME}-tmp" "$_IPE_NAME"
		eout "{ipset} updated $_IPE_NAME with $count entries"
		ipset_update_timestamp "$_IPE_NAME" "$(date +%s)"
	fi
	$IPSET flush "${_IPE_NAME}-tmp" 2>/dev/null
	$IPSET destroy "${_IPE_NAME}-tmp" 2>/dev/null
done < "$ipset_rules"
}

ipset_flush() {
if [ -z "$IPSET" ]; then
	return
fi
local ipset_rules="$INSTALL_PATH/ipset.rules"
if [ ! -f "$ipset_rules" ]; then
	return
fi
while IFS= read -r line; do
	case "$line" in
		\#*|"") continue ;;
	esac
	local name
	name="${line%%:*}"
	[ -z "$name" ] && continue
	$IPSET destroy "$name" 2>/dev/null || true       # safe: set may not exist
	$IPSET destroy "${name}-tmp" 2>/dev/null || true  # safe: set may not exist
done < "$ipset_rules"
command rm -f "$INSTALL_PATH/internals/.ipset.timestamps"
}
