#!/bin/bash
# shellcheck shell=bash
##
# Advanced Policy Firewall (APF) v2.0.2
#             (C) 2002-2026, R-fx Networks <proj@rfxn.com>
#             (C) 2026, Ryan MacDonald <ryan@rfxn.com>
# This program may be freely redistributed under the terms of the GNU GPL v2
##
#
# GeoIP country code filtering — sourced on-demand by firewall/apf
# APF internal library (files/internals/apf_geoip.sh)

# Source guard: prevent double-sourcing from multiple paths
[[ -n "${_APF_GEOIP_LOADED:-}" ]] && return 0
_APF_GEOIP_LOADED=1
# shellcheck disable=SC2034
APF_GEOIP_VERSION="1.0.0"

# --- Public API ---
# geoip_load()         — main entry point (validate, download, build chains)
# geoip_update()       — re-download + atomic ipset refresh (no downtime)
# geoip_info()         — display CC status, per-country stats

# --- CLI handlers ---
# cli_cc_trust()       — handle apf -a/-d for country codes
# cli_cc_trust_advanced() — advanced syntax CC trust
# cli_cc_trust_temp()  — temporary CC trust entries
# cli_cc_remove_entry() — targeted removal of single advanced CC entry
# cli_cc_remove()      — nuke-all removal for a CC

# --- Module state ---
# Set by geoip_download() to indicate cache freshness result (0=downloaded, 1=cache hit)
_GEOIP_CACHE_HIT=0
# Set by geoip_download_all() to count actual downloads (not cache hits)
_GEOIP_DL_COUNT=0

# --- Private helpers (prefix: _geoip_) ---

## Validate that a config variable is a non-negative integer, resetting
# to a default value if not. Uses indirect expansion (bash 4.0+).
# Args: var_name default_value
_geoip_validate_int() {
	local _vname="$1" _vdefault="$2"
	local _vval="${!_vname:-$_vdefault}"
	local _vi_re='^[0-9]+$'
	if ! [[ "$_vval" =~ $_vi_re ]]; then
		eval "$_vname=\$_vdefault"
	fi
}

## Validate prerequisites for GeoIP operations.
# Returns 1 with error message if requirements not met.
geoip_validate_config() {
	if [ "$USE_IPSET" != "1" ] || [ -z "$IPSET" ]; then
		echo "Error: GeoIP country filtering requires ipset." >&2
		echo "  Set USE_IPSET=\"auto\" or \"1\" in conf.apf" >&2
		echo "  Install ipset: apt-get install ipset / yum install ipset" >&2
		return 1
	fi
	if [ -z "$CURL" ] && [ -z "$WGET" ]; then
		echo "Error: GeoIP data download requires curl or wget." >&2
		return 1
	fi
	return 0
}

## Download country IP data using geoip_lib vendor cascade.
# Wrapper: calls geoip_lib's internal download helpers (_geoip_download_ipverse,
# _geoip_download_ipdeny) directly to avoid name collision with this function.
# Note: geoip_lib's download path includes TLS fallback (--insecure) for
# CentOS 6 and other systems with outdated CA bundles, which differs from
# APF's download_url() that only logs a diagnostic hint on TLS failure.
# Caches to $CC_DATA_DIR/{CC}.{4,6}
# Args: cc family(4|6)
# Returns 0 on success (data cached), 1 on failure.
geoip_download() {
	local cc="$1" family="$2"
	local cache_file="$CC_DATA_DIR/${cc}.${family}"
	local dl_tmp valid_count
	local _cc_lower

	# Cache freshness check: skip download if cached data is fresh
	_geoip_validate_int CC_CACHE_TTL 24
	_GEOIP_CACHE_HIT=0
	local _cache_mtime _max_age_secs
	_cache_mtime=$(stat --printf='%Y' "$cache_file" 2>/dev/null) || _cache_mtime=0  # safe: file may not exist on first run
	_max_age_secs=$(( ${CC_CACHE_TTL:-24} * 3600 ))
	if [ "$_max_age_secs" -gt 0 ] && [ -s "$cache_file" ] && \
	   [ $(( $(date +%s) - _cache_mtime )) -lt "$_max_age_secs" ]; then
		_GEOIP_CACHE_HIT=1
		return 0
	fi

	command mkdir -p "$CC_DATA_DIR" 2>/dev/null  # safe: parent dir always exists
	dl_tmp=$(mktemp "$INSTALL_PATH/.apf-geoip-XXXXXX")
	_apf_reg_tmp "$dl_tmp"
	_cc_lower=$(echo "$cc" | tr '[:upper:]' '[:lower:]')

	local cc_name
	cc_name=$(geoip_cc_name "$cc")
	eout "{geoip} downloading IPv$family data for $cc_name ($cc)"
	elog_event "geoip_download" "info" "{geoip} downloading IPv$family data for $cc_name ($cc)" \
		"cc=$cc" "family=$family"

	local rc=1
	case "${CC_SRC:-auto}" in
		ipverse)
			_geoip_download_ipverse "$_cc_lower" "$family" "$dl_tmp" && rc=0
			;;
		ipdeny)
			_geoip_download_ipdeny "$_cc_lower" "$family" "$dl_tmp" && rc=0
			;;
		auto|*)
			# Tier 1: ipverse, Tier 2: ipdeny
			if _geoip_download_ipverse "$_cc_lower" "$family" "$dl_tmp"; then
				rc=0
			elif _geoip_download_ipdeny "$_cc_lower" "$family" "$dl_tmp"; then
				rc=0
			fi
			;;
	esac

	if [ "$rc" -ne 0 ] || [ ! -s "$dl_tmp" ]; then
		eout "{geoip} download failed for $cc (IPv$family)"
		command rm -f "$dl_tmp"
		# Keep existing cache if available
		return 1
	fi

	# Validate: at least some CIDR entries
	if [ "$family" = "4" ]; then
		valid_count=$(grep -cE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$' "$dl_tmp" 2>/dev/null) || valid_count=0
	else
		valid_count=$(grep -cE '^[0-9a-fA-F:]+(/[0-9]+)?$' "$dl_tmp" 2>/dev/null) || valid_count=0
	fi
	if [ "$valid_count" -eq 0 ]; then
		eout "{geoip} no valid CIDR entries in download for $cc (IPv$family)"
		command rm -f "$dl_tmp"
		return 1
	fi

	# Cache validated data
	command cat "$dl_tmp" > "$cache_file"
	command chmod 640 "$cache_file"
	command rm -f "$dl_tmp"
	eout "{geoip} cached $valid_count CIDRs for $cc (IPv$family)"
	return 0
}

## Collect country codes from a single CC rules file.
# Args: $1=file $2=include_advanced (1=include entries with '=', 0=skip)
# Sets _GAC_CODES to comma-separated CC list (may have leading comma).
_geoip_collect_ccs_from_file() {
	local file="$1" _gac_include_adv="${2:-1}"
	local line cc
	_GAC_CODES=""
	[ -f "$file" ] || return 0
	while IFS= read -r line; do
		case "$line" in '#'*|'') continue ;; esac
		if [[ "$line" == *=* ]]; then
			[ "$_gac_include_adv" = "0" ] && continue
			cc="${line##*=}"
		else
			cc="$line"
		fi
		if [[ "$cc" == @* ]]; then
			if geoip_expand_codes "$cc"; then
				_GAC_CODES="$_GAC_CODES,$_VCC_CODES"
			fi
		elif valid_cc "$cc"; then
			_GAC_CODES="$_GAC_CODES,$cc"
		fi
	done < "$file"
}

## Collect country codes from both CC deny and allow rules files.
# Args: $1=include_advanced (1=include entries with '=', 0=skip)
# Sets _GAC_CODES to combined comma-separated CC list.
_geoip_collect_active_ccs() {
	local _gac_all="" _gac_adv="${1:-1}"
	_geoip_collect_ccs_from_file "$CC_DENY_HOSTS" "$_gac_adv"
	_gac_all="$_GAC_CODES"
	_geoip_collect_ccs_from_file "$CC_ALLOW_HOSTS" "$_gac_adv"
	_GAC_CODES="${_gac_all}${_GAC_CODES}"
}

## Download data for all active country codes from both rules files.
# Parses rules, expands continents, downloads each unique CC.
# Called on every full load — downloads when cache is stale or CC_CACHE_TTL=0.
# CC_INTERVAL (days) gates the explicit geoip_update() path; CC_CACHE_TTL
# (hours) gates per-file freshness within this function.
# Sets _GEOIP_DL_COUNT to the number of CCs that required fresh downloads.
geoip_download_all() {
	local cc seen=""
	_geoip_collect_active_ccs 1
	local cc_list="$_GAC_CODES"

	# Deduplicate and download
	local _total _cur=0 _dl_count=0 _cached_count=0 _bulk_downloaded=0
	_total=$(echo "$cc_list" | tr ',' '\n' | sort -u | grep -c . || true)  # grep -c exits 1 on 0 matches

	# Bulk-first: if multiple CCs, fetch all IPv4 data in one HTTP request
	# (~844KB) instead of N individual downloads; per-CC loop then handles
	# only IPv6 downloads (IPv4 files are fresh from bulk)
	if [ "$_total" -gt 1 ]; then
		local _world_fresh=0
		_geoip_validate_int CC_CACHE_TTL 24
		if [ -f "$CC_DATA_DIR/.world_cached" ] && [ "${CC_CACHE_TTL:-24}" -gt 0 ]; then
			local _wc_mtime
			_wc_mtime=$(stat --printf='%Y' "$CC_DATA_DIR/.world_cached" 2>/dev/null) || _wc_mtime=0  # safe: marker may not exist yet
			if [ $(( $(date +%s) - _wc_mtime )) -lt $(( ${CC_CACHE_TTL:-24} * 3600 )) ]; then
				_world_fresh=1
			fi
		fi
		if [ "$_world_fresh" = "0" ]; then
			if _geoip_world_fetch 1; then
				_bulk_downloaded=1
			fi
		fi
	fi

	local IFS=','
	for cc in $cc_list; do
		[ -z "$cc" ] && continue
		case ",$seen," in *",$cc,"*) continue ;; esac
		seen="$seen,$cc"
		_cur=$((_cur + 1))
		if [ "$_total" -gt 1 ]; then
			eout "{geoip} processing $cc ($_cur/$_total)"
		fi

		geoip_download "$cc" "4"
		if [ "$_GEOIP_CACHE_HIT" = "1" ]; then
			_cached_count=$((_cached_count + 1))
		else
			_dl_count=$((_dl_count + 1))
		fi
		if [ "$CC_IPV6" = "1" ] && [ "$USE_IPV6" = "1" ]; then
			geoip_download "$cc" "6"
		fi
	done
	if [ "$_total" -gt 0 ]; then
		eout "{geoip} IPv4 download summary: $_dl_count downloaded, $_cached_count cached (fresh)"
	fi
	_GEOIP_DL_COUNT=$((_dl_count + _bulk_downloaded))
}

## Populate an ipset from cached country data using atomic swap.
# Creates apf_cc4_{CC} or apf_cc6_{CC} sets (hash:net).
# Args: cc family(4|6)
# Returns 0 on success, 1 if no data.
geoip_populate_set() {
	local cc="$1" family="$2"
	local set_name="apf_cc${family}_${cc}"
	local cache_file="$CC_DATA_DIR/${cc}.${family}"
	local maxelem=131072
	local ipset_family="inet"

	if [ ! -f "$cache_file" ] || [ ! -s "$cache_file" ]; then
		return 1
	fi

	if [ "$family" = "6" ]; then
		ipset_family="inet6"
	fi

	# Create persistent + tmp sets
	$IPSET create "$set_name" hash:net family "$ipset_family" maxelem "$maxelem" 2>/dev/null || true  # ignore if set already exists
	$IPSET create "${set_name}-tmp" hash:net family "$ipset_family" maxelem "$maxelem" 2>/dev/null || true  # ignore if set already exists
	$IPSET flush "${set_name}-tmp"

	# Populate tmp set via restore (fast batch)
	local restore_tmp
	restore_tmp=$(mktemp "$INSTALL_PATH/.apf-geoip-XXXXXX")
	_apf_reg_tmp "$restore_tmp"

	if [ "$family" = "4" ]; then
		awk -v set="$set_name" '
			/^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
			{ entry = $1; if (entry ~ /^[0-9]+\./) print "add " set "-tmp " entry }
		' "$cache_file" > "$restore_tmp"
	else
		awk -v set="$set_name" '
			/^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
			{ entry = $1; if (entry ~ /^[0-9a-fA-F:]/) print "add " set "-tmp " entry }
		' "$cache_file" > "$restore_tmp"
	fi

	local count
	count=$(wc -l < "$restore_tmp")
	if [ "$count" -gt 0 ]; then
		if $IPSET restore -exist < "$restore_tmp" 2>/dev/null; then  # -exist ignores duplicate entries
			$IPSET swap "${set_name}-tmp" "$set_name"
		else
			eout "{geoip} WARNING: ipset restore failed for $set_name, keeping existing set"
		fi
	fi
	$IPSET flush "${set_name}-tmp" 2>/dev/null || true    # cleanup tmp set
	$IPSET destroy "${set_name}-tmp" 2>/dev/null || true  # may already be destroyed after swap
	command rm -f "$restore_tmp"
	return 0
}

## Build CC iptables chains from rules files.
# Creates CC_DENY, CC_ALLOW, CC_DENYP, CC_ALLOWP chains.
# Two passes: simple entries (bare CCs) then advanced entries.
cc_rules_load() {
	local file line cc chain action
	local _has_deny=0 _has_allow=0 _has_denyp=0 _has_allowp=0
	local _file_simple_ccs _wc_cc _wc_base _exp_cc

	# Pre-scan to determine which chains are needed
	if [ -f "$CC_DENY_HOSTS" ] && grep -qvE '^(#|$)' "$CC_DENY_HOSTS" 2>/dev/null; then
		_has_deny=1
	fi
	if [ -f "$CC_ALLOW_HOSTS" ] && grep -qvE '^(#|$)' "$CC_ALLOW_HOSTS" 2>/dev/null; then
		_has_allow=1
	fi

	# Create chains as needed
	if [ "$_has_deny" = "1" ]; then
		ipt -N CC_DENY 2>/dev/null  # ignore if chain already exists (idempotent)
		ipt -A INPUT -j CC_DENY
		ipt -A OUTPUT -j CC_DENY
	fi
	if [ "$_has_allow" = "1" ]; then
		ipt -N CC_ALLOW 2>/dev/null  # ignore if chain already exists (idempotent)
		ipt -A INPUT -j CC_ALLOW
		ipt -A OUTPUT -j CC_ALLOW
	fi

	# --- Pass 1: Simple entries (bare country codes) ---
	_geoip_collect_ccs_from_file "$CC_DENY_HOSTS" 0
	local simple_deny="$_GAC_CODES"
	_geoip_collect_ccs_from_file "$CC_ALLOW_HOSTS" 0
	local simple_allow="$_GAC_CODES"

	# Populate ipsets and add chain rules for simple deny entries
	local seen=""
	local _save_ifs="$IFS"
	IFS=','
	for cc in $simple_deny; do
		[ -z "$cc" ] && continue
		case ",$seen," in *",$cc,"*) continue ;; esac
		seen="$seen,$cc"
		_geoip_add_simple_rules "$cc" "CC_DENY" "$ALL_STOP"
	done

	# Populate ipsets and add chain rules for simple allow entries
	seen=""
	for cc in $simple_allow; do
		[ -z "$cc" ] && continue
		case ",$seen," in *",$cc,"*) continue ;; esac
		seen="$seen,$cc"
		_geoip_add_simple_rules "$cc" "CC_ALLOW" "ACCEPT"
	done
	IFS="$_save_ifs"

	# --- Pass 2: Advanced entries (proto:flow:port:CC) ---
	for file in "$CC_DENY_HOSTS" "$CC_ALLOW_HOSTS"; do
		[ -f "$file" ] || continue
		if [ "$file" = "$CC_DENY_HOSTS" ]; then
			chain="CC_DENYP"
			action="$ALL_STOP"
		else
			chain="CC_ALLOWP"
			action="ACCEPT"
		fi
		# Collect simple CCs from this file for wildcard expansion
		_file_simple_ccs=""
		if [ "$file" = "$CC_DENY_HOSTS" ]; then
			_file_simple_ccs="$simple_deny"
		else
			_file_simple_ccs="$simple_allow"
		fi
		while IFS= read -r line; do
			case "$line" in '#'*|'') continue ;; esac
			[[ "$line" == *=* ]] || continue
			# Extract CC from last field
			cc="${line##*=}"
			if [ "$cc" = "*" ]; then
				# Wildcard: expand to all simple CCs from this file
				_wc_base="${line%=*}="
				for _wc_cc in ${_file_simple_ccs//,/ }; do
					[ -z "$_wc_cc" ] && continue
					_geoip_add_advanced_rule "${_wc_base}${_wc_cc}" "$_wc_cc" "$chain" "$action"
				done
				continue
			fi
			if [[ "$cc" == @* ]]; then
				if ! geoip_expand_codes "$cc"; then continue; fi
				for _exp_cc in ${_VCC_CODES//,/ }; do
					_geoip_add_advanced_rule "$line" "$_exp_cc" "$chain" "$action"
				done
			elif valid_cc "$cc"; then
				_geoip_add_advanced_rule "$line" "$cc" "$chain" "$action"
			fi
		done < "$file"
	done

	# If CC_ALLOW has simple entries, add default deny after allow rules
	if [ -n "$simple_allow" ]; then
		_geoip_default_deny_tail "CC_ALLOW"
	fi
}

## Append the CC_ALLOW implicit deny-all tail rules (log + drop/reject).
# Called at the end of cc_rules_load() when CC_ALLOW has entries.
# Handles both IPv4 and IPv6 stacks, audit mode, and log toggle.
# Args: chain
_geoip_default_deny_tail() {
	local chain="$1"
	if [ "$CC_LOG_ONLY" = "1" ]; then
		ipt4 -A "$chain" -m limit --limit="$LOG_RATE/minute" \
			-j "$LOG_TARGET" --log-level="$LOG_LEVEL" $LEXT --log-prefix="** CC_AUDIT:DEFAULT ** "
	else
		if [ "$CC_LOG" = "1" ] && [ "$LOG_DROP" = "1" ]; then
			ipt4 -A "$chain" -m limit --limit="$LOG_RATE/minute" \
				-j "$LOG_TARGET" --log-level="$LOG_LEVEL" $LEXT --log-prefix="** CC_DENY:DEFAULT ** "
		fi
		ipt4 -A "$chain" -j "$ALL_STOP"
	fi
	if [ "$CC_IPV6" = "1" ] && [ "$USE_IPV6" = "1" ]; then
		if [ "$CC_LOG_ONLY" = "1" ]; then
			ipt6 -A "$chain" -m limit --limit="$LOG_RATE/minute" \
				-j "$LOG_TARGET" --log-level="$LOG_LEVEL" $LEXT --log-prefix="** CC_AUDIT:DEFAULT ** "
		else
			if [ "$CC_LOG" = "1" ] && [ "$LOG_DROP" = "1" ]; then
				ipt6 -A "$chain" -m limit --limit="$LOG_RATE/minute" \
					-j "$LOG_TARGET" --log-level="$LOG_LEVEL" $LEXT --log-prefix="** CC_DENY:DEFAULT ** "
			fi
			ipt6 -A "$chain" -j "$ALL_STOP"
		fi
	fi
}

## Ensure a CC chain exists and has INPUT/OUTPUT jumps.
# Creates the chain if needed and adds jump rules for both stacks.
# Args: action (DENY or ALLOW)
# Sets: _EGCC_CHAIN to the resolved chain name
_geoip_ensure_cc_chain() {
	local action="$1"
	if [ "$action" = "DENY" ]; then
		_EGCC_CHAIN="CC_DENY"
	else
		_EGCC_CHAIN="CC_ALLOW"
	fi
	ipt -N "$_EGCC_CHAIN" 2>/dev/null  # ignore if chain already exists (idempotent)
	# Ensure jump exists in INPUT/OUTPUT (check both stacks independently)
	if ! $IPT $IPT_FLAGS -S INPUT 2>/dev/null | grep -q -- "-j $_EGCC_CHAIN"; then
		ipt4 -A INPUT -j "$_EGCC_CHAIN"
		ipt4 -A OUTPUT -j "$_EGCC_CHAIN"
	fi
	if [ "$USE_IPV6" = "1" ] && ! $IP6T $IPT_FLAGS -S INPUT 2>/dev/null | grep -q -- "-j $_EGCC_CHAIN"; then
		ipt6 -A INPUT -j "$_EGCC_CHAIN"
		ipt6 -A OUTPUT -j "$_EGCC_CHAIN"
	fi
}

## Add simple (bare CC) iptables rules for a country.
# Creates ipset match rules in the specified chain.
# Args: cc chain action
_geoip_add_simple_rules() {
	# Reset IFS defensively — callers (cc_rules_load, cli_cc_trust,
	# cli_cc_trust_temp) may have IFS=',' active, which breaks unquoted
	# $LEXT word splitting in LOG rules (S-004 fix)
	local IFS=$' \t\n'
	local cc="$1" chain="$2" action="$3"
	local set4="apf_cc4_${cc}"
	local cc_name
	cc_name=$(geoip_cc_name "$cc")

	# Populate IPv4 ipset
	geoip_populate_set "$cc" "4"
	if $IPSET list -t "$set4" > /dev/null 2>&1; then
		if [ "$CC_LOG_ONLY" = "1" ]; then
			ipt4 -A "$chain" -m set --match-set "$set4" src -m limit \
				--limit="$LOG_RATE/minute" -j "$LOG_TARGET" --log-level="$LOG_LEVEL" \
				$LEXT --log-prefix="** CC_AUDIT:${cc} ** "
		else
			if [ "$CC_LOG" = "1" ] && [ "$LOG_DROP" = "1" ]; then
				ipt4 -A "$chain" -m set --match-set "$set4" src -m limit \
					--limit="$LOG_RATE/minute" -j "$LOG_TARGET" --log-level="$LOG_LEVEL" \
					$LEXT --log-prefix="** CC_${chain#CC_}:${cc} ** "
			fi
			ipt4 -A "$chain" -m set --match-set "$set4" src -j "$action"
		fi
		eout "{geoip} $chain $cc_name ($cc) IPv4"
	fi

	# IPv6
	if [ "$CC_IPV6" = "1" ] && [ "$USE_IPV6" = "1" ]; then
		local set6="apf_cc6_${cc}"
		geoip_populate_set "$cc" "6"
		if $IPSET list -t "$set6" > /dev/null 2>&1; then
			if [ "$CC_LOG_ONLY" = "1" ]; then
				ipt6 -A "$chain" -m set --match-set "$set6" src -m limit \
					--limit="$LOG_RATE/minute" -j "$LOG_TARGET" --log-level="$LOG_LEVEL" \
					$LEXT --log-prefix="** CC_AUDIT:${cc} ** "
			else
				if [ "$CC_LOG" = "1" ] && [ "$LOG_DROP" = "1" ]; then
					ipt6 -A "$chain" -m set --match-set "$set6" src -m limit \
						--limit="$LOG_RATE/minute" -j "$LOG_TARGET" --log-level="$LOG_LEVEL" \
						$LEXT --log-prefix="** CC_${chain#CC_}:${cc} ** "
				fi
				ipt6 -A "$chain" -m set --match-set "$set6" src -j "$action"
			fi
			eout "{geoip} $chain $cc_name ($cc) IPv6"
		fi
	fi
}

## Add advanced (proto:flow:port:CC) iptables rule.
# Uses trust_parse_fields() from apf_trust.sh for parsing.
# Args: entry cc chain action
_geoip_add_advanced_rule() {
	# Reset IFS defensively — prevents future regressions if callers
	# set IFS=',' before calling (same rationale as _geoip_add_simple_rules)
	local IFS=$' \t\n'
	local entry="$1" cc="$2" chain="$3" action="$4"
	local set4="apf_cc4_${cc}"

	# Create chain if not exists (may already exist from prior entries)
	ipt -N "$chain" 2>/dev/null  # fails silently if chain already exists

	# Replace CC in entry with placeholder for parsing
	local parse_entry="${entry%=*}=PLACEHOLDER"
	trust_protect_ipv6 "$parse_entry"
	trust_parse_fields "$_TPV6_RESULT"

	local proto="" dir="" pflow="" port="" ipflow=""
	case "$_TF_COUNT" in
		4) proto="tcp"; pflow="$_TF1"; port="$_TF2"; ipflow="$_TF3" ;;
		5) dir="$_TF1"; pflow="$_TF2"; port="$_TF3"; ipflow="$_TF4" ;;
		6) proto="$_TF1"; dir="$_TF2"; pflow="$_TF3"; port="$_TF4"; ipflow="$_TF5" ;;
		*) return 1 ;;
	esac

	# 5-token entries (e.g., in:d=22:s=CN) default to tcp
	[ -z "$proto" ] && proto="tcp"

	expand_port "$port"; port="$_PORT"

	# Build iptables match arguments
	local match="-p $proto"
	if [ "$pflow" = "d" ]; then
		match="$match --dport $port"
	else
		match="$match --sport $port"
	fi

	# Determine which chains to apply rule to based on direction
	local _chains="INPUT OUTPUT"
	if [ "$dir" = "in" ]; then
		_chains="INPUT"
	elif [ "$dir" = "out" ]; then
		_chains="OUTPUT"
	fi

	# Populate ipset
	geoip_populate_set "$cc" "4"

	# ipset direction: if CC is source (s=CC) match src, if dest (d=CC) match dst
	local ipset_dir="src"
	[ "$ipflow" = "d" ] && ipset_dir="dst"

	# Ensure chain jump exists in the appropriate INPUT/OUTPUT chains
	local _ch
	for _ch in $_chains; do
		if ! $IPT $IPT_FLAGS -S "$_ch" 2>/dev/null | grep -q -- "-j $chain"; then
			ipt4 -A "$_ch" -j "$chain"
		fi
		if [ "$USE_IPV6" = "1" ] && ! $IP6T $IPT_FLAGS -S "$_ch" 2>/dev/null | grep -q -- "-j $chain"; then
			ipt6 -A "$_ch" -j "$chain"
		fi
	done

	if $IPSET list -t "$set4" > /dev/null 2>&1; then
		if [ "$CC_LOG_ONLY" = "1" ]; then
			ipt4 -A "$chain" $match -m set --match-set "$set4" "$ipset_dir" \
				-m limit --limit="$LOG_RATE/minute" -j "$LOG_TARGET" \
				--log-level="$LOG_LEVEL" $LEXT --log-prefix="** CC_AUDIT:${cc} ** "
		else
			if [ "$CC_LOG" = "1" ] && [ "$LOG_DROP" = "1" ]; then
				ipt4 -A "$chain" $match -m set --match-set "$set4" "$ipset_dir" \
					-m limit --limit="$LOG_RATE/minute" -j "$LOG_TARGET" \
					--log-level="$LOG_LEVEL" $LEXT --log-prefix="** CC_${chain#CC_}:${cc} ** "
			fi
			ipt4 -A "$chain" $match -m set --match-set "$set4" "$ipset_dir" -j "$action"
		fi
	fi

	# IPv6
	if [ "$CC_IPV6" = "1" ] && [ "$USE_IPV6" = "1" ]; then
		local set6="apf_cc6_${cc}"
		geoip_populate_set "$cc" "6"
		if $IPSET list -t "$set6" > /dev/null 2>&1; then
			if [ "$CC_LOG_ONLY" = "1" ]; then
				ipt6 -A "$chain" $match -m set --match-set "$set6" "$ipset_dir" \
					-m limit --limit="$LOG_RATE/minute" -j "$LOG_TARGET" \
					--log-level="$LOG_LEVEL" $LEXT --log-prefix="** CC_AUDIT:${cc} ** "
			else
				if [ "$CC_LOG" = "1" ] && [ "$LOG_DROP" = "1" ]; then
					ipt6 -A "$chain" $match -m set --match-set "$set6" "$ipset_dir" \
						-m limit --limit="$LOG_RATE/minute" -j "$LOG_TARGET" \
						--log-level="$LOG_LEVEL" $LEXT --log-prefix="** CC_${chain#CC_}:${cc} ** "
				fi
				ipt6 -A "$chain" $match -m set --match-set "$set6" "$ipset_dir" -j "$action"
			fi
		fi
	fi
}

## Fast load: recreate ipsets from cached data (no downloads).
# Called from fast load path in files/apf before iptables-restore.
# The snapshot references --match-set, so ipsets must exist first.
_geoip_fast_load_ipsets() {
	if [ "$USE_IPSET" != "1" ] || [ -z "$IPSET" ]; then
		return 0
	fi
	local cc seen=""
	_geoip_collect_active_ccs 1
	local cc_list="$_GAC_CODES"

	local _fl_count=0
	local _save_ifs="$IFS"
	IFS=','
	for cc in $cc_list; do
		[ -z "$cc" ] && continue
		case ",$seen," in *",$cc,"*) continue ;; esac
		seen="$seen,$cc"
		geoip_populate_set "$cc" "4"
		if [ "$CC_IPV6" = "1" ] && [ "$USE_IPV6" = "1" ]; then
			geoip_populate_set "$cc" "6"
		fi
		_fl_count=$(($_fl_count + 1))
	done
	IFS="$_save_ifs"
	if [ "$_fl_count" -gt 0 ]; then
		eout "{geoip} $_fl_count country ipsets restored from cache for fast load"
	fi
}

## Main GeoIP load orchestrator.
# Called from firewall script when cc_enabled() returns true.
geoip_load() {
	if ! geoip_validate_config; then
		eout "{geoip} prerequisites not met, skipping country code filtering"
		return 1
	fi
	eout "{geoip} loading country code filtering"
	geoip_download_all

	# Warn if cached data is stale (>30 days)
	if geoip_is_stale "$CC_DATA_DIR" 30; then
		local _last_update _age_days
		if [ -f "$CC_DATA_DIR/.last_update" ]; then
			read -r _last_update < "$CC_DATA_DIR/.last_update"
			_age_days=$(( ($(date +%s) - _last_update) / 86400 ))
			eout "{geoip} WARNING: no --cc-update in $_age_days days; run apf --cc-update"
		else
			eout "{geoip} WARNING: no --cc-update on record; run apf --cc-update"
		fi
	fi

	cc_rules_load
	elog_event "rule_loaded" "info" "{geoip} country code chains loaded" \
		"deny=$CC_DENY_HOSTS" "allow=$CC_ALLOW_HOSTS"
}

## Update GeoIP data and refresh ipsets atomically (zero downtime).
# Called from apf --cc-update.
geoip_update() {
	if ! geoip_validate_config; then
		return 1
	fi

	# Check interval: skip if last update was recent enough
	_geoip_validate_int CC_INTERVAL 7
	if ! geoip_is_stale "$CC_DATA_DIR" "${CC_INTERVAL:-7}"; then
		eout "{geoip} data is fresh (interval: ${CC_INTERVAL:-7}d), skipping update"
		return 0
	fi

	eout "{geoip} updating country code data"
	geoip_download_all

	# Re-populate all active ipsets with atomic swap
	# Process substitution avoids subshell variable loss from pipeline
	local cc family set_name
	while IFS= read -r set_name; do
		# Parse set name: apf_cc{4,6}_{CC}
		family="${set_name#apf_cc}"
		family="${family%%_*}"
		cc="${set_name#apf_cc${family}_}"
		geoip_populate_set "$cc" "$family"
	done < <($IPSET list -n 2>/dev/null | grep '^apf_cc')

	# Always mark updated — we passed the staleness gate (geoip_is_stale
	# returned true) and confirmed all data is current. If downloads
	# occurred the data is fresh; if all CCs are cache hits, the data was
	# already fresh. Either way the timestamp should reflect confirmation.
	geoip_mark_updated "$CC_DATA_DIR"
	if [ "${_GEOIP_DL_COUNT:-0}" -gt 0 ]; then
		eout "{geoip} country code data updated"
	else
		eout "{geoip} country code data confirmed current, no downloads needed"
	fi
}

## Download IPv4 CIDR data for all countries from ipdeny.com all-zones tarball.
# Populates $CC_DATA_DIR with CC.4 files for all countries in the tarball.
# Args: overwrite(0|1) — 0 (default) preserves existing files; 1 overwrites all
# Sets .world_cached marker on success.
# Returns 0 on success, 1 on failure.
_geoip_world_fetch() {
	local _overwrite="${1:-0}"
	local url="https://www.ipdeny.com/ipblocks/data/countries/all-zones.tar.gz"
	local tmp_tar tmp_dir count=0

	command mkdir -p "$CC_DATA_DIR" 2>/dev/null  # safe: parent dir always exists
	tmp_tar=$(mktemp "$INSTALL_PATH/.apf-geoip-XXXXXX") || return 1
	_apf_reg_tmp "$tmp_tar"
	tmp_dir=$(mktemp -d "$INSTALL_PATH/.apf-geoip-world-XXXXXX") || { command rm -f "$tmp_tar"; return 1; }
	_apf_reg_tmp "$tmp_dir"

	eout "{geoip} fetching world IPv4 data from ipdeny.com (~1MB)"
	if ! download_url "$url" "$tmp_tar"; then
		eout "{geoip} world data download failed"
		command rm -f "$tmp_tar"
		command rm -rf "$tmp_dir"
		return 1
	fi

	if ! tar -xzf "$tmp_tar" -C "$tmp_dir" 2>/dev/null; then
		eout "{geoip} world data extract failed"
		command rm -f "$tmp_tar"
		command rm -rf "$tmp_dir"
		return 1
	fi

	local _cc_lre='^[a-z]{2}$'
	local f cc_lower cc
	for f in "$tmp_dir"/*.zone; do
		[ -f "$f" ] || continue
		cc_lower=$(basename "$f" .zone)
		if ! [[ "$cc_lower" =~ $_cc_lre ]]; then
			continue
		fi
		cc=$(echo "$cc_lower" | tr '[:lower:]' '[:upper:]')
		if [ "$_overwrite" = "1" ] || [ ! -f "$CC_DATA_DIR/${cc}.4" ]; then
			command cat "$f" > "$CC_DATA_DIR/${cc}.4"
			command chmod 640 "$CC_DATA_DIR/${cc}.4"
			count=$((count + 1))
		fi
	done

	command rm -f "$tmp_tar"
	command rm -rf "$tmp_dir"

	command touch "$CC_DATA_DIR/.world_cached"
	eout "{geoip} world GeoIP data cached: $count new countries"
	return 0
}

## Look up which country an IP or CIDR belongs to from cached GeoIP data.
# Searches all cached {CC}.4 / {CC}.6 data files for a match.
# On first IPv4 miss with no world data cached, downloads all-zones and retries.
# Args: ip_or_cidr
# Prints matching country info; returns 1 if no data or no match.
_geoip_lookup_ip() {
	local query="$1"
	local family="4" is_ipv6=0
	# Detect IPv6
	if [[ "$query" == *:* ]]; then
		family="6"
		is_ipv6=1
	fi

	if [ ! -d "$CC_DATA_DIR" ]; then
		echo "No GeoIP data cached. Run: apf --cc-update" >&2
		return 1
	fi

	# Strip CIDR mask — network address used for containment check in both cases
	local query_ip="${query%%/*}"

	local matched=0 attempt=0
	while [ "$attempt" -le 1 ]; do
		matched=0

		if [ "$is_ipv6" = "0" ]; then
			# IPv4: single awk pass across all cached country files
			local -a cc4_files=()
			local _f
			for _f in "$CC_DATA_DIR"/*.4; do
				[ -f "$_f" ] && cc4_files+=("$_f")
			done
			if [ "${#cc4_files[@]}" -gt 0 ]; then
				local match_file cc_base
				local _cc_re='^[A-Z]{2}$'
				match_file=$(geoip_cidr_search "$query_ip" "${cc4_files[@]}")
				if [ -n "$match_file" ] && [ -f "$match_file" ]; then
					cc_base=$(basename "$match_file" ".4")
					if [[ "$cc_base" =~ $_cc_re ]]; then
						_geoip_print_lookup "$cc_base" "$query"
						matched=1
					fi
				fi
			fi
		else
			# IPv6: prefix-based match (no all-zones tarball available for IPv6)
			local cc_file cc_base prefix
			local _cc_re='^[A-Z]{2}$'
			prefix="${query_ip%%:*}"
			for cc_file in "$CC_DATA_DIR"/*.6; do
				[ -f "$cc_file" ] || continue
				cc_base=$(basename "$cc_file" ".6")
				if ! [[ "$cc_base" =~ $_cc_re ]]; then
					continue
				fi
				if grep -q "^${prefix}:" "$cc_file" 2>/dev/null; then
					_geoip_print_lookup "$cc_base" "$query"
					matched=1
				fi
			done
		fi

		# Stop if matched, IPv6 (no world tarball), or world data already fetched
		if [ "$matched" = "1" ] || [ "$is_ipv6" = "1" ] || [ -f "$CC_DATA_DIR/.world_cached" ]; then
			break
		fi

		# First IPv4 miss with no world data — fetch all countries and retry once
		echo "Fetching world GeoIP data for comprehensive IP lookup (~1MB, one-time)..."
		_geoip_world_fetch || break
		attempt=$((attempt + 1))
	done

	if [ "$matched" = "0" ]; then
		echo "No country match found for $query in cached GeoIP data."
		return 1
	fi
}

## Print formatted lookup result for a matched CC.
_geoip_print_lookup() {
	local cc="$1" query="$2"
	local cc_name continent continent_name rules_status
	cc_name=$(geoip_cc_name "$cc")
	continent=$(geoip_cc_continent "$cc")
	continent_name=$(geoip_continent_name "$continent")
	rules_status=$(_geoip_rules_status "$cc")
	echo "  $query => $cc ($cc_name)"
	echo "    Continent: $continent ($continent_name)"
	echo "    Status:    $rules_status"
}

## Check CC rules status — whether a CC is in deny, allow, or neither.
_geoip_rules_status() {
	local cc="$1"
	local in_deny=0 in_allow=0
	# shellcheck disable=SC2154
	if [ -f "$CC_DENY_HOSTS" ] && grep -qxF "$cc" "$CC_DENY_HOSTS" 2>/dev/null; then
		in_deny=1
	fi
	if [ -f "$CC_ALLOW_HOSTS" ] && grep -qxF "$cc" "$CC_ALLOW_HOSTS" 2>/dev/null; then
		in_allow=1
	fi
	# Also check for advanced entries referencing this CC (skip comments)
	if [ "$in_deny" = "0" ] && [ -f "$CC_DENY_HOSTS" ]; then
		if grep -vE '^(#|$)' "$CC_DENY_HOSTS" 2>/dev/null | grep -qE "(^|[=,])${cc}\$"; then
			in_deny=1
		fi
	fi
	if [ "$in_allow" = "0" ] && [ -f "$CC_ALLOW_HOSTS" ]; then
		if grep -vE '^(#|$)' "$CC_ALLOW_HOSTS" 2>/dev/null | grep -qE "(^|[=,])${cc}\$"; then
			in_allow=1
		fi
	fi

	if [ "$in_deny" = "1" ] && [ "$in_allow" = "1" ]; then
		echo "in cc_deny.rules AND cc_allow.rules (deny takes precedence)"
	elif [ "$in_deny" = "1" ]; then
		echo "in cc_deny.rules (blocked)"
	elif [ "$in_allow" = "1" ]; then
		echo "in cc_allow.rules (allowed)"
	else
		echo "not in cc_deny.rules or cc_allow.rules"
	fi
}

## Display GeoIP status and per-country statistics.
# Args: optional argument — country code, continent shorthand, or IP/CIDR to look up
geoip_info() {
	local cc_arg="${1:-}"

	# IP/CIDR lookup mode — detect IP or CIDR input and route to lookup
	# FQDNs are excluded (valid_host matches them but they're not IPs)
	if [ -n "$cc_arg" ] && ! is_fqdn "$cc_arg" && valid_host "$cc_arg" && ! valid_cc "$cc_arg"; then
		echo "GeoIP Lookup"
		echo "============"
		echo ""
		_geoip_lookup_ip "$cc_arg"
		return $?
	fi

	# When a specific CC is requested, show its detail even if filtering is inactive
	if [ -n "$cc_arg" ]; then
		if ! valid_cc "$cc_arg"; then
			echo "Invalid country code or IP address: $cc_arg" >&2
			return 1
		fi
		echo "Country Code Detail"
		echo "==================="
		echo ""
		local cc cc_name set_name count4=0 count6=0 continent continent_name rules_status
		for cc in ${_VCC_CODES//,/ }; do
			if ! geoip_cc_known "$cc"; then
				echo "Unknown country code: $cc" >&2
				return 1
			fi
			cc_name=$(geoip_cc_name "$cc")
			continent=$(geoip_cc_continent "$cc")
			continent_name=$(geoip_continent_name "$continent")
			rules_status=$(_geoip_rules_status "$cc")
			echo "  $cc ($cc_name):"
			echo "    Continent: $continent ($continent_name)"
			echo "    Status:    $rules_status"
			# On-demand download: fetch data for uncached CCs
			if [ ! -f "$CC_DATA_DIR/${cc}.4" ]; then
				echo "    Fetching IPv4 data for $cc..."
				geoip_download "$cc" "4" > /dev/null 2>&1
			fi
			if [ "$CC_IPV6" = "1" ] && [ "$USE_IPV6" = "1" ]; then
				if [ ! -f "$CC_DATA_DIR/${cc}.6" ]; then
					echo "    Fetching IPv6 data for $cc..."
					geoip_download "$cc" "6" > /dev/null 2>&1
				fi
			fi
			# Show cached data file stats
			if [ -f "$CC_DATA_DIR/${cc}.4" ]; then
				count4=$(grep -cE '^[0-9]' "$CC_DATA_DIR/${cc}.4" 2>/dev/null) || count4=0
				echo "    Cached IPv4 CIDRs: $count4"
			else
				echo "    Cached IPv4 CIDRs: (no data - download failed or CC not supported)"
			fi
			if [ "$CC_IPV6" = "1" ] && [ "$USE_IPV6" = "1" ]; then
				if [ -f "$CC_DATA_DIR/${cc}.6" ]; then
					count6=$(grep -cE '^[0-9a-fA-F]' "$CC_DATA_DIR/${cc}.6" 2>/dev/null) || count6=0
					echo "    Cached IPv6 CIDRs: $count6"
				else
					echo "    Cached IPv6 CIDRs: (no data - download failed or CC not supported)"
				fi
			fi
			# Show live ipset stats if loaded
			set_name="apf_cc4_${cc}"
			if $IPSET list "$set_name" > /dev/null 2>&1; then
				count4=$($IPSET list -t "$set_name" 2>/dev/null | awk '/^Number of entries:/ {print $NF}')
				count4="${count4:-0}"
				echo "    Live IPv4 ipset:   $count4 entries"
			fi
			if [ "$CC_IPV6" = "1" ] && [ "$USE_IPV6" = "1" ]; then
				set_name="apf_cc6_${cc}"
				if $IPSET list "$set_name" > /dev/null 2>&1; then
					count6=$($IPSET list -t "$set_name" 2>/dev/null | awk '/^Number of entries:/ {print $NF}')
					count6="${count6:-0}"
					echo "    Live IPv6 ipset:   $count6 entries"
				fi
			fi
		done
		return 0
	fi

	# Overview mode — no argument
	if ! cc_enabled; then
		echo "Country code filtering: inactive (no entries in cc_deny/cc_allow.rules)"
		echo ""
		echo "Usage: apf --cc CC    show detail for a country code (e.g., apf --cc CN)"
		echo "       apf --cc IP    look up country for an IP address (e.g., apf --cc 8.8.8.8)"
		return 0
	fi

	echo "Country Code Filtering Status"
	echo "=============================="
	echo ""
	echo "  Data source:    $CC_SRC"
	echo "  Data directory: $CC_DATA_DIR"
	echo "  Refresh:        ${CC_INTERVAL}d"
	echo "  IPv6:           $([ "$CC_IPV6" = "1" ] && [ "$USE_IPV6" = "1" ] && echo "enabled" || echo "disabled")"
	echo "  Audit mode:     $([ "$CC_LOG_ONLY" = "1" ] && echo "enabled (LOG only, no DROP)" || echo "disabled")"
	echo ""

	if [ -f "$CC_DATA_DIR/.last_update" ]; then
		local last_update age_h
		read -r last_update < "$CC_DATA_DIR/.last_update"
		age_h=$(( ($(date +%s) - last_update) / 3600 ))
		echo "  Last update:    ${age_h}h ago"
	else
		echo "  Last update:    never"
	fi
	echo ""

	# Overview: classify active CC ipsets into deny vs allow subsections.
	# For each CC in the ipset list, grep the rules files to determine
	# membership. This handles both simple (CN) and advanced (tcp:in:d=22:s=CN)
	# entries by checking if the CC appears as a word in the file.
	local _deny_out="" _allow_out="" _other_out=""
	local set_name cc family count cc_name _in_deny _in_allow _entry
	while IFS= read -r set_name; do
		family="${set_name#apf_cc}"
		family="${family%%_*}"
		cc="${set_name#apf_cc${family}_}"
		count=$($IPSET list -t "$set_name" 2>/dev/null | awk '/^Number of entries:/ {print $NF}')
		count="${count:-0}"
		cc_name=$(geoip_cc_name "$cc")
		_entry=$(printf "  %-4s %-20s IPv%s  %6d CIDRs\n" "$cc" "$cc_name" "$family" "$count")

		# Check rules file membership (skip comments)
		_in_deny=0; _in_allow=0
		if [ -f "$CC_DENY_HOSTS" ]; then
			if grep -vE '^(#|$)' "$CC_DENY_HOSTS" 2>/dev/null | grep -qE "(^|[=,])${cc}$"; then
				_in_deny=1
			fi
		fi
		if [ -f "$CC_ALLOW_HOSTS" ]; then
			if grep -vE '^(#|$)' "$CC_ALLOW_HOSTS" 2>/dev/null | grep -qE "(^|[=,])${cc}$"; then
				_in_allow=1
			fi
		fi

		if [ "$_in_deny" = "1" ]; then
			_deny_out="${_deny_out}${_entry}
"
		elif [ "$_in_allow" = "1" ]; then
			_allow_out="${_allow_out}${_entry}
"
		else
			_other_out="${_other_out}${_entry}
"
		fi
	done < <($IPSET list -n 2>/dev/null | grep '^apf_cc' | sort)

	# Print deny subsection
	if [ -n "$_deny_out" ]; then
		echo "Denied countries:"
		printf '%s' "$_deny_out"
	fi

	# Print allow subsection
	if [ -n "$_allow_out" ]; then
		[ -n "$_deny_out" ] && echo ""
		echo "Allowed countries (strict-allowlist):"
		printf '%s' "$_allow_out"
		echo "  NOTE: cc_allow.rules active — all unlisted countries are implicitly denied"
	fi

	# Fallback: show ipsets that don't match either file (shouldn't happen,
	# but provides visibility if rules files were edited out-of-band)
	if [ -n "$_other_out" ]; then
		{ [ -n "$_deny_out" ] || [ -n "$_allow_out" ]; } && echo ""
		echo "Other active ipsets (not in rules files):"
		printf '%s' "$_other_out"
	fi
}

## CLI handler for bare country code trust (apf -d CN, apf -a US).
# Routes to CC rules files, downloads data, populates ipsets, creates rules.
# Args: host chain action file comment
# Note: $file unused — CC entries route to CC_DENY_HOSTS/CC_ALLOW_HOSTS based on $action
cli_cc_trust() {
	local host="$1" chain="$2" action="$3" file="$4" comment="$5"
	local cc_list="" cc TIME ADDED_EPOCH CMT="$comment"

	[ -n "$CC_DENY_HOSTS" ] && [ -n "$CC_ALLOW_HOSTS" ] || return 1
	if ! geoip_validate_config; then
		return 1
	fi

	# Expand continents
	if [[ "$host" == @* ]]; then
		if ! geoip_expand_codes "$host"; then
			echo "Invalid continent shorthand: $host" >&2
			return 1
		fi
		cc_list="$_VCC_CODES"
	elif valid_cc "$host"; then
		cc_list="$host"
	else
		echo "Invalid country code: $host" >&2
		return 1
	fi

	# Route to correct CC file
	local cc_file
	if [ "$action" = "DENY" ]; then
		cc_file="$CC_DENY_HOSTS"
	else
		cc_file="$CC_ALLOW_HOSTS"
	fi

	local _total _cur=0
	_total=$(echo "$cc_list" | tr ',' '\n' | grep -c . || true)  # grep -c exits 1 on 0 matches
	local IFS=','
	for cc in $cc_list; do
		[ -z "$cc" ] && continue
		_cur=$((_cur + 1))
		if [ "$_total" -gt 1 ]; then
			eout "{geoip} processing $cc ($_cur/$_total)"
		fi

		# Duplicate check across both CC files
		local _cct_dup_file=""
		if grep -v '^#' "$CC_DENY_HOSTS" 2>/dev/null | grep -Fxq "$cc"; then
			_cct_dup_file="$CC_DENY_HOSTS"
		elif grep -v '^#' "$CC_ALLOW_HOSTS" 2>/dev/null | grep -Fxq "$cc"; then
			_cct_dup_file="$CC_ALLOW_HOSTS"
		fi
		if [ -n "$_cct_dup_file" ]; then
			# Check if existing entry is temporary (has ttl= and expire= markers)
			if grep -F "# added $cc " "$_cct_dup_file" 2>/dev/null | grep -q 'ttl=.*expire='; then
				if [ "$_cct_dup_file" = "$cc_file" ]; then
					# Upgrade temp → permanent: strip ttl/expire markers
					sed -i "s/\(# added ${cc} .* addedtime=[0-9]*\) ttl=[0-9]* expire=[0-9]*/\1/" "$cc_file"
					local cc_name
					cc_name=$(geoip_cc_name "$cc")
					eout "{trust} upgraded $cc_name ($cc) from temporary to permanent"
					if [ "$SET_VERBOSE" != "1" ]; then
						echo "Upgraded $cc_name ($cc) from temporary to permanent."
					fi
					elog_event "trust_upgraded" "info" "{trust} upgraded $cc_name ($cc) to permanent" \
						"host=$cc" "action=$action"
				else
					echo "$cc already exists in ${_cct_dup_file##*/}"
				fi
				continue
			fi
			echo "$cc already exists in ${_cct_dup_file##*/}"
			continue
		fi

		# Download and populate ipset
		geoip_download "$cc" "4"
		geoip_populate_set "$cc" "4"
		if [ "$CC_IPV6" = "1" ] && [ "$USE_IPV6" = "1" ]; then
			geoip_download "$cc" "6"
			geoip_populate_set "$cc" "6"
		fi

		# Create chain + jump rules if not exists (for live add without restart)
		_geoip_ensure_cc_chain "$action"
		local cc_chain="$_EGCC_CHAIN"

		# Add ipset match rules to live chain
		_geoip_add_simple_rules "$cc" "$cc_chain" "$([ "$action" = "DENY" ] && echo "$ALL_STOP" || echo "ACCEPT")"

		# Persist to rules file
		TIME=$(date +"%D %H:%M:%S")
		ADDED_EPOCH=$(date +%s)
		_sanitize_comment
		if [ -n "$CMT" ]; then
			echo "# added $cc on $TIME addedtime=$ADDED_EPOCH with comment: $CMT" >> "$cc_file"
		else
			echo "# added $cc on $TIME addedtime=$ADDED_EPOCH" >> "$cc_file"
		fi
		echo "$cc" >> "$cc_file"

		# Count CIDRs for feedback
		local count4=0 cc_name
		cc_name=$(geoip_cc_name "$cc")
		if [ -f "$CC_DATA_DIR/${cc}.4" ]; then
			count4=$(grep -cE '^[0-9]' "$CC_DATA_DIR/${cc}.4" 2>/dev/null) || count4=0
		fi
		local action_lower
		action_lower=$(echo "$action" | tr '[:upper:]' '[:lower:]')
		eout "{trust} $action $cc_name ($cc): $count4 IPv4 CIDRs"
		elog_event "trust_added" "info" "{trust} $action $cc_name ($cc)" \
			"host=$cc" "action=$action_lower"
		if [ "$SET_VERBOSE" != "1" ]; then
			echo "$action_lower $cc_name ($cc): $count4 IPv4 CIDRs"
		fi
	done
}

## CLI handler for advanced syntax CC trust (e.g., tcp:in:d=22:s=CN).
# Args: entry chain action file comment
# Note: $file unused — CC entries route to CC_DENY_HOSTS/CC_ALLOW_HOSTS based on $action
cli_cc_trust_advanced() {
	local entry="$1" chain="$2" action="$3" file="$4" comment="$5"
	local cc TIME ADDED_EPOCH CMT="$comment"

	[ -n "$CC_DENY_HOSTS" ] && [ -n "$CC_ALLOW_HOSTS" ] || return 1
	if ! geoip_validate_config; then
		return 1
	fi

	# Extract CC from last field
	cc="${entry##*=}"

	# Route to correct CC file
	local cc_file adv_chain
	if [ "$action" = "DENY" ]; then
		cc_file="$CC_DENY_HOSTS"
		adv_chain="CC_DENYP"
	else
		cc_file="$CC_ALLOW_HOSTS"
		adv_chain="CC_ALLOWP"
	fi

	# Handle continent expansion
	if [[ "$cc" == @* ]]; then
		if ! geoip_expand_codes "$cc"; then
			echo "Invalid continent shorthand: $cc" >&2
			return 1
		fi
		local _exp_cc _total _cur=0
		_total=$(echo "$_VCC_CODES" | tr ',' '\n' | grep -c . || true)  # grep -c exits 1 on 0 matches
		for _exp_cc in ${_VCC_CODES//,/ }; do
			_cur=$((_cur + 1))
			if [ "$_total" -gt 1 ]; then
				eout "{geoip} processing $_exp_cc ($_cur/$_total)"
			fi
			geoip_download "$_exp_cc" "4"
			if [ "$CC_IPV6" = "1" ] && [ "$USE_IPV6" = "1" ]; then
				geoip_download "$_exp_cc" "6"
			fi
			_geoip_add_advanced_rule "$entry" "$_exp_cc" "$adv_chain" \
				"$([ "$action" = "DENY" ] && echo "$ALL_STOP" || echo "ACCEPT")"
		done
	elif valid_cc "$cc"; then
		geoip_download "$cc" "4"
		if [ "$CC_IPV6" = "1" ] && [ "$USE_IPV6" = "1" ]; then
			geoip_download "$cc" "6"
		fi
		_geoip_add_advanced_rule "$entry" "$cc" "$adv_chain" \
			"$([ "$action" = "DENY" ] && echo "$ALL_STOP" || echo "ACCEPT")"
	else
		echo "Invalid country code in entry: $cc" >&2
		return 1
	fi

	# Persist
	TIME=$(date +"%D %H:%M:%S")
	ADDED_EPOCH=$(date +%s)
	_sanitize_comment
	if [ -n "$CMT" ]; then
		echo "# added $entry on $TIME addedtime=$ADDED_EPOCH with comment: $CMT" >> "$cc_file"
	else
		echo "# added $entry on $TIME addedtime=$ADDED_EPOCH" >> "$cc_file"
	fi
	echo "$entry" >> "$cc_file"

	local cc_name
	cc_name=$(geoip_cc_name "$cc")
	local action_lower
	action_lower=$(echo "$action" | tr '[:upper:]' '[:lower:]')
	eout "{trust} $action advanced CC rule: $entry ($cc_name)"
	elog_event "trust_added" "info" "{trust} $action advanced CC rule: $entry ($cc_name)" \
		"host=$entry" "action=$action_lower"
	if [ "$SET_VERBOSE" != "1" ]; then
		echo "$action_lower advanced CC rule: $entry ($cc_name)"
	fi
}

## CLI handler for temporary CC trust entries.
# Args: host chain action file ttl_str comment
# Note: $file unused — CC entries route to CC_DENY_HOSTS/CC_ALLOW_HOSTS based on $action
cli_cc_trust_temp() {
	local host="$1" chain="$2" action="$3" file="$4" ttl_str="$5" comment="$6"
	local cc_list="" cc TIME ADDED_EPOCH EXPIRE_EPOCH CMT="$comment"

	[ -n "$CC_DENY_HOSTS" ] && [ -n "$CC_ALLOW_HOSTS" ] || return 1
	if ! geoip_validate_config; then
		return 1
	fi

	if [ -z "$ttl_str" ]; then
		echo "a TTL value is required (e.g., 300, 5m, 1h, 7d)" >&2
		return 1
	fi
	if ! parse_ttl "$ttl_str"; then
		echo "Invalid TTL '$ttl_str': must be a positive number with optional suffix (s/m/h/d)" >&2
		return 1
	fi

	# Expand continents
	if [[ "$host" == @* ]]; then
		if ! geoip_expand_codes "$host"; then
			echo "Invalid continent shorthand: $host" >&2
			return 1
		fi
		cc_list="$_VCC_CODES"
	elif valid_cc "$host"; then
		cc_list="$host"
	else
		echo "Invalid country code: $host" >&2
		return 1
	fi

	# Route to correct CC file
	local cc_file
	if [ "$action" = "DENY" ]; then
		cc_file="$CC_DENY_HOSTS"
	else
		cc_file="$CC_ALLOW_HOSTS"
	fi

	local _total _cur=0
	_total=$(echo "$cc_list" | tr ',' '\n' | grep -c . || true)  # grep -c exits 1 on 0 matches
	local IFS=','
	for cc in $cc_list; do
		[ -z "$cc" ] && continue
		_cur=$((_cur + 1))
		if [ "$_total" -gt 1 ]; then
			eout "{geoip} processing $cc ($_cur/$_total)"
		fi

		# Duplicate check across both CC files
		if [ -f "$CC_DENY_HOSTS" ] && grep -v '^#' "$CC_DENY_HOSTS" 2>/dev/null | grep -Fxq "$cc"; then  # safe: file may be empty
			echo "$cc already exists in cc_deny.rules"
			continue
		fi
		if [ -f "$CC_ALLOW_HOSTS" ] && grep -v '^#' "$CC_ALLOW_HOSTS" 2>/dev/null | grep -Fxq "$cc"; then  # safe: file may be empty
			echo "$cc already exists in cc_allow.rules"
			continue
		fi

		# Download and populate ipset
		geoip_download "$cc" "4"
		geoip_populate_set "$cc" "4"
		if [ "$CC_IPV6" = "1" ] && [ "$USE_IPV6" = "1" ]; then
			geoip_download "$cc" "6"
			geoip_populate_set "$cc" "6"
		fi

		# Create chain + jump rules if not exists
		_geoip_ensure_cc_chain "$action"
		local cc_chain="$_EGCC_CHAIN"
		_geoip_add_simple_rules "$cc" "$cc_chain" "$([ "$action" = "DENY" ] && echo "$ALL_STOP" || echo "ACCEPT")"

		# Persist with temp markers
		TIME=$(date +"%D %H:%M:%S")
		ADDED_EPOCH=$(date +%s)
		EXPIRE_EPOCH=$(($ADDED_EPOCH + $_TTL_SECONDS))
		_sanitize_comment
		if [ -n "$CMT" ]; then
			echo "# added $cc on $TIME addedtime=$ADDED_EPOCH ttl=$_TTL_SECONDS expire=$EXPIRE_EPOCH with comment: $CMT" >> "$cc_file"
		else
			echo "# added $cc on $TIME addedtime=$ADDED_EPOCH ttl=$_TTL_SECONDS expire=$EXPIRE_EPOCH" >> "$cc_file"
		fi
		echo "$cc" >> "$cc_file"

		local cc_name expire_disp
		cc_name=$(geoip_cc_name "$cc")
		if [ "$_TTL_SECONDS" -ge 86400 ]; then
			expire_disp="$(($_TTL_SECONDS / 86400))d"
		elif [ "$_TTL_SECONDS" -ge 3600 ]; then
			expire_disp="$(($_TTL_SECONDS / 3600))h"
		elif [ "$_TTL_SECONDS" -ge 60 ]; then
			expire_disp="$(($_TTL_SECONDS / 60))m"
		else
			expire_disp="${_TTL_SECONDS}s"
		fi
		local action_lower
		action_lower=$(echo "$action" | tr '[:upper:]' '[:lower:]')
		eout "{trust} temp $action $cc_name ($cc) for $expire_disp"
		elog_event "trust_added" "info" "{trust} temp $action $cc_name ($cc)" \
			"host=$cc" "action=$action_lower" "ttl=$_TTL_SECONDS"
		if [ "$SET_VERBOSE" != "1" ]; then
			echo "temp $action_lower $cc_name ($cc) for $expire_disp"
		fi
	done
}

## Remove a single advanced CC entry from rules files and iptables.
# SYNC: parsing mirrors _geoip_add_advanced_rule:518-542
# Handles both CC_DENY and CC_ALLOW paths. If no entries remain for
# the CC after removal, delegates to cli_cc_remove() for full cleanup.
# Args: entry cc
# Returns 0 if found/removed, 1 if not found.
cli_cc_remove_entry() {
	local IFS=$' \t\n'
	local entry="$1" cc="$2"
	local found_in=""

	[ -n "$entry" ] || return 1
	if ! valid_cc "$cc"; then
		return 1
	fi
	[ -n "$CC_DENY_HOSTS" ] && [ -n "$CC_ALLOW_HOSTS" ] || return 1

	# Determine which rules file(s) contain this entry
	if [ -f "$CC_DENY_HOSTS" ] && grep -v '^#' "$CC_DENY_HOSTS" 2>/dev/null | grep -Fxq "$entry"; then
		found_in="deny"
	fi
	if [ -f "$CC_ALLOW_HOSTS" ] && grep -v '^#' "$CC_ALLOW_HOSTS" 2>/dev/null | grep -Fxq "$entry"; then
		found_in="${found_in:+${found_in},}allow"
	fi

	if [ -z "$found_in" ]; then
		return 1
	fi
	# Remove entry + its preceding comment from rules file(s)
	# Comment format: "# added ENTRY on DATE with ..."
	local escaped_entry
	escaped_entry=$(echo "$entry" | sed 's/[.\/\[\]*]/\\&/g')
	if [[ "$found_in" == *deny* ]] && [ -f "$CC_DENY_HOSTS" ]; then
		sed -i -e "\%# added ${escaped_entry} %d" \
		       -e "\%^${escaped_entry}$%d" "$CC_DENY_HOSTS"
	fi
	if [[ "$found_in" == *allow* ]] && [ -f "$CC_ALLOW_HOSTS" ]; then
		sed -i -e "\%# added ${escaped_entry} %d" \
		       -e "\%^${escaped_entry}$%d" "$CC_ALLOW_HOSTS"
	fi

	# Parse entry to reconstruct iptables match args
	# Replace CC with PLACEHOLDER for parsing (same as _geoip_add_advanced_rule:519)
	local parse_entry="${entry%=*}=PLACEHOLDER"
	trust_protect_ipv6 "$parse_entry"
	trust_parse_fields "$_TPV6_RESULT"

	local proto="" dir="" pflow="" port="" ipflow=""
	case "$_TF_COUNT" in
		4) proto="tcp"; pflow="$_TF1"; port="$_TF2"; ipflow="$_TF3" ;;
		5) dir="$_TF1"; pflow="$_TF2"; port="$_TF3"; ipflow="$_TF4" ;;
		6) proto="$_TF1"; dir="$_TF2"; pflow="$_TF3"; port="$_TF4"; ipflow="$_TF5" ;;
		*) return 1 ;;
	esac
	[ -z "$proto" ] && proto="tcp"

	expand_port "$port"; port="$_PORT"

	# Build iptables match arguments
	local match="-p $proto"
	if [ "$pflow" = "d" ]; then
		match="$match --dport $port"
	else
		match="$match --sport $port"
	fi

	# ipset direction: s=CC → src, d=CC → dst
	local ipset_dir="src"
	[ "$ipflow" = "d" ] && ipset_dir="dst"

	# Security boundary for eval (same as cli_cc_remove):
	#   1. valid_cc() constrains $cc to ^[A-Z]{2}$ at all entry points
	#   2. grep filters -S output to lines containing "apf_cc[46]_${cc}"
	#   3. _cc_eval_re regex restricts to ^-A (CC_DENY|CC_ALLOW|...) lines
	local _cc_eval_re='^-A (CC_DENY|CC_ALLOW|CC_DENYP|CC_ALLOWP) '

	# Process each chain determined by where the entry was found
	local _chain _action
	for _chain in CC_DENYP CC_ALLOWP; do
		if [[ "$_chain" == "CC_DENYP" ]]; then
			[[ "$found_in" == *deny* ]] || continue
			_action="$ALL_STOP"
		else
			[[ "$found_in" == *allow* ]] || continue
			_action="ACCEPT"
		fi

		if $IPT $IPT_FLAGS -L "$_chain" -n > /dev/null 2>&1; then
			local set4="apf_cc4_${cc}"
			# Action rule removal — fails silently under CC_LOG_ONLY=1 (no action rule exists)
			$IPT $IPT_FLAGS -D "$_chain" $match -m set --match-set "$set4" "$ipset_dir" -j "$_action" 2>/dev/null || true
			# LOG rule removal via eval (handles shell-quoted --log-prefix values).
			# iptables -S inserts "-m tcp" between "-p tcp" and "--dport N", so $match
			# cannot be used as a single fixed-string grep — match proto and port separately.
			local _port_flag="--${pflow}port"
			$IPT $IPT_FLAGS -S "$_chain" 2>/dev/null | grep "apf_cc4_${cc}" | while IFS= read -r _rule; do
				[[ "$_rule" =~ $_cc_eval_re ]] || continue
				# Only remove LOG rules matching our specific proto/port match
				if echo "$_rule" | grep -qF -- "-p $proto" && \
				   echo "$_rule" | grep -qF -- "$_port_flag $port"; then
					eval "$IPT $IPT_FLAGS -D \"$_chain\" ${_rule#-A $_chain }" 2>/dev/null || true
				fi
			done
		fi

		# IPv6
		if [ "$USE_IPV6" = "1" ] && [ "$CC_IPV6" = "1" ] && \
		   $IP6T $IPT_FLAGS -L "$_chain" -n > /dev/null 2>&1; then
			local set6="apf_cc6_${cc}"
			$IP6T $IPT_FLAGS -D "$_chain" $match -m set --match-set "$set6" "$ipset_dir" -j "$_action" 2>/dev/null || true
			$IP6T $IPT_FLAGS -S "$_chain" 2>/dev/null | grep "apf_cc6_${cc}" | while IFS= read -r _rule; do
				[[ "$_rule" =~ $_cc_eval_re ]] || continue
				if echo "$_rule" | grep -qF -- "-p $proto" && \
				   echo "$_rule" | grep -qF -- "$_port_flag $port"; then
					eval "$IP6T $IPT_FLAGS -D \"$_chain\" ${_rule#-A $_chain }" 2>/dev/null || true
				fi
			done
		fi
	done

	# If no entries remain for this CC in either rules file, perform full cleanup
	if ! _geoip_cc_has_entries "$cc"; then
		cli_cc_remove "$cc" > /dev/null 2>&1
	fi

	eout "{trust} removed advanced CC entry: $entry"
	elog_event "trust_removed" "info" "{trust} removed advanced CC entry: $entry" \
		"host=$entry"

	return 0
}

## Remove a country code from trust system.
# Removes from CC rules files, destroys ipsets, removes chain rules.
# Args: cc
# Returns 0 if found/removed, 1 if not found.
cli_cc_remove() {
	local cc="$1"
	local found=0

	[ -n "$CC_DENY_HOSTS" ] && [ -n "$CC_ALLOW_HOSTS" ] || return 1

	# Expand continent
	if [[ "$cc" == @* ]]; then
		if geoip_expand_codes "$cc"; then
			local _exp_cc
			for _exp_cc in ${_VCC_CODES//,/ }; do
				cli_cc_remove "$_exp_cc" && found=1
			done
			[ "$found" = "1" ] && return 0
			return 1
		fi
		return 1
	fi

	# Remove from rules files
	local f escaped_cc
	escaped_cc=$(echo "$cc" | sed 's/[.\/\[\]]/\\&/g')
	for f in "$CC_DENY_HOSTS" "$CC_ALLOW_HOSTS"; do
		[ -f "$f" ] || continue
		if grep -v '^#' "$f" | grep -Fxq "$cc" 2>/dev/null; then
			found=1
		fi
		# Also remove advanced entries referencing this CC
		if grep -v '^#' "$f" | grep -q "=${cc}$" 2>/dev/null; then
			found=1
		fi
		# Remove simple entries, their comments, advanced entries, and
		# advanced entry comments in a single sed pass
		sed -i -e "\%# added ${escaped_cc} %d" \
		       -e "\%^${escaped_cc}$%d" \
		       -e "\%=${cc}$%d" \
		       -e "\%# added.*=${cc} %d" "$f"
	done

	# Remove iptables rules BEFORE destroying ipsets (ipset refuses
	# destroy when a set is still referenced by active iptables rules)
	local chain _cc_eval_re='^-A (CC_DENY|CC_ALLOW|CC_DENYP|CC_ALLOWP) '
	for chain in CC_DENY CC_ALLOW CC_DENYP CC_ALLOWP; do
		if $IPT $IPT_FLAGS -L "$chain" -n > /dev/null 2>&1; then
			# Remove rules referencing this CC's ipsets
			while $IPT $IPT_FLAGS -D "$chain" -m set --match-set "apf_cc4_${cc}" src -j "$ALL_STOP" 2>/dev/null; do :; done
			while $IPT $IPT_FLAGS -D "$chain" -m set --match-set "apf_cc4_${cc}" src -j ACCEPT 2>/dev/null; do :; done
			while $IPT $IPT_FLAGS -D "$chain" -m set --match-set "apf_cc4_${cc}" dst -j "$ALL_STOP" 2>/dev/null; do :; done
			while $IPT $IPT_FLAGS -D "$chain" -m set --match-set "apf_cc4_${cc}" dst -j ACCEPT 2>/dev/null; do :; done
			# LOG rules -- eval required because iptables -S output contains
			# shell-quoted --log-prefix values (e.g., "** CC_DENY:ZZ ** ")
			# that must be parsed as shell words for -D to match.
			# Security boundary: three independent gates prevent arbitrary eval:
			#   1. valid_cc() constrains $cc to ^[A-Z]{2}$ at all entry points
			#   2. grep filters -S output to lines containing "apf_cc[46]_${cc}"
			#   3. _cc_eval_re regex restricts to ^-A (CC_DENY|CC_ALLOW|...) lines
			# Format validation: only process rules matching APF's CC chain
			# naming convention to prevent eval from processing unexpected input.
			$IPT $IPT_FLAGS -S "$chain" 2>/dev/null | grep "apf_cc4_${cc}" | while IFS= read -r _rule; do
				[[ "$_rule" =~ $_cc_eval_re ]] || continue
				eval "$IPT $IPT_FLAGS -D \"$chain\" ${_rule#-A $chain }" 2>/dev/null || true  # best-effort LOG rule removal
			done
		fi
		if [ "$USE_IPV6" = "1" ] && $IP6T $IPT_FLAGS -L "$chain" -n > /dev/null 2>&1; then
			while $IP6T $IPT_FLAGS -D "$chain" -m set --match-set "apf_cc6_${cc}" src -j "$ALL_STOP" 2>/dev/null; do :; done
			while $IP6T $IPT_FLAGS -D "$chain" -m set --match-set "apf_cc6_${cc}" src -j ACCEPT 2>/dev/null; do :; done
			while $IP6T $IPT_FLAGS -D "$chain" -m set --match-set "apf_cc6_${cc}" dst -j "$ALL_STOP" 2>/dev/null; do :; done
			while $IP6T $IPT_FLAGS -D "$chain" -m set --match-set "apf_cc6_${cc}" dst -j ACCEPT 2>/dev/null; do :; done
			# LOG rules — eval for shell-quoted --log-prefix values (see IPv4 above)
			$IP6T $IPT_FLAGS -S "$chain" 2>/dev/null | grep "apf_cc6_${cc}" | while IFS= read -r _rule; do
				[[ "$_rule" =~ $_cc_eval_re ]] || continue
				eval "$IP6T $IPT_FLAGS -D \"$chain\" ${_rule#-A $chain }" 2>/dev/null || true  # best-effort LOG rule removal
			done
		fi
	done

	# Destroy ipsets (safe now — iptables rules referencing them are removed)
	if [ -n "$IPSET" ]; then
		$IPSET destroy "apf_cc4_${cc}" 2>/dev/null || true  # may not exist if only in rules file
		$IPSET destroy "apf_cc6_${cc}" 2>/dev/null || true  # may not exist if IPv6 disabled
	fi

	# Retain cached GeoIP data — it refreshes on the CC_CACHE_TTL cron
	# cycle and avoids a costly re-download if the CC is re-added soon.

	if [ "$found" = "1" ]; then
		return 0
	fi
	return 1
}

## Check if any entry (bare or advanced) exists for CC in either CC rules file.
# Returns 0 if any entry exists, 1 if none.
# Used by _expire_cc_temp_entry() and cli_cc_remove_entry() to decide
# whether full cleanup (ipsets, cache) is warranted after targeted removal.
# Args: cc
_geoip_cc_has_entries() {
	local IFS=$' \t\n'
	local cc="$1"
	local _f

	[ -n "$cc" ] || return 1

	for _f in "$CC_DENY_HOSTS" "$CC_ALLOW_HOSTS"; do
		[ -f "$_f" ] || continue
		if grep -v '^#' "$_f" 2>/dev/null | grep -Fxq "$cc"; then
			return 0
		fi
		if grep -v '^#' "$_f" 2>/dev/null | grep -q "=${cc}$"; then
			return 0
		fi
	done
	return 1
}

## Expire a single temporary CC entry without destroying permanent entries.
# Removes the temp metadata comment line and the bare CC entry line that
# immediately follows it. If no permanent (non-temp) entry for that CC
# remains in any CC rules file, performs full removal (iptables rules,
# ipsets, cached data) via cli_cc_remove().
# Args: cc file
# Returns: 0 on success, 1 if entry not found
_expire_cc_temp_entry() {
	local cc="$1" file="$2"
	local tmpfile

	[ -n "$cc" ] || return 1
	[ -f "$file" ] || return 1

	# Use awk to remove the temp comment + the bare CC line that follows it.
	# Temp comments match: "# added CC on ... ttl=... expire=..."
	# The next line is the bare CC entry belonging to that temp comment.
	tmpfile=$(mktemp "${file}.XXXXXX") || return 1
	awk -v cc="$cc" '
	/^# added / && index($0, "ttl=") && index($0, "expire=") {
		split($0, a, " ")
		if (a[3] == cc) { skip_next = 1; next }
	}
	skip_next && $0 == cc { skip_next = 0; next }
	{ skip_next = 0; print }
	' "$file" > "$tmpfile"
	command mv -f "$tmpfile" "$file"

	# Check if any permanent (non-temp) entry for this CC still exists
	# in EITHER CC rules file. A permanent entry is a bare CC line whose
	# preceding comment lacks ttl=/expire= markers, or an advanced entry.
	if ! _geoip_cc_has_entries "$cc"; then
		# No permanent entry remains — full cleanup (iptables, ipsets, cache)
		cli_cc_remove "$cc" > /dev/null 2>&1
	fi
	return 0
}

## Dispatch: apf cc <verb> [args]
_dispatch_cc() {
	case "${1:-}" in
	-h|--help) _cc_help ;;
	"")        geoip_info ;;
	info)
		shift
		if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then _cc_help; exit 0; fi
		geoip_info "$@" || exit 1
		;;
	lookup)
		shift
		if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then _cc_help; exit 0; fi
		geoip_info "$@" || exit 1
		;;
	update)    mutex_lock; geoip_update ;;
	*)
		# Bare argument: could be CC or IP — route to geoip_info
		if valid_cc "$1" 2>/dev/null || valid_host "$1" 2>/dev/null; then  # safe: validation only
			geoip_info "$@" || exit 1
		else
			_cli_unknown_verb "apf cc" "$1" "info lookup update"; return 1
		fi
		;;
	esac
}

_cc_help() {
	echo "usage: apf cc <command> [args]"
	echo ""
	echo "  info [CC|IP]           show GeoIP overview or detail for CC/IP"
	echo "  lookup IP              look up country for an IP or CIDR"
	echo "  update                 refresh GeoIP data and ipsets"
	echo ""
	echo "  Examples:  apf cc              (overview)"
	echo "             apf cc info CN      (country detail)"
	echo "             apf cc lookup 8.8.8.8"
}
