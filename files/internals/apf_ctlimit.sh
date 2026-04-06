#!/bin/bash
# shellcheck shell=bash
##
# Advanced Policy Firewall (APF) v2.0.2
#             (C) 2002-2026, R-fx Networks <proj@rfxn.com>
#             (C) 2026, Ryan MacDonald <ryan@rfxn.com>
# This program may be freely redistributed under the terms of the GNU GPL v2
##
#
# Connection tracking limit — sourced on-demand by apf CLI
# APF internal library (files/internals/apf_ctlimit.sh)

# Source guard: prevent double-sourcing
[[ -n "${_APF_CTLIMIT_LOADED:-}" ]] && return 0
_APF_CTLIMIT_LOADED=1
# shellcheck disable=SC2034
APF_CTLIMIT_VERSION="1.0.0"

# --- Public API ---
# ct_scan()           — run conntrack scan and block offenders
# ct_status()         — display CT_LIMIT status and last scan info

# --- CLI handlers ---
# cli_ct_scan()       — apf --ct-scan entry point
# cli_ct_status()     — apf --ct-status entry point

# --- Private helpers (prefix: _ct_) ---

## Build exemption file from loopback, trusted IPs, allow_hosts, and CT_SKIP.
# Writes one IP/CIDR per line to the given file path.
# Args: exempt_file
_ct_build_exempt() {
	local exempt_file="$1"
	true > "$exempt_file"

	# Loopback
	echo "127.0.0.0/8" >> "$exempt_file"
	echo "::1" >> "$exempt_file"

	# Trusted interface IPs
	if [ -n "$IFACE_TRUSTED" ]; then
		local _iface
		for _iface in ${IFACE_TRUSTED//,/ }; do
			if [ -n "$ip" ]; then
				$ip addr list "$_iface" 2>/dev/null | grep -w inet | tr '/' ' ' | awk '{print $2}' >> "$exempt_file"
				$ip addr list "$_iface" 2>/dev/null | grep -w inet6 | tr '/' ' ' | awk '{print $2}' >> "$exempt_file"
			fi
		done
	fi

	# Local server addresses
	if [ -f "$INSTALL_PATH/internals/.localaddrs" ]; then
		command cat "$INSTALL_PATH/internals/.localaddrs" >> "$exempt_file"
	fi
	if [ -f "$INSTALL_PATH/internals/.localaddrs6" ]; then
		command cat "$INSTALL_PATH/internals/.localaddrs6" >> "$exempt_file"
	fi

	# Allow hosts (strip comments and blank lines)
	if [ -f "$ALLOW_HOSTS" ]; then
		grep -vE '^(#|$)' "$ALLOW_HOSTS" 2>/dev/null | while IFS= read -r _line; do
			# Extract IP/CIDR only (first field, no metadata)
			local _host="${_line%% *}"
			_host="${_host%%#*}"
			[ -n "$_host" ] && echo "$_host"
		done >> "$exempt_file"
	fi

	# CT_SKIP entries (comma-separated IPs/CIDRs)
	if [ -n "$CT_SKIP" ]; then
		local _save_ifs="$IFS"
		IFS=','
		local _entry
		for _entry in $CT_SKIP; do
			_entry="${_entry## }"  # trim leading space
			_entry="${_entry%% }"  # trim trailing space
			[ -n "$_entry" ] && echo "$_entry"
		done >> "$exempt_file"
		IFS="$_save_ifs"
	fi
}

## Read conntrack data from best available source.
# Outputs raw conntrack table to stdout.
_ct_read_conntrack() {
	if [ -n "$CONNTRACK" ]; then
		$CONNTRACK -L 2>/dev/null
	elif [ -f /proc/net/nf_conntrack ]; then
		command cat /proc/net/nf_conntrack
	else
		return 1
	fi
}

## Count connections per source IP via single awk pass.
# Reads conntrack data from stdin, applies port/state/exempt filters.
# Outputs "count IP" pairs (descending by count) for IPs exceeding threshold.
# Args: exempt_file threshold [ports] [states] [skip_time_wait]
_ct_count_ips() {
	local exempt_file="$1"
	local threshold="$2"
	local ports="${3:-}"
	local states="${4:-}"
	local skip_tw="${5:-0}"

	awk -v exempt_file="$exempt_file" \
	    -v threshold="$threshold" \
	    -v port_filter="$ports" \
	    -v state_filter="$states" \
	    -v skip_tw="$skip_tw" '
	function expand_ipv6(addr,    parts, left, right, nleft, nright, i, missing, result) {
		if (index(addr, "::") > 0) {
			split(addr, parts, "::")
			nleft = split(parts[1], left, ":")
			nright = split(parts[2], right, ":")
			if (parts[1] == "") nleft = 0
			if (parts[2] == "") nright = 0
			missing = 8 - nleft - nright
			result = ""
			for (i = 1; i <= nleft; i++)
				result = result (i > 1 ? ":" : "") left[i]
			for (i = 1; i <= missing; i++)
				result = result (nleft + i > 1 ? ":" : "") "0"
			for (i = 1; i <= nright; i++)
				result = result ":" right[i]
			return result
		}
		return addr
	}

	function hex2dec(s,    i, c, v, result) {
		result = 0
		s = tolower(s)
		for (i = 1; i <= length(s); i++) {
			c = substr(s, i, 1)
			if (c >= "0" && c <= "9") v = c + 0
			else if (c == "a") v = 10
			else if (c == "b") v = 11
			else if (c == "c") v = 12
			else if (c == "d") v = 13
			else if (c == "e") v = 14
			else if (c == "f") v = 15
			else v = 0
			result = result * 16 + v
		}
		return result
	}

	BEGIN {
		# Load exemption list
		while ((getline line < exempt_file) > 0) {
			gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
			if (line == "" || substr(line, 1, 1) == "#") continue
			# Check if CIDR
			if (index(line, "/") > 0) {
				if (index(line, ":") > 0) {
					# IPv6 CIDR — parse network and prefix
					slash = index(line, "/")
					v6addr = substr(line, 1, slash - 1)
					v6bits = int(substr(line, slash + 1) + 0)
					if (v6bits >= 0 && v6bits <= 128) {
						expanded = expand_ipv6(v6addr)
						exempt6_cidr_count++
						n6 = split(expanded, g6, ":")
						for (gi = 1; gi <= 8; gi++)
							exempt6_groups[exempt6_cidr_count, gi] = hex2dec(g6[gi])
						exempt6_bits[exempt6_cidr_count] = v6bits
					}
				} else {
					# IPv4 CIDR — parse network and prefix
					n = split(line, p, "[./]")
					if (n >= 5 && p[5]+0 >= 0 && p[5]+0 <= 32) {
						net = (p[1]*16777216) + (p[2]*65536) + (p[3]*256) + p[4]
						bits = int(p[5]+0)
						exempt_cidr_count++
						exempt_cidr_net[exempt_cidr_count] = net
						exempt_cidr_bits[exempt_cidr_count] = bits
					}
				}
			} else {
				exempt[line] = 1
			}
		}
		close(exempt_file)

		# Parse port filter
		nports = 0
		if (port_filter != "") {
			nports = split(port_filter, pf, ",")
			for (i = 1; i <= nports; i++) port_set[pf[i]] = 1
		}

		# Parse state filter
		nstates = 0
		if (state_filter != "") {
			nstates = split(state_filter, sf, ",")
			for (i = 1; i <= nstates; i++) state_set[sf[i]] = 1
		}
	}

	function is_exempt(addr,    n, a, ip_int, i, s, expanded, g, gv, gi, full_groups, remainder, match_ok, group_val) {
		# Exact match
		if (addr in exempt) return 1

		if (index(addr, ":") > 0) {
			# IPv6 — check against IPv6 CIDRs
			expanded = expand_ipv6(addr)
			n = split(expanded, g, ":")
			for (gi = 1; gi <= 8; gi++)
				gv[gi] = hex2dec(g[gi])
			for (i = 1; i <= exempt6_cidr_count; i++) {
				full_groups = int(exempt6_bits[i] / 16)
				remainder = exempt6_bits[i] % 16
				match_ok = 1
				for (gi = 1; gi <= full_groups; gi++) {
					if (gv[gi] != exempt6_groups[i, gi]) { match_ok = 0; break }
				}
				if (match_ok && remainder > 0) {
					group_val = full_groups + 1
					if (int(gv[group_val] / 2^(16 - remainder)) != int(exempt6_groups[i, group_val] / 2^(16 - remainder))) {
						match_ok = 0
					}
				}
				if (match_ok) return 1
			}
			return 0
		}

		# IPv4 CIDR containment check
		n = split(addr, a, ".")
		if (n != 4) return 0
		ip_int = (a[1]*16777216) + (a[2]*65536) + (a[3]*256) + a[4]
		for (i = 1; i <= exempt_cidr_count; i++) {
			s = 2^(32 - exempt_cidr_bits[i])
			if (int(ip_int/s) == int(exempt_cidr_net[i]/s)) return 1
		}
		return 0
	}

	{
		src = ""; dport = ""; state = ""
		for (i = 1; i <= NF; i++) {
			# conntrack -L format: src=IP or /proc format: src=IP
			# Only capture FIRST occurrence of src= and dport= (request direction)
			if (substr($i, 1, 4) == "src=" && src == "") {
				src = substr($i, 5)
			}
			else if (substr($i, 1, 6) == "dport=" && dport == "") {
				dport = substr($i, 7)
			}
			# State appears as bare word (e.g., ESTABLISHED) in many formats
			# Also appears in /proc as state=X or conntrack as ESTABLISHED
		}
		# Try to extract state — multiple formats
		for (i = 1; i <= NF; i++) {
			if ($i == "ESTABLISHED" || $i == "SYN_SENT" || $i == "SYN_RECV" || \
			    $i == "FIN_WAIT" || $i == "CLOSE_WAIT" || $i == "LAST_ACK" || \
			    $i == "TIME_WAIT" || $i == "CLOSE" || $i == "LISTEN" || $i == "CLOSING") {
				state = $i
				break
			}
		}

		if (src == "") next

		# Skip TIME_WAIT if configured
		if (skip_tw == "1" && state == "TIME_WAIT") next

		# Port filter: when port filter active, skip entries with no dport
		# (ICMP, protocol-only connections that have no port concept)
		if (nports > 0) { if (dport == "" || !(dport in port_set)) next }

		# State filter
		if (nstates > 0 && state != "" && !(state in state_set)) next

		# Exempt check
		if (is_exempt(src)) next

		count[src]++
	}

	END {
		for (addr in count) {
			if (count[addr]+0 > threshold+0) {
				print count[addr], addr
			}
		}
	}
	' | sort -rn
}

## Run a CT_LIMIT scan: read conntrack, count IPs, block offenders.
ct_scan() {
	local exempt_tmp
	exempt_tmp=$(mktemp "$INSTALL_PATH/.apf-ctexempt.XXXXXX")
	_apf_reg_tmp "$exempt_tmp"
	command chmod 600 "$exempt_tmp"

	_ct_build_exempt "$exempt_tmp"

	local ct_data_tmp
	ct_data_tmp=$(mktemp "$INSTALL_PATH/.apf-ctdata.XXXXXX")
	_apf_reg_tmp "$ct_data_tmp"
	command chmod 600 "$ct_data_tmp"

	if ! _ct_read_conntrack > "$ct_data_tmp" 2>/dev/null; then
		eout "{ct_limit} conntrack data unavailable (no conntrack binary or /proc/net/nf_conntrack)"
		command rm -f "$exempt_tmp" "$ct_data_tmp"
		return 1
	fi

	local total_conns
	total_conns=$(wc -l < "$ct_data_tmp")

	local blocked=0
	local results
	results=$(_ct_count_ips "$exempt_tmp" "$CT_LIMIT" "$CT_PORTS" "$CT_STATES" "$CT_SKIP_TIME_WAIT" < "$ct_data_tmp")

	if [ -n "$results" ]; then
		while IFS= read -r _line; do
			local _count="${_line%% *}"
			local _addr="${_line##* }"
			[ -z "$_addr" ] && continue
			valid_host "$_addr" || continue

			# Skip if already in deny list (any reason — prevents duplicate blocks)
			if grep -Fxq "$_addr" "$DENY_HOSTS" 2>/dev/null; then
				continue
			fi

			# VNET per-IP override: check if a vnet rules file defines a
			# custom CT_LIMIT for this destination IP
			local _effective_limit="$CT_LIMIT"
			if [ "$SET_VNET" = "1" ] && [ -f "$INSTALL_PATH/vnet/${_addr}.rules" ]; then
				local _vnet_ct
				_vnet_ct=$(grep -m1 '^CT_LIMIT=' "$INSTALL_PATH/vnet/${_addr}.rules" 2>/dev/null | cut -d= -f2 | tr -d '"' | tr -d "'")
				local _ct_int_re='^[0-9]+$'
				if [ -n "$_vnet_ct" ] && [[ "$_vnet_ct" =~ $_ct_int_re ]] && [ "$_vnet_ct" != "0" ]; then
					_effective_limit="$_vnet_ct"
				fi
			fi

			# Re-check against effective (possibly VNET-overridden) limit
			if [ "$_count" -le "$_effective_limit" ]; then
				continue
			fi

			eout "{ct_limit} blocking $_addr ($_count connections, limit $_effective_limit)"
			elog_event "block_added" "warn" "{ct_limit} blocking $_addr ($_count connections, limit $_effective_limit)" \
				"host=$_addr" "conns=$_count" "limit=$_effective_limit"
			if ! "$INSTALL_PATH/apf" -td "$_addr" "$CT_BLOCK_TIME" "CT_LIMIT exceeded ($_count conns)"; then
				eout "{ct_limit} failed to block $_addr — apf -td returned non-zero"
				elog_event "block_failed" "error" "{ct_limit} failed to block $_addr" \
					"host=$_addr" "conns=$_count" "limit=$_effective_limit"
			fi

			# CT_PERMANENT=0: remove block history entry to prevent PERMBLOCK
			# escalation. The temp-deny is active but won't count toward
			# the PERMBLOCK_COUNT threshold.
			if [ "$CT_PERMANENT" != "1" ] && [ -f "$INSTALL_PATH/internals/.block_history" ]; then
				# Remove block history entry to prevent PERMBLOCK escalation
				local _escaped_addr="${_addr//./\\.}"
				sed -i "\%^${_escaped_addr}|%d" "$INSTALL_PATH/internals/.block_history"
			fi
			blocked=$((blocked + 1))
		done <<< "$results"
	fi

	# Write last scan timestamp
	date +%s > "$INSTALL_PATH/internals/.ct_last_scan"

	eout "{ct_limit} scan complete: $total_conns connections, $blocked blocked"

	command rm -f "$exempt_tmp" "$ct_data_tmp"
}

## Display CT_LIMIT status.
ct_status() {
	echo "CT_LIMIT Configuration:"
	echo "  CT_LIMIT=$CT_LIMIT (max connections per IP)"
	echo "  CT_INTERVAL=$CT_INTERVAL (scan interval seconds)"
	echo "  CT_BLOCK_TIME=$CT_BLOCK_TIME (block duration seconds)"
	if [ -n "$CT_PORTS" ]; then
		echo "  CT_PORTS=$CT_PORTS (port filter)"
	else
		echo "  CT_PORTS=(all ports)"
	fi
	if [ -n "$CT_STATES" ]; then
		echo "  CT_STATES=$CT_STATES (state filter)"
	else
		echo "  CT_STATES=(all states)"
	fi
	echo "  CT_SKIP_TIME_WAIT=$CT_SKIP_TIME_WAIT"
	echo "  CT_PERMANENT=$CT_PERMANENT"
	if [ -n "$CT_SKIP" ]; then
		echo "  CT_SKIP=$CT_SKIP"
	else
		echo "  CT_SKIP=(none)"
	fi

	echo ""
	if [ -f "$INSTALL_PATH/internals/.ct_last_scan" ]; then
		local last_scan
		read -r last_scan < "$INSTALL_PATH/internals/.ct_last_scan"
		local now
		now=$(date +%s)
		local age=$((now - last_scan))
		echo "  Last scan: $(date -d "@$last_scan" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "epoch $last_scan") (${age}s ago)"
	else
		echo "  Last scan: never"
	fi

	# Show data source
	if [ -n "$CONNTRACK" ]; then
		echo "  Data source: conntrack ($CONNTRACK)"
	elif [ -f /proc/net/nf_conntrack ]; then
		echo "  Data source: /proc/net/nf_conntrack"
	else
		echo "  Data source: unavailable"
	fi

	# Count current CT_LIMIT blocks in temp entries
	local ct_blocks=0
	if [ -f "$DENY_HOSTS" ]; then
		ct_blocks=$(grep -c 'CT_LIMIT' "$DENY_HOSTS" 2>/dev/null || true)  # grep -c exits 1 on 0 matches
	fi
	echo "  Active CT_LIMIT blocks: $ct_blocks"
}

## CLI handler for --ct-scan
cli_ct_scan() {
	ct_scan
}

## CLI handler for --ct-status
cli_ct_status() {
	ct_status
}

## Dispatch: apf ct <verb> [args]
_dispatch_ct() {
	case "${1:-}" in
	-h|--help) _ct_help ;;
	""|status) cli_ct_status ;;
	scan)
		if ct_enabled; then
			mutex_lock; cli_ct_scan
		else
			echo "CT_LIMIT not enabled (CT_LIMIT=0 in conf.apf)"
		fi
		;;
	*)  _cli_unknown_verb "apf ct" "$1" "scan status"; return 1 ;;
	esac
}

_ct_help() {
	echo "usage: apf ct <command>"
	echo ""
	echo "  scan                   run CT_LIMIT scan and block offenders"
	echo "  status                 show CT_LIMIT config and last scan info"
	echo ""
	echo "  Examples:  apf ct scan"
	echo "             apf ct status"
}
