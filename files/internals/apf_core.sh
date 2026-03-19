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
# APF lifecycle: start, full-load, flush, dependency checks, mutex,
# cron handlers, rule-generation helpers, firewall info display

# Source guard
[[ -n "${_APF_CORE_LOADED:-}" ]] && return 0 2>/dev/null
_APF_CORE_LOADED=1

# shellcheck disable=SC2034
APF_CORE_VERSION="1.0.0"

check_rab() {
 ml xt_recent
 ml ipt_recent
 if [ "$RAB" == "1" ]; then
        if ! $MPB --dry-run xt_recent >> /dev/null 2>&1 && ! $MPB --dry-run ipt_recent >> /dev/null 2>&1; then
                RAB="0"
                eout "{rab} force set RAB disabled, kernel module xt/ipt_recent not found."
        fi
 fi
}

check_deps() {
 local crit=""
 local warn=""
 local pkg_apt=""
 local pkg_rpm=""

 # Critical: iptables
 if [ -z "$IPT" ]; then
  crit="$crit iptables"
  pkg_apt="$pkg_apt iptables"
  pkg_rpm="$pkg_rpm iptables"
 fi

 # Critical: ip
 if [ -z "$ip" ]; then
  crit="$crit ip(iproute2)"
  pkg_apt="$pkg_apt iproute2"
  pkg_rpm="$pkg_rpm iproute"
 fi

 # Critical: modprobe (unless monolithic kernel)
 if [ "$SET_MONOKERN" != "1" ] && [ -z "$MPB" ]; then
  crit="$crit modprobe(kmod)"
  pkg_apt="$pkg_apt kmod"
  pkg_rpm="$pkg_rpm kmod"
 fi

 # Critical: ip6tables (when IPv6 enabled)
 if [ "$USE_IPV6" == "1" ] && [ -z "$IP6T" ]; then
  # Only add iptables package hint if not already listed
  crit="$crit ip6tables"
  if [ -n "$IPT" ]; then
   pkg_apt="$pkg_apt iptables"
   pkg_rpm="$pkg_rpm iptables"
  fi
 fi

 # Warn: curl/wget (when remote lists or RGT enabled)
 if [ "$DLIST_PHP" == "1" ] || [ "$DLIST_SPAMHAUS" == "1" ] || [ "$DLIST_DSHIELD" == "1" ] || [ "$DLIST_RESERVED" == "1" ] || [ "$DLIST_ECNSHAME" == "1" ] || [ "$USE_RGT" == "1" ]; then
  if [ -z "$CURL" ] && [ -z "$WGET" ]; then
   warn="$warn curl|wget(remote-lists)"
  fi
 fi

 # Warn: iptables-save/restore and diff (when fast load enabled)
 if [ "$SET_FASTLOAD" == "1" ]; then
  if [ -z "$IPTS" ]; then
   warn="$warn iptables-save(fastload)"
  fi
  if [ -z "$IPTR" ]; then
   warn="$warn iptables-restore(fastload)"
  fi
  if [ -z "$DIFF" ]; then
   warn="$warn diff(fastload)"
  fi
 fi

 # Warn: ipset (when ipset block lists enabled)
 if [ "$USE_IPSET" == "1" ] && [ -z "$IPSET" ]; then
  warn="$warn ipset(ipset-blocklists)"
 fi

 # Warn: getent (when FQDNs used in trust rules)
 if [ -z "$GETENT" ]; then
  warn="$warn getent(fqdn-trust)"
 fi

 # Warn: conntrack (when CT_LIMIT enabled)
 if ct_enabled && [ -z "$CONNTRACK" ] && [ ! -f /proc/net/nf_conntrack ]; then
  warn="$warn conntrack(ct-limit)"
 fi

 # Warn: conflicting firewall services
 if command -v systemctl > /dev/null 2>&1; then
  if systemctl is-active firewalld > /dev/null 2>&1; then
   warn="$warn firewalld(conflict)"
  fi
  if systemctl is-active ufw > /dev/null 2>&1; then
   warn="$warn ufw(conflict)"
  fi
 fi

 # Emit warnings (non-fatal)
 if [ -n "$warn" ]; then
  eout "{glob} missing optional dependencies:$warn"
 fi

 # Emit critical failures and abort
 if [ -n "$crit" ]; then
  # Detect package manager for install hint
  local hint=""
  if command -v apt-get > /dev/null 2>&1; then
   hint="apt-get install$pkg_apt"
  elif command -v dnf > /dev/null 2>&1; then
   hint="dnf install$pkg_rpm"
  elif command -v yum > /dev/null 2>&1; then
   hint="yum install$pkg_rpm"
  elif command -v microdnf > /dev/null 2>&1; then
   hint="microdnf install$pkg_rpm"
  fi
  eout "{glob} missing critical dependencies:$crit" 1
  if [ -n "$hint" ]; then
   eout "{glob}   Try: $hint" 1
  fi
  mutex_unlock
  exit 1
 fi
}

mutex_lock() {
  if [ "$APF_MUTEX_LOCKED" == "1" ]; then
    return
  fi
  # Under exec-flock gate — flock manages the lock file
  if [ "$_APF_LOCKED" == "1" ]; then
    APF_MUTEX_LOCKED="1"
    return
  fi
  # Fallback: noclobber-based file lock with stale PID detection.
  # TOCTOU note: the noclobber test-and-create is not fully atomic on all
  # filesystems, but the race window is negligible in practice -- PID space
  # is 4M+ on modern kernels, the exec-flock fast path (above) handles the
  # common case, and APF operations are infrequent (typically minutes apart).
  # The stale-PID check below covers the remaining failure mode (crashed holder).
  local start_time
  start_time=$(date +%s)
  while true; do
    if (set -C; echo "$$" > "$LOCK_FILE") 2>/dev/null; then
      chmod 600 "$LOCK_FILE"
      APF_MUTEX_LOCKED="1"
      return 0
    fi
    local lock_pid
    read -r lock_pid < "$LOCK_FILE" 2>/dev/null || lock_pid=""
    if [ -n "$lock_pid" ] && ! kill -0 "$lock_pid" 2>/dev/null; then
      command rm -f "$LOCK_FILE"
      continue
    fi
    local now
    now=$(date +%s)
    if [ $((now - start_time)) -ge "$ENTER_LOCK_TIMEOUT" ]; then
      eout "{glob} timed out while attempting to gain lock."
      exit 1
    fi
    sleep 1
  done
}

mutex_unlock() {
  if [ "$APF_MUTEX_LOCKED" == "1" ]; then
    # Under exec-flock, the file-based flock manages the lock — don't remove
    if [ "$_APF_LOCKED" != "1" ]; then
      command rm -f "$LOCK_FILE"
    fi
    APF_MUTEX_LOCKED="0"
  fi
}

save_external_baseline() {
	local bdir="$INSTALL_PATH/internals"
	# Only save when APF is not running — INPUT/OUTPUT has only external rules
	if $IPT $IPT_FLAGS -L TALLOW -n >/dev/null 2>&1; then
		return  # APF running, baseline would include APF rules
	fi
	$IPT $IPT_FLAGS -S INPUT > "$bdir/.apf.input.baseline" 2>/dev/null
	$IPT $IPT_FLAGS -S OUTPUT > "$bdir/.apf.output.baseline" 2>/dev/null
	if [ "$USE_IPV6" == "1" ]; then
		$IP6T $IPT_FLAGS -S INPUT > "$bdir/.apf6.input.baseline" 2>/dev/null
		$IP6T $IPT_FLAGS -S OUTPUT > "$bdir/.apf6.output.baseline" 2>/dev/null
	fi
}

restore_external_baseline() {
	local bdir="$INSTALL_PATH/internals"
	local f rule
	# Suppress: baseline rules may reference non-APF chains (Docker, k8s)
	# that no longer exist after a selective flush
	for f in "$bdir/.apf.input.baseline" "$bdir/.apf.output.baseline"; do
		[ -f "$f" ] || continue
		while IFS= read -r rule; do
			case "$rule" in -A*) $IPT $IPT_FLAGS $rule 2>/dev/null || true ;; esac  # safe: baseline rule may already exist
		done < "$f"
	done
	if [ "$USE_IPV6" == "1" ]; then
		for f in "$bdir/.apf6.input.baseline" "$bdir/.apf6.output.baseline"; do
			[ -f "$f" ] || continue
			while IFS= read -r rule; do
				case "$rule" in -A*) $IP6T $IPT_FLAGS $rule 2>/dev/null || true ;; esac  # safe: baseline rule may already exist
			done < "$f"
		done
	fi
}

flush_apf_chains() {
	# Surgical flush: only remove APF-owned chains, preserving Docker/k8s/etc.
	# Used when DOCKER_COMPAT="1" instead of nuclear flush.
	save_external_baseline

	# Flush INPUT and OUTPUT (APF owns these completely)
	ipt4 -F INPUT
	ipt4 -F OUTPUT
	if [ "$USE_IPV6" == "1" ]; then
		ipt6 -F INPUT
		ipt6 -F OUTPUT
	fi

	# Remove jumps from INPUT/OUTPUT to APF chains before deleting them
	local apf_chains="TALLOW TDENY TGALLOW TGDENY REFRESH_TEMP
		CC_DENY CC_ALLOW CC_DENYP CC_ALLOWP
		RESET PROHIBIT RABPSCAN TELNET_LOG SSH_LOG
		IDENT P2P DEG SMTP_BLK SYNFLOOD IN_SANITY OUT_SANITY FRAG_UDP
		PZERO MCAST LMAC PHP DSHIELD SDROP"
	# Suppress: chain may not exist if not created during this load cycle
	for chain in $apf_chains; do
		if $IPT $IPT_FLAGS -L "$chain" -n >/dev/null 2>&1; then
			ipt4 -F "$chain"
			ipt4 -X "$chain"
		fi
	done

	# IPv6-specific chains
	if [ "$USE_IPV6" == "1" ]; then
		local apf_chains6="TALLOW TDENY TGALLOW TGDENY REFRESH_TEMP
			CC_DENY CC_ALLOW CC_DENYP CC_ALLOWP
			RESET PROHIBIT RABPSCAN TELNET_LOG SSH_LOG
			IDENT P2P PHP DSHIELD SDROP SMTP_BLK SYNFLOOD IN_SANITY6 OUT_SANITY6
			FRAG_UDP6 PZERO6 MCAST6"
		# Suppress: chain may not exist if not created during this load cycle
		for chain in $apf_chains6; do
			if $IP6T $IPT_FLAGS -L "$chain" -n >/dev/null 2>&1; then
				ipt6 -F "$chain"
				ipt6 -X "$chain"
			fi
		done
	fi

	# IPSET chains (dynamic names from ipset.rules)
	if [ -n "$IPSET" ] && [ -f "$INSTALL_PATH/ipset.rules" ]; then
		while IFS= read -r line; do
			case "$line" in \#*|"") continue ;; esac
			local name
			name="${line%%:*}"
			[ -z "$name" ] && continue
			if $IPT $IPT_FLAGS -L "IPSET_${name}" -n >/dev/null 2>&1; then
				ipt4 -F "IPSET_${name}"
				ipt4 -X "IPSET_${name}"
			fi
		done < "$INSTALL_PATH/ipset.rules"
	fi

	# GRE chains (handled by gre_flush but also clean up here)
	if $IPT $IPT_FLAGS -L GRE_IN -n >/dev/null 2>&1; then
		ipt4 -F GRE_IN
		ipt4 -X GRE_IN
	fi
	if $IPT $IPT_FLAGS -L GRE_OUT -n >/dev/null 2>&1; then
		ipt4 -F GRE_OUT
		ipt4 -X GRE_OUT
	fi

	# Flush mangle PREROUTING/POSTROUTING (tosroute/ECN)
	ipt4 -t mangle -F PREROUTING 2>/dev/null || true   # safe: mangle table may not exist
	ipt4 -t mangle -F POSTROUTING 2>/dev/null || true  # safe: mangle table may not exist
	if [ "$USE_IPV6" == "1" ]; then
		ipt6 -t mangle -F PREROUTING 2>/dev/null || true   # safe: mangle table may not exist
		ipt6 -t mangle -F POSTROUTING 2>/dev/null || true  # safe: mangle table may not exist
	fi

	# Set INPUT/OUTPUT to ACCEPT; leave FORWARD as-is
	ipt -P INPUT ACCEPT
	ipt -P OUTPUT ACCEPT
	# Note: FORWARD policy deliberately NOT touched
	restore_external_baseline
}

flush() {
firewall_on=$($IPT $IPT_FLAGS -L --numeric | grep -vE "Chain|destination")
if [ "$SET_FASTLOAD" == "1" ] && [ "$DOCKER_COMPAT" != "1" ] && [ "$1" != "1" ] && [ "$DEVEL_ON" != "1" ] && [ -n "$firewall_on" ]; then
	snapshot_save
fi

if [ "$DOCKER_COMPAT" == "1" ]; then
	if [ ! "$1" = "1" ]; then
		eout "{glob} flushing APF chains (docker compat mode)"
	fi
	flush_apf_chains
else
	if [ ! "$1" = "1" ]; then
		eout "{glob} flushing & zeroing chain policies"
	fi
	chains=$(cat /proc/net/ip_tables_names 2>/dev/null)
	# Fallback for nft backend where /proc/net/ip_tables_names is absent
	if [ -z "$chains" ]; then
		chains="filter nat mangle raw"
	fi
	for i in $chains; do ipt4 -t $i -F; done
	for i in $chains; do ipt4 -t $i -X; done
	ipt -P INPUT ACCEPT
	ipt -P OUTPUT ACCEPT
	ipt -P FORWARD ACCEPT

	if [ "$USE_IPV6" == "1" ]; then
		chains6=$(cat /proc/net/ip6_tables_names 2>/dev/null)
		# Fallback for nft backend where /proc/net/ip6_tables_names is absent
		if [ -z "$chains6" ]; then
			chains6="filter nat mangle raw"
		fi
		for i in $chains6; do ipt6 -t $i -F; done
		for i in $chains6; do ipt6 -t $i -X; done
	fi
fi

if [ -f "/proc/net/ipt_recent/DEFAULT" ]; then
	eout "{glob} flushing xt/ipt_recent bans"
	echo clear > /proc/net/ipt_recent/DEFAULT
fi

ipset_flush

# Flush GeoIP country ipsets (inline — no apf_geoip.sh dependency)
if [ -n "$IPSET" ]; then
	$IPSET list -n 2>/dev/null | grep '^apf_cc' | while IFS= read -r _set; do
		$IPSET destroy "$_set" 2>/dev/null || true  # may not exist
	done
fi

gre_flush
command rm -f /etc/cron.d/refresh.apf
command rm -f /etc/cron.d/ctlimit.apf "$INSTALL_PATH/internals/cron.ctlimit"
command rm -f "$INSTALL_PATH/internals/.block_history"

if [ ! "$1" = "1" ]; then
	eout "{glob} firewall offline"
fi
}

firewall_info() {
	local running="no" rule_count=0 ipv6_count=0 chain_count=0

	# Check if firewall has rules loaded
	local fw_rules
	fw_rules=$($IPT $IPT_FLAGS -S 2>/dev/null)
	rule_count=$(echo "$fw_rules" | grep -c '^-A') || rule_count=0
	if [ "$rule_count" -gt 0 ]; then
		running="yes"
		chain_count=$(echo "$fw_rules" | grep -c '^-N') || chain_count=0
	fi
	if [ "$USE_IPV6" == "1" ] && [ -n "$IP6T" ]; then
		ipv6_count=$($IP6T $IPT_FLAGS -S 2>/dev/null | grep -c '^-A')
		[ "$ipv6_count" -gt 0 ] 2>/dev/null || ipv6_count=0
	fi

	# --- Status ---
	echo "APF v$VER — Firewall Status"
	echo ""
	echo "  Active:           $running"
	echo "  Interface:        ${IFACE_UNTRUSTED:-none}"
	if [ -n "$IFACE_TRUSTED" ]; then
		echo "  Trusted iface:    $IFACE_TRUSTED"
	fi
	echo "  IPv6:             $([ "$USE_IPV6" == "1" ] && echo "enabled" || echo "disabled")"
	echo "  IPv4 rules:       $rule_count (${chain_count} custom chains)"
	if [ "$USE_IPV6" == "1" ]; then
		echo "  IPv6 rules:       $ipv6_count"
	fi
	echo "  DEVEL_MODE:       $([ "$DEVEL_MODE" == "1" ] && echo "ON (auto-flush every 5m)" || echo "off")"

	# --- Trust ---
	echo ""
	echo "Trust System:"
	local allow_count=0 deny_count=0 temp_count=0
	if [ -f "$ALLOW_HOSTS" ]; then
		allow_count=$(grep -cv '^#\|^[[:space:]]*$' "$ALLOW_HOSTS" 2>/dev/null)
		[ "$allow_count" -gt 0 ] 2>/dev/null || allow_count=0
	fi
	if [ -f "$DENY_HOSTS" ]; then
		deny_count=$(grep -cv '^#\|^[[:space:]]*$' "$DENY_HOSTS" 2>/dev/null)
		[ "$deny_count" -gt 0 ] 2>/dev/null || deny_count=0
	fi
	if [ -f "$ALLOW_HOSTS" ] || [ -f "$DENY_HOSTS" ]; then
		temp_count=$(cat "$ALLOW_HOSTS" "$DENY_HOSTS" "$CC_DENY_HOSTS" "$CC_ALLOW_HOSTS" 2>/dev/null | grep -c '# added .* ttl=.*expire=')
		[ "$temp_count" -gt 0 ] 2>/dev/null || temp_count=0
	fi
	echo "  Allow entries:    $allow_count"
	echo "  Deny entries:     $deny_count"
	echo "  Temp entries:     $temp_count"
	if [ -n "$SET_EXPIRE" ] && [ "$SET_EXPIRE" != "0" ]; then
		echo "  Ban expiry:       ${SET_EXPIRE}s"
	fi
	if [ -n "$PERMBLOCK_COUNT" ] && [ "$PERMBLOCK_COUNT" != "0" ]; then
		echo "  Block escalation: ${PERMBLOCK_COUNT} repeats in ${PERMBLOCK_INTERVAL}s"
	fi
	echo "  FQDN resolution:  $([ -n "$GETENT" ] && echo "enabled (timeout=${FQDN_TIMEOUT:-10}s)" || echo "disabled (getent not found)")"
	if cc_enabled; then
		local cc_deny_count=0 cc_allow_count=0
		if [ -f "$CC_DENY_HOSTS" ]; then
			cc_deny_count=$(grep -cvE '^(#|$)' "$CC_DENY_HOSTS" 2>/dev/null) || cc_deny_count=0
		fi
		if [ -f "$CC_ALLOW_HOSTS" ]; then
			cc_allow_count=$(grep -cvE '^(#|$)' "$CC_ALLOW_HOSTS" 2>/dev/null) || cc_allow_count=0
		fi
		echo "  CC deny entries:  $cc_deny_count"
		echo "  CC allow entries: $cc_allow_count"
		echo "  CC audit mode:    $([ "$CC_LOG_ONLY" = "1" ] && echo "enabled" || echo "disabled")"
	fi

	# --- Filtering ---
	echo ""
	echo "Filtering:"
	echo "  TCP stop:         ${TCP_STOP:-DROP}"
	echo "  UDP stop:         ${UDP_STOP:-DROP}"
	echo "  Inbound TCP:      ${IG_TCP_CPORTS:-(none)}"
	echo "  Inbound UDP:      ${IG_UDP_CPORTS:-(none)}"
	if [ "$EGF" == "1" ]; then
		echo "  Outbound TCP:     ${EG_TCP_CPORTS:-(none)}"
		echo "  Outbound UDP:     ${EG_UDP_CPORTS:-(none)}"
	else
		echo "  Outbound filter:  disabled (EGF=0)"
	fi
	echo "  Packet sanity:    $([ "$PKT_SANITY" == "1" ] && echo "enabled" || echo "disabled")"
	if [ -n "$IG_TCP_CLIMIT" ]; then
		echo "  Connlimit:        $IG_TCP_CLIMIT"
	fi
	echo "  SYN flood:        $([ "$SYNFLOOD" == "1" ] && echo "enabled (${SYNFLOOD_RATE} burst=${SYNFLOOD_BURST})" || echo "disabled")"
	echo "  SMTP blocking:    $([ "$SMTP_BLOCK" == "1" ] && echo "enabled" || echo "disabled")"

	# --- Subsystems ---
	echo ""
	echo "Subsystems:"
	echo "  Fast load:        $([ "$SET_FASTLOAD" == "1" ] && echo "enabled" || echo "disabled")"
	echo "  RAB:              $([ "$RAB" == "1" ] && echo "enabled" || echo "disabled")"
	echo "  VNET:             $([ "$SET_VNET" == "1" ] && echo "enabled" || echo "disabled")"
	if [ "$DOCKER_COMPAT" == "1" ]; then
		echo "  Docker compat:    enabled"
	fi
	if [ "$USE_IPSET" == "1" ]; then
		local ipset_count=0
		if [ -n "$IPSET" ]; then
			ipset_count=$($IPSET list -n 2>/dev/null | grep -c .)  # grep -c exits 1 when count is 0; handled below
			[ "$ipset_count" -gt 0 ] 2>/dev/null || ipset_count=0
		fi
		echo "  ipset:            enabled ($ipset_count active lists)"
	else
		echo "  ipset:            disabled"
	fi
	if [ "$USE_GRE" == "1" ]; then
		echo "  GRE tunnels:      enabled"
	fi
	if ct_enabled; then
		echo "  CT_LIMIT:         enabled (limit=${CT_LIMIT}, scan=${CT_INTERVAL}s, block=${CT_BLOCK_TIME}s)"
	fi

	# Remote block lists
	local dlists=""
	[ "$DLIST_DSHIELD" == "1" ] && dlists="${dlists}dshield "
	[ "$DLIST_SPAMHAUS" == "1" ] && dlists="${dlists}spamhaus "
	[ "$DLIST_PHP" == "1" ] && dlists="${dlists}php "
	[ "$DLIST_RESERVED" == "1" ] && dlists="${dlists}reserved "
	[ "$DLIST_ECNSHAME" == "1" ] && dlists="${dlists}ecn "
	if [ -n "$dlists" ]; then
		echo "  Remote lists:     $dlists"
	else
		echo "  Remote lists:     none"
	fi

	# --- Logging ---
	echo ""
	echo "Logging:"
	echo "  Log file:         ${LOG_APF:-/var/log/apf_log}"
	echo "  Log drops:        $([ "$LOG_DROP" == "1" ] && echo "enabled" || echo "disabled")"
	echo "  Log target:       ${LOG_TARGET:-LOG}"
	if [ -n "$SET_TRIM" ] && [ "$SET_TRIM" != "0" ]; then
		echo "  Log trim:         ${SET_TRIM} lines"
	fi

	echo ""
	echo "Recent log:"
	if [ -f "$LOG_APF" ]; then
		local log_lines
		log_lines=$(tail -5 "$LOG_APF" 2>/dev/null)
		if [ -n "$log_lines" ]; then
			echo "$log_lines"
		else
			echo "  (log empty)"
		fi
	else
		echo "  (log file not found)"
	fi
}

tosroute() {
# Type of Service (TOS) parameters
# 0: Normal-Service
# 2: Minimize-Cost
# 4: Minimize Delay - Maximize Reliability
# 8: Maximum Throughput - Minimum Delay
# 16: No Delay - Moderate Throughput - High Reliability
#
local TYPE="$1"

if [ -z "$TYPE" ]; then
	return
fi

local tos_val tos_var ports i
for tos_val in 0 2 4 8 16; do
	tos_var="TOS_$tos_val"
	ports="${!tos_var}"
	if [ -n "$ports" ]; then
		for i in ${ports//,/ }; do
			expand_port "$i"; i="$_PORT"
			$IPT $IPT_FLAGS -t mangle -A $TYPE -p tcp --dport $i -j TOS --set-tos $tos_val
			$IPT $IPT_FLAGS -t mangle -A $TYPE -p udp --dport $i -j TOS --set-tos $tos_val
		done
	fi
done

if [ -n "$TOS_DEF_RANGE" ]; then
	for i in ${TOS_DEF_RANGE//,/ }; do
		expand_port "$i"; i="$_PORT"
		$IPT $IPT_FLAGS -t mangle -A $TYPE -p tcp --dport $i -j TOS --set-tos $TOS_DEF
		$IPT $IPT_FLAGS -t mangle -A $TYPE -p udp --dport $i -j TOS --set-tos $TOS_DEF
	done
fi
}

dnet() {
FILE="$1"
if [ -f "$FILE" ]; then
FNAME="${FILE##*/}"
eout "{glob} loading $FNAME"
 while IFS= read -r i; do
  [[ "$i" == \#* || -z "$i" ]] && continue
  if ipt_for_host "$i"; then
        $IPT_H $IPT_FLAGS -A INPUT -s "$i" -j $ALL_STOP
	$IPT_H $IPT_FLAGS -A OUTPUT -d "$i" -j $ALL_STOP
  fi
 done < "$FILE"
fi
}

cdports() {
if [ -n "$BLK_PORTS" ]; then
	eout "{glob} loading common drop ports"
for i in ${BLK_PORTS//,/ }; do
	expand_port "$i"; i="$_PORT"
	ipt -A INPUT  -p tcp --dport $i -j $TCP_STOP
	ipt -A INPUT  -p udp --dport $i -j $UDP_STOP
	ipt -A OUTPUT  -p tcp --dport $i -j $TCP_STOP
	ipt -A OUTPUT  -p udp --dport $i -j $UDP_STOP
	eout "{blk_ports} deny all to/from tcp port $i"
	eout "{blk_ports} deny all to/from udp port $i"
done
fi
}

lgate_mac() {
ipt4 -N LMAC
for mac in ${VF_LGATE//,/ }; do
MAC=$mac
if [ -n "$MAC" ]; then
  ipt4 -A INPUT  -m mac ! --mac-source "$MAC" -j LMAC
  eout "{glob} gateway ($MAC) route verification enabled"
fi
done

if [ "$LOG_LGATE" == "1" ]; then
 ipt4 -A LMAC -m limit --limit $LOG_RATE/minute -j $LOG_TARGET --log-level=$LOG_LEVEL $LEXT --log-prefix=" ** DROP FOREIGN MAC ** "
fi
ipt4 -A LMAC  -j REJECT --reject-with icmp-net-prohibited
}

# Log-then-drop helper: optional LOG rule followed by action rule.
# Usage: _log_drop ipt_fn chain match_args log_prefix action [extra_action_flags]
# shellcheck disable=SC2086
_log_drop() {
	local ipt_fn="$1" chain="$2" match="$3" prefix="$4" action="$5" extra="$6"
	if [ "$LOG_DROP" == "1" ]; then
		$ipt_fn -A "$chain" $match -m limit --limit=$LOG_RATE/minute \
			-j $LOG_TARGET --log-level=$LOG_LEVEL $LEXT --log-prefix "$prefix"
	fi
	$ipt_fn -A "$chain" $match $extra -j "$action"
}

# RAB hit log helper: emits LOG rule when RAB_LOG_HIT is enabled.
# Usage: _rab_log ipt_fn chain match_args log_prefix
# shellcheck disable=SC2086
_rab_log() {
	local ipt_fn="$1" chain="$2" match="$3" prefix="$4"
	if [ "$RAB_LOG_HIT" == "1" ]; then
		$ipt_fn -A "$chain" $match -m limit --limit=$LOG_RATE/minute \
			-j $LOG_TARGET --log-level=$LOG_LEVEL $LEXT --log-prefix "$prefix"
	fi
}

## Packet sanity TCP flag checks — shared loop for IN/OUT chains.
# Usage: pkt_sanity_flags chain ipt_fn log_prefix rab_prefix rab_mode
# Iterates canonical flag pairs, applying LOG (if LOG_DROP), RAB LOG
# (if rab_mode=1 and RAB_LOG_HIT), and DROP rules for each pair.
pkt_sanity_flags() {
	local chain="$1" ipt_fn="$2" log_prefix="$3" rab_prefix="$4" rab_mode="$5"
	local flags mask comp
	for flags in "ALL NONE" "SYN,FIN SYN,FIN" "SYN,RST SYN,RST" "FIN,RST FIN,RST" \
		     "ACK,FIN FIN" "ACK,URG URG" "ACK,PSH PSH" "ALL FIN,URG,PSH" \
		     "ALL SYN,RST,ACK,FIN,URG" "ALL ALL" "ALL FIN"; do
		read -r mask comp <<< "$flags"
		if [ "$LOG_DROP" == "1" ]; then
			$ipt_fn -A "$chain" -p tcp --tcp-flags $mask $comp \
				-m limit --limit=$LOG_RATE/minute -j $LOG_TARGET \
				--log-level=$LOG_LEVEL $LEXT --log-prefix="** $log_prefix ** "
		fi
		if [ "$rab_mode" == "1" ] && [ "$RAB_LOG_HIT" == "1" ]; then
			$ipt_fn -A "$chain" -p tcp --tcp-flags $mask $comp \
				-m limit --limit=$LOG_RATE/minute -j $LOG_TARGET \
				--log-level=$LOG_LEVEL $LEXT --log-prefix="** $rab_prefix ** "
		fi
		if [ "$rab_mode" == "1" ]; then
			$ipt_fn -A "$chain" -p tcp --tcp-flags $mask $comp $RAB_SANITY_FLAGS -j $TCP_STOP
		else
			$ipt_fn -A "$chain" -p tcp --tcp-flags $mask $comp -j $TCP_STOP
		fi
	done
}

cron_refresh() {
if [ "$SET_REFRESH" != "0" ] && [ -n "$SET_REFRESH" ]; then
cat<<EOF > "$INSTALL_PATH/internals/cron.refresh"
*/$SET_REFRESH * * * * root $INSTALL_PATH/apf --refresh >> /dev/null 2>&1 &
EOF
	chmod 644 "$INSTALL_PATH/internals/cron.refresh"
	ln -fs "$INSTALL_PATH/internals/cron.refresh" /etc/cron.d/refresh.apf
	eout "{glob} SET_REFRESH is set to $SET_REFRESH minutes"
else
	command rm -f /etc/cron.d/refresh.apf
	eout "{glob} SET_REFRESH is set disabled"

fi
}

cron_ctlimit() {
if ct_enabled; then
	local ct_min=$(( ${CT_INTERVAL:-30} / 60 ))
	[ "$ct_min" -lt 1 ] && ct_min=1
cat<<EOF > "$INSTALL_PATH/internals/cron.ctlimit"
*/$ct_min * * * * root $INSTALL_PATH/apf --ct-scan >> /dev/null 2>&1
EOF
	chmod 644 "$INSTALL_PATH/internals/cron.ctlimit"
	ln -fs "$INSTALL_PATH/internals/cron.ctlimit" /etc/cron.d/ctlimit.apf
	eout "{ct_limit} CT_LIMIT is set to $CT_LIMIT (scan every ${ct_min}m)"
else
	command rm -f /etc/cron.d/ctlimit.apf "$INSTALL_PATH/internals/cron.ctlimit"
fi
}

# Verify that an interface has a route to a network; abort if not.
_verify_iface_route() {
	local iface="$1"
	local val=""
	if [ -n "$ip" ]; then
		val=$($ip route show dev "$iface" 2>/dev/null)
	elif command -v route > /dev/null 2>&1; then
		val=$(route -n | grep -w "$iface")
	else
		eout "{glob} neither ip nor route found; cannot verify interface $iface"
		exit 1
	fi
	if [ -z "$val" ]; then
		eout "{glob} could not verify that interface $iface is routed to a network, aborting."
		if [ "$SET_VERBOSE" != "1" ]; then
			echo "could not verify that interface $iface is routed to a network, aborting."
		fi
		exit 1
	fi
}

## firewall_full_load — builds the complete iptables ruleset.
# Formerly the procedural body of files/firewall; absorbed into a function
# so start() can call it in-process instead of spawning a subprocess.
# shellcheck disable=SC2086
firewall_full_load() {
# load our iptables modules
modinit

# Delete user made chains. Flush and zero the chains.
flush 1

# Pre-configuration hook — runs before any iptables rules
if [ -x "$INSTALL_PATH/hook_pre.sh" ]; then
	eout "{glob} executing pre-configuration hook"
	# shellcheck disable=SC1090,SC1091
	. "$INSTALL_PATH/hook_pre.sh" || true  # safe: sourced hook exit code is advisory, never block firewall load
fi

if [ -n "$IF" ] && [ "$VF_ROUTE" == "1" ]; then
	for i in $IF; do
		_verify_iface_route "$i"
	done
fi
if [ -n "$IFACE_TRUSTED" ] && [ "$VF_ROUTE" == "1" ]; then
	for i in ${IFACE_TRUSTED//,/ }; do
		_verify_iface_route "$i"
	done
fi

$ip addr list "$IFACE_UNTRUSTED" | grep -w inet | grep -v inet6 | tr '/' ' ' | awk '{print$2}' > "$INSTALL_PATH/internals/.localaddrs"
if [ "$USE_IPV6" == "1" ]; then
	$ip addr list "$IFACE_UNTRUSTED" | grep -w inet6 | tr '/' ' ' | awk '{print$2}' > "$INSTALL_PATH/internals/.localaddrs6"
fi

if [ "$RAB" == "0" ]; then
	RAB_LOG_HIT=0
fi

eout "{glob} determined (IFACE_UNTRUSTED) $IFACE_UNTRUSTED has address $NET"

# Load our PREROUTE rules
tosroute PREROUTING
. "$PRERT"

# Allow all traffic on the loopback interface
ipt -A INPUT -i lo -j ACCEPT
ipt -A OUTPUT -o lo -j ACCEPT


# Allow all traffic on trusted interfaces
if [ -n "$IFACE_TRUSTED" ]; then
 for i in ${IFACE_TRUSTED//,/ }; do
 VAL_IF=$($ip addr list | grep -w "$i")
 if [ -z "$VAL_IF" ]; then
        eout "{glob} unable to verify status of interface $i; assuming untrusted"
 else
        eout "{glob} allow all to/from trusted interface $i"
        ipt -A INPUT -i "$i" -j ACCEPT
        ipt -A OUTPUT -o "$i" -j ACCEPT
 fi
 done
fi

# Silent IPs — server addresses that should receive no traffic
if [ -f "$INSTALL_PATH/silent_ips.rules" ]; then
 while IFS= read -r line || [ -n "$line" ]; do
  line="${line%%#*}"
  line="${line// /}"
  if [ -n "$line" ]; then
   if ! valid_host "$line"; then
    eout "{glob} WARNING: skipping invalid silent IP entry: $line"
    continue
   fi
   if ipt_for_host "$line"; then
    $IPT_H $IPT_FLAGS -A INPUT -d "$line" -j DROP
    $IPT_H $IPT_FLAGS -A OUTPUT -s "$line" -j DROP
    eout "{glob} silent drop for $line"
   fi
  fi
 done < "$INSTALL_PATH/silent_ips.rules"
fi

# Create GRE tunnels and firewall rules
gre_init

# Create TCP RESET & UDP PROHIBIT chains
ipt -N RESET
ipt -A RESET -p tcp -j REJECT --reject-with tcp-reset
ipt -A RESET -j DROP
ipt -N PROHIBIT
ipt4 -A PROHIBIT -j REJECT --reject-with icmp-host-prohibited
ipt6 -A PROHIBIT -j REJECT --reject-with icmp6-adm-prohibited

# Load our SYSCTL rules
. "$INSTALL_PATH/sysctl.rules" >> /dev/null 2>&1

# Fix MTU/MSS Problems
ipt -A OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

# Block common nonroutable IP networks
if [ "$BLK_MCATNET" = "1" ]; then
	dnet $MCATNET
fi
if [ "$BLK_PRVNET" = "1" ]; then
	dnet $PRVNET
fi
if [ "$BLK_RESNET" = "1" ]; then
	if [ "$DLIST_RESERVED" == "1" ]; then
		dlist_resnet
	fi
	dnet $RESNET
fi

# Create (glob)trust system chains
ipt -N TALLOW
ipt -N TDENY
ipt -N TGALLOW
ipt -N TGDENY
ipt -N REFRESH_TEMP
ipt -A INPUT -j REFRESH_TEMP
ipt -A OUTPUT -j REFRESH_TEMP
ipt -A INPUT -j TALLOW
ipt -A OUTPUT -j TALLOW
ipt -A INPUT -j TGALLOW
ipt -A OUTPUT -j TGALLOW
ipt -A INPUT -j TDENY
ipt -A OUTPUT -j TDENY
ipt -A INPUT -j TGDENY
ipt -A OUTPUT -j TGDENY

# Country Code Filtering (GeoIP)
if cc_enabled; then
	# shellcheck disable=SC1090,SC1091
	. "$INSTALL_PATH/internals/apf_geoip.sh"
	geoip_load
fi

# Load our Blocked Traffic rules
. "$INSTALL_PATH/bt.rules"

# Set refresh cron
cron_refresh

# Set CT_LIMIT scan cron
cron_ctlimit

# Load our Allow Hosts rules
glob_allow_download
allow_hosts $ALLOW_HOSTS TALLOW
elog_event "rule_loaded" "info" "{trust} trust chains loaded" \
	"allow=$ALLOW_HOSTS" "deny=$DENY_HOSTS"

# RAB default drop for events
check_rab
if [ "$RAB" == "1" ]; then
 eout "{rab} set active RAB"
 if [ "$RAB_HITCOUNT" == "0" ]; then
	RAB_HITCOUNT="1"
 fi

 if [ "$RAB_TRIP" == "0" ]; then
	RAB_TRIP_FLAGS="--rcheck"
 else
	RAB_TRIP_FLAGS="--update"
 fi

 if [ "$LOG_DROP" == "1" ] || [ "$RAB_LOG_TRIP" == "1" ]; then
	ipt -A INPUT -p all -m recent --rcheck --hitcount $RAB_HITCOUNT --seconds $RAB_TIMER -m limit --limit=$LOG_RATE/minute -j $LOG_TARGET --log-level=$LOG_LEVEL $LEXT --log-prefix="** RABTRIP ** "
 fi
 ipt -A INPUT -p all -m recent $RAB_TRIP_FLAGS --hitcount $RAB_HITCOUNT --seconds $RAB_TIMER -j $ALL_STOP

 # RAB portscan rules
 if [ "$RAB_PSCAN_LEVEL" != "0" ] && [ -n "$RAB_PSCAN_LEVEL" ]; then
  eout "{rab} set active RAB_PSCAN"
  case "$RAB_PSCAN_LEVEL" in
  1)
  RAB_PSCAN_PORTS="$RAB_PSCAN_LEVEL_1"
  ;;
  2)
  RAB_PSCAN_PORTS="$RAB_PSCAN_LEVEL_2"
  ;;
  3)
  RAB_PSCAN_PORTS="$RAB_PSCAN_LEVEL_3"
  ;;
  *)
  eout "{rab} warning: RAB_PSCAN_LEVEL='$RAB_PSCAN_LEVEL' invalid, defaulting to level 1"
  RAB_PSCAN_PORTS="$RAB_PSCAN_LEVEL_1"
  ;;
  esac
  eout "{rab} RAB_PSCAN monitored ports $RAB_PSCAN_PORTS"
  ipt -N RABPSCAN
  LDNS=$(grep -v "#" /etc/resolv.conf | grep -w nameserver | awk '{print$2}' | grep -v 127.0.0.1)
  if [ "$LDNS" ]; then
	for i in $LDNS; do
		if ipt_for_host "$i"; then
			$IPT_H $IPT_FLAGS -I RABPSCAN -s "$i" -j RETURN
		fi
	done
  fi
  for i in ${RAB_PSCAN_PORTS//,/ }; do
   if [ "$LOG_DROP" == "1" ] || [ "$RAB_LOG_HIT" == "1" ]; then
	   ipt -A RABPSCAN -p tcp --dport $i -m limit --limit=$LOG_RATE/minute -j $LOG_TARGET --log-level=$LOG_LEVEL $LEXT --log-prefix="** RABHIT ** "
	   ipt -A RABPSCAN -p udp --dport $i -m limit --limit=$LOG_RATE/minute -j $LOG_TARGET --log-level=$LOG_LEVEL $LEXT --log-prefix="** RABHIT ** "
   fi
   ipt -A RABPSCAN -p tcp --dport $i -m recent --set -j $TCP_STOP
   ipt -A RABPSCAN -p udp --dport $i -m recent --set -j $UDP_STOP
  done
  ipt -A INPUT -j RABPSCAN
 fi
fi

trim $DENY_HOSTS $SET_TRIM
trim $GDENY_HOSTS $SET_TRIM

# State tracking — fast-path for established/related connections.
# Trust chains, blocklists, sanity checks, and RAB above ensure that denied,
# malformed, and attack traffic is blocked regardless of connection state.
# Conntrack validates TCP flags for ESTABLISHED packets (invalid flags →
# INVALID state, not ESTABLISHED), so these skip safely.
ipt -A INPUT  -p tcp $STATE_MATCH ESTABLISHED,RELATED -j ACCEPT
ipt -A INPUT  -p udp $STATE_MATCH ESTABLISHED,RELATED -j ACCEPT
ipt -A OUTPUT -p tcp --dport 1024:65535 $STATE_MATCH ESTABLISHED,RELATED -j ACCEPT
ipt -A OUTPUT -p udp --dport 1024:65535 $STATE_MATCH ESTABLISHED,RELATED -j ACCEPT

# Load our LOG rules
. "$INSTALL_PATH/log.rules"

# Virtual Adapters
. "$INSTALL_PATH/vnet/main.vnet"

# Clear any cport values
cl_cports
# CRITICAL: Re-source conf.apf to reload port variables after cl_cports() clears them.
# Removing this causes a silent security regression (no port filters).
. "$CNF"

# Load our main TCP/UDP rules
if [ "$SET_VNET" == "1" ]; then
	VNET="$NET"
else
	VNET="0/0"
fi
. "$INSTALL_PATH/main.rules"

# Drop NEW tcp connections after this point
ipt -A INPUT  -p tcp ! --syn $STATE_MATCH NEW -j $ALL_STOP

# DNS
if [ -f "/etc/resolv.conf" ] && [ "$RESV_DNS" == "1" ]; then
LDNS=$(grep -v "#" /etc/resolv.conf | grep -w nameserver | awk '{print$2}' | grep -v 127.0.0.1)
  if [ -n "$LDNS" ]; then
        for i in $LDNS; do
        eout "{glob} resolv dns discovery for $i"
        if [[ "$i" == *:* ]]; then
                # IPv6 nameserver
                if [ "$USE_IPV6" == "1" ]; then
                ipt6 -A INPUT -p udp -s "$i" --sport 53 --dport 1024:65535 $STATE_MATCH ESTABLISHED,RELATED -j ACCEPT
                ipt6 -A INPUT -p tcp -s "$i" --sport 53 --dport 1024:65535 $STATE_MATCH ESTABLISHED,RELATED -j ACCEPT
                ipt6 -A OUTPUT -p udp -d "$i" --dport 53 --sport 1024:65535 -j ACCEPT
                ipt6 -A OUTPUT -p tcp -d "$i" --dport 53 --sport 1024:65535 -j ACCEPT
                fi
        else
                # IPv4 nameserver
                ipt4 -A INPUT -p udp -s "$i" --sport 53 --dport 1024:65535 $STATE_MATCH ESTABLISHED,RELATED -j ACCEPT
                ipt4 -A INPUT -p tcp -s "$i" --sport 53 --dport 1024:65535 $STATE_MATCH ESTABLISHED,RELATED -j ACCEPT
                ipt4 -A OUTPUT -p udp -d "$i" --dport 53 --sport 1024:65535 -j ACCEPT
                ipt4 -A OUTPUT -p tcp -d "$i" --dport 53 --sport 1024:65535 -j ACCEPT
        fi
        done
        if [ "$RESV_DNS_DROP" == "1" ]; then
                ipt4 -A INPUT  -p tcp --sport 53 --dport 1024:65535 -j $ALL_STOP
                ipt4 -A INPUT  -p udp --sport 53 --dport 1024:65535 -j $ALL_STOP
                if [ "$USE_IPV6" == "1" ]; then
                ipt6 -A INPUT  -p tcp --sport 53 --dport 1024:65535 -j $ALL_STOP
                ipt6 -A INPUT  -p udp --sport 53 --dport 1024:65535 -j $ALL_STOP
                fi
        fi
  fi
else
        ipt -A INPUT  -p udp --sport 53 --dport 1024:65535 $STATE_MATCH ESTABLISHED,RELATED -j ACCEPT
        ipt -A INPUT  -p tcp --sport 53 --dport 1024:65535 $STATE_MATCH ESTABLISHED,RELATED -j ACCEPT
        ipt -A OUTPUT -p udp --dport 53 --sport 1024:65535 -j ACCEPT
        ipt -A OUTPUT -p tcp --dport 53 --sport 1024:65535 -j ACCEPT
fi

# FTP
if [ "$HELPER_FTP" == "1" ]; then
ipt -A INPUT  -p tcp --sport 1024:65535 --dport $HELPER_FTP_PORT $STATE_MATCH RELATED,ESTABLISHED -j ACCEPT
ipt -A INPUT  -p tcp -m multiport --dport $HELPER_FTP_PORT,$HELPER_FTP_DATA $STATE_MATCH ESTABLISHED,RELATED -j ACCEPT
ipt -A INPUT  -p udp -m multiport --dport $HELPER_FTP_PORT,$HELPER_FTP_DATA $STATE_MATCH ESTABLISHED,RELATED -j ACCEPT
ipt -A OUTPUT  -p tcp --dport 1024:65535 --sport $HELPER_FTP_PORT $STATE_MATCH RELATED,ESTABLISHED -j ACCEPT
ipt -A OUTPUT  -p tcp -m multiport --dport $HELPER_FTP_PORT,$HELPER_FTP_DATA $STATE_MATCH ESTABLISHED,RELATED -j ACCEPT
ipt -A OUTPUT  -p udp -m multiport --dport $HELPER_FTP_PORT,$HELPER_FTP_DATA $STATE_MATCH ESTABLISHED,RELATED -j ACCEPT
fi

# SSH
if [ "$HELPER_SSH" == "1" ]; then
	ipt -A INPUT  -p tcp --sport $HELPER_SSH_PORT --dport 1024:65535 $STATE_MATCH ESTABLISHED,RELATED -j ACCEPT
fi

# Traceroute
if [ "$TCR_PASS" == "1" ]; then
	ipt -A INPUT  -p udp $STATE_MATCH NEW --dport $TCR_PORTS -j ACCEPT
        ipt -A OUTPUT  -p udp $STATE_MATCH NEW --dport $TCR_PORTS -j ACCEPT
fi


if [ "$LOG_DROP" == "1" ]; then
# Default TCP/UDP INPUT log chain
         ipt -A INPUT -p tcp -m limit --limit $LOG_RATE/minute  -j $LOG_TARGET --log-level=$LOG_LEVEL $LEXT --log-prefix "** IN_TCP DROP ** "
         ipt -A INPUT -p udp -m limit --limit $LOG_RATE/minute  -j $LOG_TARGET --log-level=$LOG_LEVEL $LEXT --log-prefix "** IN_UDP DROP ** "
fi

if [ "$LOG_DROP" == "1" ] && [ "$EGF" == "1" ]; then
# Default TCP/UDP OUTPUT log chain
         ipt -A OUTPUT -p tcp -m limit --limit $LOG_RATE/minute  -j $LOG_TARGET --log-level=$LOG_LEVEL $LEXT --log-prefix "** OUT_TCP DROP ** "
         ipt -A OUTPUT -p udp -m limit --limit $LOG_RATE/minute  -j $LOG_TARGET --log-level=$LOG_LEVEL $LEXT --log-prefix "** OUT_UDP DROP ** "
fi


# ECNSHAME
if [ "$SYSCTL_ECN" == "1" ]; then
	dlist_ecnshame
	dlist_ecnshame_hosts
fi

# Load our POSTROUTE rules
tosroute POSTROUTING
. "$POSTRT"

# Default Output Policies
if [ "$EGF" == "1" ]; then
	ipt -A OUTPUT -p tcp -j $TCP_STOP
	ipt -A OUTPUT -p udp -j $UDP_STOP
	ipt -A OUTPUT -p all -j $ALL_STOP
	eout "{glob} default (egress) output drop"
else
	ipt -A OUTPUT -j ACCEPT
	eout "{glob} default (egress) output accept"
fi

# Default Input Policies
eout "{glob} default (ingress) input drop"
ipt -A INPUT -p tcp -j $TCP_STOP
ipt -A INPUT -p udp -j $UDP_STOP
ipt -A INPUT -p all -j $ALL_STOP

# Post-configuration hook — runs after all rules including default policies
if [ -x "$INSTALL_PATH/hook_post.sh" ]; then
	eout "{glob} executing post-configuration hook"
	# shellcheck disable=SC1090,SC1091
	. "$INSTALL_PATH/hook_post.sh" || true  # safe: sourced hook exit code is advisory, never block firewall load
fi
}

start() {
check_deps
validate_config
elog_event "config_loaded" "info" "APF configuration loaded"
##
# Fast Load
##
if [ "$SET_FASTLOAD" == "1" ] && [ "$DOCKER_COMPAT" != "1" ]; then
# is this our first startup?
# if so we certainly do not want fast load
if [ ! -f "$INSTALL_PATH/internals/.last.full" ]; then
	SKIP_FASTLOAD_FIRSTRUN=1
fi
# Is our last full load more than 12h ago?
# if so we are going to full load
if [ -f "$INSTALL_PATH/internals/.last.full" ]; then
 read -r LAST_FULL < "$INSTALL_PATH/internals/.last.full"
 CURRENT_LOAD=$(date +"%s")
 LOAD_DIFF=$(($CURRENT_LOAD-$LAST_FULL))
 if [ ! "$LOAD_DIFF" -lt "43200" ]; then
	SKIP_FASTLOAD_EXPIRED=1
 fi
fi

# has our configuration changed since full load?
# if so full we go
if [ ! -f "$INSTALL_PATH/internals/.md5.cores" ]; then
        SKIP_FASTLOAD_VARS=1
	MD5_FIRSTRUN=1
else
        EMPTY_MD5=$(< "$INSTALL_PATH/internals/.md5.cores")
        if [ -z "$EMPTY_MD5" ]; then
                $MD5 $MD5_FILES > "$INSTALL_PATH/internals/.md5.cores" 2> /dev/null
        fi
	$MD5 $MD5_FILES > "$INSTALL_PATH/internals/.md5.cores.new" 2> /dev/null
        VARS_DIFF=$($DIFF "$INSTALL_PATH/internals/.md5.cores.new" "$INSTALL_PATH/internals/.md5.cores")
        if [ -n "$VARS_DIFF" ]; then
		$MD5 $MD5_FILES > "$INSTALL_PATH/internals/.md5.cores" 2> /dev/null
                SKIP_FASTLOAD_VARS=1
        fi
fi
if [ "$DEVEL_MODE" == "1" ]; then
	SKIP_FASTLOAD_VARS=1
fi
if [ ! -f "$INSTALL_PATH/internals/.md5.cores.new" ] && [ -f "$INSTALL_PATH/internals/.md5.cores" ]; then
	command cp "$INSTALL_PATH/internals/.md5.cores" "$INSTALL_PATH/internals/.md5.cores.new"
fi

if [ ! -f "$INSTALL_PATH/internals/.last.vars" ]; then
	"$INSTALL_PATH/apf" -o > "$INSTALL_PATH/internals/.last.vars"
	SKIP_FASTLOAD_VARS=1
else
	"$INSTALL_PATH/apf" -o > "$INSTALL_PATH/internals/.last.vars.new"
	VARS_DIFF=$($DIFF "$INSTALL_PATH/internals/.last.vars.new" "$INSTALL_PATH/internals/.last.vars")
	if [ -n "$VARS_DIFF" ]; then
	        "$INSTALL_PATH/apf" -o > "$INSTALL_PATH/internals/.last.vars"
		SKIP_FASTLOAD_VARS=1
	fi
fi

# check uptime is greater than 10 minutes (600s)
 read -r UPSEC _ < /proc/uptime; UPSEC="${UPSEC%%.*}"
 if [ "$UPSEC" -lt "601" ]; then
	SET_FASTLOAD_UPSEC=1
 fi

# check if we are flagged to skip fast load, otherwise off we go
if [ -z "$SKIP_FASTLOAD_FIRSTRUN" ] && [ -z "$SKIP_FASTLOAD_EXPIRED" ] && [ -z "$SKIP_FASTLOAD_VARS" ] && [ -z "$SET_FASTLOAD_UPSEC" ]; then
	# Verify snapshot backend matches current iptables backend
	detect_ipt_backend
	if [ -f "$INSTALL_PATH/internals/.apf.restore.backend" ]; then
		read -r IPT_BACKEND_SAVED < "$INSTALL_PATH/internals/.apf.restore.backend"
		if [ "$IPT_BACKEND_SAVED" != "$IPT_BACKEND" ]; then
			SKIP_FASTLOAD_BACKEND=1
		fi
	fi
	if [ "$SKIP_FASTLOAD_BACKEND" != "1" ]; then
		# Pre-validate IPv4 snapshot before attempting restore
		if [ ! -s "$INSTALL_PATH/internals/.apf.restore" ] || ! grep -q '^\*' "$INSTALL_PATH/internals/.apf.restore"; then
			eout "{glob} fast load snapshot empty or invalid, going full load"
		else
		devm
		# Recreate ipsets before restore (snapshot references --match-set)
		if [ "$USE_IPSET" == "1" ] && [ -n "$IPSET" ] && [ -f "$INSTALL_PATH/ipset.rules" ]; then
			ipset_load
		fi
		# Recreate GeoIP ipsets from cached data (no downloads)
		if cc_enabled; then
			# shellcheck disable=SC1090,SC1091
			. "$INSTALL_PATH/internals/apf_geoip.sh"
			_geoip_fast_load_ipsets
		fi
		eout "{glob} activating firewall, fast load ($IPT_BACKEND)"
		if ! $IPTR $IPT_FLAGS "$INSTALL_PATH/internals/.apf.restore" 2>/dev/null; then
			eout "{glob} fast load failed (iptables-restore error), going full load"
			flush 1
		elif [ "$USE_IPV6" == "1" ] && [ -z "$IP6TR" ]; then
			eout "{glob} fast load incomplete (ip6tables-restore not found), going full load"
			flush 1
		elif [ "$USE_IPV6" == "1" ] && [ -n "$IP6TR" ] && [ ! -f "$INSTALL_PATH/internals/.apf6.restore" ]; then
			eout "{glob} fast load incomplete (IPv6 enabled but no IPv6 snapshot), going full load"
			flush 1
		elif [ "$USE_IPV6" == "1" ] && [ -n "$IP6TR" ] && [ -f "$INSTALL_PATH/internals/.apf6.restore" ]; then
			if [ ! -s "$INSTALL_PATH/internals/.apf6.restore" ] || ! grep -q '^\*' "$INSTALL_PATH/internals/.apf6.restore"; then
				eout "{glob} IPv6 snapshot empty or invalid, going full load"
				flush 1
			elif ! $IP6TR $IPT_FLAGS "$INSTALL_PATH/internals/.apf6.restore" 2>/dev/null; then
				eout "{glob} fast load failed (ip6tables-restore error), going full load"
				flush 1
			else
				eout "{glob} firewall initialized"
				elog_event "service_state" "info" "APF firewall started (fast load)"
				mutex_unlock
				exit 0
			fi
		else
			eout "{glob} firewall initialized"
			elog_event "service_state" "info" "APF firewall started (fast load)"
			mutex_unlock
			exit 0
		fi
		fi # snapshot validation
	else
		eout "{glob} fast load snapshot backend mismatch ($IPT_BACKEND_SAVED vs $IPT_BACKEND), going full load"
	fi
 elif [ "$SKIP_FASTLOAD_FIRSTRUN" == "1" ]; then
	eout "{glob} first run? fast load skipped [internals/.last.full not present]"
 elif [ "$SKIP_FASTLOAD_EXPIRED" == "1" ]; then
	eout "{glob} fast load snapshot more than 12h old, going full load"
 elif [ "$SKIP_FASTLOAD_VARS" == "1" ]; then
	eout "{glob} config. or .rule file has changed since last full load, going full load"
 elif [ "$SET_FASTLOAD_UPSEC" == "1" ]; then
	eout "{glob} uptime less than 10 minutes, going full load"
fi

fi
##
# Full Load
##
# Remove orphaned temp files from previous versions (no-op if none exist)
_apf_cleanup_stale_tmp
eout "{glob} activating firewall"
# record our last full load
date +"%s" > "$INSTALL_PATH/internals/.last.full"
if [ ! -f "$DS_HOSTS" ]; then
	touch "$DS_HOSTS"
	chmod 640 "$DS_HOSTS"
fi
if [ ! -f "$DENY_HOSTS" ]; then
        touch "$DENY_HOSTS"
        chmod 640 "$DENY_HOSTS"
fi
if [ ! -f "$ALLOW_HOSTS" ]; then
        touch "$ALLOW_HOSTS"
        chmod 640 "$ALLOW_HOSTS"
fi
# check dev mode
devm
# generate vnet rules
"$INSTALL_PATH/vnet/vnetgen"
# start main firewall load
firewall_full_load
eout "{glob} firewall initialized"
elog_event "service_state" "info" "APF firewall started"
if [ "$MD5_FIRSTRUN" == "1" ]; then
        $MD5 $MD5_FILES > "$INSTALL_PATH/internals/.md5.cores" 2> /dev/null
fi

firewall_on=$($IPT $IPT_FLAGS -L --numeric | grep -vE "Chain|destination")
if [ "$DEVEL_ON" != "1" ] && [ "$DOCKER_COMPAT" != "1" ] && [ -n "$firewall_on" ]; then
	snapshot_save
fi
if [ "$SET_VERBOSE" == "1" ] && [ "$DEVEL_ON" == "1" ]; then
	eout "{glob} !!DEVELOPMENT MODE ENABLED!! - firewall will flush every 5 minutes."
fi

if [ "$SET_REFRESH_MD5" == "1" ] && [ "$MD5" ]; then
	$MD5 $DENY_HOSTS $GDENY_HOSTS $ALLOW_HOSTS $GALLOW_HOSTS | $MD5 | awk '{print$1}' > "$INSTALL_PATH/internals/.trusts.md5"
fi
}
