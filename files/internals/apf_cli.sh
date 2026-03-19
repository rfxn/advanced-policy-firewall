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
# APF CLI display and search functions

# Source guard
[[ -n "${_APF_CLI_LOADED:-}" ]] && return 0 2>/dev/null
_APF_CLI_LOADED=1

# shellcheck disable=SC2034
APF_CLI_VERSION="1.0.0"

help() {
	echo "usage: apf [OPTION]"
	echo ""
	echo "Firewall Control:"
	echo "  -s, --start ................. load all firewall rules"
	echo "  -r, --restart ............... flush & reload all firewall rules"
	echo "  -f, --stop, --flush ......... flush all firewall rules"
	echo "  --rules ..................... dump active rules to stdout"
	echo "  -l, --list .................. view all firewall rules in editor"
	echo "  --info ...................... show firewall status summary"
	echo "  -t, --status ................ page through full status log"
	echo "  -e, --refresh ............... refresh & re-resolve DNS in trust rules"
	echo ""
	echo "Trust Management:"
	echo "  -a HOST [CMT], --allow ...... add host/CC to allow list and load rule"
	echo "  -d HOST [CMT], --deny ....... add host/CC to deny list and load rule"
	echo "  -u HOST, --remove, --unban .. remove host/CC from all trust files"
	echo "  --list-allow ................ display allow list entries"
	echo "  --list-deny ................. display deny list entries"
	echo "  --lookup HOST ............... check if host exists in trust system"
	echo ""
	echo "  Advanced trust syntax:  apf -a \"tcp:in:d=22:s=10.0.0.0/8\""
	echo "                          apf -d \"d=3306:s=192.168.1.5\""
	echo "  Country codes:          apf -d CN      (deny China)"
	echo "                          apf -a US      (allow United States)"
	echo "                          apf -d @EU     (deny all of Europe)"
	echo "                          apf -d \"tcp:in:d=22:s=CN\""
	echo ""
	echo "Temporary Trust:"
	echo "  -ta HOST TTL [CMT], --temp-allow  temporarily allow host/CC (5m, 1h, 7d)"
	echo "  -td HOST TTL [CMT], --temp-deny   temporarily deny host/CC"
	echo "  --temp-list ................. list temp entries with remaining TTL"
	echo "  --temp-flush ................ remove all temporary entries"
	echo ""
	echo "Diagnostics:"
	echo "  -g PATTERN, --search ........ search iptables/ipset rules & trust files"
	echo "  --validate, --check ......... validate config without starting firewall"
	echo "  -o, --dump-config, --ovars .. output all configuration variables"
	echo "  -v, --version ............... output version number"
	echo "  -h, --help .................. show this help message"
	echo ""
	echo "Country Code Filtering:"
	echo "  --cc ........................ show GeoIP status overview"
	echo "  --cc CC ..................... show detail for country/continent (CN, @EU)"
	echo "  --cc IP ..................... look up country for an IP or CIDR"
	echo "  --cc-update ................. refresh GeoIP data and ipsets"
	echo ""
	echo "  NOTE: cc_allow.rules is a STRICT allowlist — all countries NOT listed"
	echo "        are blocked. Add admin IPs to allow_hosts.rules first."
	echo ""
	echo "Connection Tracking Limit:"
	echo "  --ct-scan ................... run CT_LIMIT scan and block offenders"
	echo "  --ct-status ................. show CT_LIMIT config and last scan info"
	echo ""
	echo "Subsystems:"
	echo "  --ipset-update .............. hot-reload ipset block lists"
	echo "  --gre-up .................... bring up GRE tunnels"
	echo "  --gre-down .................. tear down GRE tunnels"
	echo "  --gre-status ................ show GRE tunnel status"
}

list() {
echo "Loading iptables rules..."
iptc=$(mktemp "$INSTALL_PATH/.iptrules.XXXXXX")
_apf_reg_tmp "$iptc"
chmod 600 "$iptc"
$IPT $IPT_FLAGS --verbose --numeric --line-numbers --list >> "$iptc"
if [ "$USE_IPV6" == "1" ] && [ -n "$IP6T" ]; then
	echo "" >> "$iptc"
	echo "=== IPv6 (ip6tables) ===" >> "$iptc"
	echo "" >> "$iptc"
	$IP6T $IPT_FLAGS --verbose --numeric --line-numbers --list >> "$iptc"
fi
EDITOR_CMD=""
if [ -n "$EDITOR" ] && command -v "$EDITOR" > /dev/null 2>&1; then
	EDITOR_CMD=$(command -v "$EDITOR")
else
	for ed in pico nano vi vim; do
		if command -v "$ed" > /dev/null 2>&1; then
			EDITOR_CMD=$(command -v "$ed")
			break
		fi
	done
fi
if [ -n "$EDITOR_CMD" ]; then
	echo "Opening editor"
	$EDITOR_CMD "$iptc"
	command -v clear > /dev/null 2>&1 && clear
elif [ -t 1 ]; then
	${PAGER:-more} "$iptc"
else
	cat "$iptc"
fi
command rm -f "$iptc"
}

rules() {
	$IPT $IPT_FLAGS -S 2>/dev/null
	if [ "$USE_IPV6" == "1" ] && [ -n "$IP6T" ]; then
		echo ""
		echo "# === IPv6 ==="
		$IP6T $IPT_FLAGS -S 2>/dev/null
	fi
}

status() {
echo "$NAME Status Log:"
tac "$LOG_APF" | ${PAGER:-more}
}

cli_validate() {
    validate_config
    echo "Configuration validated successfully."
}

list_trust_file() {
    local file="$1" label="$2" content
    if [ ! -f "$file" ]; then
        echo "No ${label} found."
        return 1
    fi
    content=$(grep -v '^#' "$file" | grep -v '^[[:space:]]*$')
    if [ -z "$content" ]; then
        echo "No entries in ${label}."
        return 0
    fi
    echo "$content"
}

search() {
 local pattern="$1"
 if [ -z "$pattern" ]; then
  echo "usage: apf -g PATTERN" >&2
  return 1
 fi
 local found=0
 echo "Searching for: $pattern"
 echo ""

 # IPv4 rules (iptables -S for consistent cross-backend output)
 local ipv4_matches
 ipv4_matches=$($IPT $IPT_FLAGS -S 2>/dev/null | grep -in -- "$pattern")
 if [ -n "$ipv4_matches" ]; then
  echo "=== IPv4 (iptables -S) ==="
  echo "$ipv4_matches"
  echo ""
  found=1
 fi

 # IPv6 rules
 if [ "$USE_IPV6" == "1" ] && [ -n "$IP6T" ]; then
  local ipv6_matches
  ipv6_matches=$($IP6T $IPT_FLAGS -S 2>/dev/null | grep -in -- "$pattern")
  if [ -n "$ipv6_matches" ]; then
   echo "=== IPv6 (ip6tables -S) ==="
   echo "$ipv6_matches"
   echo ""
   found=1
  fi
 fi

 # ipset sets
 if [ "$USE_IPSET" == "1" ] && [ -n "$IPSET" ]; then
  local ipset_matches
  ipset_matches=$($IPSET list 2>/dev/null | grep -in -- "$pattern")
  if [ -n "$ipset_matches" ]; then
   echo "=== ipset ==="
   echo "$ipset_matches"
   echo ""
   found=1
  fi
 fi

 # Trust files
 for tf in $ALLOW_HOSTS $DENY_HOSTS $GALLOW_HOSTS $GDENY_HOSTS $CC_DENY_HOSTS $CC_ALLOW_HOSTS; do
  if [ -f "$tf" ]; then
   local tf_matches
   tf_matches=$(grep -in -- "$pattern" "$tf" 2>/dev/null)
   if [ -n "$tf_matches" ]; then
    echo "=== ${tf##*/} ==="
    echo "$tf_matches"
    echo ""
    found=1
   fi
  fi
 done

 if [ "$found" == "0" ]; then
  echo "No matches found."
 fi
}

ovars() {
	for var in $(nice -n 16 grep -hv "^#" "$INSTALL_PATH/conf.apf" "$INSTALL_PATH/internals/internals.conf" | grep "=" | awk -F'=' '{print $1}' | tr -d ' ' | grep -E '^[A-Za-z_][A-Za-z0-9_]*$' | awk '!seen[$0]++'); do
		echo "$var=${!var}"
	done
}

trust_lookup() {
	local host="$1"
	if [ -z "$host" ]; then
		echo "usage: apf --lookup HOST"
		return 1
	fi
	local found=0
	local label file matches

	for pair in "ALLOW:$ALLOW_HOSTS" "DENY:$DENY_HOSTS" "GLOBAL ALLOW:$GALLOW_HOSTS" "GLOBAL DENY:$GDENY_HOSTS" "CC DENY:$CC_DENY_HOSTS" "CC ALLOW:$CC_ALLOW_HOSTS"; do
		label="${pair%%:*}"
		file="${pair#*:}"
		[ -f "$file" ] || continue
		matches=$(grep -in -- "$host" "$file" 2>/dev/null)
		if [ -n "$matches" ]; then
			echo "${label} (${file##*/}):"
			echo "$matches"
			echo ""
			found=1
		fi
	done

	if [ "$found" -eq 0 ]; then
		echo "$host not found in any trust file."
		return 1
	fi
}

cl_cports() {
	IG_TCP_CPORTS=""
	IG_UDP_CPORTS=""
	IG_TCP_CLIMIT=""
	IG_UDP_CLIMIT=""
	IG_ICMP_TYPES=""
	IG_ICMPV6_TYPES=""
	EG_TCP_CPORTS=""
	EG_UDP_CPORTS=""
	EG_ICMP_TYPES=""
	EG_ICMPV6_TYPES=""
	EG_TCP_UID=""
	EG_UDP_UID=""
	SMTP_BLOCK=""
	SMTP_PORTS=""
	SMTP_ALLOWUSER=""
	SMTP_ALLOWGROUP=""
	EG_DROP_CMD=""
}
