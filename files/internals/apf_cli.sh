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

# --- CLI color helpers ---
# Respects NO_COLOR (https://no-color.org/) and non-TTY output.
# Called once at source time; functions are no-ops when color is off.
_CLI_BOLD=""
_CLI_DIM=""
_CLI_RESET=""

_cli_color_init() {
    # NO_COLOR: any non-empty value disables color
    if [ -n "${NO_COLOR:-}" ]; then
        return 0
    fi
    # Only colorize when stdout is a terminal
    if [ ! -t 1 ]; then
        return 0
    fi
    # TERM=dumb has no color support
    if [ "${TERM:-}" = "dumb" ]; then
        return 0
    fi
    _CLI_BOLD=$'\033[1m'
    _CLI_DIM=$'\033[2m'
    _CLI_RESET=$'\033[0m'
}
_cli_color_init

# --- "Did you mean?" typo correction ---
# Pure-bash Levenshtein distance using two-row DP.
# Bash 4.1+ compatible: no associative arrays, no nameref.
_cli_levenshtein() {
    local s="$1" t="$2"
    local s_len=${#s} t_len=${#t}
    local i j cost

    # Fast paths
    if [ "$s_len" -eq 0 ]; then echo "$t_len"; return; fi
    if [ "$t_len" -eq 0 ]; then echo "$s_len"; return; fi

    # prev_row[j] = distance for first i chars of s vs first j chars of t
    local prev_row=() curr_row=()
    for (( j = 0; j <= t_len; j++ )); do
        prev_row[$j]=$j
    done

    for (( i = 1; i <= s_len; i++ )); do
        curr_row[0]=$i
        for (( j = 1; j <= t_len; j++ )); do
            if [ "${s:i-1:1}" = "${t:j-1:1}" ]; then
                cost=0
            else
                cost=1
            fi
            # min(delete, insert, substitute)
            local del=$(( prev_row[j] + 1 ))
            local ins=$(( curr_row[j-1] + 1 ))
            local sub=$(( prev_row[j-1] + cost ))
            local min=$del
            [ "$ins" -lt "$min" ] && min=$ins
            [ "$sub" -lt "$min" ] && min=$sub
            curr_row[$j]=$min
        done
        # swap rows
        for (( j = 0; j <= t_len; j++ )); do
            prev_row[$j]=${curr_row[$j]}
        done
    done
    echo "${prev_row[$t_len]}"
}

# Find closest match within threshold. Returns best match on stdout,
# or empty string if no match within threshold.
# Usage: _cli_did_you_mean "input" "word1 word2 word3" [threshold]
_cli_did_you_mean() {
    local input="$1" candidates="$2" threshold="${3:-3}"
    local best="" best_dist=999 dist
    local candidate
    for candidate in $candidates; do
        dist=$(_cli_levenshtein "$input" "$candidate")
        if [ "$dist" -lt "$best_dist" ]; then
            best_dist=$dist
            best="$candidate"
        fi
    done
    if [ "$best_dist" -le "$threshold" ] && [ "$best_dist" -gt 0 ]; then
        echo "$best"
    fi
}

# Print targeted error for unknown command with optional suggestion.
# Usage: _cli_unknown_command "apf" "$1" "trust cc config ..."
_cli_unknown_command() {
    local prefix="$1" input="$2" candidates="$3"
    local suggestion
    suggestion=$(_cli_did_you_mean "$input" "$candidates")
    if [ -n "$suggestion" ]; then
        echo "${prefix}: unknown command '${input}'. Did you mean '${suggestion}'?" >&2
    else
        echo "${prefix}: unknown command '${input}'. See '${prefix} --help'." >&2
    fi
}

# Print targeted error for unknown verb with optional suggestion.
# Usage: _cli_unknown_verb "apf trust" "$1" "add deny remove ..."
_cli_unknown_verb() {
    local prefix="$1" input="$2" candidates="$3"
    local suggestion
    suggestion=$(_cli_did_you_mean "$input" "$candidates")
    if [ -n "$suggestion" ]; then
        echo "${prefix}: unknown verb '${input}'. Did you mean '${suggestion}'?" >&2
    else
        echo "${prefix}: unknown verb '${input}'. See '${prefix} --help'." >&2
    fi
}

help() {
    echo "usage: apf [COMMAND] [OPTIONS]"
    echo ""
    echo "${_CLI_BOLD}COMMANDS:${_CLI_RESET}"
    echo "  -s, --start              load all firewall rules"
    echo "  -f, --stop               flush all firewall rules"
    echo "  -r, --restart            flush & reload all firewall rules"
    echo "  -a, --allow HOST [CMT]   allow host (IP/CIDR/FQDN/CC)"
    echo "  -d, --deny  HOST [CMT]   deny host"
    echo "  -u, --remove HOST        remove host from all lists"
    echo "  -g, --search PATTERN     search rules and trust files"
    echo ""
    echo "${_CLI_BOLD}SUBCOMMANDS:${_CLI_RESET}"
    echo "  trust              trust system management"
    echo "  status             firewall status and diagnostics"
    echo "  cc                 country code / GeoIP operations"
    echo "  ct                 connection tracking limit"
    echo "  config             configuration and validation"
    echo "  ipset              ipset block list management"
    echo "  gre                GRE tunnel management"
    echo ""
    echo "${_CLI_BOLD}UTILITIES:${_CLI_RESET}"
    echo "  -e, --refresh      refresh & re-resolve DNS in trust rules"
    echo "  -l, --list         view all firewall rules in editor"
    echo "  -t, --status       page through full status log"
    echo "  -o, --dump-config  output all configuration variables"
    echo "  -v, --version      output version number"
    echo "  -h                 show this help message"
    echo "  --help             open full manual page"
    echo ""
    echo "Run 'apf <command> --help' for subcommand details."
    echo "CSF users: run 'apf --csf-help' for a command mapping."
}

list() {
echo "Loading iptables rules..."
iptc=$(mktemp "$INSTALL_PATH/.iptrules.XXXXXX")
_apf_reg_tmp "$iptc"
command chmod 600 "$iptc"
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
	command cat "$iptc"
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
		echo "usage: apf trust lookup HOST"
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

	# FQDN resolution pass: if queried host is an IP (v4 or v6), check FQDN entries
	if ! is_fqdn "$host"; then
		local _tl_line
		for pair in "ALLOW:$ALLOW_HOSTS" "DENY:$DENY_HOSTS" "GLOBAL ALLOW:$GALLOW_HOSTS" "GLOBAL DENY:$GDENY_HOSTS"; do
			label="${pair%%:*}"
			file="${pair#*:}"
			[ -f "$file" ] || continue
			while IFS= read -r _tl_line; do
				[[ "$_tl_line" =~ ^# ]] && continue
				[ -z "$_tl_line" ] && continue
				is_fqdn "$_tl_line" || continue
				if _resolve_fqdn_metadata "$_tl_line"; then
					case ",$_FQDN_RESOLVED_IPS," in
						*",$host,"*)
							echo "${label} (${file##*/}) [FQDN: $_tl_line -> $_FQDN_RESOLVED_IPS]:"
							grep -in -- "$_tl_line" "$file" 2>/dev/null  # safe: file validated above
							echo ""
							found=1
							;;
					esac
				fi
			done < "$file"
		done
	fi

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

## Dispatch: apf status <verb>
_dispatch_status() {
	case "${1:-}" in
	"")
		firewall_info
		;;
	-h|--help)
		_status_help
		;;
	rules)  rules ;;
	log)    status ;;
	*)  _cli_unknown_verb "apf status" "$1" "rules log"; return 1 ;;
	esac
}

## Dispatch: apf config <verb>
_dispatch_config() {
	case "${1:-}" in
	-h|--help|"") _config_help ;;
	dump)     apf_banner; ovars ;;
	validate) cli_validate ;;
	*)  _cli_unknown_verb "apf config" "$1" "dump validate"; return 1 ;;
	esac
}

_status_help() {
	echo "usage: apf status <command>"
	echo ""
	echo "  (none)                 show firewall status summary (= apf --info)"
	echo "  rules                  dump active rules to stdout (= apf --rules)"
	echo "  log                    page through full status log (= apf -t)"
	echo ""
	echo "  Examples:  apf status              (summary)"
	echo "             apf status rules | grep TALLOW"
}

_config_help() {
	echo "usage: apf config <command>"
	echo ""
	echo "  dump                   output all configuration variables (= apf -o)"
	echo "  validate               validate config without starting firewall"
	echo ""
	echo "  Examples:  apf config validate"
	echo "             apf config dump | grep TCP"
}

_csf_help() {
	echo "CSF-to-APF Command Reference"
	echo ""
	echo "SERVICE:"
	echo "  csf -s          =  apf -s              start firewall"
	echo "  csf -f          =  apf -f              stop/flush firewall"
	echo "  csf -r          =  apf -r              restart firewall"
	echo ""
	echo "ALLOW / DENY:"
	echo "  csf -a IP       =  apf -a IP           allow host"
	echo "  csf -d IP       =  apf -d IP           deny host"
	echo "  csf -ar IP      =  apf -u IP           remove from allow"
	echo "  csf -dr IP      =  apf -u IP           remove from deny"
	echo ""
	echo "TEMPORARY:"
	echo "  csf -ta IP TTL  =  apf trust temp add IP TTL"
	echo "  csf -td IP TTL  =  apf trust temp deny IP TTL"
	echo "  csf -t          =  apf trust temp list"
	echo "  csf -tr IP      =  apf -u IP           remove temp entry"
	echo "  csf -tf         =  apf trust temp flush"
	echo ""
	echo "SEARCH / LOOKUP:"
	echo "  csf -g IP       =  apf -g IP           search rules"
	echo "  csf -i IP       =  apf cc lookup IP    GeoIP lookup"
	echo "  csf -l          =  apf -l              list iptables rules"
	echo ""
	echo "COUNTRY BLOCKING:"
	echo "  CC_DENY in csf.conf  =  apf -d CN      per-CC via trust system"
	echo "  CC_ALLOW in csf.conf =  apf -a US      via cc_allow.rules"
	echo ""
	echo "CONFIG:"
	echo "  csf --check     =  apf config validate"
	echo ""
	echo "DIFFERENCES:"
	echo "  * APF -u searches ALL lists (no need for separate -ar/-dr)"
	echo "  * APF country blocking uses rules files, not config variables"
	echo "  * APF advanced syntax uses ':' separator (CSF uses '|')"
	echo "    CSF: tcp|in|d=22|s=10.0.0.0/8"
	echo "    APF: tcp:in:d=22:s=10.0.0.0/8"
	echo "  * APF DEVEL_MODE = CSF TESTING (auto-flush safety net)"
	echo "  * APF has no LFD -- use BFD for brute-force detection"
}
