#!/bin/bash
#
# geoip_lib.sh — GeoIP Metadata Library 1.0.5
###
# Copyright (C) 2026 R-fx Networks <proj@rfxn.com>
#                     Ryan MacDonald <ryan@rfxn.com>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
###
#
# Shared GeoIP metadata library for rfxn projects.
# Source this file to access country name, continent, and code validation functions.
# No project-specific code — all behavior controlled via variables.

# Source guard — safe for repeated sourcing
[[ -n "${_GEOIP_LIB_LOADED:-}" ]] && return 0 2>/dev/null  # return outside function is non-fatal
_GEOIP_LIB_LOADED=1

# shellcheck disable=SC2034
GEOIP_LIB_VERSION="1.0.5"

# ---------------------------------------------------------------------------
# Module-level continent CC lists (ISO 3166 assignments per UN geoscheme)
# Defined once, used by geoip_cc_continent() and geoip_expand_codes().
# Set at source time — inherited by subshells, never modified after init.
# ---------------------------------------------------------------------------
_GEOIP_CC_AF="AO,BF,BI,BJ,BW,CD,CF,CG,CI,CM,CV,DJ,DZ,EG,EH,ER,ET,GA,GH,GM,GN,GQ,GW,KE,KM,LR,LS,LY,MA,MG,ML,MR,MU,MW,MZ,NA,NE,NG,RE,RW,SC,SD,SH,SL,SN,SO,SS,ST,SZ,TD,TG,TN,TZ,UG,YT,ZA,ZM,ZW"
_GEOIP_CC_AS="AE,AF,AM,AZ,BD,BH,BN,BT,CN,CY,GE,HK,ID,IL,IN,IQ,IR,JO,JP,KG,KH,KP,KR,KW,KZ,LA,LB,LK,MM,MN,MO,MV,MY,NP,OM,PH,PK,PS,QA,SA,SG,SY,TH,TJ,TL,TM,TR,TW,UZ,VN,YE"
_GEOIP_CC_EU="AD,AL,AT,AX,BA,BE,BG,BY,CH,CZ,DE,DK,EE,ES,FI,FO,FR,GB,GG,GI,GR,HR,HU,IE,IM,IS,IT,JE,LI,LT,LU,LV,MC,MD,ME,MK,MT,NL,NO,PL,PT,RO,RS,RU,SE,SI,SK,SM,UA,VA,XK"
_GEOIP_CC_NA="AG,AI,AW,BB,BL,BM,BQ,BS,BZ,CA,CR,CU,CW,DM,DO,GD,GL,GP,GT,HN,HT,JM,KN,KY,LC,MF,MQ,MS,MX,NI,PA,PM,PR,SV,SX,TC,TT,US,VC,VG,VI"
_GEOIP_CC_SA="AR,BO,BR,CL,CO,EC,FK,GF,GY,PE,PY,SR,UY,VE"
_GEOIP_CC_OC="AS,AU,CK,FJ,FM,GU,KI,MH,MP,NC,NF,NR,NU,NZ,PF,PG,PN,PW,SB,TK,TO,TV,VU,WF,WS"

# ---------------------------------------------------------------------------
# geoip_cc_name — Map ISO 3166-1 alpha-2 country code to country name.
# Falls back to bare code for uncommon/unrecognized countries.
# Args: cc (2-letter uppercase code)
# Prints: country name string (or bare code on unknown)
# ---------------------------------------------------------------------------
geoip_cc_name() {
	local cc="$1"
	case "$cc" in
		AD) echo "Andorra" ;; AE) echo "UAE" ;; AF) echo "Afghanistan" ;;
		AG) echo "Antigua & Barbuda" ;; AL) echo "Albania" ;; AM) echo "Armenia" ;;
		AO) echo "Angola" ;; AR) echo "Argentina" ;; AT) echo "Austria" ;;
		AU) echo "Australia" ;; AZ) echo "Azerbaijan" ;; BA) echo "Bosnia" ;;
		BB) echo "Barbados" ;; BD) echo "Bangladesh" ;; BE) echo "Belgium" ;;
		BF) echo "Burkina Faso" ;; BG) echo "Bulgaria" ;; BH) echo "Bahrain" ;;
		BI) echo "Burundi" ;; BJ) echo "Benin" ;; BN) echo "Brunei" ;;
		BO) echo "Bolivia" ;; BR) echo "Brazil" ;; BS) echo "Bahamas" ;;
		BT) echo "Bhutan" ;; BW) echo "Botswana" ;; BY) echo "Belarus" ;;
		BZ) echo "Belize" ;; CA) echo "Canada" ;; CD) echo "DR Congo" ;;
		CF) echo "Central African Republic" ;; CG) echo "Congo" ;;
		CH) echo "Switzerland" ;; CI) echo "Ivory Coast" ;; CL) echo "Chile" ;;
		CM) echo "Cameroon" ;; CN) echo "China" ;; CO) echo "Colombia" ;;
		CR) echo "Costa Rica" ;; CU) echo "Cuba" ;; CV) echo "Cape Verde" ;;
		CY) echo "Cyprus" ;; CZ) echo "Czech Republic" ;; DE) echo "Germany" ;;
		DJ) echo "Djibouti" ;; DK) echo "Denmark" ;; DM) echo "Dominica" ;;
		DO) echo "Dominican Republic" ;; DZ) echo "Algeria" ;; EC) echo "Ecuador" ;;
		EE) echo "Estonia" ;; EG) echo "Egypt" ;; ER) echo "Eritrea" ;;
		ES) echo "Spain" ;; ET) echo "Ethiopia" ;; FI) echo "Finland" ;;
		FJ) echo "Fiji" ;; FR) echo "France" ;; GA) echo "Gabon" ;;
		GB) echo "United Kingdom" ;; GE) echo "Georgia" ;; GH) echo "Ghana" ;;
		GR) echo "Greece" ;; GT) echo "Guatemala" ;; GN) echo "Guinea" ;;
		GW) echo "Guinea-Bissau" ;; GY) echo "Guyana" ;; HK) echo "Hong Kong" ;;
		HN) echo "Honduras" ;; HR) echo "Croatia" ;; HT) echo "Haiti" ;;
		HU) echo "Hungary" ;; ID) echo "Indonesia" ;; IE) echo "Ireland" ;;
		IL) echo "Israel" ;; IN) echo "India" ;; IQ) echo "Iraq" ;;
		IR) echo "Iran" ;; IS) echo "Iceland" ;; IT) echo "Italy" ;;
		JM) echo "Jamaica" ;; JO) echo "Jordan" ;; JP) echo "Japan" ;;
		KE) echo "Kenya" ;; KG) echo "Kyrgyzstan" ;; KH) echo "Cambodia" ;;
		KP) echo "North Korea" ;; KR) echo "South Korea" ;; KW) echo "Kuwait" ;;
		KZ) echo "Kazakhstan" ;; LA) echo "Laos" ;; LB) echo "Lebanon" ;;
		LK) echo "Sri Lanka" ;; LR) echo "Liberia" ;; LS) echo "Lesotho" ;;
		LT) echo "Lithuania" ;; LU) echo "Luxembourg" ;; LV) echo "Latvia" ;;
		LY) echo "Libya" ;; MA) echo "Morocco" ;; MC) echo "Monaco" ;;
		MD) echo "Moldova" ;; ME) echo "Montenegro" ;; MG) echo "Madagascar" ;;
		MK) echo "North Macedonia" ;; ML) echo "Mali" ;; MM) echo "Myanmar" ;;
		MN) echo "Mongolia" ;; MO) echo "Macau" ;; MR) echo "Mauritania" ;;
		MU) echo "Mauritius" ;; MV) echo "Maldives" ;; MW) echo "Malawi" ;;
		MX) echo "Mexico" ;; MY) echo "Malaysia" ;; MZ) echo "Mozambique" ;;
		NA) echo "Namibia" ;; NE) echo "Niger" ;; NG) echo "Nigeria" ;;
		NI) echo "Nicaragua" ;; NL) echo "Netherlands" ;; NO) echo "Norway" ;;
		NP) echo "Nepal" ;; NZ) echo "New Zealand" ;; OM) echo "Oman" ;;
		PA) echo "Panama" ;; PE) echo "Peru" ;; PG) echo "Papua New Guinea" ;;
		PH) echo "Philippines" ;; PK) echo "Pakistan" ;; PL) echo "Poland" ;;
		PR) echo "Puerto Rico" ;; PS) echo "Palestine" ;; PT) echo "Portugal" ;;
		PY) echo "Paraguay" ;; QA) echo "Qatar" ;; RO) echo "Romania" ;;
		RS) echo "Serbia" ;; RU) echo "Russia" ;; RW) echo "Rwanda" ;;
		SA) echo "Saudi Arabia" ;; SB) echo "Solomon Islands" ;;
		SC) echo "Seychelles" ;; SD) echo "Sudan" ;; SE) echo "Sweden" ;;
		SG) echo "Singapore" ;; SI) echo "Slovenia" ;; SK) echo "Slovakia" ;;
		SL) echo "Sierra Leone" ;; SN) echo "Senegal" ;; SO) echo "Somalia" ;;
		SR) echo "Suriname" ;; SS) echo "South Sudan" ;; SV) echo "El Salvador" ;;
		SY) echo "Syria" ;; SZ) echo "Eswatini" ;; TD) echo "Chad" ;;
		TG) echo "Togo" ;; TH) echo "Thailand" ;; TJ) echo "Tajikistan" ;;
		TL) echo "Timor-Leste" ;; TM) echo "Turkmenistan" ;; TN) echo "Tunisia" ;;
		TR) echo "Turkey" ;; TT) echo "Trinidad & Tobago" ;; TW) echo "Taiwan" ;;
		TZ) echo "Tanzania" ;; UA) echo "Ukraine" ;; UG) echo "Uganda" ;;
		US) echo "United States" ;; UY) echo "Uruguay" ;; UZ) echo "Uzbekistan" ;;
		VA) echo "Vatican City" ;; VE) echo "Venezuela" ;; VN) echo "Vietnam" ;;
		YE) echo "Yemen" ;; ZA) echo "South Africa" ;; ZM) echo "Zambia" ;;
		ZW) echo "Zimbabwe" ;; XK) echo "Kosovo" ;;
		*) echo "$cc" ;;
	esac
}

# ---------------------------------------------------------------------------
# geoip_cc_continent — Map ISO 3166-1 country code to continent shorthand.
# Uses module-level continent lists (no eval, case-based comma search).
# Args: cc (2-letter uppercase code)
# Prints: continent shorthand (@AF, @AS, @EU, @NA, @SA, @OC) or "unknown"
# ---------------------------------------------------------------------------
geoip_cc_continent() {
	local cc="$1"
	case ",$_GEOIP_CC_AF," in *,"$cc",*) echo "@AF"; return 0 ;; esac
	case ",$_GEOIP_CC_AS," in *,"$cc",*) echo "@AS"; return 0 ;; esac
	case ",$_GEOIP_CC_EU," in *,"$cc",*) echo "@EU"; return 0 ;; esac
	case ",$_GEOIP_CC_NA," in *,"$cc",*) echo "@NA"; return 0 ;; esac
	case ",$_GEOIP_CC_SA," in *,"$cc",*) echo "@SA"; return 0 ;; esac
	case ",$_GEOIP_CC_OC," in *,"$cc",*) echo "@OC"; return 0 ;; esac
	echo "unknown"
}

# ---------------------------------------------------------------------------
# geoip_continent_name — Map continent shorthand to full name.
# Args: continent shorthand (@AF, @AS, @EU, @NA, @SA, @OC)
# Prints: full name (e.g., "Africa") or passthrough on unknown
# ---------------------------------------------------------------------------
geoip_continent_name() {
	case "$1" in
		@AF) echo "Africa" ;; @AS) echo "Asia" ;; @EU) echo "Europe" ;;
		@NA) echo "North America" ;; @SA) echo "South America" ;; @OC) echo "Oceania" ;;
		*) echo "$1" ;;
	esac
}

# ---------------------------------------------------------------------------
# geoip_expand_codes — Expand continent shorthand to comma-separated CC list.
# Sets _GEOIP_VCC_CODES. Returns 1 for unknown continent.
# Args: continent shorthand (@AF, @AS, @EU, @NA, @SA, @OC)
# ---------------------------------------------------------------------------
geoip_expand_codes() {
	local input="$1"
	case "$input" in
		@AF) _GEOIP_VCC_CODES="$_GEOIP_CC_AF" ;;
		@AS) _GEOIP_VCC_CODES="$_GEOIP_CC_AS" ;;
		@EU) _GEOIP_VCC_CODES="$_GEOIP_CC_EU" ;;
		@NA) _GEOIP_VCC_CODES="$_GEOIP_CC_NA" ;;
		@SA) _GEOIP_VCC_CODES="$_GEOIP_CC_SA" ;;
		@OC) _GEOIP_VCC_CODES="$_GEOIP_CC_OC" ;;
		*) return 1 ;;
	esac
	return 0
}

# ---------------------------------------------------------------------------
# geoip_validate_cc — Validate ISO 3166-1 country code or continent shorthand.
# Sets: _GEOIP_VCC_TYPE ("country" or "continent"), _GEOIP_VCC_CODES (CC list)
# Accepts: XX (2-letter country code) or @XX (continent shorthand).
# Returns 1 on invalid input.
# Note: format validation only — unknown codes like "ZZ" pass as "country".
# ---------------------------------------------------------------------------
geoip_validate_cc() {
	local input="$1"
	local _vcc_cc='^[A-Z]{2}$'
	local _vcc_cont='^@[A-Z]{2}$'
	_GEOIP_VCC_TYPE=""
	_GEOIP_VCC_CODES=""
	if [[ "$input" =~ $_vcc_cc ]]; then
		_GEOIP_VCC_TYPE="country"
		_GEOIP_VCC_CODES="$input"
		return 0
	fi
	if [[ "$input" =~ $_vcc_cont ]]; then
		if geoip_expand_codes "$input"; then
			_GEOIP_VCC_TYPE="continent"
			return 0
		fi
	fi
	return 1
}

# ---------------------------------------------------------------------------
# geoip_all_cc — emit all known ISO 3166-1 country codes (one per line).
# Iterates the 6 continent CC lists from module-level variables.
# Prints: one uppercase 2-letter CC per line to stdout
# ---------------------------------------------------------------------------
geoip_all_cc() {
	local _cont _code
	for _cont in "$_GEOIP_CC_AF" "$_GEOIP_CC_AS" "$_GEOIP_CC_EU" \
	             "$_GEOIP_CC_NA" "$_GEOIP_CC_SA" "$_GEOIP_CC_OC"; do
		while IFS= read -r _code; do
			[[ -n "$_code" ]] && echo "$_code"
		done <<< "${_cont//,/$'\n'}"
	done
}

# ---------------------------------------------------------------------------
# _geoip_valid_ipv4 — validate IPv4 dotted-quad with octet range check.
# Rejects octets >255 (e.g., 999.0.0.1) that a bare [0-9]+ regex would accept.
# Args: IP
# Returns: 0 if valid IPv4, 1 otherwise
# ---------------------------------------------------------------------------
_geoip_valid_ipv4() {
	local ip="$1"
	local _re='^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$'
	[[ "$ip" =~ $_re ]] || return 1
	local i
	for i in 1 2 3 4; do
		[ "${BASH_REMATCH[$i]}" -le 255 ] 2>/dev/null || return 1  # non-numeric or >255
	done
	return 0
}

# ===========================================================================
# Download Layer — CIDR data download, staleness, and search
# ===========================================================================

# ---------------------------------------------------------------------------
# Binary discovery at source time — allows env override for testing.
# ---------------------------------------------------------------------------
GEOIP_CURL_BIN="${GEOIP_CURL_BIN:-$(command -v curl 2>/dev/null || true)}"  # may be absent
GEOIP_WGET_BIN="${GEOIP_WGET_BIN:-$(command -v wget 2>/dev/null || true)}"  # may be absent
GEOIP_AWK_BIN="${GEOIP_AWK_BIN:-$(command -v awk 2>/dev/null || true)}"     # may be absent
GEOIP_DL_TIMEOUT="${GEOIP_DL_TIMEOUT:-120}"

# ---------------------------------------------------------------------------
# _geoip_download_cmd — download URL to file via curl or wget.
# Internal helper. Strict TLS by default. Set GEOIP_TLS_INSECURE=1 to allow
# insecure fallback (analogous to curl --insecure) for legacy systems with
# untrusted CA bundles or expired certificates.
# Args: URL OUTPUT
# Returns: 0 on success, 1 on failure (OUTPUT removed on failure)
# ---------------------------------------------------------------------------
_geoip_download_cmd() {
	local url="$1" output="$2"
	local rc=1

	if [[ -n "$GEOIP_CURL_BIN" ]]; then
		# Strict TLS first
		"$GEOIP_CURL_BIN" -sfL --connect-timeout "$GEOIP_DL_TIMEOUT" \
			--max-time "$GEOIP_DL_TIMEOUT" -o "$output" "$url" 2>/dev/null  # curl stderr noise suppressed
		rc=$?
		if [[ "$rc" -ne 0 && "${GEOIP_TLS_INSECURE:-0}" == "1" ]]; then
			# Explicit opt-in insecure fallback for legacy systems (EL6, etc.)
			"$GEOIP_CURL_BIN" -sfL --insecure --connect-timeout "$GEOIP_DL_TIMEOUT" \
				--max-time "$GEOIP_DL_TIMEOUT" -o "$output" "$url" 2>/dev/null  # curl stderr noise suppressed
			rc=$?
		fi
	elif [[ -n "$GEOIP_WGET_BIN" ]]; then
		# Strict TLS first
		"$GEOIP_WGET_BIN" -q --timeout="$GEOIP_DL_TIMEOUT" -O "$output" "$url" 2>/dev/null  # wget stderr noise suppressed
		rc=$?
		if [[ "$rc" -ne 0 && "${GEOIP_TLS_INSECURE:-0}" == "1" ]]; then
			# Explicit opt-in insecure fallback for legacy systems (EL6, etc.)
			"$GEOIP_WGET_BIN" -q --no-check-certificate \
				--timeout="$GEOIP_DL_TIMEOUT" -O "$output" "$url" 2>/dev/null  # wget stderr noise suppressed
			rc=$?
		fi
	else
		echo "geoip_lib: neither curl nor wget available" >&2
		return 1
	fi

	if [[ "$rc" -ne 0 ]]; then
		command rm -f "$output"
		return 1
	fi
	return 0
}

# ---------------------------------------------------------------------------
# _geoip_validate_cidr_file — validate downloaded CIDR file content.
# Checks that file has at least GEOIP_MIN_CIDR_LINES matching lines
# in expected CIDR format. Default minimum is 3 to catch truncated or
# near-empty files that happen to contain one valid-looking line.
# Args: FILE FAMILY (4 or 6)
# Returns: 0 if valid, 1 if empty/garbage/below minimum
# ---------------------------------------------------------------------------
_geoip_validate_cidr_file() {
	local file="$1" family="$2"
	local pat line_count

	[[ -f "$file" ]] || return 1
	[[ -s "$file" ]] || return 1

	if [[ "$family" == "6" ]]; then
		pat='^[0-9a-fA-F:]*/[0-9]'
	else
		pat='^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]'
	fi
	line_count=$(grep -cE "$pat" "$file" || true)  # grep -c exits 1 on 0 matches
	[[ "$line_count" -ge "${GEOIP_MIN_CIDR_LINES:-3}" ]]
}

# ---------------------------------------------------------------------------
# _geoip_download_ipverse — download CIDR data from ipverse.net.
# Args: CC FAMILY OUTPUT
#   CC: 2-letter lowercase country code (ipverse uses lowercase)
#   FAMILY: "4" or "6"
#   OUTPUT: destination file path
# Returns: 0 on success (valid CIDR), 1 on failure
# ---------------------------------------------------------------------------
_geoip_download_ipverse() {
	local cc="$1" family="$2" output="$3"
	local url tmpfile

	if [[ "$family" == "6" ]]; then
		url="https://ipverse.net/ipblocks/data/countries/${cc}.zone6"
	else
		url="https://ipverse.net/ipblocks/data/countries/${cc}.zone"
	fi

	tmpfile=$(mktemp "${output}.XXXXXX") || return 1

	if ! _geoip_download_cmd "$url" "$tmpfile"; then
		command rm -f "$tmpfile"
		return 1
	fi

	if ! _geoip_validate_cidr_file "$tmpfile" "$family"; then
		command rm -f "$tmpfile"
		return 1
	fi

	command mv -f "$tmpfile" "$output" || { command rm -f "$tmpfile"; return 1; }
	return 0
}

# ---------------------------------------------------------------------------
# _geoip_download_ipdeny — download CIDR data from ipdeny.com.
# Args: CC FAMILY OUTPUT
#   CC: 2-letter lowercase country code (ipdeny uses lowercase)
#   FAMILY: "4" or "6"
#   OUTPUT: destination file path
# Returns: 0 on success (valid CIDR), 1 on failure
# ---------------------------------------------------------------------------
_geoip_download_ipdeny() {
	local cc="$1" family="$2" output="$3"
	local url tmpfile

	if [[ "$family" == "6" ]]; then
		url="https://www.ipdeny.com/ipv6/ipaddresses/blocks/${cc}.zone"
	else
		url="https://www.ipdeny.com/ipblocks/data/countries/${cc}.zone"
	fi

	tmpfile=$(mktemp "${output}.XXXXXX") || return 1

	if ! _geoip_download_cmd "$url" "$tmpfile"; then
		command rm -f "$tmpfile"
		return 1
	fi

	if ! _geoip_validate_cidr_file "$tmpfile" "$family"; then
		command rm -f "$tmpfile"
		return 1
	fi

	command mv -f "$tmpfile" "$output" || { command rm -f "$tmpfile"; return 1; }
	return 0
}

# ---------------------------------------------------------------------------
# geoip_download — download CIDR data for a country code.
# Cascade: ipverse.net first, then ipdeny.com on failure.
# Args: CC FAMILY OUTPUT [SOURCE]
#   CC: 2-letter country code (uppercase accepted, lowercased internally)
#   FAMILY: "4" or "6"
#   OUTPUT: destination file path
#   SOURCE: "ipverse", "ipdeny", or "auto" (default: "auto")
# Returns: 0 on success, 1 on all sources failing
# ---------------------------------------------------------------------------
geoip_download() {
	local cc="$1" family="$2" output="$3" source="${4:-auto}"
	local lc_cc

	# Validate arguments
	[[ -n "$cc" ]] || { echo "geoip_download: CC required" >&2; return 1; }
	local _cc_re='^[A-Za-z]{2}$'
	[[ "$cc" =~ $_cc_re ]] || { echo "geoip_download: invalid CC format: $cc" >&2; return 1; }
	[[ -n "$family" ]] || { echo "geoip_download: FAMILY required" >&2; return 1; }
	[[ -n "$output" ]] || { echo "geoip_download: OUTPUT required" >&2; return 1; }
	[[ "$family" == "4" || "$family" == "6" ]] || { echo "geoip_download: FAMILY must be 4 or 6" >&2; return 1; }

	# Lowercase CC for URL construction (ipverse/ipdeny use lowercase)
	lc_cc=$(echo "$cc" | tr '[:upper:]' '[:lower:]')

	case "$source" in
		ipverse)
			_geoip_download_ipverse "$lc_cc" "$family" "$output"
			return $?
			;;
		ipdeny)
			_geoip_download_ipdeny "$lc_cc" "$family" "$output"
			return $?
			;;
		auto)
			# Cascade: ipverse first, ipdeny fallback
			if _geoip_download_ipverse "$lc_cc" "$family" "$output"; then
				return 0
			fi
			_geoip_download_ipdeny "$lc_cc" "$family" "$output"
			return $?
			;;
		*)
			echo "geoip_download: unknown source '$source' (use: auto, ipverse, ipdeny)" >&2
			return 1
			;;
	esac
}

# ---------------------------------------------------------------------------
# geoip_is_stale — check if CIDR data in a directory is stale.
# Reads .last_update file (epoch timestamp) and compares to current time.
# Args: DATA_DIR [MAX_AGE_DAYS]
#   DATA_DIR: directory containing .last_update file
#   MAX_AGE_DAYS: age threshold in days (default: 30)
# Returns: 0 if stale or missing, 1 if fresh
# ---------------------------------------------------------------------------
geoip_is_stale() {
	local data_dir="$1" max_age_days="${2:-30}"
	local stamp_file="$data_dir/.last_update"
	local now stamp age max_age_secs

	[[ -f "$stamp_file" ]] || return 0

	read -r stamp < "$stamp_file" || return 0
	# Validate stamp is a numeric epoch
	local _epoch_pat='^[0-9]+$'
	[[ "$stamp" =~ $_epoch_pat ]] || return 0

	now=$(date +%s)
	age=$(( now - stamp ))
	max_age_secs=$(( max_age_days * 86400 ))

	[[ "$age" -gt "$max_age_secs" ]]
}

# ---------------------------------------------------------------------------
# geoip_mark_updated — write current epoch to .last_update in data directory.
# Args: DATA_DIR
# Returns: 0 on success, 1 on failure
# ---------------------------------------------------------------------------
geoip_mark_updated() {
	local data_dir="$1"
	local _stamp_file

	[[ -n "$data_dir" ]] || return 1
	[[ -d "$data_dir" ]] || return 1

	_stamp_file="$data_dir/.last_update"
	# Remove symlink if present — prevent following attacker-controlled target
	[[ ! -L "$_stamp_file" ]] || command rm -f "$_stamp_file"
	date +%s > "$_stamp_file"
}

# ---------------------------------------------------------------------------
# geoip_cidr_search — search an IPv4 address across CIDR data files.
# Portable AWK CIDR containment — no grepcidr required.
# Extracted from APF geoip.apf:_geoip_cidr4_search().
# Args: IP FILE [FILE ...]
# Prints: matching file path on stdout
# Returns: 0 on match, 1 on no match
# ---------------------------------------------------------------------------
geoip_cidr_search() {
	local qip="$1"
	shift

	[[ -n "$qip" ]] || return 1
	[[ $# -gt 0 ]] || return 1
	# IPv6 not supported — caller should use geoip_ip6_lookup
	[[ "$qip" != *:* ]] || return 1
	# Validate IPv4 dotted-quad format (including octet range)
	_geoip_valid_ipv4 "$qip" || return 1
	[[ -n "$GEOIP_AWK_BIN" ]] || { echo "geoip_cidr_search: awk not available" >&2; return 1; }

	"$GEOIP_AWK_BIN" -v qip="$qip" '
	BEGIN {
		split(qip, a, ".")
		qint = (a[1]*16777216) + (a[2]*65536) + (a[3]*256) + a[4]
		found = ""
	}
	/^[0-9]/ {
		n = split($0, p, "[./]")
		net = (p[1]*16777216) + (p[2]*65536) + (p[3]*256) + p[4]
		bits = (n >= 5) ? int(p[5]+0) : 32
		s = 2^(32-bits)
		if (int(qint/s) == int(net/s)) { found = FILENAME; exit }
	}
	END { if (found != "") print found; exit(found == "") }
	' "$@"
}

# ===========================================================================
# IP Database Layer — consolidated integer-range database build and lookup
# ===========================================================================

# ---------------------------------------------------------------------------
# _GEOIP_V6_AWK — shared AWK functions for IPv6 hex normalization.
# Set once at source time; embedded in AWK programs via string concatenation.
# v6hex(addr): normalizes any IPv6 address to 32-char lowercase hex string.
# Rejects dotted-quad (::ffff:a.b.c.d) — returns empty string.
# mawk-compatible: no gensub, no strftime; uses index()+integer math.
# ---------------------------------------------------------------------------
# shellcheck disable=SC2034
_GEOIP_V6_AWK='
function _v6_hexval(c,    p) {
	p = index("0123456789abcdef", c)
	if (p > 0) return p - 1
	return 0
}
function _v6_hexchar(n) {
	return substr("0123456789abcdef", n + 1, 1)
}
function v6hex(addr,    n, halves, lp, rp, nl, nr, full, zf, i, j, g, c, hex) {
	if (index(addr, ".") > 0) return ""
	addr = tolower(addr)
	if (index(addr, "::") > 0) {
		n = split(addr, halves, "::")
		if (n != 2) return ""
		nl = split(halves[1], lp, ":")
		if (halves[1] == "") nl = 0
		nr = split(halves[2], rp, ":")
		if (halves[2] == "") nr = 0
		if (nl + nr > 7) return ""
		for (i = 1; i <= nl; i++) full[i] = lp[i]
		zf = 8 - nl - nr
		for (i = 1; i <= zf; i++) full[nl + i] = "0"
		for (i = 1; i <= nr; i++) full[nl + zf + i] = rp[i]
	} else {
		if (split(addr, full, ":") != 8) return ""
	}
	hex = ""
	for (i = 1; i <= 8; i++) {
		g = full[i]
		while (length(g) < 4) g = "0" g
		if (length(g) > 4) return ""
		for (j = 1; j <= 4; j++) {
			c = substr(g, j, 1)
			if (index("0123456789abcdef", c) == 0) return ""
		}
		hex = hex g
	}
	if (length(hex) != 32) return ""
	return hex
}
'

# ---------------------------------------------------------------------------
# _geoip_cidr4_to_ranges — convert IPv4 CIDR file to integer-range format.
# Input: CIDR_FILE CC
#   CIDR_FILE: file with one IPv4 CIDR per line (comments/blanks skipped)
#   CC: 2-letter country code tag for each range
# Output: "START_INT END_INT CC" lines to stdout (unsorted).
# mawk-compatible: no gensub, no strftime. 2^(32-n) safe in mawk.
# ---------------------------------------------------------------------------
_geoip_cidr4_to_ranges() {
	local cidr_file="$1" cc="$2"

	[[ -n "$GEOIP_AWK_BIN" ]] || { echo "_geoip_cidr4_to_ranges: awk not available" >&2; return 1; }
	[[ -f "$cidr_file" ]] || return 1

	"$GEOIP_AWK_BIN" -v cc="$cc" '
/^[0-9]/ {
	n = split($0, p, "[./]")
	if (n < 5) next
	net = (p[1]+0) * 16777216 + (p[2]+0) * 65536 + (p[3]+0) * 256 + (p[4]+0)
	bits = int(p[5]+0)
	if (bits < 0 || bits > 32) next
	size = 2 ^ (32 - bits)
	end = net + size - 1
	printf "%d %d %s\n", net, end, cc
}' "$cidr_file"
}

# ---------------------------------------------------------------------------
# _geoip_cidr6_to_ranges — convert IPv6 CIDR file to hex-range format.
# Input: CIDR_FILE CC
#   CIDR_FILE: file with one IPv6 CIDR per line (comments/blanks skipped)
#   CC: 2-letter country code tag for each range
# Output: "START_HEX END_HEX CC" lines to stdout (unsorted).
# START_HEX/END_HEX: 32-char lowercase hex strings (lexicographic = numeric).
# Skips lines containing dots (mapped IPv4 CIDRs).
# mawk-compatible: no gensub, no strftime. Uses _GEOIP_V6_AWK functions.
# ---------------------------------------------------------------------------
_geoip_cidr6_to_ranges() {
	local cidr_file="$1" cc="$2"

	[[ -n "$GEOIP_AWK_BIN" ]] || { echo "_geoip_cidr6_to_ranges: awk not available" >&2; return 1; }
	[[ -f "$cidr_file" ]] || return 1

	"$GEOIP_AWK_BIN" -v cc="$cc" "${_GEOIP_V6_AWK}"'
/^[0-9a-fA-F:]/ {
	if (index($0, ".") > 0) next
	n = split($0, parts, "/")
	if (n < 2) next
	prefix_len = int(parts[2] + 0)
	if (prefix_len < 0 || prefix_len > 128) next
	hex = v6hex(parts[1])
	if (hex == "") next

	pos = int(prefix_len / 4)
	rem = prefix_len % 4

	if (pos > 0) {
		start = substr(hex, 1, pos)
		end_hex = substr(hex, 1, pos)
	} else {
		start = ""
		end_hex = ""
	}

	if (rem > 0) {
		boundary = substr(hex, pos + 1, 1)
		nval = _v6_hexval(boundary)
		mask_hi = 1
		for (j = 1; j <= 4 - rem; j++) mask_hi = mask_hi * 2
		start_nib = int(nval / mask_hi) * mask_hi
		end_nib = start_nib + mask_hi - 1
		start = start _v6_hexchar(start_nib)
		end_hex = end_hex _v6_hexchar(end_nib)
		pos = pos + 1
	}

	while (length(start) < 32) start = start "0"
	while (length(end_hex) < 32) end_hex = end_hex "f"

	printf "%s %s %s\n", start, end_hex, cc
}' "$cidr_file"
}

# ---------------------------------------------------------------------------
# geoip_ip_lookup — look up IPv4 address in integer-range database.
# Searches a "START_INT END_INT CC" database file for containment.
# Args: IP DB_FILE
#   IP: IPv4 dotted-quad address
#   DB_FILE: integer-range database (output of geoip_build_ipdb)
# Prints: 2-letter country code on match (to stdout)
# Returns: 0 on match, 1 on no match or invalid input
# No caching — consumers implement their own caching strategy.
# Complexity: O(N) linear scan; high-frequency callers should cache results.
# ---------------------------------------------------------------------------
geoip_ip_lookup() {
	local ip="$1" db_file="$2"

	[[ -n "$ip" ]] || return 1
	[[ -n "$db_file" ]] || return 1
	# IPv6 not supported
	[[ "$ip" != *:* ]] || return 1
	# Validate IPv4 dotted-quad format (including octet range)
	_geoip_valid_ipv4 "$ip" || return 1
	[[ -f "$db_file" ]] || return 1
	[[ -s "$db_file" ]] || return 1
	[[ -n "$GEOIP_AWK_BIN" ]] || { echo "geoip_ip_lookup: awk not available" >&2; return 1; }

	local cc
	cc=$("$GEOIP_AWK_BIN" -v ip="$ip" '
	BEGIN {
		n = split(ip, p, ".")
		if (n != 4) exit
		target = (p[1]+0) * 16777216 + (p[2]+0) * 65536 + (p[3]+0) * 256 + (p[4]+0)
	}
	/^#/ { next }
	{
		if ($1+0 <= target && target <= $2+0) {
			print $3
			exit
		}
	}' "$db_file")

	if [[ -n "$cc" ]]; then
		echo "$cc"
		return 0
	fi
	return 1
}

# ---------------------------------------------------------------------------
# geoip_ip6_lookup — look up IPv6 address in hex-range database.
# Searches a "START_HEX END_HEX CC" database file for containment.
# START_HEX/END_HEX: 32-char lowercase hex (output of geoip_build_ip6db).
# Normalizes input via v6hex(), then lexicographic comparison on equal-length
# hex strings (equivalent to numeric comparison, no 128-bit arithmetic).
# Args: IP DB6_FILE
#   IP: IPv6 address (any valid abbreviation)
#   DB6_FILE: hex-range database file
# Prints: 2-letter country code on match (to stdout)
# Returns: 0 on match, 1 on no match or invalid input
# Rejects IPv4 (no colon in input) and dotted-quad (::ffff:a.b.c.d).
# No caching — consumers implement their own caching strategy.
# Complexity: O(N) linear scan; high-frequency callers should cache results.
# ---------------------------------------------------------------------------
geoip_ip6_lookup() {
	local ip="$1" db_file="$2"

	[[ -n "$ip" ]] || return 1
	# Must be IPv6 (contains colon)
	[[ "$ip" == *:* ]] || return 1
	# Reject dotted-quad mapped addresses — caller should use IPv4 lookup
	[[ "$ip" != *"."* ]] || return 1
	[[ -n "$db_file" ]] || return 1
	[[ -f "$db_file" && -s "$db_file" ]] || return 1
	[[ -n "$GEOIP_AWK_BIN" ]] || { echo "geoip_ip6_lookup: awk not available" >&2; return 1; }

	local cc
	cc=$("$GEOIP_AWK_BIN" -v ip="$ip" "${_GEOIP_V6_AWK}"'
	BEGIN {
		target = v6hex(ip)
		if (target == "") exit
	}
	/^#/ { next }
	{
		if ($1 <= target && target <= $2) {
			print $3
			exit
		}
	}' "$db_file")

	if [[ -n "$cc" ]]; then
		echo "$cc"
		return 0
	fi
	return 1
}

# ---------------------------------------------------------------------------
# _geoip_download_ipdeny_bulk — download ipdeny.com all-zones tarball.
# Extracts per-country IPv4 zone files to OUTPUT_DIR/{CC}.zone.
# Validates filenames and CIDR content before writing.
# Args: OUTPUT_DIR
# Returns: 0 on success (at least one valid zone file), 1 on failure
# IPv4 only — no bulk IPv6 tarball available from ipdeny.
# ---------------------------------------------------------------------------
_geoip_download_ipdeny_bulk() {
	local output_dir="$1"
	local url="https://www.ipdeny.com/ipblocks/data/countries/all-zones.tar.gz"
	local tmp_tar tmp_dir count=0

	[[ -n "$output_dir" ]] || return 1
	mkdir -p "$output_dir" 2>/dev/null || return 1  # permission errors caught by || return

	tmp_tar=$(mktemp "${output_dir}/.bulk-XXXXXX") || return 1
	tmp_dir=$(mktemp -d "${output_dir}/.bulk-extract-XXXXXX") || { command rm -f "$tmp_tar"; return 1; }

	if ! _geoip_download_cmd "$url" "$tmp_tar"; then
		command rm -f "$tmp_tar"
		command rm -rf "$tmp_dir"
		return 1
	fi

	if ! tar -xzf "$tmp_tar" -C "$tmp_dir" 2>/dev/null; then  # tar errors handled by control flow
		command rm -f "$tmp_tar"
		command rm -rf "$tmp_dir"
		return 1
	fi
	command rm -f "$tmp_tar"

	local _cc_lre='^[a-z]{2}$'
	local f cc_lower cc_upper
	for f in "$tmp_dir"/*.zone; do
		[ -f "$f" ] || continue
		cc_lower="${f##*/}"; cc_lower="${cc_lower%.zone}"
		[[ "$cc_lower" =~ $_cc_lre ]] || continue
		# Skip zz.zone — ipdeny's unassigned/reserved catch-all (/8 blocks
		# that overlap real country allocations and poison lookup results)
		[[ "$cc_lower" != "zz" ]] || continue
		if ! _geoip_validate_cidr_file "$f" "4"; then
			continue
		fi
		cc_upper=$(echo "$cc_lower" | tr '[:lower:]' '[:upper:]')
		command cp "$f" "$output_dir/${cc_upper}.zone"
		count=$((count + 1))
	done

	command rm -rf "$tmp_dir"
	[[ "$count" -gt 0 ]]
}

# ---------------------------------------------------------------------------
# geoip_build_ipdb — build consolidated IPv4 integer-range database.
# Downloads CIDR data for all countries, converts to integer ranges,
# sorts by start address, and writes to OUTPUT.
# Uses ipdeny bulk tarball when available; falls back to per-country
# cascade (ipverse → ipdeny) for any missing countries.
# Locking: callers must hold their own lock if concurrent builds are possible.
# The library does not implement internal locking — consumers (BFD, APF) use
# their existing lock infrastructure (flock on their own lock files).
# Args: OUTPUT [MIN_RANGES]
#   OUTPUT: destination file path for the integer-range database
#   MIN_RANGES: minimum expected range count (default: 1000; abort if below)
# Returns: 0 on success, 1 on failure
# Sets: _GEOIP_BUILD_COUNT  — countries successfully processed
#       _GEOIP_BUILD_FAIL   — countries that failed download
#       _GEOIP_BUILD_RANGES — total ranges in output
# ---------------------------------------------------------------------------
geoip_build_ipdb() {
	local output="$1" min_ranges="${2:-1000}"
	local tmpdir count=0 fail_count=0

	_GEOIP_BUILD_COUNT=0
	_GEOIP_BUILD_FAIL=0
	_GEOIP_BUILD_RANGES=0

	[[ -n "$output" ]] || { echo "geoip_build_ipdb: OUTPUT required" >&2; return 1; }

	tmpdir=$(mktemp -d "${output}.build-XXXXXX") || return 1
	local zones_dir="$tmpdir/zones"
	mkdir -p "$zones_dir"

	# Strategy 1: bulk tarball (~1MB, one download for all countries)
	local bulk_ok=0
	if _geoip_download_ipdeny_bulk "$zones_dir"; then
		bulk_ok=1
	fi

	# Strategy 2: per-country cascade for any CCs not covered by bulk
	local cc cidr_file
	while IFS= read -r cc; do
		# Skip if bulk already provided this CC
		if [[ "$bulk_ok" -eq 1 ]] && [[ -f "$zones_dir/${cc}.zone" ]]; then
			count=$((count + 1))
			continue
		fi
		cidr_file="$zones_dir/${cc}.zone"
		if geoip_download "$cc" "4" "$cidr_file"; then
			count=$((count + 1))
		else
			fail_count=$((fail_count + 1))
		fi
	done < <(geoip_all_cc)

	# Convert all zone files to integer ranges
	local merged="$tmpdir/merged.dat"
	: > "$merged"
	local cc_base
	for cidr_file in "$zones_dir"/*.zone; do
		[ -f "$cidr_file" ] || continue
		cc_base="${cidr_file##*/}"; cc_base="${cc_base%.zone}"
		_geoip_cidr4_to_ranges "$cidr_file" "$cc_base" >> "$merged"
	done

	# Sort by start integer
	sort -n -k1 "$merged" > "$tmpdir/sorted.dat"

	local lines
	lines=$(wc -l < "$tmpdir/sorted.dat")
	if [[ "$lines" -lt "$min_ranges" ]]; then
		echo "geoip_build_ipdb: only $lines ranges (minimum: $min_ranges)" >&2
		command rm -rf "$tmpdir"
		return 1
	fi

	if ! command mv -f "$tmpdir/sorted.dat" "$output"; then
		command rm -rf "$tmpdir"
		return 1
	fi
	command rm -rf "$tmpdir"

	_GEOIP_BUILD_COUNT="$count"
	_GEOIP_BUILD_FAIL="$fail_count"
	_GEOIP_BUILD_RANGES="$lines"
	return 0
}

# ---------------------------------------------------------------------------
# geoip_build_ip6db — build consolidated IPv6 hex-range database.
# Downloads IPv6 CIDR data for all countries via per-country cascade
# (no bulk IPv6 tarball available), converts to hex ranges, sorts
# lexicographically, and writes to OUTPUT.
# Expected: ~240 serial HTTP downloads, ~30K-60K ranges, ~2-4MB output.
# Build time: ~2-5 minutes typical (120s timeout per download worst-case).
# Locking: callers must hold their own lock if concurrent builds are possible.
# Args: OUTPUT [MIN_RANGES]
#   OUTPUT: destination file path for the hex-range database
#   MIN_RANGES: minimum expected range count (default: 500; abort if below)
# Returns: 0 on success, 1 on failure
# Sets: _GEOIP_BUILD6_COUNT  — countries successfully processed
#       _GEOIP_BUILD6_FAIL   — countries that failed download
#       _GEOIP_BUILD6_RANGES — total ranges in output
# ---------------------------------------------------------------------------
geoip_build_ip6db() {
	local output="$1" min_ranges="${2:-500}"
	local tmpdir count=0 fail_count=0

	_GEOIP_BUILD6_COUNT=0
	_GEOIP_BUILD6_FAIL=0
	_GEOIP_BUILD6_RANGES=0

	[[ -n "$output" ]] || { echo "geoip_build_ip6db: OUTPUT required" >&2; return 1; }

	tmpdir=$(mktemp -d "${output}.build6-XXXXXX") || return 1
	local zones_dir="$tmpdir/zones"
	mkdir -p "$zones_dir"

	# Per-country cascade (no bulk IPv6 tarball available)
	local cc cidr_file
	while IFS= read -r cc; do
		cidr_file="$zones_dir/${cc}.zone6"
		if geoip_download "$cc" "6" "$cidr_file"; then
			count=$((count + 1))
		else
			fail_count=$((fail_count + 1))
		fi
	done < <(geoip_all_cc)

	# Convert all zone files to hex ranges
	local merged="$tmpdir/merged.dat"
	: > "$merged"
	local cc_base
	for cidr_file in "$zones_dir"/*.zone6; do
		[ -f "$cidr_file" ] || continue
		cc_base="${cidr_file##*/}"; cc_base="${cc_base%.zone6}"
		_geoip_cidr6_to_ranges "$cidr_file" "$cc_base" >> "$merged"
	done

	# Sort lexicographically by start hex (LC_ALL=C for locale-safe ordering)
	LC_ALL=C sort -k1,1 "$merged" > "$tmpdir/sorted.dat"

	local lines
	lines=$(wc -l < "$tmpdir/sorted.dat")
	if [[ "$lines" -lt "$min_ranges" ]]; then
		echo "geoip_build_ip6db: only $lines ranges (minimum: $min_ranges)" >&2
		command rm -rf "$tmpdir"
		return 1
	fi

	if ! command mv -f "$tmpdir/sorted.dat" "$output"; then
		command rm -rf "$tmpdir"
		return 1
	fi
	command rm -rf "$tmpdir"

	_GEOIP_BUILD6_COUNT="$count"
	_GEOIP_BUILD6_FAIL="$fail_count"
	_GEOIP_BUILD6_RANGES="$lines"
	return 0
}
