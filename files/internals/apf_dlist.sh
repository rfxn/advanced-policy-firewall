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
# APF remote deny lists and download management

# Source guard
[[ -n "${_APF_DLIST_LOADED:-}" ]] && return 0 2>/dev/null
_APF_DLIST_LOADED=1

# shellcheck disable=SC2034
APF_DLIST_VERSION="1.0.0"

# download_url URL OUTPUT_FILE
# Tries curl first (better TLS 1.2 on CentOS 6), falls back to wget.
# Returns 0 on success, 1 on failure.
download_url() {
    local url="$1" output="$2"
    if [ -n "$CURL" ]; then
        $CURL -sSL --connect-timeout 10 --max-time 60 --retry 3 \
            -o "$output" "$url" >> /dev/null 2>&1 && return 0
    fi
    if [ -n "$WGET" ]; then
        $WGET -q -t 3 -T 10 -O "$output" "$url" >> /dev/null 2>&1 && return 0
    fi
    eout "{glob} download failed for $url (check TLS support on legacy systems)"
    return 1
}

dlist_resnet() {
 if [ -f "$RESNET" ]; then
        command cp "$RESNET" "$RESNET.bk"
        chmod 600 "$RESNET" "$RESNET.bk"
 fi
if ( [ -n "$CURL" ] || [ -n "$WGET" ] ) && [ -f "$RESNET" ]; then
   local url_tmp
   url_tmp=$(mktemp "$INSTALL_PATH/.apf-XXXXXX")
   _apf_reg_tmp "$url_tmp"
   eout "{resnet} downloading $DLIST_RESERVED_URL"
   if download_url "$DLIST_RESERVED_URL" "$url_tmp"; then
        eout "{resnet} parsing download into $RESNET"
        cat "$url_tmp" > "$RESNET"
   else
        eout "{resnet} download of $DLIST_RESERVED_URL failed"
	 if [ -f "$RESNET.bk" ]; then
	     command cp "$RESNET.bk" "$RESNET"
	     chmod 600 "$RESNET" "$RESNET.bk"
	 fi
   fi
   command rm -f "$url_tmp"
else
 if [ -f "$RESNET.bk" ]; then
	command cp "$RESNET.bk" "$RESNET"
	chmod 600 "$RESNET" "$RESNET.bk"
 fi
fi
}

dlist_download() {
local tag="$1" url="$2" hosts_file="$3" parse_mode="${4:-standard}"
# Backup existing file
if [ -f "$hosts_file" ]; then
   command cp "$hosts_file" "$hosts_file.bk"
   chmod 600 "$hosts_file" "$hosts_file.bk"
fi
local url_tmp
url_tmp=$(mktemp "$INSTALL_PATH/.apf-XXXXXX")
_apf_reg_tmp "$url_tmp"
eout "{$tag} downloading $url"
if download_url "$url" "$url_tmp"; then
        eout "{$tag} parsing download into $hosts_file"
        :> "$hosts_file"
        while IFS= read -r str; do
                case "$str" in \#*|"") continue ;; esac
                read -r str _ <<< "$str"
                if [ "$parse_mode" == "spamhaus" ]; then
                        [[ "$str" != */* ]] && continue
                        str="${str//;/}"
                else
                        [[ "$str" != *[0-9]* ]] && continue
                fi
                if [ -n "$str" ] && valid_ip_cidr "$str"; then
                        echo "$str" >> "$hosts_file"
                fi
        done < "$url_tmp"
else
        # Error policy: dlist restores from backup to preserve data
        eout "{$tag} download of $url failed"
        elog_event "error_occurred" "error" "{$tag} download of $url failed" \
            "url=$url"
        if [ -f "$hosts_file.bk" ]; then
            command cp "$hosts_file.bk" "$hosts_file"
            chmod 600 "$hosts_file" "$hosts_file.bk"
        fi
fi
command rm -f "$url_tmp"
}

dlist_php() {
if [ -n "$DLIST_PHP_URL" ] && [ "$DLIST_PHP" == "1" ] && ( [ -n "$CURL" ] || [ -n "$WGET" ] ); then
   dlist_download "php" "$DLIST_PHP_URL" "$PHP_HOSTS"
else
   command rm -f "$PHP_HOSTS"; touch "$PHP_HOSTS"; chmod 600 "$PHP_HOSTS"
fi
}

## Shared dlist chain loading helper.
# Usage: dlist_load_hosts chain_name hosts_file tag log_prefix
# Creates iptables chain, loads validated entries with LOG+DROP, attaches
# to INPUT and OUTPUT chains.
dlist_load_hosts() {
local _dlh_chain="$1" _dlh_file="$2" _dlh_tag="$3" _dlh_prefix="$4"
if [ -n "$(grep -v "#" "$_dlh_file")" ]; then
	eout "{$_dlh_tag} loading ${_dlh_file##*/}"
	ipt -N "$_dlh_chain"
	while IFS= read -r i; do
		[[ "$i" == \#* || -z "$i" ]] && continue
		if [ -f "$_dlh_file" ]; then
			if ! valid_ip_cidr "$i"; then
				eout "{$_dlh_tag} skipping invalid entry: $i"
				continue
			fi
			if ipt_for_host "$i"; then
				if [ "$LOG_DROP" == "1" ]; then
					$IPT_H $IPT_FLAGS -A "$_dlh_chain" -s "$i" -d "$ANY_ADDR" -m limit --limit=$LOG_RATE/minute -j $LOG_TARGET --log-level=$LOG_LEVEL $LEXT --log-prefix="** $_dlh_prefix ** "
				fi
				$IPT_H $IPT_FLAGS -A "$_dlh_chain" -s "$i" -d "$ANY_ADDR" -j $ALL_STOP
			fi
		fi
	done < "$_dlh_file"
	ipt -A INPUT -j "$_dlh_chain"
	ipt -A OUTPUT -j "$_dlh_chain"
fi
}

dlist_php_hosts()      { dlist_load_hosts "PHP"     "$PHP_HOSTS"  "php"     "PHP"; }

dlist_dshield() {
if [ -n "$DLIST_DSHIELD_URL" ] && [ "$DLIST_DSHIELD" == "1" ] && ( [ -n "$CURL" ] || [ -n "$WGET" ] ); then
   dlist_download "dshield" "$DLIST_DSHIELD_URL" "$DS_HOSTS"
else
   command rm -f "$DS_HOSTS"; touch "$DS_HOSTS"; chmod 600 "$DS_HOSTS"
fi
}

dlist_dshield_hosts()  { dlist_load_hosts "DSHIELD" "$DS_HOSTS"   "dshield" "DSHIELD"; }

dlist_spamhaus() {
if [ -n "$DLIST_SPAMHAUS_URL" ] && [ "$DLIST_SPAMHAUS" == "1" ] && ( [ -n "$CURL" ] || [ -n "$WGET" ] ); then
   dlist_download "sdrop" "$DLIST_SPAMHAUS_URL" "$DROP_HOSTS" "spamhaus"
else
   command rm -f "$DROP_HOSTS"; touch "$DROP_HOSTS"; chmod 600 "$DROP_HOSTS"
fi
}

dlist_spamhaus_hosts() { dlist_load_hosts "SDROP"   "$DROP_HOSTS" "sdrop"   "SDROP"; }

dlist_ecnshame() {
if [ -n "$DLIST_ECNSHAME_URL" ] && [ "$DLIST_ECNSHAME" == "1" ] && ( [ -n "$CURL" ] || [ -n "$WGET" ] ); then
   dlist_download "ecnshame" "$DLIST_ECNSHAME_URL" "$ECNSHAME_HOSTS"
else
   command rm -f "$ECNSHAME_HOSTS"; touch "$ECNSHAME_HOSTS"; chmod 600 "$ECNSHAME_HOSTS"
fi
}

dlist_ecnshame_hosts() {
if [ -n "$(grep -v "#" "$ECNSHAME_HOSTS")" ]; then
        eout "{ecnshame} loading ecnshame_hosts.rules"
        while IFS= read -r i; do
                [[ "$i" == \#* || -z "$i" ]] && continue
                if [ -f "$ECNSHAME_HOSTS" ]; then
			if ! valid_ip_cidr "$i"; then
				eout "{ecnshame} skipping invalid entry: $i"
				continue
			fi
			if ipt_for_host "$i"; then
				$IPT_H $IPT_FLAGS -t mangle -A POSTROUTING -p tcp -d "$i" -j ECN --ecn-tcp-remove
			fi
                fi
        done < "$ECNSHAME_HOSTS"
fi
}

## Shared helper for glob trust file downloads.
# Usage: glob_trust_download url hosts_file
# Downloads URL, parses entries through valid_host(), writes to hosts_file.
# If URL or prerequisites missing, resets hosts_file to empty.
glob_trust_download() {
local _gtd_url="$1" _gtd_hosts="$2"
if [ -n "$_gtd_url" ] && [ "$USE_RGT" == "1" ] && ( [ -n "$CURL" ] || [ -n "$WGET" ] ); then
   local url_tmp
   url_tmp=$(mktemp "$INSTALL_PATH/.apf-XXXXXX")
   _apf_reg_tmp "$url_tmp"
   eout "{trust} downloading $_gtd_url"
   if download_url "$_gtd_url" "$url_tmp"; then
        eout "{trust} parsing download into $_gtd_hosts"
        local _entry
        :> "$_gtd_hosts"
        while IFS= read -r _entry; do
            case "$_entry" in \#*|"") continue ;; esac
            read -r _entry _ <<< "$_entry"
            if [ -n "$_entry" ] && valid_host "$_entry"; then
                echo "$_entry" >> "$_gtd_hosts"
            fi
        done < "$url_tmp"
   else
        eout "{trust} download of $_gtd_url failed"
        elog_event "error_occurred" "error" "{trust} download of $_gtd_url failed" \
            "url=$_gtd_url"
   fi
   command rm -f "$url_tmp"
else
   command rm -f "$_gtd_hosts"
   touch "$_gtd_hosts"
   chmod 600 "$_gtd_hosts"
fi
}

glob_allow_download() { glob_trust_download "$GA_URL" "$GALLOW_HOSTS"; }
glob_deny_download() { glob_trust_download "$GD_URL" "$GDENY_HOSTS"; }
