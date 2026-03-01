#!/bin/bash
#
# Shared capability detection helpers for test files.
# Source this file to get skip-guard functions for optional features.

# Check if GRE tunnel support is available in this container
gre_available() {
    command -v ip >/dev/null 2>&1 || return 1
    ip tunnel add gretest mode gre remote 192.0.2.1 local 127.0.0.1 ttl 255 2>/dev/null || return 1
    ip tunnel del gretest 2>/dev/null
    return 0
}

# Check if ipset is available and functional
ipset_available() {
    command -v ipset >/dev/null 2>&1 || return 1
    ipset create _apf_probe hash:ip 2>/dev/null || return 1
    ipset destroy _apf_probe 2>/dev/null
    return 0
}

# Clean test IPs from trust files and flush trust chains.
# Usage: clean_trust_entries IP1 IP2 ...
clean_trust_entries() {
    local apf_dir="${APF_DIR:-/opt/apf}"
    local host escaped
    for host in "$@"; do
        escaped=$(echo "$host" | sed 's/[.\/\:]/\\&/g')
        sed -i "/${escaped}/d" "$apf_dir/allow_hosts.rules" 2>/dev/null || true
        sed -i "/${escaped}/d" "$apf_dir/deny_hosts.rules" 2>/dev/null || true
    done
    iptables -F TALLOW 2>/dev/null || true
    iptables -F TDENY 2>/dev/null || true
    if ip6tables_available; then
        ip6tables -F TALLOW 2>/dev/null || true
        ip6tables -F TDENY 2>/dev/null || true
    fi
}
