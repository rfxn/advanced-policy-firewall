#!/usr/bin/env bats
#
# 31: FQDN Pre-Resolution in Trust System
#
# Validates that FQDNs are resolved to IPs before passing to iptables.
# Uses /etc/hosts entries for deterministic, offline DNS resolution.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-iptables.bash

APF="/opt/apf/apf"
APF_DIR="/opt/apf"

# Track hidden binaries for cleanup
HIDDEN_BINS=""

# Test FQDN hostnames → mapped in /etc/hosts during setup_file
FQDN_SINGLE="test-fqdn-single.example"
FQDN_MULTI="test-fqdn-multi.example"
FQDN_V6="test-fqdn-v6.example"
FQDN_LOCAL="test-fqdn-local.example"
FQDN_NOEXIST="test-fqdn-noexist.invalid"

# Resolved IPs (RFC 5737 test ranges)
IP_SINGLE="192.0.2.80"
IP_MULTI_1="192.0.2.81"
IP_MULTI_2="198.51.100.80"
IP_V6="2001:db8::80"

setup_file() {
    source /opt/tests/helpers/setup-netns.sh
    source /opt/tests/helpers/reset-apf.sh
    source /opt/tests/helpers/apf-config.sh
    apf_set_interface "veth-pub" ""
    if ip6tables_available; then
        apf_set_config "USE_IPV6" "1"
    fi

    # Add test FQDN entries to /etc/hosts for deterministic resolution
    echo "$IP_SINGLE    $FQDN_SINGLE" >> /etc/hosts
    echo "$IP_MULTI_1   $FQDN_MULTI" >> /etc/hosts
    echo "$IP_MULTI_2   $FQDN_MULTI" >> /etc/hosts
    echo "$IP_V6        $FQDN_V6" >> /etc/hosts

    # Map a hostname to the server's own IP for local-addr test
    local server_ip
    server_ip=$(ip addr show veth-pub 2>/dev/null | grep -w inet | head -1 | awk '{print $2}' | cut -d/ -f1)
    if [ -n "$server_ip" ]; then
        echo "$server_ip    $FQDN_LOCAL" >> /etc/hosts
    fi

    "$APF" -f 2>/dev/null || true
    "$APF" -s
}

teardown_file() {
    "$APF" -f 2>/dev/null || true
    source /opt/tests/helpers/teardown-netns.sh
    # Remove test /etc/hosts entries (Docker-safe: sed -i fails on bind mounts)
    grep -v "test-fqdn-" /etc/hosts > /tmp/hosts_cleanup.tmp && \
        cat /tmp/hosts_cleanup.tmp > /etc/hosts && rm -f /tmp/hosts_cleanup.tmp
}

setup() {
    # Clean up test entries from trust files and iptables chains
    for host in "$FQDN_SINGLE" "$FQDN_MULTI" "$FQDN_V6" "$FQDN_LOCAL" \
                "$IP_SINGLE" "$IP_MULTI_1" "$IP_MULTI_2" "$IP_V6"; do
        local escaped
        escaped=$(echo "$host" | sed 's/[.\/\:]/\\&/g')
        sed -i "/${escaped}/d" "$APF_DIR/allow_hosts.rules" 2>/dev/null || true
        sed -i "/${escaped}/d" "$APF_DIR/deny_hosts.rules" 2>/dev/null || true
    done
    iptables -F TALLOW 2>/dev/null || true
    iptables -F TDENY 2>/dev/null || true
    if ip6tables_available; then
        ip6tables -F TALLOW 2>/dev/null || true
        ip6tables -F TDENY 2>/dev/null || true
    fi
}

hide_bin() {
    local name="$1"
    local bin_path
    local search_path="/sbin:/usr/sbin:/usr/bin:/bin:/usr/local/sbin:/usr/local/bin:$PATH"
    while bin_path=$(PATH="$search_path" command -v "$name" 2>/dev/null) && [ -n "$bin_path" ]; do
        if [ -f "$bin_path" ] && [ ! -f "${bin_path}.__hidden" ]; then
            mv "$bin_path" "${bin_path}.__hidden"
            HIDDEN_BINS="$HIDDEN_BINS $bin_path"
        else
            break
        fi
    done
}

restore_bins() {
    for bin_path in $HIDDEN_BINS; do
        if [ -f "${bin_path}.__hidden" ] || [ -L "${bin_path}.__hidden" ]; then
            mv "${bin_path}.__hidden" "$bin_path"
        fi
    done
    HIDDEN_BINS=""
    hash -r
}

teardown() {
    restore_bins
}

# =====================================================================
# Basic FQDN allow/deny
# =====================================================================

@test "apf -a FQDN creates rules for resolved IP, not hostname" {
    run "$APF" -a "$FQDN_SINGLE" "test allow"
    assert_success
    # Rule should contain the resolved IP
    assert_rule_exists_ips TALLOW "-s $IP_SINGLE.*-j ACCEPT"
    assert_rule_exists_ips TALLOW "-d $IP_SINGLE.*-j ACCEPT"
    # iptables should NOT contain the FQDN text
    local rules
    rules=$(iptables -S TALLOW 2>/dev/null)
    [[ "$rules" != *"$FQDN_SINGLE"* ]]
}

@test "apf -d FQDN creates deny rules for resolved IP" {
    run "$APF" -d "$FQDN_SINGLE"
    assert_success
    assert_rule_exists_ips TDENY "-s $IP_SINGLE.*-j DROP"
    assert_rule_exists_ips TDENY "-d $IP_SINGLE.*-j DROP"
}

@test "FQDN trust file stores hostname with resolved= metadata" {
    "$APF" -a "$FQDN_SINGLE" "metadata test"
    run grep "^${FQDN_SINGLE}$" "$APF_DIR/allow_hosts.rules"
    assert_success
    run grep "# added ${FQDN_SINGLE}.*resolved=${IP_SINGLE}" "$APF_DIR/allow_hosts.rules"
    assert_success
}

# =====================================================================
# Multiple A records
# =====================================================================

@test "FQDN with multiple A records creates rules for all IPs" {
    run "$APF" -a "$FQDN_MULTI"
    assert_success
    assert_rule_exists_ips TALLOW "-s $IP_MULTI_1.*-j ACCEPT"
    assert_rule_exists_ips TALLOW "-d $IP_MULTI_1.*-j ACCEPT"
    assert_rule_exists_ips TALLOW "-s $IP_MULTI_2.*-j ACCEPT"
    assert_rule_exists_ips TALLOW "-d $IP_MULTI_2.*-j ACCEPT"
}

@test "Multi-IP FQDN resolved= metadata contains all IPs" {
    "$APF" -a "$FQDN_MULTI"
    local comment
    comment=$(grep "# added ${FQDN_MULTI}" "$APF_DIR/allow_hosts.rules")
    [[ "$comment" == *"$IP_MULTI_1"* ]]
    [[ "$comment" == *"$IP_MULTI_2"* ]]
}

# =====================================================================
# FQDN removal
# =====================================================================

@test "apf -u FQDN removes rules by resolved IP" {
    "$APF" -a "$FQDN_SINGLE"
    assert_rule_exists_ips TALLOW "-s $IP_SINGLE.*-j ACCEPT"
    run "$APF" -u "$FQDN_SINGLE"
    assert_success
    # Rules should be gone
    local rules
    rules=$(iptables -S TALLOW 2>/dev/null | grep -- "$IP_SINGLE" || true)
    [ -z "$rules" ]
    # Trust file should be clean
    run grep "$FQDN_SINGLE" "$APF_DIR/allow_hosts.rules"
    assert_failure
}

@test "FQDN removal without metadata falls back to live resolution" {
    # Manually add FQDN entry without resolved= comment
    echo "# added $FQDN_SINGLE on 01/01/26 00:00:00" >> "$APF_DIR/allow_hosts.rules"
    echo "$FQDN_SINGLE" >> "$APF_DIR/allow_hosts.rules"
    # Add matching iptables rules manually
    iptables -I TALLOW -s "$IP_SINGLE" -j ACCEPT
    iptables -I TALLOW -d "$IP_SINGLE" -j ACCEPT
    run "$APF" -u "$FQDN_SINGLE"
    assert_success
    local rules
    rules=$(iptables -S TALLOW 2>/dev/null | grep -- "$IP_SINGLE" || true)
    [ -z "$rules" ]
}

# =====================================================================
# Advanced trust syntax with FQDN
# =====================================================================

@test "apf -a advanced syntax with FQDN resolves before iptables" {
    run "$APF" -a "d=22:s=$FQDN_SINGLE"
    assert_success
    assert_rule_exists_ips TALLOW "-s $IP_SINGLE.*-p tcp.*--dports 22.*-j ACCEPT"
    assert_rule_exists_ips TALLOW "-s $IP_SINGLE.*-p udp.*--dports 22.*-j ACCEPT"
}

@test "apf -a 5-field advanced syntax with FQDN" {
    run "$APF" -a "tcp:in:d=443:s=$FQDN_SINGLE"
    assert_success
    assert_rule_exists_ips TALLOW "-s $IP_SINGLE.*-p tcp.*--dports 443.*-j ACCEPT"
}

@test "apf -u removes advanced trust entry with FQDN" {
    "$APF" -a "d=22:s=$FQDN_SINGLE"
    run "$APF" -u "d=22:s=$FQDN_SINGLE"
    assert_success
    local rules
    rules=$(iptables -S TALLOW 2>/dev/null | grep -- "$IP_SINGLE" || true)
    [ -z "$rules" ]
}

# =====================================================================
# Temporary trust with FQDN
# =====================================================================

@test "apf -ta FQDN creates temporary allow rules" {
    run "$APF" -ta "$FQDN_SINGLE" "1h"
    assert_success
    assert_rule_exists_ips TALLOW "-s $IP_SINGLE.*-j ACCEPT"
    # Trust file should have ttl= and expire= markers
    run grep "ttl=.*expire=.*resolved=$IP_SINGLE" "$APF_DIR/allow_hosts.rules"
    assert_success
}

@test "apf -td FQDN creates temporary deny rules" {
    run "$APF" -td "$FQDN_SINGLE" "30m"
    assert_success
    assert_rule_exists_ips TDENY "-s $IP_SINGLE.*-j DROP"
}

# =====================================================================
# IPv6 FQDN resolution
# =====================================================================

@test "FQDN with AAAA record creates ip6tables rule" {
    if ! ip6tables_available; then skip "ip6tables not available"; fi
    run "$APF" -a "$FQDN_V6"
    assert_success
    # ip6tables -S normalizes expanded IPv6 from getent to compressed form
    assert_rule_exists_ip6s TALLOW "-s 2001:db8:.*-j ACCEPT"
}

# =====================================================================
# Resolution failure
# =====================================================================

@test "nonexistent FQDN produces error, no rules created" {
    run "$APF" -a "$FQDN_NOEXIST"
    assert_output --partial "Failed to resolve"
    local rules
    rules=$(iptables -S TALLOW 2>/dev/null | grep -c "ACCEPT" || true)
    [ "$rules" -eq 0 ]
}

# =====================================================================
# Local address check with FQDN
# =====================================================================

@test "FQDN resolving to server IP is rejected" {
    run "$APF" -a "$FQDN_LOCAL"
    assert_output --partial "local address"
}

# =====================================================================
# Bulk load (restart with FQDN in trust file)
# =====================================================================

@test "restart loads FQDN from trust file as resolved IPs" {
    echo "# added $FQDN_SINGLE on 01/01/26 00:00:00 resolved=$IP_SINGLE" >> "$APF_DIR/allow_hosts.rules"
    echo "$FQDN_SINGLE" >> "$APF_DIR/allow_hosts.rules"
    "$APF" -r
    assert_rule_exists_ips TALLOW "-s $IP_SINGLE.*-j ACCEPT"
    assert_rule_exists_ips TALLOW "-d $IP_SINGLE.*-j ACCEPT"
}

# =====================================================================
# Refresh re-resolution
# =====================================================================

@test "apf -e re-resolves FQDNs in trust files" {
    echo "$FQDN_SINGLE" >> "$APF_DIR/allow_hosts.rules"
    "$APF" -r
    assert_rule_exists_ips TALLOW "-s $IP_SINGLE.*-j ACCEPT"
    # Change the /etc/hosts mapping (Docker-safe: sed -i fails on bind mounts)
    sed "s/$IP_SINGLE.*$FQDN_SINGLE/198.51.100.99    $FQDN_SINGLE/" /etc/hosts \
        > /tmp/hosts_refresh.tmp && cat /tmp/hosts_refresh.tmp > /etc/hosts
    "$APF" -e
    assert_rule_exists_ips TALLOW "-s 198.51.100.99.*-j ACCEPT"
    # Restore original mapping
    sed "s/198.51.100.99.*$FQDN_SINGLE/$IP_SINGLE    $FQDN_SINGLE/" /etc/hosts \
        > /tmp/hosts_refresh.tmp && cat /tmp/hosts_refresh.tmp > /etc/hosts
    rm -f /tmp/hosts_refresh.tmp
}

# =====================================================================
# FQDN_TIMEOUT config
# =====================================================================

@test "FQDN_TIMEOUT config is respected" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "FQDN_TIMEOUT" "1"
    # A valid, resolvable hostname should still work with a short timeout
    run "$APF" -a "$FQDN_SINGLE"
    assert_success
    assert_rule_exists_ips TALLOW "-s $IP_SINGLE.*-j ACCEPT"
    apf_set_config "FQDN_TIMEOUT" "10"
}

# =====================================================================
# getent missing
# =====================================================================

@test "missing getent warns in check_deps and skips FQDN resolution" {
    hide_bin getent
    # Start should still succeed (getent is optional)
    "$APF" -f 2>/dev/null || true
    run "$APF" -s
    assert_success
    assert_output --partial "getent(fqdn-trust)"
    # But FQDN resolution should fail gracefully
    run "$APF" -a "$FQDN_SINGLE"
    assert_output --partial "Failed to resolve"
    restore_bins
    "$APF" -f 2>/dev/null || true
    "$APF" -s
}

# =====================================================================
# Duplicate detection still works with FQDN
# =====================================================================

@test "duplicate FQDN detection works" {
    "$APF" -a "$FQDN_SINGLE"
    run "$APF" -a "$FQDN_SINGLE"
    assert_output --partial "already exists"
}
